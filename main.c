#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>

#define INFILE "sample.xml"

#define FileError "FileError"

void die_FileError(const char *fname)
{
    fprintf(stderr, "%s: %s: %s\n", FileError, strerror(errno), fname);
    exit(-1);
}

typedef struct buffer {
    size_t cap;
    size_t len;
    char value[];
} Buffer;

Buffer *buffer_new(void)
{
    static const size_t CAPINIT = 2;
    Buffer *new = malloc(sizeof *new + CAPINIT);
    new->cap = CAPINIT;
    new->len = 0;
    new->value[0] = '\0';
    return new;
}

void buffer_destroy(Buffer *self)
{
    free(self);
}

Buffer *buffer_append(Buffer **self, char c)
{
    size_t newlen = (*self)->len + 1;
    while ((*self)->cap < newlen + 1) {
        size_t newcap = (*self)->cap * 2;
        Buffer *tmp = realloc(*self, sizeof *tmp + newcap);
        if (!tmp)
            return NULL;
        tmp->cap = newcap;
        *self = tmp;
    }
    (*self)->value[(*self)->len] = c;
    (*self)->value[(*self)->len + 1] = '\0';
    (*self)->len = newlen;
    return *self;
}

char stream_expect_char_in(FILE *stream, const char *chars)
{
    char buff = fgetc(stream);
    if (buff < 0)
        goto fail;
    if (strchr(chars, buff))
        return buff;

fail:
    ungetc(buff, stream);
    return '\0';
}

int stream_peek(FILE *stream)
{
    int c = fgetc(stream);
    ungetc(c, stream);
    return c;
}

typedef struct _Token Token;

typedef Token *(*TokenGetter)(FILE *stream);

typedef struct {
    const char *name;
    TokenGetter *funcs;
} ContextType;

extern const ContextType CTP_XMLDECL;
extern const ContextType CTP_TAG;
extern const ContextType CTP_CONTENT;

typedef struct {
    const char *name;
    const ContextType *newcontext;
} TokenType;

static const TokenType TokenType_WHITESPACE = (TokenType){"Whitespace", NULL};
static const TokenType TokenType_TAGSTART_SYMBOL = (TokenType){"TagStartSymbol", &CTP_TAG};
static const TokenType TokenType_TAGEND_SYMBOL = (TokenType){"TagEndSymbol", &CTP_CONTENT};
static const TokenType TokenType_XMLDECLSTART_SYMBOL = (TokenType){"XmlDeclStartSymbol", &CTP_XMLDECL};
static const TokenType TokenType_XMLDECLEND_SYMBOL = (TokenType){"XmlDeclEndSymbol", &CTP_CONTENT};
static const TokenType TokenType_NAME = (TokenType){"Name", NULL};
static const TokenType TokenType_SYMBOL = (TokenType){"Symbol", NULL};
static const TokenType TokenType_QUOTED_VALUE = (TokenType){"QuotedValue", NULL};
static const TokenType TokenType_CONTENT = (TokenType){"Content", NULL};

typedef struct _Token {
    const TokenType *type;  /* pointer is not owned */
    size_t len;
    char value[];
} Token;

Token *token_new(const TokenType *type, size_t len, const char *value)
{
    Token *new = malloc(sizeof *new + len + 1);
    new->type = type;
    new->len = len;
    memcpy(new->value, value, len);
    new->value[len] = '\0';
    return new;
}

Token *token_next_whitespace(FILE *stream)
{
    static const char TOKEN_WHITESPACE[] = " \t\r\n";

    Buffer *buff = buffer_new();

    for (;;) {
        char c = stream_expect_char_in(stream, TOKEN_WHITESPACE);
        if (!c)
            break;
        buffer_append(&buff, c);
    }

    Token *result = buff->len
        ? token_new(&TokenType_WHITESPACE, buff->len, buff->value)
        : NULL;

    buffer_destroy(buff);

    return result;
}

Token *token_next_tagstart_symbol(FILE *stream)
{
    if (!stream_expect_char_in(stream, "<"))
        return NULL;

    if (stream_expect_char_in(stream, "/"))
        return token_new(&TokenType_TAGSTART_SYMBOL, 2, "</");
    else if (stream_expect_char_in(stream, "?"))
        return token_new(&TokenType_XMLDECLSTART_SYMBOL, 2, "<?");
    else
        return token_new(&TokenType_TAGSTART_SYMBOL, 1, "<");
}

Token *token_next_tagend_symbol(FILE *stream)
{
    if (!stream_expect_char_in(stream, ">"))
        return NULL;

    return token_new(&TokenType_TAGEND_SYMBOL, 1, ">");
}

Token *token_next_xmldeclend_symbol(FILE *stream)
{
    if (!stream_expect_char_in(stream, "?"))
        return NULL;

    if (stream_expect_char_in(stream, ">"))
        return token_new(&TokenType_XMLDECLEND_SYMBOL, 2, "?>");
    else
        return token_new(&TokenType_SYMBOL, 1, "?");
}

Token *token_next_equals_symbol(FILE *stream)
{
    if (!stream_expect_char_in(stream, "="))
        return NULL;

    return token_new(&TokenType_SYMBOL, 1, "=");
}

Token *token_next_name(FILE *stream)
{
    static const char NAME_CHARS[] = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ_1234567890";

    static const size_t MAXLEN = 256;
    char buff[MAXLEN];

    size_t bytes = 0;

    while (bytes < MAXLEN) {
        int c = stream_expect_char_in(stream, NAME_CHARS);
        if (!c)
            break;
        buff[bytes++] = c;
    }

    buff[bytes] = '\0';

    if (bytes > 0)
        return token_new(&TokenType_NAME, bytes, buff);
    else
        return NULL;
}

Token *token_next_quoted_value(FILE *stream)
{
    static const size_t MAXLEN = 256;
    char buff[MAXLEN];

    size_t bytes = 0;

    int c = stream_peek(stream);
    if (c != '"')
        goto done;
    buff[bytes++] = stream_expect_char_in(stream, "\"");

    while (bytes < MAXLEN) {
        int c = fgetc(stream);
        if (c == EOF)
            goto done;
        if (c == '\\') {
            buff[bytes++] = c;
            if (bytes == MAXLEN)
                goto done;
            c = fgetc(stream);
            if (c == EOF)
                goto done;
            buff[bytes++] = c;
            continue;
        }
        if (c == '"') {
            buff[bytes++] = c;
            break;
        }
        buff[bytes++] = c;
    }

done:
    buff[bytes] = '\0';

    if (bytes > 0)
        return token_new(&TokenType_QUOTED_VALUE, bytes, buff);
    else
        return NULL;
}

Token *token_next_content(FILE *stream)
{
    static const size_t MAXLEN = 256;
    char buff[MAXLEN];

    size_t bytes = 0;

    while (bytes < MAXLEN) {
        int c = fgetc(stream);
        if (c == EOF)
            goto done;
        if (c == '<') {
            ungetc(c, stream);
            goto done;
        }
        buff[bytes++] = c;
    }

done:
    buff[bytes] = '\0';

    if (bytes > 0)
        return token_new(&TokenType_CONTENT, bytes, buff);
    else
        return NULL;
}

void token_free(Token *self)
{
    if (self)
        free(self);
}

TokenGetter XmlDecl_Funcs[] = {
    token_next_xmldeclend_symbol,
    token_next_whitespace,
    token_next_name,
    token_next_equals_symbol,
    token_next_quoted_value,
    NULL,
};

TokenGetter Tag_Funcs[] = {
    token_next_tagend_symbol,
    token_next_whitespace,
    token_next_name,
    token_next_equals_symbol,
    token_next_quoted_value,
    NULL,
};

TokenGetter Content_Funcs[] = {
    token_next_tagstart_symbol,
    token_next_whitespace,
    token_next_content,
    NULL,
};

const ContextType CTP_XMLDECL = (ContextType){"XmlDecl", XmlDecl_Funcs};
const ContextType CTP_TAG = (ContextType){"Tag", Tag_Funcs};
const ContextType CTP_CONTENT = (ContextType){"Content", Content_Funcs};

typedef struct {
    const ContextType *context;
} Context;

int main(void)
{
    FILE *stream = fopen(INFILE, "r");
    if (!stream)
        die_FileError(INFILE);

    Context ctx = { &CTP_CONTENT };

    for (;;) {
        Token *token = NULL;

        TokenGetter *getter = ctx.context->funcs;
        while (*getter != NULL) {
            token = (*getter)(stream);
            if (token)
                break;
            ++getter;
        }

        if (!token) {
            int c = stream_peek(stream);
            printf("TOKEN ERROR: '%c'\n", c);
            break;
        }

        printf("[%s] Token: <%s>: '%s' [len: %zu]\n", ctx.context->name, token->type->name, token->value, token->len);

        if (token->type->newcontext) {
            ctx.context = token->type->newcontext;
        }

        token_free(token);

        if (feof(stream))
            break;
    }

    fclose(stream);
    printf("DONE\n");
}

