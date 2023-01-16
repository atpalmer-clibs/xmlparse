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

void buffer_destroy(Buffer *self)
{
    free(self);
}

Buffer *buffer_append(Buffer **self, char c)
{
    if (!*self) {
        *self = malloc(sizeof(Buffer) + 2);
        (*self)->cap = 2;
        (*self)->len = 1;
        (*self)->value[0] = c;
        (*self)->value[1] = '\0';
    } else {
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
    }

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

Token *token_new_from_buffer_destroy(const TokenType *type, Buffer *buff)
{
    if (!buff)
        return NULL;
    Token *result = token_new(type, buff->len, buff->value);
    buffer_destroy(buff);
    return result;
}

Token *token_next_whitespace(FILE *stream)
{
    static const char TOKEN_WHITESPACE[] = " \t\r\n";

    Buffer *buff = NULL;

    for (;;) {
        char c = stream_expect_char_in(stream, TOKEN_WHITESPACE);
        if (!c)
            break;
        buffer_append(&buff, c);
    }

    return token_new_from_buffer_destroy(&TokenType_WHITESPACE, buff);
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

    Buffer *buff = NULL;

    for (;;) {
        int c = stream_expect_char_in(stream, NAME_CHARS);
        if (!c)
            break;
        buffer_append(&buff, c);
    }

    return token_new_from_buffer_destroy(&TokenType_NAME, buff);
}

Token *token_next_quoted_value(FILE *stream)
{
    Buffer *buff = NULL;

    int c = stream_peek(stream);
    if (c != '"')
        return NULL;

    stream_expect_char_in(stream, "\"");
    buffer_append(&buff, c);

    for (;;) {
        int c = fgetc(stream);
        if (c == EOF)
            break;
        if (c == '\\') {
            buffer_append(&buff, c);
            c = fgetc(stream);
            if (c == EOF)
                break;
            buffer_append(&buff, c);
            continue;
        }
        if (c == '"') {
            buffer_append(&buff, c);
            break;
        }
        buffer_append(&buff, c);
    }

    return token_new_from_buffer_destroy(&TokenType_QUOTED_VALUE, buff);
}

Token *token_next_content(FILE *stream)
{
    Buffer *buff = NULL;

    for (;;) {
        int c = fgetc(stream);
        if (c == EOF)
            break;
        if (c == '<') {
            ungetc(c, stream);
            break;
        }
        buffer_append(&buff, c);
    }

    return token_new_from_buffer_destroy(&TokenType_CONTENT, buff);
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

