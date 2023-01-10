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

char stream_expect_char_in(FILE *stream, const char *chars)
{
    char buff;
    size_t bytes_read = fread(&buff, 1, 1, stream);
    if (bytes_read != 1)
        goto fail;  /* IO error */
    if (strchr(chars, buff))
        return buff;

fail:
    fseek(stream, -bytes_read, SEEK_CUR);
    return '\0';
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
    static const char TOKEN_WHITESPACE[] = {
        ' ',
        '\t',
        '\r',
        '\n',
        '\0',  /* sentinel */
    };

    static const size_t MAXLEN = 256;
    char buff[MAXLEN];

    size_t bytes = 0;

    for (;;) {
        buff[bytes] = stream_expect_char_in(stream, TOKEN_WHITESPACE);
        if (!buff[bytes])
            break;
        ++bytes;
    }

    if (bytes > 0)
        return token_new(&TokenType_WHITESPACE, bytes, buff);
    else
        return NULL;
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
        buff[bytes] = stream_expect_char_in(stream, NAME_CHARS);
        if (!buff[bytes])
            break;
        ++bytes;
    }

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

    size_t bytes_read = fread(&buff[bytes], 1, 1, stream);
    if (buff[bytes] != '"') {
        fseek(stream, -1, SEEK_CUR);
        goto done;
    }
    bytes += bytes_read;

    while (bytes < MAXLEN) {
        bytes_read = fread(&buff[bytes], 1, 1, stream);
        if (feof(stream))
            goto done;
        if (buff[bytes] == '\\' && bytes < MAXLEN) {
            bytes += bytes_read;
            bytes_read = fread(&buff[bytes], 1, 1, stream);
            if (feof(stream))
                goto done;
            bytes += bytes_read;
            continue;
        }
        if (buff[bytes] == '"') {
            bytes += bytes_read;
            break;
        }
        bytes += bytes_read;
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
        size_t bytes_read = fread(&buff[bytes], 1, 1, stream);
        if (buff[bytes] == '<') {
            fseek(stream, -1, SEEK_CUR);
            goto done;
        }
        if (feof(stream))
            goto done;
        bytes += bytes_read;
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
            int c;
            fread(&c, 1, 1, stream);
            fseek(stream, -1, SEEK_CUR);
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

