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

typedef struct {
    const char *name;
} TokenType;

static const TokenType TokenType_WHITESPACE = (TokenType){"Whitespace"};
static const TokenType TokenType_SYMBOL = (TokenType){"Symbol"};
static const TokenType TokenType_TAGSTART_SYMBOL = (TokenType){"TagStartSymbol"};
static const TokenType TokenType_XMLDECLSTART_SYMBOL = (TokenType){"XmlDeclStartSymbol"};
static const TokenType TokenType_NAME = (TokenType){"Name"};
static const TokenType TokenType_QUOTED_VALUE = (TokenType){"QuotedValue"};
static const TokenType TokenType_CONTENT = (TokenType){"Content"};

typedef struct {
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
        size_t bytes_read = fread(&buff[bytes], 1, 1, stream);
        if (bytes_read < 1)
            return NULL;
        if (!strchr(TOKEN_WHITESPACE, buff[bytes])) {
            fseek(stream, -bytes_read, SEEK_CUR);
            break;
        }
        ++bytes;
    }

    buff[bytes] = '\0';

    if (bytes > 0)
        return token_new(&TokenType_WHITESPACE, bytes, buff);
    else
        return NULL;
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

Token *token_next_tag_symbol(FILE *stream)
{
    static const char TOKEN_SYMBOLS[] = {
        '>',
        '/',
        '?',
        '=',
        '\0',
    };

    char result = stream_expect_char_in(stream, TOKEN_SYMBOLS);
    if (!result)
        return NULL;

    return token_new(&TokenType_SYMBOL, 1, &result);
}

Token *token_next_name(FILE *stream)
{
    static const char NAME_CHARS[] = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ_1234567890";

    static const size_t MAXLEN = 256;
    char buff[MAXLEN];

    size_t bytes = 0;

    while (bytes < MAXLEN) {
        size_t bytes_read = fread(&buff[bytes], 1, 1, stream);
        if (!strchr(NAME_CHARS, buff[bytes]))
            break;
        bytes += bytes_read;
    }

    fseek(stream, -1, SEEK_CUR);
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

typedef struct {
    const char *name;
} ContextType;

static const ContextType CTP_XMLDECL = (ContextType){"XmlDecl"};
static const ContextType CTP_TAG = (ContextType){"Tag"};
static const ContextType CTP_CONTENT = (ContextType){"Content"};

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

        if (ctx.context == &CTP_CONTENT) {
            if (!token)
                token = token_next_tagstart_symbol(stream);
            if (!token)
                token = token_next_whitespace(stream);
            if (!token)
                token = token_next_content(stream);
        } else if (ctx.context == &CTP_XMLDECL) {
            if (!token)
                token = token_next_tag_symbol(stream);
            if (!token)
                token = token_next_whitespace(stream);
            if (!token)
                token = token_next_name(stream);
            if (!token)
                token = token_next_quoted_value(stream);
        } else if (ctx.context == &CTP_TAG) {
            if (!token)
                token = token_next_tag_symbol(stream);
            if (!token)
                token = token_next_whitespace(stream);
            if (!token)
                token = token_next_name(stream);
            if (!token)
                token = token_next_quoted_value(stream);
        }

        if (!token) {
            int c;
            fread(&c, 1, 1, stream);
            fseek(stream, -1, SEEK_CUR);
            printf("TOKEN ERROR: '%c'\n", c);
            break;
        }

        printf("[%s] Token: <%s>: '%s' [len: %zu]\n", ctx.context->name, token->type->name, token->value, token->len);

        if (token->type == &TokenType_TAGSTART_SYMBOL) {
            ctx.context = &CTP_TAG;
        }
        else if (token->type == &TokenType_XMLDECLSTART_SYMBOL) {
            ctx.context = &CTP_XMLDECL;
        }
        else if (token->type == &TokenType_SYMBOL && strncmp(token->value, ">", token->len) == 0) {
            ctx.context = &CTP_CONTENT;
        }

        token_free(token);

        if (feof(stream))
            break;
    }

    fclose(stream);
    printf("DONE\n");
}

