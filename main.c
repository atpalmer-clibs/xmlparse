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
static const TokenType TokenType_NAME = (TokenType){"Name"};
static const TokenType TokenType_QUOTED_VALUE = (TokenType){"QuotedValue"};

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

    char c;
    size_t bytes_read = fread(&c, 1, 1, stream);
    if (bytes_read < 1)
        return NULL;

    const char *curr = &TOKEN_WHITESPACE[0];
    for (; *curr; ++curr) {
        if (c == *curr)
            return token_new(&TokenType_WHITESPACE, 1, &c);
    }

    fseek(stream, -bytes_read, SEEK_CUR);
    return NULL;
}

Token *token_next_symbol(FILE *stream)
{
    static const char *TOKEN_SYMBOLS[] = {
        "<",
        ">",
        "/",
        "?",
        "=",
    };

    static const size_t TOKEN_SYMBOLS_COUNT = sizeof(TOKEN_SYMBOLS) / sizeof(const char *);

    for (size_t i = 0; i < TOKEN_SYMBOLS_COUNT; ++i) {
        const char *curr_sym = TOKEN_SYMBOLS[i];
        size_t len = strlen(curr_sym);
        char buff[len];
        size_t bytes_read = fread(&buff, 1, len, stream);
        if (bytes_read == len && strncmp(buff, curr_sym, bytes_read) == 0) {
            return token_new(&TokenType_SYMBOL, len, curr_sym);
        }
        fseek(stream, -bytes_read, SEEK_CUR);
    }
    return NULL;
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

void token_free(Token *self)
{
    if (self)
        free(self);
}

int main(void)
{
    FILE *stream = fopen(INFILE, "r");
    if (!stream)
        die_FileError(INFILE);

    for (int x = 0; x < 100; ++x) {
        Token *token = NULL;

        if (!token)
            token = token_next_symbol(stream);
        if (!token)
            token = token_next_whitespace(stream);
        if (!token)
            token = token_next_name(stream);
        if (!token)
            token = token_next_quoted_value(stream);

        if (!token) {
            int c;
            fread(&c, 1, 1, stream);
            fseek(stream, -1, SEEK_CUR);
            printf("TOKEN ERROR: '%c'\n", c);
            break;
        }

        printf("Token: <%s>: '%s' [len: %zu]\n", token->type->name, token->value, token->len);

        token_free(token);

        if (feof(stream))
            break;
    }

    fclose(stream);
    printf("DONE\n");
}

