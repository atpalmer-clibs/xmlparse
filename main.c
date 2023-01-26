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

void token_free(Token **self)
{
    if (!*self)
        return;

    free(*self);
    *self = NULL;
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
    FILE *stream;
    Token *token;
} Context;

Context *ctx_from_filename(const char *fn)
{
    FILE *stream = fopen(fn, "r");
    if (!stream)
        die_FileError(fn);

    Context *new = malloc(sizeof *new);
    new->context = &CTP_CONTENT;
    new->stream = stream;
    new->token = NULL;
    return new;
}

void ctx_destroy(Context *self)
{
    fclose(self->stream);
    free(self);
}

int ctx_is_done(Context *self)
{
    return feof(self->stream);
}

Token *ctx_peek_token(Context *ctx)
{
    if (!ctx->token) {
        TokenGetter *getter = ctx->context->funcs;
        while (*getter != NULL) {
            Token *token = (*getter)(ctx->stream);
            if (token) {
                if (ctx->token)
                    token_free(&ctx->token);
                ctx->token = token;

                if (!ctx->token) {
                    int c = stream_peek(ctx->stream);
                    fprintf(stderr, "TOKEN ERROR: '%c'\n", c);
                    exit(-1);
                }

                break;
            }
            ++getter;
        }
    }
    return ctx->token;
}

Token *ctx_next_token(Context *ctx)
{
    Token *token = ctx_peek_token(ctx);
    if (ctx->token) {
        if (ctx->token->type->newcontext)
            ctx->context = ctx->token->type->newcontext;
        ctx->token = NULL;
    }
    return token;
}

int ctx_token_try(Context *ctx, const TokenType *type)
{
    Token *token = ctx_peek_token(ctx);
    return token->type == type;
}

Token *ctx_token_expect_or_die(Context *ctx, const TokenType *type)
{
    Token *token = ctx_next_token(ctx);
    if (token->type != type) {
        fprintf(stderr, "Token Expect Error: Expected: %s; Found: %s\n",
            type->name,
            token->type->name);
        exit(-1);
    }
    return token;
}

typedef enum {
    XNT_DOC,
    XNT_DECL,
} XmlNodeType;

typedef struct {
    XmlNodeType type;
} XmlNode;

typedef struct {
    XmlNodeType type;
    XmlNode *xmldecl;
} XmlNode_Document;

typedef struct {
    XmlNodeType type;
    char *version;
    char *encoding;
    /* TODO: misc. attributes */
} XmlNode_XmlDecl;

XmlNode *xmlnode_new_document(void)
{
    XmlNode_Document *new = malloc(sizeof *new);
    new->type = XNT_DOC;
    new->xmldecl = NULL;
    return (XmlNode *)new;
}

XmlNode *xmlnode_new_xmldecl(void)
{
    XmlNode_XmlDecl *new = malloc(sizeof *new);
    new->type = XNT_DECL;
    new->version = NULL;
    new->encoding = NULL;
    return (XmlNode *)new;
}

void xmlnode_destroy(XmlNode *self);

void xmlnode_destroy_xmldoc(XmlNode_Document *self)
{
    if (self->xmldecl)
        xmlnode_destroy(self->xmldecl);
    free(self);
}

void xmlnode_destroy_xmldecl(XmlNode_XmlDecl *self)
{
    if (self->version)
        free(self->version);
    if (self->encoding)
        free(self->encoding);
    free(self);
}

void xmlnode_destroy(XmlNode *self)
{
    switch (self->type) {
    case XNT_DOC:
        xmlnode_destroy_xmldoc((XmlNode_Document *)self);
        break;
    case XNT_DECL:
        xmlnode_destroy_xmldecl((XmlNode_XmlDecl *)self);
        break;
    default:
        fprintf(stderr, "Unhandled XmlNode type: %d\n", self->type);
        exit(-1);
    }
}

void xml_expect_XMLDECLSTART(Context *ctx)
{
    Token *token = ctx_next_token(ctx);
    if (!token) {
        fprintf(stderr, "Error: No tokens in document.\n");
        exit(-1);
    }
    if (token->type != &TokenType_XMLDECLSTART_SYMBOL) {
        fprintf(stderr, "Error: Document must start with XML declaration.\n");
        exit(-1);
    }
}

void xml_expect_NAME(Context *ctx, const char *expect)
{
    Token *token = ctx_next_token(ctx);
    if (token->type != &TokenType_NAME) {
        fprintf(stderr, "Expecting NAME token with value \"%s\". Found: \"%s\" token.\n", expect, token->type->name);
        exit(-1);
    }
    if (strcmp(token->value, expect) != 0) {
        fprintf(stderr, "Expecting \"%s\". Found: \"%s\"\n", expect, token->value);
        exit(-1);
    }
}

void xml_parse_skip_whitespace(Context *ctx)
{
    while (!ctx_is_done(ctx)) {
        if (!ctx_token_try(ctx, &TokenType_WHITESPACE))
            return;
        ctx_token_expect_or_die(ctx, &TokenType_WHITESPACE);
    }
}

XmlNode *xml_parse_xmldecl(Context *ctx)
{
    XmlNode_XmlDecl *new = (XmlNode_XmlDecl *)xmlnode_new_xmldecl();

    xml_expect_XMLDECLSTART(ctx);
    xml_expect_NAME(ctx, "xml");

    for (;;) {
        if (ctx_token_try(ctx, &TokenType_XMLDECLEND_SYMBOL))
            break;

        xml_parse_skip_whitespace(ctx);
        Token *token = ctx_peek_token(ctx);

        if (!ctx_token_try(ctx, &TokenType_NAME))
            ctx_token_expect_or_die(ctx, &TokenType_NAME);  /* TODO: we know we're dying */

        if (strcmp(token->value, "encoding") != 0) {
            Token *token;

            ctx_token_expect_or_die(ctx, &TokenType_NAME);

            token = ctx_token_expect_or_die(ctx, &TokenType_SYMBOL);
            if (strcmp(token->value, "=") != 0) {
                fprintf(stderr, "XML encoding must have a value.\n");
                exit(-1);
            }

            token = ctx_token_expect_or_die(ctx, &TokenType_QUOTED_VALUE);

            new->encoding = strdup(token->value);
        }

        if (strcmp(token->value, "version") != 0) {
            Token *token;

            ctx_token_expect_or_die(ctx, &TokenType_NAME);

            token = ctx_token_expect_or_die(ctx, &TokenType_SYMBOL);
            if (strcmp(token->value, "=") != 0) {
                fprintf(stderr, "XML version must have a value.\n");
                exit(-1);
            }

            token = ctx_token_expect_or_die(ctx, &TokenType_QUOTED_VALUE);

            new->version = strdup(token->value);
        }

    }

    ctx_token_expect_or_die(ctx, &TokenType_XMLDECLEND_SYMBOL);

    return (XmlNode *)new;
}

XmlNode_Document *xml_parse_document(Context *ctx)
{
    XmlNode_Document *doc = (XmlNode_Document *)xmlnode_new_document();

    xml_parse_skip_whitespace(ctx);

    doc->xmldecl = xml_parse_xmldecl(ctx);

    return doc;
}

void xml_print_decl(XmlNode_XmlDecl *decl)
{
    printf("XmlNode_XmlDecl: Version: '%s'; Encoding: '%s'\n",
        decl->version,
        decl->encoding);

    /* TODO: misc attributes */
}

void xml_print_document(XmlNode_Document *doc)
{
    xml_print_decl((XmlNode_XmlDecl *)doc->xmldecl);
}

int main(void)
{
    Context *ctx = ctx_from_filename(INFILE);

    XmlNode_Document *document = xml_parse_document(ctx);
    xml_print_document(document);
    xmlnode_destroy((XmlNode *)document);

    while (!ctx_is_done(ctx)) {
        Token *token = ctx_next_token(ctx);
        if (!token)
            break;

        printf("[%s] Token: <%s>: '%s' [len: %zu]\n",
            ctx->context->name,
            token->type->name,
            token->value,
            token->len);
    }

    ctx_destroy(ctx);
    printf("DONE\n");
}

