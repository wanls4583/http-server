#ifndef HttpHeader_h
#define HttpHeader_h
#define MAX_REQ_SIZE (1024 * 1024)
#define MAX_BODY_SIZE (1024 * 1024 * 200)
typedef struct HttpHeader
{
    char *hostname;
    char *protocol;
    char *originPath;
    char *path;
    char *url;
    char *method;
    char *contentType;
    char *boundary;
    char *connnection;
    char *proxyConnection;
    char *userAgent;
    char *accept;
    char *referer;
    char *acceptEncoding;
    char *acceptLanguage;
    char *transferEncoding;
    char *trailer;
    char *reason;
    char *upgrade;
    char *secWebSocketKey;
    ssize_t contentLenth;
    int port;
    int status;
} HttpHeader;
#endif