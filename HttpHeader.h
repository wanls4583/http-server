#ifndef HttpHeader
#include "SockInfo.h"
typedef struct HttpHeader
{
    SockInfo *sockInfo;
    char *hostname;
    char *protocol;
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
    int contentLenth;
    int port;
} HttpHeader;
#endif