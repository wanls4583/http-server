#ifndef SockInfo
#include <openssl/ssl.h>
#include "HttpHeader.h"
struct SockInfo
{
    HttpHeader *header;
    SSL *ssl;
    int clntSock;
    int bufSize;
    int reqSize;
    int bodySize;
    int bodyEndFlag;
    char *ip;
    char *req;
    char *body;
    char *buf; //未处理的buf
};
#endif