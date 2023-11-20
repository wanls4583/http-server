#ifndef SockInfo
#include <openssl/ssl.h>
struct SockInfo
{
    SSL *ssl;
    int clntSock;
    char *ip;
    char *req;
};
#endif