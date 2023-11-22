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
    char *ip;
    char *req;
    char *body;
    char *buf; // 未处理的buf
};

const int MAX_SOCK = 100;

class SockContainer
{
private:
    SockInfo sockInfos[MAX_SOCK];
    pthread_mutex_t sockContainerMutex;
public:
    SockContainer();
    ~SockContainer();
    void resetSockInfo(SockInfo &sockInfo);
    void initSockInfos();
    SockInfo *getSockInfo();
};
#endif