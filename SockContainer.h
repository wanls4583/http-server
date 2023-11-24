#ifndef SockInfo_h
#define SockInfo_h
#include <iostream>
#include <openssl/ssl.h>
#include <sys/time.h>
#include <unistd.h>
#include <sys/socket.h>
#include "HttpHeader.h"
struct SockInfo
{
    HttpHeader *header;
    SSL *ssl;
    int clntSock;
    int closing;
    size_t bufSize;
    size_t reqSize;
    size_t bodySize;
    char *ip;
    char *req;
    char *body;
    char *buf; // 未处理的buf
    struct timeval tv;
    pthread_t tid;
};

const int MAX_SOCK = 100;

class SockContainer
{
private:
    SockInfo sockInfos[MAX_SOCK];
    pthread_mutex_t sockContainerMutex;
public:
    int timeout;
    SockContainer();
    ~SockContainer();
    void resetSockInfo(SockInfo &sockInfo);
    void resetSockInfoData(SockInfo &sockInfo);
    void initSockInfos();
    SockInfo *getSockInfo();
    void shutdownSock(SockInfo *sockInfo = NULL);
    void checkSockTimeout();
};
#endif