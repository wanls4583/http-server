#ifndef SockInfo_h
#define SockInfo_h
#include <iostream>
#include <openssl/ssl.h>
#include <sys/time.h>
#include <unistd.h>
#include <sys/socket.h>
#include <fcntl.h>
#include "HttpHeader.h"
struct SockInfo
{
    HttpHeader *header;
    SSL *ssl;
    int clntSock;
    int closing;
    int originSockFlag;
    int isNoBloack;
    int isNoCheckSSL;
    size_t bufSize;
    size_t reqSize;
    size_t bodySize;
    char *ip;
    char *tlsHeader;
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
    pthread_mutex_t shutdownMutex;
public:
    int timeout;
    SockContainer();
    ~SockContainer();
    void resetSockInfo(SockInfo &sockInfo);
    void resetSockInfoData(SockInfo &sockInfo);
    void initSockInfos();
    SockInfo *getSockInfo();
    void shutdownSock(SockInfo *sockInfo = NULL);
    int checkSockTimeout(SockInfo &sockInfo);
    int setNoBlock(SockInfo &sockInfo, int isNoBloack);
};
#endif