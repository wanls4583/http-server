#ifndef SockContainer_h
#define SockContainer_h
#include <iostream>
#include <openssl/ssl.h>
#include <sys/time.h>
#include <unistd.h>
#include <sys/socket.h>
#include <fcntl.h>
#include "SockInfo.h"
#include "WsUtils.h"

const int MAX_SOCK = 100;

class SockContainer {
private:
    SockInfo sockInfos[MAX_SOCK];
    pthread_mutex_t sockContainerMutex;
    pthread_mutex_t shutdownMutex;
    void _resetSockInfo(SockInfo& sockInfo);

public:
    int timeout;
    u_int64_t reqId; // 每个请求的id唯一
    u_int64_t sockId; // 每个连接的id（一个连接可能有多个请求）
    SockContainer();
    ~SockContainer();
    SockInfo* wsScokInfo; // 本地通信
    void freeHeader(HttpHeader* header);
    void freeSocksReqHeader(SocksReqHeader* header);
    void resetSockInfo(SockInfo& sockInfo);
    void resetSockInfoData(SockInfo& sockInfo);
    void initSockInfos();
    SockInfo* getSockInfo();
    void shutdownSock(SockInfo* sockInfo = NULL);
    void closeSock(SockInfo& sockInfo);
    int checkSockTimeout(SockInfo& sockInfo);
    int setNoBlock(SockInfo& sockInfo, int isNoBloack);
};
#endif