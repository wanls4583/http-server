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

const int MAX_SOCK = 300;

class SockContainer {
private:
    pthread_mutex_t sockContainerMutex;
    pthread_mutex_t shutdownMutex;
    void _resetSockInfo(SockInfo& sockInfo);

public:
    int timeout;
    u_int64_t reqId; // 每个请求的id唯一
    u_int64_t sockId; // 每个连接的id（一个连接可能有多个请求）
    SockInfo sockInfos[MAX_SOCK];
    SockContainer();
    ~SockContainer();
    SockInfo* proxyScokInfo; // 链接列表
    SockInfo* ruleScokInfo; // 规则通信
    void freeHeader(HttpHeader* header);
    void freeSocksReqHeader(SocksReqHeader* header);
    void resetSockInfo(SockInfo& sockInfo);
    void resetSockInfoData(SockInfo& sockInfo);
    void initSockInfos();
    SockInfo* getSockInfo();
    SockInfo* getSockInfoByReqId(u_int64_t reqId);
    void shutdownSock(SockInfo* sockInfo = NULL);
    void closeSock(SockInfo& sockInfo);
    int checkSockTimeout(SockInfo& sockInfo);
    int setNoBlock(SockInfo& sockInfo, int isNoBloack);
};
#endif