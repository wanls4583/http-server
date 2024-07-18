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

public:
    int timeout;
    SockContainer();
    ~SockContainer();
    void freeHeader(HttpHeader* header);
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