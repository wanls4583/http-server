#include "SockContainer.h"

using namespace std;

extern pthread_key_t ptKey;

SockContainer::SockContainer(): timeout(60) {
    pthread_mutex_init(&sockContainerMutex, NULL);
    pthread_mutex_init(&shutdownMutex, NULL);
    this->initSockInfos();
}

SockContainer::~SockContainer() {
    this->initSockInfos();
}

void SockContainer::freeHeader(HttpHeader* header) {
    free(header->hostname);
    free(header->protocol);
    free(header->path);
    free(header->url);
    free(header->method);
    free(header->contentType);
    free(header->boundary);
    free(header->connnection);
    free(header->proxyConnection);
    free(header->userAgent);
    free(header->accept);
    free(header->referer);
    free(header->acceptEncoding);
    free(header->acceptLanguage);
    free(header->reason);
    free(header);
}

void SockContainer::resetSockInfo(SockInfo& sockInfo) {
    pthread_mutex_lock(&sockContainerMutex);

    if (sockInfo.remoteSockInfo) {
        this->resetSockInfo(*sockInfo.remoteSockInfo);
        free(sockInfo.remoteSockInfo);
        sockInfo.remoteSockInfo = NULL;
    }

    this->resetSockInfoData(sockInfo);

    sockInfo.ssl = NULL;

    sockInfo.sock = -1;
    sockInfo.closing = 0;
    sockInfo.originSockFlag = 0;
    sockInfo.isNoBloack = 0;
    sockInfo.isNoCheckSSL = 0;
    sockInfo.isRemote = 1;

    sockInfo.bufSize = 0;

    free(sockInfo.ip);
    sockInfo.ip = NULL;
    free(sockInfo.buf);
    sockInfo.buf = NULL;

    sockInfo.tv.tv_sec = 0;
    sockInfo.tv.tv_usec = 0;
    sockInfo.tid = NULL;
    pthread_mutex_unlock(&sockContainerMutex);
}

void SockContainer::resetSockInfoData(SockInfo& sockInfo) {
    pthread_mutex_lock(&sockContainerMutex);

    if (sockInfo.remoteSockInfo) {
        this->resetSockInfoData(*sockInfo.remoteSockInfo);
    }

    if (sockInfo.header) {
        this->freeHeader(sockInfo.header);
        sockInfo.header = NULL;
    }

    sockInfo.reqSize = 0;
    sockInfo.bodySize = 0;

    free(sockInfo.tlsHeader);
    sockInfo.tlsHeader = NULL;
    free(sockInfo.head);
    sockInfo.head = NULL;
    free(sockInfo.body);
    sockInfo.body = NULL;
    pthread_mutex_unlock(&sockContainerMutex);
}

void SockContainer::initSockInfos() {
    for (int i = 0; i < MAX_SOCK; i++) {
        this->resetSockInfo(this->sockInfos[i]);
    }
}

SockInfo* SockContainer::getSockInfo() {
    pthread_mutex_lock(&sockContainerMutex);
    for (int i = 0; i < MAX_SOCK; i++) {
        if (this->sockInfos[i].sock == -1 && !this->sockInfos[i].closing) {
            gettimeofday(&(this->sockInfos[i].tv), NULL);
            pthread_mutex_unlock(&sockContainerMutex);
            this->sockInfos[i].sock = 0;
            return &this->sockInfos[i];
        }
    }
    pthread_mutex_unlock(&sockContainerMutex);
    return NULL;
}

void SockContainer::shutdownSock(SockInfo* sockInfo) {
    pthread_mutex_lock(&shutdownMutex);
    if (!sockInfo) {
        sockInfo = (SockInfo*)pthread_getspecific(ptKey);
    }
    if (sockInfo->sock == -1) // 线程已经退出
    {
        pthread_mutex_unlock(&shutdownMutex);
        return;
    }
    sockInfo->closing = 1; // 关闭中
    if (sockInfo->remoteSockInfo) {
        this->closeSock(*sockInfo->remoteSockInfo);
    }
    this->closeSock(*sockInfo);
    pthread_t tid = sockInfo->tid;
    pthread_mutex_unlock(&shutdownMutex);
    this->resetSockInfo(*sockInfo);
    pthread_cancel(tid);
}

void SockContainer::closeSock(SockInfo& sockInfo) {
    if (sockInfo.ssl != NULL) {
        int res = SSL_shutdown(sockInfo.ssl); // 0:未完成，1:成功，-1:失败
        shutdown(sockInfo.sock, SHUT_RDWR);
        SSL_free(sockInfo.ssl);
    } else {
        shutdown(sockInfo.sock, SHUT_RDWR);
    }
    close(sockInfo.sock);
}

int SockContainer::checkSockTimeout(SockInfo& sockInfo) {
    struct timeval tv;
    const int us = 1000000;
    gettimeofday(&tv, NULL);
    if ((tv.tv_sec * us + tv.tv_usec) - (sockInfo.tv.tv_sec * us + sockInfo.tv.tv_usec) > this->timeout * us) {
        return 0;
    }
    return 1;
}

int SockContainer::setNoBlock(SockInfo& sockInfo, int isNoBloack) {
    if (sockInfo.isNoBloack && isNoBloack || !sockInfo.isNoBloack && !isNoBloack) {
        return 1;
    }

    int newSocketFlag = sockInfo.originSockFlag | (isNoBloack ? O_NONBLOCK : O_APPEND);
    if (fcntl(sockInfo.sock, F_SETFL, newSocketFlag) == -1) // 设置成阻塞模式
    {
        cout << "set socket block flags error:" << isNoBloack << ":" << newSocketFlag << endl;
        return 0;
    }
    sockInfo.isNoBloack = isNoBloack ? 1 : 0;

    return 1;
}