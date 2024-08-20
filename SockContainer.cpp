#include "SockContainer.h"

using namespace std;

extern WsUtils wsUtils;
extern SockContainer sockContainer;
extern pthread_key_t ptKey;

SockContainer::SockContainer(): timeout(10), reqId(1), sockId(1) {
    pthread_mutex_init(&sockContainerMutex, NULL);
    pthread_mutex_init(&shutdownMutex, NULL);
    this->initSockInfos();
}

SockContainer::~SockContainer() {
    this->initSockInfos();
}

void SockContainer::freeHeader(HttpHeader* header) {
    if (!header) {
        return;
    }
    free(header->hostname);
    free(header->protocol);
    free(header->originPath);
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
    free(header->transferEncoding);
    free(header->trailer);
    free(header->reason);
    free(header);
}

void SockContainer::freeSocksReqHeader(SocksReqHeader* header) {
    if (!header) {
        return;
    }
    free(header->addr);
    free(header);
}

void SockContainer::resetSockInfo(SockInfo& sockInfo) {
    pthread_mutex_lock(&sockContainerMutex);
    this->_resetSockInfo(sockInfo);
    if (sockInfo.remoteSockInfo) {
        this->_resetSockInfo(*sockInfo.remoteSockInfo);
        free(sockInfo.remoteSockInfo);
        sockInfo.remoteSockInfo = NULL;
    }
    pthread_mutex_unlock(&sockContainerMutex);
}

void SockContainer::_resetSockInfo(SockInfo& sockInfo) {
    if (sockInfo.sockId < 0) {
        return;
    }

    if (sockContainer.wsScokInfo == &sockInfo) {
        sockContainer.wsScokInfo = NULL;
    }

    this->resetSockInfoData(sockInfo);

    sockInfo.tid = NULL;
    sockInfo.wsTid = NULL;
    sockInfo.ssl = NULL;
    sockInfo.localSockInfo = NULL;

    sockInfo.reqId = 0;
    sockInfo.sockId = 0;
    sockInfo.sock = -1;
    sockInfo.closing = 0;
    sockInfo.originSockFlag = 0;
    sockInfo.isNoBloack = 0;
    sockInfo.isNoCheckSSL = 0;
    sockInfo.isNoCheckSocks = 0;
    sockInfo.isProxy = 0;
    sockInfo.isWebSock = 0;
    sockInfo.recivedCloseFrame = 0;
    sockInfo.port = 0;

    sockInfo.bufSize = 0;

    free(sockInfo.ip);
    sockInfo.ip = NULL;
    free(sockInfo.buf);
    sockInfo.buf = NULL;
    free(sockInfo.cipher);
    sockInfo.cipher = NULL;
    free(sockInfo.pem_cert);
    sockInfo.pem_cert = NULL;

    sockInfo.tv.tv_sec = 0;
    sockInfo.tv.tv_nsec = 0;
}

void SockContainer::resetSockInfoData(SockInfo& sockInfo) {
    if (sockInfo.remoteSockInfo) {
        this->resetSockInfoData(*sockInfo.remoteSockInfo);
    }

    if (sockInfo.header) {
        this->freeHeader(sockInfo.header);
        sockInfo.header = NULL;
    }

    if (sockInfo.socksReqHeader) {
        this->freeSocksReqHeader(sockInfo.socksReqHeader);
        sockInfo.socksReqHeader = NULL;
    }

    if (sockInfo.isProxy) { // 远程服务器每次只返回一个响应，所以可清空还未处理的数据
        sockInfo.bufSize = 0;
        free(sockInfo.buf);
        sockInfo.buf = NULL;
    }

    sockInfo.reqSize = 0;
    sockInfo.bodySize = 0;

    free(sockInfo.tlsHeader);
    sockInfo.tlsHeader = NULL;
    free(sockInfo.socksHeader);
    sockInfo.socksHeader = NULL;
    free(sockInfo.head);
    sockInfo.head = NULL;
    free(sockInfo.body);
    sockInfo.body = NULL;
    wsUtils.freeFragment(sockInfo.wsFragment);
    sockInfo.wsFragment = NULL;
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
            timespec_get(&(this->sockInfos[i].tv), TIME_UTC);
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

    if (sockInfo->sock <= 0 || sockInfo->closing == 1) { // 线程已经退出或正在退出
        pthread_mutex_unlock(&shutdownMutex);
        return;
    }
    sockInfo->closing = 1; // 关闭中
    pthread_mutex_unlock(&shutdownMutex);

    this->closeSock(*sockInfo);
    if (sockInfo->remoteSockInfo) {
        this->closeSock(*sockInfo->remoteSockInfo);
    }

    pthread_t wsTid = sockInfo->remoteSockInfo ? sockInfo->remoteSockInfo->wsTid : NULL;
    pthread_t tid = sockInfo->tid;
    u_int64_t sockId = sockInfo->sockId;
    int sock = sockInfo->sock;
    this->resetSockInfo(*sockInfo);

    if (wsTid) {
        pthread_cancel(wsTid);
    }
    if (tid) {
        cout << "pthread_cancel:" << sockId << ":" << sock << endl;
        pthread_cancel(tid);
    }
    pthread_testcancel();
    // cout << "pthread_testcancel" << endl;
}

void SockContainer::closeSock(SockInfo& sockInfo) {
    if (sockInfo.ssl != NULL) {
        int res = SSL_shutdown(sockInfo.ssl); // 0:未完成，1:成功，-1:失败
        shutdown(sockInfo.sock, SHUT_RDWR);
        usleep(1000); // 此时可能有其他线程正准备执行 SSL_read 或 SSL_write
        SSL_free(sockInfo.ssl);
    } else {
        shutdown(sockInfo.sock, SHUT_RDWR);
    }
    close(sockInfo.sock);
}

int SockContainer::checkSockTimeout(SockInfo& sockInfo) {
    struct timespec tv;
    const int us = 1000000;
    timespec_get(&tv, TIME_UTC);
    if ((tv.tv_sec * us + tv.tv_nsec / 1000) - (sockInfo.tv.tv_sec * us + sockInfo.tv.tv_nsec / 1000) > this->timeout * us) {
        return 0;
    }
    return 1;
}

int SockContainer::setNoBlock(SockInfo& sockInfo, int isNoBloack) {
    if (sockInfo.isNoBloack && isNoBloack || !sockInfo.isNoBloack && !isNoBloack) {
        return 1;
    }

    int newSocketFlag = sockInfo.originSockFlag | (isNoBloack ? O_NONBLOCK : O_APPEND);
    if (fcntl(sockInfo.sock, F_SETFL, newSocketFlag) == -1) // 设置阻塞模式
    {
        cout << "set socket block flags error:" << isNoBloack << ":" << newSocketFlag << endl;
        return 0;
    }
    sockInfo.isNoBloack = isNoBloack ? 1 : 0;

    return 1;
}