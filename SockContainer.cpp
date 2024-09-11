#include "SockContainer.h"
#include "RuleUtils.h"

using namespace std;

extern WsUtils wsUtils;
extern SockContainer sockContainer;
extern RuleUtils ruleUtils;
extern pthread_key_t ptKey;

SockContainer::SockContainer(): timeout(10), reqId(1), sockId(1) {
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
    free(header->upgrade);
    free(header->secWebSocketKey);
    free(header->upgradeInsecureRequests);
    free(header->authorization);
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
    this->_resetSockInfo(sockInfo);
    if (sockInfo.remoteSockInfo) {
        this->_resetSockInfo(*sockInfo.remoteSockInfo);
        free(sockInfo.remoteSockInfo);
        sockInfo.remoteSockInfo = NULL;
    }
}

void SockContainer::_resetSockInfo(SockInfo& sockInfo) {
    this->resetSockInfoData(sockInfo);

    if (sockContainer.proxyScokInfo == &sockInfo) {
        sockContainer.proxyScokInfo = NULL;
    }

    if (sockContainer.ruleScokInfo == &sockInfo) {
        sockContainer.ruleScokInfo = NULL;
    }

    if (sockInfo.ssl) {
        SSL_free(sockInfo.ssl);
        sockInfo.ssl = NULL;
    }

    sockInfo.tid = NULL;
    sockInfo.wsTid = NULL;
    sockInfo.localSockInfo = NULL;

    sockInfo.reqId = 0;
    sockInfo.sockId = 0;
    sockInfo.sock = -1;
    sockInfo.state = 0;
    sockInfo.originSockFlag = 0;
    sockInfo.isNoBloack = 0;
    sockInfo.isNoCheckSSL = 0;
    sockInfo.isNoCheckSocks = 0;
    sockInfo.isProxy = 0;
    sockInfo.isWebSock = 0;
    sockInfo.recivedCloseFrame = 0;
    sockInfo.port = 0;

    sockInfo.bufSize = 0;
    sockInfo.ruleBufSize = 0;

    free(sockInfo.ip);
    sockInfo.ip = NULL;
    free(sockInfo.buf);
    sockInfo.buf = NULL;
    free(sockInfo.cipher);
    sockInfo.cipher = NULL;
    free(sockInfo.pem_cert);
    sockInfo.pem_cert = NULL;
    free(sockInfo.ruleBuf);
    sockInfo.ruleBuf = NULL;

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

    sockInfo.headSize = 0;
    sockInfo.bodySize = 0;
    sockInfo.bodyIndex = 0;
    sockInfo.ruleState = 0;

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
        pthread_mutex_init(&this->sockInfos[i].mutex, NULL);
        pthread_cond_init(&this->sockInfos[i].cond, NULL);
    }
}

SockInfo* SockContainer::getSockInfo() {
    for (int i = 0; i < MAX_SOCK; i++) {
        if (this->sockInfos[i].state == SOCK_STATE_CLOSED && (!this->sockInfos[i].remoteSockInfo || this->sockInfos[i].remoteSockInfo->state == SOCK_STATE_CLOSED)) {
            this->resetSockInfo(this->sockInfos[i]);
        }
        if (this->sockInfos[i].sockId <= 0 && !this->sockInfos[i].state) {
            timespec_get(&(this->sockInfos[i].tv), TIME_UTC);
            this->sockInfos[i].sock = 0;
            return &this->sockInfos[i];
        }
    }
    return NULL;
}

SockInfo* SockContainer::getSockInfoByReqId(u_int64_t reqId) {
    for (int i = 0; i < MAX_SOCK; i++) {
        if (!this->sockInfos[i].state && this->sockInfos[i].reqId == reqId) {
            return &this->sockInfos[i];
        }
    }
    return NULL;
}

void SockContainer::shutdownSock(SockInfo* sockInfo) {
    int singleMode = 0;
    if (!sockInfo) {
        sockInfo = (SockInfo*)pthread_getspecific(ptKey);
    } else {
        singleMode = 1; // 只关闭一端
    }

    this->closeSock(*sockInfo);
    if (!singleMode && sockInfo->remoteSockInfo) {
        this->closeSock(*sockInfo->remoteSockInfo);
        sockInfo->remoteSockInfo->state = SOCK_STATE_CLOSED;
    }

    sockInfo->state = SOCK_STATE_CLOSED; // 已关闭

    if (sockContainer.ruleScokInfo == sockInfo) {
        ruleUtils.broadcastAll();
    }
}

void SockContainer::closeSock(SockInfo& sockInfo) {
    if (sockInfo.ssl != NULL) {
        int res = SSL_shutdown(sockInfo.ssl); // 0:未完成，1:成功，-1:失败
        shutdown(sockInfo.sock, SHUT_RDWR);
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