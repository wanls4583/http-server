#include "SockContainer.h"

SockContainer::SockContainer() {
    pthread_mutex_init(&sockContainerMutex, NULL);
    this->initSockInfos();
}

SockContainer::~SockContainer()
{
    this->initSockInfos();
}

void SockContainer::resetSockInfo(SockInfo &sockInfo)
{
    pthread_mutex_lock(&sockContainerMutex);
    if (sockInfo.header)
    {
        free(sockInfo.header->hostname);
        free(sockInfo.header->protocol);
        free(sockInfo.header->path);
        free(sockInfo.header->url);
        free(sockInfo.header->method);
        free(sockInfo.header->contentType);
        free(sockInfo.header->boundary);
        free(sockInfo.header->connnection);
        free(sockInfo.header->proxyConnection);
        free(sockInfo.header->userAgent);
        free(sockInfo.header->accept);
        free(sockInfo.header->referer);
        free(sockInfo.header->acceptEncoding);
        free(sockInfo.header->acceptLanguage);
        free(sockInfo.header);
    }
    free(sockInfo.ssl);
    free(sockInfo.ip);
    free(sockInfo.req);
    free(sockInfo.body);
    free(sockInfo.buf);

    sockInfo.header = NULL;
    sockInfo.ssl = NULL;
    sockInfo.ip = NULL;
    sockInfo.req = NULL;
    sockInfo.body = NULL;
    sockInfo.buf = NULL;
    sockInfo.clntSock = -1;
    sockInfo.bufSize = 0;
    sockInfo.reqSize = 0;
    sockInfo.bodySize = 0;
    pthread_mutex_unlock(&sockContainerMutex);
}

void SockContainer::initSockInfos()
{
    for (int i = 0; i < MAX_SOCK; i++)
    {
        this->resetSockInfo(this->sockInfos[i]);
    }
}

SockInfo *SockContainer::getSockInfo() {
    pthread_mutex_lock(&sockContainerMutex);
    for (int i = 0; i < MAX_SOCK; i++)
    {
        if (this->sockInfos[i].clntSock == -1) {
            pthread_mutex_unlock(&sockContainerMutex);
            return &this->sockInfos[i];
        }
    }
    pthread_mutex_unlock(&sockContainerMutex);
    return NULL;
}