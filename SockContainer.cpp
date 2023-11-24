#include "SockContainer.h"

using namespace std;

extern pthread_key_t ptKey;

SockContainer::SockContainer() : timeout(5)
{
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
    sockInfo.tid = NULL;
    sockInfo.clntSock = -1;
    sockInfo.bufSize = 0;
    sockInfo.reqSize = 0;
    sockInfo.bodySize = 0;
    sockInfo.tv.tv_sec = 0;
    sockInfo.tv.tv_usec = 0;
    sockInfo.closing = 0;
    pthread_mutex_unlock(&sockContainerMutex);
}

void SockContainer::resetSockInfoData(SockInfo &sockInfo)
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
    free(sockInfo.req);
    free(sockInfo.body);
    free(sockInfo.buf);

    sockInfo.header = NULL;
    sockInfo.req = NULL;
    sockInfo.body = NULL;
    sockInfo.buf = NULL;
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

SockInfo *SockContainer::getSockInfo()
{
    pthread_mutex_lock(&sockContainerMutex);
    for (int i = 0; i < MAX_SOCK; i++)
    {
        if (this->sockInfos[i].clntSock == -1 && !this->sockInfos[i].closing)
        {
            gettimeofday(&(this->sockInfos[i].tv), NULL);
            pthread_mutex_unlock(&sockContainerMutex);
            return &this->sockInfos[i];
        }
    }
    pthread_mutex_unlock(&sockContainerMutex);
    return NULL;
}

void SockContainer::shutdownSock(SockInfo *sockInfo)
{
    // pthread_mutex_lock(&sockContainerMutex);
    if (!sockInfo)
    {
        sockInfo = (SockInfo *)pthread_getspecific(ptKey);
    }
    if (sockInfo->clntSock == -1) // 线程已经退出
    {
        // pthread_mutex_unlock(&sockContainerMutex);
        return;
    }
    sockInfo->closing = 1; // 关闭中
    if (sockInfo->ssl != NULL)
    {
        int res = SSL_shutdown(sockInfo->ssl);
        sleep(1);
        if (res == 0)
        { // 0:未完成，1:成功，-1:失败
            // pthread_mutex_unlock(&sockContainerMutex);
            this->shutdownSock(sockInfo);
            return;
        }
        else
        {
            SSL_free(sockInfo->ssl);
        }
    }
    pthread_t tid = sockInfo->tid;

    shutdown(sockInfo->clntSock, SHUT_RDWR);
    close(sockInfo->clntSock);

    // pthread_mutex_unlock(&sockContainerMutex);

    this->resetSockInfo(*sockInfo);
    pthread_cancel(tid);
}

void SockContainer::checkSockTimeout()
{
    struct timeval tv;
    gettimeofday(&tv, NULL);
    // cout << tv.tv_sec << endl;
    for (int i = 0; i < MAX_SOCK; i++)
    {
        if (this->sockInfos[i].clntSock != -1)
        {
            if (tv.tv_sec - this->sockInfos[i].tv.tv_sec >= this->timeout)
            {
                this->shutdownSock(&this->sockInfos[i]);
            }
        }
    }
}