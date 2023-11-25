#include <fstream>
#include <iostream>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
// #include <sys/malloc.h>
// #include <openssl/applink.c>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/bio.h>
#include <pthread.h>
#include <fcntl.h>
#include "utils.h"
#include "TlsUtils.h"
#include "HttpUtils.h"

using namespace std;

static const int port = 8000;
static int servSock;
static struct sockaddr_in servAddr;

SockContainer sockContainer;
TlsUtils tlsUtil;
HttpUtils httpUtils;
pthread_key_t ptKey;

int initServSock();
void *initClntSock(void *arg);

int main()
{
    pthread_key_create(&ptKey, NULL);
    servSock = initServSock();

    while (1)
    {
        struct sockaddr_in clntAddr;
        socklen_t clntAddrLen = sizeof(clntAddr);
        int clntSock = accept(servSock, (struct sockaddr *)&clntAddr, &clntAddrLen);
        char *ip = inet_ntoa(clntAddr.sin_addr);
        SockInfo *sockInfo = sockContainer.getSockInfo();
        if (sockInfo)
        {
            pthread_t tid;

            (*sockInfo).clntSock = clntSock;
            (*sockInfo).ip = (char *)calloc(1, strlen(ip) + 1); // inet_ntoa 获取到的地址永远是同一块地址
            memcpy((*sockInfo).ip, ip, strlen(ip));

            pthread_create(&tid, NULL, initClntSock, sockInfo);
            pthread_detach(tid);
            (*sockInfo).tid = tid;
        }
        else
        {
            shutdown(clntSock, SHUT_RDWR);
            close(clntSock);
        }
    }

    shutdown(servSock, SHUT_RDWR);
    close(servSock);

    return 0;
}

int initServSock()
{
    int servSock = socket(AF_INET, SOCK_STREAM, 0);

    memset(&servAddr, 0, sizeof(servAddr));

    servAddr.sin_family = AF_INET;
    // servAddr.sin_addr.s_addr = inet_addr("127.0.0.1");
    servAddr.sin_addr.s_addr = htonl(INADDR_ANY);
    servAddr.sin_port = htons(port);

    bind(servSock, (struct sockaddr *)&servAddr, sizeof(servAddr));

    listen(servSock, 10);

    return servSock;
}

void *initClntSock(void *arg)
{
    SSL *ssl;
    ssize_t bufSize = 0;
    SockInfo &sockInfo = *((SockInfo *)arg);
    HttpHeader *header = NULL;
    int clntSock = sockInfo.clntSock;
    int hasError = 0;

    if (!sockInfo.ssl)
    {
        pthread_setspecific(ptKey, arg);
        ssl = sockInfo.ssl = tlsUtil.checkSLL(clntSock);
    }

    int oldSocketFlag = fcntl(clntSock, F_GETFL, 0);
    int newSocketFlag = oldSocketFlag | O_NONBLOCK;
    if (fcntl(clntSock, F_SETFL, newSocketFlag) == -1) // 设置成非阻塞模式
    {
        shutdown(servSock, SHUT_RDWR);
        close(clntSock);
        cout << "set socket to nonblock error." << endl;
        return NULL;
    }

    header = httpUtils.reciveReqHeader(sockInfo, hasError);

    if (hasError || !header || !header->hostname) // 解析请求头失败
    {
        sockContainer.shutdownSock();
        return NULL;
    }

    httpUtils.reciveReqBody(sockInfo, hasError);

    if (hasError) // 获取请求体失败
    {
        sockContainer.shutdownSock();
        return NULL;
    }

    if (strcmp(header->method, "CONNECT") == 0)
    {
        httpUtils.sendTunnelOk(sockInfo);
        initClntSock(&sockInfo);
    }
    else if (strcmp(header->method, "GET") == 0 || strcmp(header->method, "POST") == 0)
    {
        int suc = httpUtils.sendFile(sockInfo);
        if (strcmp(sockInfo.header->connnection, "close") == 0 || suc == 0)
        {
            sockContainer.shutdownSock();
        }
        else
        {
            sockContainer.resetSockInfoData(sockInfo);
            gettimeofday(&sockInfo.tv, NULL); // 重置超时时间
            // cout << sockInfo.clntSock <<  ":" << sockInfo.tv.tv_sec << ":" << sockInfo.tv.tv_usec << endl;
            initClntSock(arg);
        }
    }

    return NULL;
}