#include <fstream>
#include <iostream>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netdb.h>
// #include <sys/malloc.h>
// #include <openssl/applink.c>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/bio.h>
#include <pthread.h>
#include "utils.h"
#include "TlsUtils.h"
#include "HttpUtils.h"

using namespace std;

static const int port = 8001;
static int servSock;
static struct sockaddr_in servAddr;

SockContainer sockContainer;
TlsUtils tlsUtil;
HttpUtils httpUtils;
pthread_key_t ptKey;

int initServSock();
void* initClntSock(void* arg);
void initRemoteSock(SockInfo& sockInfo);
int forward(SockInfo& sockInfo);
void addRootCert();

int main() {
    addRootCert();
    signal(SIGPIPE, SIG_IGN); // 屏蔽SIGPIPE信号，防止进程退出
    pthread_key_create(&ptKey, NULL);
    servSock = initServSock();

    while (1) {
        struct sockaddr_in clntAddr;
        socklen_t clntAddrLen = sizeof(clntAddr);
        int sock = accept(servSock, (struct sockaddr*)&clntAddr, &clntAddrLen);
        char* ip = inet_ntoa(clntAddr.sin_addr);
        SockInfo* sockInfo = sockContainer.getSockInfo();
        if (sockInfo) {
            pthread_t tid;

            (*sockInfo).sock = sock;
            (*sockInfo).originSockFlag = fcntl(sock, F_GETFL, 0);
            (*sockInfo).ip = (char*)calloc(1, strlen(ip) + 1); // inet_ntoa 获取到的地址永远是同一块地址
            memcpy((*sockInfo).ip, ip, strlen(ip));

            pthread_create(&tid, NULL, initClntSock, sockInfo);
            pthread_detach(tid);
            (*sockInfo).tid = tid;
        } else {
            shutdown(sock, SHUT_RDWR);
            close(sock);
        }
    }

    shutdown(servSock, SHUT_RDWR);
    close(servSock);

    return 0;
}

int initServSock() {
    int servSock = socket(AF_INET, SOCK_STREAM, 0);

    memset(&servAddr, 0, sizeof(servAddr));

    servAddr.sin_family = AF_INET;
    // servAddr.sin_addr.s_addr = inet_addr("127.0.0.1");
    servAddr.sin_addr.s_addr = htonl(INADDR_ANY);
    servAddr.sin_port = htons(port);

    bind(servSock, (struct sockaddr*)&servAddr, sizeof(servAddr));

    listen(servSock, 10);

    return servSock;
}

void* initClntSock(void* arg) {
    SSL* ssl;
    ssize_t bufSize = 0;
    SockInfo& sockInfo = *((SockInfo*)arg);
    HttpHeader* header = NULL;
    int sock = sockInfo.sock;
    int hasError = 0;

    if (sockInfo.closing || -1 == sockInfo.sock) {
        return NULL;
    }

    pthread_setspecific(ptKey, arg);
    sockContainer.setNoBlock(sockInfo, 1); // 设置成非阻塞模式

    if (!sockInfo.isNoCheckSSL) {
        httpUtils.reciveTlsHeader(sockInfo, hasError);

        if (hasError) {
            sockContainer.shutdownSock();
            return NULL;
        }

        if (httpUtils.isClntHello(sockInfo)) {
            sockContainer.setNoBlock(sockInfo, 0); // ssl握手需要在阻塞模式下
            ssl = sockInfo.ssl = tlsUtil.getSSL(sock);
            sockContainer.setNoBlock(sockInfo, 1); // 设置成非阻塞模式
        }

        sockInfo.isNoCheckSSL = 1;
    }

    header = httpUtils.reciveHeader(sockInfo, hasError);

    if (hasError) {
        sockContainer.shutdownSock();
        return NULL;
    }

    if (!header || !header->hostname || !header->method) { // 解析请求头失败
        sockContainer.resetSockInfoData(sockInfo);
        initClntSock(arg);
        return NULL;
    }

    httpUtils.reciveBody(sockInfo, hasError);

    if (hasError) // 获取请求体失败
    {
        sockContainer.shutdownSock();
        return NULL;
    }

    if (strcmp(header->method, "CONNECT") == 0) // 客户端https代理连接请求
    {
        httpUtils.sendTunnelOk(sockInfo);
        sockContainer.resetSockInfoData(sockInfo);
        sockInfo.isNoCheckSSL = 0; // CONNECT请求为https的代理连接请求，下一次请求才是真正的tls握手请求
        sockInfo.header->isProxyHeader = 1;
        initClntSock(arg);
    } else if (strcmp(header->method, "GET") == 0 || strcmp(header->method, "POST") == 0) {
        if (strcmp(sockInfo.header->hostname, "proxy.lisong.hn.cn") == 0) { // 本地访问代理设置页面
            httpUtils.sendFile(sockInfo);
        } else if (sockInfo.header->isProxyHeader) { // 客户端代理转发请求
            if (!sockInfo.remoteSockInfo) { // 新建远程连接
                initRemoteSock(sockInfo);
            }
            if (!forward(sockInfo)) {
                sockContainer.shutdownSock();
                return NULL;
            }
        } else {
            sockContainer.shutdownSock();
            return NULL;
        }

        if (sockInfo.header->connnection && strcmp(sockInfo.header->connnection, "close") == 0) {
            sockContainer.shutdownSock();
        } else {
            sockContainer.resetSockInfoData(sockInfo);
            initClntSock(arg);
        }
    }

    return NULL;
}

void initRemoteSock(SockInfo& sockInfo) {
    struct hostent* host = gethostbyname(sockInfo.header->hostname);

    if (!host->h_length) {
        sockContainer.shutdownSock();
        return;
    }

    struct sockaddr_in remoteAddr;
    int remoteSock = socket(PF_INET, SOCK_STREAM, IPPROTO_TCP);

    memset(&remoteAddr, 0, sizeof(remoteAddr));
    remoteAddr.sin_family = host->h_addrtype;
    remoteAddr.sin_addr = *((struct in_addr*)host->h_addr_list[0]);
    remoteAddr.sin_port = htons(sockInfo.header->port);
    connect(remoteSock, (struct sockaddr*)&remoteAddr, sizeof(remoteAddr));

    sockInfo.remoteSockInfo = (SockInfo*)calloc(1, sizeof(SockInfo));
    sockContainer.resetSockInfo(*sockInfo.remoteSockInfo);
    sockInfo.remoteSockInfo->sock = remoteSock;
}

int forward(SockInfo& sockInfo) { // 转发请求
    string req = httpUtils.createReqData(sockInfo);
    HttpHeader* header = NULL;
    int hasError = 0;
    ssize_t result = 0;

    result = httpUtils.writeData(*sockInfo.remoteSockInfo, (char*)req.c_str(), req.size());

    if (READ_ERROR == result || READ_END == result) {
        return 0;
    }

    header = httpUtils.reciveHeader(*sockInfo.remoteSockInfo, hasError);

    if (hasError) {
        return 0;
    }

    httpUtils.reciveBody(*sockInfo.remoteSockInfo, hasError);

    if (hasError) {
        return 0;
    }

    string data = sockInfo.remoteSockInfo->head;
    data += sockInfo.remoteSockInfo->body;

    result = httpUtils.writeData(sockInfo, (char*)data.c_str(), data.size());

    if (READ_ERROR == result || READ_END == result) {
        return 0;
    }

    return 1;
}

void addRootCert() {
    char* str = runCmd("security find-certificate -c lisong.hn.cn");
    if (string(str).find("keychain:") != 0) { // 安装证书
        runCmd("security add-trusted-cert -r trustRoot -k ~/Library/Keychains/login.keychain-db rootCA/rootCA.crt ");
    }
    free(str);
}