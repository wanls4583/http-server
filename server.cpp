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
#include "regex.h"
#include "utils.h"
#include "TlsUtils.h"
#include "HttpUtils.h"

using namespace std;

static int proxyPort = 8000;
static int servSock;
static struct sockaddr_in servAddr;

SockContainer sockContainer;
TlsUtils tlsUtil;
HttpUtils httpUtils;
pthread_key_t ptKey;

int initServSock();
void* initClntSock(void* arg);
int initRemoteSock(SockInfo& sockInfo);
int forward(SockInfo& sockInfo);
void setProxyPort();
void addRootCert();
void testReg();

int main() {
    // testReg();
    // return 0;
    setProxyPort();
    addRootCert();
    signal(SIGPIPE, SIG_IGN); // 屏蔽SIGPIPE信号，防止进程退出
    pthread_key_create(&ptKey, NULL);
    servSock = initServSock();
    if (servSock < 0) {
        return -1;
    }

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
    servAddr.sin_port = htons(proxyPort);

    if (::bind(servSock, (struct sockaddr*)&servAddr, sizeof(servAddr)) == -1) {
        cout << "bind fail: " << proxyPort << endl;
        return -1;
    }

    if (listen(servSock, 10) == -1) {
        cout << "listen fail" << endl;
        return -2;
    }

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
            ssl = sockInfo.ssl = tlsUtil.getSSL(sockInfo);
            sockContainer.setNoBlock(sockInfo, 1); // 设置成非阻塞模式
        }

        sockContainer.resetSockInfoData(sockInfo); // 清除掉 CONNECT 请求的数据
        sockInfo.isNoCheckSSL = 1;
    }

    header = httpUtils.reciveHeader(sockInfo, hasError); // 读取客户端的请求头

    if (hasError) {
        sockContainer.shutdownSock();
        return NULL;
    }

    if (!header || !header->hostname || !header->method) { // 解析请求头失败
        sockContainer.resetSockInfoData(sockInfo);
        initClntSock(arg);
        return NULL;
    }

    // if (strcmp(header->hostname, "developer.mozilla.org") != 0) {
    //     sockContainer.shutdownSock();
    //     return NULL;
    // }

    httpUtils.reciveBody(sockInfo, hasError); // 读取客户端的请求体

    if (hasError) // 获取请求体失败
    {
        sockContainer.shutdownSock();
        return NULL;
    }

    if (strcmp(header->method, "CONNECT") == 0) // 客户端https代理连接请求
    {
        httpUtils.sendTunnelOk(sockInfo);
        sockInfo.isNoCheckSSL = 0; // CONNECT请求使用的是http协议，用来为https的代理建立连接，下一次请求才是真正的tls握手请求
        initClntSock(arg);
    } else if (httpUtils.checkMethod(sockInfo.header->method)) {
        if (sockInfo.header->port == proxyPort) { // 本地访问代理设置页面
            httpUtils.sendFile(sockInfo);
        } else if (sockInfo.isProxy) { // 客户端代理转发请求
            if (!sockInfo.remoteSockInfo) { // 新建远程连接
                if (!initRemoteSock(sockInfo)) {
                    sockContainer.shutdownSock();
                    return NULL;
                }
            }
            if (!forward(sockInfo)) {
                sockContainer.shutdownSock();
                return NULL;
            }
            if (sockInfo.remoteSockInfo->header->connnection && strcmp(sockInfo.remoteSockInfo->header->connnection, "close") == 0) { // 远程服务器非长连接
                sockContainer.shutdownSock();
                return NULL;
            }
        } else {
            sockContainer.shutdownSock();
            return NULL;
        }

        if (sockInfo.header->connnection && strcmp(sockInfo.header->connnection, "close") == 0) { // 客户端非长连接
            sockContainer.shutdownSock();
        } else {
            sockContainer.resetSockInfoData(sockInfo);
            initClntSock(arg);
        }
    }

    return NULL;
}

int initRemoteSock(SockInfo& sockInfo) {
    struct hostent* host = gethostbyname(sockInfo.header->hostname);

    if (!host || !host->h_length) {
        sockContainer.shutdownSock();
        return 0;
    }

    // char **pptr = host->h_addr_list;
    // char str[INET_ADDRSTRLEN];
    // for (int i = 0; *pptr != NULL; pptr++, i++) {
    //     printf("ip-%d: %s\n", i, inet_ntop(host->h_addrtype, pptr, str, sizeof(str)));
    // }

    struct sockaddr_in remoteAddr;
    int remoteSock = socket(PF_INET, SOCK_STREAM, IPPROTO_TCP);

    memset(&remoteAddr, 0, sizeof(remoteAddr));
    remoteAddr.sin_family = host->h_addrtype;
    remoteAddr.sin_addr = *((struct in_addr*)host->h_addr_list[0]);
    remoteAddr.sin_port = htons(sockInfo.header->port);

    int err = connect(remoteSock, (struct sockaddr*)&remoteAddr, sizeof(remoteAddr));
    if (err != 0) {
        cout << "connect fail:" << sockInfo.header->hostname << endl;
        return 0;
    }

    sockInfo.remoteSockInfo = (SockInfo*)calloc(1, sizeof(SockInfo));
    sockContainer.resetSockInfo(*sockInfo.remoteSockInfo);
    sockInfo.remoteSockInfo->sock = remoteSock;

    if (sockInfo.header->port == 443) {
        // SSL_load_error_strings();
        // OpenSSL_add_ssl_algorithms();

        SSL_CTX* ctx = SSL_CTX_new(SSLv23_client_method());
        SSL* ssl = SSL_new(ctx);
        sockInfo.remoteSockInfo->ssl = ssl;
        SSL_set_fd(ssl, remoteSock);
        // 将主机名称写入 ClientHello 消息中的 ServerName 扩展字段中，有些服务器建立 TLS 连接时可能会校验该字段
        SSL_set_tlsext_host_name(ssl, sockInfo.header->hostname);

        err = SSL_connect(ssl);
        if (err != 1) {
            int sslErrCode = SSL_get_error(ssl, err);
            cout << "SSL_connect fail:" << sslErrCode << endl;
            return 0;
        }
    }

    sockContainer.setNoBlock(*sockInfo.remoteSockInfo, 1); // 设置成非阻塞模式

    return 1;
}

int forward(SockInfo& sockInfo) { // 转发请求
    SockInfo& remoteSockInfo = *sockInfo.remoteSockInfo;
    HttpHeader* header = NULL;
    char* req = NULL;
    int hasError = 0;
    size_t reqSize = 0;
    ssize_t result = 0;

    httpUtils.createReqData(sockInfo, req, reqSize);

    result = httpUtils.writeData(*sockInfo.remoteSockInfo, req, reqSize); // 转发客户端请求到远程服务器

    if (READ_ERROR == result || READ_END == result) {
        return 0;
    }

    header = httpUtils.reciveHeader(*sockInfo.remoteSockInfo, hasError); // 读取远程服务器的响应头

    if (hasError) {
        return 0;
    }

    if (strcmp(sockInfo.header->method, "HEAD") != 0) { // HEAD请求没有响应体，即使有，也应该丢弃
        httpUtils.reciveBody(*sockInfo.remoteSockInfo, hasError); // 读取远程服务器的响应体

        if (hasError) {
            return 0;
        }
    }

    int dataSize = remoteSockInfo.reqSize + remoteSockInfo.bodySize;
    char* data = (char*)calloc(1, dataSize);
    memcpy(data, remoteSockInfo.head, remoteSockInfo.reqSize);

    if (remoteSockInfo.bodySize) {
        memcpy(data + remoteSockInfo.reqSize, remoteSockInfo.body, remoteSockInfo.bodySize);
    }

    result = httpUtils.writeData(sockInfo, data, dataSize); // 将远程服务器返回的数据发送给客户端
    free(data);

    if (READ_ERROR == result || READ_END == result) {
        return 0;
    }

    return 1;
}

void addRootCert() {
    string cmd = "security find-certificate -c ";
    char* cn = tlsUtil.certUtils.getRootCertNameByOid((char*)"2.5.4.3");
    char* cmdRes = runCmd((cmd + string(cn)).c_str());
    if (string(cmdRes).find("keychain:") != 0) { // 安装证书
        runCmd("security add-trusted-cert -r trustRoot -k ~/Library/Keychains/login.keychain-db rootCA/rootCA.crt ");
    }
    // 设置http代理
    runCmd(("networksetup -setwebproxy Wi-Fi 127.0.0.1 " + to_string(proxyPort)).c_str());
    // 设置https代理
    runCmd(("networksetup -setsecurewebproxy Wi-Fi 127.0.0.1 " + to_string(proxyPort)).c_str());
    // 设置socket代理
    runCmd(("networksetup -setsocksfirewallproxy Wi-Fi 127.0.0.1 " + to_string(proxyPort)).c_str());
    free(cmdRes);
}

void setProxyPort() {
    char* cmdRes;
    string cmd = "";
    for (; proxyPort < 65536; proxyPort++) {
        cmd = "lsof -i tcp:" + to_string(proxyPort);
        cmdRes = runCmd(cmd.c_str());
        if (string(cmdRes).size() > 0) {
            continue;
        } else {
            break;
        }
    }
    cout << "proxyPort: " << proxyPort << endl;
}

void testReg() {
    regex_t* r = (regex_t*)malloc(sizeof(regex_t)); //分配编译后模式的存储空间
    char* text = (char*)"asdfsddb"; //目标文本
    char* regtxt = (char*)"a[[:alpha:]]+b"; //模式
    int status = regcomp(r, regtxt, REG_EXTENDED); //编译模式
    if (status) { //处理可能的错误
        char error_message[1000];
        regerror(status, r, error_message, 1000);
        printf("Regex error compiling '%s': %s\n", text, error_message);
        return;
    }
    size_t nmatch = 3; //保存结果，每次匹配有两组$&，$1结果，分别是整体与子匹配
    regmatch_t m[nmatch];
    char* p = text;
    while (1) { //连续匹配直到行尾
        status = regexec(r, p, nmatch, m, 0); //匹配操作
        if (status == REG_NOMATCH) { //判断结束或错误
            char error_message[1000];
            regerror(status, r, error_message, 1000);
            printf("Regex Match Error '%s': %s\n", text, error_message);
            break;
        }
        int i;
        for (i = 0; i < nmatch; i++) {  //打印结果，注意regmatch_t中保存的偏移信息
            printf("%.*s, so = %d, eo = %d\n", int(m[i].rm_eo - m[i].rm_so), p + m[i].rm_so, (int)m[i].rm_so, (int)m[i].rm_eo);
        }
        p += m[0].rm_eo;
    }
    regfree(r);
}