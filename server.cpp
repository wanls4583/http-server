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
#include "SockContainer.h"

using namespace std;

enum { MSG_REQ = 1, MSG_RES, MSG_DNS, MSG_STATUS, MSG_TIME, MSG_CIPHER, MSG_CERT, MSG_PORT };
enum { STATUS_FAIL_CONNECT = 1, STATUS_FAIL_SSL_CONNECT };

static int proxyPort = 8000;
static int servSock;
static struct sockaddr_in servAddr;

SockContainer sockContainer;
TlsUtils tlsUtil;
HttpUtils httpUtils;
WsUtils wsUtils;
pthread_key_t ptKey;

int initServSock();
void* initClntSock(void* arg);
int initRemoteSock(SockInfo& sockInfo);
int forward(SockInfo& sockInfo);
void* forwardWebocket(void* arg);
int initLocalWebscoket(SockInfo& sockInfo);
void setProxyPort();
void addRootCert();
void sendRecordToLacal(SockInfo& sockInfo, int type, char* data, ssize_t size);

int main() {
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
        if (sock < 0) {
            continue;
        }

        char* ip = inet_ntoa(clntAddr.sin_addr);
        SockInfo* sockInfo = sockContainer.getSockInfo();
        if (sockInfo) {
            pthread_t tid;

            (*sockInfo).sock = sock;
            (*sockInfo).sockId = sockContainer.sockId++;
            (*sockInfo).port = ntohs(clntAddr.sin_port);
            (*sockInfo).originSockFlag = fcntl(sock, F_GETFL, 0);
            (*sockInfo).ip = (char*)calloc(strlen(ip) + 1, 1); // inet_ntoa 获取到的地址永远是同一块地址
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
    sendRecordToLacal(sockInfo, MSG_PORT, NULL, 0);

    if (!sockInfo.isNoCheckSSL) {
        httpUtils.preReciveHeader(sockInfo, hasError);
        if (hasError) {
            sockContainer.shutdownSock();
            return NULL;
        }
        if (sockInfo.tlsHeader) { // https/wss会先建立tls连接
            sockContainer.setNoBlock(sockInfo, 0); // ssl握手需要在阻塞模式下
            ssl = sockInfo.ssl = tlsUtil.getSSL(sockInfo);
            sockContainer.setNoBlock(sockInfo, 1); // 设置成非阻塞模式
            sockInfo.isNoCheckSocks = 1;
        }
        sockContainer.resetSockInfoData(sockInfo); // 清除掉 CONNECT 请求的数据
        sockInfo.isNoCheckSSL = 1;
    }

    if (!sockInfo.isNoCheckSocks) {
        httpUtils.preReciveHeader(sockInfo, hasError);
        if (hasError) {
            sockContainer.shutdownSock();
            return NULL;
        }
        sockInfo.isNoCheckSocks = 1;
        if (sockInfo.socksHeader) {
            httpUtils.freeData(sockInfo); // 消耗掉流中的数据
            httpUtils.sendSocksOk(sockInfo);
            httpUtils.reciveSocksReqHeader(sockInfo, hasError);
            if (hasError) {
                sockContainer.shutdownSock();
                return NULL;
            }
            httpUtils.sendSocksRes(sockInfo);
            sockInfo.isNoCheckSSL = 0; // socks5可以代理https协议
            // 开始转发，注意：使用socks5代理，不会发送CONNECT请求，而是直接发送http/https/ws/wss请求
            initClntSock(arg);
            return NULL;
        }
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

    sockInfo.reqId = sockContainer.reqId++;

    if (strcmp(header->method, "CONNECT") == 0) // 客户端https代理连接请求
    {
        // https/ws/wss，代理客户端会先发送CONNECT请求
        // "CONNECT my.test.com:8000 HTTP/1.1\r\n
        // Host: my.test.com:8000r\n
        // Proxy-Connection: keep-aliver\n
        // r\n"
        httpUtils.sendTunnelOk(sockInfo);
        sockInfo.isNoCheckSSL = 0; // CONNECT请求使用的是http协议，用来为https的代理建立连接，下一次请求才是真正的tls握手请求
        initClntSock(arg);
    } else if (httpUtils.checkMethod(sockInfo.header->method)) {
        if (sockInfo.header->port == proxyPort) { // 本地访问代理设置页面
            // wbscoket升级请求，ws/wss：
            // "GET / HTTP/1.1r\n
            // Host: my.test.com:8000r\n
            // Connection: Upgrader\n
            // Pragma: no-cacher\n
            // Cache-Control: no-cacher\n
            // Upgrade: websocketr\n
            // Origin: http://my.test.com:8000r\n
            // Sec-WebSocket-Version: 13r\n
            // Accept-Encoding: gzip, deflater\n
            // Accept-Language: zh-CN,zh;q=0.9,en;q=0.8,zh-TW;q=0.7r\n
            // Sec-WebSocket-Key: NEerQfgc8XgSwPhADPkkIg==r\n
            // r\n"
            if (sockInfo.header->connnection && sockInfo.header->upgrade &&
                !strcmp(sockInfo.header->connnection, "Upgrade") && !strcmp(sockInfo.header->upgrade, "websocket")) {
                httpUtils.sendUpgradeOk(sockInfo);
                initLocalWebscoket(sockInfo);
                return NULL;
            } else {
                httpUtils.sendFile(sockInfo);
            }
        } else if (sockInfo.isProxy) { // 客户端代理转发请求
            char* req;
            ssize_t reqSize;
            httpUtils.createReqData(sockInfo, req, reqSize);
            sendRecordToLacal(sockInfo, MSG_REQ, req, reqSize);
            gettimeofday(&sockInfo.forward_start_tv, NULL);

            if (!sockInfo.remoteSockInfo) { // 新建远程连接
                if (!initRemoteSock(sockInfo)) {
                    sockContainer.shutdownSock();
                    return NULL;
                }
            } else {
                sendRecordToLacal(sockInfo, MSG_DNS, sockInfo.remoteSockInfo->ip, strlen(sockInfo.remoteSockInfo->ip));
            }

            if (sockInfo.remoteSockInfo->cipher) {
                sendRecordToLacal(sockInfo, MSG_CIPHER, sockInfo.remoteSockInfo->cipher, -1);
            }
            if (sockInfo.remoteSockInfo->pem_cert) {
                sendRecordToLacal(sockInfo, MSG_CERT, sockInfo.remoteSockInfo->pem_cert, -1);
            }

            if (!forward(sockInfo)) {
                sockContainer.shutdownSock();
                return NULL;
            }

            if (sockInfo.isWebSock) { // websocket连接
                return NULL;
            }

            if (!sockInfo.remoteSockInfo->header->connnection ||
                sockInfo.remoteSockInfo->header->connnection && strcmp(sockInfo.remoteSockInfo->header->connnection, "close") == 0) { // 远程服务器非长连接
                sockContainer.shutdownSock(sockInfo.remoteSockInfo);
                sockInfo.remoteSockInfo = NULL;
            }
        } else {
            sockContainer.shutdownSock();
            return NULL;
        }

        if (sockInfo.header) {
            if (!sockInfo.header->connnection && !sockInfo.header->proxyConnection ||
                sockInfo.header->connnection && strcmp(sockInfo.header->connnection, "close") == 0 ||
                sockInfo.header->proxyConnection && strcmp(sockInfo.header->proxyConnection, "close") == 0) { // 客户端非长连接
                sockContainer.shutdownSock();
            } else {
                sockContainer.resetSockInfoData(sockInfo);
                initClntSock(arg);
            }
        } else {
            sockContainer.shutdownSock();
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

    char* ip = (char*)calloc(INET_ADDRSTRLEN, 1);
    inet_ntop(host->h_addrtype, host->h_addr_list[0], ip, INET_ADDRSTRLEN);
    sendRecordToLacal(sockInfo, MSG_DNS, ip, strlen(ip));

    int err = connect(remoteSock, (struct sockaddr*)&remoteAddr, sizeof(remoteAddr));
    if (err != 0) {
        char status = STATUS_FAIL_CONNECT;
        sendRecordToLacal(sockInfo, MSG_STATUS, &status, 1);
        cout << "connect fail:" << sockInfo.header->hostname << endl;
        return 0;
    }

    sockInfo.remoteSockInfo = (SockInfo*)calloc(1, sizeof(SockInfo));
    sockContainer.resetSockInfo(*sockInfo.remoteSockInfo);
    sockInfo.remoteSockInfo->ip = ip;
    sockInfo.remoteSockInfo->sock = remoteSock;
    sockInfo.remoteSockInfo->localSockInfo = &sockInfo;

    if (sockInfo.ssl) {
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
            char status = STATUS_FAIL_SSL_CONNECT;
            sendRecordToLacal(sockInfo, MSG_STATUS, &status, 1);
            cout << "SSL_connect fail:" << sslErrCode << endl;
            return 0;
        } else {
            // 获取当前cipher和可选cipher列表--begin
            char* cipher_buf = (char*)calloc(2000, 1);
            int index = 0;
            const char* current_cipher = SSL_get_cipher(ssl); // TLS_AES_128_GCM_SHA256
            memcpy(cipher_buf, current_cipher, strlen(current_cipher));
            index += strlen(current_cipher);

            for (int i = 0; ; i++) {
                const char* cipher = SSL_get_cipher_list(ssl, i);
                if (cipher) {
                    cipher_buf[index++] = ';';
                    memcpy(cipher_buf + index, cipher, strlen(cipher));
                    index += strlen(cipher);
                } else {
                    break;
                }
            }
            sockInfo.remoteSockInfo->cipher = cipher_buf;
            // 获取当前cipher和可选cipher列表--end

            // 获取服务器证书--begin
            long size = 0;
            char* buf = NULL;

            X509* x509 = SSL_get_peer_certificate(ssl);
            FILE* pemFile = fopen("./tmp.pem", "w+");
            PEM_write_X509(pemFile, x509);

            size = ftell(pemFile);
            buf = (char*)calloc(size, 1);

            fseek(pemFile, 0, SEEK_SET);
            fread(buf, size, 1, pemFile);
            fclose(pemFile);
            sockInfo.remoteSockInfo->pem_cert = buf;
            // 获取服务器证书--end
        }
    }

    sockContainer.setNoBlock(*sockInfo.remoteSockInfo, 1); // 设置成非阻塞模式

    return 1;
}

int initLocalWebscoket(SockInfo& sockInfo) {
    int hasError = 0;
    if (sockContainer.wsScokInfo) {
        if (sockContainer.wsScokInfo->sockId == sockInfo.sockId) {
            return 0;
        }
        sockContainer.shutdownSock(&sockInfo);
    }
    sockContainer.wsScokInfo = &sockInfo;
    while (sockContainer.wsScokInfo == &sockInfo) {
        WsFragment* wsFragment = httpUtils.reciveWsFragment(sockInfo, hasError);
        if (hasError) {
            sockContainer.shutdownSock(&sockInfo);
            break;
        }
        if (wsFragment) {
            if (wsFragment->opCode == 0x08) { // 关闭
                sockContainer.shutdownSock(&sockInfo);
                cout << "ws:close" << endl;
                break;
            }
            if (wsUtils.fragmentComplete(sockInfo.wsFragment)) { // 消息接收完整
                char* msg = (char*)wsUtils.getMsg(sockInfo.wsFragment);
                cout << "ws:" << msg << endl;
                wsUtils.freeFragment(sockInfo.wsFragment);
                sockInfo.wsFragment = NULL;
                if (strcmp(msg, "close") == 0) {
                    sockContainer.shutdownSock(&sockInfo);
                } else if (strcmp(msg, "start") == 0) {
                    wsUtils.sendMsg(sockInfo, (unsigned char*)"staet", 4);
                } else if (strcmp(msg, "ping") == 0) {
                    wsUtils.sendMsg(sockInfo, (unsigned char*)"pong", 4);
                }
            }
        }
    }

    return 0;
}

void sendRecordToLacal(SockInfo& sockInfo, int type, char* data, ssize_t size) {
    if (!sockContainer.wsScokInfo) {
        return;
    }
    size = !data ? 0 : size;
    size = size == -1 ? strlen(data) : size;

    int index = 0;
    int idSize = 8;
    int pid = 0;
    ssize_t bufSize = idSize * 2 + 1 + size;
    u_int64_t reqId = htonll(sockInfo.reqId);
    u_int64_t sockId = htonll(sockInfo.sockId);

    if (type == MSG_REQ) {
        bufSize += 7;
        // 频繁使用popen调用命令行将导致内存泄漏
        // char* p = findPidByPort(sockInfo.port);
        // if (p) {
        //     pid = atoi(p);
        // }
    } else if (type == MSG_PORT) {
        bufSize += 2;
    }

    unsigned char* msg = (unsigned char*)calloc(bufSize, 1);

    msg[index++] = type; // msg_type
    memcpy(msg + index, &reqId, idSize);
    index += idSize;
    memcpy(msg + index, &sockId, idSize);
    index += idSize;
    if (type == MSG_REQ) {
        if (sockInfo.header && sockInfo.header->upgrade && strcmp(sockInfo.header->upgrade, "websocket") == 0) {
            msg[index++] = sockInfo.ssl ? 4 : 3; // wss/ws
        } else {
            msg[index++] = sockInfo.ssl ? 2 : 1; // https/http
        }

        int p = htonl(pid);
        memcpy(msg + index, &p, 4); // 代理程序进程号
        index += 4;

        unsigned short pt = htons(sockInfo.port);
        memcpy(msg + index, &pt, 2); // 客户端的端口
        index += 2;
    } else if (type == MSG_PORT) {
        unsigned short pt = htons(sockInfo.port);
        memcpy(msg + index, &pt, 2); // 客户端的端口
        index += 2;
    }
    if (data && size > 0) {
        memcpy(msg + index, data, size);
    }

    wsUtils.sendMsg(*sockContainer.wsScokInfo, msg, bufSize);
    free(msg);
}

int forward(SockInfo& sockInfo) { // 转发http/https请求
    SockInfo& remoteSockInfo = *sockInfo.remoteSockInfo;
    HttpHeader* header = NULL;
    char* req = NULL;
    int hasError = 0;
    ssize_t reqSize = 0;
    ssize_t result = 0;

    httpUtils.createReqData(sockInfo, req, reqSize);
    result = httpUtils.writeData(*sockInfo.remoteSockInfo, req, reqSize); // 转发客户端请求到远程服务器
    free(req);

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
    char* data = (char*)calloc(dataSize, 1);
    memcpy(data, remoteSockInfo.head, remoteSockInfo.reqSize);

    if (remoteSockInfo.bodySize) {
        memcpy(data + remoteSockInfo.reqSize, remoteSockInfo.body, remoteSockInfo.bodySize);
    }

    result = httpUtils.writeData(sockInfo, data, dataSize); // 将远程服务器返回的数据发送给客户端
    sendRecordToLacal(sockInfo, MSG_RES, data, dataSize);
    free(data);

    u_int64_t duration = 0;
    gettimeofday(&sockInfo.forward_end_tv, NULL);
    duration = sockInfo.forward_end_tv.tv_sec * 1000000 + sockInfo.forward_end_tv.tv_usec -
        (sockInfo.forward_start_tv.tv_sec * 1000000 + sockInfo.forward_start_tv.tv_usec);
    duration = htonll(duration);
    sendRecordToLacal(sockInfo, MSG_TIME, (char*)(&duration), sizeof(u_int64_t));

    if (READ_ERROR == result || READ_END == result) {
        return 0;
    }

    if (header->status == 101 && header->upgrade && strcmp(header->upgrade, "websocket") == 0) { // webscoket连接成功
        pthread_t localTid;
        pthread_t remoteTid;

        pthread_create(&localTid, NULL, forwardWebocket, &sockInfo);
        pthread_detach(localTid);
        pthread_create(&remoteTid, NULL, forwardWebocket, sockInfo.remoteSockInfo);
        pthread_detach(remoteTid);

        // pthread_t为结构体，引用赋值需要再初始化以后再赋值，否则里面的元素是空的
        sockInfo.wsTid = localTid;
        sockInfo.remoteSockInfo->wsTid = remoteTid;
    }

    return 1;
}

void* forwardWebocket(void* arg) { // 转发webscoket请求
    SockInfo& sockInfo = *((SockInfo*)arg);
    int hasError = 0;
    while (1) {
        WsFragment* wsFragment = httpUtils.reciveWsFragment(sockInfo, hasError);
        if (hasError) {
            break;
        }
        unsigned char* buf = wsUtils.createMsg(wsFragment);
        if (sockInfo.remoteSockInfo) {
            httpUtils.writeData(*sockInfo.remoteSockInfo, (char*)buf, wsFragment->fragmentSize);
        } else if (sockInfo.localSockInfo) {
            httpUtils.writeData(*sockInfo.localSockInfo, (char*)buf, wsFragment->fragmentSize);
        }
    }

    return NULL;
}

void addRootCert() {
    string cmd = "security find-certificate -c ";
    char* cn = tlsUtil.certUtils.getRootCertNameByOid((char*)"2.5.4.3");
    char* cmdRes = runCmd((cmd + string(cn)).c_str());
    if (cmdRes && string(cmdRes).find("keychain:") != 0) { // 安装证书
        free(cmdRes);
        cmdRes = runCmd("security add-trusted-cert -r trustRoot -k ~/Library/Keychains/login.keychain-db rootCA/rootCA.crt ");
        free(cmdRes);
    }
    // 设置http代理
    cmdRes = runCmd(("networksetup -setwebproxy Wi-Fi 127.0.0.1 " + to_string(proxyPort)).c_str());
    free(cmdRes);
    // 设置https代理
    cmdRes = runCmd(("networksetup -setsecurewebproxy Wi-Fi 127.0.0.1 " + to_string(proxyPort)).c_str());
    free(cmdRes);
    // 设置socket代理
    cmdRes = runCmd(("networksetup -setsocksfirewallproxy Wi-Fi 127.0.0.1 " + to_string(proxyPort)).c_str());
    free(cmdRes);
}

void setProxyPort() {
    char* cmdRes;
    string cmd = "";
    for (; proxyPort < 65536; proxyPort++) {
        cmd = "lsof -i tcp:" + to_string(proxyPort);
        cmdRes = runCmd(cmd.c_str());
        if (cmdRes && string(cmdRes).size() > 0) {
            continue;
        } else {
            break;
        }
    }
    free(cmdRes);
    cout << "proxyPort: " << proxyPort << endl;
}