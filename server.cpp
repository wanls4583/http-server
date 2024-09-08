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
#include "V8Utils.h"
#include "SockContainer.h"

using namespace std;

enum { MSG_REQ_HEAD = 1, MSG_REQ_BODY, MSG_REQ_BODY_END, MSG_RES_HEAD, MSG_RES_BODY, MSG_RES_BODY_END, MSG_DNS, MSG_STATUS, MSG_TIME, MSG_CIPHER, MSG_CERT, MSG_PORT };
enum { STATUS_FAIL_CONNECT = 1, STATUS_FAIL_SSL_CONNECT };
enum { TIME_DNS_START = 1, TIME_DNS_END, TIME_CONNECT_START, TIME_CONNECT_END, TIME_CONNECT_SSL_START, TIME_CONNECT_SSL_END, TIME_REQ_START, TIME_REQ_END, TIME_RES_START, TIME_RES_END };

static int proxyPort = 8000;
static int servSock;
static struct sockaddr_in servAddr;

SockContainer sockContainer;
TlsUtils tlsUtil;
HttpUtils httpUtils;
WsUtils wsUtils;
pthread_key_t ptKey;
pthread_mutex_t pemMutex;
pthread_mutex_t sendRecordMutex;
char* scriptScource = NULL;

int initServSock();
void* initV8Loop(void* arg);
void* initClntSock(void* arg);
int initRemoteSock(SockInfo& sockInfo);
ssize_t getChunkSize(SockInfo& sockInfo, ssize_t& numSize);
int reciveBody(SockInfo& sockInfo);
int forward(SockInfo& sockInfo);
void* forwardWebocket(void* arg);
int initLocalWebscoket(SockInfo& sockInfo, int type);
void setProxyPort();
void addRootCert();
void sendRecordToLacal(SockInfo& sockInfo, SockInfo* wsSockInfo, int type, char* data, ssize_t size);
void sendTimeToLacal(SockInfo& sockInfo, int timeType);

int main() {
    setProxyPort();
    addRootCert();
    signal(SIGPIPE, SIG_IGN); // 屏蔽SIGPIPE信号，防止进程退出
    pthread_mutex_init(&pemMutex, NULL);
    pthread_mutex_init(&sendRecordMutex, NULL);
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
            // cout << "pthread_create:" << (*sockInfo).sockId << ":" << (*sockInfo).sock << endl;
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

    // cout << "initClntSock:" << sockInfo.sockId << ":" << sockInfo.sock << endl;
    pthread_setspecific(ptKey, arg);
    sockContainer.setNoBlock(sockInfo, 1); // 设置成非阻塞模式
    sendRecordToLacal(sockInfo, sockContainer.proxyScokInfo, MSG_PORT, NULL, 0);

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

            // 获取当前cipher和可选cipher列表--begin
            char* cipher_buf = (char*)calloc(2000, 1);
            int index = 0;
            const char* version = SSL_get_version(ssl);
            const char* current_cipher = SSL_get_cipher(ssl); // TLS_AES_128_GCM_SHA256
            memcpy(cipher_buf, version, strlen(version));
            index += strlen(version);
            cipher_buf[index++] = ';';
            memcpy(cipher_buf + index, current_cipher, strlen(current_cipher));
            index += strlen(current_cipher);

            STACK_OF(SSL_CIPHER)* ciphers = SSL_get_client_ciphers(ssl);
            for (int i = 0; i < sk_SSL_CIPHER_num(ciphers); i++) {
                const SSL_CIPHER* c = sk_SSL_CIPHER_value(ciphers, i);
                const char* cipher = SSL_CIPHER_get_name(c);
                if (cipher) {
                    cipher_buf[index++] = ';';
                    memcpy(cipher_buf + index, cipher, strlen(cipher));
                    index += strlen(cipher);
                }
            }
            sockInfo.cipher = cipher_buf;
            // 获取当前cipher和可选cipher列表--end
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
                if (!strcmp(sockInfo.header->path, "/proxy")) {
                    httpUtils.sendUpgradeOk(sockInfo);
                    initLocalWebscoket(sockInfo, 1);
                } else if (!strcmp(sockInfo.header->path, "/rule")) {
                    httpUtils.sendUpgradeOk(sockInfo);
                    initLocalWebscoket(sockInfo, 2);
                } else {
                    sockContainer.shutdownSock();
                }
                return NULL;
            } else {
                httpUtils.sendFile(sockInfo);
            }
        } else if (sockInfo.isProxy) { // 客户端代理转发请求
            char* req;
            ssize_t reqSize;
            httpUtils.createReqData(sockInfo, req, reqSize);
            sendRecordToLacal(sockInfo, sockContainer.proxyScokInfo, MSG_REQ_HEAD, req, reqSize);
            if (sockInfo.cipher) {
                sendRecordToLacal(sockInfo, sockContainer.proxyScokInfo, MSG_CIPHER, sockInfo.cipher, -1);
            }

            if (!sockInfo.remoteSockInfo) { // 新建远程连接
                if (!initRemoteSock(sockInfo)) {
                    usleep(1000 * 500); // 留出时间供客户端根据端口查询进程
                    sockContainer.shutdownSock();
                    return NULL;
                }
            } else {
                sockInfo.remoteSockInfo->reqId = sockInfo.reqId;
                sendRecordToLacal(sockInfo, sockContainer.proxyScokInfo, MSG_DNS, sockInfo.remoteSockInfo->ip, strlen(sockInfo.remoteSockInfo->ip));
            }

            if (sockInfo.remoteSockInfo->pem_cert) {
                sendRecordToLacal(sockInfo, sockContainer.proxyScokInfo, MSG_CERT, sockInfo.remoteSockInfo->pem_cert, -1);
            }

            if (!forward(sockInfo)) {
                if (!sockInfo.isWebSock) { // websocket通过单边去关闭
                    sockContainer.shutdownSock();
                }
                return NULL;
            }

            if (!(sockInfo.header->upgradeInsecureRequests || sockInfo.header->authorization) || // 对于需要验证密码的请求，客户端验证后会带上Authorization请求头
                sockInfo.remoteSockInfo->header->connnection && strcmp(sockInfo.remoteSockInfo->header->connnection, "close") == 0) { // 远程服务器非长连接
                sockContainer.shutdownSock();
                return NULL;
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
    sendTimeToLacal(sockInfo, TIME_DNS_START);
    struct hostent* host = gethostbyname(sockInfo.header->hostname);
    sendTimeToLacal(sockInfo, TIME_DNS_END);

    if (!host || !host->h_length) {
        return 0;
    }
    // https://securepubads.g.doubleclick.net/pcs/view
    // char **pptr = host->h_addr_list;
    // char str[INET_ADDRSTRLEN];
    // for (int i = 0; *pptr != NULL; pptr++, i++) {
    //     printf("ip-%d: %s\n", i, inet_ntop(host->h_addrtype, pptr, str, sizeof(str)));
    // }

    struct sockaddr_in remoteAddr;
    int remoteSock = socket(PF_INET, SOCK_STREAM, IPPROTO_TCP);
    int originSockFlag = fcntl(remoteSock, F_GETFL, 0);
    int sockFlag = fcntl(remoteSock, F_SETFL, originSockFlag | O_NONBLOCK);
    if (sockFlag == -1) {
        cout << "fcntl err" << endl;
    }

    memset(&remoteAddr, 0, sizeof(remoteAddr));
    remoteAddr.sin_family = host->h_addrtype;
    remoteAddr.sin_addr = *((struct in_addr*)host->h_addr_list[0]);
    remoteAddr.sin_port = htons(sockInfo.header->port);

    char* ip = (char*)calloc(INET_ADDRSTRLEN, 1);
    inet_ntop(host->h_addrtype, host->h_addr_list[0], ip, INET_ADDRSTRLEN);
    sendRecordToLacal(sockInfo, sockContainer.proxyScokInfo, MSG_DNS, ip, strlen(ip));

    sendTimeToLacal(sockInfo, TIME_CONNECT_START);
    int retries = 0;
    // cout << "connect start:" << sockInfo.header->hostname << endl;
    while (1) {
        int err = connect(remoteSock, (struct sockaddr*)&remoteAddr, sizeof(remoteAddr));
        if (err != 0) {
            if (errno == EISCONN) {
                break;
            }
            if (errno == EINTR || errno == EAGAIN || errno == EINPROGRESS || errno == EALREADY) {
                usleep(1000);
                retries++;
                if (retries >= 5000) { // 5秒超时
                    char status = STATUS_FAIL_CONNECT;
                    sendRecordToLacal(sockInfo, sockContainer.proxyScokInfo, MSG_STATUS, &status, 1);
                    // cout << "connect timeout:" << sockInfo.sockId << ":" << sockInfo.sock << ":" << sockInfo.header->hostname << endl;
                    return 0;
                }
            } else {
                char status = STATUS_FAIL_CONNECT;
                sendRecordToLacal(sockInfo, sockContainer.proxyScokInfo, MSG_STATUS, &status, 1);
                // cout << "connect fail:" << sockInfo.sockId << ":" << sockInfo.sock << ":" << sockInfo.header->hostname << endl;
                return 0;
            }
        } else {
            break;
        }
    }
    sendTimeToLacal(sockInfo, TIME_CONNECT_END);

    sockInfo.remoteSockInfo = (SockInfo*)calloc(1, sizeof(SockInfo));
    sockContainer.resetSockInfo(*sockInfo.remoteSockInfo);
    sockInfo.remoteSockInfo->sockId = sockInfo.sockId; // preReadData|readData|writeData会判断该id
    sockInfo.remoteSockInfo->reqId = sockInfo.reqId;
    sockInfo.remoteSockInfo->ip = ip;
    sockInfo.remoteSockInfo->sock = remoteSock;
    sockInfo.remoteSockInfo->localSockInfo = &sockInfo;
    sockInfo.remoteSockInfo->originSockFlag = originSockFlag;
    sockInfo.remoteSockInfo->isNoBloack = 1;

    if (sockInfo.ssl) {
        sockContainer.setNoBlock(*sockInfo.remoteSockInfo, 0);
        // SSL_load_error_strings();
        // OpenSSL_add_ssl_algorithms();

        SSL_CTX* ctx = SSL_CTX_new(SSLv23_client_method());
        SSL* ssl = SSL_new(ctx);
        sockInfo.remoteSockInfo->ssl = ssl;
        SSL_set_fd(ssl, remoteSock);
        // 将主机名称写入 ClientHello 消息中的 ServerName 扩展字段中，有些服务器建立 TLS 连接时可能会校验该字段
        SSL_set_tlsext_host_name(ssl, sockInfo.header->hostname);

        sendTimeToLacal(sockInfo, TIME_CONNECT_SSL_START);
        int err = SSL_connect(ssl);
        sendTimeToLacal(sockInfo, TIME_CONNECT_SSL_END);
        if (err != 1) {
            int sslErrCode = SSL_get_error(ssl, err);
            char status = STATUS_FAIL_SSL_CONNECT;
            sendRecordToLacal(sockInfo, sockContainer.proxyScokInfo, MSG_STATUS, &status, 1);
            cout << "SSL_connect fail:" << sockInfo.sockId << ":" << sockInfo.sock << ":" << sslErrCode << endl;
            return 0;
        } else {
            // 获取服务器证书--begin
            long size = 0;
            char* buf = NULL;
            X509* x509 = SSL_get_peer_certificate(ssl);

            pthread_mutex_lock(&pemMutex);
            FILE* pemFile = fopen("./tmp.pem", "w+");
            PEM_write_X509(pemFile, x509);

            size = ftell(pemFile);
            buf = (char*)calloc(size, 1);

            fseek(pemFile, 0, SEEK_SET);
            fread(buf, size, 1, pemFile);
            fclose(pemFile);
            pthread_mutex_unlock(&pemMutex);

            sockInfo.remoteSockInfo->pem_cert = buf;
            // 获取服务器证书--end
        }
    }

    sockContainer.setNoBlock(*sockInfo.remoteSockInfo, 1); // 设置成非阻塞模式

    return 1;
}

int initLocalWebscoket(SockInfo& sockInfo, int type) {
    int hasError = 0;
    ssize_t result = 0;
    SockInfo* wsScokInfo = NULL;
    if (type == 1) {
        wsScokInfo = sockContainer.proxyScokInfo;
    } else if (type == 2) {
        wsScokInfo = sockContainer.ruleScokInfo;
    }
    if (wsScokInfo) {
        if (wsScokInfo->sockId == sockInfo.sockId) {
            return 0;
        }
        wsUtils.close(*wsScokInfo); // 发送关闭祯
        usleep(1000); // 等客户端处理完关闭祯在断开连接
        sockContainer.shutdownSock(wsScokInfo);
    }
    if (type == 1) {
        sockContainer.proxyScokInfo = &sockInfo;
    } else if (type == 2) {
        sockContainer.ruleScokInfo = &sockInfo;
    }
    while (1) {
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
                if (strcmp(msg, "start") == 0) {
                    result = wsUtils.sendMsg(sockInfo, (unsigned char*)"start", 5);
                } else if (strcmp(msg, "ping") == 0) {
                    result = wsUtils.sendMsg(sockInfo, (unsigned char*)"pong", 4);
                }
                if (READ_ERROR == result) {
                    sockContainer.shutdownSock(&sockInfo);
                    break;
                }
            }
        }
    }

    return 0;
}

void sendTimeToLacal(SockInfo& sockInfo, int timeType) {
    if (!sockContainer.proxyScokInfo) {
        return;
    }
    timespec tv;
    timespec_get(&tv, TIME_UTC);

    u_int64_t t = (u_int64_t)tv.tv_sec * 1000000 + (u_int64_t)tv.tv_nsec / 1000;
    t = htonll(t);

    char* msg = (char*)calloc(sizeof(u_int64_t) + 2, 1);
    msg[0] = timeType;
    memcpy(msg + 1, &t, sizeof(u_int64_t));

    sendRecordToLacal(sockInfo, sockContainer.proxyScokInfo, MSG_TIME, msg, sizeof(u_int64_t) + 1);
    free(msg);
}

void sendRecordToLacal(SockInfo& sockInfo, SockInfo* wsSockInfo, int type, char* data, ssize_t size) {
    if (!wsSockInfo) {
        return;
    }
    size = !data ? 0 : size;
    size = size == -1 ? strlen(data) : size;

    int index = 0;
    int idSize = sizeof(uint64_t);
    int ptSize = sizeof(unsigned short);
    ssize_t bufSize = (idSize + 1) * 2 + 1 + size;
    u_int64_t reqId = htonll(sockInfo.reqId);
    u_int64_t sockId = htonll(sockInfo.sockId);

    if (type == MSG_REQ_HEAD) {
        bufSize += 1;
        bufSize += 1 + ptSize;
        bufSize += 1 + strlen(sockInfo.ip);
        // 频繁使用popen调用命令行将导致内存泄漏
        // char* p = findPidByPort(sockInfo.port);
        // if (p) {
        //     pid = atoi(p);
        // }
    } else if (type == MSG_PORT) {
        bufSize += 1 + ptSize;
    }

    unsigned char* msg = (unsigned char*)calloc(bufSize, 1);

    msg[index++] = type; // msg_type
    msg[index++] = idSize;
    memcpy(msg + index, &reqId, idSize);
    index += idSize;
    msg[index++] = idSize;
    memcpy(msg + index, &sockId, idSize);
    index += idSize;
    if (type == MSG_REQ_HEAD) {
        if (sockInfo.header && sockInfo.header->upgrade && strcmp(sockInfo.header->upgrade, "websocket") == 0) {
            msg[index++] = sockInfo.ssl ? 4 : 3; // wss/ws
        } else {
            msg[index++] = sockInfo.ssl ? 2 : 1; // https/http
        }

        unsigned short pt = htons(sockInfo.port);
        msg[index++] = ptSize;
        memcpy(msg + index, &pt, ptSize); // 客户端的端口
        index += ptSize;

        msg[index++] = strlen(sockInfo.ip);
        memcpy(msg + index, sockInfo.ip, strlen(sockInfo.ip));
        index += strlen(sockInfo.ip);
    } else if (type == MSG_PORT) {
        unsigned short pt = htons(sockInfo.port);
        msg[index++] = ptSize;
        memcpy(msg + index, &pt, ptSize); // 客户端的端口
        index += ptSize;
    }
    if (data && size > 0) {
        memcpy(msg + index, data, size);
    }

    pthread_mutex_lock(&sendRecordMutex);
    wsUtils.sendMsg(*wsSockInfo, msg, bufSize, 1, 2);
    pthread_mutex_unlock(&sendRecordMutex);

    free(msg);
}

ssize_t getChunkSize(SockInfo& sockInfo, ssize_t& numSize) {
    string num = "";
    ssize_t i = 0;
    while (sockInfo.buf[i] >= '0' && sockInfo.buf[i] <= '9' ||
        sockInfo.buf[i] >= 'a' && sockInfo.buf[i] <= 'z' ||
        sockInfo.buf[i] >= 'A' && sockInfo.buf[i] <= 'Z') {
        num += sockInfo.buf[i];
        i++;
    }
    if (i == 0) { // 数据错误
        return -2;
    }
    if (sockInfo.bufSize < i + 2) { // 待接收数据
        return -1;
    }
    if (sockInfo.buf[i] != '\r' || sockInfo.buf[i + 1] != '\n') { // 数据错误
        return -2;
    }
    numSize = i + 2;

    return stol(num, NULL, 16);
}

int reciveBody(SockInfo& sockInfo) {
    HttpHeader* header = sockInfo.header;
    string boundary = httpUtils.getBoundary(header);
    ssize_t bufSize = sockInfo.bufSize;
    ssize_t preBufSize = 0;
    ssize_t bodySize = 0;
    ssize_t dataSize = 0;
    ssize_t chunkSize = -1, numSize = 0;
    char* preBuf = NULL;
    int isChunk = header->transferEncoding && !strcmp(header->transferEncoding, "chunked") ? 1 : 0;
    int isEnd = 0, hasError = 0;

    while (!isEnd) {
        dataSize = 0;
        while (!bufSize) {
            bufSize = httpUtils.reciveData(sockInfo);
            httpUtils.checkError(sockInfo, bufSize, hasError);
            if (hasError) {
                if (preBuf != sockInfo.buf) {
                    free(preBuf);
                }
                sendRecordToLacal(
                    sockInfo.localSockInfo ? *sockInfo.localSockInfo : sockInfo,
                    sockContainer.proxyScokInfo,
                    sockInfo.localSockInfo ? MSG_RES_BODY_END : MSG_REQ_BODY_END,
                    NULL, 0
                );
                return 0;
            }
        }
        if (isChunk) {
            chunkSize = chunkSize == -1 ? getChunkSize(sockInfo, numSize) : chunkSize;
            if (chunkSize == -2) { // 数据错误
                return 0;
            } else if (chunkSize == -1) { // 待接收数据用来解析chunk大小
                bufSize = 0;
                continue;
            } else if (chunkSize == 0) { // 最后一个chunk
                dataSize = numSize;
                isChunk = 0;
                if (!header->trailer) {
                    boundary = "\r\n";
                } else {
                    boundary = "\r\n\r\n";
                }
            } else if (bodySize + sockInfo.bufSize - numSize >= chunkSize + 2) { // 接收满一个chunk，加2是因为一个chunk后面会跟着\r\n
                dataSize = chunkSize + 2 + numSize - bodySize;
                chunkSize = -1;
                bodySize = 0;
            } else {
                bodySize += sockInfo.bufSize;
            }
        } else if (header->contentLenth > 0) {
            if (header->contentLenth <= sockInfo.bufSize + bodySize) {
                dataSize = header->contentLenth - bodySize;
                isEnd = true;
            } else {
                bodySize += sockInfo.bufSize;
            }
        } else if (boundary.size()) {
            preBuf = (char*)realloc(preBuf, preBufSize + sockInfo.bufSize);
            memcpy(preBuf + preBufSize, sockInfo.buf, sockInfo.bufSize);
            ssize_t preSize = preBufSize > boundary.size() ? preBufSize - boundary.size() : 0;
            ssize_t pos = kmpStrstr(preBuf, boundary.c_str(), preBufSize + sockInfo.bufSize, boundary.size(), preSize);
            free(preBuf);
            if (pos != -1) {
                dataSize = pos + boundary.size() - preBufSize;
                isEnd = true;
            } else if (sockInfo.bufSize < boundary.size()) {
                bufSize = 0;
                continue;
            } else {
                preBuf = sockInfo.buf;
                preBufSize = sockInfo.bufSize;
            }
        }
        dataSize = dataSize ? dataSize : sockInfo.bufSize;
        sendRecordToLacal(
            sockInfo.localSockInfo ? *sockInfo.localSockInfo : sockInfo,
            sockContainer.proxyScokInfo,
            sockInfo.localSockInfo ? MSG_RES_BODY : MSG_REQ_BODY,
            sockInfo.buf, dataSize
        );
        if (isEnd) {
            sendRecordToLacal(
                sockInfo.localSockInfo ? *sockInfo.localSockInfo : sockInfo,
                sockContainer.proxyScokInfo,
                sockInfo.localSockInfo ? MSG_RES_BODY_END : MSG_REQ_BODY_END,
                NULL, 0
            );
        }

        ssize_t result = httpUtils.writeData(sockInfo.remoteSockInfo ? *sockInfo.remoteSockInfo : *sockInfo.localSockInfo, sockInfo.buf, dataSize); // 将远程服务器返回的数据发送给客户端
        if (READ_ERROR == result || READ_END == result) {
            return 0;
        }

        if (sockInfo.bufSize > dataSize) {
            sockInfo.bufSize -= dataSize;
            char* data = (char*)calloc(sockInfo.bufSize + 1, 1);
            memcpy(data, sockInfo.buf + dataSize, sockInfo.bufSize);
            free(sockInfo.buf);
            sockInfo.buf = data;
            bufSize = sockInfo.bufSize;
        } else {
            if (preBuf != sockInfo.buf) {
                free(sockInfo.buf);
            }
            sockInfo.buf = NULL;
            sockInfo.bufSize = 0;
            bufSize = 0;
        }
    }

    return 1;
}

int forward(SockInfo& sockInfo) { // 转发http/https请求
    SockInfo& remoteSockInfo = *sockInfo.remoteSockInfo;
    HttpHeader* header = sockInfo.header;
    string boundary = "";
    char* req = NULL;
    int hasError = 0;
    ssize_t reqSize = 0;
    ssize_t result = 0;

    sendTimeToLacal(sockInfo, TIME_REQ_START); // request-begin
    httpUtils.createReqData(sockInfo, req, reqSize);
    result = httpUtils.writeData(*sockInfo.remoteSockInfo, req, reqSize); // 转发客户端请求头
    free(req);
    if (READ_ERROR == result || READ_END == result) {
        return 0;
    }
    boundary = httpUtils.getBoundary(header);
    if (header->contentLenth > 0 || boundary.size()) {
        if (!reciveBody(sockInfo)) { // 读取和转发客户端请求体
            return 0;
        }
    }
    sendTimeToLacal(sockInfo, TIME_REQ_END); // request-end

    httpUtils.waiteData(*sockInfo.remoteSockInfo);
    sendTimeToLacal(sockInfo, TIME_RES_START); // response-begin
    header = httpUtils.reciveHeader(*sockInfo.remoteSockInfo, hasError); // 读取远程服务器的响应头
    if (hasError) {
        return 0;
    }

    char* data = (char*)calloc(remoteSockInfo.headSize, 1);
    memcpy(data, remoteSockInfo.head, remoteSockInfo.headSize);
    sendRecordToLacal(sockInfo, sockContainer.proxyScokInfo, MSG_RES_HEAD, data, remoteSockInfo.headSize);
    result = httpUtils.writeData(sockInfo, data, remoteSockInfo.headSize); // 转发服务端响应头
    free(data);
    if (READ_ERROR == result || READ_END == result) {
        return 0;
    }

    if (header->status == 101 && header->upgrade && strcmp(header->upgrade, "websocket") == 0) { // webscoket连接成功
        sockInfo.remoteSockInfo->isWebSock = 1;
        sockInfo.isWebSock = 1;

        pthread_t remoteTid;
        pthread_create(&remoteTid, NULL, forwardWebocket, sockInfo.remoteSockInfo);
        pthread_detach(remoteTid);
        // pthread_t为结构体，引用赋值需要再初始化以后再赋值，否则里面的元素是空的
        sockInfo.remoteSockInfo->wsTid = remoteTid;
        forwardWebocket(&sockInfo);

        return 0;
    }

    boundary = httpUtils.getBoundary(header);
    if (strcmp(sockInfo.header->method, "HEAD") != 0 // HEAD请求没有响应体，即使有，也应该丢弃
        && !(header->status >= 100 && header->status <= 199)
        && header->status != 204
        && header->status != 205
        && header->status != 304
        && (header->contentLenth != 0 || boundary.size())) {
        if (!reciveBody(*sockInfo.remoteSockInfo)) { // 读取和转发服务端响应体
            return 0;
        }
    }
    sendTimeToLacal(sockInfo, TIME_RES_END);// response-end

    return 1;
}

void* forwardWebocket(void* arg) { // 转发webscoket请求
    SockInfo& sockInfo = *((SockInfo*)arg);
    int hasError = 0;
    ssize_t result = 0;
    u_int64_t sockId = sockInfo.sockId;
    int sock = sockInfo.sock;
    while (1) {
        WsFragment* wsFragment = httpUtils.reciveWsFragment(sockInfo, hasError);
        if (hasError) {
            sockContainer.shutdownSock(&sockInfo);
            break;
        }
        unsigned char* buf = wsUtils.createMsg(wsFragment);
        if (sockInfo.remoteSockInfo) {
            result = httpUtils.writeData(*sockInfo.remoteSockInfo, (char*)buf, wsFragment->fragmentSize);
        } else if (sockInfo.localSockInfo) {
            result = httpUtils.writeData(*sockInfo.localSockInfo, (char*)buf, wsFragment->fragmentSize);
        }
        if (READ_ERROR == result || wsFragment->opCode == 0x08) {
            sockContainer.shutdownSock(&sockInfo);
            break;
        }
        if ((sockInfo.remoteSockInfo && sockInfo.remoteSockInfo->state == SOCK_STATE_CLOSED) ||
            (sockInfo.localSockInfo && sockInfo.localSockInfo->state == SOCK_STATE_CLOSED)) { // 对端已经关闭
            wsUtils.close(sockInfo);
            sockContainer.shutdownSock(&sockInfo);
            break;
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