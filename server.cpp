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
#include <libproc.h>
#include "nlohmann/json.hpp"
#include "utils.h"
#include "TlsUtils.h"
#include "HttpUtils.h"
#include "V8Utils.h"
#include "SockContainer.h"
#include "RuleUtils.h"
#include "LevelUtils.h"
#include "DataUtils.h"
#include <regex>

using namespace std;
using json = nlohmann::json;

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
pthread_mutex_t cmdMutex;
RuleUtils ruleUtils;
LevelUtils persitLevelUtils("persist_level.db");
LevelUtils tempLevelUtils("temp_level.db", true);
DataUtils dataUtils;
char* scriptScource = NULL;

int initServSock();
void* initClntSock(void* arg);
int initRemoteSock(SockInfo& sockInfo);
int checkApi(SockInfo& sockInfo);
void getClientPath(SockInfo& sockInfo);
ssize_t getChunkSize(char* buf, ssize_t bufSize, ssize_t& numSize);
string getUnChunkData(SockInfo& sockInfo);
string createChunkData(string body, char* bodyTrailer);
void replaceHead(SockInfo& sockInfo, char* header);
void replaceBody(SockInfo& sockInfo, char* body);
string replaceHeadEncoding(char* head);
void resetBody(SockInfo& sockInfo, string body);
void resetBuf(SockInfo& sockInfo, string ruleStr);
int reciveBody(SockInfo& sockInfo, bool ifWrite = true);
bool ifHasBody(SockInfo& sockInfo, ruleType type);
int checkRule(SockInfo& sockInfo, ruleType type, ruleMethodType methodType);
int checkBreakpoint(SockInfo& sockInfo, ruleType type);
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
    pthread_mutex_init(&cmdMutex, NULL);
    pthread_key_create(&ptKey, NULL);
    servSock = initServSock();
    if (servSock < 0) {
        return -1;
    }

    ssize_t size = 0;
    char* ruleStr = dataUtils.getData(DATA_TYPE_RULE, 0, size);
    ruleUtils.parseRule(ruleStr);

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
    int sock = sockInfo.sock;
    int hasError = 0;

    // cout << "initClntSock:" << sockInfo.sockId << ":" << sockInfo.sock << endl;
    pthread_setspecific(ptKey, arg);
    sockContainer.setNoBlock(sockInfo, 1); // 设置成非阻塞模式

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

    httpUtils.reciveHeader(sockInfo, hasError); // 读取客户端的请求头

    if (hasError) {
        sockContainer.shutdownSock();
        return NULL;
    }

    if (!sockInfo.header || !sockInfo.header->hostname || !sockInfo.header->method) { // 解析请求头失败
        sockContainer.shutdownSock();
        return NULL;
    }

    sockInfo.reqId = sockContainer.reqId++;

    if (strcmp(sockInfo.header->method, "CONNECT") == 0) // 客户端https代理连接请求
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
            cout << sockInfo.header->path << endl;
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
                } else if (!strcmp(sockInfo.header->path, "/data")) {
                    httpUtils.sendUpgradeOk(sockInfo);
                    initLocalWebscoket(sockInfo, 3);
                } else {
                    sockContainer.shutdownSock();
                }
                return NULL;
            } else if (!strncmp(sockInfo.header->path, "/api", strlen("/api"))) { // 本地ajax请求
                if (!checkApi(sockInfo)) {
                    sockContainer.shutdownSock();
                    return NULL;
                }
            } else {
                httpUtils.sendFile(sockInfo);
            }
        } else if (sockInfo.isProxy) { // 客户端代理转发请求
            if (!checkBreakpoint(sockInfo, RULE_REQ)) { // 中断请求
                sockContainer.shutdownSock();
                return NULL;
            }
            if (!checkRule(sockInfo, RULE_REQ, RULE_METHOD_HEAD)) { // 拦截请求头
                sockContainer.shutdownSock();
                return NULL;
            }

            char* req;
            ssize_t reqSize;
            httpUtils.createReqData(sockInfo, req, reqSize);
            sendRecordToLacal(sockInfo, sockContainer.proxyScokInfo, MSG_REQ_HEAD, req, reqSize);
            if (sockInfo.cipher) {
                sendRecordToLacal(sockInfo, sockContainer.proxyScokInfo, MSG_CIPHER, sockInfo.cipher, -1);
            }

            if (!sockInfo.remoteSockInfo) { // 新建远程连接
                if (!initRemoteSock(sockInfo)) {
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
    } else {
        sockContainer.shutdownSock();
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

            string str = "";
            str += buf;
            str += "@@@@";
            str += tlsUtil.certUtils.parseX509(x509);
            buf = (char*)calloc(str.size() + 1, 1);
            memcpy(buf, str.c_str(), str.size());
            sockInfo.remoteSockInfo->pem_cert = buf;
            // 获取服务器证书--end
        }
    }

    sockContainer.setNoBlock(*sockInfo.remoteSockInfo, 1); // 设置成非阻塞模式

    return 1;
}

int checkApi(SockInfo& sockInfo) {
    char* api = sockInfo.header->path + strlen("/api");
    if (httpUtils.checkIfReqBody(sockInfo.header)) {
        if (!reciveBody(sockInfo, false)) { // 读取客户端请求体
            return 0;
        }
    }
    if (!strcmp(sockInfo.header->method, "OPTIONS")) {
        httpUtils.sendOptionsOk(sockInfo);
        sockContainer.resetSockInfoData(sockInfo);
        initClntSock(&sockInfo);
        return 0;
    }
    if (!strncmp(api, "/decompress", strlen("/decompress"))) { // 解压
        char* contentType = (char*)"application/octet-stream";
        char* type = api + strlen("/decompress");
        if (!sockInfo.bodySize) {
            httpUtils.sendJson(sockInfo, NULL, 0, contentType);
            return 0;
        }
        ssize_t decoded_size = 0;
        char* decoded_buf = NULL;
        if (!strcmp(type, "/br")) {
            decoded_buf = brotli_decompress(sockInfo.body, sockInfo.bodySize, &decoded_size);
        } else if (!strcmp(type, "/gzip")) {
            decoded_buf = zlib_decompress(sockInfo.body, sockInfo.bodySize, &decoded_size, E_ZIP_GZIP);
        } else if (!strcmp(type, "/deflate")) {
            decoded_buf = zlib_decompress(sockInfo.body, sockInfo.bodySize, &decoded_size, E_ZIP_RAW);
        }
        if (decoded_buf) {
            httpUtils.sendJson(sockInfo, decoded_buf, decoded_size, contentType);
        } else {
            httpUtils.sendJson(sockInfo, sockInfo.body, sockInfo.bodySize, contentType);
        }
    } else if (!strncmp(api, "/get", strlen("/get"))) { // 获取数据
        char* contentType = (char*)"application/octet-stream";
        char* type = api + strlen("/get");
        char* buf = NULL;
        ssize_t size = 0;
        if (!strncmp(type, "/rule", strlen("/rule"))) {
            contentType = (char*)"application/json";
            type += strlen("/rule");
            if (strlen(type)) {
                if (!strncmp(type, "/on_off", strlen("/on_off"))) {
                    buf = dataUtils.getData(DATA_TYPE_RULE_ENABLE, 0, size);
                }
            } else {
                buf = dataUtils.getData(DATA_TYPE_RULE, 0, size);
            }
        } else if (!strncmp(type, "/cert", strlen("/cert"))) {
            u_int64_t reqId = stoull(type + strlen("/cert") + 1);
            buf = dataUtils.getData(DATA_TYPE_CERT, reqId, size);
        } else if (!strncmp(type, "/req_head", strlen("/req_head"))) {
            u_int64_t reqId = stoull(type + strlen("/req_head") + 1);
            buf = dataUtils.getData(DATA_TYPE_REQ_HEAD, reqId, size);
        } else if (!strncmp(type, "/res_head", strlen("/res_head"))) {
            u_int64_t reqId = stoull(type + strlen("/res_head") + 1);
            buf = dataUtils.getData(DATA_TYPE_RES_HEAD, reqId, size);
        } else if (!strncmp(type, "/req_body", strlen("/req_body"))) {
            u_int64_t reqId = stoull(type + strlen("/req_body") + 1);
            buf = dataUtils.getData(DATA_TYPE_REQ_BODY, reqId, size);
        } else if (!strncmp(type, "/res_body", strlen("/res_body"))) {
            u_int64_t reqId = stoull(type + strlen("/res_body") + 1);
            buf = dataUtils.getData(DATA_TYPE_RES_BODY, reqId, size);
        }
        httpUtils.sendJson(sockInfo, buf, size, contentType);
    } else if (!strncmp(api, "/put", strlen("/put"))) { // 保存数据
        char* contentType = (char*)"application/json";
        char* type = api + strlen("/put");
        char* buf = NULL;
        ssize_t size = 0;

        if (!strncmp(type, "/rule", strlen("/rule"))) {
            type += strlen("/rule");
            if (strlen(type)) {
                if (!strncmp(type, "/on", strlen("/on"))) {
                    dataUtils.saveData((char*)"true", 4, DATA_TYPE_RULE_ENABLE);
                } else if (!strncmp(type, "/off", strlen("/off"))) {
                    dataUtils.saveData((char*)"false", 5, DATA_TYPE_RULE_ENABLE);
                }
            } else {
                dataUtils.saveData(sockInfo.body, sockInfo.bodySize, DATA_TYPE_RULE);
                ruleUtils.parseRule(sockInfo.body);
            }
        } else if (!strncmp(type, "/clear", strlen("/clear"))) {
            tempLevelUtils.clear();
        } else if (!strncmp(type, "/breakpoint", strlen("/breakpoint"))) {
            u_int64_t reqId = stoull(type + strlen("/breakpoint") + 1);
            ruleUtils.broadcast(reqId, sockInfo.body, sockInfo.bodySize);
        }
        httpUtils.sendJson(sockInfo, NULL, 0, contentType);
    } else {
        httpUtils.send404(sockInfo);
    }

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
                u_int64_t msgLen = wsUtils.getMsgLength(sockInfo.wsFragment);
                if (!msgLen) {
                    continue;
                }

                char* msg = (char*)wsUtils.getMsg(sockInfo.wsFragment);
                cout << "ws:" << msg << endl;
                wsUtils.freeFragment(sockInfo.wsFragment);
                sockInfo.wsFragment = NULL;
                if (strcmp(msg, "start") == 0) {
                    result = wsUtils.sendMsg(sockInfo, (unsigned char*)"start", 5);
                } else if (strcmp(msg, "ping") == 0) {
                    result = wsUtils.sendMsg(sockInfo, (unsigned char*)"pong", 4);
                }
                free(msg);
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
    int usSize = sizeof(unsigned short);
    ssize_t bufSize = (idSize + 1) * 2 + 1;
    u_int64_t reqId = htonll(sockInfo.reqId);
    u_int64_t sockId = htonll(sockInfo.sockId);

    if (type == MSG_REQ_HEAD) {
        bufSize += 1;
        bufSize += 1 + usSize;
        bufSize += 1 + strlen(sockInfo.ip);
        bufSize += 1 + usSize;
        getClientPath(sockInfo);
        if (sockInfo.clientPath) {
            bufSize += strlen(sockInfo.clientPath);
        }
    } else if (type == MSG_RES_HEAD) {
        bufSize += 1 + usSize;
        bufSize += strlen(sockInfo.header->url);
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
        msg[index++] = usSize;
        memcpy(msg + index, &pt, usSize); // 客户端的端口
        index += usSize;

        msg[index++] = strlen(sockInfo.ip);
        memcpy(msg + index, sockInfo.ip, strlen(sockInfo.ip));
        index += strlen(sockInfo.ip);

        unsigned short originClientPathLen = sockInfo.clientPath ? strlen(sockInfo.clientPath) : 0;
        unsigned short clientPathLen = htons(originClientPathLen);
        msg[index++] = usSize;
        memcpy(msg + index, &clientPathLen, usSize);
        index += usSize;
        memcpy(msg + index, sockInfo.clientPath, originClientPathLen);
        index += originClientPathLen;
    } else if (type == MSG_RES_HEAD) {
        unsigned short len = htons(strlen(sockInfo.header->url));
        msg[index++] = usSize;
        memcpy(msg + index, &len, usSize); // url长度
        index += usSize;

        memcpy(msg + index, sockInfo.header->url, strlen(sockInfo.header->url));
        index += strlen(sockInfo.header->url);
    }

    if (MSG_REQ_HEAD == type) {
        dataUtils.saveData(data, size, DATA_TYPE_REQ_HEAD, sockInfo.reqId);
    } else if (MSG_RES_HEAD == type) {
        dataUtils.saveData(data, size, DATA_TYPE_RES_HEAD, sockInfo.reqId);
    } else if (MSG_REQ_BODY == type) {
        dataUtils.saveData(data, size, DATA_TYPE_REQ_BODY, sockInfo.reqId);
    } else if (MSG_RES_BODY == type) {
        dataUtils.saveData(data, size, DATA_TYPE_RES_BODY, sockInfo.reqId);
    } else if (MSG_CERT == type) {
        dataUtils.saveData(data, size, DATA_TYPE_CERT, sockInfo.reqId);
        return;
    }

    if (data && size > 0) {
        if (MSG_REQ_BODY == type || MSG_RES_BODY == type) { // 只发送大小
            u_int64_t len = htonll(size);
            size = 1 + idSize;
            data = (char*)calloc(size, 1);
            data[0] = idSize;
            memcpy(data + 1, &len, idSize);
        }
        bufSize += size;
        msg = (unsigned char*)realloc(msg, bufSize + 1);
        msg[bufSize] = 0;
        memcpy(msg + index, data, size);
    }

    pthread_mutex_lock(&sendRecordMutex);
    wsUtils.sendMsg(*wsSockInfo, msg, bufSize, 1, 2);
    pthread_mutex_unlock(&sendRecordMutex);

    free(msg);
}

void getClientPath(SockInfo& sockInfo) {
    if (!sockInfo.clientPath) {
        char* p = findPidByPort(sockInfo.port);
        if (p) {
            int pid = atoi(p);
            char pathbuf[PROC_PIDPATHINFO_MAXSIZE];
            int ret = proc_pidpath(pid, pathbuf, sizeof(pathbuf));
            if (ret > 0) {
                sockInfo.clientPath = (char*)calloc(ret + 1, 1);
                memcpy(sockInfo.clientPath, pathbuf, ret);
            }
        }
    }
}

ssize_t getChunkSize(char* buf, ssize_t bufSize, ssize_t& numSize) {
    string num = "";
    ssize_t i = 0;
    while (buf[i] >= '0' && buf[i] <= '9' ||
        buf[i] >= 'a' && buf[i] <= 'z' ||
        buf[i] >= 'A' && buf[i] <= 'Z') {
        num += buf[i];
        i++;
    }
    if (i == 0) { // 数据错误
        return -2;
    }
    if (bufSize < i + 2) { // 待接收数据
        return -1;
    }
    if (buf[i] != '\r' || buf[i + 1] != '\n') { // 数据错误
        return -2;
    }
    numSize = i + 2;

    return stol(num, NULL, 16);
}

string getUnChunkData(SockInfo& sockInfo) {
    ssize_t index = 0, preIndex = 0, chunkSize = 0;
    string body = "";

    free(sockInfo.bodyTrailer);
    sockInfo.bodyTrailer = NULL;
    sockInfo.bodyTrailerSize = 0;

    if (sockInfo.header->transferEncoding && !string(sockInfo.header->transferEncoding).compare("chunked")) {
        while ((chunkSize = getChunkSize(sockInfo.body + preIndex, sockInfo.bodySize - preIndex, index)) > 0) { // 解块
            preIndex += index;
            body.append(sockInfo.body + preIndex, chunkSize);
            preIndex += chunkSize + 2;
        }
        if (chunkSize == 0) {
            preIndex += index;
            if (preIndex + 2 < sockInfo.bodySize) {
                chunkSize = sockInfo.bodySize - preIndex;
                sockInfo.bodyTrailer = copyBuf(sockInfo.body + preIndex, chunkSize);
                sockInfo.bodyTrailerSize = chunkSize;
            }
        }
    } else {
        body = string(sockInfo.body, sockInfo.bodySize);
    }

    if (body.size() && sockInfo.header->contentEncoding) { // 解压缩
        ssize_t decoded_size = 0;
        char* decoded_buf = NULL;
        if (!strcmp(sockInfo.header->contentEncoding, "br")) {
            decoded_buf = brotli_decompress((char*)body.c_str(), body.size(), &decoded_size);
        } else if (!strcmp(sockInfo.header->contentEncoding, "gzip")) {
            decoded_buf = zlib_decompress((char*)body.c_str(), body.size(), &decoded_size, E_ZIP_GZIP);
        } else if (!strcmp(sockInfo.header->contentEncoding, "deflate")) {
            decoded_buf = zlib_decompress((char*)body.c_str(), body.size(), &decoded_size, E_ZIP_RAW);
        }
        if (decoded_size > 0) {
            body = string(decoded_buf, decoded_size);
        }
    }

    return body;
}

string createChunkData(string body, char* bodyTrailer) {
    ssize_t chunkLimit = 1024 * 100; //500k
    ssize_t count = 0;
    string result = "";

    while (count < body.size()) {
        ssize_t chunkSize = body.size() - count;
        chunkSize = chunkSize > chunkLimit ? chunkLimit : chunkSize;
        ostringstream ss;
        ss << std::hex << chunkSize;
        result += ss.str();
        result += "\r\n";
        result.append(body.substr(count, chunkSize));
        result += "\r\n";
        count += chunkSize;
    }
    result += "0\r\n";
    if (bodyTrailer) {
        result.append(bodyTrailer);
    } else {
        result += "\r\n";
    }

    return result;
}

void replaceHead(SockInfo& sockInfo, char* header) {
    free(sockInfo.head);
    sockInfo.head = copyBuf(header);
    sockInfo.headSize = strlen(header);
}

void replaceBody(SockInfo& sockInfo, char* body) {
    free(sockInfo.body);
    sockInfo.body = copyBuf(body);
    sockInfo.bodySize = strlen(body);
}

string replaceHeadEncoding(char* head) {
    char* result = head;
    head = ruleUtils.delHeader(result, (char*)"content-length");
    result = head ? head : result;

    head = ruleUtils.delHeader(result, (char*)"content-encoding");
    result = head ? head : result;

    head = ruleUtils.delHeader(result, (char*)"transfer-encoding");
    result = head ? head : result;

    head = ruleUtils.addHeader(result, (char*)"Transfer-Encoding", (char*)"chunked");
    result = head ? head : result;

    return string(result);
}

void resetBody(SockInfo& sockInfo, string body) {
    string buf = createChunkData(body, ruleUtils.ifHasHeader(sockInfo.head, "Trailer") ? sockInfo.bodyTrailer : NULL);

    free(sockInfo.body);
    sockInfo.bodySize = 0;
    sockInfo.body = NULL;

    free(sockInfo.buf);
    sockInfo.bufSize = 0;
    sockInfo.buf = NULL;

    buf += sockInfo.buf ? string(sockInfo.buf, sockInfo.bufSize) : "";
    sockInfo.buf = copyBuf(buf.c_str(), buf.size());
    sockInfo.bufSize = buf.size();
}

void resetBuf(SockInfo& sockInfo, string ruleStr) {
    string buf = ruleStr;

    free(sockInfo.head);
    sockInfo.head = NULL;
    sockInfo.headSize = 0;

    free(sockInfo.body);
    sockInfo.body = NULL;
    sockInfo.bodySize = 0;

    buf += sockInfo.buf ? string(sockInfo.buf, sockInfo.bufSize) : "";
    sockInfo.buf = copyBuf(buf.c_str(), buf.size());
    sockInfo.bufSize = buf.size();
}

int reciveBody(SockInfo& sockInfo, bool ifWrite) {
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
                if (ifWrite) {
                    sendRecordToLacal(
                        sockInfo.localSockInfo ? *sockInfo.localSockInfo : sockInfo,
                        sockContainer.proxyScokInfo,
                        sockInfo.localSockInfo ? MSG_RES_BODY_END : MSG_REQ_BODY_END,
                        NULL, 0
                    );
                }
                return 0;
            }
        }
        if (isChunk) {
            chunkSize = chunkSize == -1 ? getChunkSize(sockInfo.buf, sockInfo.bufSize, numSize) : chunkSize;
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

        if (ifWrite) {
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
        } else {
            sockInfo.body = (char*)realloc(sockInfo.body, sockInfo.bodySize + dataSize + 1);
            sockInfo.body[sockInfo.bodySize + dataSize] = 0;
            memcpy(sockInfo.body + sockInfo.bodySize, sockInfo.buf, dataSize);
            sockInfo.bodySize += dataSize;
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

bool ifHasBody(SockInfo& sockInfo, ruleType type) {
    char* method = sockInfo.localSockInfo ? sockInfo.localSockInfo->header->method : sockInfo.header->method;

    return RULE_REQ == type && httpUtils.checkIfReqBody(sockInfo.header) || RULE_RES == type && httpUtils.checkIfResBody(sockInfo.header, method);
}

int checkRule(SockInfo& sockInfo, ruleType type, ruleMethodType methodType) {
    int bodyWay = -1;
    bool headChanged = false, bodyChanged = false, bodyRecived = false;
    bool isRemote = sockInfo.localSockInfo ? true : false;
    char* head = NULL;
    string body = "";
    string originUnChunkData = "";
    RuleNode* node = ruleUtils.ruleList;

    while (node) {
        char* url = isRemote ? sockInfo.localSockInfo->header->url : sockInfo.header->url;
        if (wildcardMatch(url, (char*)node->url.c_str())) {
            if (node->type == type && node->methodType == methodType) {
                string unChunkData = "";
                string ruleStr = "";
                string ruleBuf = "";
                ssize_t ruleBufSize = 0;
                head = NULL;
                switch (node->method) {
                case MODIFY_PARAM_ADD: // 新增参数
                    head = ruleUtils.addParam(sockInfo.head, (char*)node->key.c_str(), (char*)node->value.c_str());
                    break;
                case MODIFY_PARAM_MOD: // 修改参数
                    head = ruleUtils.modParam(sockInfo.head, (char*)node->key.c_str(), (char*)node->value.c_str(), node->enableReg, node->icase);
                    break;
                case MODIFY_PARAM_DEL: // 删除参数
                    head = ruleUtils.delParam(sockInfo.head, (char*)node->key.c_str(), node->enableReg, node->icase);
                    break;
                case MODIFY_HEADER_ADD: // 新增首部
                    head = ruleUtils.addHeader(sockInfo.head, (char*)node->key.c_str(), (char*)node->value.c_str());
                    break;
                case MODIFY_HEADER_MOD: // 修改首部
                    head = ruleUtils.modHeader(sockInfo.head, (char*)node->key.c_str(), (char*)node->value.c_str(), node->enableReg, node->icase);
                    break;
                case MODIFY_HEADER_DEL: // 删除首部
                    head = ruleUtils.delHeader(sockInfo.head, (char*)node->key.c_str(), node->enableReg, node->icase);
                    break;
                case MODIFY_BODY_MOD: // 实体修改
                    if (ifHasBody(sockInfo, type)) {
                        if (!bodyRecived) {
                            if (!reciveBody(sockInfo, false)) {
                                return 0;
                            }
                            bodyRecived = true;
                        }
                        unChunkData = bodyChanged ? body : getUnChunkData(sockInfo);
                        body = ruleUtils.modBody(unChunkData, node->key, node->value, node->enableReg);
                        bodyChanged = true;
                    }
                    break;
                case MODIFY_BODY_REP: // 实体替换
                    body = node->value;
                    bodyChanged = true;
                    break;
                default:
                    break;
                }
                if (head) {
                    headChanged = true;
                    replaceHead(sockInfo, head);
                    free(head);
                }
            } else if (node->type == type && RULE_METHOD_BODY == node->methodType) {
                bodyWay = node->method;
            }
        }
        node = node->next;
    }

    if (headChanged || bodyChanged) { // 修改了实体时，因为提前修改过Transfer-Encoding等首部，需要重新更新header，确保后面的reciveBody能不正确解析
        sockContainer.freeHeader(sockInfo.header);
        if (RULE_REQ == type) {
            sockInfo.header = httpUtils.getHttpReqHeader(sockInfo);
        } else {
            sockInfo.header = httpUtils.getHttpResHeader(sockInfo);
        }
    }

    if (bodyChanged) {
        resetBody(sockInfo, body);
    }

    if (MODIFY_BODY_REP == bodyWay || MODIFY_BODY_MOD == bodyWay && ifHasBody(sockInfo, type)) { // 提前修改Transfer-Encoding等首部，确保实体被浏览器正确被接收
        replaceHead(sockInfo, (char*)replaceHeadEncoding(sockInfo.head).c_str());
    }

    return 1;
}

int checkBreakpoint(SockInfo& sockInfo, ruleType type) {
    bool isRemote = sockInfo.localSockInfo ? true : false;
    BreakPoint* node = ruleUtils.breakpintList;

    while (node) {
        char* url = isRemote ? sockInfo.localSockInfo->header->url : sockInfo.header->url;
        if (node->type == type && wildcardMatch(url, (char*)node->url.c_str())) {
            string ruleStr = "";
            if (ifHasBody(sockInfo, type) && !reciveBody(sockInfo, false)) {
                return 0;
            }
            string unChunkData = getUnChunkData(sockInfo);
            sockInfo.ruleState = 1;
            ruleStr += node->type;
            ruleStr.append(sockInfo.head, sockInfo.headSize);
            ruleStr.append(unChunkData);
            sendRecordToLacal(
                sockInfo.localSockInfo ? *sockInfo.localSockInfo : sockInfo,
                sockContainer.proxyScokInfo,
                MSG_RULE,
                (char*)ruleStr.c_str(), ruleStr.size()
            );

            if (sockInfo.localSockInfo) {
                pthread_cond_wait(&sockInfo.localSockInfo->cond, &sockInfo.localSockInfo->mutex);
            } else {
                pthread_cond_wait(&sockInfo.cond, &sockInfo.mutex);
            }

            sockInfo.ruleState = 2;
            ruleStr = sockInfo.ruleBuf ? string(sockInfo.ruleBuf, sockInfo.ruleBufSize) : "";
            free(sockInfo.ruleBuf);
            sockInfo.ruleBuf = NULL;
            sockInfo.ruleBufSize = 0;

            ssize_t pos = ruleStr.find("\r\n\r\n");
            if (pos != string::npos) {
                string head = ruleStr.substr(0, pos + 4);
                string body = ruleStr.substr(pos + 4);
                head = replaceHeadEncoding((char*)head.c_str());
                body = createChunkData(body, ruleUtils.ifHasHeader(sockInfo.head, "Trailer") ? sockInfo.bodyTrailer : NULL);
                ruleStr = head + body;
            }
            resetBuf(sockInfo, ruleStr);

            int hasError = 0;
            sockContainer.freeHeader(sockInfo.header);
            sockInfo.header = NULL;
            httpUtils.reciveHeader(sockInfo, hasError);
            if (hasError) {
                return 0;
            }
            break;
        }
    }

    return 1;
}

int forward(SockInfo& sockInfo) { // 转发http/https请求
    SockInfo& remoteSockInfo = *sockInfo.remoteSockInfo;
    HttpHeader* header = sockInfo.header;
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

    if (!checkRule(sockInfo, RULE_REQ, RULE_METHOD_BODY)) {// 拦截请求体
        return 0;
    }

    if (httpUtils.checkIfReqBody(sockInfo.header)) {
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

    if (!checkBreakpoint(sockInfo, RULE_RES)) { // 中断响应
        return 0;
    }

    if (!checkRule(*sockInfo.remoteSockInfo, RULE_RES, RULE_METHOD_HEAD)) { // 拦截响应头
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

    if (httpUtils.checkIfWebScoket(header)) { // webscoket连接成功
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

    if (!checkRule(*sockInfo.remoteSockInfo, RULE_RES, RULE_METHOD_BODY)) { // 拦截响应体
        return 0;
    }

    if (httpUtils.checkIfResBody(header, sockInfo.header->method)) {
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