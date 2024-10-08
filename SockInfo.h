#ifndef SockInfo_h
#define SockInfo_h

#include <openssl/ssl.h>
#include "HttpHeader.h"
#include "SocksReqHeader.h"
#include "WsFragment.h"

enum { SOCK_STATE_CLOSED = 1 };

typedef struct SockInfo {
    HttpHeader* header;
    SocksReqHeader* socksReqHeader;
    SSL* ssl;
    SockInfo* remoteSockInfo;
    SockInfo* localSockInfo;
    pthread_cond_t cond;
    pthread_mutex_t mutex;

    u_int64_t reqId;
    u_int64_t sockId;
    int sock;
    int state;
    int originSockFlag;
    int isNoBloack;
    int isNoCheckSSL;
    int isNoCheckSocks;
    int isProxy;
    int isWebSock;
    int recivedCloseFrame;
    int port;
    int ruleState; // 1:阻塞中, 2:已完成

    ssize_t bufSize;
    ssize_t ruleBufSize;
    ssize_t headSize;
    ssize_t bodySize;
    ssize_t bodyIndex;

    char* ip;
    char* tlsHeader;
    char* socksHeader;
    char* head;
    char* body;
    char* buf; // 未处理的buf
    char* ruleBuf; // 被修改的bug
    char* cipher;
    char* pem_cert;
    char* clientPath;
    WsFragment* wsFragment;

    struct timespec tv;
    pthread_t tid;
    pthread_t wsTid;
} SockInfo;
#endif