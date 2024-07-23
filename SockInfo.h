#ifndef SockInfo_h
#define SockInfo_h

#include <openssl/ssl.h>
#include "HttpHeader.h"
#include "SocksReqHeader.h"
#include "WsFragment.h"

typedef struct SockInfo {
    HttpHeader* header;
    SocksReqHeader* socksReqHeader;
    SSL* ssl;
    SockInfo* remoteSockInfo;
    SockInfo* localSockInfo;

    u_int64_t id;
    int sock;
    int closing;
    int originSockFlag;
    int isNoBloack;
    int isNoCheckSSL;
    int isNoCheckSocks;
    int isProxy;

    size_t bufSize;
    size_t reqSize;
    size_t bodySize;

    char* ip;
    char* tlsHeader;
    char* socksHeader;
    char* head;
    char* body;
    char* buf; // 未处理的buf
    WsFragment* wsFragment;

    struct timeval tv;
    pthread_t tid;
    pthread_t wsTid;
} SockInfo;
#endif