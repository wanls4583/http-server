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
    int port;

    ssize_t bufSize;
    ssize_t reqSize;
    ssize_t bodySize;

    char* ip;
    char* tlsHeader;
    char* socksHeader;
    char* head;
    char* body;
    char* buf; // 未处理的buf
    char* cipher;
    char* pem_cert;
    WsFragment* wsFragment;

    struct timeval tv;
    struct timeval forward_start_tv;
    struct timeval forward_end_tv;
    pthread_t tid;
    pthread_t wsTid;
} SockInfo;
#endif