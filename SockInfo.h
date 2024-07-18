#ifndef SockInfo_h
#define SockInfo_h

#include <openssl/ssl.h>
#include "HttpHeader.h"
#include "WsFragment.h"

typedef struct SockInfo {
    HttpHeader* header;
    SSL* ssl;
    SockInfo* remoteSockInfo;

    int sock;
    int closing;
    int originSockFlag;
    int isNoBloack;
    int isNoCheckSSL;
    int isProxy;

    size_t bufSize;
    size_t reqSize;
    size_t bodySize;

    char* ip;
    char* tlsHeader;
    char* head;
    char* body;
    char* buf; // 未处理的buf
    WsFragment* wsFragment;

    struct timeval tv;
    pthread_t tid;
} SockInfo;
#endif