#ifndef TLS_UTILS
#define TLS_UTILS

#include <pthread.h>
#include "CertUtils.h"
#include "SockContainer.h"

#define TLS_CONTENT_TYPE_LEN 1
#define TLS_VERSION_LEN 2
#define TLS_LEN 2
#define TLS_HAND_TYPE_LEN 1
#define TLS_HAND_LEN 3
#define TLS_HIGH_VERSION_LEN 2
#define TLS_RANDOM_LEN 32
#define TLS_PRE_SESSION_LEN (TLS_CONTENT_TYPE_LEN + TLS_VERSION_LEN + TLS_LEN + TLS_HAND_TYPE_LEN + TLS_HAND_LEN + TLS_HIGH_VERSION_LEN + TLS_RANDOM_LEN)
#define TLS_SESSION_ID_LEN_ 1
#define TLS_CIPHER_SUITES_LEN_ 2
#define TLS_COMP_METH_LEN_ 1
#define TLS_EXT_LEN 2

using namespace std;

typedef struct ServerMap
{
    char *serverName;
    SSL_CTX *ctx;
    ServerMap *next;
} ServerMap;

class TlsUtils
{
private:
    ServerMap *ctxHead;
    ServerMap *ctxEnd;
    pthread_mutex_t certMutex;
    int maxCtx;
    int ctxCount;

public:
    CertUtils certUtils;
    TlsUtils();
    unsigned int bufToInt(char *buf, int size);
    char *getServerName(int sock);
    SSL_CTX *getCert(SockInfo& sockInfo);
    SSL_CTX *initCert(char *serverName);
    SSL *getSSL(SockInfo& sockInfo);
};
#endif
