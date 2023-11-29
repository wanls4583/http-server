#include <iostream>
#include <sys/socket.h>
#include <openssl/err.h>
#include <openssl/ssl.h>
#include <openssl/bio.h>
#include "TlsUtils.h"

using namespace std;

TlsUtils::TlsUtils() : ctxHead(NULL), ctxEnd(NULL), maxCtx(100), ctxCount(0)
{
    pthread_mutex_init(&certMutex, NULL);
};

unsigned int TlsUtils::bufToInt(char *buf, int size)
{
    unsigned int res = 0;
    for (int i = 0; i < size; i++)
    {
        res = (res << 8) | u_int8_t(*(buf + i));
    }
    return res;
}

char *TlsUtils::getServerName(int sock)
{
    char buf[5], *pos, *serverName = NULL, *end;
    short tlsLen = 0;
    unsigned int sessionIdLen = 0, cipherSuitesLen = 0, compMethLen = 0, extType = 0, extLen = 0;

    memset(buf, 0, sizeof(buf));
    recv(sock, buf, sizeof(buf), MSG_PEEK);
    memcpy(&tlsLen, buf + 3, 2);
    tlsLen = ntohs(tlsLen);

    pos = (char *)malloc(tlsLen);
    memset(pos, 0, tlsLen);
    recv(sock, pos, tlsLen, MSG_PEEK);
    end = pos + tlsLen - 1;
    pos += TLS_PRE_SESSION_LEN;

    // memcpy((char*)(&sessionIdLen) + (4-TLS_SESSION_ID_LEN_), pos, TLS_SESSION_ID_LEN_);
    // sessionIdLen = ntohl(sessionIdLen);
    sessionIdLen = bufToInt(pos, TLS_SESSION_ID_LEN_);
    pos += TLS_SESSION_ID_LEN_;
    pos += sessionIdLen;

    // memcpy((char*)(&cipherSuitesLen) + (4-TLS_CIPHER_SUITES_LEN_), pos, TLS_CIPHER_SUITES_LEN_);
    // cipherSuitesLen = ntohl(cipherSuitesLen);
    cipherSuitesLen = bufToInt(pos, TLS_CIPHER_SUITES_LEN_);
    pos += TLS_CIPHER_SUITES_LEN_;
    pos += cipherSuitesLen;

    // memcpy((char*)(&compMethLen) + (4-TLS_COMP_METH_LEN_), pos, TLS_COMP_METH_LEN_);
    // compMethLen = ntohl(compMethLen);
    compMethLen = bufToInt(pos, TLS_COMP_METH_LEN_);
    pos += TLS_COMP_METH_LEN_;
    pos += compMethLen;
    pos += TLS_EXT_LEN;

    while (pos < end)
    {
        extType = bufToInt(pos, 2);
        pos += 2;
        extLen = bufToInt(pos, 2);
        pos += 2;
        if (extType == 0)
        {
            int nameLen = bufToInt(pos + 3, 2);
            serverName = (char *)calloc(1, nameLen + 1);
            memcpy(serverName, pos + 5, nameLen);
            break;
        }
        pos += extLen;
    }
    return serverName;
}

SSL_CTX *TlsUtils::getCert(int sock)
{
    pthread_mutex_lock(&certMutex);
    char *serverName = this->getServerName(sock);
    if (!serverName)
    {
        serverName = (char *)"127.0.0.1";
    }
    ServerMap *head = this->ctxHead;
    while (head)
    {
        if (serverName && strcmp(head->serverName, serverName) == 0)
        {
            pthread_mutex_unlock(&certMutex);
            return head->ctx;
        }
        head = head->next;
    }
    SSL_CTX *ctx = this->initCert(serverName);

    if (!ctx)
    {
        pthread_mutex_unlock(&certMutex);
        return NULL;
    }

    ServerMap *srvMap = (ServerMap *)malloc(sizeof(ServerMap));
    srvMap->serverName = serverName;
    srvMap->ctx = ctx;
    srvMap->next = NULL;
    if (this->ctxEnd)
    {
        this->ctxEnd->next = srvMap;
        this->ctxEnd = srvMap;
    }
    else
    {
        this->ctxHead = srvMap;
        this->ctxEnd = srvMap;
    }
    this->ctxCount++;
    if (this->ctxCount > this->maxCtx)
    {
        head = this->ctxHead;
        this->ctxCount = this->maxCtx;
        this->ctxHead = head->next;

        SSL_CTX_free(head->ctx);
        free(head->serverName);
        free(head);
    }
    pthread_mutex_unlock(&certMutex);
    return ctx;
}

SSL_CTX *TlsUtils::initCert(char *serverName)
{
    EVP_PKEY *pkey;
    X509 *domainCert;

    if (!this->certUtils.createCertFromRequestFile(&pkey, &domainCert, serverName))
    {
        return NULL;
    }

    SSL_load_error_strings();
    OpenSSL_add_ssl_algorithms();
    SSL_CTX *ctx = SSL_CTX_new(TLS_server_method());
    if (!ctx)
    {
        ERR_print_errors_fp(stderr);
        return NULL;
    }
    // if (SSL_CTX_use_certificate_file(ctx, "rootCA/server.crt", SSL_FILETYPE_PEM) <= 0)
    // {
    //     ERR_print_errors_fp(stderr);
    //     exit(3);
    // }
    // if (SSL_CTX_use_PrivateKey_file(ctx, "rootCA/server.key", SSL_FILETYPE_PEM) <= 0)
    // {
    //     ERR_print_errors_fp(stderr);
    //     exit(4);
    // }
    if (SSL_CTX_use_certificate(ctx, domainCert) <= 0)
    {
        ERR_print_errors_fp(stderr);
        return NULL;
    }
    if (SSL_CTX_use_PrivateKey(ctx, pkey) <= 0)
    {
        ERR_print_errors_fp(stderr);
        return NULL;
    }
    if (!SSL_CTX_check_private_key(ctx))
    {
        fprintf(stderr, "Private key does not match the certificate public key\n");
        return NULL;
    }
    return ctx;
}

SSL *TlsUtils::getSSL(int sock)
{
    char buf[2];
    SSL *ssl = NULL;
    SSL_CTX *ctx = NULL;
    ctx = this->getCert(sock);
    if (!ctx)
    {
        return NULL;
    }
    X509 *client_cert;
    int err;
    char *str;
    ssl = SSL_new(ctx);
    SSL_set_fd(ssl, sock);
    err = SSL_accept(ssl);
    // printf("SSL connection using %s\n", SSL_get_cipher(ssl)); // TLS_AES_128_GCM_SHA256
    return ssl;
}