#include <iostream>
#include <sys/socket.h>
#include <openssl/err.h>
#include <openssl/ssl.h>
#include <openssl/bio.h>
#include "TlsUtils.h"

using namespace std;

TlsUtils::TlsUtils() : ctxHead(NULL), ctxEnd(NULL), maxCtx(100), ctxCount(0){};

unsigned int TlsUtils::bufToInt(char *buf, int size)
{
    unsigned int res = 0;
    for (int i = 0; i < size; i++)
    {
        res = (res << 8) | u_int8_t(*(buf + i));
    }
    return res;
}

int TlsUtils::isClntHello(int clntSock)
{
    char buf[6];
    memset(buf, 0, sizeof(buf));
    recv(clntSock, buf, sizeof(buf), MSG_PEEK);
    if (buf[0] == 0x16 && buf[1] == 0x03 && buf[2] == 0x01 && buf[5] == 0x01)
    {
        return 1;
    }
    return 0;
}

char *TlsUtils::getServerName(int clntSock)
{
    char buf[5], *pos, *serveName, *end;
    short tlsLen = 0;
    unsigned int sessionIdLen = 0, cipherSuitesLen = 0, compMethLen = 0, extType = 0, extLen = 0;

    memset(buf, 0, sizeof(buf));
    recv(clntSock, buf, sizeof(buf), MSG_PEEK);
    memcpy(&tlsLen, buf + 3, 2);
    tlsLen = ntohs(tlsLen);

    pos = (char *)malloc(tlsLen);
    memset(pos, 0, tlsLen);
    recv(clntSock, pos, tlsLen, MSG_PEEK);
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
            serveName = (char *)malloc(nameLen);
            memcpy(serveName, pos + 5, nameLen);
            break;
        }
        pos += extLen;
    }
    return serveName;
}

SSL_CTX *TlsUtils::getCert(int clntSock)
{
    char *serverName = this->getServerName(clntSock);
    ServerMap *head = this->ctxHead;
    while (head)
    {
        if (strcmp(head->serveName, serverName) == 0)
        {
            return head->ctx;
        }
        head = head->next;
    }
    SSL_CTX *ctx = this->initCert(serverName);

    if (!ctx)
    {
        return NULL;
    }

    ServerMap *srvMap = (ServerMap *)malloc(sizeof(ServerMap));
    srvMap->serveName = serverName;
    srvMap->ctx = ctx;
    srvMap->next = NULL;
    if (this->ctxEnd)
    {
        this->ctxEnd->next = srvMap;
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
        free(head);
    }
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
