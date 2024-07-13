#ifndef CERT_UTILS
#define CERT_UTILS

#include <iostream>
#include <openssl/pem.h>
#include <openssl/conf.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>

#define FORMAT_DER 1 // FORMAT_ASN1
#define FORMAT_PEM 3
#define FORMAT_NET 4
#define FORMAT_P12 5

class CertUtils
{
private:
    RSA *rsa;
    X509 *rootCert;
    EVP_PKEY *rootKey;

public:
    CertUtils();
    int add_ext(X509 *cert, int nid, char *value);
    int createCertFromRequestFile(EVP_PKEY **pkey, X509 **domainCert, char *serverName);
    char* getRootCertNameByOid(char* oId);
};
#endif