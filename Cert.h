#include <stdlib.h>
#include <iostream>
#include <openssl/pem.h>
#include <openssl/conf.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>

#define FORMAT_DER 1 //FORMAT_ASN1
#define FORMAT_PEM 3
#define FORMAT_NET 4
#define FORMAT_P12 5

class Cert
{
private:
    RSA *rsa;
    BIO *rootCertIn;
    BIO *rootKeyIn;
public:
    Cert();
    static void rsaCallback(int p, int n, void *arg);
    int add_ext(X509 *cert, int nid, char *value);
    int createCertFromRequestFile(EVP_PKEY **pkey, X509 **domainCert);
};
