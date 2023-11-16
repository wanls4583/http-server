#include "Cert.h"

using namespace std;

Cert::Cert()
{
    rsa = RSA_generate_key(1024, RSA_F4, rsaCallback, NULL);
    rootCertIn = BIO_new_file("/Users/lisong/github/http-server/rootCA/rootCA.crt", "r");
    rootKeyIn = BIO_new_file("/Users/lisong/github/http-server/rootCA/rootCA.key.pem", "r");
};

void Cert::rsaCallback(int p, int n, void *arg)
{
    char c = 'B';

    if (p == 0)
        c = '.';
    if (p == 1)
        c = '+';
    if (p == 2)
        c = '*';
    if (p == 3)
        c = '\n';
    fputc(c, stderr);
};

int Cert::add_ext(X509 *cert, int nid, char *value)
{
    X509_EXTENSION *ex;
    X509V3_CTX ctx;
    /* This sets the 'context' of the extensions. */
    /* No configuration database */
    X509V3_set_ctx_nodb(&ctx);
    /*
     * Issuer and subject certs: both the target since it is self signed, no
     * request and no CRL
     */
    X509V3_set_ctx(&ctx, cert, cert, NULL, NULL, 0);
    ex = X509V3_EXT_conf_nid(NULL, &ctx, nid, value);
    if (!ex)
        return 0;

    X509_add_ext(cert, ex, -1);
    X509_EXTENSION_free(ex);
    return 1;
}

int Cert::createCertFromRequestFile(EVP_PKEY **pkey, X509 **domainCert) {
    X509 *x;
    EVP_PKEY *pk;
    X509_NAME *name = NULL;
    X509 * rootCert = PEM_read_bio_X509(this->rootCertIn, NULL, 0, NULL); //x509根证书对象
    EVP_PKEY * rootKey = PEM_read_bio_PrivateKey(this->rootKeyIn, NULL, 0, NULL); //根证书密钥对象

    pk = EVP_PKEY_new();
    x = X509_new();

    if (!EVP_PKEY_assign_RSA(pk, this->rsa)) {
        return 0;
    }

    X509_set_version(x, 2);
    ASN1_INTEGER_set(X509_get_serialNumber(x), 1);
    X509_gmtime_adj(X509_get_notBefore(x), 0);
    X509_gmtime_adj(X509_get_notAfter(x), (long)60 * 60 * 24 * 365);
    X509_set_pubkey(x, pk);

    name = X509_get_subject_name(x);

    unsigned char c[] = "CN";
    unsigned char cn[] = "my.test.com";
    unsigned char o[] = "Internet Widgits Pty Ltd";
    unsigned char ou[] = "Internet Widgits Pty Ltd";
    X509_NAME_add_entry_by_txt(name, "C", MBSTRING_ASC, c, -1, -1, 0);
    X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC, cn, -1, -1, 0);
    X509_NAME_add_entry_by_txt(name, "O", MBSTRING_ASC, o, -1, -1, 0);
    X509_NAME_add_entry_by_txt(name, "OU", MBSTRING_ASC, ou, -1, -1, 0);

    X509_set_issuer_name(x, X509_get_issuer_name(rootCert));

    add_ext(x, NID_subject_alt_name, "IP:127.0.0.1,DNS:my.test.com"); //DNS必须，否则浏览器校验会失败
    add_ext(x, NID_basic_constraints, "critical,CA:FALSE"); //critical代表关键，默认是非关键，其他扩展也是
    add_ext(x, NID_key_usage, "digitalSignature,nonRepudiation,keyEncipherment,dataEncipherment");

    if (!X509_sign(x, rootKey, EVP_sha256())) { //使用CA根证书签名域证书
        return 0;
    }

    *pkey = pk;
    *domainCert = x;

    return 1;
}