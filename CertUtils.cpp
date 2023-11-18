#include "CertUtils.h"

using namespace std;

CertUtils::CertUtils() : rsa(NULL), rootCert(NULL), rootKey(NULL)
{
    // 生成RSA密钥对-begin
    BIGNUM *bne = BN_new();
    unsigned long e = RSA_F4;
    int ret = BN_set_word(bne, e);
    if (ret != 1)
    {
        fprintf(stderr, "MakeLocalKeySSL BN_set_word err \n");
        return;
    }
    this->rsa = RSA_new();
    ret = RSA_generate_key_ex(rsa, 1024, bne, NULL);
    if (ret != 1)
    {
        fprintf(stderr, "MakeLocalKeySSL RSA_generate_key_ex err \n");
        return;
    }
    // 生成RSA密钥对-end

    // 加载根证书-begin
    BIO *rootCertIn = BIO_new_file("rootCA/rootCA.crt", "r");
    BIO *rootKeyIn = BIO_new_file("rootCA/rootCA.key.pem", "r");
    this->rootCert = PEM_read_bio_X509(rootCertIn, NULL, 0, NULL);     // x509根证书对象
    this->rootKey = PEM_read_bio_PrivateKey(rootKeyIn, NULL, 0, NULL); // 根证书密钥对象
    if (!this->rootCert)
    {
        fprintf(stderr, "PEM_read_bio_X509 调用失败 \n");
    }
    if (!this->rootKey)
    {
        fprintf(stderr, "PEM_read_bio_PrivateKey 调用失败 \n");
    }
    BIO_free(rootCertIn);
    BIO_free(rootKeyIn);
    // 加载根证书-end
};

int CertUtils::add_ext(X509 *cert, int nid, char *value)
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

int CertUtils::createCertFromRequestFile(EVP_PKEY **pkey, X509 **domainCert, char *serverName)
{
    X509 *x;
    EVP_PKEY *pk;
    X509_NAME *name = NULL;

    pk = EVP_PKEY_new();
    x = X509_new();

    if (!EVP_PKEY_assign_RSA(pk, this->rsa))
    {
        fprintf(stderr, "EVP_PKEY_assign_RSA 调用失败");
        return 0;
    }

    X509_set_version(x, 2);
    ASN1_INTEGER_set(X509_get_serialNumber(x), 1);
    X509_gmtime_adj(X509_get_notBefore(x), 0);
    X509_gmtime_adj(X509_get_notAfter(x), (long)60 * 60 * 24 * 365);
    X509_set_pubkey(x, pk);

    name = X509_get_subject_name(x);

    unsigned char c[] = "CN";
    unsigned char o[] = "Internet Widgits Pty Ltd";
    unsigned char ou[] = "Internet Widgits Pty Ltd";

    X509_NAME_add_entry_by_txt(name, "C", MBSTRING_ASC, c, -1, -1, 0);
    X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC, (unsigned char *)serverName, -1, -1, 0);
    X509_NAME_add_entry_by_txt(name, "O", MBSTRING_ASC, o, -1, -1, 0);
    X509_NAME_add_entry_by_txt(name, "OU", MBSTRING_ASC, ou, -1, -1, 0);

    X509_set_issuer_name(x, X509_get_issuer_name(rootCert));

    string altName = "IP:127.0.0.1,DNS:";
    altName += serverName;

    add_ext(x, NID_subject_alt_name, (char *)altName.c_str());              // DNS必须，否则浏览器校验会失败
    add_ext(x, NID_basic_constraints, (char *)"critical,CA:FALSE"); // critical代表关键，默认是非关键，其他扩展也是
    add_ext(x, NID_key_usage, (char *)"digitalSignature,nonRepudiation,keyEncipherment,dataEncipherment");

    if (!X509_sign(x, rootKey, EVP_sha256()))
    { // 使用CA根证书签名域证书
        fprintf(stderr, "X509_sign 调用失败");
        return 0;
    }

    *pkey = pk;
    *domainCert = x;

    return 1;
}