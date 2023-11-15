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

int Cert::add_ext(STACK_OF(X509_EXTENSION) *sk, int nid, char *value)
{
    X509_EXTENSION *ex;
    ex = X509V3_EXT_conf_nid(NULL, NULL, nid, value);
    if (!ex)
        return 0;
    sk_X509_EXTENSION_push(sk, ex);

    return 1;
}

int Cert::mkreq(X509_REQ **csr, EVP_PKEY **privateKey, int serial, int days)
{
    X509_REQ *x;
    EVP_PKEY *pk;
    X509_NAME *name = NULL;
    STACK_OF(X509_EXTENSION) *exts = NULL;

    if ((pk = EVP_PKEY_new()) == NULL){
        return 0;
    }
    if ((x = X509_REQ_new()) == NULL){
        return 0;
    }


    if (!EVP_PKEY_assign_RSA(pk, rsa)) {
        return 0;
    }

    X509_REQ_set_pubkey(x, pk);
    name = X509_REQ_get_subject_name(x);

    /*
     * This function creates and adds the entry, working out the correct
     * string type and performing checks on its length. Normally we'd check
     * the return value for errors...
     */
    unsigned char c[] = "CN";
    unsigned char cn[] = "my.test.com";
    unsigned char o[] = "lisong.com.cn";
    unsigned char ou[] = "lisong.com";
    X509_NAME_add_entry_by_txt(name, "C", MBSTRING_ASC, c, -1, -1, 0);
    X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC, cn, -1, -1, 0);
    X509_NAME_add_entry_by_txt(name, "O", MBSTRING_ASC, o, -1, -1, 0);
    X509_NAME_add_entry_by_txt(name, "OU", MBSTRING_ASC, ou, -1, -1, 0);

    if (!X509_REQ_sign(x, pk, EVP_sha1())) {
        return 0;
    }
    *csr = x;
    *privateKey = pk;
    return 1;
}

int Cert::createCertFromRequestFile(EVP_PKEY **privateKey, X509 **domainCert)
{
    X509 * rootCert = PEM_read_bio_X509(rootCertIn, NULL, 0, NULL); //x509根证书对象
    EVP_PKEY * rootKey = PEM_read_bio_PrivateKey(rootKeyIn, NULL, 0, NULL); //根证书密钥对象
    
    X509_REQ *csr = NULL;
    mkreq(&csr, privateKey, 0, 365);
    RSA_print_fp(stdout, EVP_PKEY_get1_RSA(*privateKey), 0);
    X509_REQ_print_fp(stdout, csr);

    EVP_PKEY *userKey = NULL;
    X509 *userCert = NULL;
    userKey = X509_REQ_get_pubkey(csr); //从请求文件中获取公钥
    userCert = X509_new(); //x509对象 用于生成证书

    X509_set_version(userCert, 2);
    ASN1_INTEGER_set(X509_get_serialNumber(userCert), 1);
    X509_gmtime_adj(X509_get_notBefore(userCert), 0);
    X509_gmtime_adj(X509_get_notAfter(userCert), (long)60 * 60 * 24 * 365);
    X509_set_pubkey(userCert, userKey); //将公钥载入至用户证书
    EVP_PKEY_free(userKey);

    // X509_set_subject_name(userCert, csr->req_info.subject);
    X509_set_subject_name(userCert, X509_REQ_get_subject_name(csr));
    X509_set_issuer_name(userCert, X509_get_issuer_name(rootCert));
    X509_sign(userCert, rootKey, EVP_sha1()); //CA私钥签名

    *domainCert = userCert;

    return 1;

    // 按格式签发用户证书并生成私钥
    // BIO * bcert = NULL, *bkey = NULL;
    // int i,j,ret;
    // if(format == FORMAT_DER)
    // {
    //     ret = 1;
    //     i = i2d_X509_bio(bcert, userCert);
    //     j = i2d_PrivateKey_bio(bkey, userKey);
    // }
    // else if(format == FORMAT_PEM)
    // {
    //     ret = 1;
    //     i = PEM_write_bio_X509(bcert, userCert);
    //     j = PEM_write_bio_PrivateKey(bkey, userKey, NULL, NULL, 0, NULL, NULL);
    // }
    // if(!i)
    // {
    //     ui->textBrowser->append(getTime() + "签发PEM或DER用户文件时发生错误");
    //     ret = 0;
    // }
    // return ret;
}