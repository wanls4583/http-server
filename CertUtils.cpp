#include "CertUtils.h"
#include "utils/hex.h"

#define pemFilePath "rootCA/rootCA.crt"
#define keyFilePath "rootCA/rootCA.key"

using namespace std;

CertUtils::CertUtils(): rsa(NULL), rootCert(NULL), rootKey(NULL) {
    // 生成RSA密钥对-begin
    BIGNUM* bne = BN_new();
    unsigned long e = RSA_F4;
    int ret = BN_set_word(bne, e);
    if (ret != 1) {
        fprintf(stderr, "MakeLocalKeySSL BN_set_word err \n");
        return;
    }
    this->rsa = RSA_new();
    // 对于ios系统的客户端，使用RSA密钥的TLS服务器证书和签发证书的CA必须使用长度大于或等于2048位的密钥。TLS 不再信任所用RSA密钥长度小于2048位的证书
    ret = RSA_generate_key_ex(rsa, 2048, bne, NULL);
    if (ret != 1) {
        fprintf(stderr, "MakeLocalKeySSL RSA_generate_key_ex err \n");
        return;
    }
    // 生成RSA密钥对-end

    // 加载根证书-begin
    BIO* rootCertIn = BIO_new_file(pemFilePath, "r");
    BIO* rootKeyIn = BIO_new_file(keyFilePath, "r");
    this->rootCert = PEM_read_bio_X509(rootCertIn, NULL, 0, NULL);     // x509根证书对象
    this->rootKey = PEM_read_bio_PrivateKey(rootKeyIn, NULL, 0, NULL); // 根证书密钥对象
    if (!this->rootCert) {
        fprintf(stderr, "PEM_read_bio_X509 调用失败 \n");
    }
    if (!this->rootKey) {
        fprintf(stderr, "PEM_read_bio_PrivateKey 调用失败 \n");
    }
    BIO_free(rootCertIn);
    BIO_free(rootKeyIn);
    // 加载根证书-end
};

int CertUtils::add_ext(X509* cert, int nid, char* value) {
    X509_EXTENSION* ex;
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

int CertUtils::createCertFromRequestFile(EVP_PKEY** pkey, X509** domainCert, char* serverName) {
    X509* x;
    EVP_PKEY* pk;
    X509_NAME* name = NULL;

    pk = EVP_PKEY_new();
    x = X509_new();

    if (!EVP_PKEY_assign_RSA(pk, this->rsa)) {
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
    X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC, (unsigned char*)serverName, -1, -1, 0);
    X509_NAME_add_entry_by_txt(name, "O", MBSTRING_ASC, o, -1, -1, 0);
    X509_NAME_add_entry_by_txt(name, "OU", MBSTRING_ASC, ou, -1, -1, 0);

    X509_set_issuer_name(x, X509_get_issuer_name(rootCert));

    string altName = "";
    char lastCh = serverName[strlen(serverName) - 1];
    if (lastCh >= '1' && lastCh <= '9') { // ip地址
        altName += "IP:";
        altName += serverName;
    } else {
        altName += "DNS:";
        altName += serverName;
    }

    add_ext(x, NID_subject_alt_name, (char*)altName.c_str());      // DNS必须，否则浏览器校验会失败
    add_ext(x, NID_basic_constraints, (char*)"critical,CA:FALSE"); // critical代表关键，默认是非关键，其他扩展也是
    add_ext(x, NID_key_usage, (char*)"digitalSignature,nonRepudiation,keyEncipherment,dataEncipherment");

    if (!X509_sign(x, rootKey, EVP_sha256())) { // 使用CA根证书签名域证书
        fprintf(stderr, "X509_sign 调用失败");
        return 0;
    }

    *pkey = pk;
    *domainCert = x;

    return 1;
}

char* CertUtils::getRootCertNameByOid(char* oId) {
    X509_NAME* name = X509_get_issuer_name(rootCert);
    int entryCount = X509_NAME_entry_count(name);
    for (int i = 0; i < entryCount; i++) {
        X509_NAME_ENTRY* entry = X509_NAME_get_entry(name, i);
        ASN1_OBJECT* obj = X509_NAME_ENTRY_get_object(entry);
        ASN1_STRING* data = X509_NAME_ENTRY_get_data(entry);
        // 解析OID为可读字符串
        char oidStr[80];
        OBJ_obj2txt(oidStr, sizeof(oidStr), obj, 1);
        // 获取数据
        char* dataStr = (char*)ASN1_STRING_get0_data(data);
        // 打印结果
        // printf("Field %d: OID=%s, Data=%s\n", i, oidStr, dataStr);
        if (!strcmp(oidStr, oId)) {
            return dataStr;
        }
    }
    return (char*)calloc(1, 1);
}

void showX509(X509* x509) {
    X509_NAME* subject = X509_get_subject_name(x509);
    X509_NAME* isUser = X509_get_issuer_name(x509);
    char* subject_str = X509_NAME_oneline(subject, NULL, 0);
    char* issuer_str = X509_NAME_oneline(isUser, NULL, 0);
    printf("subject: %s\n", subject_str);
    printf("issuer: %s\n", issuer_str);

    int entryCount = X509_NAME_entry_count(subject);
    for (int i = 0; i < entryCount; i++) {
        X509_NAME_ENTRY* entry = X509_NAME_get_entry(subject, i);
        ASN1_OBJECT* obj = X509_NAME_ENTRY_get_object(entry);
        ASN1_STRING* data = X509_NAME_ENTRY_get_data(entry);
        // 解析OID为可读字符串
        char oidStr[80];
        OBJ_obj2txt(oidStr, sizeof(oidStr), obj, 1);
        // 获取数据
        char* dataStr = (char*)ASN1_STRING_get0_data(data);
        // 打印结果
        printf("Field %d: OID=%s, Data=%s\n", i, oidStr, dataStr);
    }
    int version = ((int)X509_get_version(x509)) + 1;
    printf("tls_version: %d\n", version);

    ASN1_INTEGER* serial = X509_get_serialNumber(x509);
    BIGNUM* bn = ASN1_INTEGER_to_BN(serial, NULL);
    char* tmp = BN_bn2hex(bn);
    printf("serial: %s\n", tmp);

    char buf[4096] = { 0 };
    const EVP_MD* digest = EVP_sha1();
    unsigned len;
    int rc = X509_digest(x509, digest, (unsigned char*)buf, &len);
    printf("digest: ");
    show_hex(buf, len, 1);

    ASN1_TIME* not_before = X509_get_notBefore(x509);
    ASN1_TIME* not_after = X509_get_notAfter(x509);
    printf("not_before: %s\n", not_before->data);
    printf("not_after: %s\n", not_after->data);

    GENERAL_NAMES* subjectAltNames = (GENERAL_NAMES*)X509_get_ext_d2i(x509, NID_subject_alt_name, NULL, NULL);
    int cnt = sk_GENERAL_NAME_num(subjectAltNames);
    for (int i = 0; i < cnt; i++) {
        GENERAL_NAME* generalName = sk_GENERAL_NAME_value(subjectAltNames, i);
        if (generalName->type == GEN_DNS) {
            cout << generalName->d.dNSName->data << endl;
        } else if (generalName->type == GEN_IPADD) {
            unsigned char* data = generalName->d.ip->data;
            cout << data[0] << '.' << data[1] << '.' << data[2] << '.' << data[3] << endl;
        }
    }
}