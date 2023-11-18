#include <fstream>
#include <iostream>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
// #include <openssl/applink.c>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/bio.h>
#include <pthread.h>
#include "TlsUtils.h"

using namespace std;

#define CHK_NULL(x)                 \
    if ((x) == NULL)                \
    {                               \
        cout << "CHK_NULL" << endl; \
        shutdownSock();             \
        pthread_exit(NULL);         \
    }
#define CHK_SSL(err)                 \
    if ((err) == -1)                 \
    {                                \
        ERR_print_errors_fp(stderr); \
        cout << "CHK_SSL" << endl;   \
        shutdownSock();              \
        pthread_exit(NULL);          \
    }

struct SockInfo
{
    SSL *ssl;
    int clntSock;
};

int initServSock();
void *initClntSock(void *arg);
void shutdownSock();
void initSockInfos();
void resetSockInfo(SockInfo &sockInfo);
SSL *checkSLL(int clntSock);
int readData(int clntSock, SSL *ssl, char *buf, int length);
int writeData(int clntSock, SSL *ssl, char *buf, int length);
int notFound(int clntSock, SSL *ssl);
char *readFile(ifstream &inFile, int &len);
string findFileName(string s);
string getType(string fName);

const int port = 8000;
const int MAX_SOCK = 100;
static int servSock;
static SockInfo sockInfos[MAX_SOCK];
static TlsUtils tlsUtil;

pthread_key_t ptKey; 

int main()
{
    initSockInfos();
    pthread_key_create(&ptKey, NULL);
    servSock = initServSock();

    while (1)
    {
        struct sockaddr_in clntAddr;
        socklen_t clntAddrLen = sizeof(clntAddr);
        int clntSock = accept(servSock, (struct sockaddr *)&clntAddr, &clntAddrLen);
        int i = 0;
        for (; i < 100; i++)
        {
            if (sockInfos[i].clntSock == -1)
            {
                sockInfos[i].clntSock = clntSock;
                break;
            }
        }
        cout << "clntSock:" << clntSock << ";i:" << i << endl;
        pthread_t tid;
        pthread_create(&tid, NULL, initClntSock, &sockInfos[i]);
        pthread_detach(tid);
    }

    shutdown(servSock, SHUT_RDWR);

    return 0;
}


int initServSock()
{
    int servSock = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in servAddr;

    memset(&servAddr, 0, sizeof(servAddr));

    servAddr.sin_family = AF_INET;
    // servAddr.sin_addr.s_addr = inet_addr("127.0.0.1");
    servAddr.sin_addr.s_addr = htonl(INADDR_ANY);
    servAddr.sin_port = htons(port);

    bind(servSock, (struct sockaddr *)&servAddr, sizeof(servAddr));

    listen(servSock, 10);

    return servSock;
}

void *initClntSock(void *arg)
{
    SSL *ssl;
    int err;
    char buf[10240];
    SockInfo sockInfo = *((SockInfo *)arg);
    int clntSock = sockInfo.clntSock;

    pthread_setspecific(ptKey, arg);

    ssl = sockInfo.ssl = checkSLL(clntSock);

    // cout<<"ssl:"<<(ssl!=NULL)<<endl;

    err = readData(clntSock, ssl, buf, sizeof(buf));

    string fName = findFileName(buf);

    if (fName.length())
    {
        fName = "www" + fName;
        ifstream inFile(fName.c_str(), ios::in | ios::binary);

        if (inFile.good())
        {
            string head = "HTTP/1.1 200 OK\n";
            string type = getType(fName);
            int len = 0;
            char *data = readFile(inFile, len);

            head += "Content-Type: " + type + "\n";
            head += "Connection: close\n";
            head += "Content-Length: " + to_string(len) + "\n";
            head += "\n";

            cout << fName << ":" << len << endl;

            writeData(clntSock, ssl, const_cast<char *>(head.c_str()), head.length());
            writeData(clntSock, ssl, data, len);

            delete[] data;
        }
        else
        {
            cout << fName << endl;
            notFound(clntSock, ssl);
        }
    }
    else
    {
        cout << "empty:" << buf << endl;
        notFound(clntSock, ssl);
    }

    shutdownSock();

    return NULL;
}

int readData(int clntSock, SSL *ssl, char *buf, int length)
{
    int err;
    if (ssl == NULL)
    {
        read(clntSock, buf, length);
    }
    else
    {
        err = SSL_read(ssl, buf, length);
        CHK_SSL(err);
    }
    return err;
}

int writeData(int clntSock, SSL *ssl, char *buf, int length)
{
    int err;
    if (ssl == NULL)
    {
        err = write(clntSock, buf, length);
    }
    else
    {
        err = SSL_write(ssl, buf, length);
        CHK_SSL(err);
    }
    return err;
}

void initSockInfos() {
    for (int i = 0; i < MAX_SOCK; i++)
    {
        resetSockInfo(sockInfos[i]);
    }
}

void resetSockInfo(SockInfo &sockInfo) {
    sockInfo.clntSock = -1;
    sockInfo.ssl = NULL;
}

void shutdownSock()
{
    SockInfo &sockInfo = *(SockInfo *)pthread_getspecific(ptKey);
    if (sockInfo.ssl != NULL)
    {
        SSL_shutdown(sockInfo.ssl);
        SSL_free(sockInfo.ssl);
    }
    close(sockInfo.clntSock);
    resetSockInfo(sockInfo);
}

SSL *checkSLL(int clntSock)
{
    char buf[2];
    SSL *ssl = NULL;
    if (tlsUtil.isClntHello(clntSock))
    {
        SSL_CTX *ctx = tlsUtil.getCert(clntSock);
        X509 *client_cert;
        int err;
        char *str;
        ssl = SSL_new(ctx);
        CHK_NULL(ssl);
        SSL_set_fd(ssl, clntSock);
        err = SSL_accept(ssl);
        CHK_SSL(err);

        // printf("SSL connection using %s\n", SSL_get_cipher(ssl));

        client_cert = SSL_get_peer_certificate(ssl);

        if (client_cert != NULL)
        {
            printf("Client certificate:\n");

            str = X509_NAME_oneline(X509_get_subject_name(client_cert), 0, 0);
            CHK_NULL(str);
            printf("\t subject: %s\n", str);
            OPENSSL_free(str);

            str = X509_NAME_oneline(X509_get_issuer_name(client_cert), 0, 0);
            CHK_NULL(str);
            printf("\t issuer: %s\n", str);
            OPENSSL_free(str);

            /* We could do all sorts of certificate verification stuff here before
            deallocating the certificate. */

            X509_free(client_cert);
        }
        else
        {
            // printf("Client does not have certificate.\n");
        }
    }
    return ssl;
}

int notFound(int clntSock, SSL *ssl)
{
    int err;
    string s = "HTTP/1.1 404 Not Found\nConnection: close\n\n404 Not Found";
    if (ssl == NULL)
    {
        err = write(clntSock, s.c_str(), s.length());
    }
    else
    {
        err = SSL_write(ssl, s.c_str(), s.length());
        CHK_SSL(err);
    }
    return err;
}

string getType(string fName)
{
    if (fName.find(".png") == fName.length() - 4)
    {
        return "image/apng";
    }
    else if (fName.find(".jpg") == fName.length() - 4)
    {
        return "image/jpg";
    }
    else
    {
        return "text/html";
    }
}

char *readFile(ifstream &inFile, int &len)
{

    inFile.seekg(0, inFile.end);

    len = inFile.tellg();

    inFile.seekg(0, inFile.beg);

    char *arr = new char[len];

    inFile.read(arr, len);

    return arr;
}

string findFileName(string s)
{
    int n = s.find("\r\n"), n1 = 0;
    if (n < 0)
    {
        return "";
    }
    s = s.substr(0, n);
    n = s.find(" ");
    n1 = s.rfind(" ");
    s = s.substr(n + 1, n1 - n - 1);
    return s;
}