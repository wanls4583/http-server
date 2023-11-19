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
    char *ip;
};

typedef struct HttpHeader
{
    char *hostname;
    char *protocol;
    char *method;
    char *connnection;
    char *proxyConnection;
    char *userAgent;
    char *accept;
    char *referer;
    char *acceptEncoding;
    char *acceptLanguage;
    int port;
} HttpHeader;

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
HttpHeader *getHttpHeader(string req);
string findFileName(string s);
string getType(string fName);

const int port = 8000;
const int MAX_SOCK = 100;
static int servSock;
static SockInfo sockInfos[MAX_SOCK];
static TlsUtils tlsUtil;
struct sockaddr_in servAddr;

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
        char *ip = inet_ntoa(servAddr.sin_addr);
        for (; i < 100; i++)
        {
            if (sockInfos[i].clntSock == -1)
            {
                sockInfos[i].clntSock = clntSock;
                sockInfos[i].ip = (char *)malloc(strlen(ip)); // inet_ntoa 获取到的地址永远是同一块地址
                memcpy(sockInfos[i].ip, ip, strlen(ip));
                break;
            }
        }
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
    err = readData(clntSock, ssl, buf, sizeof(buf));

    HttpHeader *header = getHttpHeader(buf);
    if (!header || !header->hostname)
    {
        shutdown(servSock, SHUT_RDWR);
        return NULL;
    }
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

            // cout << fName << ":" << len << endl;

            writeData(clntSock, ssl, const_cast<char *>(head.c_str()), head.length());
            writeData(clntSock, ssl, data, len);

            delete[] data;
        }
        else
        {
            // cout << "notFound:" << buf << endl;
            notFound(clntSock, ssl);
        }
    }
    else
    {
        // cout << "empty:" << buf << endl;
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

void initSockInfos()
{
    for (int i = 0; i < MAX_SOCK; i++)
    {
        resetSockInfo(sockInfos[i]);
    }
}

void resetSockInfo(SockInfo &sockInfo)
{
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
    SSL_CTX *ctx = NULL;
    if (!tlsUtil.isClntHello(clntSock))
    {
        return NULL;
    }
    ctx = tlsUtil.getCert(clntSock);
    if (!ctx)
    {
        return NULL;
    }
    X509 *client_cert;
    int err;
    char *str;
    ssl = SSL_new(ctx);
    CHK_NULL(ssl);
    SSL_set_fd(ssl, clntSock);
    err = SSL_accept(ssl);
    CHK_SSL(err);
    // printf("SSL connection using %s\n", SSL_get_cipher(ssl)); // TLS_AES_128_GCM_SHA256
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

HttpHeader *getHttpHeader(string req)
{
    HttpHeader *header = (HttpHeader *)calloc(1, sizeof(HttpHeader));
    string line = "", prop = "", val = "";
    int pos = req.find("\r\n"), n = 0;
    if (pos != req.npos)
    {
        line = req.substr(0, pos);
        n = line.find(' ');
        if (n == req.npos)
        {
            return NULL;
        }
        val = line.substr(0, n);
        header->method = new char[val.size() + 1];
        strcpy(header->method, val.c_str());
        val = line.substr(line.rfind(' ') + 1);
        header->protocol = new char[val.size() + 1];
        strcpy(header->protocol, val.c_str());
        req = req.substr(pos + 2);
    }
    while ((pos = req.find("\r\n")) != req.npos)
    {
        line = req.substr(0, pos);
        req = req.substr(pos + 2);
        n = line.find(": ");
        if (n == req.npos)
        {
            break;
        }
        prop = line.substr(0, n);
        val = line.substr(n + 2);
        // cout<<prop<<":"<<val<<endl;
        if (prop.compare("Host") == 0)
        {
            n = val.find(':');
            string host = val.substr(0, n);
            header->hostname = new char[host.size()];
            strcpy(header->hostname, host.c_str());
            header->port = atoi(val.substr(n + 1).c_str());
        }
        else if (prop.compare("Connection") == 0)
        {
            header->connnection = new char[val.size() + 1];
            strcpy(header->connnection, val.c_str());
        }
        else if (prop.compare("Proxy-Connection") == 0)
        {
            header->proxyConnection = new char[val.size() + 1];
            strcpy(header->proxyConnection, val.c_str());
        }
        else if (prop.compare("User-Agent") == 0)
        {
            header->userAgent = new char[val.size() + 1];
            strcpy(header->userAgent, val.c_str());
        }
        else if (prop.compare("Accept") == 0)
        {
            header->accept = new char[val.size() + 1];
            strcpy(header->accept, val.c_str());
        }
        else if (prop.compare("Referer") == 0)
        {
            header->referer = new char[val.size() + 1];
            strcpy(header->referer, val.c_str());
        }
        else if (prop.compare("Accept-Encoding") == 0)
        {
            header->acceptEncoding = new char[val.size() + 1];
            strcpy(header->acceptEncoding, val.c_str());
        }
        else if (prop.compare("Accept-Language") == 0)
        {
            header->acceptLanguage = new char[val.size() + 1];
            strcpy(header->acceptLanguage, val.c_str());
        }
    }

    return header;
}