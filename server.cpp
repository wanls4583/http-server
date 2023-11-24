#include <fstream>
#include <iostream>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
// #include <sys/malloc.h>
// #include <openssl/applink.c>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/bio.h>
#include <pthread.h>
#include "utils.h"
#include "TlsUtils.h"
#include "HttpClient.h"

#define CHK_ERR(err)                  \
    if ((err) == -1)                  \
    {                                 \
        ERR_print_errors_fp(stderr);  \
        cout << "CHK_ERR" << endl;    \
        sockContainer.shutdownSock(); \
    }

using namespace std;

int initServSock();
void *initClntSock(void *arg);
ssize_t reciveReqData(SockInfo &sockInfo);
ssize_t readData(SockInfo &sockInfo, char *buf, size_t length);
ssize_t writeData(SockInfo &sockInfo, char *buf, size_t length);
ssize_t sendTunnelOk(SockInfo &sockInfo);
ssize_t send404(SockInfo &sockInfo);
int sendFile(SockInfo &sockInfo);
char *readFile(ifstream &inFile, size_t &len);
string findFileName(string s);
string getType(string fName);
void checkSockTimeout(int n);

const int port = 8000;
static int servSock;
static SockContainer sockContainer;
static TlsUtils tlsUtil;
struct sockaddr_in servAddr;

pthread_key_t ptKey;

int main()
{
    pthread_key_create(&ptKey, NULL);
    servSock = initServSock();

    checkSockTimeout(0);

    while (1)
    {
        struct sockaddr_in clntAddr;
        socklen_t clntAddrLen = sizeof(clntAddr);
        int clntSock = accept(servSock, (struct sockaddr *)&clntAddr, &clntAddrLen);
        char *ip = inet_ntoa(clntAddr.sin_addr);
        SockInfo *sockInfo = sockContainer.getSockInfo();
        if (sockInfo)
        {
            pthread_t tid;

            (*sockInfo).clntSock = clntSock;
            (*sockInfo).ip = (char *)calloc(1, strlen(ip) + 1); // inet_ntoa 获取到的地址永远是同一块地址
            memcpy((*sockInfo).ip, ip, strlen(ip));

            pthread_create(&tid, NULL, initClntSock, sockInfo);
            pthread_detach(tid);
            (*sockInfo).tid = tid;
        }
        else
        {
            close(clntSock);
        }
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
    ssize_t bufSize = 0;
    SockInfo &sockInfo = *((SockInfo *)arg);
    HttpHeader *header = NULL;
    HttpClient httpClient;
    int clntSock = sockInfo.clntSock;

    if (!sockInfo.ssl)
    {
        pthread_setspecific(ptKey, arg);
        ssl = sockInfo.ssl = tlsUtil.checkSLL(clntSock);
    }

    while ((bufSize = reciveReqData(sockInfo)) > 0 && !sockInfo.header)
    {
        size_t pos = kmpStrstr(sockInfo.buf, "\r\n\r\n", sockInfo.bufSize, 4);
        if (pos != -1)
        {
            sockInfo.reqSize = pos + 4;
            sockInfo.req = (char *)calloc(1, sockInfo.reqSize + 1);
            memcpy(sockInfo.req, sockInfo.buf, sockInfo.reqSize);
            header = httpClient.getHttpHeader(&sockInfo);
            sockInfo.header = header;

            sockInfo.bufSize -= sockInfo.reqSize;
            if (sockInfo.bufSize)
            {
                char *buf = (char *)calloc(1, sockInfo.bufSize + 1);
                memcpy(buf, sockInfo.buf + sockInfo.reqSize, sockInfo.bufSize);
                free(sockInfo.buf);
                sockInfo.buf = buf;
            }
            else
            {
                free(sockInfo.buf);
                sockInfo.buf = NULL;
            }
            break;
        }

        if (sockInfo.bufSize > MAX_REQ_SIZE)
        { // 请求头超出限制
            bufSize = -1;
            break;
        }
    }

    if (bufSize < 0 || !header || !header->hostname)
    {
        sockContainer.shutdownSock();
        return NULL;
    }

    ssize_t preSize = 0;
    while (bufSize > 0)
    {
        if (header->contentLenth)
        {
            if (header->contentLenth <= sockInfo.bufSize)
            {
                sockInfo.bodySize = header->contentLenth;
                sockInfo.body = (char *)calloc(1, sockInfo.bodySize + 1);
                memcpy(sockInfo.body, sockInfo.buf, sockInfo.bodySize);
                break;
            }
        }
        else if (header->boundary)
        {
            if (sockInfo.bufSize)
            {
                string boundary = "--";
                boundary += header->boundary;
                boundary += "--\r\n";
                preSize = preSize > boundary.size() ? preSize - boundary.size() : preSize;
                size_t pos = kmpStrstr(sockInfo.buf, boundary.c_str(), sockInfo.bufSize, boundary.size(), preSize);
                if (pos != -1)
                {
                    sockInfo.bodySize = pos + boundary.size();
                    sockInfo.body = (char *)calloc(1, sockInfo.bodySize + 1);
                    memcpy(sockInfo.body, sockInfo.buf, sockInfo.bodySize);
                    break;
                }
            }
        }
        else if (header->contentLenth == 0)
        {
            break;
        }

        if (sockInfo.bufSize > MAX_BODY_SIZE)
        { // 请求体超出限制
            bufSize = -1;
            break;
        }

        preSize = sockInfo.bufSize;
        bufSize = reciveReqData(sockInfo);
    }

    if (bufSize < 0)
    {
        sockContainer.shutdownSock();
        return NULL;
    }

    if (sockInfo.bodySize)
    {
        sockInfo.bufSize -= sockInfo.bodySize;
        if (sockInfo.bufSize)
        {
            char *buf = (char *)calloc(1, sockInfo.bufSize + 1);
            memcpy(buf, sockInfo.buf + sockInfo.bodySize, sockInfo.bufSize);
            free(sockInfo.buf);
            sockInfo.buf = buf;
        }
        else
        {
            free(sockInfo.buf);
            sockInfo.buf = NULL;
        }
    }

    // if (strcmp(header->hostname, "my.test.com") != 0)
    // {
    //     sockContainer.shutdownSock();
    //     return NULL;
    // }

    if (strcmp(header->method, "CONNECT") == 0)
    {
        sendTunnelOk(sockInfo);
        initClntSock(&sockInfo);
    }
    else if (strcmp(header->method, "GET") == 0 || strcmp(header->method, "POST") == 0)
    {
        int suc = sendFile(sockInfo);
        if (strcmp(sockInfo.header->connnection, "close") == 0 || suc == 0)
        {
            sockContainer.shutdownSock();
        }
        else
        {
            sockContainer.resetSockInfoData(sockInfo);
            initClntSock(arg);
        }
    }

    return NULL;
}

void checkSockTimeout(int n)
{
    sockContainer.checkSockTimeout();
    signal(SIGALRM, checkSockTimeout);
    alarm(1);
}

ssize_t reciveReqData(SockInfo &sockInfo)
{
    char buf[1024 * 10];
    ssize_t bufSize = readData(sockInfo, buf, sizeof(buf));

    if (bufSize <= 0 || sockInfo.clntSock == -1)
    {
        return -1;
    }

    sockInfo.buf = (char *)realloc(sockInfo.buf, sockInfo.bufSize + bufSize + 1);
    memcpy(sockInfo.buf + sockInfo.bufSize, buf, bufSize);
    sockInfo.bufSize += bufSize;
    sockInfo.buf[sockInfo.bufSize] = '\0';

    return bufSize;
}

ssize_t readData(SockInfo &sockInfo, char *buf, size_t length)
{
    ssize_t err;
    if (sockInfo.ssl == NULL)
    {
        err = read(sockInfo.clntSock, buf, length);
    }
    else
    {
        err = SSL_read(sockInfo.ssl, buf, length);
    }
    gettimeofday(&sockInfo.tv, NULL);

    CHK_ERR(err);
    return err;
}

ssize_t writeData(SockInfo &sockInfo, char *buf, size_t length)
{
    ssize_t err;
    if (sockInfo.ssl == NULL)
    {
        err = write(sockInfo.clntSock, buf, length);
    }
    else
    {
        err = SSL_write(sockInfo.ssl, buf, length);
    }
    CHK_ERR(err);
    return err;
}

ssize_t send404(SockInfo &sockInfo)
{
    ssize_t err;
    string s = "HTTP/1.1 404 Not Found\nConnection: close\n\n404 Not Found";
    if (sockInfo.ssl == NULL)
    {
        err = write(sockInfo.clntSock, s.c_str(), s.length());
    }
    else
    {
        err = SSL_write(sockInfo.ssl, s.c_str(), s.length());
        CHK_ERR(err);
    }
    return err;
}

ssize_t sendTunnelOk(SockInfo &sockInfo)
{
    string s = "HTTP/1.1 200 Connection Established\r\n\r\n";
    return write(sockInfo.clntSock, s.c_str(), s.length());
}

int sendFile(SockInfo &sockInfo)
{
    string fName = findFileName(sockInfo.req);
    if (fName.length())
    {
        fName = "www" + fName;
        ifstream inFile(fName.c_str(), ios::in | ios::binary);

        if (inFile.good())
        {
            string head = "HTTP/1.1 200 OK\n";
            string type = getType(fName);
            size_t len = 0;
            char *data = readFile(inFile, len);

            head += "Content-Type: " + type + "\n";
            if (strcmp(sockInfo.header->connnection, "close") == 0)
            {
                head += "Connection: close\n";
            }
            else
            {
                head += "Connection: keep-alive\n";
                head += "Keep-Alive: timeout=5\n";
            }
            head += "Content-Length: " + to_string(len) + "\n";
            head += "\n";

            // cout << fName << ":" << len << endl;

            writeData(sockInfo, const_cast<char *>(head.c_str()), head.length());
            writeData(sockInfo, data, len);

            delete[] data;
        }
        else
        {
            // cout << "send404:" << buf << endl;
            send404(sockInfo);
        }
        return 1;
    }
    else
    {
        // cout << "empty:" << buf << endl;
        send404(sockInfo);
        return 0;
    }
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

char *readFile(ifstream &inFile, size_t &len)
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
    size_t n = s.find("\r\n"), n1 = 0;
    if (n == s.npos)
    {
        return "";
    }
    s = s.substr(0, n);
    n = s.find(" ");
    n1 = s.rfind(" ");
    s = s.substr(n + 1, n1 - n - 1);
    return s;
}