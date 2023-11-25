#ifndef HttpUtils_h
#define HttpUtils_h
#include <iostream>
#include <fstream>
#include <climits>
#include "SockContainer.h"
#include "utils.h"

using namespace std;

#define READ_AGAIN LONG_MAX
#define READ_END 0
#define READ_ERROR 0
class HttpUtils
{
private:
public:
    HttpUtils();
    ~HttpUtils();
    HttpHeader *getHttpHeader(SockInfo *sockInfo);
    HttpHeader *reciveReqHeader(SockInfo &sockInfo, int &hasError);
    void reciveReqBody(SockInfo &sockInfo, int &hasError);
    ssize_t reciveReqData(SockInfo &sockInfo);
    ssize_t readData(SockInfo &sockInfo, char *buf, size_t length);
    ssize_t writeData(SockInfo &sockInfo, char *buf, size_t length);
    ssize_t getSockErr(SockInfo &sockInfo, ssize_t err);
    ssize_t sendTunnelOk(SockInfo &sockInfo);
    int sendFile(SockInfo &sockInfo);
    ssize_t send404(SockInfo &sockInfo);
    string getType(string fName);
    char *readFile(ifstream &inFile, size_t &len);
    string findFileName(string s);
};
#endif