#ifndef HttpUtils_h
#define HttpUtils_h
#include <iostream>
#include <fstream>
#include <climits>
#include <sys/stat.h>
#include "SockContainer.h"
#include "utils.h"

using namespace std;

#define READ_AGAIN LONG_MAX
#define READ_END 0
#define READ_ERROR LONG_MIN
class HttpUtils {
private:
    int cpuTime;
    int endTryTimes;
public:
    HttpUtils();
    ~HttpUtils();
    HttpHeader* getHttpReqHeader(SockInfo& sockInfo);
    HttpHeader* getHttpResHeader(SockInfo& sockInfo);
    void setHeaderKeyValue(HttpHeader* header, string head);
    int isClntHello(SockInfo& sockInfo);
    HttpHeader* reciveHeader(SockInfo& sockInfo, int& hasError);
    void reciveBody(SockInfo& sockInfo, int& hasError);
    void reciveTlsHeader(SockInfo& sockInfo, int& hasError);
    ssize_t reciveHttpData(SockInfo& sockInfo);
    ssize_t recvData(SockInfo& sockInfo, char* buf, size_t length);
    ssize_t readData(SockInfo& sockInfo, char* buf, size_t length);
    ssize_t writeData(SockInfo& sockInfo, char* buf, size_t length);
    void checkError(SockInfo& sockInfo, ssize_t bufSize, int& endTryTimes, int& loop, int& hasError);
    ssize_t getSockErr(SockInfo& sockInfo, ssize_t err);
    ssize_t sendTunnelOk(SockInfo& sockInfo);
    int sendFile(SockInfo& sockInfo);
    ssize_t send404(SockInfo& sockInfo);
    string getType(string fName);
    char* readFile(ifstream& inFile, size_t& len);
    string createReqData(SockInfo& sockInfo);
};
#endif