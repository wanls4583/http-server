#ifndef HttpUtils_h
#define HttpUtils_h
#include <iostream>
#include <fstream>
#include <climits>
#include <sys/stat.h>
#include "SockContainer.h"
#include "WsUtils.h"
#include "utils.h"

using namespace std;

#define READ_AGAIN LONG_MAX
#define READ_END 0
#define READ_ERROR LONG_MIN
class HttpUtils {
private:
    int cpuTime;
    int endTryTimes;
    HttpHeader* getHttpReqHeader(SockInfo& sockInfo);
    HttpHeader* getHttpResHeader(SockInfo& sockInfo);
    void setHeaderKeyValue(HttpHeader* header, string head);
    ssize_t preReadData(SockInfo& sockInfo, char* buf, ssize_t length);
    ssize_t readData(SockInfo& sockInfo, char* buf, ssize_t length);
    ssize_t getSockErr(SockInfo& sockInfo, ssize_t err);
public:
    HttpUtils();
    ~HttpUtils();
    int checkMethod(const char* method);
    char* replaceHeaderKeyVal(char* header, char* prop, char* val);
    char* addHeaderKeyVal(char* header, char* hkey, char* hval);
    char* delHeaderKeyVal(char* header, char* hkey);
    char* getSecWebSocketAccept(SockInfo& sockInfo);
    string getBoundary(HttpHeader* header);
    void preReciveHeader(SockInfo& sockInfo, int& hasError);
    HttpHeader* reciveHeader(SockInfo& sockInfo, int& hasError);
    WsFragment* reciveWsFragment(SockInfo& sockInfo, int& hasError);
    void reciveSocksReqHeader(SockInfo& sockInfo, int& hasError);
    ssize_t waiteData(SockInfo& sockInfo);
    ssize_t reciveData(SockInfo& sockInfo);
    ssize_t freeData(SockInfo& sockInfo);
    ssize_t writeData(SockInfo& sockInfo, char* buf, ssize_t length);
    void checkError(SockInfo& sockInfo, ssize_t& bufSize, int& hasError);
    bool checkIfWebScoket(HttpHeader* header);
    bool checkIfResponsBody(HttpHeader* header, char* method);
    ssize_t sendTunnelOk(SockInfo& sockInfo);
    ssize_t sendUpgradeOk(SockInfo& sockInfo);
    ssize_t sendSocksOk(SockInfo& sockInfo);
    ssize_t sendSocksRes(SockInfo& sockInfo);
    int sendFile(SockInfo& sockInfo);
    ssize_t send404(SockInfo& sockInfo);
    string getType(string fName);
    void createReqData(SockInfo& sockInfo, char*& req, ssize_t& reqSize);
};
#endif