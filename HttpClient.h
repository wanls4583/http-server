#include <iostream>
#include "SockInfo.h"
#include "utils.h"

using namespace std;

class HttpClient
{
private:
public:
    HttpClient();
    ~HttpClient();
    HttpHeader *getHttpHeader(SockInfo *sockInfo);
    char *createReqData(SockInfo *sockInfo);
    int sendReqData(SockInfo *sockInfo);
};