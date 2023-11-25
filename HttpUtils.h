#include <iostream>
#include "SockContainer.h"
#include "utils.h"

using namespace std;

class HttpUtils
{
private:
public:
    HttpUtils();
    ~HttpUtils();
    HttpHeader *getHttpHeader(SockInfo *sockInfo);
    char *createReqData(SockInfo *sockInfo);
    int sendReqData(SockInfo *sockInfo);
};