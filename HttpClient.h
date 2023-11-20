#include <iostream>
#include "HttpHeader.h"
#include "utils.h"

using namespace std;

class HttpClient
{
private:
    HttpHeader *header;

public:
    HttpClient();
    ~HttpClient();
    HttpHeader *getHttpHeader(SockInfo *sockInfo);
    char *createReqData();
    int sendReqData(char *req);
};