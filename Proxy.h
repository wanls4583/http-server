#ifndef Proxy_h
#define Proxy_h
#include <iostream>
#include "SockContainer.h"

using namespace std;

#define READ_AGAIN LONG_MAX
#define READ_END 0
#define READ_ERROR 0
class Proxy
{
private:
public:
    Proxy();
    ~Proxy();
    char *createReqData(SockInfo *sockInfo);
};
#endif