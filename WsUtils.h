#ifndef WsUtils_h
#define WsUtils_h
#include "SockInfo.h"
#include "WsFragment.h"

class WsUtils {
public:
    WsFragment* parseFragment(SockInfo& sockInfo);
    void freeFragment(WsFragment* fragment);
    int fragmentComplete(WsFragment* fragment);
    u_int64_t getMsgLength(WsFragment* fragment);
    unsigned char* getMsg(WsFragment* fragment);
    unsigned char* createMsg(WsFragment* fragment);
    ssize_t sendMsg(SockInfo& sockinfo, unsigned char* msg, u_int64_t size, int fin = 1, int opCode = 1);
};
#endif