#ifndef SocksReqHeader_h
#define SocksReqHeader_h

typedef struct SocksReqHeader {
    int version;
    int cmd;
    int rsv;
    int atyp;
    char* addr;
    int  port;
} SocksReqHeader;
#endif