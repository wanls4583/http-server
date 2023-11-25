#include "Proxy.h"

Proxy::Proxy()
{
}

Proxy::~Proxy()
{
}

char *Proxy::createReqData(SockInfo *sockInfo)
{
    string firstLine = "";
    string req = sockInfo->req;
    HttpHeader *header = sockInfo->header;
    char *str = NULL;
    int pos = req.find("\r\n");

    firstLine += header->method;
    firstLine += " ";
    firstLine += header->path;
    firstLine += " ";
    firstLine += header->protocol;

    req = firstLine + req.substr(pos);
    str = (char *)calloc(1, req.size());

    return str;
}