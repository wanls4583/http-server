#include "HttpClient.h"

HttpClient::HttpClient()
{
}

HttpClient::~HttpClient()
{
}

char *HttpClient::createReqData(SockInfo *sockInfo)
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

int HttpClient::sendReqData(SockInfo *sockInfo)
{
    return 0;
}

HttpHeader *HttpClient::getHttpHeader(SockInfo *sockInfo)
{
    HttpHeader *header = (HttpHeader *)calloc(1, sizeof(HttpHeader));
    string line = "", prop = "", val = "", req = sockInfo->req;
    int pos = req.find("\r\n");

    if (pos != req.npos)
    {
        line = req.substr(0, pos);
        int lSpace = line.find(' ');
        int rSpace = line.rfind(' ');
        if (lSpace == req.npos)
        {
            return NULL;
        }
        val = line.substr(0, lSpace);
        header->method = new char[val.size() + 1];
        strcpy(header->method, val.c_str());

        val = line.substr(lSpace + 1, rSpace - lSpace - 1);
        header->path = new char[val.size() + 1];
        strcpy(header->path, val.c_str());

        val = line.substr(rSpace + 1);
        header->protocol = new char[val.size() + 1];
        strcpy(header->protocol, val.c_str());

        req = req.substr(pos + 2);
    }
    while ((pos = req.find("\r\n")) != req.npos)
    {
        line = req.substr(0, pos);
        req = req.substr(pos + 2);
        int colon = line.find(": ");
        if (colon == req.npos)
        {
            break;
        }
        prop = line.substr(0, colon);
        val = line.substr(colon + 2);
        if (prop.compare("Host") == 0)
        {
            string host = val;
            colon = val.find(':');
            if (colon == val.npos)
            {
                header->port = sockInfo->ssl ? 443 : 80;
            }
            else
            {
                header->port = atoi(val.substr(colon + 1).c_str());
                host = val.substr(0, colon);
            }
            header->hostname = new char[host.size() + 1];
            strcpy(header->hostname, host.c_str());
        }
        else if (prop.compare("Content-Type") == 0)
        {
            string type = val;
            string boundary = " boundary=";
            char **strs = NULL;
            int len = split(strs, val, ';');
            header->contentType = strs[0];
            for (int i = 1; i < len; i++)
            {
                string s = strs[i];
                if (s.find(boundary) == 0)
                {
                    header->boundary = new char[s.size() - boundary.size() + 1];
                    strcpy(header->boundary, s.substr(boundary.size()).c_str());
                }
            }
        }
        else if (prop.compare("Content-Length") == 0)
        {
            header->contentLenth = atoi(val.c_str());
        }
        else if (prop.compare("Connection") == 0)
        {
            header->connnection = new char[val.size() + 1];
            strcpy(header->connnection, val.c_str());
        }
        else if (prop.compare("Proxy-Connection") == 0)
        {
            header->proxyConnection = new char[val.size() + 1];
            strcpy(header->proxyConnection, val.c_str());
        }
        else if (prop.compare("User-Agent") == 0)
        {
            header->userAgent = new char[val.size() + 1];
            strcpy(header->userAgent, val.c_str());
        }
        else if (prop.compare("Accept") == 0)
        {
            header->accept = new char[val.size() + 1];
            strcpy(header->accept, val.c_str());
        }
        else if (prop.compare("Referer") == 0)
        {
            header->referer = new char[val.size() + 1];
            strcpy(header->referer, val.c_str());
        }
        else if (prop.compare("Accept-Encoding") == 0)
        {
            header->acceptEncoding = new char[val.size() + 1];
            strcpy(header->acceptEncoding, val.c_str());
        }
        else if (prop.compare("Accept-Language") == 0)
        {
            header->acceptLanguage = new char[val.size() + 1];
            strcpy(header->acceptLanguage, val.c_str());
        }
    }

    if (header->path)
    {
        string path = header->path;
        pos = path.find("://");
        if (pos != path.npos)
        {
            header->url = header->path;
            path = path.substr(pos + 3);
            pos = path.find('/');
            path = path.substr(pos);
            header->path = (char *)calloc(1, path.size() + 1);
            stpcpy(header->path, path.c_str());
        }
        else if (header->path[0] == '/')
        {
            string url = sockInfo->ssl ? "https://" : "http://";
            url += header->hostname;
            url += ":";
            url += to_string(header->port);
            url += header->path;
            header->url = new char[url.size() + 1];
            strcpy(header->url, url.c_str());
        }
    }

    return header;
}