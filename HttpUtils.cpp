#include "HttpUtils.h"

extern SockContainer sockContainer;

HttpUtils::HttpUtils()
{
}

HttpUtils::~HttpUtils()
{
}

HttpHeader *HttpUtils::getHttpHeader(SockInfo *sockInfo)
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
            free(strs);
        }
        else if (prop.compare("Content-Length") == 0)
        {
            header->contentLenth = atol(val.c_str());
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

HttpHeader *HttpUtils::reciveReqHeader(SockInfo &sockInfo, int &hasError)
{
    HttpHeader *header = NULL;
    ssize_t bufSize = 0;
    while (!sockInfo.header)
    {
        bufSize = this->reciveReqData(sockInfo);

        if (READ_ERROR == bufSize || READ_END == bufSize || sockInfo.closing || -1 == sockInfo.clntSock)
        {
            hasError = 1;
            break;
        }
        else if (READ_AGAIN == bufSize)
        {
            if (!sockContainer.checkSockTimeout(sockInfo))
            {
                hasError = 1;
                break;
            }
            usleep(1);
            continue;
        }

        size_t pos = kmpStrstr(sockInfo.buf, "\r\n\r\n", sockInfo.bufSize, 4);

        if (pos != -1)
        {
            sockInfo.reqSize = pos + 4;
            sockInfo.req = (char *)calloc(1, sockInfo.reqSize + 1);
            memcpy(sockInfo.req, sockInfo.buf, sockInfo.reqSize);
            header = this->getHttpHeader(&sockInfo);
            sockInfo.header = header;

            sockInfo.bufSize -= sockInfo.reqSize;
            if (sockInfo.bufSize)
            {
                char *buf = (char *)calloc(1, sockInfo.bufSize + 1);
                memcpy(buf, sockInfo.buf + sockInfo.reqSize, sockInfo.bufSize);
                free(sockInfo.buf);
                sockInfo.buf = buf;
            }
            else
            {
                free(sockInfo.buf);
                sockInfo.buf = NULL;
            }
            break;
        }

        if (sockInfo.bufSize > MAX_REQ_SIZE)
        { // 请求头超出限制
            bufSize = -1;
            break;
        }
    }

    return header;
}

void HttpUtils::reciveReqBody(SockInfo &sockInfo, int &hasError)
{
    ssize_t preSize = -1;
    ssize_t bufSize = -1;
    HttpHeader *header = sockInfo.header;

    while (1)
    {
        if (preSize == -1)
        {
            preSize = sockInfo.bufSize;
        }
        else
        {
            preSize = sockInfo.bufSize;
            bufSize = this->reciveReqData(sockInfo);
        }

        if (READ_ERROR == bufSize || READ_END == bufSize || sockInfo.closing || -1 == sockInfo.clntSock)
        {
            hasError = 1;
            break;
        }
        else if (READ_AGAIN == bufSize)
        {
            if (!sockContainer.checkSockTimeout(sockInfo))
            {
                hasError = 1;
                break;
            }
            usleep(1);
            continue;
        }

        if (header->contentLenth)
        {
            if (header->contentLenth <= sockInfo.bufSize)
            {
                sockInfo.bodySize = header->contentLenth;
                sockInfo.body = (char *)calloc(1, sockInfo.bodySize + 1);
                memcpy(sockInfo.body, sockInfo.buf, sockInfo.bodySize);
                break;
            }
        }
        else if (header->boundary)
        {
            if (sockInfo.bufSize)
            {
                string boundary = "--";
                boundary += header->boundary;
                boundary += "--\r\n";
                preSize = preSize > boundary.size() ? preSize - boundary.size() : preSize;
                size_t pos = kmpStrstr(sockInfo.buf, boundary.c_str(), sockInfo.bufSize, boundary.size(), preSize);
                if (pos != -1)
                {
                    sockInfo.bodySize = pos + boundary.size();
                    sockInfo.body = (char *)calloc(1, sockInfo.bodySize + 1);
                    memcpy(sockInfo.body, sockInfo.buf, sockInfo.bodySize);
                    break;
                }
            }
        }
        else if (header->contentLenth == 0)
        {
            break;
        }

        if (sockInfo.bufSize > MAX_BODY_SIZE)
        { // 请求体超出限制
            bufSize = READ_ERROR;
            break;
        }
    }

    if (!hasError && sockInfo.bodySize)
    {
        sockInfo.bufSize -= sockInfo.bodySize;
        if (sockInfo.bufSize)
        {
            char *buf = (char *)calloc(1, sockInfo.bufSize + 1);
            memcpy(buf, sockInfo.buf + sockInfo.bodySize, sockInfo.bufSize);
            free(sockInfo.buf);
            sockInfo.buf = buf;
        }
        else
        {
            free(sockInfo.buf);
            sockInfo.buf = NULL;
        }
    }
}

ssize_t HttpUtils::reciveReqData(SockInfo &sockInfo)
{
    char buf[1024 * 10];
    ssize_t bufSize = this->readData(sockInfo, buf, sizeof(buf));

    if (bufSize > 0 && READ_AGAIN != bufSize)
    {
        sockInfo.buf = (char *)realloc(sockInfo.buf, sockInfo.bufSize + bufSize + 1);
        memcpy(sockInfo.buf + sockInfo.bufSize, buf, bufSize);
        sockInfo.bufSize += bufSize;
        sockInfo.buf[sockInfo.bufSize] = '\0';
    }
    return bufSize;
}

ssize_t HttpUtils::readData(SockInfo &sockInfo, char *buf, size_t length)
{
    ssize_t err;
    ssize_t result;

    if (sockInfo.ssl == NULL)
    {
        err = read(sockInfo.clntSock, buf, length);
    }
    else
    {
        err = SSL_read(sockInfo.ssl, buf, length);
    }

    result = this->getSockErr(sockInfo, err);

    return result;
}

ssize_t HttpUtils::writeData(SockInfo &sockInfo, char *buf, size_t length)
{
    ssize_t err;
    ssize_t result = READ_AGAIN;

    while (READ_AGAIN == result)
    {
        if (sockInfo.ssl == NULL)
        {
            err = write(sockInfo.clntSock, buf, length);
        }
        else
        {
            err = SSL_write(sockInfo.ssl, buf, length);
        }
        result = this->getSockErr(sockInfo, err);
    }

    return result;
}

ssize_t HttpUtils::getSockErr(SockInfo &sockInfo, ssize_t err)
{
    ssize_t result;

    if (sockInfo.ssl == NULL)
    {
        if (err > 0)
        {
            result = err;
        }
        else if (err == 0)
        {
            result = READ_END;
        }
        else if (errno == EINTR || errno == EWOULDBLOCK || errno == EAGAIN)
        {
            result = READ_AGAIN;
        }
        else
        {
            result = READ_ERROR;
        }
    }
    else
    {
        int nRes = SSL_get_error(sockInfo.ssl, err);
        if (nRes == SSL_ERROR_NONE)
        {
            result = err;
        }
        else if (nRes == SSL_ERROR_WANT_READ)
        {
            result = READ_AGAIN;
        }
        else
        {
            result = READ_ERROR;
        }
    }

    return result;
}

ssize_t HttpUtils::sendTunnelOk(SockInfo &sockInfo)
{
    string s = "HTTP/1.1 200 Connection Established\r\n\r\n";
    return write(sockInfo.clntSock, s.c_str(), s.length());
}

int HttpUtils::sendFile(SockInfo &sockInfo)
{
    string fName = this->findFileName(sockInfo.req);
    if (fName.length())
    {
        fName = "www" + fName;
        ifstream inFile(fName.c_str(), ios::in | ios::binary);

        if (inFile.good())
        {
            string head = "HTTP/1.1 200 OK\n";
            string type = this->getType(fName);
            size_t len = 0;
            char *data = this->readFile(inFile, len);

            head += "Content-Type: " + type + "\n";
            if (strcmp(sockInfo.header->connnection, "close") == 0)
            {
                head += "Connection: close\n";
            }
            else
            {
                head += "Connection: keep-alive\n";
                head += "Keep-Alive: timeout=";
                head += to_string(sockContainer.timeout) + "\n";
            }
            head += "Content-Length: " + to_string(len) + "\n";
            head += "\n";

            // cout << fName << ":" << len << endl;

            this->writeData(sockInfo, const_cast<char *>(head.c_str()), head.length());
            this->writeData(sockInfo, data, len);

            free(data);
        }
        else
        {
            // cout << "send404:" << buf << endl;
            this->send404(sockInfo);
            return 0;
        }
        return 1;
    }
    else
    {
        // cout << "empty:" << buf << endl;
        this->send404(sockInfo);
        return 0;
    }
}

ssize_t HttpUtils::send404(SockInfo &sockInfo)
{
    ssize_t err;
    string str404 = "404 Not Found";
    string s = "HTTP/1.1 404 Not Found\r\nConnection: close\r\nContent-Length: ";

    s += to_string(str404.size());
    s += "\r\n\r\n";
    s += str404;

    err = this->writeData(sockInfo, const_cast<char *>(s.c_str()), s.length());

    return err;
}

string HttpUtils::getType(string fName)
{
    if (fName.find(".png") == fName.length() - 4)
    {
        return "image/apng";
    }
    else if (fName.find(".jpg") == fName.length() - 4)
    {
        return "image/jpg";
    }
    else
    {
        return "text/html";
    }
}

char *HttpUtils::readFile(ifstream &inFile, size_t &len)
{

    inFile.seekg(0, inFile.end);

    len = inFile.tellg();

    inFile.seekg(0, inFile.beg);

    char *arr = (char *)calloc(1, len);

    inFile.read(arr, len);

    return arr;
}

string HttpUtils::findFileName(string s)
{
    size_t n = s.find("\r\n"), n1 = 0;
    if (n == s.npos)
    {
        return "";
    }
    s = s.substr(0, n);
    n = s.find(" ");
    n1 = s.rfind(" ");
    s = s.substr(n + 1, n1 - n - 1);
    return s;
}