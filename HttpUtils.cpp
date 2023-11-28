#include "HttpUtils.h"

extern SockContainer sockContainer;

HttpUtils::HttpUtils() {
    this->cpuTime = 1000; // 1毫秒
    this->endTryTimes = 10;
}

HttpUtils::~HttpUtils() {
}

HttpHeader* HttpUtils::getHttpReqHeader(SockInfo& sockInfo) {
    HttpHeader* header = (HttpHeader*)calloc(1, sizeof(HttpHeader));
    string line = "", prop = "", val = "", head = sockInfo.head;
    size_t pos = head.find("\r\n");

    if (pos != head.npos) {
        line = head.substr(0, pos);
        size_t lSpace = line.find(' ');
        size_t rSpace = line.rfind(' ');
        if (lSpace == head.npos) {
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

        head = head.substr(pos + 2);
    }

    this->setHeaderKeyValue(header, head);

    if (!header->port) {
        header->port = sockInfo.ssl ? 443 : 80;
    }

    if (header->path) {
        string path = header->path;
        pos = path.find("://");
        if (pos != path.npos) {
            header->url = header->path;
            header->isProxyHeader = 1;
            path = path.substr(pos + 3);
            pos = path.find('/');
            path = path.substr(pos);
            header->path = (char*)calloc(1, path.size() + 1);
            stpcpy(header->path, path.c_str());
        } else if (header->path[0] == '/') {
            string url = sockInfo.ssl ? "https://" : "http://";
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

HttpHeader* HttpUtils::getHttpResHeader(SockInfo& sockInfo) {
    HttpHeader* header = (HttpHeader*)calloc(1, sizeof(HttpHeader));
    string line = "", prop = "", val = "", head = sockInfo.head;
    size_t pos = head.find("\r\n");

    if (pos != head.npos) {
        size_t space = head.npos;

        line = head.substr(0, pos);
        space = line.find(' ');

        if (space != head.npos) {
            val = line.substr(0, space);
            header->protocol = new char[val.size() + 1];
            strcpy(header->protocol, val.c_str());
            line = line.substr(space + 1);
        }

        space = line.find(' ');

        if (space != head.npos) {
            val = line.substr(0, space);
            header->status = atoi(val.c_str());

            val = line.substr(space + 1);
            header->reason = new char[val.size() + 1];
            strcpy(header->reason, val.c_str());
        }

        head = head.substr(pos + 2);
    }

    this->setHeaderKeyValue(header, head);

    return header;
}

void HttpUtils::setHeaderKeyValue(HttpHeader* header, string head) {
    size_t pos = head.npos;
    string line = "", prop = "", val = "";
    while ((pos = head.find("\r\n")) != head.npos) {
        line = head.substr(0, pos);
        head = head.substr(pos + 2);
        size_t colon = line.find(": ");
        if (colon == head.npos) {
            break;
        }
        prop = line.substr(0, colon);
        val = line.substr(colon + 2);
        if (prop.compare("Host") == 0) {
            string host = val;
            colon = val.find(':');
            if (colon != val.npos) {
                header->port = atoi(val.substr(colon + 1).c_str());
                host = val.substr(0, colon);
            }
            header->hostname = new char[host.size() + 1];
            strcpy(header->hostname, host.c_str());
        } else if (prop.compare("Content-Type") == 0) {
            string type = val;
            string boundary = " boundary=";
            char** strs = NULL;
            int len = split(strs, val, ';');
            header->contentType = strs[0];
            for (int i = 1; i < len; i++) {
                string s = strs[i];
                if (s.find(boundary) == 0) {
                    header->boundary = new char[s.size() - boundary.size() + 1];
                    strcpy(header->boundary, s.substr(boundary.size()).c_str());
                }
            }
            free(strs);
        } else if (prop.compare("Content-Length") == 0) {
            header->contentLenth = atol(val.c_str());
        } else if (prop.compare("Connection") == 0) {
            header->connnection = new char[val.size() + 1];
            strcpy(header->connnection, val.c_str());
        } else if (prop.compare("Proxy-Connection") == 0) {
            header->proxyConnection = new char[val.size() + 1];
            strcpy(header->proxyConnection, val.c_str());
        } else if (prop.compare("User-Agent") == 0) {
            header->userAgent = new char[val.size() + 1];
            strcpy(header->userAgent, val.c_str());
        } else if (prop.compare("Accept") == 0) {
            header->accept = new char[val.size() + 1];
            strcpy(header->accept, val.c_str());
        } else if (prop.compare("Referer") == 0) {
            header->referer = new char[val.size() + 1];
            strcpy(header->referer, val.c_str());
        } else if (prop.compare("Accept-Encoding") == 0) {
            header->acceptEncoding = new char[val.size() + 1];
            strcpy(header->acceptEncoding, val.c_str());
        } else if (prop.compare("Accept-Language") == 0) {
            header->acceptLanguage = new char[val.size() + 1];
            strcpy(header->acceptLanguage, val.c_str());
        }
    }
}

int HttpUtils::isClntHello(SockInfo& sockInfo) {
    char* buf = sockInfo.tlsHeader;
    if (buf && buf[0] == 0x16 && buf[1] == 0x03 && buf[2] == 0x01 && buf[5] == 0x01) {
        return 1;
    }
    return 0;
}

void HttpUtils::reciveTlsHeader(SockInfo& sockInfo, int& hasError) {
    ssize_t bufSize = 0, count = 0;
    int len = 6, endTryTimes = 0, loop = 0;
    char* buf = (char*)calloc(1, len);
    while (count < len) {
        bufSize = this->recvData(sockInfo, buf + count, len - count);

        checkError(sockInfo, bufSize, endTryTimes, loop, hasError);

        if (hasError) {
            break;
        } else if (loop) {
            loop = 0;
            continue;
        }
        count += bufSize;
    }

    if (!hasError) {
        sockInfo.tlsHeader = buf;
    }
}

HttpHeader* HttpUtils::reciveHeader(SockInfo& sockInfo, int& hasError) {
    HttpHeader* header = NULL;
    ssize_t bufSize = 0;
    int endTryTimes = 0, loop = 0;
    while (!sockInfo.header) {
        size_t pos = kmpStrstr(sockInfo.buf, "\r\n\r\n", sockInfo.bufSize, 4);

        if (pos != -1) {
            sockInfo.reqSize = pos + 4;
            sockInfo.head = (char*)calloc(1, sockInfo.reqSize + 1);
            memcpy(sockInfo.head, sockInfo.buf, sockInfo.reqSize);
            header = this->getHttpReqHeader(sockInfo);
            sockInfo.header = header;

            sockInfo.bufSize -= sockInfo.reqSize;
            if (sockInfo.bufSize) {
                char* buf = (char*)calloc(1, sockInfo.bufSize + 1);
                memcpy(buf, sockInfo.buf + sockInfo.reqSize, sockInfo.bufSize);
                free(sockInfo.buf);
                sockInfo.buf = buf;
            } else {
                free(sockInfo.buf);
                sockInfo.buf = NULL;
            }
            break;
        }

        if (sockInfo.bufSize > MAX_REQ_SIZE) { // 请求头超出限制
            break;
        }

        bufSize = this->reciveHttpData(sockInfo);

        checkError(sockInfo, bufSize, endTryTimes, loop, hasError);

        if (hasError) {
            break;
        } else if (loop) {
            loop = 0;
            continue;
        }
    }

    return header;
}

void HttpUtils::reciveBody(SockInfo& sockInfo, int& hasError) {
    ssize_t preSize = 0;
    ssize_t bufSize = sockInfo.bufSize;
    HttpHeader* header = sockInfo.header;
    int endTryTimes = 0, loop = 0;

    while (1) {
        if (header->contentLenth) {
            if (header->contentLenth <= sockInfo.bufSize) {
                sockInfo.bodySize = header->contentLenth;
                sockInfo.body = (char*)calloc(1, sockInfo.bodySize + 1);
                memcpy(sockInfo.body, sockInfo.buf, sockInfo.bodySize);
                break;
            }
        } else if (header->boundary) {
            if (sockInfo.bufSize) {
                string boundary = "--";
                boundary += header->boundary;
                boundary += "--\r\n";
                preSize = preSize > boundary.size() ? preSize - boundary.size() : preSize;
                size_t pos = kmpStrstr(sockInfo.buf, boundary.c_str(), sockInfo.bufSize, boundary.size(), preSize);
                if (pos != -1) {
                    sockInfo.bodySize = pos + boundary.size();
                    sockInfo.body = (char*)calloc(1, sockInfo.bodySize + 1);
                    memcpy(sockInfo.body, sockInfo.buf, sockInfo.bodySize);
                    break;
                }
            }
        } else if (header->contentLenth == 0) {
            break;
        }

        if (sockInfo.bufSize > MAX_BODY_SIZE) { // 请求体超出限制
            bufSize = READ_ERROR;
            break;
        }

        preSize = sockInfo.bufSize;
        bufSize = this->reciveHttpData(sockInfo);

        checkError(sockInfo, bufSize, endTryTimes, loop, hasError);

        if (hasError) {
            break;
        } else if (loop) {
            loop = 0;
            continue;
        }
    }

    if (!hasError && sockInfo.bodySize) {
        sockInfo.bufSize -= sockInfo.bodySize;
        if (sockInfo.bufSize) {
            char* buf = (char*)calloc(1, sockInfo.bufSize + 1);
            memcpy(buf, sockInfo.buf + sockInfo.bodySize, sockInfo.bufSize);
            free(sockInfo.buf);
            sockInfo.buf = buf;
        } else {
            free(sockInfo.buf);
            sockInfo.buf = NULL;
        }
    }
}

ssize_t HttpUtils::reciveHttpData(SockInfo& sockInfo) {
    char buf[1024 * 10];
    ssize_t bufSize = this->readData(sockInfo, buf, sizeof(buf));

    if (bufSize > 0 && READ_AGAIN != bufSize) {
        sockInfo.buf = (char*)realloc(sockInfo.buf, sockInfo.bufSize + bufSize + 1);
        memcpy(sockInfo.buf + sockInfo.bufSize, buf, bufSize);
        sockInfo.bufSize += bufSize;
        sockInfo.buf[sockInfo.bufSize] = '\0';
    }
    return bufSize;
}

ssize_t HttpUtils::recvData(SockInfo& sockInfo, char* buf, size_t length) {
    ssize_t err;
    ssize_t result;

    err = recv(sockInfo.sock, buf, length, MSG_PEEK);

    result = this->getSockErr(sockInfo, err);

    if (result > 0 && READ_AGAIN != result) {
        gettimeofday(&sockInfo.tv, NULL); // 重置超时时间
    }

    return result;
}

ssize_t HttpUtils::readData(SockInfo& sockInfo, char* buf, size_t length) {
    ssize_t err;
    ssize_t result;

    if (sockInfo.ssl == NULL) {
        err = read(sockInfo.sock, buf, length);
    } else {
        err = SSL_read(sockInfo.ssl, buf, length);
    }

    result = this->getSockErr(sockInfo, err);

    if (result > 0 && READ_AGAIN != result) {
        gettimeofday(&sockInfo.tv, NULL); // 重置超时时间
    }

    return result;
}

ssize_t HttpUtils::writeData(SockInfo& sockInfo, char* buf, size_t length) {
    ssize_t err;
    ssize_t result = READ_AGAIN;

    while (READ_AGAIN == result) {
        if (sockInfo.ssl == NULL) {
            err = write(sockInfo.sock, buf, length);
        } else {
            err = SSL_write(sockInfo.ssl, buf, length);
        }
        result = this->getSockErr(sockInfo, err);
        if (READ_AGAIN == result) {
            usleep(this->cpuTime);
        }
    }

    if (result > 0) {
        gettimeofday(&sockInfo.tv, NULL); // 重置超时时间
    }

    return result;
}

void HttpUtils::checkError(SockInfo& sockInfo, ssize_t bufSize, int& endTryTimes, int& loop, int& hasError) {
    if (READ_ERROR == bufSize || sockInfo.closing || -1 == sockInfo.sock) {
        hasError = 1;
        return;
    } else if (READ_AGAIN == bufSize || READ_END == bufSize) {
        if (!sockContainer.checkSockTimeout(sockInfo)) {
            hasError = 1;
            return;
        }
        if (READ_END == bufSize) {
            if (endTryTimes > this->endTryTimes) {
                hasError = 1;
                return;
            }
            endTryTimes++;
        }
        usleep(this->cpuTime);
        loop = 1;
    }
}

ssize_t HttpUtils::getSockErr(SockInfo& sockInfo, ssize_t err) {
    ssize_t result;

    if (err == 0) {
        return READ_END;
    }

    if (sockInfo.ssl == NULL) {
        if (err > 0) {
            result = err;
        } else if (errno == EINTR || errno == EWOULDBLOCK || errno == EAGAIN) {
            result = READ_AGAIN;
        } else {
            result = READ_ERROR;
        }
    } else {
        int nRes = SSL_get_error(sockInfo.ssl, err);
        if (nRes == SSL_ERROR_NONE) {
            result = err;
        } else if (SSL_ERROR_WANT_READ == nRes || SSL_ERROR_WANT_WRITE == nRes) {
            result = READ_AGAIN;
        } else {
            result = READ_ERROR;
        }
    }

    return result;
}

ssize_t HttpUtils::sendTunnelOk(SockInfo& sockInfo) {
    string s = "HTTP/1.1 200 Connection Established\r\n\r\n";
    return write(sockInfo.sock, s.c_str(), s.length());
}

int HttpUtils::sendFile(SockInfo& sockInfo) {
    string fName = sockInfo.header->path;
    if (fName.length()) {
        int pos = fName.find('?');
        if (pos != fName.npos) {
            fName = fName.substr(0, pos);
        }
        fName = "www" + fName;
        ifstream inFile(fName.c_str(), ios::in | ios::binary);

        if (inFile.good()) {
            string head = "HTTP/1.1 200 OK\n";
            string type = this->getType(fName);
            size_t len = 0;
            char* data = this->readFile(inFile, len);

            head += "Content-Type: " + type + "\n";
            if (strcmp(sockInfo.header->connnection, "close") == 0) {
                head += "Connection: close\n";
            } else {
                head += "Connection: keep-alive\n";
                head += "Keep-Alive: timeout=";
                head += to_string(sockContainer.timeout) + "\n";
            }
            head += "Content-Length: " + to_string(len) + "\n";
            head += "\n";

            this->writeData(sockInfo, const_cast<char*>(head.c_str()), head.length());
            this->writeData(sockInfo, data, len);

            free(data);
        } else {
            this->send404(sockInfo);
            return 0;
        }
        return 1;
    } else {
        this->send404(sockInfo);
        return 0;
    }
}

ssize_t HttpUtils::send404(SockInfo& sockInfo) {
    ssize_t err;
    string str404 = "404 Not Found";
    string s = "HTTP/1.1 404 Not Found\r\nConnection: close\r\nContent-Length: ";

    s += to_string(str404.size());
    s += "\r\n\r\n";
    s += str404;

    err = this->writeData(sockInfo, const_cast<char*>(s.c_str()), s.length());

    return err;
}

string HttpUtils::getType(string fName) {
    if (fName.find(".png") == fName.length() - 4) {
        return "image/apng";
    } else if (fName.find(".jpg") == fName.length() - 4) {
        return "image/jpg";
    } else {
        return "text/html";
    }
}

char* HttpUtils::readFile(ifstream& inFile, size_t& len) {

    inFile.seekg(0, inFile.end);

    len = inFile.tellg();

    inFile.seekg(0, inFile.beg);

    char* arr = (char*)calloc(1, len);

    inFile.read(arr, len);

    return arr;
}

string HttpUtils::createReqData(SockInfo& sockInfo) {
    string firstLine = "";
    string head = sockInfo.head;
    HttpHeader* header = sockInfo.header;
    char* str = NULL;
    int pos = head.find("\r\n");

    firstLine += header->method;
    firstLine += " ";
    firstLine += header->path;
    firstLine += " ";
    firstLine += header->protocol;

    head = firstLine + head.substr(pos);

    return head;
}