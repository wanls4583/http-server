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

    if (!header->port) { // 如果 host 首部没有携带端口，证明其是用默认端口
        header->port = sockInfo.ssl ? 443 : 80;
    }

    if (strcmp(header->method, "CONNECT") == 0) { //例：CONNECT lp.open.weixin.qq.com:443 HTTP/1.1
        sockInfo.isProxy = 1;
    }

    if (header->path) {
        string path = header->path;
        pos = path.find("://");
        header->originPath = copyBuf(header->path);
        if (header->path[0] == '/') {
            // 服务器模式或者 https 代理请求。https 请求代理会先发送 CONNECT 请求，所以请求路径不会带协议头。例：
            // GET /common/csdn-toolbar/images/wx-pay.svg HTTP/1.1
            string url = sockInfo.ssl ? "https://" : "http://";
            url += header->hostname;
            url += ":";
            url += to_string(header->port);
            url += header->path;
            header->url = new char[url.size() + 1];
            strcpy(header->url, url.c_str());
        } else if (pos != path.npos && pos <= 4) {
            // http 代理请求。例：
            // GET http://121.196.45.222:2401/name/sysdate HTTP/1.1
            // GET http://www.leiyang.gov.cn/front/ui/jquery/jquery.js HTTP/1.1
            sockInfo.isProxy = 1;
            header->url = copyBuf(header->path);
            path = path.substr(pos + 3);
            pos = path.find('/');
            if (pos != path.npos) {
                path = path.substr(pos);
            }
            free(header->path);
            header->path = copyBuf(path.c_str());
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

int HttpUtils::checkMethod(const char* method) {
    if (strcmp(method, "GET")) {
        return 1;
    }
    if (strcmp(method, "POST")) {
        return 1;
    }
    if (strcmp(method, "CONNECT")) {
        return 1;
    }
    if (strcmp(method, "HEAD")) {
        return 1;
    }
    if (strcmp(method, "OPTIONS")) {
        return 1;
    }
    if (strcmp(method, "PUT")) {
        return 1;
    }
    if (strcmp(method, "PATCH")) {
        return 1;
    }
    if (strcmp(method, "DELETE")) {
        return 1;
    }
    if (strcmp(method, "TRACE")) {
        return 1;
    }

    return 0;
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
        } else if (prop.compare("Transfer-Encoding") == 0) {
            header->transferEncoding = new char[val.size() + 1];
            strcpy(header->transferEncoding, val.c_str());
        } else if (prop.compare("Trailer") == 0) {
            header->trailer = new char[val.size() + 1];
            strcpy(header->trailer, val.c_str());
        } else if (prop.compare("Upgrade") == 0) {
            header->upgrade = new char[val.size() + 1];
            strcpy(header->upgrade, val.c_str());
        } else if (prop.compare("Sec-WebSocket-Key") == 0) {
            header->secWebSocketKey = new char[val.size() + 1];
            strcpy(header->secWebSocketKey, val.c_str());
        }
    }
}

char* HttpUtils::getSecWebSocketAccept(SockInfo& sockInfo) {
    char* result = NULL;
    if (sockInfo.header->secWebSocketKey) {
        digest_ctx ctx;
        string input = "";
        string suffix = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";
        // input += "w4v7O6xFTi36lq3RNcgctw==";
        input += sockInfo.header->secWebSocketKey;
        input += suffix;

        new_sha1_digest(&ctx);
        digest_hash(&ctx, (u8*)input.c_str(), input.size());

        int base64Size = ctx.result_size * 6 / 4 + 3;
        result = (char*)malloc(base64Size);
        memset(result, 0, base64Size);
        base64_encode((unsigned char*)ctx.hash, ctx.result_size, (unsigned char*)result);
        // Oy4NRAQ13jhfONC7bP8dTKb4PTU=
        // cout << "Sec-WebSocket-Accept: " << result << endl;

        free_digest(&ctx);
    }
    return result;
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
            if (string(sockInfo.head).find("HTTP") == 0) { // 响应头，HTTP/1.1 200 OK
                header = this->getHttpResHeader(sockInfo);
            } else { // 请求头，GET /index.html HTTP/1.1
                header = this->getHttpReqHeader(sockInfo);
            }
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
    string boundary = "";
    int endTryTimes = 0, loop = 0;

    if (header->boundary) {
        boundary += "--";
        boundary += header->boundary;
        boundary += "--\r\n";
        // 当 Content-Type 为 multipart/form-data 的时候，表单数据将由 boundary 分割
        // 示例
        // Content-Length: 43022511\r\n
        // Content-Type:  multipart/form-data; boundary=----WebKitFormBoundary9Z2MtPaeCJ1817FM\r\n
        // \r\n
        // ------WebKitFormBoundary9Z2MtPaeCJ1817FM\r\n
        // Content-Disposition: form-data; name="myname"\r\n
        // \r\n
        // 名称1
        // ------WebKitFormBoundary9Z2MtPaeCJ1817FM\r\n
        // Content-Disposition: form-data; name="name1"\r\n
        // \r\n
        // 名称2
        // ------WebKitFormBoundary9Z2MtPaeCJ1817FM\r\n
        // Content-Disposition: form-data; name="nameyfile"; filename="高等数学 第七版 上册 习题全解指南 同济.pdf"\r\n
        // Content-Type: application/pdf\r\n
        // \r\n
        // 这里是编码后的文件数据...
        // ------WebKitFormBoundary9Z2MtPaeCJ1817FM--\r\n
    } else if (header->transferEncoding && !strcmp(header->transferEncoding, "chunked")) {
        // 当传输编码方式为 chunked 时，数据以一系列分块的形式进行发送。 Content-Length 首部在这种情况下不被发送。
        // 在每一个分块的开头需要添加当前分块的长度，以十六进制的形式表示，后面紧跟着 '\r\n' ，之后是分块本身，后面也是'\r\n' 。
        // 终止块是一个常规的分块，不同之处在于其长度为 0。终止块后面是一个挂载（trailer），由一系列（或者为空）的实体消息首部构成。
        // 示例：
        // HTTP/1.1 200 OK\r\n
        // Content-Type: text/plain\r\n
        // Transfer-Encoding: chunked\r\n
        // Trailer: Expires\r\n
        // \r\n
        // 7\r\n
        // Mozilla\r\n
        // 9\r\n
        // Developer\r\n
        // 7\r\n
        // Network\r\n
        // 0\r\n
        // Expires: Wed, 21 Oct 2015 07:28:00 GMT\r\n
        // \r\n
        // 以上示例需要注意：Expires 那一行可能没有也可能后面还有很多其他首部行，具体是由请求头里面的 Trailer 首部决定的
        if (!header->trailer) { // 没有 trailer 字段
            boundary += "0\r\n\r\n";
        } else { // 有 trailer 字段，为了方便起见，这里不对挂载字段做解析，只匹配请求体最后的空行
            boundary += "\r\n\r\n";
        }
    }

    while (1) {
        if (header->contentLenth) {
            if (header->contentLenth <= sockInfo.bufSize) {
                sockInfo.bodySize = header->contentLenth;
                sockInfo.body = (char*)calloc(1, sockInfo.bodySize + 1);
                memcpy(sockInfo.body, sockInfo.buf, sockInfo.bodySize);
                break;
            }
        } else if (boundary.size()) {
            if (sockInfo.bufSize) {
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

// 该方法查看流中的数据，但不会将数据从流中删除
ssize_t HttpUtils::recvData(SockInfo& sockInfo, char* buf, size_t length) {
    ssize_t err;
    ssize_t result;

    err = recv(sockInfo.sock, buf, length, MSG_PEEK); // MSG_PEEK查看传入数据，数据将复制到缓冲区中，但不会从输入队列中删除

    result = this->getSockErr(sockInfo, err);

    if (result > 0 && READ_AGAIN != result) {
        gettimeofday(&sockInfo.tv, NULL); // 重置超时时间
    }

    return result;
}

// 读取流中的数据，并将读取的将数据从流中删除
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

// 将数据写入到流中
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

ssize_t HttpUtils::sendUpgradeOk(SockInfo& sockInfo) {
    char* secWebSocketAccept = getSecWebSocketAccept(sockInfo);
    string s = "HTTP/1.1 101 Switching Protocols\r\rUpgrade: websocket\r\nConnection: Upgrade\r\n";

    if (secWebSocketAccept) {
        s += "Sec-WebSocket-Accept: ";
        s += secWebSocketAccept;
        s += "\r\n";
    }

    s += "\r\n";

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
        struct stat s;

        if (inFile.good() && stat(fName.c_str(), &s) == 0 && s.st_mode & S_IFREG) {
            string head = "HTTP/1.1 200 OK\r\n";
            string type = this->getType(fName);
            size_t len = 0;
            char* data = readFile(inFile, len);

            head += "Content-Type: " + type + "\r\n";
            if (sockInfo.header->connnection && strcmp(sockInfo.header->connnection, "close") == 0) {
                head += "Connection: close\r\n";
            } else {
                head += "Connection: keep-alive\r\n";
                head += "Keep-Alive: timeout=";
                head += to_string(sockContainer.timeout) + "\r\n";
            }
            head += "Content-Length: " + to_string(len) + "\r\n";
            head += "\r\n";

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

void HttpUtils::createReqData(SockInfo& sockInfo, char*& req, size_t& reqSize) {
    string firstLine = "";
    string head = sockInfo.head;
    HttpHeader* header = sockInfo.header;
    int pos = head.find("\r\n");

    firstLine += header->method;
    firstLine += " ";
    firstLine += header->path;
    firstLine += " ";
    firstLine += header->protocol;

    reqSize = firstLine.size() + sockInfo.reqSize - pos + sockInfo.bodySize;
    req = (char*)calloc(1, reqSize + 1);
    memcpy(req, firstLine.c_str(), firstLine.size());
    memcpy(req + firstLine.size(), sockInfo.head + pos, sockInfo.reqSize - pos);
    memcpy(req + firstLine.size() + sockInfo.reqSize - pos, sockInfo.body, sockInfo.bodySize);
}