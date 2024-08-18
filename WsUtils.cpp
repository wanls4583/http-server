#include <iostream>
#include "WsUtils.h"
#include "HttpUtils.h"

#define checkFragment(length, fragment) if((length)<=0){free(fragment);return NULL;}

extern HttpUtils httpUtils;

WsFragment* WsUtils::parseFragment(SockInfo& sockInfo) {
    WsFragment* fragment = (WsFragment*)calloc(1, sizeof(WsFragment));
    ssize_t bufSize = sockInfo.bufSize;
    int index = 0;
    unsigned char* buf = (unsigned char*)sockInfo.buf;

    checkFragment(bufSize, fragment);

    fragment->fin = (buf[index] & 0x80) >> 7;
    fragment->rsv = (buf[index] & 0x70) >> 4;
    fragment->opCode = buf[index] & 0x0f;
    bufSize--;
    index++;

    checkFragment(bufSize, fragment);
    fragment->mask = (buf[index] & 0x80) >> 7;
    fragment->dataLen = buf[index] & 0x7f;
    bufSize--;
    index++;

    if (fragment->mask == 0 && fragment->dataLen == 0) { // 空数据祯
        return fragment;
    }

    fragment->fragmentSize = 2; // fragment至少有两个字节，即使是数据长度为0（例如 close:0x08、ping:0x09 等操作）
    if (fragment->dataLen == 126) {
        checkFragment(bufSize - 2, fragment);
        fragment->dataLen2 = (buf[2] << 8) | buf[3];
        bufSize -= 2;
        index += 2;
        fragment->fragmentSize += fragment->dataLen2 + 2;
    } else if (fragment->dataLen == 127) {
        checkFragment(bufSize - 4, fragment);
        fragment->dataLen2 =
            ((u_int64_t)buf[2] << 56) |
            ((u_int64_t)buf[3] << 48) |
            ((u_int64_t)buf[4] << 40) |
            ((u_int64_t)buf[5] << 32) |
            ((u_int64_t)buf[6] << 24) |
            ((u_int64_t)buf[7] << 16) |
            ((u_int64_t)buf[8] << 8) |
            (u_int64_t)buf[9];
        bufSize -= 8;
        index += 8;
        fragment->fragmentSize += fragment->dataLen2 + 8;
    } else {
        fragment->fragmentSize += fragment->dataLen;
    }

    if (fragment->mask && bufSize >= 4) {
        fragment->maskKey = (unsigned char*)calloc(4, 1);
        memcpy(fragment->maskKey, buf + index, 4);
        bufSize -= 4;
        index += 4;
        fragment->fragmentSize += 4;
    }

    u_int16_t len = fragment->dataLen2 ? fragment->dataLen2 : fragment->dataLen;

    if (bufSize != len) {
        free(fragment->maskKey);
        free(fragment);
        return NULL;
    }

    fragment->data = (unsigned char*)calloc(len + 1, 1);
    memcpy(fragment->data, buf + index, len);

    if (fragment->mask) {
        for (u_int16_t i = 0; i < len; i++) {
            int j = i % 4;
            fragment->data[i] = fragment->data[i] ^ fragment->maskKey[j];
        }
    }

    return fragment;
}

unsigned char* WsUtils::createMsg(WsFragment* fragment) {
    unsigned char* msg = NULL;
    int index = 0;
    u_int64_t dataLen = fragment->dataLen2 ? fragment->dataLen2 : fragment->dataLen;
    u_int64_t fragmentSize = dataLen + 2;

    if (dataLen > 65535) {
        fragmentSize += 8;
    } else if (dataLen > 125) {
        fragmentSize += 2;
    }

    if (fragment->mask) {
        fragmentSize += 4;
    }

    fragment->fragmentSize = fragmentSize;
    msg = (unsigned char*)calloc(fragmentSize + 1, 1);

    if (fragment->fin) {
        msg[index] |= 0x80;
    }

    if (fragment->rsv) {
        msg[index] |= (fragment->rsv << 4);
    }

    msg[index] |= fragment->opCode;
    index++;

    if (fragment->mask) {
        msg[index] |= 0x80;
    }

    if (dataLen > 65535) {
        msg[index++] |= 0x7f;
        msg[index] = (dataLen >> 56) & 0xff;
        msg[index + 1] = (dataLen >> 48) & 0xff;
        msg[index + 2] = (dataLen >> 40) & 0xff;
        msg[index + 3] = (dataLen >> 32) & 0xff;
        msg[index + 4] = (dataLen >> 24) & 0xff;
        msg[index + 5] = (dataLen >> 16) & 0xff;
        msg[index + 6] = (dataLen >> 8) & 0xff;
        msg[index + 7] = (dataLen) & 0xff;
        index += 8;
    } else if (dataLen > 125) {
        msg[index++] |= 0x7e;
        unsigned short len = htons(dataLen);
        memcpy(msg + index, &len, 2);
        index += 2;
    } else {
        msg[index++] |= dataLen;
    }

    if (fragment->mask) {
        memcpy(msg + index, fragment->maskKey, 4);
        index += 4;
    }

    if (dataLen > 0) {
        memcpy(msg + index, fragment->data, dataLen);
    }

    if (fragment->mask) {
        for (u_int16_t i = 0; i < dataLen; i++) {
            int j = i % 4;
            msg[index + i] = msg[index + i] ^ fragment->maskKey[j];
        }
    }

    return msg;
}

void WsUtils::freeFragment(WsFragment* fragment) {
    if (!fragment) {
        return;
    }
    if (fragment->next) {
        freeFragment(fragment->next);
    }
    free(fragment->maskKey);
    free(fragment->data);
    free(fragment);
}

int WsUtils::fragmentComplete(WsFragment* fragment) {
    if (fragment) {
        while (fragment->next) {
            fragment = fragment->next;
        }
        if (fragment->fin == 1) {
            return 1;
        }
    }

    return 0;
}

u_int64_t WsUtils::getMsgLength(WsFragment* fragment) {
    u_int64_t size = 0;

    if (fragmentComplete(fragment)) {
        while (fragment) {
            size += fragment->dataLen2 ? fragment->dataLen2 : fragment->dataLen;
            fragment = fragment->next;
        }
    }

    return size;
}

unsigned char* WsUtils::getMsg(WsFragment* fragment) {
    unsigned char* msg = NULL;
    unsigned char* tmp = NULL;
    u_int16_t len = getMsgLength(fragment);

    if (len) {
        msg = (unsigned char*)calloc(len + 1, 1);
        tmp = msg;
        while (fragment) {
            len = fragment->dataLen2 ? fragment->dataLen2 : fragment->dataLen;
            memcpy(tmp, fragment->data, len);
            tmp += len;
            fragment = fragment->next;
        }
    }

    return msg;
}

ssize_t WsUtils::sendMsg(SockInfo& sockinfo, unsigned char* msg, u_int64_t size, int fin, int opCode) {
    ssize_t bufSize = 0;
    WsFragment* fragment = (WsFragment*)calloc(1, sizeof(WsFragment));
    unsigned char* data = NULL;
    if (size > 0) {
        data = (unsigned char*)calloc(size + 1, 1);
        memcpy(data, msg, size);
    }

    fragment->fin = fin;
    fragment->opCode = opCode;
    fragment->dataLen2 = size;
    fragment->data = data;

    msg = createMsg(fragment);
    bufSize = httpUtils.writeData(sockinfo, (char*)msg, fragment->fragmentSize);
    freeFragment(fragment);

    return bufSize;
}

ssize_t WsUtils::close(SockInfo& sockinfo) {
    return sendMsg(sockinfo, NULL, 0, 1, 0x08);
}