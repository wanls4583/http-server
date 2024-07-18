#include <iostream>
#include "WsUtils.h"

#define checkFragment(length, fragment) if((length)<=0){free(fragment);return NULL;}

WsFragment* WsUtils::parseFragment(SockInfo& sockInfo) {
    WsFragment* fragment = (WsFragment*)calloc(1, sizeof(WsFragment));
    size_t bufSize = sockInfo.bufSize;
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

    fragment->fragmentSize = 2;
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

    if (fragment->mask) {
        checkFragment(bufSize - 4, fragment);
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

void WsUtils::freeFragment(WsFragment* fragment) {
    if (!fragment) {
        return;
    }
    if (fragment->next) {
        freeFragment(fragment->next);
    }
    if (fragment->maskKey) {
        free(fragment->maskKey);
    }
    if (fragment->data) {
        free(fragment->data);
    }
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