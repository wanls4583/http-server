#include "DataUtils.h"
#include "LevelUtils.h"
#include "SockContainer.h"

#define checkData(length) if((length)<0){return;}

extern LevelUtils levelUtils;
extern SockContainer sockContainer;
extern WsUtils wsUtils;

using namespace std;

DataUtils::DataUtils() {
}

DataUtils::~DataUtils() {
}

void DataUtils::saveRule(char* data, u_int64_t dataLen) {
  string key = "rule";
  levelUtils.put(key, data, dataLen);
}

void DataUtils::savePem(char* data, u_int64_t dataLen, u_int64_t reqId) {
  string key = "";
  key += "pem:";
  key += reqId;
  levelUtils.put(key, data, dataLen);
}

void DataUtils::saveBody(char* data, u_int64_t dataLen, int type, u_int64_t reqId) {
  ssize_t size = 0;
  string key = "";

  if (type == 1) {
    key = "reqBodyChunks:";
    key += reqId;
  } else {
    key = "resBodyChunks:";
    key += reqId;
  }

  char* bytes = levelUtils.get(key, size);
  int chunks = atoi(bytes);
  bytes = (char*)to_string(chunks).c_str();
  levelUtils.del(key);
  levelUtils.put(key, bytes, strlen(bytes));

  if (type == 1) {
    key = "reqBody:";
    key += reqId;
  } else {
    key = "resBody:";
    key += reqId;
  }

  levelUtils.put(key, data, dataLen);
}

void DataUtils::sendData(char* data, u_int64_t dataLen, int type) {
  u_int64_t index = 0, reqId = 0;

  checkData(dataLen - 2);

  int reqSize = data[index++];
  checkData(dataLen - index - reqSize);
  memcpy(&reqId, data + index, reqSize);
  reqId = ntohll(reqId);
  index += reqSize;

  string key = "";
  if (type == 1) {
    key = "reqBodyChunks:";
    key += reqId;
  } else if (type == 2) {
    key = "resBodyChunks:";
    key += reqId;
  } else if (type == 3) {
    key = "pem:";
    key += reqId;
  } else if (type == 4) {
    key = "rule";
  }

  ssize_t size = 0;
  char* bytes = levelUtils.get(key, size);

  char* result = bytes;
  ssize_t resultSize = size;

  if (type == 1 || type == 2) {
    result = NULL;
    resultSize = 0;

    int chunks = atoi(bytes);
    for (int i = 0; i < chunks; i++) {
      string key = type == 1 ? "reqBody:" : "resBody:";
      key += reqId;
      key += ":";
      key += i;
      bytes = levelUtils.get(key, size);
      if (bytes) {
        result = (char*)realloc(result, resultSize + size + 1);
        memcpy(result + resultSize, bytes, size);
        resultSize += size;
        result[resultSize] = 0;
      }
    }
  }

  ssize_t bufSize = 1 + reqSize + resultSize;
  unsigned char* buf = (unsigned char*)calloc(bufSize + 1, 1);
  memcpy(buf, data, 1 + reqSize);
  memcpy(buf + 1 + reqSize, result, resultSize);
  wsUtils.sendMsg(*sockContainer.dataScokInfo, buf, bufSize, 1, 2);
}