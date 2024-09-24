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

void DataUtils::saveBody(char* data, u_int64_t dataLen, SockInfo& sockInfo) {
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
  }

  ssize_t size = 0;
  char* bytes = levelUtils.get((char*)(key).c_str(), size);

  char* result = bytes;
  ssize_t resultSize = size;

  if (type == 1 || type == 2) {
    result = NULL;
    resultSize = 0;

    int chunks = atoi(bytes);
    for (int i = 0; i < chunks; i++) {
      string key = "reqBody:";
      key += i;
      bytes = levelUtils.get((char*)(key).c_str(), size);
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