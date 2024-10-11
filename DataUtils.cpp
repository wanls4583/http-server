#include "brotli/decode.h"
#include "utils.h"
#include "DataUtils.h"
#include "LevelUtils.h"
#include "SockContainer.h"
#include "RuleUtils.h"

#define checkData(length) if((length)<0){return;}

extern LevelUtils persitLevelUtils;
extern LevelUtils tempLevelUtils;
extern SockContainer sockContainer;
extern WsUtils wsUtils;

using namespace std;

DataUtils::DataUtils() {
}

DataUtils::~DataUtils() {
}

void DataUtils::saveData(char* data, u_int64_t dataLen, int type, u_int64_t reqId) {
  LevelUtils* levelUtils = &tempLevelUtils;
  string key = "";
  if (DATA_TYPE_RULE == type) {
    key = "rule";
    levelUtils = &persitLevelUtils;
    levelUtils->del(key);
  } else if (DATA_TYPE_CERT == type) {
    key = "cert:";
    key += to_string(reqId);
  } else if (DATA_TYPE_REQ_HEAD == type) {
    key = "reqHead:";
    key += to_string(reqId);
  } else if (DATA_TYPE_RES_HEAD == type) {
    key = "resHead:";
    key += to_string(reqId);
  } else if (DATA_TYPE_REQ_BODY == type || DATA_TYPE_RES_BODY == type) {
    if (DATA_TYPE_REQ_BODY == type) {
      key = "reqBodyChunkSize:";
    } else if (DATA_TYPE_RES_BODY == type) {
      key = "resBodyChunkSize:";
    }
    key += to_string(reqId);

    ssize_t size = 0;
    char* bytes = levelUtils->get(key, size);
    int chunks = bytes ? atoi(bytes) : 0;
    bytes = (char*)to_string(chunks + 1).c_str();
    levelUtils->del(key);
    levelUtils->put(key, bytes, strlen(bytes));

    if (type == DATA_TYPE_REQ_BODY) {
      key = "reqBody:";
    } else {
      key = "resBody:";
    }
    key += to_string(reqId);
    key += ":";
    key += to_string(chunks);

    SockInfo* sockInfo = sockContainer.getSockInfoByReqId(reqId);
    size_t decoded_size = 0;
    uint8_t decoded_buf[size * 20];
    if (sockInfo->remoteSockInfo && sockInfo->remoteSockInfo->header && sockInfo->remoteSockInfo->header->contentEncoding && !strcmp(sockInfo->remoteSockInfo->header->contentEncoding, "br")) {
      BrotliDecoderResult st = BrotliDecoderDecompress(size, (uint8_t*)data, &decoded_size, decoded_buf);
    }
  }

  levelUtils->put(key, data, dataLen);
}

char* DataUtils::getData(int dataType, u_int64_t reqId, ssize_t& size) {
  LevelUtils* levelUtils = &tempLevelUtils;
  string key = "";
  if (DATA_TYPE_RULE == dataType) {
    key = "rule";
    levelUtils = &persitLevelUtils;
  } else if (DATA_TYPE_CERT == dataType) {
    key = "cert:";
    key += to_string(reqId);
  } else if (DATA_TYPE_REQ_HEAD == dataType) {
    key = "reqHead:";
    key += to_string(reqId);
  } else if (DATA_TYPE_RES_HEAD == dataType) {
    key = "resHead:";
    key += to_string(reqId);
  } else if (DATA_TYPE_REQ_BODY == dataType) {
    key = "reqBodyChunkSize:";
    key += to_string(reqId);
  } else if (DATA_TYPE_RES_BODY == dataType) {
    key = "resBodyChunkSize:";
    key += to_string(reqId);
  }

  size = 0;
  char* result = levelUtils->get(key, size);

  if (DATA_TYPE_REQ_BODY == dataType || DATA_TYPE_RES_BODY == dataType) {
    ssize_t chunkSize = 0;
    char* bytes = NULL;
    int chunks = result ? atoi(result) : 0;

    size = 0;
    result = NULL;
    for (int i = 0; i < chunks; i++) {
      string key = dataType == 1 ? "reqBody:" : "resBody:";
      key += to_string(reqId);
      key += ":";
      key += to_string(i);
      bytes = levelUtils->get(key, chunkSize);
      if (bytes) {
        result = (char*)realloc(result, size + chunkSize + 1);
        memcpy(result + size, bytes, chunkSize);
        size += chunkSize;
        result[size] = 0;
      }
    }
  }

  return result;
}

void DataUtils::sendData(char* data, u_int64_t dataLen) {
  u_int64_t index = 0, reqSize = 0, reqId = 0, dataType = 0;

  checkData(dataLen - 2);
  dataType = data[index++];
  reqSize = data[index++];

  checkData(dataLen - index - reqSize);
  memcpy(&reqId, data + index, reqSize);
  reqId = ntohll(reqId);
  index += reqSize;

  ssize_t resultSize = 0;
  char* result = this->getData(dataType, reqId, resultSize);

  ssize_t bufSize = 2 + reqSize + resultSize;
  unsigned char* buf = (unsigned char*)calloc(bufSize + 1, 1);

  index = 0;
  memcpy(buf, data, 1 + 1 + reqSize);
  index += 1 + 1 + reqSize;

  memcpy(buf + index, result, resultSize);
  wsUtils.sendMsg(*sockContainer.dataScokInfo, buf, bufSize, 1, 2);
}