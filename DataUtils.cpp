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