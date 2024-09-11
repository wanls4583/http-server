#include <iostream>
#include "utils.h"
#include "RuleUtils.h"
#include "SockContainer.h"

#define checkRuleData(length) if((length)<0){return;}

extern SockContainer sockContainer;
extern const int MAX_SOCK;

RuleUtils::RuleUtils() {
}

RuleUtils::~RuleUtils() {
}

void RuleUtils::clearRule() {
  RuleNode* node = this->ruleNode;
  RuleNode* tmp;

  while (node) {
    tmp = node->next;
    free(node);
    node = tmp;
  }

  this->ruleNode = NULL;
  this->reciveId = 0;
}

void RuleUtils::parseRule(char* data, u_int64_t dataLen) {
  RuleNode* node = NULL;
  RuleNode* preNode = NULL;
  u_int64_t index = 0;
  unsigned short size = 0;

  this->clearRule();
  this->reciveId = data[index++];
  checkRuleData(dataLen - index);

  while (dataLen - index > 4) {
    node = (RuleNode*)calloc(1, sizeof(RuleNode));
    node->reqFlag = data[index++];
    node->resFlag = data[index++];
    memcpy(&size, data + index, 2);
    size = ntohs(size);
    index += 2;
    checkRuleData(dataLen - index - size);
    node->rule = (char*)calloc(size + 1, 1);
    memcpy(node->rule, data + index, size);
    index += size;
    if (preNode) {
      preNode->next = node;
    }
    if (!this->ruleNode) {
      this->ruleNode = node;
    }
    preNode = node;
  }
}

void RuleUtils::reciveData(char* data, u_int64_t dataLen) {
  u_int64_t index = 0, reqId = 0;

  checkRuleData(dataLen - 2);

  int msgType = data[index++];
  int reqSize = data[index++];
  checkRuleData(dataLen - index - reqSize);
  memcpy(&reqId, data + index, reqSize);
  reqId = ntohll(reqId);
  index += reqSize;

  SockInfo* sockInfo = sockContainer.getSockInfoByReqId(reqId);
  if (sockInfo) {
    SockInfo* nowSockInfo = sockInfo;
    if (sockInfo->ruleState != 1) {
      nowSockInfo = sockInfo->remoteSockInfo;
    }

    ssize_t bufSize = nowSockInfo->bufSize + dataLen - index;
    char* buf = (char*)calloc(bufSize, 1);
    memcpy(buf, data + index, dataLen - index);
    memcpy(buf + dataLen - index, nowSockInfo->buf, nowSockInfo->bufSize);
    nowSockInfo->ruleBuf = buf;
    nowSockInfo->ruleBufSize = bufSize;

    cout << "broadcast:" << sockInfo->reqId << endl;
    pthread_cond_broadcast(&sockInfo->cond);
  }
}

void RuleUtils::broadcastAll() {
  for (int i = 0; i < MAX_SOCK; i++) {
    SockInfo* sockInfo = &sockContainer.sockInfos[i];
    SockInfo* nowSockInfo = sockInfo;

    if (nowSockInfo->ruleState == 1 || nowSockInfo->remoteSockInfo && nowSockInfo->remoteSockInfo->ruleState == 1) {
      if (nowSockInfo->ruleState != 1) {
        nowSockInfo = nowSockInfo->remoteSockInfo;
      }

      ssize_t bufSize = nowSockInfo->bufSize + nowSockInfo->headSize + nowSockInfo->bodySize;
      char* buf = (char*)calloc(bufSize, 1);
      memcpy(buf, nowSockInfo->head, nowSockInfo->headSize);
      memcpy(buf + nowSockInfo->headSize, nowSockInfo->body, nowSockInfo->bodySize);
      memcpy(buf + nowSockInfo->headSize + nowSockInfo->bodySize, nowSockInfo->buf, sockInfo->bufSize);
      nowSockInfo->ruleBuf = buf;
      nowSockInfo->ruleBufSize = bufSize;

      cout << "broadcastAll:" << sockInfo->reqId << endl;
      pthread_cond_broadcast(&sockInfo->cond);
    }
  }
}

RuleNode* RuleUtils::findRule(SockInfo* sockInfo) {
  RuleNode* node = this->ruleNode;
  HttpHeader* header = sockInfo->header;

  if (sockInfo->localSockInfo) {
    header = sockInfo->localSockInfo->header;
  }

  if (!header || !header->url) {
    return NULL;
  }

  while (node) {
    if (wildcardMatch(header->url, node->rule)) {
      return node;
    }
    node = node->next;
  }

  return NULL;
}

