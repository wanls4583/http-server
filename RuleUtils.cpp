#include <iostream>
#include "utils.h"
#include "RuleUtils.h"
#include "SockContainer.h"

#define checkRuleData(length) if((length)<=0){return;}

extern SockContainer sockContainer;

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
    memcmp(&size, data + index, 2);
    size = ntohs(size);
    index += 2;
    checkRuleData(dataLen - index - size);
    node->rule = (char*)calloc(size + 1, 1);
    memcpy(node->rule, data + index, size);
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
  index += reqSize;

  SockInfo* sockInfo = sockContainer.getSockInfoByReqId(reqId);
  if (sockInfo) {
    ssize_t bufSize = sockInfo->bufSize + dataLen - index;
    char* buf = (char*)calloc(bufSize, 1);
    memcpy(buf, data + index, dataLen - index);
    memcpy(buf + dataLen - index, sockInfo->buf, sockInfo->bufSize);
    sockInfo->ruleBuf = buf;

    pthread_cond_broadcast(&sockInfo->cond);
  }
}

RuleNode* RuleUtils::findRule(SockInfo* sockInfo) {
  RuleNode* node = this->ruleNode;

  if (!sockInfo->header || !sockInfo->header->url) {
    return NULL;
  }

  while (node) {
    if (wildcardMatch(sockInfo->header->url, node->rule)) {
      return node;
    }
  }

  return NULL;
}

