#include <iostream>
#include <regex>
#include "utils.h"
#include "RuleUtils.h"
#include "SockContainer.h"
#include "nlohmann/json.hpp"

using json = nlohmann::json;

#define checkRuleData(length) if((length)<0){return;}

extern SockContainer sockContainer;
extern const int MAX_SOCK;

RuleUtils::RuleUtils() {
}

RuleUtils::~RuleUtils() {
}

void RuleUtils::clearRule() {
  RuleNode* node = this->ruleList;
  RuleNode* next = NULL;

  while (node) {
    next = node->next;
    free(node);
    node = next;
  }

  this->ruleList = NULL;
}

void RuleUtils::parseRule(char* data) {
  this->clearRule();
  if (!data) {
    return;
  }

  RuleNode* head = NULL;
  RuleNode* node = NULL;
  json j = json::parse(data);
  if (!j.is_array()) {
    return;
  }

  for (auto& el : j.items()) {
    json v = el.value();
    if (v.contains("enable") && !v.at("enable")) {
      continue;
    }
    if (v.contains("url") && v.contains("type") && v.contains("wayType") && v.contains("way") && v.contains("key") && v.contains("value")) {
      string url = v.at("url");
      int type = v.at("type");
      int wayType = v.at("wayType");
      int way = v.at("way");
      string key = v.at("key");
      string value = v.at("value");
      bool enableReg = false;
      if (v.contains("enableReg")) {
        enableReg = v.at("enableReg");
      }
      if (type < RULE_REQ || type > RULE_RES) {
        continue;
      }
      if (wayType < RULE_WAY_HEAD || wayType > RULE_WAY_BODY) {
        continue;
      }
      if (way < MODIFY_PARAM_ADD || way > MODIFY_BODY_MOD) {
        continue;
      }
      node = (RuleNode*)malloc(sizeof(RuleNode));
      node->url = url;
      node->type = (ruleType)type;
      node->wayType = (ruleWayType)wayType;
      node->way = (ruleWay)way;
      node->key = key;
      node->value = value;
      node->enableReg = enableReg;
      node->next = NULL;
      if (head) {
        head->next = node;
        head = node;
      } else {
        this->ruleList = node;
        head = node;
      }
    }
  }
}

void RuleUtils::broadcast(u_int64_t reqId, char* data, u_int64_t dataLen) {
  SockInfo* sockInfo = sockContainer.getSockInfoByReqId(reqId);
  if (sockInfo) {
    SockInfo* nowSockInfo = sockInfo;
    if (sockInfo->ruleState != 1) {
      nowSockInfo = sockInfo->remoteSockInfo;
    }

    free(nowSockInfo->ruleBuf);
    nowSockInfo->ruleBuf = copyBuf(data, dataLen);
    nowSockInfo->ruleBufSize = dataLen;

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

      cout << "broadcastAll:" << sockInfo->reqId << endl;
      pthread_cond_broadcast(&sockInfo->cond);
    }
  }
}

char* RuleUtils::addParam(char* header, char* key, char* value) {
  string head = header;
  ssize_t pos = head.find("\r\n");
  string after = head.substr(pos);
  if (pos == head.npos) {
    return NULL;
  }

  string line = head.substr(0, pos);
  pos = line.find("?");
  if (pos != head.npos) {
    line += "?";
  } else {
    line += "&";
  }
  line += key;
  if (strlen(value)) {
    line += "=";
    line += value;
  }
  head = line + after;

  return copyBuf(head.c_str());
}

char* RuleUtils::modParam(char* header, char* key, char* value, bool isRegex) {
  string head = header;
  ssize_t pos = head.find("\r\n");
  string after = head.substr(pos);
  if (pos == head.npos) {
    return NULL;
  }

  string line = head.substr(0, pos);
  pos = line.find("?");
  if (pos == head.npos) {
    return NULL;
  }

  regex reg(key);
  string path = line.substr(0, pos + 1);
  string param = line.substr(pos + 1);
  char** list = NULL;
  int size = split(param, list, '&');
  param = "";

  for (int i = 0; i < size; i++) {
    string str = list[i];
    if (!str.size()) {
      if (i < size - 1) {
        param += "&";
      }
      continue;
    }

    char** l;
    int n = split(str, l, '=');
    bool suc = false;
    if (isRegex && regex_match(l[0], reg) || !isRegex && string(key).compare(l[0]) == 0) {
      param += l[0];
      param += "=";
      param += value;
      suc = true;
    }
    if (!suc) {
      param += l[0];
      if (str.find("=") != str.npos) {
        param += "=";
      }
    }
    if (i < size - 1) {
      param += "&";
    }
  }
  head = path + param;

  return copyBuf(head.c_str());
}

char* RuleUtils::delParam(char* header, char* key, bool isRegex) {
  string head = header;
  ssize_t pos = head.find("\r\n");
  string after = head.substr(pos);
  if (pos == head.npos) {
    return NULL;
  }

  string line = head.substr(0, pos);
  pos = line.find("?");
  if (pos == head.npos) {
    return NULL;
  }

  regex reg(key);
  string path = line.substr(0, pos + 1);
  string param = line.substr(pos + 1);
  char** list = NULL;
  int size = split(param, list, '&');
  param = "";

  for (int i = 0; i < size; i++) {
    string str = list[i];
    if (!str.size()) {
      if (i < size - 1) {
        param += "&";
      }
      continue;
    }

    char** l;
    int n = split(str, l, '=');
    bool suc = false;
    if (isRegex && regex_match(l[0], reg) || !isRegex && string(key).compare(l[0]) == 0) {
      suc = true;
    }
    if (!suc) {
      param += l[0];
      if (str.find("=") != str.npos) {
        param += "=";
      }
    }
    if (i < size - 1) {
      param += "&";
    }
  }
  head = path + param;

  return copyBuf(head.c_str());
}

char* RuleUtils::addHeader(char* header, char* hkey, char* hval) {
  ssize_t k_len = strlen(hkey), v_len = strlen(hval), buf_len = strlen(header);
  char* result = (char*)calloc(buf_len + k_len + 2 + v_len + 3, 1);
  char* tmp = result;

  memcpy(tmp, header, buf_len - 2);
  tmp += buf_len - 2; // 尾部有空行\r\n
  memcpy(tmp, hkey, k_len);
  tmp += k_len;
  tmp[0] = ':';
  tmp[1] = ' ';
  tmp += 2;
  memcpy(tmp, hval, v_len);
  tmp += v_len;
  tmp[0] = '\r';
  tmp[1] = '\n';
  tmp[2] = '\r';
  tmp[3] = '\n';

  return result;
}

char* RuleUtils::modHeader(char* header, char* hkey, char* hval, bool isRegex) {
  string head = string(header);
  ssize_t pos = head.npos, index = 0;
  string line = "", key = "", val = "";
  char* result = NULL;
  char* tmp = NULL;
  int colonSize = 0;
  regex reg(hkey);

  while ((pos = head.find("\r\n")) != head.npos) {
    line = head.substr(0, pos);
    head = head.substr(pos + 2);
    ssize_t colon = line.find(":");
    if (colon == head.npos) {
      break;
    }
    colonSize = line[colon + 1] == ' ' ? 2 : 1;
    key = line.substr(0, colon);
    val = line.substr(colon + colonSize);
    if (isRegex && regex_match(key, reg) || !isRegex && string(hkey).compare(key) == 0) {
      ssize_t k_len = key.size(), v_len = strlen(hval);
      result = (char*)calloc(index + k_len + 2 + v_len + 2 + head.size() + 1, 1);
      tmp = result;
      memcpy(tmp, header, index);
      tmp += index;
      memcpy(tmp, key.c_str(), k_len);
      tmp += k_len;
      tmp[0] = ':';
      tmp[1] = ' ';
      tmp += 2;
      memcpy(tmp, hval, v_len);
      tmp += v_len;
      tmp[0] = '\r';
      tmp[1] = '\n';
      tmp += 2;
      memcpy(tmp, head.c_str(), head.size());
      break;
    }
    index += pos + 2;
  }

  return result;
}

char* RuleUtils::delHeader(char* header, char* hkey, bool isRegex) {
  string head = string(header);
  ssize_t pos = head.npos, index = 0;
  string line = "", key = "", val = "";
  char* result = NULL;
  int colonSize = 0;
  regex reg(hkey);

  while ((pos = head.find("\r\n")) != head.npos) {
    line = head.substr(0, pos);
    head = head.substr(pos + 2);
    ssize_t colon = line.find(":");
    if (colon == head.npos) {
      break;
    }
    colonSize = line[colon + 1] == ' ' ? 2 : 1;
    key = line.substr(0, colon);
    key = to_lower(key);
    val = line.substr(colon + colonSize);
    if (isRegex && regex_match(key, reg) || !isRegex && string(hkey).compare(key) == 0) {
      result = (char*)calloc(index + head.size() + 1, 1);
      memcpy(result, header, index);
      memcpy(result + index, head.c_str(), head.size());
      break;
    }
    index += pos + 2;
  }

  return result;
}

string RuleUtils::modBody(string body, string key, string val, bool isRegex) {
  string newBody = "";
  if (isRegex) {
    regex reg(key);
    newBody = regex_replace(body, reg, val);
  } else {
    string::size_type pos = 0;
    newBody = string(body);
    while ((pos = newBody.find(key, pos)) != string::npos) {
      newBody.replace(pos, key.size(), val);
      pos += key.size();
    }
  }

  return newBody;
}