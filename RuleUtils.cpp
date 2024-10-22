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
  this->ruleList = NULL;
  this->breakpintList = NULL;
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

void RuleUtils::clearBreakPoint() {
  BreakPoint* node = this->breakpintList;
  BreakPoint* next = NULL;

  while (node) {
    next = node->next;
    free(node);
    node = next;
  }

  this->breakpintList = NULL;
}

void RuleUtils::parseRule(char* data) {
  this->clearRule();
  string test = R"(
    [
      {"url": "https://www.baidu.com*", "type": 1, "methodType": 1, "method": 1, "key": "testAdd", "value": "123"},
      {"url": "https://www.baidu.com*", "type": 1, "methodType": 1, "method": 1, "key": "testMod", "value": "123"},
      {"url": "https://www.baidu.com*", "type": 1, "methodType": 1, "method": 1, "key": "testDel", "value": "123"},
      {"url": "https://www.baidu.com*", "type": 1, "methodType": 1, "method": 2, "key": "testMod", "value": "456"},
      {"url": "https://www.baidu.com*", "type": 1, "methodType": 1, "method": 3, "key": "testDel", "value": "1"},
      {"url": "https://www.baidu.com*", "type": 1, "methodType": 1, "method": 4, "key": "testAdd", "value": "abc"},
      {"url": "https://www.baidu.com*", "type": 1, "methodType": 1, "method": 5, "key": "accept-language", "value": "testMod"},
      {"url": "https://www.baidu.com*", "type": 1, "methodType": 1, "method": 6, "key": "accept-encoding", "value": "1"},
      {"url": "https://www.baidu.com*", "type": 2, "methodType": 1, "method": 4, "key": "testAdd", "value": "def"},
      {"url": "https://www.baidu.com*", "type": 2, "methodType": 1, "method": 5, "key": "traceid", "value": "testMod"},
      {"url": "https://www.baidu.com*", "type": 2, "methodType": 1, "method": 6, "key": "date", "value": "1"},
      {"url": "https://www.baidu.com*", "type": 2, "methodType": 2, "method": 8, "key": "<div", "value": "<div test=\"1\" "},
      {"url": "https://www.baidu.com*", "type": 2, "methodType": 2, "method": 8, "key": "[\\u4e00-\\u9fa5]+", "value": "测试中文", "enableReg": true}
    ]
  )";
  // string test = R"(
  //   [,
  //     {"url": "https://www.baidu.com*", "type": 2, "methodType": 2, "method": 7, "key": "", "value": "testMod"}]
  //    ]
  // )";
  // data = copyBuf(test.c_str());
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
    if (v.contains("url") && v.contains("type") && v.contains("methodType") && v.contains("method") && v.contains("key") && v.contains("value")) {
      string url = v.at("url");
      int type = v.at("type");
      int methodType = v.at("methodType");
      int method = v.at("method");
      string key = v.at("key");
      string value = v.at("value");
      bool enableWildcard = false;
      bool enableReg = false;
      bool icase = false;
      if (v.contains("enableWildcard")) {
        enableWildcard = v.at("enableWildcard");
      }
      if (v.contains("enableReg")) {
        enableReg = v.at("enableReg");
      }
      if (v.contains("icase")) {
        icase = v.at("icase");
      } else if (MODIFY_HEADER_ADD <= method && method <= MODIFY_HEADER_DEL) {
        icase = true;
      }
      if (type < RULE_REQ || type > RULE_RES) {
        continue;
      }
      if (methodType < RULE_METHOD_HEAD || methodType > RULE_METHOD_BODY) {
        continue;
      }
      if (method < MODIFY_PARAM_ADD || method > MODIFY_BODY_MOD) {
        continue;
      }
      node = (RuleNode*)malloc(sizeof(RuleNode));
      node->url = url;
      node->type = (ruleType)type;
      node->methodType = (ruleMethodType)methodType;
      node->method = (ruleMethod)method;
      node->key = key;
      node->value = value;
      node->enableWildcard = enableWildcard;
      node->enableReg = enableReg;
      node->icase = icase;
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

void RuleUtils::parseBreakpint(char* data) {
  this->clearBreakPoint();
  if (!data) {
    return;
  }

  BreakPoint* head = NULL;
  BreakPoint* node = NULL;
  json j = json::parse(data);
  if (!j.is_array()) {
    return;
  }

  for (auto& el : j.items()) {
    json v = el.value();
    if (v.contains("enable") && !v.at("enable")) {
      continue;
    }
    if (v.contains("url") && v.contains("type")) {
      string url = v.at("url");
      int type = v.at("type");

      if (type < RULE_REQ || type > RULE_RES) {
        continue;
      }
      node = (BreakPoint*)malloc(sizeof(BreakPoint));
      node->url = url;
      node->type = (ruleType)type;
      node->next = NULL;
      if (head) {
        head->next = node;
        head = node;
      } else {
        this->breakpintList = node;
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
  string head = string(header);
  ssize_t pos = head.find(" ");
  if (pos == string::npos) {
    return NULL;
  }
  ssize_t secPos = head.find(" ", pos + 1);
  if (secPos == string::npos) {
    return NULL;
  }

  string before = head.substr(0, pos + 1);
  string path = head.substr(pos + 1, secPos - pos - 1);
  string after = head.substr(secPos);
  pos = path.find("?");
  if (pos == string::npos) {
    path += "?";
  } else {
    path += "&";
  }
  path += key;
  if (strlen(value)) {
    path += "=";
    path.append(value, strlen(value));
  }
  head = before + path + after;

  return copyBuf(head.c_str());
}

char* RuleUtils::modParam(char* header, char* key, char* value, bool isRegex, bool icase) {
  string head = header;
  ssize_t pos = head.find(" ");
  if (pos == head.npos) {
    return NULL;
  }
  ssize_t secPos = head.find(" ", pos + 1);
  if (secPos == head.npos) {
    return NULL;
  }

  string before = head.substr(0, pos + 1);
  string line = head.substr(pos + 1, secPos - pos - 1);
  string after = head.substr(secPos);

  pos = line.find("?");
  if (pos == string::npos) {
    return NULL;
  }

  string path = line.substr(0, pos + 1);
  string param = line.substr(pos + 1);
  char** list = NULL;
  int size = split(param, list, '&');
  wregex reg(stringToWstring(key), icase ? regex_constants::icase : regex_constants::ECMAScript);
  string src = icase ? to_lower(string(key)) : string(key);
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
    if (i > 0) {
      param += "&";
    }
    if (isRegex && regex_match(stringToWstring(l[0]), reg) || !isRegex && src.compare(icase ? to_lower(l[0]) : l[0]) == 0) {
      param += l[0];
      param += "=";
      param += value;
      suc = true;
    }
    if (!suc) {
      param += l[0];
      if (str.find("=") != string::npos) {
        param += "=";
      }
      if (n > 1 && l[1]) {
        param += l[1];
      }
    }
    freeStrList(l, n);
  }
  head = before + path + param + after;

  return copyBuf(head.c_str());
}

char* RuleUtils::delParam(char* header, char* key, bool isRegex, bool icase) {
  string head = header;
  ssize_t pos = head.find(" ");
  if (pos == head.npos) {
    return NULL;
  }
  ssize_t secPos = head.find(" ", pos + 1);
  if (secPos == head.npos) {
    return NULL;
  }

  string before = head.substr(0, pos + 1);
  string line = head.substr(pos + 1, secPos - pos - 1);
  string after = head.substr(secPos);

  pos = line.find("?");
  if (pos == string::npos) {
    return NULL;
  }

  string path = line.substr(0, pos + 1);
  string param = line.substr(pos + 1);
  char** list = NULL;
  int size = split(param, list, '&');
  wregex reg(stringToWstring(key), icase ? regex_constants::icase : regex_constants::ECMAScript);
  string src = icase ? to_lower(string(key)) : string(key);
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
    if (isRegex && regex_match(stringToWstring(l[0]), reg) || !isRegex && src.compare(icase ? to_lower(l[0]) : l[0]) == 0) {
      suc = true;
    }
    if (!suc) {
      if (i > 0) {
        param += "&";
      }
      param += l[0];
      if (str.find("=") != string::npos) {
        param += "=";
      }
      if (n > 1 && l[1]) {
        param += l[1];
      }
    }
    freeStrList(l, n);
  }
  head = before + path + param + after;

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

char* RuleUtils::modHeader(char* header, char* hkey, char* hval, bool isRegex, bool icase) {
  string head = string(header);
  ssize_t pos = head.npos, index = 0;
  string line = "", key = "", val = "";
  char* result = NULL;
  char* tmp = NULL;
  int colonSize = 0;
  wregex reg(stringToWstring(hkey), icase ? regex_constants::icase : regex_constants::ECMAScript);
  string src = icase ? to_lower(string(hkey)) : string(hkey);

  pos = head.find("\r\n");
  if (pos == string::npos) {
    return NULL;
  }
  index = pos + 2;
  head = head.substr(pos + 2);

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
    if (isRegex && regex_match(stringToWstring(key), reg) || !isRegex && src.compare(icase ? to_lower(string(key)) : key) == 0) {
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

char* RuleUtils::delHeader(char* header, char* hkey, bool isRegex, bool icase) {
  string head = string(header);
  ssize_t pos = head.npos, index = 0;
  string line = "", key = "", val = "";
  char* result = NULL;
  int colonSize = 0;
  wregex reg(stringToWstring(hkey), icase ? regex_constants::icase : regex_constants::ECMAScript);
  string src = icase ? to_lower(string(hkey)) : string(hkey);

  pos = head.find("\r\n");
  if (pos == string::npos) {
    return NULL;
  }
  index = pos + 2;
  head = head.substr(pos + 2);

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
    if (isRegex && regex_match(stringToWstring(key), reg) || !isRegex && src.compare(icase ? to_lower(string(key)) : key) == 0) {
      result = (char*)calloc(index + head.size() + 1, 1);
      memcpy(result, header, index);
      memcpy(result + index, head.c_str(), head.size());
      break;
    }
    index += pos + 2;
  }

  return result;
}

string RuleUtils::modBody(string body, string key, string val, bool isRegex, bool icase) {
  if (isRegex) {
    wstring wbody = stringToWstring(body);
    wstring wkey = stringToWstring(key);
    wstring wval = stringToWstring(val);
    wstring newBody = L"";
    regex_constants::syntax_option_type flag = regex_constants::multiline;
    if (icase) {
      flag = flag | regex_constants::icase;
    }
    wregex reg(wkey.c_str(), flag);
    newBody = regex_replace(wbody, reg, wval);
    return wstringToString(newBody);
  } else {
    string::size_type pos = 0;
    string newBody = string(body);
    while ((pos = newBody.find(key, pos)) != string::npos) {
      newBody.replace(pos, key.size(), val);
      pos += key.size();
    }
    return newBody;
  }
}

bool RuleUtils::ifHasHeader(string head, string header) {
  string key = "(^|\r\n)";
  key += header;
  key += ":";

  wregex reg(stringToWstring(key).c_str(), regex_constants::multiline | regex_constants::icase);
  wsmatch matches;
  wstring whead = stringToWstring(head);
  
  // return regex_search(whead, matches, reg);
  return regex_search(whead, reg);
}