#ifndef RuleUtils_h
#define RuleUtils_h

#include "SockInfo.h"

typedef struct RuleNode {
  int id;
  int reqFlag;
  int resFlag;
  char* rule;
  RuleNode* next;
} RuleNode;

class RuleUtils {
private:
public:
  RuleUtils();
  ~RuleUtils();
  RuleNode* ruleNode;
  int reciveId;
  void clearRule();
  void parseRule(char* data, u_int64_t dataLen);
  void reciveData(char* data, u_int64_t dataLen);
  void broadcastAll();
  RuleNode* findRule(SockInfo* sockInfo);

};
#endif