#ifndef RuleUtils_h
#define RuleUtils_h

using namespace std;

typedef enum { RULE_REQ = 1, RULE_RES } ruleType;
typedef enum { RULE_WAY_HEAD = 1, RULE_WAY_BODY } ruleWayType;
typedef enum {
  MODIFY_PARAM_ADD = 1,
  MODIFY_PARAM_MOD,
  MODIFY_PARAM_DEL,
  MODIFY_HEADER_ADD,
  MODIFY_HEADER_MOD,
  MODIFY_HEADER_DEL,
  MODIFY_BODY_REP,
  MODIFY_BODY_MOD,
  BREAK_POINT
} ruleWay;

typedef struct RuleNode {
  ruleType type;
  ruleWayType wayType;
  ruleWay way;
  string url;
  string key;
  string value;
  bool enableReg;
  RuleNode* next;
} RuleNode;

class RuleUtils {
private:
public:
  RuleUtils();
  ~RuleUtils();
  RuleNode* ruleList;
  void clearRule();
  void parseRule(char* data);
  void broadcast(u_int64_t reqId, char* data, u_int64_t dataLen);
  void broadcastAll();
  char* addParam(char* header, char* key, char* value);
  char* modParam(char* header, char* key, char* value, bool isRegex = false);
  char* delParam(char* header, char* key, bool isRegex = false);
  char* addHeader(char* header, char* hkey, char* hval);
  char* modHeader(char* header, char* hkey, char* hval, bool isRegex = false);
  char* delHeader(char* header, char* hkey, bool isRegex = false);
  string modBody(string body, string key, string val, bool isRegex = false);
};
#endif