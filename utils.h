#ifndef UTILS
#define UTILS
#include <iostream>
#include <sstream>
#include <fstream>
#include "utils/hex.h"
#include "utils/md5.h"
#include "utils/sha.h"
#include "utils/digest.h"
#include "utils/base64.h"

using namespace std;

enum { STATUS_FAIL_CONNECT = 1, STATUS_FAIL_SSL_CONNECT };
enum { MSG_REQ_HEAD = 1, MSG_REQ_BODY, MSG_REQ_BODY_END, MSG_RES_HEAD, MSG_RES_BODY, MSG_RES_BODY_END, MSG_DNS, MSG_STATUS, MSG_TIME, MSG_CIPHER, MSG_CERT, MSG_PORT, MSG_RULE, MSG_REQ_BODY_DATA, MSG_RES_BODY_DATA };
enum { TIME_DNS_START = 1, TIME_DNS_END, TIME_CONNECT_START, TIME_CONNECT_END, TIME_CONNECT_SSL_START, TIME_CONNECT_SSL_END, TIME_REQ_START, TIME_REQ_END, TIME_RES_START, TIME_RES_END };
enum { DATA_TYPE_REQ_HEAD = 1, DATA_TYPE_RES_HEAD, DATA_TYPE_REQ_BODY, DATA_TYPE_RES_BODY, DATA_TYPE_CERT, DATA_TYPE_RULE };

char* to_lower(char* s);
char* to_upper(char* s);
string to_lower(string s);
string to_upper(string s);
int split(const string& s, char**& strs, const char delim);
char* jsU8ArrayToChar(char* arr);
int* getLink(const char* p, ssize_t pSize);
int kmpStrstr(const char* s, const char* p, ssize_t sSize, ssize_t pSize, ssize_t start = 0);
char* copyBuf(const char* str);
char* sliceBuf(const char* str, ssize_t start, ssize_t end);
char* runCmd(const char* strCmd);
char* readFile(ifstream& inFile, ssize_t& len);
char* findPidByPort(int port);
bool wildcardMatch(char* s, char* p);

#endif