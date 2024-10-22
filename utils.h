#ifndef UTILS
#define UTILS
#include <iostream>
#include <sstream>
#include <fstream>
#include <unistd.h>
#include <openssl/ssl.h>
#include <zlib.h>
#include "brotli/decode.h"
#include "utils/hex.h"
#include "utils/md5.h"
#include "utils/sha.h"
#include "utils/digest.h"
#include "utils/base64.h"

using namespace std;

typedef enum {
  E_ZIP_RAW = -MAX_WBITS,
  E_ZIP_ZLIB = MAX_WBITS,
  E_ZIP_GZIP = MAX_WBITS + 16
} zip_type;
enum { STATUS_FAIL_CONNECT = 1, STATUS_FAIL_SSL_CONNECT };
enum { MSG_REQ_HEAD = 1, MSG_REQ_BODY, MSG_REQ_BODY_END, MSG_RES_HEAD, MSG_RES_BODY, MSG_RES_BODY_END, MSG_DNS, MSG_STATUS, MSG_TIME, MSG_CIPHER, MSG_CERT, MSG_RULE };
enum { TIME_DNS_START = 1, TIME_DNS_END, TIME_CONNECT_START, TIME_CONNECT_END, TIME_CONNECT_SSL_START, TIME_CONNECT_SSL_END, TIME_REQ_START, TIME_REQ_END, TIME_RES_START, TIME_RES_END };
enum { DATA_TYPE_REQ_HEAD = 1, DATA_TYPE_RES_HEAD, DATA_TYPE_REQ_BODY, DATA_TYPE_RES_BODY, DATA_TYPE_CERT, DATA_TYPE_RULE, DATA_TYPE_RULE_ENABLE };

char* to_lower(char* s);
char* to_upper(char* s);
string to_lower(string s);
string to_upper(string s);
int split(const string& s, char**& strs, const char delim);
void freeStrList(char** strs, int size);
char* jsU8ArrayToChar(char* arr);
int* getLink(const char* p, ssize_t pSize);
int kmpStrstr(const char* s, const char* p, ssize_t sSize, ssize_t pSize, ssize_t start = 0);
char* copyBuf(const char* str, ssize_t size = 0);
char* sliceBuf(const char* str, ssize_t start, ssize_t end);
char* runCmd(const char* strCmd);
void removeDir(const char* dir);
char* readFile(ifstream& inFile, ssize_t& len);
struct tm ASN1_GetTm(ASN1_TIME* time);
char* findPidByPort(int port);
bool wildcardMatch(char* s, char* p);
char* brotli_decompress(char* data, ssize_t datalen, ssize_t* destLen);
char* zlib_decompress(char* data, ssize_t datalen, ssize_t* destLen, zip_type type);
wstring stringToWstring(const string& str);
string wstringToString(const wstring& wstr);

#endif