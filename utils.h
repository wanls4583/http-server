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

int split(char**& strs, const string& s, const char delim);
int* getLink(const char* p, ssize_t pSize);
int kmpStrstr(const char* s, const char* p, ssize_t sSize, ssize_t pSize, ssize_t start = 0);
char* copyBuf(const char* str);
char* sliceBuf(const char* str, ssize_t start, ssize_t end);
char* runCmd(const char* strCmd);
char* readFile(ifstream& inFile, ssize_t& len);

#endif