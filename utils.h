#ifndef UTILS
#define UTILS
#include <iostream>
#include <sstream>

using namespace std;

int split(char**& strs, const string& s, const char delim);
int* getLink(const char* p, size_t pSize);
int kmpStrstr(const char* s, const char* p, size_t sSize, size_t pSize, size_t start = 0);
char* copyBuf(const char* str);
char* sliceBuf(const char* str, size_t start, size_t end);
char* runCmd(const char* strCmd);

#endif