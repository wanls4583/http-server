#ifndef UTILS
#define UTILS
#include <iostream>
#include <sstream>

using namespace std;

int split(char **&strs, const string &s, const char delim);
int *getLink(const char *p, size_t pSize);
int kmpStrstr(const char *s, const char *p, size_t sSize, size_t pSize);

#endif