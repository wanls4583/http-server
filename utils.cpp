#include "utils.h"
#include <openssl/ssl.h>

int split(char**& strs, const string& s, const char delim = ' ') {
    vector<string> sv;
    istringstream iss(s);
    string temp;

    while (getline(iss, temp, delim)) {
        sv.emplace_back(temp);
    }

    int size = sv.size();

    if (!size) {
        return 0;
    }

    strs = (char**)calloc(size, sizeof(char*));

    for (int i = 0; i < size; i++) {
        strs[i] = new char[sv[i].size() + 1];
        strcpy(strs[i], sv[i].c_str());
    }

    return size;
}

int* getLink(const char* p, ssize_t pSize) {
    int* link = (int*)calloc(1, pSize * sizeof(int));
    link[0] = -1;
    link[1] = 0;
    // cout << "-1,0";
    for (int i = 2; i < pSize; i++) {
        int j = link[i - 1];
        while (j > -1) {
            if (p[i - 1] == p[j]) {
                break;
            }
            j = link[j];
        }
        link[i] = j + 1;
        // cout << "," << link[i];
    }
    // cout << endl;
    return link;
}

int kmpStrstr(const char* s, const char* p, ssize_t sSize, ssize_t pSize, ssize_t start) {
    if (pSize > sSize || pSize < 1) {
        return -1;
    }
    int* link = getLink(p, pSize);
    int i = start, j = 0;
    while (i < sSize && j < pSize) {
        if (s[i] == p[j]) {
            i++;
            j++;
        } else {
            j = link[j];
            if (j == -1) {
                i++;
                j++;
            }
        }
    }
    if (j >= pSize) {
        return i - j;
    }
    free(link);

    return -1;
}

char* copyBuf(const char* str) {
    if (str && strlen(str)) {
        char* s = (char*)calloc(strlen(str) + 1, 1);
        strcpy(s, str);
        return s;
    }
    return NULL;
}

char* sliceBuf(const char* str, ssize_t start, ssize_t end) {
    if (end <= start) {
        return NULL;
    }
    char* res = (char*)calloc(end - start, 1);
    memcpy(res, str + start, end - start);

    return res;
}

char* concatBuf(const char* a, const char* b, ssize_t aSize, ssize_t bSize) {
    char* res = (char*)calloc(aSize + bSize, 1);

    memcpy(res, a, aSize);
    memcpy(res + aSize, b, bSize);

    return res;
}

char* runCmd(const char* strCmd) {
    FILE* fp = NULL;
    char buf[1024];
    char* result = (char*)calloc(4096, 1);
    if ((fp = popen(strCmd, "r")) != NULL) {
        while (fgets(buf, 1024, fp) != NULL) {
            strcat(result, buf);
        }
        pclose(fp);
        fp = NULL;
        return result;
    }
    return NULL;
}

char* readFile(ifstream& inFile, ssize_t& len) {

    inFile.seekg(0, inFile.end);

    len = inFile.tellg();

    inFile.seekg(0, inFile.beg);

    char* arr = (char*)calloc(len, 1);

    inFile.read(arr, len);

    return arr;
}

static tm ASN1_GetTm(ASN1_TIME* time) {
    struct tm t;
    const char* str = (const char*)time->data;
    size_t i = 0;

    memset(&t, 0, sizeof(t));

    if (time->type == V_ASN1_UTCTIME) /* two digit year */
    {
        t.tm_year = (str[i] - '0') * 10 + (str[i + 1] - '0');
        i += 2;
        if (t.tm_year < 70) {
            t.tm_year += 100;
        }
    } else if (time->type == V_ASN1_GENERALIZEDTIME) /* four digit year */
    {
        t.tm_year = (str[i] - '0') * 1000 + (str[i + 1] - '0') * 100 + (str[i + 2] - '0') * 10 + (str[i + 3] - '0');
        t.tm_year -= 1900;
        i += 4;
    }

    t.tm_mon = ((str[i] - '0') * 10 + (str[i + 1] - '0')) - 1; // -1 since January is 0 not 1.
    i += 2;
    t.tm_mday = (str[i] - '0') * 10 + (str[i + 1] - '0');
    i += 2;
    t.tm_hour = (str[i] - '0') * 10 + (str[i + 1] - '0');
    i += 2;
    t.tm_min = (str[i] - '0') * 10 + (str[i + 1] - '0');
    i += 2;
    t.tm_sec = (str[i] - '0') * 10 + (str[i + 1] - '0');

    return t;
}