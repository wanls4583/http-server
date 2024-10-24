#include "utils.h"
#include "regex.h"
#include <boost/locale.hpp>

extern pthread_mutex_t cmdMutex;

char* to_lower(char* s) {
    ssize_t len = strlen(s);
    for (ssize_t i = 0; i < len; i++) {
        if (s[i] >= 'A' && s[i] <= 'Z') {
            s[i] += 32;
        }
    }
    return s;
}

char* to_upper(char* s) {
    ssize_t len = strlen(s);
    for (ssize_t i = 0; i < len; i++) {
        if (s[i] >= 'a' && s[i] <= 'z') {
            s[i] -= 32;
        }
    }
    return s;
}

string to_lower(string s) {
    ssize_t len = s.size();
    for (ssize_t i = 0; i < len; i++) {
        if (s[i] >= 'A' && s[i] <= 'Z') {
            s[i] += 32;
        }
    }
    return s;
}

string to_upper(string s) {
    ssize_t len = s.size();
    for (ssize_t i = 0; i < len; i++) {
        if (s[i] >= 'a' && s[i] <= 'z') {
            s[i] -= 32;
        }
    }
    return s;
}

int split(const string& s, char**& strs, const char delim = ' ') {
    vector<string> sv;
    istringstream iss(s);
    string temp;

    while (getline(iss, temp, delim)) {
        sv.emplace_back(temp);
    }
    if (s.back() == delim) {
        sv.emplace_back("");
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

void freeStrList(char** strs, int size) {
    for (int i = 0; i < size; i++) {
        free(strs[i]);
    }
    free(strs);
}

char* jsU8ArrayToChar(char* arr) {
    char** str;
    char* result;

    ssize_t size = split(arr, str, ',');
    result = (char*)calloc(size, 1);

    for (int i = 0; i < size; i++) {
        result[i] = atoi(str[i]);
    }

    return result;
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
    if (sSize < 1 || pSize < 1 || pSize > sSize) {
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

char* copyBuf(const char* str, ssize_t size) {
    if (!str) {
        return NULL;
    }
    size = size ? size : strlen(str);
    if (str && size) {
        char* s = (char*)calloc(size + 1, 1);
        memcpy(s, str, size);
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
    int bufSize = 1024;
    int resultSize = 0;
    char buf[bufSize];
    char* result = NULL;
    if ((fp = popen(strCmd, "r")) != NULL) {
        while (!feof(fp)) {
            memset(buf, 0, bufSize);
            if (fgets(buf, bufSize, fp) != NULL) {
                int len = buf[bufSize - 1] ? bufSize : strlen(buf);
                len = len > bufSize ? bufSize : len;
                result = (char*)realloc(result, resultSize + len + 1);
                result[resultSize + len] = 0; // realloc增加的内存不会清空
                memcpy(result + resultSize, buf, len);
                resultSize += len;
            }
        }
        // cout << "size:" << resultSize << endl;
        pclose(fp);
        fp = NULL;

        return result;
    }
    return NULL;
}

void removeDir(const char* dir) {
    string cmd = "rm -rf ";
    cmd += dir;
    runCmd(cmd.c_str());
}

char* readFile(ifstream& inFile, ssize_t& len) {

    inFile.seekg(0, inFile.end);

    len = inFile.tellg();

    inFile.seekg(0, inFile.beg);

    char* arr = (char*)calloc(len, 1);

    inFile.read(arr, len);

    return arr;
}

struct tm ASN1_GetTm(ASN1_TIME* time) {
    struct tm t;
    const char* str = (const char*)time->data;
    ssize_t i = 0;

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

char* findPidByPort(int pt) {
    char* pid = NULL;
    string s = to_string(pt);
    char* port = (char*)s.c_str();
    string cmd = "netstat -anv -p TCP | grep ";
    cmd += port;
    pthread_mutex_lock(&cmdMutex);
    char* text = runCmd(cmd.c_str());
    pthread_mutex_unlock(&cmdMutex);
    if (!text || !strlen(text)) {
        return pid;
    }
    // cout << text << endl;
    // cout << "text:" << strlen(text) << endl;
    // return NULL;
    // char* text = (char*)"tcp4       0      0  127.0.0.1.56711        127.0.0.1.56712        ESTABLISHED  408209  146988  41901      0 00182 00000000 0000000000513a09 00000080 01000900      1      0 000001\ntcp4       0      0  127.0.0.1.56712        127.0.0.1.56711        ESTABLISHED  408108  146988  41902      0 00182 00000000 0000000000513a08 00000080 04000900      1      0 0000001"; //目标文本
    // port = (char*)"56711";
    regex_t* lineReg = (regex_t*)malloc(sizeof(regex_t));
    regex_t* spaceReg = (regex_t*)malloc(sizeof(regex_t));
    regex_t* portReg = (regex_t*)malloc(sizeof(regex_t));
    int status = regcomp(lineReg, (char*)"\r\n|\n|\r", REG_EXTENDED); //编译模式
    status = regcomp(spaceReg, (char*)"[[:space:]]+", REG_EXTENDED); //编译模式
    status = regcomp(portReg, (char*)"([[:digit:]]+)[[:space:]]", REG_EXTENDED); //编译模式
    // itoa(pt, port, 10);
    // if (status) { //处理可能的错误
    //     char error_message[1000];
    //     regerror(status, r, error_message, 1000);
    //     printf("Regex error compiling '%s': %s\n", text, error_message);
    // }
    ssize_t nmatch = 2; //可有有子匹配，$&，$1，$2，$3...，下标为0，1，2，3...
    regmatch_t m[nmatch];
    char* p = text;
    char* line = NULL;
    int isEnd = 0, start = 0, end = 0;
    while (!isEnd) {
        memset(m, -1, sizeof(regmatch_t) * nmatch);
        status = regexec(lineReg, p, 1, m, 0); //匹配操作
        if (status == REG_NOMATCH) { //判断结束或错误
            // char error_message[1000];
            // regerror(status, r, error_message, 1000);
            // printf("Regex Match Error '%s': %s\n", text, error_message);
            isEnd = 1;
            line = p;
        } else {
            start = (int)m[0].rm_so;
            end = (int)m[0].rm_eo;
            line = (char*)malloc(start);
            memcpy(line, p, start);
            p += end;
        }

        for (int i = 0; i <= 9; i++) {
            status = regexec(spaceReg, line, 1, m, 0);
            if (status == REG_NOMATCH) {
                break;
            }
            start = m[0].rm_so;
            end = m[0].rm_eo;
            if (i == 2) {
                char* ip = line + end;
                status = regexec(portReg, ip, 2, m, 0);
                if (status == REG_NOMATCH) {
                    break;
                }
                if (strncmp(ip + m[1].rm_so, port, m[1].rm_eo - m[1].rm_so)) {
                    break;
                }
            }
            if (i == 9) {
                char* pt = line + end;
                status = regexec(spaceReg, pt, 1, m, 0);
                if (status == REG_NOMATCH) {
                    break;
                }
                pid = (char*)calloc(m[0].rm_so + 1, 1);
                memcpy(pid, pt, m[0].rm_so);
                // cout << "find pid:" << pid << endl;
                free(text);

                return pid;
            }
            line += end;
            if (!line[0]) {
                break;
            }
        }

        if (!p[0]) {
            break;
        }
    }
    free(text);

    return pid;
}

bool allStars(char* str, int left, int right) {
    for (int i = left; i < right; ++i) {
        if (str[i] != '*') {
            return false;
        }
    }
    return true;
}
bool charMatch(char u, char v) { return u == v || v == '?'; };

bool wildcardMatch(char* s, char* p) {
    int len_s = strlen(s), len_p = strlen(p);
    while (len_s && len_p && p[len_p - 1] != '*') {
        if (charMatch(s[len_s - 1], p[len_p - 1])) {
            len_s--;
            len_p--;
        } else {
            return false;
        }
    }
    if (len_p == 0) {
        return len_s == 0;
    }

    int sIndex = 0, pIndex = 0;
    int sRecord = -1, pRecord = -1;
    while (sIndex < len_s && pIndex < len_p) {
        if (p[pIndex] == '*') {
            ++pIndex;
            sRecord = sIndex;
            pRecord = pIndex;
        } else if (charMatch(s[sIndex], p[pIndex])) {
            ++sIndex;
            ++pIndex;
        } else if (sRecord != -1 && sRecord + 1 < len_s) {
            ++sRecord;
            sIndex = sRecord;
            pIndex = pRecord;
        } else {
            return false;
        }
    }
    return allStars(p, pIndex, len_p);
}

char* brotli_decompress(char* data, ssize_t datalen, ssize_t* destLen) {
    char* result = NULL;
    size_t decoded_size = datalen * 20;
    unsigned char decoded_buf[decoded_size];
    BrotliDecoderResult st = BrotliDecoderDecompress(datalen, (unsigned char*)data, &decoded_size, decoded_buf);
    if (st == BROTLI_DECODER_RESULT_SUCCESS) {
        *destLen = decoded_size;
        result = (char*)calloc(decoded_size + 1, 1);
        memcpy(result, decoded_buf, decoded_size);
    }

    return result;
}

char* zlib_decompress(char* data, ssize_t datalen, ssize_t* destLen, zip_type type) {
    z_stream zs;                        // z_stream is zlib's control structure
    memset(&zs, 0, sizeof(zs));
    *destLen = 0;

    int ret = inflateInit2(&zs, type);
    if (ret != Z_OK) {
        return NULL;
    }

    zs.next_in = (Bytef*)data;
    zs.avail_in = datalen;

    char outbuffer[32768];
    char* result = NULL;
    ssize_t size = 0;

    do {
        zs.next_out = reinterpret_cast<Bytef*>(outbuffer);
        zs.avail_out = sizeof(outbuffer);
        ret = inflate(&zs, 0);
        if (size < zs.total_out) {
            ssize_t num = zs.total_out - size;
            ssize_t newSize = size + num;
            result = (char*)realloc(result, newSize + 1);
            result[newSize] = 0;
            memcpy(result + size, outbuffer, zs.total_out - size);
            size = newSize;
        }
    } while (ret == Z_OK);

    inflateEnd(&zs);
    *destLen = size;

    return result;
}

wstring stringToWstring(const string& str) {
    wstring result = boost::locale::conv::utf_to_utf<wchar_t>(str);
    return result;
}

string wstringToString(const wstring& wstr) {
    string result = boost::locale::conv::utf_to_utf<char>(wstr);
    return result;
}