#include "utils.h"

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

int* getLink(const char* p, size_t pSize) {
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

int kmpStrstr(const char* s, const char* p, size_t sSize, size_t pSize, size_t start) {
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

char* sliceBuf(const char* str, size_t start, size_t end) {
    if (end <= start) {
        return NULL;
    }
    char *res = (char *)calloc(end - start, 1);
    memcpy(res, str + start, end - start);

    return res;
}

char* concatBuf(const char* a, const char* b, size_t aSize, size_t bSize) {
    char *res = (char *)calloc(aSize + bSize, 1);

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

char* readFile(ifstream& inFile, size_t& len) {

    inFile.seekg(0, inFile.end);

    len = inFile.tellg();

    inFile.seekg(0, inFile.beg);

    char* arr = (char*)calloc(len, 1);

    inFile.read(arr, len);

    return arr;
}