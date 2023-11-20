#include "utils.h"

int split(char **&strs, const string &s, const char delim = ' ')
{
    vector<string> sv;
    istringstream iss(s);
    string temp;

    while (getline(iss, temp, delim))
    {
        sv.emplace_back(std::move(temp));
    }

    int size = sv.size();

    if (!size)
    {
        return 0;
    }

    strs = (char **)calloc(size, sizeof(char *));

    for (int i = 0; i < size; i++)
    {
        strs[i] = new char[sv[i].size() + 1];
        strcpy(strs[i], sv[i].c_str());
    }

    return size;
}