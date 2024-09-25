#ifndef LevelUtils_h
#define LevelUtils_h
#include "leveldb/db.h"

using namespace std;

class LevelUtils {
private:
  leveldb::Status status;
  leveldb::DB* db;
public:
  const char* filename;
  LevelUtils(const char* filename);
  ~LevelUtils();
  char* get(string key, ssize_t& size);
  bool put(string key, char* data, ssize_t size);
  bool del(string key);
};
#endif