#ifndef LevelUtils_h
#define LevelUtils_h
#include "leveldb/db.h"

class LevelUtils {
private:
  leveldb::Status status;
  leveldb::DB* db;
public:
  const char* filename;
  LevelUtils(const char* filename);
  ~LevelUtils();
  char* get(char* key, ssize_t& size);
  bool put(char* key, char* data, ssize_t size);
  bool del(char* key);
};
#endif