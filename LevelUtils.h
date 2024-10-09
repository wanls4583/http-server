#ifndef LevelUtils_h
#define LevelUtils_h
#include "leveldb/db.h"

using namespace std;

class LevelUtils {
private:
  leveldb::Status status;
  leveldb::DB* db;
  pthread_mutex_t mutex;
public:
  const char* filename;
  LevelUtils(const char* filename, bool clear = false);
  ~LevelUtils();
  void init();
  void clear();
  char* get(string key, ssize_t& size);
  bool put(string key, char* data, ssize_t size);
  bool del(string key);
};
#endif