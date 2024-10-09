#include "LevelUtils.h"
#include "utils.h"

using namespace std;

LevelUtils::LevelUtils(const char* filename, bool clear) {
  pthread_mutex_init(&mutex, NULL);
  this->filename = filename;
  if (clear) {
    removeDir(filename);
  }
  this->init();
}

LevelUtils::~LevelUtils() {
  delete this->db;
}

void LevelUtils::init() {
  pthread_mutex_lock(&mutex);
  delete this->db;
  leveldb::Options options;
  options.create_if_missing = true;
  status = leveldb::DB::Open(options, filename, &db);
  pthread_mutex_unlock(&mutex);
}

void LevelUtils::clear() {
  pthread_mutex_lock(&mutex);
  removeDir(filename);
  pthread_mutex_unlock(&mutex);

  this->init();
}

char* LevelUtils::get(string key, ssize_t& size) {
  char* bytes = NULL;
  size = 0;
  if (this->status.ok()) {
    std::string s;

    pthread_mutex_lock(&mutex);
    leveldb::Status status = this->db->Get(leveldb::ReadOptions(), key, &s);
    pthread_mutex_unlock(&mutex);

    if (status.ok()) {
      bytes = (char*)calloc(s.size() + 1, 1);
      memcpy(bytes, s.c_str(), s.size());
      size = s.size();
    }
  }
  return bytes;
}

bool LevelUtils::put(string key, char* data, ssize_t size) {
  if (this->status.ok()) {
    leveldb::Slice slice(data, size);

    pthread_mutex_lock(&mutex);
    leveldb::Status status = this->db->Put(leveldb::WriteOptions(), key, slice);
    pthread_mutex_unlock(&mutex);

    return status.ok();
  }
  return false;
}

bool LevelUtils::del(string key) {
  if (this->status.ok()) {
    pthread_mutex_lock(&mutex);
    leveldb::Status status = this->db->Delete(leveldb::WriteOptions(), key);
    pthread_mutex_unlock(&mutex);

    return status.ok();
  }
  return false;
}