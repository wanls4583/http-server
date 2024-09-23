#include "LevelUtils.h"

LevelUtils::LevelUtils(const char* filename) {
  this->filename = filename;
  leveldb::Options options;
  options.create_if_missing = true;
  status = leveldb::DB::Open(options, filename, &db);
}

LevelUtils::~LevelUtils() {
  delete this->db;
}

char* LevelUtils::get(char* key, ssize_t& size) {
  char* bytes = NULL;
  if (this->status.ok()) {
    std::string s;
    leveldb::Status status = this->db->Get(leveldb::ReadOptions(), key, &s);
    bytes = (char*)calloc(s.size() + 1, 1);
    memcpy(bytes, s.c_str(), s.size());
  }
  return bytes;
}

bool LevelUtils::put(char* key, char* data, ssize_t size) {
  if (this->status.ok()) {
    leveldb::Slice slice(data, size);
    leveldb::Status status = this->db->Put(leveldb::WriteOptions(), key, slice);
    return status.ok();
  }
  return false;
}

bool LevelUtils::del(char* key) {
  if (this->status.ok()) {
    leveldb::Status status = this->db->Delete(leveldb::WriteOptions(), key);
    return status.ok();
  }
  return false;
}