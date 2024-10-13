#ifndef DataUtils_h
#define DataUtils_h
#include "SockInfo.h"


class DataUtils {
private:
public:
  DataUtils();
  ~DataUtils();
  char* getData(int dataType, u_int64_t reqId, ssize_t& size);
  void saveData(char* data, u_int64_t dataLen, int type, u_int64_t reqId = 0);
};
#endif