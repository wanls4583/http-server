#ifndef DataUtils_h
#define DataUtils_h
#include "SockInfo.h"


class DataUtils {
private:
public:
  DataUtils();
  ~DataUtils();
  void saveBody(char* data, u_int64_t dataLen, SockInfo& sockInfo);
  void sendData(char* data, u_int64_t dataLen, int type);
};
#endif