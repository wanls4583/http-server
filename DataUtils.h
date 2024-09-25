#ifndef DataUtils_h
#define DataUtils_h
#include "SockInfo.h"


class DataUtils {
private:
public:
  DataUtils();
  ~DataUtils();
  void saveRule(char* data, u_int64_t dataLen);
  void savePem(char* data, u_int64_t dataLen, u_int64_t reqId);
  void saveBody(char* data, u_int64_t dataLen, int type, u_int64_t reqId);
  void sendData(char* data, u_int64_t dataLen, int type);
};
#endif