#ifndef v8_h
#define v8_h
#include "libplatform/libplatform.h"
#include "v8-context.h"
#include "v8-initialization.h"
#include "v8-isolate.h"
#include "v8-local-handle.h"
#include "v8-primitive.h"
#include "v8-script.h"

class V8Utils {
private:
public:
  V8Utils();
  ~V8Utils();
  void initEventLoop();
};
#endif