#include "V8Utils.h"
#include <iostream>
#include <unistd.h>

extern char* scriptScource;

V8Utils::V8Utils() {
}

V8Utils::~V8Utils() {
}

void V8Utils::initEventLoop() {
  std::unique_ptr<v8::Platform> platform = v8::platform::NewDefaultPlatform();
  v8::V8::InitializePlatform(platform.get());
  v8::V8::Initialize();

  // Create a new Isolate and make it the current one.
  v8::Isolate::CreateParams create_params;
  create_params.array_buffer_allocator = v8::ArrayBuffer::Allocator::NewDefaultAllocator();
  v8::Isolate* isolate = v8::Isolate::New(create_params);
  {
    v8::Isolate::Scope isolate_scope(isolate);
    // Create a stack-allocated handle scope.
    v8::HandleScope handle_scope(isolate);
    // Create a new context.
    v8::Local<v8::Context> context = v8::Context::New(isolate);
    // Enter the context.
    v8::Context::Scope context_scope(context);
    while (1) {
      if (!scriptScource) {
        usleep(1000);
        continue;
      }
      v8::Local<v8::String> source = v8::String::NewFromUtf8(isolate, scriptScource).ToLocalChecked();
      v8::Local<v8::Script> script = v8::Script::Compile(context, source).ToLocalChecked();
      v8::Local<v8::Value> result = script->Run(context).ToLocalChecked();
      v8::Local<v8::Value> func = context->Global()->Get(context, v8::String::NewFromUtf8(isolate, "run").ToLocalChecked()).ToLocalChecked();
      scriptScource = NULL; // 清空脚本
      if (func->IsFunction()) {
        while (1) {
          if (scriptScource) { // 重新编译新的脚本
            break;
          }
          v8::Local<v8::Value> arguments[2];
          // arguments[0] = v8::String::NewFromUtf8(isolate, "1").ToLocalChecked();
          arguments[0] = v8::Number::New(isolate, 10.1);
          arguments[1] = v8::Number::New(isolate, 2);
          {
            v8::MaybeLocal<v8::Value> foo_ret = func.As<v8::Object>()->CallAsFunction(context, context->Global(), 2, arguments);
            if (!foo_ret.IsEmpty()) {
              v8::String::Utf8Value utf8Value(isolate, foo_ret.ToLocalChecked());
              std::cout << "result: " << *utf8Value << std::endl;
            }
          }
          usleep(1000);
        }
      }
    }
  }
  // Dispose the isolate and tear down V8.
  isolate->Dispose();
  v8::V8::Dispose();
  v8::V8::DisposePlatform();
  delete create_params.array_buffer_allocator;
}