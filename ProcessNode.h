#ifndef ProcessNode_h
#define ProcessNode_h

typedef struct ProcessNode {
  int id;
  int reqFlag;
  int resFlag;
  ProcessNode* next;
} ProcessNode;
#endif