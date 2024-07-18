#ifndef WsFragment_h
#define WsFragment_h

typedef struct WsFragment {
    // [1bit]FIN如果是1，表示这是消息（message）的最后一个分片（fragment），如果是0，表示不是最后一个分片
    unsigned char fin;
    // [3bit]rsv标志位，用来代表是否采用WebSocket扩展，一般为0
    unsigned char rsv;
    // [4bit]opCode操作代码，其值所代表的含义如下：
    // 0x0：表示一个延续帧。当Opcode为0时，表示本次数据传输采用了数据分片，当前收到的数据帧为其中一个数据分片
    // 0x1：表示这是一个文本帧（frame）
    // 0x2：表示这是一个二进制帧（frame）
    // 0x3-7：保留的操作代码，用于后续定义的非控制帧
    // 0x8：表示连接断开
    // 0x9：表示这是一个ping操作
    // 0xA：表示这是一个pong操作
    // 0xB-F：保留的操作代码，用于后续定义的控制帧
    unsigned char opCode;
    // [1bit]mask表示是否要对数据载荷进行掩码操作
    // 从客户端向服务端发送数据时，需要对数据进行掩码操作，此时mask为1
    // 从服务端向客户端发送数据时，不需要对数据进行掩码操作，此时mask为0
    // 如果服务端接收到的数据没有进行过掩码操作，服务端需要断开连接
    // 如果mask是1，那么在Masking-key中会定义一个掩码键（masking key），并用这个掩码键来对数据载荷进行反掩码
    unsigned char mask;
    // [7bit]dataLen，数据的长度
    // 如果dataLen为(0~126)，则dataLen代表所要接收的数据的长度
    // 如果dataLen为126，则dataLen的后续的2个字节代表的一个16位的无符号整数才是真正的数据长度
    // 如果dataLen为127，则dataLen的后续的4个字节代表的一个64位的无符号整数才是真正的数据长度
    unsigned char dataLen;
    // [2/4byte]，依dataLen而定
    u_int64_t dataLen2;
    // [4byte]掩码键，依mask而定
    unsigned char* maskKey;
    // 接收的数据
    unsigned char* data;
    // 下一祯
    WsFragment* next;
    u_int64_t fragmentSize;
} WsFragment;
#endif