#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>

uint32_t convertBigSmallEndian32(uint32_t num) {
  return (((num >> 0) & 0xFF) << 24) |
      (((num >> 8) & 0xFF) << 16) |
      (((num >> 16)& 0xFF) << 8) |
      (((num >> 24)& 0xFF) << 0);
}

uint32_t getFourByte(uint8_t *packet) {
  // 按网络传输的顺序读入 4 字节（注意本机为小端序，低位字节在前，而传输按从前到后进行，故packet[0](即“前”)对应低位，而packet[3](即“后”)对应高位）
  // 这样读进来便不会改变传输内容的大小端，即保持网络字节的大端序（也就是说在本机还需要转换之后才能使用）
  return (packet[0] << 0) |
      (packet[1] << 8) |
      (packet[2] << 16) |
      (packet[3] << 24);
}

void putFourByte(uint8_t *packet, uint32_t num) {
  // 按网络传输顺序放入 4 字节
  packet[0] = (num >> 0) & 0xFF;
  packet[1] = (num >> 8) & 0xFF;
  packet[2] = (num >> 16)  & 0xFF;
  packet[3] = (num >> 24)  & 0xFF;
}

bool checkMask(uint32_t mask) {
  // 检验 mask 是否合法——即连续的 1 后跟上连续的 0
  mask = convertBigSmallEndian32(mask);
  int i;
  for (i = 31; i >= 0; --i) {
    if(((mask >> i) & 1) == 0) break;
  }
  return (i == -1 || (mask & ((1 << i) - 1)) == 0);
}

extern bool isMulticastAddress(const in_addr_t &addr) {
  // 判断是否为 ripv2 组播地址 224.0.0.9
  return addr == 0x090000E0;
}

uint32_t getMaskFromLen(uint32_t len) {
  // 从子网掩码长度生成子网掩码
  return (~((1 << (32 - len)) - 1));
}

bool isInSameNetworkSegment(in_addr_t addr1, in_addr_t addr2, uint32_t len) {
  // 判断两个 ip 地址（子网掩码由len确定）是否在同一网段
  // addr1和addr2为大端序，len为小端序
  addr1 = convertBigSmallEndian32(addr1);
  addr2 = convertBigSmallEndian32(addr2);
  uint32_t mask = getMaskFromLen(len);
  return (addr1 & mask) == (addr2 & mask);
}
