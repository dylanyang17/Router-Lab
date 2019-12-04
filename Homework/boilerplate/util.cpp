#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include "router_hal.h"

uint32_t convertBigSmallEndian32(uint32_t num) {
  return (((num >> 0) & 0xFF) << 24) |
    (((num >> 8) & 0xFF) << 16) |
    (((num >> 16)& 0xFF) << 8) |
    (((num >> 24)& 0xFF) << 0);
}

void cycleSum(uint32_t &sum, uint16_t num) {
  // 循环求和，用于求校验和
  while(num) {
    sum += num;
    num = sum >> 16;
    sum = sum & 0xFFFF;
  }
}

uint16_t calcIPChecksum(uint8_t *packet, size_t len) {
  // 计算 packet 的 ip 首部校验和
  size_t headLen = (size_t)(packet[0] & 0xF) * 4;
  uint32_t sum = 0;       // 计算得到的校验和
  for (int i = 0; i < headLen; i += 2) {
    if (i==10) continue;
    uint16_t tmp = ((uint16_t)packet[i] << 8) + packet[i + 1];
    cycleSum(sum, tmp);
  }
  return sum ^ 0xFFFF;
}

uint16_t calcUDPChecksum(uint8_t *packet, size_t len, in_addr_t srcAddr, in_addr_t dstAddr) {
  // 计算 packet 的 udp 首部校验和（packet起始便为UDP头），len 为 UDP 包长度
  uint32_t sum = 0;
  // 伪首部
  cycleSum(sum, (uint16_t)(srcAddr >> 16));
  cycleSum(sum, (uint16_t)(srcAddr & 0xFFFF));
  cycleSum(sum, (uint16_t)(dstAddr >> 16));
  cycleSum(sum, (uint16_t)(dstAddr & 0xFFFF));
  cycleSum(sum, (uint16_t)0x11);
  cycleSum(sum, (uint16_t)len);
  // 首部+数据，**注意奇数字节时相当于往末尾填零**
  for (int i = 0; i < len; i += 2) {
    uint16_t tmp = ((uint16_t)packet[i] << 8);
    if (i + 1 < len) {
      tmp += packet[i + 1];
    }
    cycleSum(sum, tmp);
  }
  return sum ^ 0xFFFF;
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

uint32_t getMaskFromLen(uint32_t len) {
  // 从子网掩码长度生成小端序的子网掩码【注意此处为小端序，主要是便于计算】
  return (~((1 << (32 - len)) - 1));
}

uint32_t getNetworkSegment(in_addr_t addr, uint32_t len) {
  // 计算网络标识，注意为大端序
  uint32_t mask = getMaskFromLen(len);
  addr = convertBigSmallEndian32(addr) & mask;
  return convertBigSmallEndian32(addr);
}

bool isInSameNetworkSegment(in_addr_t addr1, in_addr_t addr2, uint32_t len) {
  // 判断两个 ip 地址（子网掩码由len确定）是否在同一网段
  // addr1和addr2为大端序，len为小端序
  addr1 = convertBigSmallEndian32(addr1);
  addr2 = convertBigSmallEndian32(addr2);
  uint32_t mask = getMaskFromLen(len);
  return (addr1 & mask) == (addr2 & mask);
}
