#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include "router_hal.h"
#include "router.h"
#define MAXN 105

void cycleSum(uint32_t &sum, const uint16_t &num) {
  // 循环求和，用于求校验和
  sum += num;
  sum = (sum >> 16) + (sum & 0xFFFF);
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
