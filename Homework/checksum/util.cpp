#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include "router_hal.h"
#define MAXN 105

uint32_t convertBigSmallEndian32(uint32_t num) {
  return (((num >> 0) & 0xFF) << 24) |
    (((num >> 8) & 0xFF) << 16) |
    (((num >> 16)& 0xFF) << 8) |
    (((num >> 24)& 0xFF) << 0);
}

inline void cycleSum(uint32_t &sum, const uint16_t &num) {
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
