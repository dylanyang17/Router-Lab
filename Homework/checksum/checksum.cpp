#include <stdint.h>
#include <iostream>
#include <cstdio>
#include <stdlib.h>
using namespace std;

/**
 * @brief 进行 IP 头的校验和的验证
 * @param packet 完整的 IP 头和载荷
 * @param len 即 packet 的长度，单位是字节，保证包含完整的 IP 头
 * @return 校验和无误则返回 true ，有误则返回 false
 */
uint16_t calcIPChecksum(uint8_t *packet, size_t len) {
  size_t headLen = (size_t)(packet[0] & 0xF) * 4;
  uint32_t sum = 0;       // 计算得到的校验和
  for (int i = 0; i < headLen; i += 2) {
    if (i==10) continue;
    uint16_t tmp = ((uint16_t)packet[i] << 8) + packet[i + 1];
    while(tmp) {
      sum += tmp;
      tmp = sum >> 16;
      sum = sum & 0xFFFF;
    }
  }
  return sum ^ 0xFFFF ;
}

bool validateIPChecksum(uint8_t *packet, size_t len) {
  uint16_t sum = calcIPChecksum(packet, len);       // 计算得到的校验和
  uint16_t pracsum = ((uint16_t)packet[10] << 8) + packet[11];
  return sum == pracsum;
}
