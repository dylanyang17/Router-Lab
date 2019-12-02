#include <stdint.h>
#include <stdlib.h>
/* 删除重复代码
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
*/
/**
 * @brief 进行转发时所需的 IP 头的更新：
 *        你需要先检查 IP 头校验和的正确性，如果不正确，直接返回 false ；
 *        如果正确，请更新 TTL 和 IP 头校验和，并返回 true 。
 *        你可以从 checksum 题中复制代码到这里使用。
 * @param packet 收到的 IP 包，既是输入也是输出，原地更改
 * @param len 即 packet 的长度，单位为字节
 * @return 校验和无误则返回 true ，有误则返回 false
 */

extern uint16_t calcIPChecksum(uint8_t *packet, size_t len);
extern bool validateIPChecksum(uint8_t *packet, size_t len);

bool forward(uint8_t *packet, size_t len) {
  // TODO:
  if (validateIPChecksum(packet, len) == false)
    return false;
  packet[8]--;
  uint16_t checksum = calcIPChecksum(packet, len);
  packet[10] = checksum >> 8;
  packet[11] = checksum & 0xFF;
  return true;
}
