#include <stdint.h>
#include <stdlib.h>
/**
 * @brief 进行转发时所需的 IP 头的更新：
 *        保证原本的校验和正确（在接收到时便进行过判断）
 *        需要更新 TTL 和 IP 头校验和
 * @param packet 收到的 IP 包，既是输入也是输出，原地更改
 * @param len 即 packet 的长度，单位为字节
 */

extern uint16_t calcIPChecksum(uint8_t *packet, size_t len);
extern bool validateIPChecksum(uint8_t *packet, size_t len);

void forward(uint8_t *packet, size_t len) {
  // 增量更新
  uint32_t m1 = (packet[8] << 8) + packet[9], m2 = ((packet[8] - 1) << 8) + packet[9], HC = (packet[10] << 8) + packet[11];
  HC = HC + m1;
  HC = (HC & 0xFFFF) + (HC >> 16);
  HC = HC + (m2 ^ 0xFFFF);
  HC = (HC & 0xFFFF) + (HC >> 16);
  if (HC == 0xFFFF) {
    HC = 0;
  }
  packet[8]--;
  packet[10] = HC >> 8;
  packet[11] = HC & 0xFF;
}
