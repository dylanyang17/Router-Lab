#include "rip.h"
#include <stdint.h>
#include <stdlib.h>

/*
  在头文件 rip.h 中定义了如下的结构体：
  #define RIP_MAX_ENTRY 25
  typedef struct {
    // all fields are big endian
    // we don't store 'family', as it is always 2(response) and 0(request)
    // we don't store 'tag', as it is always 0
    uint32_t addr;
    uint32_t mask;
    uint32_t nexthop;
    uint32_t metric;
  } RipEntry;

  typedef struct {
    uint32_t numEntries;
    // all fields below are big endian
    uint8_t command; // 1 for request, 2 for response, otherwsie invalid
    // we don't store 'version', as it is always 2
    // we don't store 'zero', as it is always 0
    RipEntry entries[RIP_MAX_ENTRY];
  } RipPacket;

  你需要从 IPv4 包中解析出 RipPacket 结构体，也要从 RipPacket 结构体构造出对应的 IP 包
  由于 Rip 包结构本身不记录表项的个数，需要从 IP 头的长度中推断，所以在 RipPacket 中额外记录了个数。
  需要注意这里的地址都是用 **大端序** 存储的，1.2.3.4 对应 0x04030201 。
*/

uint32_t getFourByte(uint8_t *packet) {
  return (packet[0] << 24) |
      (packet[1] << 16) |
      (packet[2] << 8) |
      (packet[3] << 0);
}

uint32_t convertBigSmallEndian(uint32_t num) {
  uint32_t ret = 0;
  return (((num >> 0) & 0xFF) << 24) |
      (((num >> 8) & 0xFF) << 16) |
      (((num >> 16)& 0xFF) << 8) |
      (((num >> 24)& 0xFF) << 0);
}

bool checkMask(uint32_t mask) {
  mask = convertBigSmallEndian(mask);
  int i;
  for (i = 31; i >= 0; --i) {
    if(((mask >> i) & 1) == 0) break;
  }
  return (i == -1 || (mask & ((1 << i) - 1)) == 0);
}

bool getRipEntry(uint8_t *packet, RipEntry *entry) {
  if (packet[0] != 1 && packet[0] != 2)
    // Command
    return false;
  if (packet[1] != 2)
    // Version
    return false;
  if (packet[2] != 0 || packet[3] != 0)
    // Zero
    return false;
  uint16_t family = ((uint16_t)packet[4] << 8) + packet[5];
  if ((packet[0] == 1 && family != 0) || (packet[0] == 2 && family != 2))
    // Family
    return false;
  if (packet[6] != 0 || packet[7] != 0)
    // Tag
    return false;
  entry->addr = getFourByte(packet + 8);
  entry->mask = getFourByte(packet + 12);
  entry->nexthop = getFourByte(packet + 16);
  entry->metric = getFourByte(packet + 20);
  uint32_t tmp = convertBigSmallEndian(entry->metric);
  if (tmp < 1 || tmp > 16)
    // Metric
    return false;
  if (!checkMask(entry->mask))
    // Mask
    return false;
  return true;
}

/**
 * @brief 从接受到的 IP 包解析出 Rip 协议的数据
 * @param packet 接受到的 IP 包
 * @param len 即 packet 的长度
 * @param output 把解析结果写入 *output
 * @return 如果输入是一个合法的 RIP 包，把它的内容写入 RipPacket 并且返回 true；否则返回 false
 * 
 * IP 包的 Total Length 长度可能和 len 不同，当 Total Length 大于 len 时，把传入的 IP 包视为不合法。
 * 你不需要校验 IP 头和 UDP 的校验和是否合法。
 * 你需要检查 Command 是否为 1 或 2，Version 是否为 2， Zero 是否为 0，
 * Family 和 Command 是否有正确的对应关系，Tag 是否为 0，
 * Metric 转换成小端序后是否在 [1,16] 的区间内，
 * Mask 的二进制是不是连续的 1 与连续的 0 组成等等。
 */
bool disassemble(const uint8_t *packet, uint32_t len, RipPacket *output) {
  // TODO:

}

/**
 * @brief 从 RipPacket 的数据结构构造出 RIP 协议的二进制格式
 * @param rip 一个 RipPacket 结构体
 * @param buffer 一个足够大的缓冲区，你要把 RIP 协议的数据写进去
 * @return 写入 buffer 的数据长度
 * 
 * 在构造二进制格式的时候，你需要把 RipPacket 中没有保存的一些固定值补充上，包括 Version、Zero、Address Family 和 Route Tag 这四个字段
 * 你写入 buffer 的数据长度和返回值都应该是四个字节的 RIP 头，加上每项 20 字节。
 * 需要注意一些没有保存在 RipPacket 结构体内的数据的填写。
 */
uint32_t assemble(const RipPacket *rip, uint8_t *buffer) {
  // TODO:
  return 0;
}
