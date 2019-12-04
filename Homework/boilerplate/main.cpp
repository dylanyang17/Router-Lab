#include "router_hal.h"
#include "rip.h"
#include "router.h"
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <time.h>

extern bool validateIPChecksum(uint8_t *packet, size_t len);
extern void update(bool insert, RoutingTableEntry entry);
extern bool query(uint32_t addr, uint32_t *nexthop, uint32_t *if_index);
extern bool forward(uint8_t *packet, size_t len);
extern bool disassemble(const uint8_t *packet, uint32_t len, RipPacket *output);
extern uint32_t assemble(const RipPacket *rip, uint8_t *buffer);
extern uint32_t getFourByte(uint8_t *packet);
extern void putFourByte(uint8_t *packet, uint32_t num);
extern uint32_t convertBigSmallEndian32(uint32_t num);
extern uint16_t calcIPChecksum(uint8_t *packet, size_t len);
extern uint16_t calcUDPChecksum(uint8_t *packet, size_t len, in_addr_t srcAddr, in_addr_t dstAddr);

extern uint32_t getMaskFromLen(uint32_t len);
extern bool isInSameNetworkSegment(in_addr_t addr1, in_addr_t addr2, uint32_t len);

extern const int MAXN = 105;
extern RoutingTableEntry table[MAXN];
extern bool enabled[MAXN];

uint8_t packet[2048];
uint8_t output[2048];
uint16_t ipTag;  // ip头中的16位标识
// 0: 10.0.0.1
// 1: 10.0.1.1
// 2: 10.0.2.1
// 3: 10.0.3.1
// 你可以按需进行修改，注意端序
in_addr_t addrs[N_IFACE_ON_BOARD] = {0x0100000a, 0x0101000a, 0x0102000a, 0x0103000a};
const in_addr_t multicastAddr = 0x090000E0;  // ripv2 的组播地址 224.0.0.9

void sendRipPacket(const uint32_t &if_index, const RipPacket &rip, in_addr_t dstAddr) {
  // 将 rip 封装 UDP 和 IP 头，并从索引为 if_index 的网络接口发送出去，发送的目的 ip 地址为dstAddr。注意 rip 报文封装之后长度不会超过以太网的 MTU
  // assemble
  // 为了获得 rip_len, 先填入 rip 部分:
  uint32_t rip_len = assemble(&rip, &output[20 + 8]);
  // IP
  ++ipTag;
  output[0]  = 0x45;
  output[1]  = 0xC0; // 此处设置为同抓包得到的相同，表示网间控制的一般服务
  output[2]  = ((rip_len + 20 + 8) >> 8) & 0xFF;
  output[3]  = (rip_len + 20 + 8) & 0xFF;
  output[4]  = (ipTag >> 8) & 0xFF;  // IP 长度
  output[5]  = ipTag & 0xFF;
  output[6]  = 0x00;   // 不用考虑分片
  output[7]  = 0x00;
  output[8]  = 0x01;   // TTL为1，因为只向邻居发送rip报文
  output[9]  = 0x11;   // 表示携带UDP协议
  output[10] = 0x00;
  output[11] = 0x00;   // 头部校验和留至填充头部完毕之后计算
  putFourByte(output + 12, addr[if_index]);
  putFourByte(output + 16, dstAddr);
  uint16_t cksum = calcIPChecksum(output, rip_len + 20 + 8);  // IP 头部校验和
  output[10] = (cksum >> 8) & 0xFF;
  output[11] = cksum & 0xFF;

  // UDP
  // port = 520
  output[20] = 0x02;
  output[21] = 0x08;   // 源端口为 520
  output[22] = 0x02;
  output[23] = 0x08;   // 目的端口为 520
  output[24] = ((rip_len + 8) >> 8) & 0xFF;
  output[25] = (rip_len + 8) & 0xFF;  // UDP长度
  output[26] = 0x00;
  output[27] = 0x00;   // 待会计算校验和
  cksum = calcUDPChecksum(output + 20, rip_len + 8);
  output[26] = (cksum >> 8) & 0xFF;
  output[27] = cksum & 0xFF;

  // RIP 在上面已经填过了
  // checksum calculation for ip and udp
  // if you don't want to calculate udp checksum, set it to zero
  // send it back
  HAL_SendIPPacket(if_index, output, rip_len + 20 + 8, src_mac);
}

int main(int argc, char *argv[]) {
  srand(time(NULL));
  ipTag = (uint32_t)rand();
  int res = HAL_Init(1, addrs);
  if (res < 0) {
    return res;
  }

  // Add direct routes
  // For example:
  // 10.0.0.0/24 if 0
  // 10.0.1.0/24 if 1
  // 10.0.2.0/24 if 2
  // 10.0.3.0/24 if 3
  for (uint32_t i = 0; i < N_IFACE_ON_BOARD;i++) {
    RoutingTableEntry entry = {
      .addr = addrs[i], // big endian
      .len = 24, // small endian
      .if_index = i, // small endian
      .metric = 1,  // small endian
      .nexthop = 0 // big endian, means direct
    };
    update(true, entry);
  }

  uint64_t last_time = 0;
  while (1) {
    uint64_t time = HAL_GetTicks();
    if (time > last_time + 30 * 1000) {
      // What to do?
      // TODO 例行更新 进行查询？
      last_time = time;
      printf("Timer\n");
    }

    int mask = (1 << N_IFACE_ON_BOARD) - 1;
    macaddr_t src_mac;
    macaddr_t dst_mac;
    int if_index;
    res = HAL_ReceiveIPPacket(mask, packet, sizeof(packet), src_mac,
        dst_mac, 1000, &if_index);
    if (res == HAL_ERR_EOF) {
      break;
    } else if (res < 0) {
      return res;
    } else if (res == 0) {
      // Timeout
      continue;
    } else if (res > sizeof(packet)) {
      // packet is truncated, ignore it
      continue;
    }

    if (!validateIPChecksum(packet, res)) {
      printf("Invalid IP Checksum\n");
      continue;
    }
    in_addr_t src_addr, dst_addr;
    // extract src_addr and dst_addr from packet
    // big endian
    src_addr = getFourByte(packet + 12);
    dst_addr = getFourByte(packet + 16);

    bool dst_is_me = false;
    for (int i = 0; i < N_IFACE_ON_BOARD;i++) {
      if (memcmp(&dst_addr, &addrs[i], sizeof(in_addr_t)) == 0) {
        dst_is_me = true;
        break;
      }
    }
    // TODO: Handle rip multicast address?
    bool isMulti = (dst_addr == multicastAddr);
    if (isMulti || dst_is_me) {  // 224.0.0.9 or me
      // TODO: RIP?
      RipPacket rip;
      if (disassemble(packet, res, &rip)) {
        for (int i = 0; i < rip.numEntries; ++i) {
          // 注意可能有多组 rip 条目
          if (rip.command == 1) {
            // request
            // 请求报文必须满足 metric 为 16，注意 metric 为大端序
            uint32_t metricSmall = convertBigSmallEndian32(rip.entries[i].metric);
            if (metricSmall != 16) continue;
            // TODO TODO 注意若表项数目大于 25，则需要分开发送
            RipPacket resp;
            // TODO 封装响应报文，注意选择路由条目
            resp.command = 2;  // response
            for (int i = 0; i < MAXN; ++i) {
              if (enabled[i] && !isInSameNetworkSegment(table[i].addr, src_addr, table[i].len)) {
                // 与来源ip的网段不同
                uint32_t id = resp.numEntries++;
                resp.entries[id].addr = table[i].addr;
                resp.entries[id].mask = convertBigSmallEndian32(getMaskFromLen(table[i].len));
                resp.entries[id].nexthop = table[i].nexthop;
                resp.entries[id].metric = convertBigSmallEndian32(table[i].metric);
              }
            }
            sendRipPacket(if_index, resp);
          } else {
            // response
            // TODO: use query and update
          }
        }
      } else {
        // forward
        // beware of endianness
        uint32_t nexthop, dest_if;
        if (query(src_addr, &nexthop, &dest_if)) {
          // found
          macaddr_t dest_mac;
          // direct routing
          if (nexthop == 0) {
            nexthop = dst_addr;
          }
          if (HAL_ArpGetMacAddress(dest_if, nexthop, dest_mac) == 0) {
            // found
            memcpy(output, packet, res);
            // update ttl and checksum
            forward(output, res);
            // TODO: you might want to check ttl=0 case
            HAL_SendIPPacket(dest_if, output, res, dest_mac);
          } else {
            // not found
          }
        } else {
          // not found
        }
      }
    }
  }
  return 0;
}
