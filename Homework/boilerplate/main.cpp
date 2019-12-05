#include "router_hal.h"
#include "rip.h"
#include "router.h"
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#define RIP_MAX_ENTRY 25

extern bool validateIPChecksum(uint8_t *packet, size_t len);
extern bool update(RoutingTableEntry entry);
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
extern uint32_t getLenFromMask(uint32_t mask);
extern bool isInSameNetworkSegment(in_addr_t addr1, in_addr_t addr2, uint32_t len);

extern const int MAXN = 105;
extern RoutingTableEntry table[MAXN];
extern bool enabled[MAXN];

extern void printAddr(const in_addr_t &addr, FILE *file);
extern void printRouteEntry(const RoutingTableEntry &entry, FILE *file);
extern void printRouteTable(FILE *file);

uint8_t packet[2048];
uint8_t output[2048];
uint16_t ipTag;  // ip头中的16位标识
// 0: 10.0.0.1
// 1: 10.0.1.1
// 2: 10.0.2.1
// 3: 10.0.3.1
// 你可以按需进行修改，注意端序
// in_addr_t addrs[N_IFACE_ON_BOARD] = {0x0100000a, 0x0101000a, 0x0102000a, 0x0103000a};


// TODO: 记得更改正确的 IP 地址，以及对应的接口名称(在standard.h中修改)
// 0: 192.168.3.2
// 1: 192.168.4.1
// 2: 10.0.2.1
// 3: 10.0.3.1
in_addr_t addrs[N_IFACE_ON_BOARD] = {0x0203A8C0, 0x0104A8C0, 0x0102000a, 0x0103000a};
const in_addr_t multicastAddr = 0x090000E0;  // ripv2 的组播地址 224.0.0.9
macaddr_t multicastMac;

void sendRipPacketByHAL(const uint32_t &if_index, const RipPacket &rip, in_addr_t dstAddr, macaddr_t dstMac) {
  // 将 rip 封装 UDP 和 IP 头，并从索引为 if_index 的网络接口发送出去，发送的目的 ip 地址为dstAddr。注意 rip 报文封装之后长度不会超过以太网的 MTU
  // assemble
  // 为了获得 rip_len, 先填入 rip 部分:
  uint32_t rip_len = assemble(&rip, &output[20 + 8]);
  in_addr_t srcAddr = addrs[if_index];
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
  putFourByte(output + 12, srcAddr);
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
  cksum = calcUDPChecksum(output + 20, rip_len + 8, srcAddr, dstAddr);
  output[26] = (cksum >> 8) & 0xFF;
  output[27] = cksum & 0xFF;

  // RIP 在上面已经填过了
  // checksum calculation for ip and udp
  // if you don't want to calculate udp checksum, set it to zero
  // send it back
  HAL_SendIPPacket(if_index, output, rip_len + 20 + 8, dstMac);
}

void sendRipUpdate(const RipPacket &upd) {
  // 向各个网口发送 rip 更新报文，更新报文从 upd 计算得到
  // 注意计算时滤掉 addr 与出接口在同一网段的，并且对于
  // nexthop 与出接口在同一网段的，发送的 metric 设为 16（毒逆）
  // NOTE: 这样的毒逆默认了路由器不会在同一接口上进行转发
  // 也就是说默认同一网段可互达
  printf("sendRipUpdate\n");
  RipPacket resp;
  for (int i = 0; i < N_IFACE_ON_BOARD; ++i) {
    macaddr_t mac;
    resp.numEntries = 0;
    resp.command = 2;
    for (int j = 0; j < upd.numEntries; ++j) {
      // 毒性逆转
      uint32_t len = getLenFromMask(convertBigSmallEndian32(upd.entries[j].mask));
      if (!isInSameNetworkSegment(upd.entries[j].addr, addrs[i], len)) {
        uint32_t id = resp.numEntries++;
        resp.entries[id] = upd.entries[j];
        if (isInSameNetworkSegment(resp.entries[id].nexthop, addrs[i], len)) {
          resp.entries[id].metric = convertBigSmallEndian32(16);
        }
      }
    }
    if (resp.numEntries) {
      sendRipPacketByHAL(i, resp, multicastAddr, multicastMac);
    }
  }
}

int main(int argc, char *argv[]) {
  freopen("nul", "w", stdout);
  srand(time(NULL));
  ipTag = (uint32_t)rand();
  int res = HAL_Init(1, addrs);
  int messageId = 0;  // for debug
  if (res < 0) {
    return res;
  }
  HAL_ArpGetMacAddress(0, multicastAddr, multicastMac); // 组播 ip 对应的组播 mac 地址，一定存在

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
    update(entry);
  }

  uint64_t last_time = 0;
  while (1) {
    uint64_t time = HAL_GetTicks();
    if (time > last_time + 5 * 1000) {
      // 例行更新
      RipPacket upd;
      upd.command = 2;
      upd.numEntries = 0;
      for (int i = 0; i < MAXN; ++i) {
        if (enabled[i]) {
          uint32_t id = upd.numEntries++;
          upd.entries[id].addr = table[i].addr;
          upd.entries[id].mask = convertBigSmallEndian32(getMaskFromLen(table[i].len));
          upd.entries[id].nexthop = 0;
          upd.entries[id].metric = convertBigSmallEndian32(table[i].metric);
          if (upd.numEntries == RIP_MAX_ENTRY) {
            sendRipUpdate(upd);
            upd.numEntries = 0;
          }
        }
      }
      if (upd.numEntries) {
        sendRipUpdate(upd);
      }
      last_time = time;
      printf("Timer Fired: Update\n");
      printRouteTable(stderr);
    }

    int mask = (1 << N_IFACE_ON_BOARD) - 1;
    macaddr_t srcMac;
    macaddr_t dstMac;
    int if_index;
    res = HAL_ReceiveIPPacket(mask, packet, sizeof(packet), srcMac,
        dstMac, 1000, &if_index);
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
    ++messageId;
    printf("%d:: Valid Message. res: %d\n", messageId, res);

    if (!validateIPChecksum(packet, res)) {
      printf("%d:: Invalid IP Checksum\n", messageId);
      continue;
    }
    in_addr_t srcAddr, dstAddr;
    // extract srcAddr and dstAddr from packet
    // big endian
    srcAddr = getFourByte(packet + 12);
    dstAddr = getFourByte(packet + 16);

    bool dst_is_me = false;
    for (int i = 0; i < N_IFACE_ON_BOARD;i++) {
      if (memcmp(&dstAddr, &addrs[i], sizeof(in_addr_t)) == 0) {
        dst_is_me = true;
        break;
      }
    }
    bool isMulti = (dstAddr == multicastAddr);
    if (isMulti || dst_is_me) {  
      // 224.0.0.9 or me，进行接收处理
      printf("%d:: Dst is me or multicast.\n", messageId);
      RipPacket rip;
      if (disassemble(packet, res, &rip)) {
        // 为 rip 数据报
        if (rip.command == 1) {
          // request
          // 请求报文必须满足 metric 为 16，注意 metric 为大端序
          // 注意若表项数目大于 25，则需要分开发送
          printf("%d:: Received rip request.\n", messageId);
          uint32_t metricSmall = convertBigSmallEndian32(rip.entries[0].metric);
          if (metricSmall != 16) continue;
          RipPacket resp;
          // 封装响应报文，注意选择路由条目
          resp.command = 2;  // response
          resp.numEntries = 0;
          for (int j = 0; j < MAXN; ++j) {
            if (enabled[j] && !isInSameNetworkSegment(table[j].addr, srcAddr, table[j].len)) {
              // 与来源ip的网段不同
              uint32_t id = resp.numEntries++;
              resp.entries[id].addr = table[j].addr;
              resp.entries[id].mask = convertBigSmallEndian32(getMaskFromLen(table[j].len));
              resp.entries[id].nexthop = 0;
              resp.entries[id].metric = convertBigSmallEndian32(table[j].metric);
              if (table[j].nexthop == srcAddr) {
                // 毒性逆转
                resp.entries[id].metric = 16;
              }
              if (resp.numEntries == RIP_MAX_ENTRY) {
                // 满 25 条，进行一次发送
                sendRipPacketByHAL(if_index, resp, srcAddr, srcMac);
                resp.numEntries = 0;
              }
            }
          }
          if (resp.numEntries) {
            sendRipPacketByHAL(if_index, resp, srcAddr, srcMac);
          }
        } else {
          // response
          printf("%d:: Received rip response.\n", messageId);
          RipPacket upd;
          upd.numEntries = 0;
          upd.command = 2;
          for (int i = 0; i < rip.numEntries; ++i) {
            RoutingTableEntry entry;
            entry.addr = rip.entries[i].addr;
            entry.len  = getLenFromMask(convertBigSmallEndian32(rip.entries[i].mask));
            entry.if_index = if_index;
            entry.metric = convertBigSmallEndian32(rip.entries[i].metric);
            entry.nexthop = srcAddr;
            bool suc = update(entry);
            if (suc) {
              // 若更新路由表成功，触发更新
              printf("%d:: Update router successfully.", messageId);
              printRouteEntry(entry, stdout);
              uint32_t id = upd.numEntries++;
              upd.entries[id] = rip.entries[i];
              upd.entries[id].nexthop = 0;
              upd.entries[id].metric = convertBigSmallEndian32(entry.metric);
            }
          }
          if (upd.numEntries) {
            sendRipUpdate(upd);
          }
        }
      } else {
        // Target is me but not rip.
      }
    } else {
      // forward
      // beware of endianness
      printf("%d:: Forward.\n", messageId);
      uint32_t nexthop, dest_if;
      if (query(dstAddr, &nexthop, &dest_if)) {
        // found
        macaddr_t dest_mac;
        // direct routing
        if (nexthop == 0) {
          nexthop = dstAddr;
        }
        if (HAL_ArpGetMacAddress(dest_if, nexthop, dest_mac) == 0) {
          // found
          memcpy(output, packet, res);
          // update ttl and checksum
          forward(output, res);
          // check ttl!=0
          if (output[8] != 0) {
            HAL_SendIPPacket(dest_if, output, res, dest_mac);
            printf("%d:: Forward successfully. dest_if: %d  Nexthop:", messageId, dest_if);
            printAddr(nexthop, stdout);
            printf("\n");
          } else {
            // ttl == 0
            printf("%d:: TTL is 0.\n", messageId);
          }
        } else {
          // not found
          printf("%d:: Failed to get mac address. dest_if: %d Nexthop:", messageId, dest_if);
          printAddr(nexthop, stdout);
          printf("\n");
        }
      } else {
        // not found
        printf("%d:: No matching item in table.\n", messageId);
      }
    }
  }
  return 0;
}
