// 计算udp校验和的C++代码，校验和由 calcUDPChecksum.in 存储

#include <iostream>
#include <cstdio>
#include <cstring>
#include <cstdint>

typedef uint32_t in_addr_t;

void cycleSum(uint32_t &sum, uint16_t num) {
  // 循环求和，用于求校验和
  while(num) {
    sum += num;
    num = sum >> 16;
    sum = sum & 0xFFFF;
  }
}

uint16_t calcUDPChecksum(uint8_t *packet, size_t len, in_addr_t srcAddr, in_addr_t dstAddr) {
  // 计算 packet 的 udp 首部校验和（packet起始便为UDP头），len 为 UDP 包长度
  // 源ip和目的ip分别为srcAddr和dstAddr，目的是作为伪首部计算校验和
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
    if (i==6) continue;
    uint16_t tmp = ((uint16_t)packet[i] << 8);
    if (i + 1 < len) {
      tmp += packet[i + 1];
    }
    cycleSum(sum, tmp);
  }
  return sum ^ 0xFFFF;
}

const int MAXN = 3005;
char s[MAXN];
uint8_t pack[MAXN];
uint32_t sum;

uint32_t getHexCharValue(char c) {
  if (c >= '0' && c <= '9') return c - '0';
  else if (c >= 'a' && c <= 'f') return c - 'a' + 10;
  else return c - 'A' + 10;
}

int main() {
  // TODO 注意只处理了偶数字节的情况
  freopen("calcUdpChecksum.in", "r", stdin);
  scanf("%s", s);
  int slen = strlen(s);
  uint32_t len = 0;
  for(int i = 0; i < slen; i += 2) {
    pack[len++] = (getHexCharValue(s[i]) << 4) + getHexCharValue(s[i+1]);
  }
  // in_addr_t srcAddr = 0x0203A8C0;
  // in_addr_t dstAddr = 0x0900A8C0; // TODO 记得更改
  in_addr_t srcAddr = 0xC0A80302;
  in_addr_t dstAddr = 0xE0000009;
  uint16_t sum = calcUDPChecksum(pack, len, srcAddr, dstAddr);
  printf("%04x\n", sum);
  return 0;
}
