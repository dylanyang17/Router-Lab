#include "router.h"
#include <stdint.h>
#include <stdlib.h>
#include <vector>

std::vector<RoutingTableEntry> table;

/*
typedef struct {
  uint32_t addr; // 大端序，IPv4 地址
  uint32_t len; // 小端序，前缀长度
  uint32_t if_index; // 小端序，出端口编号
  uint32_t metric;   // 小端序
  uint64_t timestamp;// 小端序
  uint32_t nexthop; // 大端序，下一跳的 IPv4 地址
} RoutingTableEntry;
   约定 addr 和 nexthop 以 **大端序** 存储。
   这意味着 1.2.3.4 对应 0x04030201 而不是 0x01020304。
   保证 addr 仅最低 len 位可能出现非零。
   当 nexthop 为零时这是一条直连路由。
   你可以在全局变量中把路由表以一定的数据结构格式保存下来。

   注意 nexthop 可能为 0.0.0.0，这样可以保证不被更新，表示直连
 */

extern uint32_t convertBigSmallEndian32(uint32_t num);
extern uint32_t getMaskFromLen(uint32_t len);

int find(const RoutingTableEntry &entry) {
  // 找到 addr 和 len 同 entry 均相同的表项，返回其下标，未找到则返回 -1
  for (int i = 0; i < table.size(); ++i) {
    if (table[i].addr == entry.addr && table[i].len == entry.len)
      return i;
  }
  return -1;
}

/** 注意同之前 lookup oj 测试题中的实现不同
 * @brief 插入一条路由表表项，若 metric 为 16 则表示删除
 * @param entry 要插入/删除的表项
 * 
 * 如果不存在一条 addr 和 len 都相同(下称同一网段)的表项，
 * 则直接插入即可（metric需小于16）;
 * 如果有一条同网段的表项，则判断nexthop是否相同，相同则直接
 * 更新(metric==16表示删除)，不同则仅当新的 metric + 1 小于
 * 原 metric 时再进行更新
 *
 * 有实质更新则返回 true，否则返回 false
 */

bool update(RoutingTableEntry entry) {
  // NOTE: 注意这里对 entry 进行了子网掩码的与操作，以保证entry的addr的主机标识为0，即仅最低 len 位可能出现非零
  entry.addr &= convertBigSmallEndian32(getMaskFromLen(entry.len));
  int ind = find(entry);
  ++entry.metric;  // 在此处进行了加1
  if (ind != -1) {
    // 原表项中存在该网段
    if (table[ind].nexthop == entry.nexthop) {
      // 首先判断来源是否相同，相同则直接更新
      if (entry.metric >= 16) {
        // 删除表项
        table.erase(table.begin() + ind);
        return true;
      } else if (entry.metric != table[ind].metric){
        // 不删除，仅更新
        table[ind] = entry;
      } else {
        // 无实质变动，仅更新timestamp，并返回 false
        table[ind].timestamp = entry.timestamp;
        return false;
      }
    } else if (entry.metric < table[ind].metric) {
      // 否则若新 metric < 旧 metric
      table[ind] = entry;
      return true;
    } else {
      return false;
    }
  } else if (entry.metric < 16){
    // 原表项中不存在该网段且新metric<16
    // TODO
    table.push_back(entry);
    return true;
  } else {
    return false;
  }
}

bool match(const RoutingTableEntry &entry, uint32_t addr) {
  // 判断地址 addr 是否处在 entry 所表示的网段中（由entry.addr和entry.len确定网段）
  uint32_t addr2 = convertBigSmallEndian32(entry.addr);
  addr = convertBigSmallEndian32(addr);
  for (int i = 0; i < entry.len; ++i) {
    if ((addr & (1 << (31-i))) != (addr2 & (1 << (31-i))))
      return false;
  }
  return true;
}

/**
 * @brief 进行一次路由表的查询，按照最长前缀匹配原则
 * @param addr 需要查询的目标地址，大端序
 * @param nexthop 如果查询到目标，把表项的 nexthop 写入
 * @param if_index 如果查询到目标，把表项的 if_index 写入
 * @return 查到则返回 true ，没查到则返回 false
 */
bool query(uint32_t addr, uint32_t *nexthop, uint32_t *if_index) {
  int ind = -1;
  for (int i = 0; i < table.size(); ++i) {
    if (match(table[i], addr)) {
      if (ind == -1 || table[i].len > table[ind].len)
        ind = i;
    }
  }
  if (ind == -1)
    return false;
  *nexthop = table[ind].nexthop;
  *if_index = table[ind].if_index;
  return true;
}
