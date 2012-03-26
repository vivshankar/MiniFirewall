#ifndef __INC_MINIFIREWALL_DEF
#define __INC_MINIFIREWALL_DEF

// Error Codes
#define SUCCESS 0
#define E_FILEREAD_NOT_ALLOWED -1
#define E_FILEWRITE_NOT_ALLOWED -2

// Network Codes
#define PROTO_TCP 6
#define PROTO_UDP 17
#define PROTO_ICMP 1

struct NetAddr
{
  // 0 - All IP Address
  unsigned int m_iIP;
  // 0 - All Net Masks
  unsigned int m_iNetMask;
  // 0 - ALL
  unsigned int m_iPort;
};

struct FirewallRule
{
  int m_iID;
  // 0 - OUTPUT, 1 - INPUT
  int m_bInput;
  // 0 - ALL, 1 - TCP, 2 - UDP, 3 - ICMP
  int m_iProtocol;
  struct NetAddr m_srcAddr;
  struct NetAddr m_destAddr;
  // 0 - Allow, 1 - Block
  int m_bBlock;
  // 0 - Not deleted
  int m_bDeleted;
  struct FirewallRule* m_pNext;
  struct FirewallRule* m_pPrev;
};

void InitNetAddr(struct NetAddr* pAddr)
{
  //memset(pAddr->m_strIP, 0, 20);
  //memset(pAddr->m_strNetMask, 0, 20);
  pAddr->m_iIP = 0;
  pAddr->m_iNetMask = 0;
  pAddr->m_iPort = 0;
}

void InitFirewallRule(struct FirewallRule* pRule)
{
  pRule->m_bInput = 0;
  pRule->m_iProtocol = 0;
  pRule->m_bBlock = 0;
  pRule->m_pNext = 0;
  pRule->m_pPrev = 0;
  pRule->m_bDeleted = 0;
  
  InitNetAddr(&(pRule->m_srcAddr));
  InitNetAddr(&(pRule->m_destAddr));
}

#endif
