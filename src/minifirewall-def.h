#ifndef __INC_MINIFIREWALL_DEF
#define __INC_MINIFIREWALL_DEF

// Error Codes
#define SUCCESS 0
#define E_FILEREAD_NOT_ALLOWED -1
#define E_FILEWRITE_NOT_ALLOWED -2

struct NetAddr
{
  // NULL - All IP Address
  unsigned char m_strIP[20];
  // NULL - All Net Masks
  unsigned char m_strNetMask[20];
  // 0 - ALL
  long m_lPort;
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
  memset(pAddr->m_strIP, 0, 20);
  memset(pAddr->m_strNetMask, 0, 20);
  pAddr->m_lPort = 0;
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
