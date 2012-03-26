#include <stdio.h>
#include "minifirewall-def.h"

unsigned char* addr_to_string(unsigned int addr)
{
  unsigned char* pStrAddr = (unsigned char*) malloc(20);
  memset(pStrAddr, 0, 20);
  sprintf(pStrAddr, "%3d.%3d.%3d.%3d", addr & 0x000000FF, (addr & 0x0000FF00) >> 8, (addr & 0x00FF0000) >> 16, (addr & 0xFF000000) >> 24);
  
  return pStrAddr;
}

unsigned int string_to_addr(unsigned char* pStrAddr)
{
  unsigned int byte1, byte2, byte3, byte4;
  if (pStrAddr == NULL)
    return;

  sscanf(pStrAddr, "%d.%d.%d.%d", &byte4, &byte3, &byte2, &byte1);
  return ((byte1 << 24) | (byte2 << 16) | (byte3 << 8) | byte4);
}

int WriteRule(const struct FirewallRule* pRule)
{
  int numWritten = 0;

  FILE *wFile = fopen("/proc/minifirewall", "w");
  if (wFile == NULL)
  {
    printf("error: File /proc/minifirewall could not be opened for writing");
    return E_FILEWRITE_NOT_ALLOWED;
  }

  numWritten = fwrite((unsigned char*) pRule, 1, sizeof(struct FirewallRule), wFile);
  if (numWritten == 0) 
  {
    printf("The rule could not be written");
    return 0;
  }

  fclose(wFile);

  return 1;
}

void PrintAll() 
{
  int numRead = 0;
  FILE *rFile = fopen("/proc/minifirewall", "rw");
  struct FirewallRule* pRule = NULL;

  if (rFile == NULL) {
    printf("error: File /proc/minifirewall could not be opened for reading");
    return;
  }

  printf("ID\tProtocol\tIN/OUTPUT\tSource IP\tNet Mask\tSource Port\tDest. IP\tNet Mask\tDest. Port\tAction\n");
  printf("\n");
  
  do {
    if (pRule != NULL) {
      free(pRule);
    }

    pRule = (struct FirewallRule*) malloc(sizeof(struct FirewallRule));
    if (pRule == NULL) {
      printf("The rule is NULL\n");
      return;
    }
    
    InitFirewallRule(pRule);
    rewind(rFile); // to ensure offsets don't create problems in getting the next rule
    fflush(rFile);
    numRead = fread(pRule, sizeof(struct FirewallRule), 1, rFile);

    if (numRead == 1) {
      printf("%d\t", pRule->m_iID);
      if (pRule->m_iProtocol == 0) {
	printf("%s\t\t", "ALL");
      } else if (pRule->m_iProtocol == PROTO_TCP) {
	printf("%s\t\t", "TCP");
      } else if (pRule->m_iProtocol == PROTO_UDP) {
	printf("%s\t\t", "UDP");
      } else if (pRule->m_iProtocol == PROTO_ICMP) {
	printf("%s\t\t", "ICMP");
      } else {
        printf("%s\t\t", "UNKNOWN");
      }

      printf("%s\t", ((pRule->m_bInput == 0) ? "OUTPUT" : "INPUT"));
      
      printf("%s\t  %s\t\t%d\t", addr_to_string(pRule->m_srcAddr.m_iIP), 
	     addr_to_string(pRule->m_srcAddr.m_iNetMask),
	     pRule->m_srcAddr.m_iPort);

      printf("%s\t  %s\t\t%d\t", addr_to_string(pRule->m_destAddr.m_iIP), 
	     addr_to_string(pRule->m_destAddr.m_iNetMask),
	     pRule->m_destAddr.m_iPort);
      printf("%s\n", ((pRule->m_bBlock == 0) ? "UNBLOCK" : "BLOCK"));
    }
  } while(pRule != NULL && pRule->m_pNext != NULL);

  if (pRule != NULL) {
    free(pRule);
  }

  fclose(rFile);

  return;
}

int main(int argc, char** argv)
{
  struct FirewallRule* pRule = (struct FirewallRule*) malloc(sizeof(struct FirewallRule));
  int index = 1;
  
  InitFirewallRule(pRule);

  for (index = 1; index < argc; ++index)
  {
    char* arg = argv[index];
    printf("%s\n", arg);
    if (strcmp(arg, "--in") == 0) {
      pRule->m_bInput = 1;
      continue;
    } else if (strcmp(arg, "--out") == 0) {
      pRule->m_bInput = 0;
      continue;
    } else if (strcmp(arg, "--proto") == 0) {
      char* argval = argv[++index];
      
      if (strcmp(argval, "ALL") == 0) {
	pRule->m_iProtocol = 0;
	continue;
      } else if (strcmp(argval, "TCP") == 0) {
	pRule->m_iProtocol = PROTO_TCP;
	continue;
      } else if (strcmp(argval, "UDP") == 0) {
	pRule->m_iProtocol = PROTO_UDP;
	continue;
      } else if (strcmp(argval, "ICMP") == 0) {
	pRule->m_iProtocol = PROTO_ICMP;
	continue;
      } else {
	printf("ERROR: --proto must be followed by TCP, UDP, ICMP or ALL\n");
	return -1;
      }
    } else if (strcmp(arg, "--srcip") == 0) {
      char* argval = argv[++index];
      pRule->m_srcAddr.m_iIP = string_to_addr(argval);
      //memcpy(pRule->m_srcAddr.m_strIP, argval, strlen(argval) + 1);
      continue;
    } else if (strcmp(arg, "--srcport") == 0) {
      char* argval = argv[++index];
      sscanf(argval, "%d", &(pRule->m_srcAddr.m_iPort));
      continue;
    } else if (strcmp(arg, "--srcnetmask") == 0) {
      char* argval = argv[++index];
      pRule->m_srcAddr.m_iNetMask = string_to_addr(argval);
      //memcpy(pRule->m_srcAddr.m_strNetMask, argval, strlen(argval) + 1);
      continue;
    } else if (strcmp(arg, "--destip") == 0) {
      char* argval = argv[++index];
      pRule->m_destAddr.m_iIP = string_to_addr(argval);
      //memcpy(pRule->m_destAddr.m_strIP, argval, strlen(argval) + 1);
      continue;
    } else if (strcmp(arg, "--destport") == 0) {
      char* argval = argv[++index];
      sscanf(argval, "%d", &(pRule->m_destAddr.m_iPort));
      continue;
    } else if (strcmp(arg, "--destnetmask") == 0) {
      char* argval = argv[++index];
      pRule->m_destAddr.m_iNetMask = string_to_addr(argval);
      //memcpy(pRule->m_destAddr.m_strNetMask, argval, strlen(argval) + 1);
      //pRule->m_destAddr.m_strNetMask = argval;
      continue;
    } else if (strcmp(arg, "--action") == 0) {
      char* argval = argv[++index];
      pRule->m_bBlock = ((strcmp(argval, "BLOCK") == 0) ? 1 : 0);
    } else if (strcmp(arg, "--print") == 0) {
      PrintAll();
      if (pRule != NULL)
	free(pRule);
      return 0;
    } else if (strcmp(arg, "--delete") == 0) {
      char *argval = argv[++index];
      sscanf(argval, "%d", &(pRule->m_iID));
      //pRule->m_iID = (int) argval;
      pRule->m_bDeleted = 1;
    }
  }

  WriteRule(pRule);
  free(pRule);

  return 0;
}
