#include <stdio.h>
#include "minifirewall-def.h"

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

  printf("ID\tProtocol\tI/O\tSource IP\tNet Mask\tSource Port\tDest. IP\tNet Mask\tDest. Port\tAction\n");
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
    
    if (numRead == /*sizeof(struct FirewallRule)*/1) {
      printf("%d\t", pRule->m_iID);
      if (pRule->m_iProtocol == 0) {
	printf("%s\t\t", "ALL");
      } else if (pRule->m_iProtocol == 1) {
	printf("%s\t\t", "TCP");
      } else if (pRule->m_iProtocol == 2) {
	printf("%s\t\t", "UDP");
      } else if (pRule->m_iProtocol == 3) {
	printf("%s\t\t", "ICMP");
      } else {
        printf("%s\t\t", "UNKNOWN");
      }

      printf("%s\t", ((pRule->m_bInput == 0) ? "OUTPUT" : "INPUT"));

      printf("%s\t%s\t%d\t", ((strcmp(pRule->m_srcAddr.m_strIP, "") == 0) ? "---------------" : pRule->m_srcAddr.m_strIP), 
	     ((strcmp(pRule->m_srcAddr.m_strNetMask, "") == 0) ? "----------------" : pRule->m_srcAddr.m_strNetMask),
	     pRule->m_srcAddr.m_lPort);

      printf("%s\t%s\t%d\t", ((strcmp(pRule->m_destAddr.m_strIP, "") == 0) ? "----------------" : pRule->m_destAddr.m_strIP), 
	     ((strcmp(pRule->m_destAddr.m_strNetMask, "") == 0) ? "----------------" : pRule->m_destAddr.m_strNetMask),
	     pRule->m_destAddr.m_lPort);
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
	pRule->m_iProtocol = 1;
	continue;
      } else if (strcmp(argval, "UDP") == 0) {
	pRule->m_iProtocol = 2;
	continue;
      } else if (strcmp(argval, "ICMP") == 0) {
	pRule->m_iProtocol = 3;
	continue;
      } else {
	printf("ERROR: --proto must be followed by TCP, UDP, ICMP or ALL\n");
	return -1;
      }
    } else if (strcmp(arg, "--srcip") == 0) {
      char* argval = argv[++index];
      memcpy(pRule->m_srcAddr.m_strIP, argval, strlen(argval) + 1);
      continue;
    } else if (strcmp(arg, "--srcport") == 0) {
      char* argval = argv[++index];
      sscanf(argval, "%ld", &(pRule->m_srcAddr.m_lPort));
      continue;
    } else if (strcmp(arg, "--srcnetmask") == 0) {
      char* argval = argv[++index];
      memcpy(pRule->m_srcAddr.m_strNetMask, argval, strlen(argval) + 1);
      continue;
    } else if (strcmp(arg, "--destip") == 0) {
      char* argval = argv[++index];
      memcpy(pRule->m_destAddr.m_strIP, argval, strlen(argval) + 1);
      //pRule->m_destAddr.m_strIP = argval;
      continue;
    } else if (strcmp(arg, "--destport") == 0) {
      char* argval = argv[++index];
      sscanf(argval, "%ld", &(pRule->m_destAddr.m_lPort));
      
      continue;
    } else if (strcmp(arg, "--destnetmask") == 0) {
      char* argval = argv[++index];
      memcpy(pRule->m_destAddr.m_strNetMask, argval, strlen(argval) + 1);
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
