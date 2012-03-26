#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/proc_fs.h>
#include <linux/string.h>
#include <linux/vmalloc.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/ip.h>
#include <linux/skbuff.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <asm/uaccess.h>
#include "minifirewall-def.h"

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("Mini Firewall Kernel Module");
MODULE_AUTHOR("Vivek Shankar");


static struct proc_dir_entry *proc_entry;
// State variables for rules management
static struct FirewallRule *pHead, *pTail, *pIndex;
static int iMaxID;
// State variables for Netfilter module
static struct nf_hook_ops nfho_prerouting, nfho_localin, nfho_localout, nfho_postrouting;

// Functions for rules management
ssize_t mod_write(struct file* filp, const char __user *buff, unsigned long len, void* data);
int mod_read(char* page, char** start, off_t off, int count, int *eof, void *data);

// Functions for netfilter management
int init_nf_module(void);
void cleanup_nf_module(void);

int init_minifirewall_module(void)
{
  int ret = 0;

  proc_entry = create_proc_entry("minifirewall", 0644, NULL);
  if (proc_entry == NULL)
  {
    ret = -ENOMEM;
    printk(KERN_INFO "minifirewall: Couldn't create proc entry\n");

    return ret;
  }

  pHead = NULL;
  pTail = NULL;
  pIndex = NULL;
  iMaxID = 0;
  
  proc_entry->read_proc = mod_read;
  proc_entry->write_proc = mod_write;

  init_nf_module();
  printk(KERN_INFO "minifirewall: Module loaded\n");

  return ret;
}

void cleanup_minifirewall_module(void)
{
  struct FirewallRule *pCurr = NULL;
  
  cleanup_nf_module();
  remove_proc_entry("minifirewall", NULL);
  
  for (pCurr = pHead; pCurr != NULL;) {
    struct FirewallRule *pTemp = pCurr;
    printk(KERN_INFO "Unloaded pCurr->m_iID = %d", pCurr->m_iID);

    pCurr = pCurr->m_pNext;

    vfree(pTemp);
  }

  pHead = pTail = pIndex = NULL;

  printk(KERN_INFO "minifirewall: Module unloaded.\n");
}

module_init(init_minifirewall_module);
module_exit(cleanup_minifirewall_module);

int mod_read(char* page, char **start, off_t off, int count, int *eof, void *data)
{
  int len;
  struct FirewallRule *pRule = NULL;

  printk(KERN_INFO "minifirewall: mod_read START; off = %d", off);
  if (off > 0)
  {
    *eof = 1;
    return 1;
  }

  if (pIndex == 0) {
    pIndex = pHead;
  }

  if (pHead == NULL) {
    printk(KERN_INFO "minifirewall: No elements");
    return 0;
  }

  pRule = pIndex;
  printk(KERN_INFO "Rule ID = %d, protocol = %d, blocked = %d, Next = %d", pRule->m_iID, pRule->m_iProtocol, pRule->m_bBlock, (pRule->m_pNext != NULL));
  //len = copy_to_user(page, pRule, sizeof(struct FirewallRule));
  //len = sprintf(page, "%s", pRule);
  memcpy(page, pRule, sizeof(struct FirewallRule) + 1);
  len = sizeof(struct FirewallRule);

  pIndex = pIndex->m_pNext;

  return len;
}

ssize_t delete_rule(struct FirewallRule *pRule)
{
  struct FirewallRule *pCurr = NULL;
  if (pHead == NULL) {
    printk(KERN_INFO "minifirewall: There are no rules to delete");
    return -EFAULT;
  }

  for (pCurr = pHead; pCurr != NULL; pCurr = pCurr->m_pNext) {
    if (pRule->m_iID == pCurr->m_iID) {
      if (pCurr == pHead) {
	pHead = pCurr->m_pNext;
      }
      
      if (pCurr == pTail) {
	pTail = pCurr->m_pPrev;
      }

      if (pCurr->m_pPrev != NULL) {
	pCurr->m_pPrev->m_pNext = pCurr->m_pNext;
      }

      if (pCurr->m_pNext != NULL) {
	pCurr->m_pNext->m_pPrev = pCurr->m_pPrev;
      }

      vfree(pCurr);
      break;
    }
  }
  
  return 0;
}

ssize_t mod_write(struct file *filp, const char __user *buff, unsigned long len, void *data)
{
  struct FirewallRule* pRule = NULL;
  printk(KERN_INFO "minifirewall: mod_write START; len = %d", len);

  pRule = (struct FirewallRule*) vmalloc(sizeof(struct FirewallRule));
  if (pRule == NULL) {
    printk(KERN_INFO "minifirewall: Memory could not be allocated of size %d", sizeof(struct FirewallRule));
    return -ENOMEM;
  }

  if (copy_from_user(pRule, buff, len)) 
  {
    printk(KERN_INFO "minifirewall: copy_from_user failed");
    vfree(pRule);
    return -EFAULT;
  }

  if (pRule->m_bDeleted == 1) {
    if (delete_rule(pRule) < 0) {
      printk(KERN_INFO "minifirewall: rule could not be deleted");
      vfree(pRule);
      return -EFAULT;
    }

    vfree(pRule);
    printk(KERN_INFO "minifirewall: rule deleted");
    return len;
  }

  if (pHead == NULL) {
    pHead = pRule;
    pTail = pRule;
  } else {
    pTail->m_pNext = pRule;
    pRule->m_pPrev = pTail;
    pTail = pRule;
  }

  pRule->m_iID = ++iMaxID;
  printk(KERN_INFO "Last rule ID = %d, protocol = %d", pRule->m_iID, pRule->m_iProtocol);
  
  return len;
}

unsigned int check_rules(int bInput, unsigned int proto, unsigned int saddr, unsigned int sport, unsigned int daddr, unsigned int dport)
{
  struct FirewallRule *pCurr = NULL;

  // TODO: This is likely to be a multi-threaded application. The rules structure should be protected with R/O access.
  if (pHead == NULL) {
    printk(KERN_INFO "minifirewall: No rules to check");
    return NF_ACCEPT;
  }

  for (pCurr = pHead; pCurr != NULL; pCurr = pCurr->m_pNext) {
    unsigned int ip;
    // Check if this is an input rule
    if (pCurr->m_bInput != bInput)
      continue;

    // Check the protocol
    if (pCurr->m_iProtocol != 0 && pCurr->m_iProtocol != proto)
      continue;

    // Check the source IP
    if (pCurr->m_srcAddr.m_iIP != 0) {
      ip = (pCurr->m_srcAddr.m_iNetMask != 0) ? (pCurr->m_srcAddr.m_iIP & pCurr->m_srcAddr.m_iNetMask) : pCurr->m_srcAddr.m_iIP;
      if (saddr != ip)
	continue;
    }

    // Check the source port
    if (pCurr->m_srcAddr.m_iPort != 0 && pCurr->m_srcAddr.m_iPort != sport)
      continue;

     // Check the dest IP
    if (pCurr->m_destAddr.m_iIP != 0) {
      ip = (pCurr->m_destAddr.m_iNetMask != 0) ? (pCurr->m_destAddr.m_iIP & pCurr->m_destAddr.m_iNetMask) : pCurr->m_destAddr.m_iIP;
      if (daddr != ip)
	continue;
    }

    // Check the dest port
    if (pCurr->m_destAddr.m_iPort != 0 && pCurr->m_destAddr.m_iPort != sport)
      continue;
    
    // We have a match!
    if (pCurr->m_bBlock == 1) {
      printk(KERN_INFO "minifirewall: Dropping packet; protocol = %d, saddr = %d, sport = %d, daddr = %d, dport = %d, rule = %d", proto, saddr, sport, daddr, dport, pCurr->m_iID);
      return NF_DROP;
    }
    else
      return NF_ACCEPT;
  }
  
  // Nothing found
  return NF_ACCEPT;
}

unsigned int hook_prerouting(unsigned int hooknum, struct sk_buff *skb, const struct net_device *in, const struct net_device *out, int (*okfn) (struct sk_buff*))
{
  struct iphdr *ip_header = NULL;
  unsigned int proto = 0, saddr = 0, sport = 0, daddr = 0, dport = 0;
  
  if (pHead == NULL) {
    printk(KERN_INFO "No rules to check");
    return NF_ACCEPT;
  }

  //printk(KERN_INFO "In hook_prerouting");
  ip_header = ip_hdr(skb);
  if (!ip_header) {
    printk(KERN_INFO "minifirewall: ip_header is NULL");
    return NF_ACCEPT;
  }

  proto = ip_header->protocol;
  saddr = ip_header->saddr;
  daddr = ip_header->daddr;
  
  if (proto == IPPROTO_TCP) {
    struct tcphdr *tcp_header = NULL;
    tcp_header = tcp_hdr(skb);
    if (tcp_header == NULL) {
      printk(KERN_INFO "minifirewall: TCP protocol packet has no TCP header! Exiting");
      return NF_ACCEPT;
    }

    sport = tcp_header->source;
    dport = tcp_header->dest;
  } else if (proto == IPPROTO_UDP) {
    struct udphdr *udp_header = NULL;
    udp_header = udp_hdr(skb);
    if (udp_header == NULL) {
      printk(KERN_INFO "minifirewall: UDP protocol packet has no UDP header! Exiting");
      return NF_ACCEPT;
    }

    sport = udp_header->source;
    dport = udp_header->dest;
  }

  //printk(KERN_INFO "proto = %u, saddr = %u, sport = %u, daddr = %u, dport = %u", proto, saddr, sport, daddr, dport);
  return check_rules(1, proto, saddr, sport, daddr, dport);
}

unsigned int hook_localin(unsigned int hooknum, struct sk_buff *skb, const struct net_device *in, const struct net_device *out, int (*okfn) (struct sk_buff*))
{
  //printk(KERN_INFO "In hook_localin");
  return NF_ACCEPT;
}

unsigned int hook_localout(unsigned int hooknum, struct sk_buff *skb, const struct net_device *in, const struct net_device *out, int (*okfn) (struct sk_buff*))
{
  //printk(KERN_INFO "In hook_localout");
  return NF_ACCEPT;
}

unsigned int hook_postrouting(unsigned int hooknum, struct sk_buff *skb, const struct net_device *in, const struct net_device *out, int (*okfn) (struct sk_buff*))
{
  struct iphdr *ip_header = NULL;
  unsigned int proto = 0, saddr = 0, sport = 0, daddr = 0, dport = 0;
  
  if (pHead == NULL) {
    printk(KERN_INFO "minifirewall: No rules to check");
    return NF_ACCEPT;
  }

  //printk(KERN_INFO "In hook_postrouting");
  ip_header = ip_hdr(skb);
  if (!ip_header) {
    printk(KERN_INFO "minifirewall: ip_header is NULL");
    return NF_ACCEPT;
  }

  proto = ip_header->protocol;
  saddr = ip_header->saddr;
  daddr = ip_header->daddr;
  
  if (proto == IPPROTO_TCP) {
    struct tcphdr *tcp_header = NULL;
    tcp_header = tcp_hdr(skb);
    if (tcp_header == NULL) {
      printk(KERN_INFO "minifirewall: TCP protocol packet has no TCP header! Exiting");
      return NF_ACCEPT;
    }

    sport = tcp_header->source;
    dport = tcp_header->dest;
  } else if (proto == IPPROTO_UDP) {
    struct udphdr *udp_header = NULL;
    udp_header = udp_hdr(skb);
    if (udp_header == NULL) {
      printk(KERN_INFO "minifirewall: UDP protocol packet has no UDP header! Exiting");
      return NF_ACCEPT;
    }

    sport = udp_header->source;
    dport = udp_header->dest;
  }

  //  printk(KERN_INFO "proto = %u, saddr = %u, sport = %u, daddr = %u, dport = %u", proto, saddr, sport, daddr, dport);

  return check_rules(0, proto, saddr, sport, daddr, dport);
}

int init_nf_module(void)
{
  nfho_prerouting.hook = hook_prerouting;
  /* Handler function */
  nfho_prerouting.hooknum = NF_INET_PRE_ROUTING; /* First hook for IPv4 */
  nfho_prerouting.pf = PF_INET;
  nfho_prerouting.priority = NF_IP_PRI_FIRST; /* Make our function first */

  nfho_localin.hook = hook_localin;
  /* Handler function */
  nfho_localin.hooknum = NF_INET_LOCAL_IN;
  nfho_localin.pf = PF_INET;
  nfho_localin.priority = NF_IP_PRI_FIRST; /* Make our function first */

  nfho_localout.hook = hook_localout;
  /* Handler function */
  nfho_localout.hooknum = NF_INET_LOCAL_OUT;
  nfho_localout.pf = PF_INET;
  nfho_localout.priority = NF_IP_PRI_FIRST; /* Make our function first */

  nfho_postrouting.hook = hook_postrouting;
  /* Handler function */
  nfho_postrouting.hooknum = NF_INET_POST_ROUTING; /* First hook for IPv4 */
  nfho_postrouting.pf = PF_INET;
  nfho_postrouting.priority = NF_IP_PRI_FIRST; /* Make our function first */

  nf_register_hook(&nfho_prerouting);
  nf_register_hook(&nfho_localin);
  nf_register_hook(&nfho_localout);
  nf_register_hook(&nfho_postrouting);

  return 0;
}

void cleanup_nf_module(void)
{
  nf_unregister_hook(&nfho_prerouting);
  nf_unregister_hook(&nfho_localin);
  nf_unregister_hook(&nfho_localout);
  nf_unregister_hook(&nfho_postrouting);
}
