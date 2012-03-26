#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/proc_fs.h>
#include <linux/string.h>
#include <linux/vmalloc.h>
#include <asm/uaccess.h>
#include "minifirewall-def.h"

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("Mini Firewall Kernel Module");
MODULE_AUTHOR("Vivek Shankar");

#define MAX_LENGTH  (20 * sizeof(struct FirewallRule))

static struct proc_dir_entry *proc_entry;
static struct FirewallRule *pHead, *pTail, *pIndex;
static int iTotal;

ssize_t mod_write(struct file* filp, const char __user *buff, unsigned long len, void* data);
int mod_read(char* page, char** start, off_t off, int count, int *eof, void *data);

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
  iTotal = 0;
  
  proc_entry->read_proc = mod_read;
  proc_entry->write_proc = mod_write;

  printk(KERN_INFO "minifirewall: Module loaded\n");

  return ret;
}

void cleanup_minifirewall_module(void)
{
  struct FirewallRule *pCurr = NULL;
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
      --iTotal;
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

  pRule->m_iID = ++iTotal;
  printk(KERN_INFO "Number of rules created = %d, last rule ID = %d, protocol = %d", iTotal, pRule->m_iID, pRule->m_iProtocol);
  
  return len;
}
