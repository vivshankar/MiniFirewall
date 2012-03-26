#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/proc_fs.h>
#include <linux/string.h>
#include <linux/vmalloc.h>
#include <asm/uaccess.h>

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("Mini Firewall Kernel Module");
MODULE_AUTHOR("Vivek Shankar");

struct FirewallRule
{
  int m_protocol;
  unsigned char* m_srcIP;
  unsigned char* m_srcNetMask;
  unsigned char* m_destIP;
  unsigned char* m_destNetMask;
  int bBlock;
};

#define MAX_LENGTH  (20 * sizeof(FirewallRule))

static struct proc_dir_entry *proc_entry;
static unsigned char* rules;
static int index;
static int next;

ssize_t minifirewall_write(struct file* filp, const char __user *buff, unsigned long len, void* data);
int minifirewall_read(char* page, char** start, off_t off, int count, int *eof, void *data);

int init_minifirewall_module(void)
{
  int ret = 0;

  rules = (unsigned char*) vmalloc(MAX_LENGTH);

  if (!rules)
  {
    return -ENOMEM;
  } 
  
  memset(rules, 0, MAX_LENGTH);
  proc_entry = create_proc_entry("minifirewall", 0644, NULL);
  if (proc_entry == NULL)
  {
    ret = -ENOMEM;
    vfree(rules);
    printk(KERN_INFO "minifirewall: Couldn't create proc entry\n");

    return ret;
  }
  
  index = 0;
  next = 0;
  proc_entry->read_proc = mod_read;
  proc_entry->write_proc = mod_write;

  printk(KERN_INFO "minifirewall: Module loaded\n");

  return ret;
}

void cleanup_minifirewall_module(void)
{
  remove_proc_entry("minifirewall", NULL);
  vfree(rules);
  printk(KERN_INFO "minifirewall: Module unloaded.\n");
}

module_init(init_minifirewall_module);
module_exit(cleanup_minifirewall_module);

int mod_read(char* page, char **start, off_t off, int count, int *eof, void *data)
{
  int len;

  printk(KERN_INFO "minifirewall: mod_read START");
  if (off > 0)
  {
    *eof = 1;
    return 0;
  }

  if (next >= index)
    next = 0;

  struct FirewallRule *pRule = &(rules[next]);
  len = sprintf(page, "%s\n", pRule);
  next += len;

  return len;
}

ssize_t mod_write(struct file *filp, const char __user *buff, unsigned long len, void *data)
{
  int space_available = (MAX_LENGTH - index) + 1;
 
  printk(KERN_INFO "minifirewall: mod_write START");
  if (len > space_available)
  {
    printk(KERN_INFO "minifirewall: No more rules allowed!\n");
    return -ENOSPC;
  }

  if (copy_from_user(&rules[index], buff, len)) 
  {
    return -EFAULT;
  }

  FirewallRule* rule = &rules[index];
  printk(KERN_INFO "rules[index]->srcIP = %s", rule->srcIP);
  index += len;
  rules[index-1] = 0;
  return len;
}
