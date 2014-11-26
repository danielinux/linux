#include <asm/uaccess.h>

#include <linux/errno.h>
#include <linux/time.h>
#include <linux/proc_fs.h>
#include <linux/stat.h>
#include <linux/slab.h>
#include <linux/init.h>
#include <linux/sched.h>
#include <linux/module.h>
#include <linux/bitops.h>
#include <linux/mount.h>
#include <linux/nsproxy.h>
#include <net/net_namespace.h>
#include <linux/seq_file.h>
#include <pico_tree.h>
#include <pico_ipv4.h>

extern struct pico_tree Routes;

static int stack_proc_show(struct seq_file *m, void *v)
{
  seq_printf(m,"picoTCP\n");
  return 0;
}

static int route_proc_show(struct seq_file *m, void *v)
{
  struct pico_ipv4_route *r;
  struct pico_tree_node *index;
  seq_printf(m,"Iface\tDestination\tGateway\t\tFlags\tRefCnt\tUse\tMetric\tMask\tMTU\tWindow\tIRTT \n");
  pico_tree_foreach(index, &Routes){
      int flags = 1;
      r = index->keyValue;
      if (r->netmask.addr == 0)
          flags += 2;
      seq_printf(m, "%s\t%08X\t%08X\t%04X\t0\t0\t%d\t%08X\t0\t0\t0\n", 
          r->link->dev->name, r->dest.addr, r->gateway.addr, flags, r->metric, r->netmask.addr);
  }
  return 0;
}

static int route_proc_open(struct inode *inode, struct file *file)
{
  return single_open(file, route_proc_show, NULL);
}

static int stack_proc_open(struct inode *inode, struct file *file)
{
  return single_open(file, stack_proc_show, NULL);
}

static const struct file_operations route_proc_fops = {
  .owner    = THIS_MODULE,
  .open   = route_proc_open,
  .read   = seq_read,
  .llseek   = seq_lseek,
  .release  = single_release,
};

static const struct file_operations stack_proc_fops = {
  .owner    = THIS_MODULE,
  .open   = stack_proc_open,
  .read   = seq_read,
  .llseek   = seq_lseek,
  .release  = single_release,
};

static __net_init int proc_net_route_init(struct net *net)
{
  struct proc_dir_entry *pde;

  /* /proc/net/route */
  pde = proc_create("route", S_IRUGO, net->proc_net, &route_proc_fops);
  if (!pde) {
    remove_proc_entry("route", net->proc_net);
    return -1;
  }
  printk("picoTCP: Created /proc/net/route.\n");

  /* /proc/net/stack */
  pde = proc_create("stack", S_IRUGO, net->proc_net, &stack_proc_fops);
  if (!pde) {
    remove_proc_entry("stack", net->proc_net);
    return -1;
  }
  printk("picoTCP: Created /proc/net/stack.\n");
  return 0;
}

static void __net_exit proc_net_route_exit(struct net *net)
{
    remove_proc_entry("route", net->proc_net);
}

static struct pernet_operations ip_route_proc_ops __net_initdata =  {
  .init = proc_net_route_init,
  .exit = proc_net_route_exit,
};

int __init ip_route_proc_init(void)
{
  return register_pernet_subsys(&ip_route_proc_ops);
}


