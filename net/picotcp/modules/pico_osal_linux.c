/* Linux kernel osal implementation  */
#include "pico_defines.h"
#include "pico_device.h"
#include "pico_stack.h"
#include "pico_tree.h"
#include "pico_ipv4.h"
#include <linux/mutex.h>
#include <linux/types.h>
#include <linux/socket.h>
#include <linux/kthread.h>
#include <linux/module.h>
#include <net/ip.h>
#include <net/protocol.h>
#include <uapi/linux/if_arp.h>

extern volatile int pico_stack_is_ready;

struct picotcp_sock {
  struct sock sk; /* Must be the first member */
  struct pico_socket *pico;
};


static struct proto picotcp_proto = {
  .name = "INET",
  .owner = THIS_MODULE,
  .obj_size = sizeof(struct picotcp_sock),
};


void * pico_mutex_init(void) {
    struct mutex *m = kmalloc(sizeof(struct mutex), GFP_ATOMIC);
    if (!m)
        return NULL;
    mutex_init(m);
    if (!m)
        return NULL;
    return m;
}
void pico_mutex_deinit(void *_m)
{
    struct mutex *m = (struct mutex *)_m;
    mutex_destroy(m);
    kfree(m);
}

void pico_mutex_lock(void *_m)
{
    struct mutex *m = (struct mutex *)_m;
    mutex_lock(m);
}

void pico_mutex_unlock(void *_m)
{
    struct mutex *m = (struct mutex *)_m;
    mutex_unlock(m);
}


void * pico_signal_init(void)
{
    struct mutex *m ;
    m = pico_mutex_init();
    mutex_lock(m);
    return m;
}

void pico_signal_deinit(void * signal)
{
    return pico_mutex_deinit(signal);
}

void pico_signal_wait(void * signal)
{
    return pico_mutex_lock(signal);
}

int pico_signal_wait_timeout(void * signal, unsigned long timeout)
{
    unsigned long giveup = jiffies_to_msecs(jiffies) + timeout;
    while(!mutex_trylock(signal)) {
        if (jiffies_to_msecs(jiffies) > giveup)
            return -1;
        set_current_state(TASK_INTERRUPTIBLE);
        schedule();
    }
    return 0;
}

void pico_signal_send(void * signal)
{
    return pico_mutex_unlock(signal);
}



static int picotcp_release(struct socket *sock)
{
  printk("Called picotcp_release()\n");
  return 0;
}

static int picotcp_gifconf(struct socket *sock, unsigned int cmd, unsigned long arg);
static int picotcp_iogflags(struct socket *sock, unsigned int cmd, unsigned long arg);
static int picotcp_iogmac(struct socket *sock, unsigned int cmd, unsigned long arg);
static int picotcp_iogmtu(struct socket *sock, unsigned int cmd, unsigned long arg);
static int picotcp_iogaddr(struct socket *sock, unsigned int cmd, unsigned long arg);
static int picotcp_iogbrd(struct socket *sock, unsigned int cmd, unsigned long arg);
static int picotcp_iogmask(struct socket *sock, unsigned int cmd, unsigned long arg);

static int picotcp_ioctl(struct socket *sock, unsigned int cmd, unsigned long arg)
{
  int err;
  if (!arg)
    return -EINVAL;
  switch(cmd) {
	  case SIOCGSTAMP:
	  	err = sock_get_timestamp(sock->sk, (struct timeval __user *)arg);
	  	break;
	  case SIOCGSTAMPNS:
	  	err = sock_get_timestampns(sock->sk, (struct timespec __user *)arg);
	  	break;
    case SIOCGIFCONF:
      err = picotcp_gifconf(sock, cmd, arg);
      break;
    case SIOCGIFFLAGS:
      err = picotcp_iogflags(sock, cmd, arg);
      break;
    case SIOCGIFHWADDR:
      err = picotcp_iogmac(sock, cmd, arg);
      break;
    case SIOCGIFMTU:
      err = picotcp_iogmtu(sock, cmd, arg);
      break;
    case SIOCGIFADDR:
    case SIOCGIFDSTADDR:
      err = picotcp_iogaddr(sock, cmd, arg);
      break;
    case SIOCGIFBRDADDR:
      err = picotcp_iogbrd(sock, cmd, arg);
      break;
    case SIOCGIFNETMASK:
      err = picotcp_iogmask(sock, cmd, arg);
      break;
    case SIOCGIFMETRIC:
    case SIOCGIFMAP:
    {
      struct ifmap m = { };
      ((struct ifreq *)arg)->ifr_metric = 0;
      if(copy_to_user(&((struct ifreq *)arg)->ifr_map, &m, sizeof(m)))
        err = EFAULT;
      else
        err = 0;
      break;
    }
    case SIOCGIFTXQLEN:
    {
      ((struct ifreq *)arg)->ifr_qlen = 500;
      err = 0;
      break;
    }

    default:
      err = -EOPNOTSUPP;
  }
  printk("Called ioctl(%u,%lu), returning %d\n", cmd, arg, err);
  return err;
}

static int picotcp_connect(struct socket *sock, struct sockaddr *addr, int addr_len, int flags)
{
  return -EPERM;
}

static int picotcp_bind(struct socket *sock, struct sockaddr *addr, int addr_len)
{
  return -EPERM;
}

static int picotcp_listen(struct socket *sock, int backlog)
{

  return 0;
}

const struct proto_ops picotcp_proto_ops = {
	.family		   = PF_INET,
	.owner		   = THIS_MODULE,
	.release	   = picotcp_release,
	.ioctl		   = picotcp_ioctl,
	.connect	   = picotcp_connect,
	.bind		     = picotcp_bind,
	.listen		   = picotcp_listen,
#if 0
	.socketpair	   = sock_no_socketpair,
	.accept		   = pico_accept,
	.getname	   = pico_getname,
	.poll		   = pico_poll,
	.listen		   = pico_listen,
	.shutdown	   = pico_shutdown,
	.setsockopt	   = sock_common_setsockopt,
	.getsockopt	   = sock_common_getsockopt,
	.sendmsg	   = pico_sendto,
	.recvmsg	   = pico_recvfrom,
	.mmap		   = sock_no_mmap,
	.sendpage	   = pico_sendpage,
	.splice_read	   = tcp_splice_read,
#endif
};
EXPORT_SYMBOL(picotcp_proto_ops);

extern struct pico_tree Device_tree;

static char *picotcp_netif_get(char *last) {
  struct pico_tree_node *n;
  pico_tree_foreach(n, &Device_tree) {
    struct pico_device *dev = n->keyValue;
    if (!last)
      return dev->name;
    if (strcmp(last, dev->name) == 0)
      last = NULL;
  }
  return NULL;
}


static int picodev_to_ifreq(const char *ifname, struct ifreq *ifr) {
  struct pico_device *dev;
  struct sockaddr_in *addr = (struct sockaddr_in *) &ifr->ifr_addr;
  struct pico_ipv4_link *l;

  if (!ifr)
    return -1;
  dev = pico_get_device(ifname);
  if (!dev)
    return -1;

  strncpy(ifr->ifr_name, dev->name, IFNAMSIZ);
  l = pico_ipv4_link_by_dev(dev);
  addr->sin_family = AF_INET;
  if (!l) {
    addr->sin_addr.s_addr = 0U;
  } else {
    addr->sin_addr.s_addr = l->address.addr;
  }
  return 0;
}

static int picotcp_iogaddr(struct socket *sock, unsigned int cmd, unsigned long arg)
{
  struct ifreq *ifr;
  struct pico_device *dev;
  struct pico_ipv4_link *l;
  struct sockaddr_in *addr;
  if (!arg)
    return -EINVAL;

  ifr = (struct ifreq *)arg;
  dev = pico_get_device(ifr->ifr_name);
  if (!dev)
    return -ENOENT;
  addr = (struct sockaddr_in *) &ifr->ifr_addr;

  l = pico_ipv4_link_by_dev(dev);
  addr->sin_family = AF_INET;
  if (!l) {
    addr->sin_addr.s_addr = 0U;
  } else {
    addr->sin_addr.s_addr = l->address.addr;
  }
  return 0;
}

static int picotcp_iogbrd(struct socket *sock, unsigned int cmd, unsigned long arg)
{
  struct ifreq *ifr;
  struct pico_device *dev;
  struct pico_ipv4_link *l;
  struct sockaddr_in *addr;
  if (!arg)
    return -EINVAL;

  ifr = (struct ifreq *)arg;
  dev = pico_get_device(ifr->ifr_name);
  if (!dev)
    return -ENOENT;
  addr = (struct sockaddr_in *) &ifr->ifr_addr;

  l = pico_ipv4_link_by_dev(dev);
  addr->sin_family = AF_INET;
  if (!l) {
    addr->sin_addr.s_addr = 0U;
  } else {
    addr->sin_addr.s_addr = l->address.addr | (~l->netmask.addr);
  }
  return 0;
}

static int picotcp_iogmask(struct socket *sock, unsigned int cmd, unsigned long arg)
{
  struct ifreq *ifr;
  struct pico_device *dev;
  struct pico_ipv4_link *l;
  struct sockaddr_in *addr;
  if (!arg)
    return -EINVAL;

  ifr = (struct ifreq *)arg;
  dev = pico_get_device(ifr->ifr_name);
  if (!dev)
    return -ENOENT;
  addr = (struct sockaddr_in *) &ifr->ifr_addr;

  l = pico_ipv4_link_by_dev(dev);
  addr->sin_family = AF_INET;
  if (!l) {
    addr->sin_addr.s_addr = 0U;
  } else {
    addr->sin_addr.s_addr = l->netmask.addr;
  }
  return 0;
}

static int picotcp_iogflags(struct socket *sock, unsigned int cmd, unsigned long arg)
{
  struct ifreq *ifr;
  struct pico_device *dev;
  if (!arg)
    return -EINVAL;

  ifr = (struct ifreq *)arg;
  dev = pico_get_device(ifr->ifr_name);
  if (!dev)
    return -ENOENT;

  ifr->ifr_flags = IFF_BROADCAST | IFF_MULTICAST;

  if (pico_ipv4_link_by_dev(dev) 
#ifdef CONFIG_PICO_IPV6
    || pico_ipv6_link_by_dev(dev)
#endif
    ) {
    ifr->ifr_flags |= IFF_UP|IFF_RUNNING;
  }
  return 0;
}


static int picotcp_iogmac(struct socket *sock, unsigned int cmd, unsigned long arg)
{
  struct ifreq *ifr;
  struct pico_device *dev;
  if (!arg)
    return -EINVAL;

  ifr = (struct ifreq *)arg;
  dev = pico_get_device(ifr->ifr_name);
  if (!dev)
    return -ENOENT;


  if (dev->eth) {
    if(copy_to_user(ifr->ifr_hwaddr.sa_data, dev->eth, PICO_SIZE_ETH))
      return -EFAULT;
    ifr->ifr_hwaddr.sa_family = ARPHRD_ETHER;
  } else {
    memset(&ifr->ifr_hwaddr, 0, sizeof(struct sockaddr));
    ifr->ifr_hwaddr.sa_family = ARPHRD_NONE;
  }

  if (strcmp(ifr->ifr_name, "lo") == 0) {
    ifr->ifr_hwaddr.sa_family = ARPHRD_LOOPBACK;
  }

  return 0;
}

static int picotcp_iogmtu(struct socket *sock, unsigned int cmd, unsigned long arg)
{
  struct ifreq *ifr;
  struct pico_device *dev;
  if (!arg)
    return -EINVAL;

  ifr = (struct ifreq *)arg;
  dev = pico_get_device(ifr->ifr_name);
  if (!dev)
    return -ENOENT;

  ifr->ifr_mtu = 1500;
  return 0;
}

static int picotcp_gifconf(struct socket *sock, unsigned int cmd, unsigned long arg)
{

  struct ifconf *ifc;
  struct ifreq ifr;
  char *devname = NULL;
  int i;
  int size = 0;

  ifc = (struct ifconf *)arg;
  if (!arg)
    return -EINVAL;

  for(i = 0; i < ifc->ifc_len / sizeof(struct ifreq); i++) {
    devname = picotcp_netif_get(devname);
    if (!devname)
      break;
    if (picodev_to_ifreq(devname, &ifr) < 0)
      return -EINVAL;

    if (copy_to_user(&ifc->ifc_req[i], &ifr, sizeof(struct ifreq)))
      return -EFAULT;
    size += sizeof(struct ifreq);
  }
  ifc->ifc_len = size;
  printk("Called picotcp_gifconf\n");
  return 0;
}


static int picotcp_create(struct net *net, struct socket *sock, int protocol, int kern)
{
  struct sock *sk;
	sock->state = SS_UNCONNECTED;
  sock->ops = &picotcp_proto_ops;

  sk = sk_alloc(net, PF_INET, GFP_KERNEL, &picotcp_proto);
  if (!sk) {
    return -ENOMEM;
  }

  sock->sk = sk;

  return 0;
}



static int __net_init pico_net_init(struct net *net)
{
  return 0;
}

static void __net_exit pico_net_exit(struct net *net)
{

}


static struct pernet_operations picotcp_net_ops = {
  .init = pico_net_init,
  .exit = pico_net_exit,
};

static const struct net_proto_family picotcp_family_ops = {
  .family = PF_INET,
  .create = picotcp_create,
  .owner  = THIS_MODULE,
};

MODULE_ALIAS_NETPROTO(PF_INET);

static int __init af_inet_picotcp_init(void)
{
  int rc = proto_register(&picotcp_proto, 1);
  while (!pico_stack_is_ready)
    schedule();
  if (rc)
    panic("Cannot register AF_INET family for PicoTCP\n");
  sock_register(&picotcp_family_ops);

  register_pernet_subsys(&picotcp_net_ops);
  return 0;
}

static void __exit af_inet_picotcp_exit(void)
{
  sock_unregister(PF_INET);
  proto_unregister(&picotcp_proto);
  unregister_pernet_subsys(&picotcp_net_ops);
}

fs_initcall(af_inet_picotcp_init);
