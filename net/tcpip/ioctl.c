#include "pico_defines.h"
#include "pico_device.h"
#include "pico_stack.h"
#include "pico_tree.h"
#include "pico_ipv4.h"
#include "pico_socket.h"
#include <linux/mutex.h>
#include <linux/types.h>
#include <linux/socket.h>
#include <linux/kthread.h>
#include <linux/module.h>
#include <linux/wait.h>
#include <net/ip.h>
#include <net/protocol.h>
#include <uapi/linux/if_arp.h>
#include <picotcp.h>

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

static int picotcp_iosgaddr(struct socket *sock, unsigned int cmd, unsigned long arg, int set)
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
  if (set) {
    if (!l || addr->sin_addr.s_addr != l->address.addr) {
      struct pico_ip4 a, nm;
      a.addr = addr->sin_addr.s_addr;
      if (l)
        nm.addr = l->netmask.addr;
      else
        nm.addr = htonl(0xFFFFFF00); /* Default 24 bit nm */
      if (l)
        pico_ipv4_link_del(dev, l->address);
      pico_ipv4_link_add(dev, a, nm);
    }
    return 0;
  }
  addr->sin_family = AF_INET;
  if (!l) {
    addr->sin_addr.s_addr = 0U;
  } else {
    addr->sin_addr.s_addr = l->address.addr;
  }
  return 0;
}

static int picotcp_iosgbrd(struct socket *sock, unsigned int cmd, unsigned long arg, int set)
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

  if (set)
    return -EOPNOTSUPP;

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

static int picotcp_iosgmask(struct socket *sock, unsigned int cmd, unsigned long arg, int set)
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
  if (!l)
    return -ENOENT;

  if (set) {
    if (addr->sin_addr.s_addr != l->netmask.addr) {
      struct pico_ip4 a, nm;
      a.addr = l->address.addr;
      nm.addr = addr->sin_addr.s_addr;
      pico_ipv4_link_del(dev, l->address);
      pico_ipv4_link_add(dev, a, nm);
    }
    return 0;
  }

  addr->sin_family = AF_INET;
  if (!l) {
    addr->sin_addr.s_addr = 0U;
  } else {
    addr->sin_addr.s_addr = l->netmask.addr;
  }
  return 0;
}

static int picotcp_iosgflags(struct socket *sock, unsigned int cmd, unsigned long arg, int set)
{
  struct ifreq *ifr;
  struct pico_device *dev;
  if (!arg)
    return -EINVAL;

  ifr = (struct ifreq *)arg;
  dev = pico_get_device(ifr->ifr_name);
  if (!dev)
    return -ENOENT;

  /* Set flags: we only care about UP flag being reset */
  if (set && ((ifr->ifr_flags & IFF_UP) == 0) ) {
    struct pico_ipv4_link *l = pico_ipv4_link_by_dev(dev);
    while(l) {
      pico_ipv4_link_del(dev, l->address);
      l = pico_ipv4_link_by_dev(dev);
    }
    return 0;
  }

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


static int picotcp_iosgmac(struct socket *sock, unsigned int cmd, unsigned long arg, int set)
{
  struct ifreq *ifr;
  struct pico_device *dev;
  if (!arg)
    return -EINVAL;

  if (set)
    return -EOPNOTSUPP; /* Can't change macaddress on the fly... */

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

static int picotcp_iosgmtu(struct socket *sock, unsigned int cmd, unsigned long arg, int set)
{
  struct ifreq *ifr;
  struct pico_device *dev;
  if (!arg)
    return -EINVAL;

  if (set)
    return -EOPNOTSUPP; /* We don't support dynamic MTU now. */

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


int picotcp_ioctl(struct socket *sock, unsigned int cmd, unsigned long arg)
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
      err = picotcp_iosgflags(sock, cmd, arg, 0);
      break;
    case SIOCGIFHWADDR:
      err = picotcp_iosgmac(sock, cmd, arg, 0);
      break;
    case SIOCGIFMTU:
      err = picotcp_iosgmtu(sock, cmd, arg, 0);
      break;
    case SIOCGIFADDR:
    case SIOCGIFDSTADDR:
      err = picotcp_iosgaddr(sock, cmd, arg, 0);
      break;
    case SIOCGIFBRDADDR:
      err = picotcp_iosgbrd(sock, cmd, arg, 0);
      break;
    case SIOCGIFNETMASK:
      err = picotcp_iosgmask(sock, cmd, arg, 0);
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

    /* Set functions */

    case SIOCSIFADDR:
      err = picotcp_iosgaddr(sock, cmd, arg, 1);
      break;
    case SIOCSIFBRDADDR:
      err = picotcp_iosgbrd(sock, cmd, arg, 1);
      break;
    case SIOCSIFNETMASK:
      err = picotcp_iosgmask(sock, cmd, arg, 1);
      break;
    case SIOCSIFFLAGS:
      err = picotcp_iosgflags(sock, cmd, arg, 1);
      break;

    default:
      err = -EOPNOTSUPP;
  }
  printk("Called ioctl(%u,%lu), returning %d\n", cmd, arg, err);
  return err;
}
