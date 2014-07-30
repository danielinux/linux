/* Linux kernel osal implementation  */
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
#include <pico_bsd_sockets.h>

#define SOCK_OPEN                   0
#define SOCK_BOUND                  1
#define SOCK_LISTEN                 2
#define SOCK_CONNECTED              3
#define SOCK_ERROR                  4
#define SOCK_RESET_BY_PEER          5
#define SOCK_CLOSED                 100

extern volatile int pico_stack_is_ready;
extern void *picoLock;
/* UTILS */
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

/*** Helper functions ***/
static int bsd_to_pico_addr(union pico_address *addr, struct sockaddr *_saddr, socklen_t socklen)
{
    if (socklen == SOCKSIZE6) {
        struct sockaddr_in6 *saddr = (struct sockaddr_in6 *)_saddr;
        memcpy(&addr->ip6.addr, &saddr->sin6_addr.s6_addr, 16);
        saddr->sin6_family = AF_INET6;
    } else {
        struct sockaddr_in *saddr = (struct sockaddr_in *)_saddr;
        addr->ip4.addr = saddr->sin_addr.s_addr;
        saddr->sin_family = AF_INET;
    }
    return 0;
}

static uint16_t bsd_to_pico_port(struct sockaddr *_saddr, socklen_t socklen)
{
    if (socklen == SOCKSIZE6) {
        struct sockaddr_in6 *saddr = (struct sockaddr_in6 *)_saddr;
        return saddr->sin6_port;
    } else {
        struct sockaddr_in *saddr = (struct sockaddr_in *)_saddr;
        return saddr->sin_port;
    }
}

static int pico_port_to_bsd(struct sockaddr *_saddr, socklen_t socklen, uint16_t port)
{
    if (socklen == SOCKSIZE6) {
        struct sockaddr_in6 *saddr = (struct sockaddr_in6 *)_saddr;
        saddr->sin6_port = port;
        return 0;
    } else {
        struct sockaddr_in *saddr = (struct sockaddr_in *)_saddr;
        saddr->sin_port = port;
        return 0;
    }
    pico_err = PICO_ERR_EINVAL;
    return -1;
}

static int pico_addr_to_bsd(struct sockaddr *_saddr, socklen_t socklen, union pico_address *addr, uint16_t net)
{
    if ((socklen == SOCKSIZE6) && (net == PICO_PROTO_IPV6)) {
        struct sockaddr_in6 *saddr = (struct sockaddr_in6 *)_saddr;
        memcpy(&saddr->sin6_addr.s6_addr, &addr->ip6.addr, 16);
        saddr->sin6_family = AF_INET6;
    } else if ((socklen == SOCKSIZE) && (net == PICO_PROTO_IPV4)) {
        struct sockaddr_in *saddr = (struct sockaddr_in *)_saddr;
        saddr->sin_addr.s_addr = addr->ip4.addr;
        saddr->sin_family = AF_INET;
    }
    return 0;
}


/* Sockets */
struct picotcp_sock {
  struct sock sk; /* Must be the first member */
  struct pico_socket *pico;
  uint8_t  in_use;
  uint8_t  state;
  uint8_t  nonblocking;     /* The non-blocking flag, for non-blocking socket operations */
  uint16_t events;          /* events that we filter for */
  uint16_t revents;         /* received events */
  uint16_t proto;
  void *   mutex_lock;      /* mutex for clearing revents */
  uint32_t timeout;         /* this is used for timeout sockets */
  wait_queue_head_t wait;    /* Signal queue */
};

#define picotcp_sock(x) ((struct picotcp_sock *)x->sk)
#define psk_lock(x) pico_mutex_lock(x->mutex_lock)
#define psk_unlock(x) pico_mutex_unlock(x->mutex_lock)

static void pico_event_clear(struct picotcp_sock *psk, uint16_t events)
{
    psk_lock(psk);
    psk->revents &= ~events;
    psk_unlock(psk);
}

uint16_t pico_bsd_select(struct picotcp_sock *psk)
{
    uint16_t events = psk->events & psk->revents; /* maybe an event we are waiting for, was already queued ? */
    DEFINE_WAIT(wait);
    /* wait for one of the selected events... */
    while (!events)
    {
        prepare_to_wait_exclusive(&psk->wait, &wait, TASK_INTERRUPTIBLE);
        events = (psk->revents & psk->events); /* filter for the events we were waiting for */
        if (!events)
          schedule();
        finish_wait(&psk->wait, &wait);
    }
    /* the event we were waiting for happened, now report it */
    return events; /* return any event(s) that occurred, that we were waiting for */
}


static uint16_t pico_bsd_wait(struct picotcp_sock *psk, int read, int write, int close)
{
  psk_lock(psk);

  psk->events = PICO_SOCK_EV_ERR;
  psk->events |= PICO_SOCK_EV_FIN;
  psk->events |= PICO_SOCK_EV_CONN;
  if (close)
      psk->events |= PICO_SOCK_EV_CLOSE;
  if (read) 
      psk->events |= PICO_SOCK_EV_RD;
  if (write)
      psk->events |= PICO_SOCK_EV_WR;

  psk_unlock(psk);

  return pico_bsd_select(psk);
}


static void picotcp_socket_event(uint16_t ev, struct pico_socket *s)
{
    struct picotcp_sock * psk = (struct picotcp_sock *)s->priv;
    if(!psk || !psk->mutex_lock)
    {
        if(ev & (PICO_SOCK_EV_CLOSE | PICO_SOCK_EV_FIN) )
            pico_socket_close(s);

        /* endpoint not initialized yet! */
        return;
    }

    if(psk->in_use != 1)
        return;


    pico_mutex_lock(psk->mutex_lock); /* lock over the complete body is needed */
    psk->revents |= ev; /* set those events */

    if(ev & PICO_SOCK_EV_CONN)
    {
        if(psk->state != SOCK_LISTEN)
        {
            psk->state  = SOCK_CONNECTED;
        }
    }

    if(ev & PICO_SOCK_EV_ERR)
    {
      if(pico_err == PICO_ERR_ECONNRESET)
      {
        dbg("Connection reset by peer...\n");
        psk->state = SOCK_RESET_BY_PEER;
      }
    }

    if (ev & PICO_SOCK_EV_CLOSE) {
        psk->state = SOCK_CLOSED;
    }

    if (ev & PICO_SOCK_EV_FIN) {
        psk->state = SOCK_CLOSED;
    }

    /* sending the event, while no one was listening,
       will just cause an extra loop in select() */
    wake_up_interruptible(&psk->wait);
    pico_mutex_unlock(psk->mutex_lock);
}

static int picotcp_connect(struct socket *sock, struct sockaddr *_saddr, int socklen, int flags)
{
  struct picotcp_sock *psk = picotcp_sock(sock);
  union pico_address addr;
  uint8_t port;
  uint16_t ev;
  int err;
  printk("Called connect\n");

  if (bsd_to_pico_addr(&addr, _saddr, socklen) < 0) {
      printk("Connect: invalid address\n");
      return -EINVAL;
  }

  port = bsd_to_pico_port(_saddr, socklen);
  if (port == 0) {
      printk("Connect: invalid port\n");
      return -EINVAL;
  }

  printk("Calling pico_socket_connect\n");
  pico_mutex_lock(picoLock);
  err = pico_socket_connect(psk->pico, &addr, port);
  pico_mutex_unlock(picoLock);
  printk("Calling pico_socket_connect: done\n");

  if (err) {
    return 0 - pico_err;
  }

  if (psk->nonblocking) {
      return -EAGAIN;
  } else {
      /* wait for event */
      printk("Trying to establish connection...\n");
      ev = pico_bsd_wait(psk, 0, 0, 0); /* wait for ERR, FIN and CONN */
  }

  if(ev & PICO_SOCK_EV_CONN)
  {
      /* clear the EV_CONN event */
      printk("Connected\n");
      pico_event_clear(psk, PICO_SOCK_EV_CONN);
      return 0;
  } else {
      pico_socket_close(psk->pico);
  }
  return -EINTR;
}

static int picotcp_bind(struct socket *sock, struct sockaddr *local_addr, int socklen)
{
   union pico_address addr;
   struct picotcp_sock *psk = picotcp_sock(sock);
   uint16_t port;
   printk("Called bind\n");
   if (bsd_to_pico_addr(&addr, local_addr, socklen) < 0) {
        printk("bind: invalid address\n");
        return -EINVAL;
    }
    port = bsd_to_pico_port(local_addr, socklen);
    /* No check for port, if == 0 use autobind */

    pico_mutex_lock(picoLock);
    if(pico_socket_bind(psk->pico, &addr, &port) < 0)
    {
        pico_mutex_unlock(picoLock);
        printk("bind: failed\n");
        return 0 - pico_err;
    }

    psk->state = SOCK_BOUND;
    pico_mutex_unlock(picoLock);
    printk("Bind: success\n");
    return 0;
}

static int picotcp_accept(struct socket *sock, struct socket *newsock, int flags)
{
    struct picotcp_sock *psk = picotcp_sock(sock);
    struct picotcp_sock *newpsk = picotcp_sock(newsock);
    uint16_t events = psk->revents;
    union pico_address picoaddr;
    uint16_t port;
    if (!psk || !newpsk)
        return -EINVAL;

    if (psk->state != SOCK_LISTEN)
        return -EOPNOTSUPP;


    pico_mutex_lock(picoLock);

    newpsk->state = SOCK_OPEN;
    newpsk->mutex_lock = pico_mutex_init();

    pico_mutex_unlock(picoLock);

    if(events & PICO_SOCK_EV_CONN)
    {
        pico_mutex_lock(picoLock);
        newpsk->pico = pico_socket_accept(psk->pico,&picoaddr,&port);
        if (!newpsk->pico)
        {
            pico_mutex_unlock(picoLock);
            return  0 - pico_err;
        }
        pico_event_clear(psk, PICO_SOCK_EV_CONN); /* clear the CONN event the listening socket */
        newpsk->state = SOCK_CONNECTED;
        newpsk->sk.sk_state = TCP_ESTABLISHED;

        /* Use this to copy the origin address if needed 
        if (newpsk->pico->net->proto_number == PICO_PROTO_IPV4)
            *socklen = SOCKSIZE;
        else
            *socklen = SOCKSIZE6;
        if (pico_addr_to_bsd(_orig, *socklen, &picoaddr, newpsk->s->net->proto_number) < 0) {
            pico_mutex_unlock(picoLock);
            return -1;
        }
        pico_port_to_bsd(_orig, *socklen, port);
        */
        newpsk->in_use = 1;
        pico_mutex_unlock(picoLock);
        return 0;
    }
    return -EAGAIN;
}


static int picotcp_listen(struct socket *sock, int backlog)
{
  struct picotcp_sock *psk = picotcp_sock(sock);
  int err;
  struct sock *sk = sock->sk;
  printk("Called listen()\n");
  sk->sk_state = TCP_LISTEN;
  pico_mutex_lock(picoLock);
  err = pico_socket_listen(psk->pico, backlog);
  pico_mutex_unlock(picoLock);

  if (err)
      return 0 - pico_err;

  printk("Listen: success\n");
  return 0;
}


static struct proto picotcp_proto = {
  .name = "INET",
  .owner = THIS_MODULE,
  .obj_size = sizeof(struct picotcp_sock),
};

static int picotcp_release(struct socket *sock)
{
  struct picotcp_sock *psk = picotcp_sock(sock);
  if (!psk)
    return -EINVAL;
  printk("Called picotcp_release()\n");
  pico_mutex_lock(picoLock);
  pico_socket_close(psk->pico);
  pico_mutex_unlock(picoLock);
  mutex_destroy(psk->mutex_lock);
  sock_orphan(sock->sk);
  return 0;
}


/* IOCTLs */
static int picotcp_gifconf(struct socket *sock, unsigned int cmd, unsigned long arg);
static int picotcp_iosgflags(struct socket *sock, unsigned int cmd, unsigned long arg, int set);
static int picotcp_iosgmac(struct socket *sock, unsigned int cmd, unsigned long arg, int set);
static int picotcp_iosgmtu(struct socket *sock, unsigned int cmd, unsigned long arg, int set);
static int picotcp_iosgaddr(struct socket *sock, unsigned int cmd, unsigned long arg, int set);
static int picotcp_iosgbrd(struct socket *sock, unsigned int cmd, unsigned long arg, int set);
static int picotcp_iosgmask(struct socket *sock, unsigned int cmd, unsigned long arg, int set);

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

const struct proto_ops picotcp_proto_ops = {
	.family		   = PF_INET,
	.owner		   = THIS_MODULE,
	.release	   = picotcp_release,
	.ioctl		   = picotcp_ioctl,
	.connect	   = picotcp_connect,
	.bind		     = picotcp_bind,
	.listen		   = picotcp_listen,
	.accept		   = picotcp_accept,
#if 0
	.socketpair	   = sock_no_socketpair,
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


static int picotcp_create(struct net *net, struct socket *sock, int protocol, int kern)
{
  struct picotcp_sock *psk;
  struct pico_socket *ps;
  struct sock *sk;

  sock->ops = &picotcp_proto_ops;

  ps = pico_socket_open(PICO_PROTO_IPV4, protocol, picotcp_socket_event);

  sk = sk_alloc(net, PF_INET, GFP_KERNEL, &picotcp_proto);
  if (!sk) {
    return -ENOMEM;
  }
  psk = (struct picotcp_sock *) sk;

  sock->sk = sk;
  psk->pico = ps;

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
