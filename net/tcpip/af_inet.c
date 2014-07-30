/* Linux kernel osal implementation  */
#include <picotcp.h>

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

static int picotcp_shutdown(struct socket *sock, int how)
{
    struct picotcp_sock *psk = picotcp_sock(sock);
    printk("Called picotcp_shutdown\n");
    if(psk->pico) /* valid socket, try to close it */
    {
        pico_mutex_lock(picoLock);
        pico_socket_shutdown(psk->pico, how);
        pico_mutex_unlock(picoLock);
    }
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



const struct proto_ops picotcp_proto_ops = {
	.family		   = PF_INET,
	.owner		   = THIS_MODULE,
	.release	   = picotcp_release,
	.ioctl		   = picotcp_ioctl,
	.connect	   = picotcp_connect,
	.bind		     = picotcp_bind,
	.listen		   = picotcp_listen,
	.accept		   = picotcp_accept,
	.socketpair	 = sock_no_socketpair,
	.setsockopt	 = sock_common_setsockopt,
	.getsockopt	 = sock_common_getsockopt,
	.shutdown	   = picotcp_shutdown,
	.mmap		     = sock_no_mmap,
#if 0
	.getname	   = pico_getname,
	.poll		     = pico_poll,
	.listen		   = pico_listen,
	.sendmsg	   = pico_sendto,
	.recvmsg	   = pico_recvfrom,
	.sendpage	   = pico_sendpage,
	.splice_read = tcp_splice_read,
#endif
};
EXPORT_SYMBOL(picotcp_proto_ops);




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

static int __net_init picotcp_net_init(struct net *net)
{
  return 0;
}

static void __net_exit picotcp_net_exit(struct net *net)
{

}

static const struct net_proto_family picotcp_family_ops = {
  .family = PF_INET,
  .create = picotcp_create,
  .owner  = THIS_MODULE,
};

static struct pernet_operations picotcp_net_ops = {
  .init = picotcp_net_init,
  .exit = picotcp_net_exit,
};

int af_inet_picotcp_init(void)
{
  int rc = proto_register(&picotcp_proto, 1);
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


MODULE_ALIAS_NETPROTO(PF_INET);

