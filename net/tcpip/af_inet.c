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
        printk("Found IPv4, port is %hu\n", short_be(saddr->sin_port));
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
  volatile uint16_t revents;         /* received events */
  uint16_t proto;
  void *   mutex_lock;      /* mutex for clearing revents */
  struct net *net;          /* Network */
  uint32_t timeout;         /* this is used for timeout sockets */
  wait_queue_head_t wait;    /* Signal queue */
};

#define picotcp_sock(x) ((struct picotcp_sock *)x->sk)
#define psk_lock(x) pico_mutex_lock(x->mutex_lock)
#define psk_unlock(x) pico_mutex_unlock(x->mutex_lock)

static struct proto picotcp_proto = {
  .name = "INET",
  .owner = THIS_MODULE,
  .obj_size = sizeof(struct picotcp_sock),
};

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
    printk("Called SELECT\n");
    /* wait for one of the selected events... */
    prepare_to_wait(sk_sleep(&psk->sk), &wait, TASK_INTERRUPTIBLE);
    while (!events)
    {
        events = (psk->revents & psk->events); /* filter for the events we were waiting for */
        if (!events)
          schedule();
        if (signal_pending(current)) {
          psk->revents = PICO_SOCK_EV_ERR;
          break;
        }
    }
    finish_wait(sk_sleep(&psk->sk), &wait);
    printk("SELECT: wakeup!\n");
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

static unsigned int picotcp_poll(struct file *file, struct socket *sock, poll_table *wait)
{
  struct picotcp_sock *psk = picotcp_sock(sock);
  struct sock *sk = sock->sk;
  unsigned int mask = 0;

  sock_poll_wait(file, sk_sleep(sk), wait);

  psk_lock(psk);
  if (sk->sk_err)
    mask |= POLLERR;
  if (psk->revents & PICO_SOCK_EV_CLOSE)
    mask |= POLLHUP;
  if (psk->revents & PICO_SOCK_EV_RD)
    mask |= POLLIN;
  if (psk->revents & PICO_SOCK_EV_WR)
    mask |= POLLOUT;
  psk_unlock(psk);

  return mask;
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

    if (psk->sk.sk_err)
    {
        ev = PICO_SOCK_EV_ERR | (psk->sk.sk_err << 8); 

    }

    printk("An event will be parsed! ev value is %hu\n", ev);

    if(psk->in_use != 1)
        return;


    psk_lock(psk);
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
        dbg("Connection reset...\n");
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
    printk("Waking up all the selects...\n");
    wake_up_interruptible(sk_sleep(&psk->sk));
    psk_unlock(psk);
}

static int picotcp_connect(struct socket *sock, struct sockaddr *_saddr, int socklen, int flags)
{
  struct picotcp_sock *psk = picotcp_sock(sock);
  union pico_address addr;
  uint16_t port;
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

static struct picotcp_sock *picotcp_sock_new(struct sock *parent, struct net *net, int protocol)
{
  struct picotcp_sock *psk;
  struct sock *sk;

  if (!parent)
    sk = sk_alloc(net, PF_INET, GFP_ATOMIC, &picotcp_proto);
  else
    sk = sk_clone_lock(parent, GFP_ATOMIC);
  if (!sk) {
    return NULL;
  }
  psk = (struct picotcp_sock *) sk;
  psk->mutex_lock = pico_mutex_init();

  psk->nonblocking = 0;
  psk->net = net;
  psk->state = SOCK_OPEN;
  psk->in_use = 0;
  psk->events = 0;
  psk->revents = 0;
  psk->proto = protocol;

  return psk;
}

static int picotcp_getname(struct socket *sock, struct sockaddr * local_addr, int *socklen, int peer)
{ 
    struct picotcp_sock *psk = picotcp_sock(sock);
    union pico_address addr;
    uint16_t port, proto;

    pico_mutex_lock(picoLock);
    if(pico_socket_getname(psk->pico, &addr, &port, &proto) < 0)
    {
        pico_mutex_unlock(picoLock);
        return -EFAULT;
    }

    if (proto == PICO_PROTO_IPV6)
        *socklen = SOCKSIZE6;
    else
        *socklen = SOCKSIZE;

    if (pico_addr_to_bsd(local_addr, *socklen, &addr, proto) < 0) {
        pico_mutex_unlock(picoLock);
        return -1;
    }
    pico_port_to_bsd(local_addr, *socklen, port);
    return 0;
}


static int picotcp_accept(struct socket *sock, struct socket *newsock, int flags)
{
    struct picotcp_sock *psk = picotcp_sock(sock);
    struct picotcp_sock *newpsk;
    uint16_t events;
    union pico_address picoaddr;
    uint16_t port;

    printk("Called ACCEPT\n");

    if (psk->state != SOCK_LISTEN) {
        printk("Invalid socket state, not listening\n");
        return -EOPNOTSUPP;
    }

    printk("Going to sleep...\n");

    if (psk->nonblocking)
      events = PICO_SOCK_EV_CONN;
    else
      events = pico_bsd_wait(psk, 0, 0, 0);

    printk("ACCEPT resumed\n");

    /* Here I check for psk again, to avoid races */
    if (!psk || !psk->in_use)
        return -EINTR;

    if(events & PICO_SOCK_EV_CONN)
    {
        struct pico_socket *ps;
        pico_mutex_lock(picoLock);
        psk_lock(psk);
        ps = pico_socket_accept(psk->pico,&picoaddr,&port);
        psk_unlock(psk);
        if (!ps)
        {
            pico_mutex_unlock(picoLock);
            return  0 - pico_err;
        }
        pico_event_clear(psk, PICO_SOCK_EV_CONN); /* clear the CONN event the listening socket */
        newpsk = picotcp_sock_new(&psk->sk, psk->net, psk->proto);
        if (!psk) {
          pico_mutex_unlock(picoLock);
          pico_socket_close(ps);
          return -ENOMEM;
        }
        sock_init_data(newsock, &newpsk->sk);
        newsock->sk = &newpsk->sk;
        newsock->state = SS_CONNECTED;
        newpsk->state = SOCK_CONNECTED;
        newpsk->sk.sk_state = TCP_ESTABLISHED;
        newpsk->pico = ps;
        ps->priv = newsock;
        newpsk->in_use = 1;
        sock_graft(&newpsk->sk, newsock);
        pico_mutex_unlock(picoLock);
        printk("ACCEPT: SUCCESS!\n");
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
  psk->state = SOCK_LISTEN;
  return 0;
}

static int picotcp_sendmsg(struct kiocb *cb, struct socket *sock,
             struct msghdr *msg, size_t len)
{
    struct picotcp_sock *psk = picotcp_sock(sock);
    struct sock_iocb *siocb = kiocb_to_siocb(cb);
    struct scm_cookie tmp_scm;
    int tot_len = 0, err;
    union pico_address _addr, *addr = NULL;
    uint16_t port = 0;
    uint8_t *kbuf;

    printk("Called picotcp_sendmsg\n");

    if (len <= 0)
      return -EINVAL;

    if (!siocb->scm) {
      siocb->scm= &tmp_scm;
      memset(&tmp_scm, 0, sizeof(tmp_scm));
    }

    kbuf = kmalloc(len, GFP_ATOMIC);
    if (!kbuf)
      return -ENOMEM;

    err = scm_send(sock, msg, siocb->scm, false);
    if (err < 0)
      return err;

    if (msg->msg_namelen) {
      bsd_to_pico_addr(&_addr, msg->msg_name, msg->msg_namelen);
      port = bsd_to_pico_port(msg->msg_name, msg->msg_namelen);
      addr = &_addr;
      printk("Address is copied\n");
    }

    memcpy_fromiovec(kbuf, msg->msg_iov, len);


    while (tot_len < len) {
      int r;
      psk_lock(psk);
      r = pico_socket_sendto(psk->pico, kbuf, len, &addr, port);
      psk_unlock(psk);
      printk("> sendto returned %d - expected len is %d\n", r, len);
      if (r < 0) {
        kfree(kbuf);
        return 0 - pico_err;
      }

      tot_len += r;

      pico_event_clear(psk, PICO_SOCK_EV_WR);
      if ((tot_len > 0) && psk->proto == PICO_PROTO_UDP)
          break;

      if (tot_len < len) {
        uint16_t ev = 0;
        ev = pico_bsd_wait(psk, 0, 1, 1);
        if ((ev & (PICO_SOCK_EV_ERR | PICO_SOCK_EV_FIN | PICO_SOCK_EV_CLOSE)) || (ev == 0)) {
            pico_event_clear(psk, PICO_SOCK_EV_WR);
            pico_event_clear(psk, PICO_SOCK_EV_ERR);
            kfree(kbuf);
            return -EINTR;
        }
      }
    }

    printk("About to return from sendmsg. tot_len is %d\n", tot_len);
    kfree(kbuf);
    return tot_len;
}

#pragma GCC push_options
static int picotcp_recvmsg(struct kiocb *cb, struct socket *sock,
             struct msghdr *msg, size_t len, int flags)
{
    struct picotcp_sock *psk = picotcp_sock(sock);
    struct sock_iocb *siocb = kiocb_to_siocb(cb);
    struct sock *sk = sock->sk;
    struct scm_cookie tmp_scm;
    int tot_len = 0, skip;
    uint8_t *kbuf;
    union pico_address addr;
    uint16_t port;
    printk("Called picotcp_recvmsg\n");
    skip = sk_peek_offset(sk, flags);

    if ((len - skip) < 1)
      return -EINVAL;

    kbuf = kmalloc(len, GFP_ATOMIC);
    if (!kbuf)
      return -ENOMEM;

    while (tot_len < len - skip) {
      int r;
      psk_lock(psk);
      r = pico_socket_recvfrom(psk->pico, kbuf, len - skip, &addr, &port);
      psk_unlock(psk);
      printk("> recvfrom returned %d - expected len is %d skip is %d\n", r, len - skip, skip);
      if (r < 0) {
        kfree(kbuf);
        return 0 - pico_err;
      }

      tot_len += r;

      if (r == 0) {
        pico_event_clear(psk, PICO_SOCK_EV_RD);
        pico_event_clear(psk, PICO_SOCK_EV_ERR);
        if (tot_len > 0) {
          printk("recvfrom returning %d\n", tot_len);
          goto recv_success;
        }
      }
      if ((tot_len > 0) && psk->proto == PICO_PROTO_UDP)
        goto recv_success;

      if (tot_len < (len - skip)) {
        uint16_t ev = 0;
        ev = pico_bsd_wait(psk, 1, 0, 1);
        if ((ev & (PICO_SOCK_EV_ERR | PICO_SOCK_EV_FIN | PICO_SOCK_EV_CLOSE)) || (ev == 0)) {
            pico_event_clear(psk, PICO_SOCK_EV_RD);
            pico_event_clear(psk, PICO_SOCK_EV_ERR);
            kfree(kbuf);
            return -EINTR;
        }
      }
    }

recv_success:
    printk("About to return from recvmsg. tot_len is %d\n", tot_len);
    if (msg->msg_name) {
      pico_addr_to_bsd(msg->msg_name, msg->msg_namelen, &addr, PICO_PROTO_IPV4);
      pico_port_to_bsd(msg->msg_name, msg->msg_namelen, port);
      printk("Address is copied\n");
    }
    if (memcpy_toiovec(msg->msg_iov, kbuf + skip, tot_len))
      return -EFAULT;

    kfree(kbuf);
    if (!siocb->scm) {
      siocb->scm= &tmp_scm;
      memset(&tmp_scm, 0, sizeof(tmp_scm));
    }
    scm_recv(sock, msg, siocb->scm, flags);
    printk("Returning from recvmsg\n");
    return tot_len;
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


static int picotcp_release(struct socket *sock)
{
  struct picotcp_sock *psk = picotcp_sock(sock);
  if (!psk)
    return -EINVAL;
  printk("Called picotcp_release()\n");
  pico_mutex_lock(picoLock);
  psk_lock(psk);
  pico_socket_close(psk->pico);
  psk_unlock(psk);
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
	.getname     = picotcp_getname,
	.accept		   = picotcp_accept,
	.shutdown	   = picotcp_shutdown,
	.poll		     = picotcp_poll,

	.mmap		     = sock_no_mmap,
	.socketpair	 = sock_no_socketpair,
  .sendpage    = sock_no_sendpage,

	.setsockopt	 = sock_common_setsockopt,
	.getsockopt	 = sock_common_getsockopt,
	.sendmsg	   = picotcp_sendmsg,
	.recvmsg	   = picotcp_recvmsg,
};
EXPORT_SYMBOL(picotcp_proto_ops);




static int picotcp_create(struct net *net, struct socket *sock, int protocol, int kern)
{
  struct picotcp_sock *psk;
  struct pico_socket *ps;

  printk("Called picotcp_create\n");

  sock->ops = &picotcp_proto_ops;

  printk("Selected socket type: %d\n", sock->type);
  printk("Selected protocol: %d\n", protocol);

  /* Convert IP sockets into DGRAM, so ioctl are still possible (e.g.: ifconfig) */
  if (sock->type == SOCK_DGRAM)
    protocol = IPPROTO_UDP;
  else
    protocol = IPPROTO_TCP;


  ps = pico_socket_open(PICO_PROTO_IPV4, protocol, picotcp_socket_event);
  if (!ps) 
    return 0 - pico_err;

  psk = picotcp_sock_new(NULL, net, protocol);
  if (!psk)
    return -ENOMEM;
  sock_init_data(sock, &psk->sk);
  sock->sk = &psk->sk;
  psk->pico = ps;
  ps->priv = psk;
  psk->in_use = 1;
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
