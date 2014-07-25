/* Linux kernel osal implementation  */
#include "pico_defines.h"
#include "pico_stack.h"
#include <linux/mutex.h>
#include <linux/types.h>
#include <linux/kthread.h>


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

#ifdef PICO_WIP

const struct proto_ops pico_tcp_proto_ops = {
	.family		   = PF_INET,
	.owner		   = THIS_MODULE,
	.release	   = pico_release,
	.bind		   = pico_bind,
	.connect	   = pico_connect,
	.socketpair	   = sock_no_socketpair,
	.accept		   = pico_accept,
	.getname	   = pico_getname,
	.poll		   = pico_poll,
	.ioctl		   = pico_ioctl,
	.listen		   = pico_listen,
	.shutdown	   = pico_shutdown,
	.setsockopt	   = sock_common_setsockopt,
	.getsockopt	   = sock_common_getsockopt,
	.sendmsg	   = pico_sendto,
	.recvmsg	   = pico_recvfrom,
	.mmap		   = sock_no_mmap,
	.sendpage	   = pico_sendpage,
	.splice_read	   = tcp_splice_read,
};
EXPORT_SYMBOL(picotcp_proto_ops);

/* Upon startup we insert all the elements in inetsw_array[] into
 * the linked list inetsw.
 */
static struct inet_protosw inetsw_array[] =
{
	{
		.type =       SOCK_STREAM,
		.protocol =   IPPROTO_TCP,
		.prot =       &tcp_prot,
		.ops =        &picotcp_proto_ops,
		.flags =      INET_PROTOSW_PERMANENT |
			      INET_PROTOSW_ICSK,
	},

	{
		.type =       SOCK_DGRAM,
		.protocol =   IPPROTO_UDP,
		.prot =       &udp_prot,
		.ops =        &picotcp_proto_ops,
		.flags =      INET_PROTOSW_PERMANENT,
       },
};

#define INETSW_ARRAY_LEN ARRAY_SIZE(inetsw_array)
#endif
