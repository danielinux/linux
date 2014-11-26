/*********************************************************************
   PicoTCP. Copyright (c) 2012 TASS Belgium NV. Some rights reserved.
   See LICENSE and COPYING for usage.

   Authors: Daniele Lacamera
 *********************************************************************/


#include "pico_device.h"
#include "pico_stack.h"
#include "pico_ipv4.h"
#include "linux/netdevice.h"
#include "linux/kthread.h"
#include <linux/err.h>
#include <linux/errno.h>
#include <linux/types.h>
#include <linux/socket.h>
#include <linux/in.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/sched.h>
#include <linux/timer.h>
#include <linux/string.h>
#include <linux/sockios.h>
#include <linux/capability.h>
#include <linux/fcntl.h>
#include <linux/mm.h>
#include <linux/interrupt.h>
#include <linux/stat.h>
#include <linux/init.h>
#include <linux/poll.h>
#include <linux/random.h>
#include <linux/slab.h>
#include <picotcp.h>

#include <asm/uaccess.h>

#include <linux/inetdevice.h>
#include <linux/netdevice.h>

#include <net/sock.h>

extern volatile int pico_stack_is_ready;
extern int sysctl_picotcp_dutycycle;

#define netdev_debug(...) do{}while(0)
//#define netdev_debug printk


/* Device related */
struct pico_device_linux;

struct pico_netdev_work
{
	struct delayed_work work;
	struct pico_device_linux* pico;
};


struct pico_device_linux {
    struct pico_device dev;
    struct net_device *netdev;
    struct workqueue_struct* wqueue;
    struct pico_netdev_work net_init;
};



#ifdef CONFIG_NET_POLL_CONTROLLER
static int pico_linux_poll(struct pico_device *dev, int loop_score)
{
    struct pico_device_linux *lnx = (struct pico_device_linux *) dev;
    if (!lnx || !lnx->netdev || !lnx->netdev->netdev_ops)
        return loop_score;
    if (lnx->netdev->netdev_ops->ndo_poll_controller) {
        lnx->netdev->netdev_ops->ndo_poll_controller(lnx->netdev);
    }
    return --loop_score;
}
#endif


static int pico_linux_send(struct pico_device *dev, void *buf, int len)
{
    struct pico_device_linux *lnx = (struct pico_device_linux *) dev;
    struct sk_buff *skb;
    uint8_t *start_buf;
    netdev_debug("%s: network send called (%d bytes)\n", lnx->netdev->name, len);
    rcu_read_lock();

    //skb = netdev_alloc_skb(lnx->netdev, len);
    skb = __netdev_alloc_skb(lnx->netdev, len, GFP_DMA);
    if (!skb)
        goto fail_unlock;
    skb->dev = ((struct pico_device_linux*)dev)->netdev;
    start_buf = skb_put(skb, len);
    if (!start_buf) {
      netdev_debug("failed skb_put!\n");
      goto fail_free;
    }
    memcpy(start_buf, buf, len);
    if (!pico_stack_is_ready) {
        netdev_debug("network send: stack not ready\n");
        goto fail_free;
    }

    if (!lnx->netdev || !lnx->netdev->netdev_ops || !lnx->netdev->netdev_ops->ndo_start_xmit) {
        netdev_debug("network send: device %s not ready\n", lnx->netdev->name);
        goto fail_free;
    }
    if (dev->eth) {
      skb->mac_header = (sk_buff_data_t) (skb->data - skb->head);
      skb->network_header = (sk_buff_data_t)(skb->mac_header + 14);
    } else {
      skb->network_header = (sk_buff_data_t)(skb->data - skb->head);
    }

    /* Deliver the packet to the device driver */
    if (NETDEV_TX_OK != dev_queue_xmit(skb)) {
      netdev_debug("Error queuing TX frame!\n");
      goto fail_free;
    }
    rcu_read_unlock();
    netdev_debug("network send: done!\n");
    return len;

fail_free:
    kfree_skb(skb);
fail_unlock:
    rcu_read_unlock();
    return 0;
}

void pico_dev_attach(struct net_device *netdev);


void cleanup_workqueue(struct pico_device_linux *pico) {
    if (pico && pico->wqueue) {
	    flush_workqueue(pico->wqueue);
	    destroy_workqueue(pico->wqueue);
    }
}


static void picotcp_dev_attach_retry(struct work_struct *todo)
{
	struct pico_netdev_work *temp;
    struct delayed_work *dwork;
    struct pico_device_linux *pico;

    dwork = to_delayed_work(todo);
	temp = container_of(dwork, struct pico_netdev_work, work);
    pico = temp->pico;

	if (!pico_stack_is_ready) {
	    printk("Stack still not ready. Device %s will be attached later.\n", pico->netdev->name);
		queue_delayed_work(pico->wqueue, &(pico->net_init.work), 100 * sysctl_picotcp_dutycycle);
		return;
	}

	rtnl_lock();
	pico_dev_attach(pico->netdev);
	rtnl_unlock();
    printk("Cleaning up workqueue\n");
	cleanup_workqueue(pico);

}



void pico_dev_attach(struct net_device *netdev)
{
    struct pico_device_linux *pico_linux_dev = PICO_ZALLOC(sizeof(struct pico_device_linux));
    uint8_t *macaddr = NULL;
    const uint8_t macaddr_zero[6] = {0, 0, 0, 0, 0, 0};

    if (!netdev)
        return;

    pico_linux_dev->netdev = netdev;

    if (!pico_stack_is_ready) {
	    printk("Stack not ready. Device %s will be attached later.\n", netdev->name);
		pico_linux_dev->wqueue = create_singlethread_workqueue("picotcp_dev_attach_retry");
		if (pico_linux_dev->wqueue) {
			INIT_DELAYED_WORK(&(pico_linux_dev->net_init.work), picotcp_dev_attach_retry);
			pico_linux_dev->net_init.pico = pico_linux_dev;
			queue_delayed_work(pico_linux_dev->wqueue, &(pico_linux_dev->net_init.work), 100 * sysctl_picotcp_dutycycle);

		} else {
			printk("Workqueue for net device init not created. Device %s will not be attached.\n", netdev->name);
		}
		return;
    }


    if (!pico_linux_dev)
        panic("Unable to initialize network device\n");

    if (memcmp(netdev->dev_addr, macaddr_zero, 6) != 0) {
        macaddr = (uint8_t *) netdev->dev_addr;
    }

    if( 0 != pico_device_init(&pico_linux_dev->dev, netdev->name, macaddr)) {
        return;
    }

    pico_linux_dev->dev.send = pico_linux_send;

#ifdef CONFIG_NET_POLL_CONTROLLER
    pico_linux_dev->dev.poll = pico_linux_poll;
#endif
    netdev_debug("Device %s created.\n", pico_linux_dev->dev.name);
    netdev->picodev = &pico_linux_dev->dev;
}
