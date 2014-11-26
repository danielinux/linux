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
static struct workqueue_struct* pico_net_dev_init_workqueue;
static struct pico_netdev_work net_device_init;

#define netdev_debug(...) do{}while(0)


/* Device related */

struct pico_device_linux {
    struct pico_device dev;
    struct net_device *netdev;
};


struct pico_netdev_work
{
	struct delayed_work work;
	struct net_device* netdev;
};

#ifdef CONFIG_NET_POLL_CONTROLLER
}static int pico_linux_poll(struct pico_device *dev, int loop_score)
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
      skb->mac_header = skb->data - skb->head;
      skb->network_header = skb->mac_header + 14;
    } else {
      skb->network_header = skb->data - skb->head;
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

static rx_handler_result_t pico_linux_recv(struct sk_buff **pskb)
{
  struct sk_buff *skb = *pskb;
    struct pico_device_linux *lnx;
    BUG_ON(!skb);
    BUG_ON(!skb->dev);
    lnx = (struct pico_device_linux *)skb->dev->picodev;
    netdev_debug("%s:network recv (%d B)\n", lnx->netdev->name, skb->len);
    pico_stack_recv(&lnx->dev, skb->data, skb->len);
    return RX_HANDLER_CONSUMED;
}




void pico_dev_attach(struct net_device *netdev);


void cleanup_workqueue(void) {
	flush_workqueue(pico_net_dev_init_workqueue);
	destroy_workqueue(pico_net_dev_init_workqueue);
}


static void picotcp_dev_attach_retry(struct work_struct *todo)
{
	if (!pico_stack_is_ready) {
		queue_delayed_work(pico_net_dev_init_workqueue, &(net_device_init.work), sysctl_picotcp_dutycycle);
		return;
	}

	struct pico_netdev_work* temp;
    struct net_device* netdev;

	temp= container_of(todo, struct pico_netdev_work, work);
	netdev= temp->netdev;

	rtnl_lock();
	pico_dev_attach(netdev);
	rtnl_unlock();

}



void pico_dev_attach(struct net_device *netdev)
{
    struct pico_device_linux *pico_linux_dev = PICO_ZALLOC(sizeof(struct pico_device_linux));
    uint8_t *macaddr = NULL;
    const uint8_t macaddr_zero[6] = {0, 0, 0, 0, 0, 0};

    if (!netdev)
        return;

    if (!pico_stack_is_ready) {
		pico_net_dev_init_workqueue= create_singlethread_workqueue("picotcp_dev_attach_retry");
		if (pico_net_dev_init_workqueue) {
			INIT_DELAYED_WORK(&(net_device_init.work), picotcp_dev_attach_retry);
			net_device_init.netdev =netdev;

			queue_delayed_work(pico_net_dev_init_workqueue, &(net_device_init.work), sysctl_picotcp_dutycycle);

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

    pico_linux_dev->netdev = netdev;
    pico_linux_dev->dev.send = pico_linux_send;
    if (netdev_rx_handler_register(netdev, pico_linux_recv, NULL) < 0) {
        netdev_debug("%s: unable to register for RX events\n", netdev->name);
    }

#ifdef CONFIG_NET_POLL_CONTROLLER
    pico_linux_dev->dev.poll = pico_linux_poll;
#endif
    dbg("Device %s created.\n", pico_linux_dev->dev.name);
    netdev->picodev = &pico_linux_dev->dev;


	cleanup_workqueue();
}
