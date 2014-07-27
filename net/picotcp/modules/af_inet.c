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

#include <asm/uaccess.h>

#include <linux/inetdevice.h>
#include <linux/netdevice.h>
static volatile int pico_stack_is_ready;
#define PICOTCP_INTERVAL (5)

#pragma GCC push_options
#pragma GCC optimize("O0")


static DEFINE_SPINLOCK(picotcp_spin);
#ifdef ONE_TASK_PICOTCP
static struct task_struct *kpicotcpd_task; 

/* Stack main thread */
static int picotcp_main_thread(void *unused)
{
    unsigned long now;
    printk(KERN_INFO "Starting TCP/IP stack.");
    if (pico_stack_init() < 0)
        return -1;

    pico_stack_is_ready++;

    now = jiffies;

    for(;;) {
        set_current_state(TASK_INTERRUPTIBLE);
        schedule();
        if (now + PICOTCP_INTERVAL < jiffies) {
            set_current_state(TASK_RUNNING);
            now = jiffies;
            pico_stack_tick();
        }
    }
    return 0;
}
#endif

static struct timer_list picotcp_tick_timer;
static struct tasklet_struct picotcp_tick_task;


/* Device related */

struct pico_device_linux {
    struct pico_device dev;
    struct net_device *netdev;
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
    printk("%s: network send called (%d bytes)\n", lnx->netdev->name, len);
    rcu_read_lock();

    //skb = netdev_alloc_skb(lnx->netdev, len);
    skb = __netdev_alloc_skb(lnx->netdev, len, GFP_DMA);
    if (!skb)
        goto fail_unlock;
    skb->dev = ((struct pico_device_linux*)dev)->netdev;
    start_buf = skb_put(skb, len);
    if (!start_buf) {
      printk("failed skb_put!\n");
      goto fail_free;
    }
    memcpy(start_buf, buf, len);
    if (!pico_stack_is_ready) {
        printk("network send: stack not ready\n");
        goto fail_free;
    }

    if (!lnx->netdev || !lnx->netdev->netdev_ops || !lnx->netdev->netdev_ops->ndo_start_xmit) {
        printk("network send: device %s not ready\n", lnx->netdev->name);
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
      printk("Error queuing TX frame!\n");
      goto fail_free;
    }
    rcu_read_unlock();
    printk("network send: done!\n");
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
    printk("%s:network recv (%d B)\n", lnx->netdev->name, skb->len);
    pico_stack_recv(&lnx->dev, skb->data, skb->len);
    return RX_HANDLER_CONSUMED;
}

struct timer_list picotcp_dev_attach_retry_timer;
void pico_dev_attach(struct net_device *netdev);

static void picotcp_dev_attach_retry(unsigned long x)
{
    if (!pico_stack_is_ready) {
        picotcp_dev_attach_retry_timer.expires = jiffies + msecs_to_jiffies(PICOTCP_INTERVAL* 4);
        picotcp_dev_attach_retry_timer.function = picotcp_dev_attach_retry;
        picotcp_dev_attach_retry_timer.data = x;
        add_timer(&picotcp_dev_attach_retry_timer);
    } else {
        struct net_device *netdev = (struct net_device *)x;
        pico_dev_attach(netdev);
    }
}

void pico_dev_attach(struct net_device *netdev)
{
    struct pico_device_linux *pico_linux_dev = PICO_ZALLOC(sizeof(struct pico_device_linux));
    uint8_t *macaddr = NULL;
    const uint8_t macaddr_zero[6] = {0, 0, 0, 0, 0, 0};


    if (!netdev)
        return;
    
    if (!pico_stack_is_ready) {
        init_timer(&picotcp_dev_attach_retry_timer);
        picotcp_dev_attach_retry_timer.expires = jiffies + msecs_to_jiffies(PICOTCP_INTERVAL * 4);
        picotcp_dev_attach_retry_timer.function = picotcp_dev_attach_retry;
        picotcp_dev_attach_retry_timer.data = (unsigned long)netdev;
        add_timer(&picotcp_dev_attach_retry_timer);
        return;
    }

    if (!pico_linux_dev)
        panic("Unable to initialize network device\n"); 

    if (memcmp(netdev->dev_addr, macaddr_zero, 6) != 0) {
        macaddr = (uint8_t *) netdev->dev_addr;
    }

    spin_lock(&picotcp_spin);
    if( 0 != pico_device_init(&pico_linux_dev->dev, netdev->name, macaddr)) {
        spin_unlock(&picotcp_spin);
        return;
    }

    pico_linux_dev->netdev = netdev;
    pico_linux_dev->dev.send = pico_linux_send;
    if (netdev_rx_handler_register(netdev, pico_linux_recv, NULL) < 0) {
        printk("%s: unable to register for RX events\n", netdev->name);
    }

#ifdef CONFIG_NET_POLL_CONTROLLER
    pico_linux_dev->dev.poll = pico_linux_poll;
#endif
    dbg("Device %s created.\n", pico_linux_dev->dev.name);
    netdev->picodev = &pico_linux_dev->dev;

/* 
    if (netdev->netdev_ops)
      dev_set_mtu(netdev, 1500);
*/

    /* TEST: Eth0 has hardcoded ip address */
    if (strcmp(netdev->name, "eth0") == 0) {
        struct pico_ip4 pico_test_addr;
        struct pico_ip4 pico_test_mask;
        pico_string_to_ipv4("10.99.0.6", &pico_test_addr.addr);
        pico_string_to_ipv4("255.255.255.0", &pico_test_mask.addr);
        pico_ipv4_link_add(&pico_linux_dev->dev, pico_test_addr, pico_test_mask);
    }
    spin_unlock(&picotcp_spin);

}

static void picotcp_timeout_tick(unsigned long unused)
{
    (void)unused;
    tasklet_schedule(&picotcp_tick_task);
    picotcp_tick_timer.expires = jiffies + msecs_to_jiffies(PICOTCP_INTERVAL);
    add_timer(&picotcp_tick_timer);
}
static void picotcp_tick(unsigned long unused)
{
    (void)unused;
    if (pico_stack_is_ready) {
        spin_lock(&picotcp_spin);
        pico_stack_tick();
        spin_unlock(&picotcp_spin);
    }
}

/* Stack Init Functions */
int __init picotcp_init(void)
{
    if (pico_stack_init() < 0)
        panic("Unable to start picoTCP\n");
    pico_stack_is_ready++;
    init_timer(&picotcp_tick_timer);
    picotcp_tick_timer.expires = jiffies + msecs_to_jiffies(PICOTCP_INTERVAL);
    picotcp_tick_timer.function = picotcp_timeout_tick;
    tasklet_init(&picotcp_tick_task, picotcp_tick, 0);
    add_timer(&picotcp_tick_timer);
    printk("Task PicoTCP created.\n");


    return 0;
}
fs_initcall(picotcp_init);

/* AF_INET SOCKET INTERFACE (WIP) */

static int picotcp_create(struct net *net, struct socket *sock, int protocol, int kern)
{
    /* TODO: Attach socket interface */
    return 0;
}


static const struct net_proto_family picotcp_family_ops = {
  .family = PF_INET,
  .create = picotcp_create,
  .owner  = THIS_MODULE,
};

MODULE_ALIAS_NETPROTO(PF_INET);
#pragma GCC pop_options
