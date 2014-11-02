#include "pico_device.h"
#include "pico_stack.h"
#include <picotcp.h>
#include <linux/types.h>
#include <linux/socket.h>
#include <linux/wait.h>

volatile int pico_stack_is_ready;
static struct workqueue_struct *picotcp_workqueue;
static struct delayed_work picotcp_work;
wait_queue_head_t picotcp_stack_init_wait;

extern int ip_route_proc_init(void);

static void picotcp_tick(struct work_struct *unused)
{
    (void)unused;
    if (pico_stack_is_ready) {
        pico_bsd_stack_tick();
    }
    queue_delayed_work(picotcp_workqueue, &picotcp_work, PICOTCP_INTERVAL);
}

/* Stack Init Functions */
int __init picotcp_init(void)
{
    init_waitqueue_head(&picotcp_stack_init_wait);
    if (pico_stack_init() < 0)
        panic("Unable to start picoTCP\n");
    pico_bsd_init();
    picotcp_workqueue = create_singlethread_workqueue("picotcp_tick");
    INIT_DELAYED_WORK(&picotcp_work, picotcp_tick);
    printk("PicoTCP created.\n");
    queue_delayed_work(picotcp_workqueue, &picotcp_work, PICOTCP_INTERVAL);
    pico_stack_is_ready++;
    wake_up_interruptible_all(&picotcp_stack_init_wait);

    af_inet_picotcp_init();
    if (ip_route_proc_init() < 0)
      printk("Failed initializing /proc/net/route\n");
    return 0;
}
fs_initcall(picotcp_init);
