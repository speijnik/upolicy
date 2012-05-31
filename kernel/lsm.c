/* lsm.c
 *
 * Copyright (C) 2012 Stephan Peijnik <stephan@peijnik.at>
 *
 * This file is part of upolicy.
 *
 *
 *  upolicy is free software; you can redistribute it and/or
 *  modify it under the terms of the GNU General Public License
 *  as published by the Free Software Foundation; either version 2
 *  of the License, or (at your option) any later version.
 *
 *  upolicy is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with upolicy; if not, write to the Free Software
 *  Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, 
 *  MA  02110-1301, USA.
 */

#include <linux/kthread.h>
#include <linux/list.h>
#include <linux/lsmstub.h>
#include <linux/module.h>
#include <linux/moduleparam.h>
#include <linux/pid.h>
#include <linux/security.h>
#include <linux/semaphore.h>
#include <linux/spinlock.h>

#include <kupolicy/context.h>
#include <kupolicy/handler.h>
#include <kupolicy/netlink.h>
#include <kupolicy/tracee.h>
#include <kupolicy/tracer.h>

static const char* const version = "0.0";
static unsigned int registered = 0;
static struct task_struct *worker_thread;
static struct semaphore worker_semaphore;
static struct semaphore worker_exit_semaphore;
static DEFINE_SPINLOCK(worker_list_lock);
static LIST_HEAD(worker_list);
static int worker_enabled = 0;

static unsigned int debug_flags = UP_DEBUG_FLAG_DEFAULT;
module_param(debug_flags, uint, S_IWUSR|S_IRUGO);

#ifdef UPOLICY_DEBUG
unsigned int up_debug_flags(void) {
	return debug_flags;
}
#endif /* UPOLICY_DEBUG */

struct up_worker_item {
	enum UP_WORKER_ITEM_TYPE type;
	void *data0;
	void *data1;
	struct list_head list;
};

typedef void (*worker_handler_t)(struct up_worker_item *item, int free_only);

#define worker_func_name(name) (worker_handler_ ##name)
#define worker_func(name) static void worker_func_name(name) \
	(struct up_worker_item *item, int free_only)

worker_func(all_tracees_exited);
worker_func(ctx_all_tracees_exited);
worker_func(tracee_exited);

static struct security_operations security_ops = {
  .name = "upolicy",
  .bprm_set_creds = up_bprm_set_creds,
  .cred_free = up_cred_free,
  .cred_prepare = up_cred_prepare,
  .cred_transfer = up_cred_transfer,
  .task_kill = up_task_kill,
  .task_create = up_task_create,
  .dentry_open = up_fs_dentry_open,
  .unix_stream_connect = up_unix_stream_connect,
  .socket_create = up_socket_create,
  .socket_bind = up_socket_bind,
  .socket_connect = up_socket_connect,
  .socket_listen = up_socket_listen,
  .socket_accept = up_socket_accept,
  .ptrace_access_check = up_ptrace_access_check,
};

static const worker_handler_t worker_handlers[__UP_WORKER_MAX] = {
		[UP_WORKER_ALL_TRACEES_EXITED] = worker_func_name(all_tracees_exited),
		[UP_WORKER_CTX_ALL_TRACEES_EXITED] = worker_func_name(ctx_all_tracees_exited),
		[UP_WORKER_TRACEE_EXITED] = worker_func_name(tracee_exited),
};

static int __init up_lsm_init(void)
{

  return lsmstub_register(THIS_MODULE, &security_ops);
}

static void __exit up_lsm_cleanup(void)
{
  lsmstub_unregister(&security_ops);
}

static int __worker_add(enum UP_WORKER_ITEM_TYPE type, void *data0, void *data1,
		gfp_t gfp) {
	struct up_worker_item *item;
	unsigned long flags;
	int worker_enabled_local;
	spin_lock_irqsave(&worker_list_lock, flags);
	worker_enabled_local = worker_enabled;
	spin_unlock_irqrestore(&worker_list_lock, flags);

	if (!worker_enabled_local) {
		return -ENOSYS;
	}

	item = kzalloc(sizeof(struct up_worker_item), gfp);
	if (unlikely(!item)) {
		up_eprintk("Out of memory.\n");
		return -ENOMEM;
	}
	item->type = type;
	item->data0 = data0;
	item->data1 = data1;
	spin_lock_irqsave(&worker_list_lock, flags);
	list_add_tail(&item->list, &worker_list);
	spin_unlock_irqrestore(&worker_list_lock, flags);
	up(&worker_semaphore);
	return 0;
}

static void worker_stop(void) {
	up_dprintk(WORKER, "asking worker thread to exit...\n");
	__worker_add(UP_WORKER_EXIT, NULL, NULL, GFP_KERNEL);
	down(&worker_exit_semaphore);
	up_dprintk(WORKER, "worker thread exited.\n");
}

int up_worker_add(enum UP_WORKER_ITEM_TYPE type, void *data0, void *data1, gfp_t gfp)
{
	if (type <= UP_WORKER_EXIT || type >= __UP_WORKER_MAX) {
		up_eprintk("Invalid worker type %d.\n", type);
		return -EINVAL;
	}
	return __worker_add(type, data0, data1, gfp);
}

static int worker_thread_main(void *unused) {
	/* Main function for cleanup thread */
	int exit = 0;
	struct up_worker_item *item;
	unsigned long flags;

	worker_enabled = 1;

	do {
		if (down_timeout(&worker_semaphore, 50)) {
			continue;
		}
		up_dprintk(WORKER, "something to do...\n");

		item = NULL;

		/* Let's keep the critical section as short as possible...
		 * Here we only fetch the first entry off the list and delete it from the list.
		 * The downside here is that we can only process the items one by one.
		 */
		spin_lock_irqsave(&worker_list_lock, flags);
		if (!list_empty(&worker_list)) {
			item = list_first_entry(&worker_list, struct up_worker_item, list);
			list_del(&item->list);
		}
		spin_unlock_irqrestore(&worker_list_lock, flags);

		if (item != NULL){
			if (item->type == UP_WORKER_EXIT) {
				up_dprintk(WORKER, "item@%p: exit received.\n", item);
				exit = 1;

			} else {
				if (worker_handlers[item->type]) {
					up_dprintk(WORKER, "handling item %p with handler %p\n", item, worker_handlers[item->type]);
					worker_handlers[item->type](item, 0);
				} else {
					up_eprintk("item@%p: unknown type: %d\n", item, item->type);
				}
			}
			kfree(item);
		}

	} while(!exit);

	spin_lock_irqsave(&worker_list_lock, flags);
	worker_enabled = 0;
	spin_unlock_irqrestore(&worker_list_lock, flags);

	/*
	 * There is no need to hold the lock anymore, because
	 * worker_enabled has been set to 0 already...
	 */
	if (!list_empty(&worker_list)) {
		struct list_head *tmp, *tmp2;
		up_eprintk("still items on worker list:\n");
		list_for_each_safe(tmp, tmp2, &worker_list) {
			item = list_entry(tmp, struct up_worker_item, list);
			list_del(tmp);
			if (worker_handlers[item->type]) {
				worker_handlers[item->type](item, 1);
			}
		}
	}
	up(&worker_exit_semaphore);
	return 0;
}

static int __init upolicy_init(void) {
  int error = 0;
  registered = 0;
  
  up_dprintk(CORE, "debug flags: %x\n", debug_flags);

  sema_init(&worker_exit_semaphore, 0);
  sema_init(&worker_semaphore, 0);

  worker_thread = kthread_run(worker_thread_main, NULL, "kupolicy");

  if (unlikely(!worker_thread)) {
  	up_eprintk("creating worker thread failed: %p\n", worker_thread);
  	goto out_cleanup;
  }

  error = up_netlink_init();
  if (error) {
    up_eprintk("netlink_init failed: %d\n", error);
    goto out_cleanup_workerthread;
  }

  error = up_lsm_init();
  if (error) {
    up_eprintk("lsm_init failed: %d\n", error);
    goto out_cleanup_netlink;
  }

  registered = 1;
  printk(KERN_INFO "upolicy: v%s initialized.\n", version);
  return error;

 out_cleanup_netlink:
  up_netlink_cleanup();
 out_cleanup_workerthread:
 	worker_stop();
 out_cleanup:
  return error;
}

static void __exit upolicy_cleanup(void)
{
  if (registered) {
    up_lsm_cleanup();
    up_netlink_cleanup();
    worker_stop();
  }

  printk(KERN_INFO "upolicy: cleaned up.\n");
}

module_init(upolicy_init);
module_exit(upolicy_cleanup);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Stephan Peijnik <stephan@peijnik.at>");

worker_func(all_tracees_exited) {
	struct up_tracer *tracer = item->data0;
	int rc = 0;

	if (tracer->socket.nlpid != UP_NL_PID_INVALID) {
		struct up_nlhdr *up_nlhdr;
		struct sk_buff *skb = __up_nlevent_prepare(NLMSG_GOODSIZE,
				UPOLICY_EVENT(ALL_TRACEES_EXITED),
				&up_nlhdr, UPOLICY_COMMAND(NOTIFICATION), tracer->socket.nlpid);
		if (unlikely(!skb)) {
					up_eprintk("__up_nlevent_prepare failed.\n");
		} else {
			rc = up_nlmsg_send(skb, tracer);
			up_dprintk(WORKER, "ALL_TRACEES_EXITED sent: %d\n", rc);
		}
	} else {
		up_dprintk(WORKER, "not sending notification: nlpid is invalid.\n");
	}

	up_tracer_put(tracer);
}

worker_func(ctx_all_tracees_exited) {
	struct up_context *ctx = item->data0;
	int rc = 0;

	if (ctx->tracer->socket.nlpid != UP_NL_PID_INVALID) {
		struct up_nlhdr *up_nlhdr;
		struct sk_buff *skb = __up_nlevent_prepare(NLMSG_GOODSIZE,
				UPOLICY_EVENT(CTX_ALL_TRACEES_EXITED),
				&up_nlhdr, UPOLICY_COMMAND(NOTIFICATION), ctx->tracer->socket.nlpid);

		if (unlikely(!skb)) {
			up_eprintk("__up_nlevent_prepare failed.\n");
		} else {
			up_nlhdr->context_id = ctx->id;
			rc = up_nlmsg_send(skb, ctx->tracer);
			up_dprintk(WORKER, "CTX_ALL_TRACEES_EXITED sent: %d\n", rc);
		}
	} else {
		up_dprintk(WORKER, "not sending notification: nlpid is invalid.\n");
	}
	up_context_put(ctx);
}

worker_func(tracee_exited) {
	struct up_context *ctx = item->data0;
	struct pid *pid_ptr = item->data1;
	pid_t pid = pid_nr(pid_ptr);

	if (ctx->tracer->socket.nlpid != UP_NL_PID_INVALID) {
		int pid_exists = 0;
		unsigned long flags;
		struct list_head *entry;

		read_lock_irqsave(&ctx->tracees_rwlock, flags);
		list_for_each(entry, &ctx->tracees_list) {
			struct up_tracee *tracee = list_entry(entry, struct up_tracee, list);
			pid_t other_pid = pid_nr(tracee->tg_pid);
			if (unlikely(other_pid == pid)) {
				pid_exists = 1;
				break;
			}
		}
		read_unlock_irqrestore(&ctx->tracees_rwlock, flags);

		if (!pid_exists) {
			struct up_nlhdr *up_nlhdr;
			struct sk_buff *skb = __up_nlevent_prepare(NLMSG_GOODSIZE,
					UPOLICY_EVENT(TRACEE_EXITED),
					&up_nlhdr, UPOLICY_COMMAND(NOTIFICATION), ctx->tracer->socket.nlpid);

			if (unlikely(!skb)) {
				up_eprintk("__up_nlevent_prepare failed.\n");
			} else {
				int rc = 0;
				up_nlhdr->context_id = ctx->id;
				up_nlhdr->pid = pid;
				rc = up_nlmsg_send(skb, ctx->tracer);
				up_dprintk(WORKER, "TRACEE_EXITED sent: %d\n", rc);
			}
		} else {
			up_dprintk(WORKER, "not sending notification: PID is still alive.\n");
		}
	} else {
		up_dprintk(WORKER, "not sending notification: nlpid is invalid.\n");
	}

	/* Drop the reference... */
	put_pid(pid_ptr);
	up_context_put(ctx);
}
