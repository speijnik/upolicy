/* upolicy.h
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
#ifndef _KUPOLICY_UPOLICY_H
#define _KUPOLICY_UPOLICY_H

#include <linux/types.h>

/* shared between kernel and userspace */

#include <kupolicy/types.h>

/**
 * enum UP_EVENT - upolicy event types
 * @_UPOLICY_EV_TRACEE_NEW: New tracee event
 * @UPOLICY_EV_LAST_UNBLOCKABLE_QUESTION: Last unblockable question
 * @_UPOLICY_EV_CONTEXT_CREATED: Context created notification
 * @_UPOLICY_EV_ALL_TRACEES_EXITED: All tracees exited notification
 * @UPOLICY_EV_LAST_UNBLOCKABLE: Last unblockable event.
 * All events below can be subscribed to on a per-context basis.
 * @_UPOLICY_EV_TRACEE_EXITED: A tracee exited
 * @_UPOLICY_EV_TRACEE_STARTED: New tracee has started
 * @_UPOLICY_EV_CTX_ALL_TRACEES_EXITED: All tracees inside a context exited
 * @UPOLICY_EV_LAST_NOTIFY_ONLY: Last notification-only event
 * @_UPOLICY_EV_TRACER_INIT: Tracee wants to become tracer event
 * @_UPOLICY_EV_CLONE: clone() called event
 * @_UPOLICY_EV_OPEN: open() called event
 * @_UPOLICY_EV_SYMLINK: symlink creation event
 * @_UPOLICY_EV_SOCKET_ACCEPT: accept() called event
 * @_UPOLICY_EV_SOCKET_BIND: bind() called event
 * @_UPOLICY_EV_SOCKET_CONNECT: connect() called event
 * @_UPOLICY_EV_SOCKET_CREATE: socket() called event
 * @_UPOLICY_EV_SOCKET_LISTEN: listen() called event
 * @_UPOLICY_EV_UNIX_STREAM_CONNECT: connect() on Unix stream event
 * @_UPOLICY_EV_KILL: signal delivery event
 * @_UPOLICY_EV_EXEC: exec event
 * @_UPOLICY_EV_PTRACE_ATTACH: ptrace attach event
 * @__UPOLICY_EV_MAX: maximum event number plus 1
 */
enum UP_EVENT
{
  _UPOLICY_EV_TRACEE_NEW,
  UPOLICY_EV_LAST_UNBLOCKABLE_QUESTION = _UPOLICY_EV_TRACEE_NEW,
  _UPOLICY_EV_CONTEXT_CREATED,
  _UPOLICY_EV_ALL_TRACEES_EXITED,
  UPOLICY_EV_LAST_UNBLOCKABLE = _UPOLICY_EV_ALL_TRACEES_EXITED,

  _UPOLICY_EV_TRACEE_EXITED,
  _UPOLICY_EV_TRACEE_STARTED,
  _UPOLICY_EV_CTX_ALL_TRACEES_EXITED,
  UPOLICY_EV_LAST_NOTIFY_ONLY = _UPOLICY_EV_CTX_ALL_TRACEES_EXITED,

  _UPOLICY_EV_TRACER_INIT,
  _UPOLICY_EV_CLONE,
  _UPOLICY_EV_OPEN,
  _UPOLICY_EV_SYMLINK,

  _UPOLICY_EV_SOCKET_ACCEPT,
  _UPOLICY_EV_SOCKET_BIND,
  _UPOLICY_EV_SOCKET_CONNECT,
  _UPOLICY_EV_SOCKET_CREATE,
  _UPOLICY_EV_SOCKET_LISTEN,
  _UPOLICY_EV_UNIX_STREAM_CONNECT,

  _UPOLICY_EV_KILL,
  _UPOLICY_EV_EXEC,
  _UPOLICY_EV_PTRACE_ATTACH,

  __UPOLICY_EV_MAX
};

#define UPOLICY_EV_MAX (__UPOLICY_EV_MAX - 1)
#define UPOLICY_EV_FIRST_BLOCKABLE (UPOLICY_EV_LAST_UNBLOCKABLE + 1)

/*
 * All events set mask
 */
#define UPOLICY_EV_FLAG_ALL			\
  ((1 << (__UPOLICY_EV_MAX - UPOLICY_EV_FIRST_BLOCKABLE)) - 1)

/**
 * upolicy_ev_flag - Event to event-flag conversion (for use with
 * upolicy_event_mask_t). Note that events below
 * UPOLICY_EV_FIRST_UNBLOCKABLE should never be converted to a flag.
 * The C compiler should be issuing a warning in that case anyways.
 *
 * @ev: Event number
 */
static inline __u64 upolicy_ev_flag(enum UP_EVENT ev) {
	return (1 << (ev - UPOLICY_EV_FIRST_BLOCKABLE)) & UPOLICY_EV_FLAG_ALL;
}

/**
 * enum UP_EVENT_TYPE - event type
 *
 * @UP_EV_TYPE_SKIP: skip event
 * @UP_EV_TYPE_QUESTION: question event
 * @UP_EV_TYPE_NOTIFICATION: notification event
 */
enum UP_EVENT_TYPE {
	UP_EV_TYPE_SKIP,
	UP_EV_TYPE_QUESTION,
	UP_EV_TYPE_NOTIFICATION
};

#define UP_EV_TYPE(type) (UP_EV_TYPE_ ##type)

/*
 * Event to event-value conversion.
 */
#define UPOLICY_EVENT(ev)			\
  (_UPOLICY_EV_ ##ev)

#ifdef __KERNEL__
/* kernel-only */

#include <linux/kernel.h>
#include <linux/printk.h>

enum _UP_DEBUG_FLAG {
	UP_DEBUG_CORE,
	UP_DEBUG_REFCOUNT,
	UP_DEBUG_NETLINK,
	UP_DEBUG_TRACEE,
	UP_DEBUG_TRACER,
	UP_DEBUG_CONTEXT,
	UP_DEBUG_WORKER,
	UP_DEBUG_HANDLER_CRED,
	UP_DEBUG_HANDLER_FS,
	UP_DEBUG_HANDLER_PTRACE,
	UP_DEBUG_HANDLER_SOCKET,
	UP_DEBUG_HANDLER_TASK,
	UP_DEBUG_HANDLER_BPRM,
	__UP_DEBUG_MAX,
};

#define UP_DEBUG_FLAG(x) (1 << x)
#define UP_DEBUG_FLAG_ALL (UP_DEBUG_FLAG(__UP_DEBUG_MAX) - 1)

/*
 * Default is to print everything, except for refcount.
 */
#define UP_DEBUG_FLAG_DEFAULT UP_DEBUG_FLAG_ALL & \
		~(UP_DEBUG_FLAG(UP_DEBUG_REFCOUNT) | UP_DEBUG_FLAG(UP_DEBUG_HANDLER_CRED))

#ifdef UPOLICY_DEBUG

unsigned int up_debug_flags(void);

static inline void __up_dprintk(enum _UP_DEBUG_FLAG flag, const char *func_name,
		int line_no, const char *fmt, ...) {
	va_list va;

	if (!(up_debug_flags() & UP_DEBUG_FLAG(flag)))
		return;

	printk(KERN_DEBUG "[upolicy] <%s:%d> ", func_name, line_no);
	va_start(va, fmt);
	vprintk(fmt, va);
	va_end(va);
}

#define up_dprintk(debug_name, fmt, ...)				\
	__up_dprintk(UP_DEBUG_ ##debug_name, __func__, __LINE__, fmt, ## __VA_ARGS__)
#else /* !UPOLICY_DEBUG */
#define up_dprintk(debug_flag, fmt, ...) /* empty */
#endif /* UPOLICY_DEBUG */

#define up_eprintk(fmt, ...)        \
	printk(KERN_ERR "[upolicy] <%s:%d> " fmt, __func__, __LINE__, ## __VA_ARGS__)

#include <linux/list.h>
#include <linux/sched.h>

/* forward declarations */
struct cred;
struct up_context;
struct up_socket;
struct up_tracee;
struct up_tracer;
struct sk_buff;

#ifndef task_security
#define task_security(task)			\
  (task_cred_xxx((task), security))
#endif /* task_security */

/**
 * task_upolicy - Gets the pointer to a task's upolicy struct.
 * @task: Tstruct task_struct pointer
 */
#define task_upolicy(task)			\
  (struct upolicy*) (task_security(task))

/**
 * current_upolicy - Gets the pointer to the current task's upolicy
 * struct.
 */
#define current_upolicy()			\
  (struct upolicy*) (current_cred() ? current_security() : NULL)

/**
 * cred_upolicy - Gets the pointer to a cred's upolicy struct.
 *
 * @cred: struct cred pointer
 */
#define cred_upolicy(cred)			\
  (struct upolicy*) ((cred)->security)

/**
 * struct upolicy -  Per-process upolicy information
 * A pointer to this struct is present in cred.security for 
 * each tracer and tracee.
 *
 * @tracer: Tracer struct, non-NULL for all tracers
 * @tracee: Tracee struct, non-NULL for all tracees
 */
struct upolicy
{
  struct up_tracer* tracer;
  struct up_tracee* tracee;
};

/* function declarations */
/**
 * up_alloc - allocate struct upolicy
 * @gfp: gfp
 */
struct upolicy* up_alloc(gfp_t gfp);

/**
 * up_free - free struct upolicy saved in struct cred
 * @cred: struct cred containing struct upolicy in security field
 */
void up_free(struct cred* cred);

/**
 * up_copy - copy upolicy information from old credentials to new one
 * @new: new credentials
 * @old: old credentials
 * @gfp: gfp
 */
int up_copy(struct cred* new, const struct cred* old, gfp_t gfp);

/**
 * up_same_context - Check if two tasks are in the same upolicy context, where
 * src is assumed to be a parent of dest.
 *
 * @src: Source
 * @dest: Destination
 */
int up_same_context(struct upolicy* src, struct upolicy* dest);

/**
 * up_want_handle_event - Check if the current task needs the event to be handled
 *
 * @ev: Event number
 */
struct up_tracee *up_want_handle_event(enum UP_EVENT ev);

/**
 * enum UP_WORKER_ITEM_TYPE - Worker thread item types
 *
 * @UP_WORKER_EXIT: Exit item
 * @UP_WORKER_ALL_TRACEES_EXITED: All tracees exited item
 * @UP_WORKER_CTX_ALL_TRACEES_EXITED: All tracees of a context exited item
 * @__UP_WORKER_MAX: Maximum worker item type plus 1
 */
enum UP_WORKER_ITEM_TYPE {
	UP_WORKER_EXIT,
	UP_WORKER_ALL_TRACEES_EXITED,
	UP_WORKER_CTX_ALL_TRACEES_EXITED,
	UP_WORKER_TRACEE_EXITED,
	__UP_WORKER_MAX
};

/**
 * up_worker_add - Add item to worker thread
 * @type: Item type
 * @data0: first data field
 * @data1: second data field
 * @gfp: gfp
 */
int up_worker_add(enum UP_WORKER_ITEM_TYPE type, void *data0, void *data1,
		gfp_t gfp);

/**
 * up_pre_send_fixup_pid - pre-send callback that fixes UP_NLA_PID by
 * using the PID-namespace local value for the given tracer.
 */
int up_pre_send_fixup_pid(struct sk_buff *skb, struct up_tracee *tracee,
		struct up_tracer *tracer, void *data);

#endif /* __KERNEL__ */

#endif /* _KUPOLICY_UPOLICY_H */
