/* netlink.h
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
#ifndef _KUPOLICY_NETLINK_H
#define _KUPOLICY_NETLINK_H

/* parts shared between kernel and userspace */
#include <kupolicy/types.h>
#include <kupolicy/upolicy.h>
#include <kupolicy/netlink_version.h>

#define UP_NL_FAMILY_NAME "upolicy"

/*
 * An unanswered question will survive for 20 * 30 (=600) seconds,
 * which should give any userspace application plenty of time to answer it.
 */
#define UP_QUESTION_MAX_RETRIES 20
#define UP_QUESTION_WAIT_SECS 30

/**
 * struct up_nlhdr - Common upolicy netlink header
 * @context_id: Context ID
 * @pid: Process ID
 * @tid: Task ID
 */
struct up_nlhdr {
  up_ctx_id context_id;
  pid_t     pid;

  pid_t     tid;
};

/**
 * enum UP_CMD - netlink commands
 *
 * @UP_NLC_UNSPEC: unspecified command
 * @UP_NLC_INIT: init command
 *               Does not require any netlink attributes
 * @UP_NLC_CTX_CREATE: context create command
 *              Requires the UP_NLA_NOTIFYMASK, UP_NLA_QUESTIONMASK and
 *              UP_NLA_UCONTEXT_ID attributes.
 * @UP_NLC_CTX_DESTROY: context destroy command
 * @UP_NLC_DECISION: event decision command.
 * 							Requires the UP_NLA_DECISION attribute.
 * @UP_NLC_QUESTION: Question command (kernel to userspace)
 * @UP_NLC_NOTIFICATION: Notification command (kernel to userspace)
 * @__UP_NLC_MAX: Maximum command number plus 1
 *
 */
enum UP_CMD {
  UP_NLC_UNSPEC,

  /* commands from user- to kernelspace */
  UP_NLC_INIT,
  UP_NLC_CTX_CREATE,
  UP_NLC_CTX_DESTROY,
  UP_NLC_DECISION,

  /* commands from kernel- to userspace */
  UP_NLC_QUESTION,
  UP_NLC_NOTIFICATION,
  __UP_NLC_MAX,
};

#define UP_NLC_MAX (__UP_NLC_MAX - 1)

#define UPOLICY_COMMAND(cmd) (UP_NLC_ ##cmd)

/**
 * enum UP_NLA - netlink attributes
 * @UP_NLA_UNSPEC: unspecified attribute
 * @UP_NLA_EVENTMASK: event mask (uint64)
 * @UP_NLA_NOTIFYMASK: notify mask (uint64)
 * @UP_NLA_EVENTNO: event number (uint16)
 * @UP_NLA_UCONTEXT_ID: userspace-provided context ID (uint16)
 * @UP_NLA_DECISION: decision (uint8)
 * @UP_NLA_CLONE_FLAGS: clone flags (uint64)
 * @UP_NLA_SOCKET_REMOTE: remote socket (container)
 * @UP_NLA_SOCKET_LOCAL: local socket (container)
 * @UP_NLA_PID: (target) process ID
 * @UP_NLA_SIGNO: signal number
 * @UP_NLA_PATH: path
 * @UP_NLA_PTRACE_MODE: ptrace mode
 * @__UP_NLA_MAX: maximum attribute number plus 1
 */
enum UP_NLA {
  UP_NLA_UNSPEC,
  UP_NLA_EVENTMASK,
  UP_NLA_NOTIFYMASK,
  UP_NLA_EVENTNO,
  UP_NLA_UCONTEXT_ID,
  UP_NLA_DECISION,
  UP_NLA_CLONE_FLAGS,
  UP_NLA_SOCKET_REMOTE,
  UP_NLA_SOCKET_LOCAL,
  UP_NLA_PID,
  UP_NLA_SIGNO,
  UP_NLA_PATH,
  UP_NLA_PTRACE_MODE,
  __UP_NLA_MAX,
};

#define UP_NLA_MAX (__UP_NLA_MAX - 1)


/**
 * enum UP_NLA_SOCK - socket netlink attributes to be used in UP_NLA_SOCKET_REMOTE
 * and UP_NLA_SOCKET_LOCAL containers
 *
 * @UP_NLA_SOCKET_UNSPEC: unspecified attribute
 * @UP_NLA_SOCKET_FAMILY: socket family (uint32)
 * @UP_NLA_SOCKET_TYPE: socket type (uint32)
 * @UP_NLA_SOCKET_PROTO: socket protocol (uint32)
 * @UP_NLA_SOCKET_ADDRLEN: address length (uint32)
 * @UP_NLA_SOCKET_INADDR: IPv4 address (struct sockaddr_in)
 * @UP_NLA_SOCKET_IN6ADDR: IPv6 address (struct sockaddr_in6)
 * @UP_NLA_SOCKET_UNADDR: Unix socket address (struct sockaddr_un)
 * @UP_NLA_SOCKET_NLADDR: Netlink address (struct sockaddr_nl)
 * @UP_NLA_SOCKET_BACKLOG: listen() backlog value (uint32)
 * @__UP_NLA_SOCKET_MAX: Maximum attribute number plus 1
 */
enum UP_NLA_SOCK {
	UP_NLA_SOCKET_UNSPEC,

	UP_NLA_SOCKET_FAMILY,
	UP_NLA_SOCKET_TYPE,
	UP_NLA_SOCKET_PROTO,

	UP_NLA_SOCKET_ADDRLEN,
	UP_NLA_SOCKET_INADDR,
	UP_NLA_SOCKET_IN6ADDR,
	UP_NLA_SOCKET_UNADDR,
	UP_NLA_SOCKET_NLADDR,
	UP_NLA_SOCKET_BACKLOG,

	__UP_NLA_SOCKET_MAX,
};

#define UP_NLA_SOCKET_MAX (__UP_NLA_SOCKET_MAX - 1)

/**
 * enum UP_EV_DECISION - decision values
 * @UP_DECIDE_KILL: deny call and kill tracee
 * @UP_DECIDE_ALLOW: allow call
 * @UP_DECIDE_DENY: deny call
 * @UP_DECIDE_POSTPONE: decision postponed.
 *   This value should NEVER be passed to the kernel and is reserved for use
 *   in the userspace library.
 * @__UP_DECISION_MAX: maximum decision value plus 1
 */
enum UP_EV_DECISION {
  UP_DECIDE_KILL,
  UP_DECIDE_ALLOW,
  UP_DECIDE_DENY,
  UP_DECIDE_POSTPONE,
  __UP_DECISION_MAX,
};

#define UP_EV_DECISION_MAX (__UP_DECISION_MAX - 1)

#define UP_DECISION(name) (UP_DECIDE_ ##name)
#define UP_DECISION_WANTS_PARAMS(dec) (0)

#ifdef __KERNEL__
/* kernel-only parts */

#include <linux/semaphore.h>
#include <net/netlink.h>
#include <net/genetlink.h>

/* forward declarations */
struct sk_buff;
struct upolicy;
struct up_nlhdr;
struct up_tracer;
struct up_tracee;
struct net;

struct up_question;


/*
 * If the default netlink message size is smaller than 6144 bytes we need
 * to use a bigger buffer when sending messages that contain a path.
 * This is because the maximum path length is 4096 bytes and we still need
 * some extra memory for headers, other attributes, etc.
 * 2048 bytes for this other data should be sufficient.
 */
#include <linux/skbuff.h>
#include <linux/netlink.h>

#if PAGE_SIZE < 6144UL
#define UP_NLMSG_PATHSIZE SKB_WITH_OVERHEAD(6144UL)
#else /* NLMSG_GOODSIZE >= 6144UL */
#define UP_NLMSG_PATHSIZE NLMSG_GOODSIZE
#endif /* NLMSG_GOODSIZE < 6144UL */

typedef int (*up_pre_send_cb_t)(struct sk_buff *skb, struct up_tracee *tracee,
		struct up_tracer *tracer, void *data);

/*
 * UP_NL_MAX_QUESTIONS - Maximum number of active questions.
 * This limits the number of concurrently allocated
 * up_question objects and thus helps prevent DoS attacks
 * by generating a lot of questions.
 */
#define UP_NL_MAX_QUESTIONS 16384

/**
 * struct up_socket - Per-tracer socket information
 * @question_list: Head of question list
 * @question_rwlock: rwlock protecting question_list
 * @nlpid: Netlink PID of userspace application
 * @net_ns: Network namespace of tracer
 */
struct up_socket {
  struct list_head question_list;
  rwlock_t         question_rwlock;
  u32              nlpid;
  struct net      *net_ns;
};

/**
 * struct up_nl_response - netlink response message
 * @skb: sk_buff of response
 * @info: generic netlink info
 */
struct up_nl_response {
	struct sk_buff *skb;
	struct genl_info info;
};

/*
 * Invalid netlink PID.
 */
#define UP_NL_PID_INVALID 0

/**
 * up_netlink_init - Netlink initialization.
 */
int __init up_netlink_init(void);

/**
 * up_netlink cleanup - Netlink cleanup.
 */
void up_netlink_cleanup(void);

/**
 * up_socket_init - Socket initialization.
 *
 * @socket: Socket
 * @nlpid: Netlink PID
 */
void up_socket_init(struct up_socket* socket, u32 nlpid);

/**
 * up_socket_cleanup - Socket cleanup.
 *
 * @socket: Socket
 */
void up_socket_cleanup(struct up_socket* socket);

/**
 * __up_nlmsg_prepare - Prepare netlink message.
 *
 * On success returns pointer to sk_buff of new message.
 * It is up to the caller to fill nlhdr with correct values.
 *
 * @nlpid: Netlink PID of destination
 * @cmd: Command
 * @nlhdr: Pointer to up_nlhdr pointer.
 */
struct sk_buff *__up_nlmsg_prepare(size_t size, u32 nlpid, enum UP_CMD cmd,
				 struct up_nlhdr **nlhdr);

static inline struct sk_buff *up_nlmsg_prepare(u32 nlpid, enum UP_CMD cmd,
		struct up_nlhdr **nlhdr) {
	return __up_nlmsg_prepare(NLMSG_GOODSIZE, nlpid, cmd, nlhdr);
}

/**
 * up_nlmsg_send - Send netlink message.
 *
 * Returns value >= 0 on success, < 0 on error.
 *
 * @skb: Buffer containing full message as allocated by up_nlmsg_prepare.
 * @tracer: Tracer the message will be sent to.
 */
int up_nlmsg_send(struct sk_buff *skb, struct up_tracer *tracer);

/**
 * __up_nlevent_prepare - Prepare netlink event
 * @ev: Event number
 * @nlhdr: Pointer to up_nlhdr pointer
 * @cmd: Command
 * @nlpid: Netlink PID of destination
 */
static inline struct sk_buff *__up_nlevent_prepare(size_t size, enum UP_EVENT ev,
		struct up_nlhdr **nlhdr, enum UP_CMD cmd, u32 nlpid) {
	struct sk_buff *skb = __up_nlmsg_prepare(size, nlpid, cmd, nlhdr);

	if (likely(skb)) {
		NLA_PUT_U16(skb, UP_NLA_EVENTNO, ev);
		goto out;
		nla_put_failure:
			up_eprintk("nla_put_u16 failed, skb@%p, ev=%d\n", skb, ev);
			kfree_skb(skb);
			skb = NULL;
	} else {
		up_eprintk("nlmsg_prepare failed, event=%d\n", ev);
	}
	out:
	return skb;
}

#define up_nlevent_prepare(ev, nlhdr) __up_nlevent_prepare(NLMSG_GOODSIZE, ev, nlhdr, UPOLICY_COMMAND(QUESTION), 0)

/**
 * up_nlmsg_headers - Get pointers to nlmsg headers from sk_buff struct
 *
 * @skb: sk_buff struct to extract headers from
 * @nlhdr: netlink header
 * @genlhdr: generic netlink header
 * @uphdr: upolicy netlink header
 */
static inline int up_nlmsg_headers(struct sk_buff *skb, struct nlmsghdr **nlhdr, struct genlmsghdr **genlhdr, struct up_nlhdr **uphdr) {
	if (unlikely(!skb))
		return -EINVAL;

	if (nlhdr)
		*nlhdr = nlmsg_hdr(skb);
	if (genlhdr)
		*genlhdr = nlmsg_data(*nlhdr);
	if (uphdr)
		*uphdr = genlmsg_data(*genlhdr);
	return 0;
}

/**
 * __up_nlevent_send - Send netlink event to all tracers.
 *
 * @skb: sk_buff as allocated with up_nlevent_prepare
 * @tracee: tracee that generated the event
 * @ev: Event
 * @response: Pointer to response struct. May be NULL if no response processing is
 *   required.
 * @tsk: Task that generated the event.
 * @cb: Callback to be invoked prior to sending the message to a tracer.
 * @cb_data: Additional data to be passed to the callback.
 *
 * cb may be NULL, which means no callback will be invoked.
 *
 */
enum UP_EV_DECISION __up_nlevent_send(struct sk_buff *skb, struct up_tracee *tracee,
		enum UP_EVENT ev, struct up_nl_response *response, struct task_struct *tsk,
		up_pre_send_cb_t cb, void *cb_data);

/**
 * up_nlevent_send_single - Send netlink event to a single tracer.
 *
 * @skb: sk_buff as allocated with up_nlevent_prepare
 * @tracee: tracee that generated the event
 * @ev: Event
 * @response: Pointer to response struct. May be NULL if no response processing is
 *   required.
 * @tsk: Task that generated the event.
 */
enum UP_EV_DECISION __up_nlevent_send_single(struct sk_buff *skb, struct up_tracee *tracee,
		enum UP_EVENT ev, struct up_nl_response *response, struct task_struct *tsk);

/**
 * up_nlevent_send _single - Send netlink event to a single tracer.
 *
 * This is a thin wrapper around __up_nlevent_send_single, which passes along all values and
 * sets the tsk parameter to current.
 *
 * @skb: sk_buff
 * @ev: Event
 * @tracee: tracee
 */
static inline enum UP_EV_DECISION up_nlevent_send_single(struct sk_buff *skb,
		enum UP_EVENT ev, struct up_tracee *tracee) {
	return __up_nlevent_send_single(skb, tracee, ev, NULL, current);
}

/**
 * up_nlevent_send - Send netlink event to all tracers.
 *
 * This is a thin wrapper around __up_nlevent_send, which passes along all values and
 * sets the tsk parameter to current.
 *
 * @skb: sk_buff
 * @tracee: tracee
 * @ev: event
 * @response: Pointer to struct up_nl_response
 */
static inline enum UP_EV_DECISION up_nlevent_send(struct sk_buff *skb,
		struct up_tracee *tracee, enum UP_EVENT ev, struct up_nl_response *response) {
	return __up_nlevent_send(skb, tracee, ev, response, current, NULL, NULL);
}

/**
 * __up_nlevent_send_simple - Send netlink event to all tracers.
 *
 * This is a thin wrapper around __up_nlevent_send and __up_nlevent_prepare that should
 * be used when no additional netlink attributes are used for the event.
 *
 * @tracee: Tracee
 * @ev: Event
 * @response: Pointer to struct up_nl_response
 * @tsk: Task
 */
static inline enum UP_EV_DECISION __up_nlevent_send_simple(struct up_tracee *tracee,
		enum UP_EVENT ev, struct up_nl_response *response, struct task_struct *tsk) {
	enum UP_EV_DECISION decision = UP_DECISION(KILL);
	struct sk_buff *skb = NULL;
	struct up_nlhdr *nlhdr = NULL;

	skb = up_nlevent_prepare(ev, &nlhdr);

	if (unlikely(!skb)) {
		up_eprintk("up_nlevent_prepare failed.\n");
		goto out;
	}

	decision = __up_nlevent_send(skb, tracee, ev, response, tsk, NULL, NULL);

	out:
	return decision;
}

/**
 * up_nlevent_send_simple - Send simple netlink event
 *
 * @tracee: Tracee
 * @ev: Event
 * @response: Pointer to struct up_nl_response
 */
static inline enum UP_EV_DECISION up_nlevent_send_simple(struct up_tracee *tracee,
		enum UP_EVENT ev, struct up_nl_response *response) {
	return __up_nlevent_send_simple(tracee, ev, response, current);
}

/**
 * __up_nlevent_send_single_simple - Send a simple netlink event to a single tracer
 *
 * @tracee: Tracee
 * @ev: Event
 * @response: Pointer to struct up_nl_response
 * @tsk: Task
 */
static inline enum UP_EV_DECISION __up_nlevent_send_single_simple(struct up_tracee *tracee,
		enum UP_EVENT ev, struct up_nl_response *response, struct task_struct *tsk) {
	enum UP_EV_DECISION decision = UP_DECISION(KILL);
	struct sk_buff *skb = NULL;
	struct up_nlhdr *nlhdr = NULL;

	skb = up_nlevent_prepare(ev, &nlhdr);

	if (unlikely(!skb)) {
		up_eprintk("skb allocation failed.\n");
		goto out;
	}

	decision = __up_nlevent_send_single(skb, tracee, ev, response, tsk);

	out:
	return decision;
}

/**
 * up_nlevent_send_single_simple - Send simple netlink event to a single tracer
 * @tracee: Tracee
 * @ev: Event
 * @response: Pointer to up_nl_response
 */
static inline enum UP_EV_DECISION up_nlevent_send_single_simple(struct up_tracee *tracee,
		enum UP_EVENT ev, struct up_nl_response *response) {
	return __up_nlevent_send_single_simple(tracee, ev, response, current);
}

/**
 * up_nl_response_free - free memory of struct up_nl_response members
 * @response: Pointer to struct up_nl_response
 */
void up_nl_response_free(struct up_nl_response *response);

#endif /* __KERNEL__ */


#endif /* _KUPOLICY_NETLINK_H */
