/* netlink.c
 *
 * Copyright (C) 2012 Stephan Peijnik <stephan@peijnik.at>
 *
 * This file is part of upolicy.
 *
 *  upolicy is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation, either version 3 of the License, or
 *  (at your option) any later version.
 *
 *  upolicy is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with upolicy.  If not, see <http://www.gnu.org/licenses/>.
 */

#include "config.h"

#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <semaphore.h>
#include <sys/epoll.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <unistd.h>

#if TIME_WITH_SYS_TIME
# include <sys/time.h>
# include <time.h>
#else
# if HAVE_SYS_TIME_H
#  include <sys/time.h>
# else
#  include <time.h>
# endif
#endif

#include <netlink/netlink.h>
#include <netlink/genl/genl.h>
#include <netlink/genl/ctrl.h>

#include <upolicy/context.h>
#include <upolicy/netlink.h>
#include <upolicy/internal.h>

/* local type declarations */

enum EV_INFO_TYPE {
	EV_INFO_UNUSED,
	EV_INFO_POSTPONED,
	EV_INFO_CURRENT,
};

#define MAX_EVENT_INFO_COUNT 20
#define NETLINK_EPOLL_TIMEOUT 50

/**
 * Internal event info struct.
 * This additionally contains a list_entry, for use
 * in postponed and unused lists and an EV_INFO_TYPE designating
 * whether it is unused or not.
 */
struct event_info {
	struct upolicy_event_info  info;
	struct nl_msg             *msg;
	enum EV_INFO_TYPE          type;
	time_t                     timestamp;
	struct list_entry          entry;
};

static struct upolicy_event_info *event_info_get();
static void event_info_put(struct upolicy_event_info *info);
static void event_info_postpone(struct upolicy_event_info *info,
		struct nl_msg *msg);

/**
 * netlink message handler function pointer
 */
typedef int (*nlmsg_handler_t)(struct nl_msg *msg, struct nlmsghdr *nlhdr,
		struct genlmsghdr *genl_hdr, struct up_nlhdr *up_nlhdr);

/**
 * event handler function pointer
 */
typedef int (*event_handler_t)(struct upolicy_context *ctx,
		struct nl_msg *msg, struct nlmsghdr *nlhdr, struct genlmsghdr *genl_hdr,
		struct up_nlhdr *up_nlhdr, enum UP_EVENT event, struct upolicy_event_info *info,
		const struct upolicy_ops *ops);

/**
 * send_sync helper structure
 */
struct sync_waiter {
	/**
	 * wait semaphore
	 */
	sem_t wait_semaphore;

	/**
	 * sequence number of message for which we are waiting for an ACK
	 */
	__u32 seq;


	/**
	 * result of sync message
	 */
	int result;

	/**
	 * list entry
	 */
	struct list_entry entry;
};

/* local helper macros */

/**
 * netlink handler name macro
 */
#define nlhdlr_name(name) (__nl_handle_ ##name)

/**
 * netlink handler function signature macro
 */
#define nlhdlr(name) static int nlhdlr_name(name) (struct nl_msg* msg, \
		struct nlmsghdr *nlhdr, struct genlmsghdr *genl_hdr, struct up_nlhdr *up_nlhdr)

/**
 * event handler name macro
 */
#define eventhdlr_name(name) (__ev_handle_ ##name)
#define eventhdlr(name) static int eventhdlr_name(name)  ( \
		struct upolicy_context *ctx, struct nl_msg* msg, struct nlmsghdr *nlhdr, \
		struct genlmsghdr *genl_hdr, struct up_nlhdr *up_nlhdr, \
		enum UP_EVENT event, struct upolicy_event_info *info, const struct upolicy_ops *ops)

/* forward declaration of local functions */

/**
 * Send init message to kernel
 *
 */
static int genl_send_init(void);

/**
 * Main function for thread which receives netlink messages
 * for us.
 */
static void *receiver_thread_main(void *unused);

/**
 * Handle netlink messages of type question
 */
nlhdlr(question);

/**
 * Handle netlink messages of type notification
 */
nlhdlr(notification);

/**
 * Handle context created event
 */
eventhdlr(context_created);

/**
 * Handle all tracees exited event
 */
eventhdlr(all_tracees_exited);

/**
 * Handle tracee_new event
 */
eventhdlr(tracee_new);

/**
 * Handle tracer_init event
 */
eventhdlr(tracer_init);

/**
 * Handle socket_create event
 */
eventhdlr(socket_create);

/**
 * Handle socket_bind event
 */
eventhdlr(socket_bind);

/**
 * Handle socket_accept event
 */
eventhdlr(socket_accept);

/**
 * Handle socket_listen event
 */
eventhdlr(socket_listen);

/**
 * Handle socket_connect event
 */
eventhdlr(socket_connect);

/**
 * Handle kill event
 */
eventhdlr(kill);

/**
 * Handle exec event
 */
eventhdlr(exec);

/**
 * Handle ptrace_attach event
 */
eventhdlr(ptrace_attach);

/**
 * Handle ctx_all_tracees_exited event
 */
eventhdlr(ctx_all_tracees_exited);

/**
 * Handle tracee_exited event
 */
eventhdlr(tracee_exited);

/**
 * Handle tracee_started event
 */
eventhdlr(tracee_started);

/* local variables */
/**
 * Netlink socket
 */
static struct nl_sock *sock = NULL;

/**
 * Socket rwlock.
 * This is NOT used when reading or writing from or to the socket, but rather when
 * dereferencing the sock variable.
 */
static pthread_rwlock_t sock_rwlock = PTHREAD_RWLOCK_INITIALIZER;

/**
 * Socket writer semaphore (binary).
 * Binary semaphore which ensures that only a single thread is writing to the netlink
 * socket at any time.
 */
static sem_t sock_write_sem;

/**
 * Tracee exit semaphore (binary).
 * Binary semaphore which is initialized to zero and post'ed when
 * all tracees have exited.
 */
//static sem_t tracee_exit_sem;
static pthread_cond_t tracees_exited_cond = PTHREAD_COND_INITIALIZER;
static pthread_mutex_t tracees_exited_mutex = PTHREAD_MUTEX_INITIALIZER;
static pthread_mutex_t join_mutex = PTHREAD_MUTEX_INITIALIZER;

/**
 * Netlink family ID
 */
static int family_id = 0;

/**
 * Receiver thread
 */
static pthread_t receiver_thread;

/**
 * epoll file descriptor
 */
static int epoll_fd = -1;

/**
 * epoll event struct
 */
static struct epoll_event ep_event = {
		.events = EPOLLIN|EPOLLHUP|EPOLLERR,
};

/**
 * Receiver thread semaphore (binary).
 * Binary semaphore which is initialized to zero and post'ed when
 * the receiver thread exits.
 */
static sem_t receiver_exit_sem;

/**
 * Binary semaphore protecting access to the sync_waiter_list list.
 */
static sem_t sync_waiter_list_sem;

/**
 * Sync waiter list.
 */
static struct list sync_waiter_list = LIST_INITIALIZER;

/**
 * Definition of a "null header". All values in this header are zero.
 */
static const struct up_nlhdr up_nullhdr = {
		.context_id = 0,
		.pid = 0,
		.tid = 0
};

/**
 * Array of netlink message handler function pointers.
 */
static const nlmsg_handler_t up_handlers[UP_NLC_MAX + 1] = {
		[UP_NLC_QUESTION]		= nlhdlr_name(question),
		[UP_NLC_NOTIFICATION] = nlhdlr_name(notification),
};

static struct list event_info_unused_list = LIST_INITIALIZER;
static struct list event_info_postponed_list = LIST_INITIALIZER;
static sem_t event_info_unused_semaphore;
static pthread_mutex_t event_info_unused_list_mutex = PTHREAD_MUTEX_INITIALIZER;
static pthread_mutex_t event_info_postponed_list_mutex =
		PTHREAD_MUTEX_INITIALIZER;
static unsigned char tracees_active = 0;

#define EVHDLR(ev,name) [UPOLICY_EVENT(ev)] = eventhdlr_name(name)
/**
 * Array of event handler function pointers.
 */
static const event_handler_t event_handlers[UPOLICY_EV_MAX + 1] = {
		EVHDLR(TRACEE_NEW, tracee_new),
		EVHDLR(CONTEXT_CREATED, context_created),
		EVHDLR(ALL_TRACEES_EXITED, all_tracees_exited),
		EVHDLR(CTX_ALL_TRACEES_EXITED, ctx_all_tracees_exited),
		EVHDLR(TRACER_INIT, tracer_init),
		EVHDLR(SOCKET_ACCEPT, socket_accept),
		EVHDLR(SOCKET_BIND, socket_bind),
		EVHDLR(SOCKET_CONNECT, socket_connect),
		EVHDLR(SOCKET_CREATE, socket_create),
		EVHDLR(SOCKET_LISTEN, socket_listen),
		EVHDLR(KILL, kill),
		EVHDLR(EXEC, exec),
		EVHDLR(PTRACE_ATTACH, ptrace_attach),
		EVHDLR(TRACEE_EXITED, tracee_exited),
		EVHDLR(TRACEE_STARTED, tracee_started),
};

#undef EVHDLR


/**
 * Shortcut macro for defining a simple netlink attribute entry for use in
 * netlink policies.
 */
#define NLA_POLICY_ENTRY(attr_name, value_type) \
		[(UP_NLA_ ##attr_name)] = { .type = (NLA_ ##value_type) }

/**
 * Base netlink policy as used by upolicy
 */
static const struct nla_policy base_policy[UP_NLA_MAX + 1] = {
		NLA_POLICY_ENTRY(EVENTNO, U16),
		NLA_POLICY_ENTRY(UCONTEXT_ID, U16),
		NLA_POLICY_ENTRY(SOCKET_LOCAL, NESTED),
		NLA_POLICY_ENTRY(SOCKET_REMOTE, NESTED),
		NLA_POLICY_ENTRY(CLONE_FLAGS, U64),
		NLA_POLICY_ENTRY(SIGNO, U32),
		NLA_POLICY_ENTRY(PID, U32),
		NLA_POLICY_ENTRY(PATH, STRING),
		NLA_POLICY_ENTRY(PTRACE_MODE, U32),
};

static const struct nla_policy socket_nested_policy[UP_NLA_SOCKET_MAX + 1] = {
		NLA_POLICY_ENTRY(SOCKET_FAMILY, U32),
		NLA_POLICY_ENTRY(SOCKET_TYPE, U32),
		NLA_POLICY_ENTRY(SOCKET_PROTO, U32),
		NLA_POLICY_ENTRY(SOCKET_ADDRLEN, U32),
		[UP_NLA_SOCKET_INADDR] = { .minlen = sizeof(struct sockaddr_in) },
		[UP_NLA_SOCKET_IN6ADDR] = { .minlen = sizeof(struct sockaddr_in6) },
		[UP_NLA_SOCKET_UNADDR] = { .minlen = sizeof(struct sockaddr_un) },
		[UP_NLA_SOCKET_NLADDR] = { .minlen = sizeof(struct sockaddr_nl) },

};

int upolicy_msg_send_sync(struct nl_msg *msg) {
	struct sync_waiter *waiter = malloc(sizeof(struct sync_waiter));
	struct nlmsghdr *msghdr = nlmsg_hdr(msg);
	int rc;

	if (waiter == NULL)
		return -ENOMEM;

	nl_complete_msg(sock, msg);
	waiter->seq = msghdr->nlmsg_seq;
	sem_init(&waiter->wait_semaphore, 0, 0);

	sem_wait(&sync_waiter_list_sem);
	list_prepend(&sync_waiter_list, &waiter->entry);
	sem_post(&sync_waiter_list_sem);

	up_dprintf(NETLINK, "Waiting for sock_write_sem to become available...");
	rc = sem_wait(&sock_write_sem);
	if (rc) {
		up_eprintf("sem_wait failed: %s (%d)", strerror(errno), errno);
		rc = errno;
		goto out_err;
	}

	up_dprintf(NETLINK, "Sending msg@%p...", msg);
	rc = nl_send(sock, msg);
	up_dprintf(NETLINK, "msg@%p sent, result=%d", msg, rc);

	if (rc < 0) {
		out_err:
		up_eprintf("msg@%p: nl_send failed: %s (%d)", msg, strerror(rc), rc);
		list_remove(&sync_waiter_list, &waiter->entry);
		free(waiter);
		return rc;
	}
	sem_wait(&waiter->wait_semaphore);

	rc = waiter->result;
	free(waiter);
	up_dprintf(NETLINK, "msg@%p: ACK received.", msg);

	if (sem_post(&sock_write_sem)) {
		up_eprintf("sem_post failed: %s (%d)", strerror(errno), errno);
		return errno;
	}

	return rc;
}

int upolicy_msg_send(struct nl_msg *msg) {
	int rc = 0;
	struct nl_sock *socket;
	assert(msg);

	up_dprintf(NETLINK, "Waiting for sock_write_sem to become available...");
	rc = sem_wait(&sock_write_sem);
	if (rc) {
		up_eprintf("sem_wait failed: %s (%d)", strerror(errno), errno);
		rc = errno;
		goto out_nopost;
	}
	socket = sock;
	if (sem_post(&sock_write_sem)) {
		up_eprintf("sem_post failed: %s (%d)", strerror(errno), errno);
		return errno;
	}

	/* This is the only thread writing to the socket right now ... */
	up_dprintf(NETLINK, "Sending msg@%p...", msg);
	rc = nl_send_auto(socket, msg);
	up_dprintf(NETLINK, "msg@%p sent, result=%d", msg, rc);

	out_nopost:
	return rc;
}

void upolicy_msg_destroy(struct nl_msg *msg) {
	if (msg)
		nlmsg_free(msg);
	up_dprintf(NETLINK, "msg@%p destroyed.", msg);
}

static struct nl_msg *msg_reply_init(struct upolicy_event_info *info,
		struct up_nlhdr **new, enum UP_CMD cmd) {
	struct nl_msg *msg = NULL;

	msg = upolicy_msg_init(new, cmd);
	if (msg != NULL) {
		(*new)->context_id = info->ctx->id;
		(*new)->pid = info->pid;
		(*new)->tid = info->tid;
	}
	return msg;
}
static struct nl_msg *msg_decision_init(struct upolicy_event_info *info,
		upolicy_decision decision) {
	struct nl_msg *msg = NULL;
	struct up_nlhdr *nlhdr = NULL;

	msg = msg_reply_init(info, &nlhdr, UPOLICY_COMMAND(DECISION));

	if (!msg) {
		return msg;
	}

	nla_put_u8(msg, UP_NLA_DECISION, decision);
	return msg;
}

static int genl_parse_socket(struct nlattr *attr, int *family, int *addrlen,
		struct sockaddr **address) {
	struct nlattr *sock_attrs[UP_NLA_SOCKET_MAX+1];
	int rc = 0;

	assert(attr && family && addrlen && address);

	if ((rc = nla_parse_nested(sock_attrs, UP_NLA_SOCKET_MAX,
			attr, (struct nla_policy*) socket_nested_policy))) {
		up_eprintf("nla_parse_nested failed: %d", rc);
		return -EINVAL;
	}

	/* Mandatory attributes: family and addrlen */
	if (!sock_attrs[UP_NLA_SOCKET_FAMILY] || !sock_attrs[UP_NLA_SOCKET_ADDRLEN]) {
		up_eprintf("Attribute missing (family@%p,addrlen@%p)",
				sock_attrs[UP_NLA_SOCKET_FAMILY],
				sock_attrs[UP_NLA_SOCKET_ADDRLEN]);
		return -EINVAL;
	}

	/* One of the INADDR, IN6ADDR or UNADDR must be present. */
	if (!sock_attrs[UP_NLA_SOCKET_INADDR] && !sock_attrs[UP_NLA_SOCKET_IN6ADDR] &&
			!sock_attrs[UP_NLA_SOCKET_UNADDR] && !sock_attrs[UP_NLA_SOCKET_NLADDR]) {
		up_eprintf("All of INADDR, IN6ADDR, UNADDR and NLADDR are missing.");
		return -EINVAL;
	}

	/* Now that all are present we can safely set our pointers... */
	*family = nla_get_u32(sock_attrs[UP_NLA_SOCKET_FAMILY]);
	*addrlen = nla_get_u32(sock_attrs[UP_NLA_SOCKET_ADDRLEN]);

	enum UP_NLA_SOCK addr_attr = UP_NLA_SOCKET_UNSPEC;

	if (sock_attrs[UP_NLA_SOCKET_INADDR]) {
		addr_attr = UP_NLA_SOCKET_INADDR;
	} else if (sock_attrs[UP_NLA_SOCKET_IN6ADDR]) {
		addr_attr = UP_NLA_SOCKET_IN6ADDR;
	} else if (sock_attrs[UP_NLA_SOCKET_UNADDR]){
		addr_attr = UP_NLA_SOCKET_UNADDR;
	} else {
		addr_attr = UP_NLA_SOCKET_NLADDR;
	}

	*address = (struct sockaddr*) nla_data(sock_attrs[addr_attr]);
	return 0;
}

struct nl_msg *upolicy_msg_init(struct up_nlhdr **nlhdr, enum UP_CMD cmd) {
	struct nl_msg *msg = NULL;
	struct up_nlhdr *msg_nlhdr;

	assert(sock);
	assert(family_id);

	msg = nlmsg_alloc();
	if (!msg) {
		up_eprintf("nlmsg_alloc failed.");
		goto out;
	}

	msg_nlhdr = genlmsg_put(msg, NL_AUTO_PID, NL_AUTO_SEQ, family_id,
			sizeof(struct up_nlhdr), 0, cmd, UP_NL_VERSION);

	if (!msg_nlhdr) {
		up_eprintf("genlmsg_put failed.");
		goto out_free;
	}

	if (nlhdr == NULL) {
		struct up_nlhdr *hdr_tmp;
		nlhdr = &hdr_tmp;
		hdr_tmp = (struct up_nlhdr*) &up_nullhdr;
	} else {
		*nlhdr = msg_nlhdr;
	}


	out:
	return msg;

	out_free:
	nlmsg_free(msg);
	msg = NULL;
	goto out;
	return NULL; /* unreachable */
}

/**
 * Netlink ACK handler function.
 * This is required for our custom implementation of send_sync.
 */
static int __handle_ack(struct nl_msg *msg, void *unused) {
	struct nlmsghdr *hdr = nlmsg_hdr(msg);
	struct list_entry *entry;

	sem_wait(&sync_waiter_list_sem);
	list_foreach(&sync_waiter_list, entry) {
		struct sync_waiter *waiter = list_entry(entry, struct sync_waiter, entry);
		if (waiter->seq == hdr->nlmsg_seq) {
			waiter->result = 0;
			sem_post(&waiter->wait_semaphore);
			up_dprintf(NETLINK, "waiter woken up...");
			list_remove(&sync_waiter_list, entry);
			break;
		}
	}

	sem_post(&sync_waiter_list_sem);
	return NL_OK;
}

static int __handle_error(struct sockaddr_nl *nla, struct nlmsgerr *nlerr, void *unused) {
	struct nlmsghdr *hdr = &(nlerr->msg);
	struct list_entry *entry;

	up_dprintf(NETLINK, "Received error %d for seq=%d", nlerr->error, hdr->nlmsg_seq);

	sem_wait(&sync_waiter_list_sem);
	list_foreach(&sync_waiter_list, entry) {
		struct sync_waiter *waiter = list_entry(entry, struct sync_waiter, entry);
		if (waiter->seq == hdr->nlmsg_seq) {
			waiter->result = nlerr->error;
			sem_post(&waiter->wait_semaphore);
			up_dprintf(NETLINK, "waiter woken up...");
			list_remove(&sync_waiter_list, entry);
			break;
		}
	}
	sem_post(&sync_waiter_list_sem);
	return NL_OK;
}

static int __handle_invalid(struct nl_msg *msg, void *unused) {
	struct nlmsghdr *hdr = nlmsg_hdr(msg);
	struct list_entry *entry;

	up_dprintf(NETLINK, "Received invalid message.");

	sem_wait(&sync_waiter_list_sem);
	up_dprintf(NETLINK, "looking for waiter...");
	list_foreach(&sync_waiter_list, entry) {
		struct sync_waiter *waiter = list_entry(entry, struct sync_waiter, entry);
		up_dprintf(NETLINK, "checking waiter: %p", waiter);
		if (waiter->seq == hdr->nlmsg_seq) {
			up_dprintf(NETLINK, "found waiter @%p", waiter);
			waiter->result = -1;
			sem_post(&waiter->wait_semaphore);
			up_dprintf(NETLINK, "waiter woken up...");
			list_remove(&sync_waiter_list, entry);
			break;
		}
	}

	if (!entry) {
		up_dprintf(NETLINK, "waiter not found...");
	}
	sem_post(&sync_waiter_list_sem);
	return NL_OK;
}

/**
 * Main netlink message handler.
 * This function is called by libnl whenever a valid message is received.
 * It then fetches information common to all netlink message handler functions,
 * looks up the function in the up_handlers array and hands over control to the
 * function in charge of the message received.
 */
static int __handle_nlmsg(struct nl_msg *msg, void *unused) {
	struct nlmsghdr *hdr = nlmsg_hdr(msg);
	struct genlmsghdr *genlhdr = nlmsg_data(hdr);
	struct up_nlhdr *up_nlhdr = NULL;
	int rc = 0;

	up_dprintf(NETLINK, "received nlmsg@%p, cmd=%d", msg, genlhdr->cmd);

	up_nlhdr = genlmsg_data(genlhdr);

	if (genlhdr->cmd > UP_NLC_MAX) {
		up_eprintf("command > CMD_MAX: %d > %d", genlhdr->cmd, UP_NLC_MAX);
		rc = -EINVAL;
		goto out;
	}

	if (!up_handlers[genlhdr->cmd]) {
		up_eprintf("no handler for command %d found.", genlhdr->cmd);
		rc = -EINVAL;
		goto out;
	}

	rc = up_handlers[genlhdr->cmd](msg, hdr, genlhdr, up_nlhdr);
	up_dprintf(NETLINK, "handler %p returned %d", up_handlers[genlhdr->cmd], rc);
	out:
	return NL_OK;
}

/****************************************************************************************
 * BEGIN library-local functions
 ****************************************************************************************/
__internal__ int upolicy_netlink_init(void) {
	int rc = 0;
	int fd = 0;
	int i = 0;
	int flags = 0;
	struct nl_cb *cb = nl_cb_alloc(NL_CB_DEFAULT);

	if (!cb) {
		up_eprintf("nl_cb_alloc failed.");
		rc = -ENOMEM;
		goto out_nounlock;
	}

	epoll_fd = epoll_create1(EPOLL_CLOEXEC);


	if (epoll_fd < 0) {
		up_eprintf("epoll_create() failed: %s (%d)", strerror(errno), errno);
		nl_cb_put(cb);
		goto out_nounlock;
	}

	rc = sem_init(&receiver_exit_sem, 0, 0);
	if (rc) {
		up_eprintf("sem_init(receiver_exit_sem) failed: %s (%d)", strerror(errno), errno);
		nl_cb_put(cb);
		close(epoll_fd);
		epoll_fd = -1;
		goto out_nounlock;
	}

	rc = sem_init(&sync_waiter_list_sem, 0, 1);
	if (rc) {
		up_eprintf("sem_init(sync_waiter_list_sem) failed: %s (%d)", strerror(errno), errno);
		nl_cb_put(cb);
		sem_destroy(&receiver_exit_sem);
		close(epoll_fd);
		epoll_fd = -1;
		goto out_nounlock;
	}

	rc = sem_init(&event_info_unused_semaphore, 0, 0);
	if (rc) {
		up_eprintf("sem_init(event_info_unused_semaphore) failed: %s (%d)",
				strerror(errno), errno);
		nl_cb_put(cb);
		sem_destroy(&receiver_exit_sem);
		sem_destroy(&sync_waiter_list_sem);
		close(epoll_fd);
		epoll_fd = -1;
		goto out_nounlock;
	}

	rc = pthread_rwlock_wrlock(&sock_rwlock);
	if (rc) {
		up_eprintf("pthread_rwlock_wrlock failed: %s (%d)", strerror(errno), errno);
		nl_cb_put(cb);
		sem_destroy(&receiver_exit_sem);
		sem_destroy(&sync_waiter_list_sem);
		close(epoll_fd);
		epoll_fd = -1;
		goto out_nounlock;
	}

	if (sock) {
		up_eprintf("socket exists.");
		nl_cb_put(cb);
		sem_destroy(&receiver_exit_sem);
		sem_destroy(&sync_waiter_list_sem);
		rc = -EEXIST;
		close(epoll_fd);
		epoll_fd = -1;
		goto out;
	}

	rc = sem_init(&sock_write_sem, 0, 1);
	if (rc) {
		up_eprintf("sem_init failed (write sem): %s (%d)", strerror(errno), errno);
		rc = errno;
		nl_cb_put(cb);
		sem_destroy(&receiver_exit_sem);
		sem_destroy(&sync_waiter_list_sem);
		close(epoll_fd);
		epoll_fd = -1;
		goto out;
	}

	nl_cb_set(cb, NL_CB_VALID, NL_CB_CUSTOM, __handle_nlmsg, NULL);
	nl_cb_set(cb, NL_CB_ACK, NL_CB_CUSTOM, __handle_ack, NULL);
	nl_cb_set(cb, NL_CB_INVALID, NL_CB_CUSTOM, __handle_invalid, NULL);
	nl_cb_err(cb, NL_CB_CUSTOM, __handle_error, NULL);
	sock = nl_socket_alloc_cb(cb);

	if (!sock) {
		up_eprintf("nl_socket_alloc_cb failed.");
		rc = -ENOMEM;
		nl_cb_put(cb);
		sem_destroy(&sock_write_sem);
		sem_destroy(&receiver_exit_sem);
		sem_destroy(&sync_waiter_list_sem);
		close(epoll_fd);
		epoll_fd = -1;
		goto out;
	}

	nl_socket_set_passcred(sock, 0);
	nl_socket_disable_seq_check(sock);

	rc = genl_connect(sock);
	if (rc) {
		up_eprintf("genl_connect failed: %s (%d)", nl_geterror(rc), rc);
		goto out_sk_free_err;
	}

	if (nl_socket_set_nonblocking(sock) < 0) {
		up_eprintf("nl_socket_set_nonblocking failed: %s (%d)",
				strerror(errno), errno);
		goto out_sk_free_err;
	}

	fd = nl_socket_get_fd(sock);
	flags = fcntl(fd, F_GETFD, 0);
	if (flags < 0) {
		up_eprintf("fcntl(fd, F_GETFD, 0) failed: %s (%d)", strerror(errno), errno);
		goto out_sk_free_err;
	}


	if (!(flags & FD_CLOEXEC)) {
		if (fcntl(fd, F_SETFD, flags | FD_CLOEXEC)) {
			up_eprintf("fcntl(fd, F_SETFD, %x) failed: %s (%d)", flags | FD_CLOEXEC,
					strerror(errno), errno);
			goto out_sk_free_err;
		}
	}

	rc = epoll_ctl(epoll_fd, EPOLL_CTL_ADD, fd, &ep_event);

	if (rc < 0) {
		up_eprintf("epoll_ctl(%d, EPOLL_CTL_ADD, %d, %p) failed: %s (%d)",
				epoll_fd, fd, &ep_event, strerror(errno), errno);
		goto out_sk_free_err;
	}

	family_id = genl_ctrl_resolve(sock, UP_NL_FAMILY_NAME);
	if (family_id < 0) {
		up_eprintf("genl_ctrl_resolve failed: %s (%d)", nl_geterror(family_id),
				family_id);
		rc = -ENOSYS;
		family_id = 0;
		goto out_sk_free_err;
	}

	if ((rc = pthread_create(&receiver_thread, NULL, receiver_thread_main, NULL))) {
		up_eprintf("could not create receiver thread: %s (%d)", strerror(rc), rc);
		family_id = 0;
		goto out_sk_free_err;
	}

	rc = genl_send_init();
	if (rc < 0) {
		up_eprintf("genl_send_init failed: %s (%d)", strerror(rc), rc);
		goto out_sk_free_err;
	}

	for(i = 0; i < MAX_EVENT_INFO_COUNT; i++) {
		struct event_info *evinfo = malloc(sizeof(struct event_info));
		if (!evinfo) {
			up_eprintf("malloc() failed.");
			rc = -ENOMEM;
			goto out_sk_free_err;
		}
		memset(evinfo, 0, sizeof(struct event_info));
		evinfo->type = EV_INFO_UNUSED;
		list_append(&event_info_unused_list, &evinfo->entry);
		sem_post(&event_info_unused_semaphore);
	}

	up_dprintf(NETLINK, "initialized. sock@%p", sock);
	out:
	pthread_rwlock_unlock(&sock_rwlock);
	out_nounlock:
	return rc;

	out_sk_free_err:
	sem_destroy(&sock_write_sem);
	sem_destroy(&receiver_exit_sem);
	sem_destroy(&sync_waiter_list_sem);
	nl_socket_free(sock);
	sock = NULL;
	if (epoll_fd >= 0) {
		close(epoll_fd);
		epoll_fd = -1;
	}
	goto out;
	return 0; /* unreachable */
}

__internal__ void upolicy_netlink_cleanup(void) {
	if (sem_post(&receiver_exit_sem)) {
		up_dprintf(NETLINK, "Waiting for receiver thread to exit...");
		pthread_join(receiver_thread, NULL);
	}

	if (epoll_fd) {
		close(epoll_fd);
		epoll_fd = -1;
	}

	if (!pthread_rwlock_wrlock(&sock_rwlock)) {
		if (sock) {
			nl_close(sock);
			nl_socket_free(sock);
			sock = NULL;
		}
		pthread_rwlock_unlock(&sock_rwlock);
	}
	else {
		up_eprintf("pthread_rwlock_wrlock failed.");
	}
	up_dprintf(NETLINK, "cleaned up.");
}
/****************************************************************************************
 * END library-local functions
 ****************************************************************************************/

static int genl_send_init(void) {
	struct nl_msg *msg;
	int rc;
	assert(sock);

	msg = upolicy_msg_init(NULL, UPOLICY_COMMAND(INIT));
	if (!msg) {
		up_eprintf("upolicy_msg_init failed.");
		return -ENOMEM;
	}

	rc = upolicy_msg_send_sync(msg);
	if (rc < 0) {
		up_eprintf("msg_send_sync failed: %s (%d)", strerror(rc), rc);
	} else {
		up_dprintf(NETLINK, "msg_send_sync: success.");
	}
	return rc;
}

static inline int genl_parse(struct nlmsghdr *nlh, struct nlattr **attrs,
		const struct nla_policy *policy) {
	int rc = 0;
	/*
	 * NOTE: We do have to manually discard the const pointer on policy here, because
	 * libnl wants a non-const policy struct.
	 */
	rc = genlmsg_parse(nlh, sizeof(struct up_nlhdr), attrs, UP_NLA_MAX,
			(struct nla_policy*) policy);
	if (rc) {
		up_eprintf("genl_parse failed: %d", rc);
	}
	return rc;
}

static int __handle_event(struct nl_msg *msg, struct nlmsghdr *nlhdr,
		struct genlmsghdr *genl_hdr, struct up_nlhdr *up_nlhdr, int is_notification) {
	struct nlattr *attrs[UP_NLA_MAX + 1];
	uint16_t eventno;
	struct upolicy_context *ctx = NULL;
	struct upolicy_event_info *info;
	struct upolicy_ops *ops = NULL;
	int rc = 0;

	if ((rc = genl_parse(nlhdr, attrs, base_policy))) {
		up_eprintf("msg@%p: __genlparse failed: %s (%d)", msg, strerror(rc), rc);
		return rc;
	}

	if (!attrs[UP_NLA_EVENTNO]) {
		up_eprintf("msg@%p: EVENTNO missing", msg);
		return -EINVAL;
	}

	eventno = nla_get_u16(attrs[UP_NLA_EVENTNO]);

	if (eventno > UPOLICY_EV_MAX) {
		up_eprintf("msg@%p: eventno > EV_MAX - %u > %u", msg, eventno, UPOLICY_EV_MAX);
		return -EINVAL;
	}
	else if (event_handlers[eventno] == NULL) {
		up_eprintf("msg@%p: handler for event %u missing.", msg, eventno);
		return -EINVAL;
	}

	ctx = upolicy_context_find(up_nlhdr->context_id);

	info = event_info_get();
	info->ctx = ctx;
	info->pid = up_nlhdr->pid;
	info->tid = up_nlhdr->tid;
	info->is_notification = is_notification;

	if (ctx) {
		if (is_notification) {
			ops = (struct upolicy_ops*) ctx->notify_ops;
		} else {
			ops = (struct upolicy_ops*) ctx->question_ops;
		}
	}

	up_dprintf(NETLINK, "Received event %d %s.", eventno,
			is_notification ? "notification" : "question");
	rc = event_handlers[eventno](ctx, msg, nlhdr, genl_hdr, up_nlhdr, eventno,
			info, (const struct upolicy_ops*) ops);

	if (rc == UP_DECISION(POSTPONE)) {
		/* postpone event */
		event_info_postpone(info, msg);
		return 0;
	}
	else if (!is_notification && rc > 0 && rc <= UP_EV_DECISION_MAX) {
		return upolicy_event_decide(info, rc);
	}

	event_info_put(info);
	return rc;
}

int upolicy_event_decide(struct upolicy_event_info *info,
		upolicy_decision decision) {
	struct nl_msg *reply_msg;
	int rc = 0;

	reply_msg = msg_decision_init(info, decision);

	if (!reply_msg) {
		up_eprintf("msg_decision_init() failed: %s (%d)", strerror(errno), errno);
		return -ENOMEM;
	}

	if ((rc = upolicy_msg_send(reply_msg)) < 0) {
		return rc;
	}

	event_info_put(info);
	return rc;
}

/****************************************************************************************
 * BEGIN netlink handlers
 ****************************************************************************************/
nlhdlr(question) {
	return __handle_event(msg, nlhdr, genl_hdr, up_nlhdr, 0);
}

nlhdlr(notification) {
	return __handle_event(msg, nlhdr, genl_hdr, up_nlhdr, 1);
}
/****************************************************************************************
 * END netlink handlers
 ****************************************************************************************/

/****************************************************************************************
 * BEGIN event handlers
 ****************************************************************************************/
#define invoke_handler(cb_name, ...) \
			up_dprintf(NETLINK, "Invoking handler %s.", #cb_name); \
			decision = ops-> cb_name (info, ##__VA_ARGS__); \
			up_dprintf(NETLINK, "Result of call to handler %s was %d.", #cb_name, decision)


eventhdlr(tracee_exited) {
	upolicy_decision decision = UP_DECISION(ALLOW);

	up_dprintf(NETLINK, "tracee_exited event received for ctx=%d (%p), pid=%d",
			info->ctx ? info->ctx->id : 0, info->ctx, info->pid);
	if (info->ctx && ops->tracee_exited) {
		invoke_handler(tracee_exited);
	}
	return decision;
}

eventhdlr(tracee_started) {
	upolicy_decision decision = UP_DECISION(ALLOW);
	up_dprintf(NETLINK, "tracee_started event received for ctx=%d (%p), pid=%d",
			info->ctx ? info->ctx->id : 0, info->ctx, info->pid);
	if (info->ctx && ops->tracee_started) {
		invoke_handler(tracee_started);
	}
	return decision;
}

eventhdlr(all_tracees_exited) {
	/* No need to check anything here. */
	up_dprintf(NETLINK, "All tracees exited event received.");
	pthread_mutex_lock(&tracees_exited_mutex);
	pthread_cond_broadcast(&tracees_exited_cond);
	tracees_active = 0;
	pthread_mutex_unlock(&tracees_exited_mutex);
	return 0;
}

eventhdlr(ctx_all_tracees_exited) {
	upolicy_decision decision = UP_DECISION(ALLOW);

	if (ops->all_tracees_exited) {
		up_dprintf(NETLINK, "All tracees of context %d exited.", ctx->id);
		invoke_handler(all_tracees_exited);
	}
	return decision;
}

eventhdlr(tracee_new) {
	up_ctx_id ctx_id = 0;
	struct nl_msg *response_msg;
	struct up_nlhdr *response_hdr;
	int rc;

	ctx_id = upolicy_context_find_newtracee(up_nlhdr->pid);

	response_msg = upolicy_msg_init(&response_hdr, UPOLICY_COMMAND(DECISION));
	if (response_msg == NULL) {
		up_eprintf("msg_init failed.");
		return UP_DECISION(KILL);;
	}

	response_hdr->pid = up_nlhdr->pid;
	response_hdr->tid = up_nlhdr->tid;
	response_hdr->context_id = ctx_id;
	nla_put_u8(response_msg, UP_NLA_DECISION, UP_DECISION(ALLOW));

	up_dprintf(NETLINK, "New tracee(pid=%d,tid=%d) - setting context ID to %d", up_nlhdr->pid,
			up_nlhdr->tid, ctx_id);

	rc = upolicy_msg_send(response_msg);
	return rc < 0 ? UP_DECISION(KILL) : UP_DECISION(ALLOW);
}

eventhdlr(context_created) {
	struct nlattr *attrs[UP_NLA_MAX+1];
	int rc = genl_parse(nlhdr, attrs, base_policy);
	up_ctx_id local_id = 0;

	if (rc) {
		return rc;
	}

	if (!attrs[UP_NLA_UCONTEXT_ID]) {
		up_eprintf("msg@%p: UCONTEXT_ID attribute missing.", msg);
		return UP_DECISION(KILL);
	}

	local_id = nla_get_u16(attrs[UP_NLA_UCONTEXT_ID]);

	ctx = upolicy_context_find_create(local_id);
	if (!ctx) {
		up_eprintf("Context with UCONTEXT_ID=%d not found.", local_id);
		return UP_DECISION(KILL);
	}

	ctx->id = up_nlhdr->context_id;
	up_dprintf(NETLINK, "Waking up context@%p: id=%d", ctx, ctx->id);
	sem_post(&ctx->created_sem);

	return UP_DECISION(ALLOW);
}

eventhdlr(tracer_init) {
	upolicy_decision decision = UP_DECISION(ALLOW);

	if (ops->tracer_init != NULL) {
		invoke_handler(tracer_init);
	}

	return decision;
}

eventhdlr(socket_accept) {
	upolicy_decision decision = UP_DECISION(ALLOW);
	if (ops->socket_accept != NULL) {
		int family_local = 0;
		int family_remote = 0;
		struct sockaddr *address_local = NULL;
		struct sockaddr *address_remote = NULL;
		int addrlen_local = 0;
		int addrlen_remote = 0;
		int rc = 0;
		struct nlattr *attrs[UP_NLA_MAX+1];

		rc = genl_parse(nlhdr, attrs, base_policy);

		if (rc) {
			up_eprintf("Parsing genl policy failed: %d", rc);
			return UP_DECISION(KILL);
		}

		if (!attrs[UP_NLA_SOCKET_LOCAL]) {
			up_eprintf("UP_NLA_SOCKET_LOCAL missing in message.");
			return UP_DECISION(KILL);
		} else if (!attrs[UP_NLA_SOCKET_REMOTE]) {
			up_eprintf("UP_NLA_SOCKET_REMOTE missing in message.");
			return UP_DECISION(KILL);
		}

		if ((rc = genl_parse_socket(attrs[UP_NLA_SOCKET_LOCAL], &family_local,
				&addrlen_local, &address_local))) {
			up_eprintf("parsing local socket failed: %d", rc);
			return UP_DECISION(KILL);
		}

		if ((rc = genl_parse_socket(attrs[UP_NLA_SOCKET_REMOTE], &family_remote,
				&addrlen_remote, &address_remote))) {
			up_eprintf("parsing remote socket failed: %d", rc);
			return UP_DECISION(KILL);
		}

		if (family_remote != family_local) {
			up_eprintf("local and remote families do not match (%d vs %d).",
					family_local, family_remote);
			return UP_DECISION(KILL);
		}

		invoke_handler(socket_accept, family_local, address_local, addrlen_local,
				address_remote, addrlen_remote);
	}
	return decision;
}

eventhdlr(socket_bind) {
	upolicy_decision decision = UP_DECISION(ALLOW);
	if (ops->socket_bind != NULL) {
		int family = 0;
		struct sockaddr *address = NULL;
		int addrlen = 0;
		int rc = 0;
		struct nlattr *attrs[UP_NLA_MAX+1];

		rc = genl_parse(nlhdr, attrs, base_policy);

		if (rc) {
			up_eprintf("Parsing genl policy failed: %d", rc);
			return UP_DECISION(KILL);
		}

		if (!attrs[UP_NLA_SOCKET_LOCAL]) {
			up_eprintf("UP_NLA_SOCKET_LOCAL missing in message.");
			return UP_DECISION(KILL);
		}

		if ((rc = genl_parse_socket(attrs[UP_NLA_SOCKET_LOCAL], &family, &addrlen, &address))) {
			up_eprintf("parsing socket failed: %d", rc);
			return UP_DECISION(KILL);
		}

		invoke_handler(socket_bind, family, address, addrlen);
	}
	return decision;
}

eventhdlr(socket_connect) {
	upolicy_decision decision = UP_DECISION(ALLOW);
	if (ops->socket_connect != NULL) {
		int family_local = 0;
		int family_remote = 0;
		struct sockaddr *address_local = NULL;
		struct sockaddr *address_remote = NULL;
		int addrlen_local = 0;
		int addrlen_remote = 0;
		int rc = 0;
		struct nlattr *attrs[UP_NLA_MAX+1];

		rc = genl_parse(nlhdr, attrs, base_policy);

		if (rc) {
			up_eprintf("Parsing genl policy failed: %d", rc);
			return UP_DECISION(KILL);
		}

		if (!attrs[UP_NLA_SOCKET_LOCAL]) {
			up_eprintf("UP_NLA_SOCKET_LOCAL missing in message.");
			return UP_DECISION(KILL);
		} else if (!attrs[UP_NLA_SOCKET_REMOTE]) {
			up_eprintf("UP_NLA_SOCKET_REMOTE missing in message.");
			return UP_DECISION(KILL);
		}

		if ((rc = genl_parse_socket(attrs[UP_NLA_SOCKET_LOCAL], &family_local,
				&addrlen_local, &address_local))) {
			up_eprintf("parsing local socket failed: %d", rc);
			return UP_DECISION(KILL);
		}

		if ((rc = genl_parse_socket(attrs[UP_NLA_SOCKET_REMOTE], &family_remote,
				&addrlen_remote, &address_remote))) {
			up_eprintf("parsing remote socket failed: %d", rc);
			return UP_DECISION(KILL);
		}

		if (family_remote != family_local) {
			up_eprintf("local and remote families do not match (%d vs %d).",
								family_local, family_remote);
			return UP_DECISION(KILL);
		}

		invoke_handler(socket_connect, family_local, address_local, addrlen_local,
				address_remote, addrlen_remote);
	}
	return decision;
}

eventhdlr(socket_create) {
	upolicy_decision decision = UP_DECISION(ALLOW);

	if (ops->socket_create != NULL) {
		int family = 0;
		int type = 0;
		int protocol = 0;
		int rc = 0;
		struct nlattr *attrs[UP_NLA_MAX+1];
		struct nlattr *sock_attrs[UP_NLA_SOCKET_MAX+1];

		rc = genl_parse(nlhdr, attrs, base_policy);

		if (rc) {
			up_eprintf("Parsing genl policy failed: %d", rc);
			return UP_DECISION(KILL);
		}

		if (!attrs[UP_NLA_SOCKET_LOCAL]) {
			up_eprintf("UP_NLA_SOCKET_LOCAL missing in message.");
			return UP_DECISION(KILL);
		}

		if ((rc = nla_parse_nested(sock_attrs, UP_NLA_SOCKET_MAX,
				attrs[UP_NLA_SOCKET_LOCAL], (struct nla_policy*) socket_nested_policy))) {
			up_eprintf("nla_parse_nested failed: %d", rc);
			return UP_DECISION(KILL);
		}

		if (!sock_attrs[UP_NLA_SOCKET_FAMILY] || !sock_attrs[UP_NLA_SOCKET_TYPE]
		    || !sock_attrs[UP_NLA_SOCKET_PROTO]) {
			up_eprintf("Attribute missing (family@%p,type@%p,proto@%p)",
					sock_attrs[UP_NLA_SOCKET_FAMILY], sock_attrs[UP_NLA_SOCKET_TYPE],
					sock_attrs[UP_NLA_SOCKET_PROTO]);
			return UP_DECISION(KILL);
		}

		family = (int) nla_get_u32(sock_attrs[UP_NLA_SOCKET_FAMILY]);
		type = (int) nla_get_u32(sock_attrs[UP_NLA_SOCKET_TYPE]);
		protocol = (int) nla_get_u32(sock_attrs[UP_NLA_SOCKET_PROTO]);

		invoke_handler(socket_create, family, type, protocol);
	}
	return decision;
}

eventhdlr(socket_listen) {
	upolicy_decision decision = UP_DECISION(ALLOW);
	if (ops->socket_listen != NULL) {
		int family = 0;
		struct sockaddr *address = NULL;
		int addrlen = 0;
		int rc = 0;
		struct nlattr *attrs[UP_NLA_MAX+1];

		rc = genl_parse(nlhdr, attrs, base_policy);

		if (rc) {
			up_eprintf("Parsing genl policy failed: %d", rc);
			return UP_DECISION(KILL);
		}

		if (!attrs[UP_NLA_SOCKET_LOCAL]) {
			up_eprintf("UP_NLA_SOCKET_LOCAL missing in message.");
			return UP_DECISION(KILL);
		}

		if ((rc = genl_parse_socket(attrs[UP_NLA_SOCKET_LOCAL], &family, &addrlen, &address))) {
			up_eprintf("parsing socket failed: %d", rc);
			return UP_DECISION(KILL);
		}

		invoke_handler(socket_listen, family, address, addrlen);
	}
	return decision;
}

eventhdlr(kill) {
	upolicy_decision decision = UP_DECISION(ALLOW);
	if (ops->kill) {
		struct nlattr *attrs[UP_NLA_MAX+1];
		int rc = genl_parse(nlhdr, attrs, base_policy);
		pid_t pid = 0;
		int signo = 0;
		if (rc) {
			up_eprintf("Parsing genl policy failed: %d", rc);
			return UP_DECISION(KILL);
		}

		if (!attrs[UP_NLA_SIGNO] || !attrs[UP_NLA_PID]) {
			up_eprintf("Attribute missing (signo@%p,pid@%p)", attrs[UP_NLA_SIGNO],
					attrs[UP_NLA_PID]);
			return UP_DECISION(KILL);
		}

		pid = nla_get_u32(attrs[UP_NLA_PID]);
		signo = nla_get_u32(attrs[UP_NLA_SIGNO]);

		invoke_handler(kill, pid, signo);
	}
	return decision;
}

eventhdlr(exec) {
	upolicy_decision decision = UP_DECISION(ALLOW);
	if (ops->exec) {
		struct nlattr *attrs[UP_NLA_MAX+1];
		int rc = genl_parse(nlhdr, attrs, base_policy);
		const char *path = NULL;

		if (rc) {
			up_eprintf("Parsing genl policy failed: %d", rc);
			return UP_DECISION(KILL);
		}

		if (!attrs[UP_NLA_PATH]) {
			up_eprintf("Path attribute missing.");
			return UP_DECISION(KILL);
		}

		path = nla_get_string(attrs[UP_NLA_PATH]);

		invoke_handler(exec, path);
	}
	return decision;
}

eventhdlr(ptrace_attach) {
	upolicy_decision decision = UP_DECISION(ALLOW);
	if (ops->ptrace_attach) {
		struct nlattr *attrs[UP_NLA_MAX+1];
		int rc = genl_parse(nlhdr, attrs, base_policy);
		pid_t pid;
		unsigned int mode;

		if (rc) {
			up_eprintf("Parsing genl policy failed: %d", rc);
			return UP_DECISION(KILL);
		}

		if (!attrs[UP_NLA_PID] || !attrs[UP_NLA_PTRACE_MODE]) {
			up_eprintf("Attribute missing, pid@%p,ptrace_mode@%p", attrs[UP_NLA_PID],
					attrs[UP_NLA_PTRACE_MODE]);
			return UP_DECISION(KILL);
		}

		pid = nla_get_u32(attrs[UP_NLA_PID]);
		mode = nla_get_u32(attrs[UP_NLA_PTRACE_MODE]);

		invoke_handler(ptrace_attach, pid, mode);
	}
	return decision;
}

/******************************************************************************
 * END event handlers
 *****************************************************************************/

/******************************************************************************
 * BEGIN event_info helpers
 *****************************************************************************/
static struct upolicy_event_info *event_info_get() {
	struct event_info *info;
	sem_wait(&event_info_unused_semaphore);

	pthread_mutex_lock(&event_info_unused_list_mutex);
	assert(event_info_unused_list.head != NULL);
	info = list_entry(event_info_unused_list.head, struct event_info, entry);
	assert(info->type == EV_INFO_UNUSED);
	info->type = EV_INFO_CURRENT;
	list_remove(&event_info_unused_list, &info->entry);
	pthread_mutex_unlock(&event_info_unused_list_mutex);

	memset(&info->info, 0, sizeof(struct upolicy_event_info));

	return &info->info;
}

static void event_info_put(struct upolicy_event_info *info) {
	/* This case is possible because struct upolicy_event_info is the first
	 * member of struct event_info. Passing any other data here will break
	 * things. I mean it.
	 */
	struct event_info *event_info = (struct event_info *) info;

	assert(event_info != NULL);
	assert(event_info->type != EV_INFO_UNUSED);

	if (event_info->type == EV_INFO_POSTPONED) {
		/* Postponed entries need to be removed from the postponed list first. */
		pthread_mutex_lock(&event_info_postponed_list_mutex);
		list_remove(&event_info_postponed_list, &event_info->entry);
		pthread_mutex_unlock(&event_info_postponed_list_mutex);

		nlmsg_free(event_info->msg);
		event_info->msg = NULL;
	}

	event_info->type = EV_INFO_UNUSED;
	memset(&event_info->info, 0, sizeof(struct upolicy_event_info));
	event_info->timestamp = 0;

	/* Lock the unused list and add the item */
	pthread_mutex_lock(&event_info_unused_list_mutex);
	list_append(&event_info_unused_list, &event_info->entry);
	pthread_mutex_unlock(&event_info_unused_list_mutex);

	/* finally post on the unused semaphore. */
	sem_post(&event_info_unused_semaphore);
}

static void event_info_postpone(struct upolicy_event_info *info,
		struct nl_msg *msg) {
	struct event_info *event_info = (struct event_info*) info;

	assert(info != NULL);
	assert(msg != NULL);
	assert(event_info->type == EV_INFO_CURRENT);

	/* Postpone decision */
	event_info->timestamp = time(0);
	nlmsg_get(msg);
	event_info->msg = msg;
	event_info->type = EV_INFO_POSTPONED;

	pthread_mutex_lock(&event_info_postponed_list_mutex);
	list_append(&event_info_postponed_list, &event_info->entry);
	pthread_mutex_unlock(&event_info_postponed_list_mutex);
}
/******************************************************************************
 * END event_info helpers
 *****************************************************************************/


int upolicy_join(void) {
	int rc = 0;
	struct timespec ts;

	if (pthread_mutex_trylock(&join_mutex) != 0) {
		up_eprintf("upolicy_join can only be called a single time.");
		return -EBUSY;
	}

	up_dprintf(NETLINK, "Running waitpid() loop...");
	pthread_mutex_lock(&tracees_exited_mutex);
	do {
		waitpid(-1, NULL, WNOHANG);

		if (!tracees_active)
			break;

		/* Wait for 50 msecs */
		if ((rc = clock_gettime(CLOCK_REALTIME, &ts))) {
			up_eprintf("clock_gettime failed.");
			break;
		}
		ts.tv_nsec += 1000 * 50;
	} while ((rc = pthread_cond_timedwait(&tracees_exited_cond,
			&tracees_exited_mutex, &ts)) == ETIMEDOUT);
	pthread_mutex_unlock(&tracees_exited_mutex);
	pthread_mutex_unlock(&join_mutex);
	up_dprintf(NETLINK, "All tracees exited.");

	return 0;
}

static void *receiver_thread_main(void* unused) {
	int rc = 0;

	up_dprintf(NETLINK, "starting to receive messages...");
	do {
		struct epoll_event ev;

		rc = epoll_wait(epoll_fd, &ev, 1, NETLINK_EPOLL_TIMEOUT);
		if (rc < 0) {
			up_eprintf("epoll_wait failed: %s (%d)\n", strerror(errno), errno);
		} else {
			/* No matter which event happened, we go ahead and process it. */
			rc = nl_recvmsgs_default(sock);
			if (rc < 0) {
				up_eprintf("Message receiving failed: %s (%d)", strerror(rc), rc);
			} else {
				up_dprintf(NETLINK, "Data received.");
			}
		}
		/* wait for 10ms */

	} while(sem_trywait(&receiver_exit_sem) && sock && rc >= 0);
	up_dprintf(NETLINK, "Receiver thread exited.");
	return (void*)0;
}

__internal__ void upolicy_set_tracees_active() {
	pthread_mutex_lock(&tracees_exited_mutex);
	if (!tracees_active)
		tracees_active = 1;
	pthread_mutex_unlock(&tracees_exited_mutex);
}
