/* handler_socket.c
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

#include <linux/net.h>

#include <linux/in.h>
#include <linux/in6.h>
#include <linux/un.h>

#include <net/af_unix.h>

#include <kupolicy/handler.h>
#include <kupolicy/netlink.h>
#include <kupolicy/tracee.h>
#include <kupolicy/upolicy.h>

static inline struct nlattr *__nla_socket_start(struct sk_buff *skb, enum UP_NLA type) {
	if (unlikely(type != UP_NLA_SOCKET_REMOTE && type != UP_NLA_SOCKET_LOCAL)) {
		return NULL;
	}
	return nla_nest_start(skb, type);
}

#define nla_socket_start(skb, type, attrs) \
		if (unlikely(!(attrs = __nla_socket_start(skb, UP_NLA_SOCKET_ ##type))))	\
			goto nla_put_failure;

#define nla_socket_end(skb, start) nla_nest_end(skb, start)
#define nla_socket_cancel(skb, start) nla_nest_cancel(skb, start)

static inline int __nla_put_socket_address(struct sk_buff *skb, struct socket *sock,
		struct sockaddr *address, int addrlen) {
	int rc = 0;
	if (unlikely(!sock->ops)) {
		up_eprintk("Cannot detect family type: socket->ops is NULL (socket=%p).\n", sock);
		rc = -EINVAL;
		goto out;
	}

	switch(sock->ops->family) {
		case PF_INET:
			NLA_PUT(skb, UP_NLA_SOCKET_INADDR, sizeof(struct sockaddr_in), address);
			break;

		case PF_INET6:
			NLA_PUT(skb, UP_NLA_SOCKET_IN6ADDR, sizeof(struct sockaddr_in6), address);
			break;

		case PF_UNIX:
			NLA_PUT(skb, UP_NLA_SOCKET_UNADDR, sizeof(struct sockaddr_un), address);
			break;

		case PF_NETLINK:
			NLA_PUT(skb, UP_NLA_SOCKET_NLADDR, sizeof(struct sockaddr_nl), address);
			break;

		default:
			up_eprintk("Unsupported socket protocol family %d.\n", sock->ops->family);
			rc = -EINVAL;
			goto out;
			break;
	}
	NLA_PUT_U32(skb, UP_NLA_SOCKET_ADDRLEN, addrlen);
	NLA_PUT_U32(skb, UP_NLA_SOCKET_FAMILY, sock->ops->family);

	out:
	return rc;

	nla_put_failure:
	rc = -ENOMEM;
	return rc;
}

#define nla_put_socket_address(skb, sk, sa, sa_len) \
		if ((rc = __nla_put_socket_address(skb, sk, sa, sa_len)))	\
			goto nla_put_failure;

static inline int __nla_put_socket_info(struct sk_buff *skb, struct socket *sock,
		int remote) {
	int rc = 0;
	struct sockaddr_in sa_in;
	struct sockaddr_in6 sa_in6;
	struct sockaddr_un sa_un;
	struct sockaddr_nl sa_nl;
	struct sockaddr *address;
	int addrlen = 0;

	if (unlikely(!sock->ops)) {
		up_eprintk("Cannot detect family type: socket->ops is NULL (socket=%p).\n", sock);
		rc = -EINVAL;
		goto out;
	}

	switch(sock->ops->family) {
		case PF_INET:
			address = (struct sockaddr*) &sa_in;
			break;
		case PF_INET6:
			address = (struct sockaddr*) &sa_in6;
			break;
		case PF_UNIX:
			address = (struct sockaddr*) &sa_un;
			break;

		case PF_NETLINK:
			address = (struct sockaddr*) &sa_nl;
			break;

		default:
			up_eprintk("Unsupported socket protocol family %d.\n", sock->ops->family);
			rc = -EINVAL;
			goto out;
			break;
	}

	if (remote) {
		rc = kernel_getpeername(sock, address, &addrlen);
	} else {
		rc = kernel_getsockname(sock, address, &addrlen);
	}

	if (unlikely(rc)) {
		up_eprintk("kernel_get%sname failed: %d (family=%d)\n", remote ? "peer" : "sock",
				rc, sock->ops->family);
		goto out;
	}

	rc = __nla_put_socket_address(skb, sock, address, addrlen);

	out:
	return rc;
}
#define __nla_put_socket(skb, sock, remote) \
			do { \
					if (unlikely(__nla_put_socket_info(skb, sock, remote))) \
						goto nla_put_failure; \
			}	while(0)
#define nla_put_socket_local(skb, sock) __nla_put_socket(skb, sock, 0)
#define nla_put_socket_remote(skb, sock) __nla_put_socket(skb, sock, 1)

static inline int __nla_put_unix_socket(struct sk_buff *skb, struct sock *sk) {
	struct unix_sock *unix_sock = unix_sk(sk);

	unix_state_lock(unix_sock);
	/* Behave just as unix_getname does... */
	if (!unix_sock->addr) {
		struct sockaddr_un unaddr;
		NLA_PUT_U32(skb, UP_NLA_SOCKET_ADDRLEN, sizeof(short));
		NLA_PUT_U32(skb, UP_NLA_SOCKET_FAMILY, AF_UNIX);
		unaddr.sun_family = AF_UNIX;
		unaddr.sun_path[0] = 0;
		NLA_PUT(skb, UP_NLA_SOCKET_UNADDR, sizeof(struct sockaddr_un), &unaddr);
	} else {
		NLA_PUT_U32(skb, UP_NLA_SOCKET_ADDRLEN, unix_sock->addr->len);
		NLA_PUT_U32(skb, UP_NLA_SOCKET_FAMILY, unix_sock->addr->name[0].sun_family);
		NLA_PUT(skb, UP_NLA_SOCKET_UNADDR, sizeof(struct sockaddr_un),
				&(unix_sock->addr->name[0]));
	}
	unix_state_unlock(unix_sock);
	return 0;

nla_put_failure:
	unix_state_unlock(unix_sock);
	return -ENOMEM;
}

#define nla_put_unix_socket(skb, sk) \
		do { \
				if (unlikely(__nla_put_unix_socket(skb, sk))) \
					goto nla_put_failure; \
		} while(0)

/*
 * BEGIN LSM handler functions
 */
int up_unix_stream_connect(struct sock *sock, struct sock *other, struct sock *newsk) {
	struct up_tracee *tracee = up_want_handle_event(UPOLICY_EVENT(UNIX_STREAM_CONNECT));
	struct sk_buff *skb = NULL;
	struct nlattr *local_start = NULL;
	struct nlattr *remote_start = NULL;

	int rc = 0;

	if (unlikely(tracee)) {
		struct up_nlhdr *up_nlhdr;
		enum UP_EV_DECISION decision = UP_DECISION(ALLOW);

		skb = up_nlevent_prepare(UPOLICY_EVENT(UNIX_STREAM_CONNECT), &up_nlhdr);

		if (likely(skb)) {
			nla_socket_start(skb, LOCAL, local_start);
			nla_put_unix_socket(skb, sock);
			nla_socket_end(skb, local_start);

			nla_socket_start(skb, REMOTE, remote_start);
			nla_put_unix_socket(skb, other);
			nla_socket_end(skb, remote_start);

			decision = up_nlevent_send(skb, tracee, UPOLICY_EVENT(SOCKET_CREATE), NULL);
			if (decision != UP_DECISION(ALLOW)) {
				up_dprintk(HANDLER_SOCKET,
						"tracee@%p,tsk@%p: unix_stream_connect(%p,%p,%p) denied (%d).\n",
						tracee, current, sock, other, newsk, decision);
				rc = -EPERM;
			}
		} else {
			rc = -EPERM;
		}

		up_tracee_put(tracee);
	}
	return rc;
nla_put_failure:
	up_eprintk("nla_put_failure.\n");
	if (remote_start)
		nla_socket_cancel(skb, remote_start);
	else if (local_start)
		nla_socket_cancel(skb, local_start);
	kfree_skb(skb);
	up_tracee_put(tracee);
	return -ENOMEM;
}

int up_socket_create(int family, int type, int protocol, int kern) {
	struct up_tracee *tracee = up_want_handle_event(UPOLICY_EVENT(SOCKET_CREATE));
	int rc = 0;
	struct sk_buff *skb = NULL;
	struct nlattr *nested_start = NULL;

	if (unlikely(tracee)) {
		struct up_nlhdr *up_nlhdr;
		enum UP_EV_DECISION decision = UP_DECISION(ALLOW);

		skb = up_nlevent_prepare(UPOLICY_EVENT(SOCKET_CREATE), &up_nlhdr);

		if (likely(skb)) {
			nla_socket_start(skb, LOCAL, nested_start);
			NLA_PUT_U32(skb, UP_NLA_SOCKET_FAMILY, family);
			NLA_PUT_U32(skb, UP_NLA_SOCKET_TYPE, type);
			NLA_PUT_U32(skb, UP_NLA_SOCKET_PROTO, protocol);
			nla_socket_end(skb, nested_start);

			decision = up_nlevent_send(skb, tracee, UPOLICY_EVENT(SOCKET_CREATE), NULL);
			if (decision != UP_DECISION(ALLOW)) {
				up_dprintk(HANDLER_SOCKET,
						"tracee@%p,tsk@%p: socket_create(%d,%d,%d) denied (%d).\n",
						tracee, current, family, type, protocol, decision);
				rc = -EPERM;
			}
		} else {
			rc = -EPERM;
		}
		up_tracee_put(tracee);
	}
	return rc;

nla_put_failure:
	up_eprintk("nla_put_failure.\n");
	if (nested_start)
		nla_socket_cancel(skb, nested_start);
	kfree_skb(skb);
	up_tracee_put(tracee);
	return -ENOMEM;
}

int up_socket_bind(struct socket *sock, struct sockaddr *address, int addrlen) {
	int rc = 0;
	struct up_tracee *tracee = up_want_handle_event(UPOLICY_EVENT(SOCKET_BIND));
	struct sk_buff *skb = NULL;
	struct nlattr *local_start = NULL;

	if (unlikely(tracee)) {
		struct up_nlhdr *up_nlhdr;
		enum UP_EV_DECISION decision = UP_DECISION(ALLOW);

		skb = up_nlevent_prepare(UPOLICY_EVENT(SOCKET_BIND), &up_nlhdr);
		if (likely(skb)) {
			nla_socket_start(skb, LOCAL, local_start);
			nla_put_socket_address(skb, sock, address, addrlen);
			nla_socket_end(skb, local_start);

			decision = up_nlevent_send(skb, tracee, UPOLICY_EVENT(SOCKET_BIND), NULL);
			if (decision != UP_DECISION(ALLOW)) {
				up_dprintk(HANDLER_SOCKET,
						"tracee@%p,tsk@%p: socket_bind(%p,%p,%d) denied (%d).\n",
						tracee, current, sock, address, addrlen, decision);
				rc = -EPERM;
			}
		} else {
			rc = -EPERM;
		}
		up_tracee_put(tracee);
	}
	return rc;

nla_put_failure:
	up_eprintk("nla_put_failure.\n");
	if (local_start)
		nla_socket_cancel(skb, local_start);
	kfree_skb(skb);
	up_tracee_put(tracee);
	return -ENOMEM;
}

int up_socket_connect(struct socket *sock, struct sockaddr *address, int addrlen) {
	int rc = 0;
	struct up_tracee *tracee = up_want_handle_event(UPOLICY_EVENT(SOCKET_CONNECT));
	struct sk_buff *skb = NULL;
	struct nlattr *local_start = NULL;
	struct nlattr *remote_start = NULL;
	if (unlikely(tracee)) {
		struct up_nlhdr *up_nlhdr;
		enum UP_EV_DECISION decision = UP_DECISION(ALLOW);

		skb = up_nlevent_prepare(UPOLICY_EVENT(SOCKET_CONNECT), &up_nlhdr);
		if (likely(skb)) {
			nla_socket_start(skb, LOCAL, local_start);
			nla_put_socket_local(skb, sock);
			nla_socket_end(skb, local_start);

			nla_socket_start(skb, REMOTE, remote_start);
			nla_put_socket_address(skb, sock, address, addrlen);
			nla_socket_end(skb, remote_start);

			decision = up_nlevent_send(skb, tracee, UPOLICY_EVENT(SOCKET_CONNECT), NULL);
			if (decision != UP_DECISION(ALLOW)) {
				up_dprintk(HANDLER_SOCKET,
						"tracee@%p,tsk@%p: socket_connect(%p,%p,%d) denied (%d).\n",
						tracee, current, sock, address, addrlen, decision);
				rc = -EPERM;
			}
		} else {
			rc = -EPERM;
		}

		up_tracee_put(tracee);
	}

	return rc;
nla_put_failure:
	up_eprintk("nla_put_failure.\n");
	if (remote_start)
		nla_socket_cancel(skb, remote_start);
	else if (local_start)
		nla_socket_cancel(skb, local_start);
	kfree_skb(skb);
	up_tracee_put(tracee);
	return -ENOMEM;
}

int up_socket_listen(struct socket *sock, int backlog) {
	int rc = 0;
	struct up_tracee *tracee = up_want_handle_event(UPOLICY_EVENT(SOCKET_LISTEN));
	struct sk_buff *skb = NULL;
	struct nlattr *local_start = NULL;

	if (unlikely(tracee)) {
		struct up_nlhdr *up_nlhdr;
		enum UP_EV_DECISION decision = UP_DECISION(ALLOW);
		skb = up_nlevent_prepare(UPOLICY_EVENT(SOCKET_LISTEN), &up_nlhdr);

		if (likely(skb)) {
			nla_socket_start(skb, LOCAL, local_start);
			nla_put_socket_local(skb, sock);
			nla_socket_end(skb, local_start);

			decision = up_nlevent_send(skb, tracee, UPOLICY_EVENT(SOCKET_LISTEN), NULL);
			if (decision != UP_DECISION(ALLOW)) {
				up_dprintk(HANDLER_SOCKET,
						"tracee@%p,tsk@%p: socket_listen(%p,%d) denied (decision=%d).\n",
						tracee, current, sock, backlog, decision);
				rc = -EPERM;
			}
		} else {
			rc = -EPERM;
		}
		up_tracee_put(tracee);
	}

	return rc;
nla_put_failure:
	up_eprintk("nla_put_failure.\n");
	if (local_start)
		nla_socket_cancel(skb, local_start);
	kfree_skb(skb);
	up_tracee_put(tracee);
	return -ENOMEM;
}

int up_socket_accept(struct socket *sock, struct socket *newsock) {
	int rc = 0;
	struct sk_buff *skb = NULL;
	struct nlattr *local_start = NULL;
	struct nlattr *remote_start = NULL;
	struct up_tracee *tracee = up_want_handle_event(UPOLICY_EVENT(SOCKET_ACCEPT));

	if (unlikely(tracee)) {
		struct up_nlhdr *up_nlhdr;
		enum UP_EV_DECISION decision = UP_DECISION(ALLOW);
		skb = up_nlevent_prepare(UPOLICY_EVENT(SOCKET_ACCEPT), &up_nlhdr);

		if (likely(skb)) {
			nla_socket_start(skb, LOCAL, local_start);
			nla_put_socket_local(skb, sock);
			nla_socket_end(skb, local_start);

			nla_socket_start(skb, REMOTE, remote_start);
			nla_put_socket_remote(skb, newsock);
			nla_socket_end(skb, remote_start);

			decision = up_nlevent_send(skb, tracee, UPOLICY_EVENT(SOCKET_ACCEPT), NULL);
			if (decision != UP_DECISION(ALLOW)) {
				up_dprintk(HANDLER_SOCKET,
						"tracee@%p,tsk@%p: socket_accept(%p,%p) denied (decision=%d).\n",
						tracee, current, sock, newsock, decision);
				rc = -EPERM;
			}
		} else {
			rc = -EPERM;
		}
		up_tracee_put(tracee);
	}

	return rc;

nla_put_failure:
	up_eprintk("nla_put_failure.\n");
	if (remote_start)
		nla_socket_cancel(skb, remote_start);
	else if (local_start)
		nla_socket_cancel(skb, local_start);
	kfree_skb(skb);
	up_tracee_put(tracee);
	return -ENOMEM;
}
/*
 * END LSM handler functions
 */
