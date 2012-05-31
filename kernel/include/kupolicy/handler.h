/* handler.h
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
#ifndef _KUPOLICY_HANDLER_H
#define _KUPOLICY_HANDLER_H

#ifdef __KERNEL__
#include <linux/types.h>
#include <kupolicy/context.h>
#include <kupolicy/tracee.h>
#include <kupolicy/types.h>
#include <kupolicy/upolicy.h>

/* forward declarations */
struct cred;
struct file;
struct linux_binprm;
struct siginfo;
struct sock;
struct sockaddr;
struct socket;
struct task_struct;

/* from handler_bprm.c */
int up_bprm_set_creds(struct linux_binprm *bprm);

/* from handler_cred.c */
void up_cred_free(struct cred *cred);
int up_cred_prepare(struct cred *new, const struct cred *old,
		    gfp_t gfp);
void up_cred_transfer(struct cred *new, const struct cred *old);

/* from handler_fs.c. */
int up_fs_dentry_open(struct file *file, const struct cred *cred);

/* from handler_ptrace.c */
int up_ptrace_access_check(struct task_struct *tsk, unsigned int mode);

/* from handler_socket.c */
int up_unix_stream_connect(struct sock *sock, struct sock *other, struct sock *newsk);
int up_socket_create(int family, int type, int protocol, int kern);
int up_socket_bind(struct socket *sock, struct sockaddr *address, int addrlen);
int up_socket_connect(struct socket *sock, struct sockaddr *address, int addrlen);
int up_socket_listen(struct socket *sock, int backlog);
int up_socket_accept(struct socket *sock, struct socket *newsock);

/* from handler_task.c */
int up_task_kill(struct task_struct *p, struct siginfo *info,
		 int sig, u32 secid);
int up_task_create(unsigned long clone_flags);

#endif /* __KERNEL__ */

#endif /* _KUPOLICY_HANDLER_H */
