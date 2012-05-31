/* context.h
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
#ifndef UPOLICY_CONTEXT_H
#define UPOLICY_CONTEXT_H

#include <semaphore.h>
#include <sys/types.h>

#include <upolicy/list.h>
#include <upolicy/types.h>

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

/* forward declarations */
struct upolicy_context;
struct sockaddr;

/**
 * @defgroup Context Context
 * @{
 */

/**
 * event information passed to every event handler
 */
struct upolicy_event_info {
  struct upolicy_context *ctx; /**< context that caused the event */
  pid_t                   pid; /**< process ID that caused the event */
  pid_t                   tid; /**< thread ID that caused the event */
  int         is_notification; /**< 1 if event is a notification */
};

/**
 * Structure holding per-context callbacks.
 * These are used for both question and notification events.
 */
struct upolicy_ops {
	/** A tracee has exited. */
	upolicy_decision (*tracee_exited) (struct upolicy_event_info *info);

	/* A tracee has started. */
	upolicy_decision (*tracee_started)(struct upolicy_event_info *info);

  /** All tracees in this context have exited callback */
  upolicy_decision (*all_tracees_exited) (struct upolicy_event_info *info);

  /** Tracee tries to become tracer callback */
  upolicy_decision (*tracer_init) (struct upolicy_event_info *info);

  /** clone event callback */
  upolicy_decision (*clone) (struct upolicy_event_info *info, u_int32_t flags);
  /** kill event callback */
  upolicy_decision (*kill) (struct upolicy_event_info *info, pid_t pid, int signo);
  /** exec event callback */
  upolicy_decision (*exec) (struct upolicy_event_info *info, const char *path);

  /** open event callback */
  upolicy_decision (*open)  (struct upolicy_event_info *info, const char *path, 
			mode_t mode);
  /** symlink event callback */
  upolicy_decision (*symlink) (struct upolicy_event_info *info, const char *source, 
			  const char *destination);

  /** accept event callback */
  upolicy_decision (*socket_accept) (struct upolicy_event_info *info, int family, 
				struct sockaddr *local_address, 
				int local_addrlen,
				struct sockaddr *remote_addr,
				int remote_addrlen);
  /** bind event callback */
  upolicy_decision (*socket_bind) (struct upolicy_event_info *info, int family,
			      struct sockaddr *address, int addrlen);

  /** connect event callback */
  upolicy_decision (*socket_connect) (struct upolicy_event_info *info, int family,
				 struct sockaddr *local_address, 
				 int local_addrlen,
				 struct sockaddr *remote_address,
				 int remote_addrlen);

  /** socket creation event callback */
  upolicy_decision (*socket_create) (struct upolicy_event_info *info, int family,
				int type, int protocol);
  /** listen event callback */
  upolicy_decision (*socket_listen) (struct upolicy_event_info *info, int family,
	       struct sockaddr *address, int addrlen);

  /** ptrace attach event callback */
  upolicy_decision (*ptrace_attach) (struct upolicy_event_info *info, pid_t pid,
  		unsigned int mode);
};

/**
 * Struct holding context information
 */
struct upolicy_context {
  up_ctx_id                id;           /**< context ID */
  sem_t                    created_sem;  /**< semaphore used internally */
  const struct upolicy_ops *question_ops; /**< question event operations */
  const struct upolicy_ops *notify_ops;   /**< notify event operations */
  struct list_entry        entry;         /**< list information */
  void                     *user;        /**< user-definable data */
};

/**
 * Create and initialize context
 *
 * @param ctx Pointer to context struct
 * @returns 0 on success, negative value on failure
 */
int upolicy_context_create(struct upolicy_context *ctx);

/**
 * Destroy context
 *
 * @param ctx Pointer to context struct
 * @returns 0 on success, negative value on failure
 */
int upolicy_context_destroy(struct upolicy_context *ctx);

/**
 * Find context by context ID
 *
 * @param id Context ID to use for lookup
 * @returns NULL on failure, pointer to context struct on success
 */
struct upolicy_context *upolicy_context_find(up_ctx_id id);

/**
 * \brief Fork into context
 *
 * \param ctx Context struct
 * \returns negative value on error, 0 in child and child PID in parent
 */
pid_t upolicy_context_fork(struct upolicy_context *ctx);

/**
 * @}
 */

#ifdef __cplusplus
}
#endif /* __cplusplus */


#endif /* UPOLICY_CONTEXT_H */
