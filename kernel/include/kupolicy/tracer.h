/* tracer.h
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
#ifndef _KUPOLICY_TRACER_H
#define _KUPOLICY_TRACER_H

#include <linux/types.h>

#ifdef __KERNEL__
struct upolicy;
struct up_context;

#include <linux/list.h>
#include <linux/spinlock.h>

#include <kupolicy/context.h>
#include <kupolicy/netlink.h>
#include <kupolicy/types.h>

/**
 * struct up_tracer - Tracer information
 * @contexts_list: List head of tracer's context list
 * @max_ctx_id: Current maximum context ID number
 * @null_context: NULL context
 * @socket: Socket information
 * @pid_ns: PID namespace the tracer executes in
 * @contexts_rwlock: rwlock protecting contexts_list
 * @usage: Reference count
 * @tracee_count: Number of active tracees
 */
struct up_tracer {
  struct list_head contexts_list;
  up_ctx_id        max_ctx_id;
  struct up_context null_context;
  struct up_socket socket;
  struct pid_namespace* pid_ns;
  rwlock_t         contexts_rwlock;
  atomic_t         usage;
  atomic_t         tracee_count;
};

/**
 * up_tracer_alloc - Allocate and initialize up_tracer structure.
 *
 * @up: Pointer to upolicy struct containing this tracer.
 * @gfp: gfp_t used for allocation
 */
struct up_tracer* up_tracer_alloc(struct upolicy* up, gfp_t gfp);

/**
 * up_tracer_get - Get reference to tracer struct.
 *
 * This function increments the tracer's usage count.
 *
 * @tracer: Pointer to tracer struct.
 */
static inline struct up_tracer* __up_tracer_get(struct up_tracer* tracer) {
  if (unlikely(!tracer))
    goto out;

  BUG_ON(atomic_read(&tracer->usage) == 0);

  atomic_inc(&tracer->usage);

 out:
  return tracer;
}

/**
 * up_tracer_put - Decrement reference count of upolicy tracer.
 *
 * If the reference count reaches zero due to this call
 * the tracer struct is free'd.
 *
 * @tracer: Pointer to tracer struct
 */
void __up_tracer_put(struct up_tracer* tracer);

/**
 * up_tracer_attach_ctx - Attach context to tracer.
 *
 * @tracer: Pointer to tracer struct
 * @ctx: Pointer to context struct
 */
int up_tracer_attach_ctx(struct up_tracer* tracer, struct up_context* ctx);

/**
 * up_tracer_find_ctx - Lookup context by context id.
 *
 * Returns NULL on error.
 *
 * @tracer: Pointer to tracer struct
 * @ctx_id: Context ID
 */
struct up_context* up_tracer_find_ctx(struct up_tracer* tracer,
				      up_ctx_id ctx_id);

/**
 * up_tracer_detach_ctx - Detaches context from tracer.
 *
 * All tracees left in this context are killed by this function.
 *
 * @tracer: Pointer to tracer struct
 * @ctx: Pointer to context struct
 */
void up_tracer_detach_ctx(struct up_tracer* tracer,
			  struct up_context* ctx);

/**
 * up_tracer_detach_all - Detaches all contexts from the tracer.
 *
 * All tracees of the given tracer are killed by this function.
 *
 * @tracer: Pointer to tracer struct
 */
void up_tracer_detach_all(struct up_tracer* tracer);

#ifdef UPOLICY_DEBUG
#include <kupolicy/upolicy.h>

static inline struct up_tracer *__dbg_up_tracer_get(struct up_tracer *tracer,
		const char *func_name, int line_no) {
	__up_dprintk(UP_DEBUG_REFCOUNT, func_name, line_no, "GET: tracer@%p\n", tracer);
	return __up_tracer_get(tracer);
}

static inline void __dbg_up_tracer_put(struct up_tracer *tracer,
		const char *func_name, int line_no)
{
	__up_dprintk(UP_DEBUG_REFCOUNT, func_name, line_no, "PUT: tracer@%p\n", tracer);
	__up_tracer_put(tracer);
}

#define up_tracer_get(tracer) __dbg_up_tracer_get(tracer, __func__, __LINE__)
#define up_tracer_put(tracer) __dbg_up_tracer_put(tracer, __func__, __LINE__)
#else
#define up_tracer_get __up_tracer_get
#define up_tracer_put __up_tracer_put
#endif

#endif /* __KERNEL__ */

#endif /* _KUPOLICY_TRACER_H */
