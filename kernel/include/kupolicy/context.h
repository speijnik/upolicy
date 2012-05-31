/* context.h
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
#ifndef _KUPOLICY_CONTEXT_H
#define _KUPOLICY_CONTEXT_H

#include <linux/types.h>
#include <kupolicy/types.h>

#ifdef __KERNEL__
#include <linux/list.h>
#include <linux/spinlock.h>

#include <kupolicy/upolicy.h>

/* forward declarations */
struct up_tracee;
struct up_tracer;

/**
 * struct up_context - context information
 *
 * @id: Per-tracer context ID. Possible values: 1 to max(typeof(up_ctx_id))
 *      ID 0 is reserved.
 * @question_mask: Question mask
 * @notify_mask: Notify mask
 * @combined_mask: Logical OR of question_mask, notify_mask and parent
 *                 combined_mask. This allows for fast checking if a given event
 *                 needs to be handled at all, meaning that events which do not
 *                 need to be handled are ignored early.
 * @tracees_list: Head of list of tracees
 * @tracer: Tracer this context belongs to
 * @list: List entry for use from within up_tracer
 * @tracees_rwlock: rwlock for tracees_list
 * @usage: Usage count
 *
 */
struct up_context {
  up_ctx_id id;
  up_event_mask question_mask;
  up_event_mask notify_mask;
  up_event_mask combined_mask;
  struct list_head tracees_list;
  struct up_tracer *tracer;
  struct list_head list;
  rwlock_t tracees_rwlock;
  atomic_t usage;
};

/**
 * up_context_alloc - Allocate and initialize context struct.
 *
 * @tracer: Tracer this new context belongs to.
 */
struct up_context* up_context_alloc(struct up_tracer *tracer);

/**
 * up_context_init - Initialize context struc.
 *
 * @ctx: Context to initialize.
 * @tracer: Tracer this new context belongs to.
 *
 * This function MUST NOT be called after up_context_alloc. It exists for correct initialization
 * of a tracer's NULL-context only.
 */
void up_context_init(struct up_context *ctx, struct up_tracer *tracer);

void __up_context_put(struct up_context* ctx);
int up_context_add(struct up_context* ctx, struct up_tracee* tracee);
void up_context_remove(struct up_context* ctx, struct up_tracee* tracee);
void up_context_killtracees(struct up_context *ctx);

static inline struct up_context *__up_context_get(struct up_context* ctx) {
	if (unlikely(!ctx))
		return ctx;

	BUG_ON(atomic_read(&ctx->usage) == 0);

  atomic_inc(&ctx->usage);
  return ctx;
}

#ifdef UPOLICY_DEBUG
#include <kupolicy/upolicy.h>

static inline struct up_context *__dbg_up_ctx_get(struct up_context *ctx,
		const char *func_name, int line_no) {
	__up_dprintk(UP_DEBUG_REFCOUNT, func_name, line_no, "GET: ctx@%p\n", ctx);
	return __up_context_get(ctx);
}

static inline void __dbg_up_ctx_put(struct up_context *ctx,
		const char *func_name, int line_no)
{
	__up_dprintk(UP_DEBUG_REFCOUNT, func_name, line_no, "PUT: ctx@%p\n", ctx);
	__up_context_put(ctx);
}

#define up_context_get(ctx) __dbg_up_ctx_get(ctx, __func__, __LINE__)
#define up_context_put(ctx) __dbg_up_ctx_put(ctx, __func__, __LINE__)
#else /* !UPOLICY_DEBUG */
#define up_context_get __up_context_get
#define up_context_put __up_context_put
#endif /* UPOLICY_DEBUG */

static inline enum UP_EVENT_TYPE up_context_wants_event(struct up_context *ctx, enum UP_EVENT ev) {
	u64 ev_flag = 0;

	if (ev <= UPOLICY_EV_LAST_UNBLOCKABLE_QUESTION)
		return UP_EV_TYPE(QUESTION);
	else if (ev <= UPOLICY_EV_LAST_UNBLOCKABLE)
		return UP_EV_TYPE(NOTIFICATION);

	/* Default cases handled, now check what the context actually defines. */
	ev_flag = upolicy_ev_flag(ev);

	if ((ctx->question_mask & ev_flag)) {
		/* Make sure events that are notify-only are never sent as question. */
		return ev <= UPOLICY_EV_LAST_NOTIFY_ONLY ?
				UP_EV_TYPE(NOTIFICATION) : UP_EV_TYPE(QUESTION);
	}
	else if ((ctx->notify_mask & ev_flag)) {
		return UP_EV_TYPE(NOTIFICATION);
	}

	return UP_EV_TYPE(SKIP);
}

#endif /* __KERNEL__ */

#endif /* _KUPOLICY_CONTEXT_H */
