/* tracee.h
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
#ifndef _KUPOLICY_TRACEE_H
#define _KUPOLICY_TRACEE_H
#ifdef __KERNEL__
#include <linux/list.h>
#include <linux/types.h>

#include <kupolicy/upolicy.h>

struct pid;
struct cred;
struct up_context;
struct up_tracer;

/**
 * struct up_tracee - Tracee information
 * @context: Context the tracee is executing inside
 * @tracer: Tracer responsible for this tracee
 * @tg_pid: ThreadGroup PID
 * @parent_tracee: Pointer to parent tracer's tracee
 * @list: List information. Used in up_context.tracees_list.
 * @usage: Reference count
 */
struct up_tracee {
  struct up_context *context;
  struct up_tracer  *tracer;
  struct pid*        tg_pid;
  struct up_tracee  *parent_tracee;
  struct list_head   list;
  atomic_t           usage;
};

/**
 * up_tracee_alloc - Allocates memory for a tracee struct.
 * @gfp: Allocation GFP type
 */
struct up_tracee* up_tracee_alloc(gfp_t gfp);

/**
 * __up_tracee_put - Decrements usage count of tracee.
 * @tracee: Tracee
 */
void __up_tracee_put(struct up_tracee *tracee);

/**
 * __up_tracee_get - Increment usage count of tracee and returns pointer to it.
 * @tracee: Tracee
 *
 * Is a no-op for tracee=NULL and returns NULL then.
 */
static inline struct up_tracee* __up_tracee_get(struct up_tracee *tracee) {
  if (unlikely(!tracee))
    goto out;

  BUG_ON(atomic_read(&tracee->usage) == 0);

  atomic_inc(&tracee->usage);
 out:
  return tracee;
}

#ifdef UPOLICY_DEBUG
#include <kupolicy/upolicy.h>

static inline struct up_tracee *__dbg_up_tracee_get(struct up_tracee *tracee,
		const char *func_name, int line_no) {
	__up_dprintk(UP_DEBUG_REFCOUNT, func_name, line_no, "GET: tracee@%p\n", tracee);
	return __up_tracee_get(tracee);
}

static inline void __dbg_up_tracee_put(struct up_tracee *tracee,
		const char *func_name, int line_no)
{
	__up_dprintk(UP_DEBUG_REFCOUNT, func_name, line_no, "PUT: tracee@%p\n", tracee);
	__up_tracee_put(tracee);
}
#define up_tracee_get(t) __dbg_up_tracee_get(t, __func__, __LINE__)
#define up_tracee_put(t) __dbg_up_tracee_put(t, __func__, __LINE__)
#else /* !UPOLICY_DEBUG */
#define up_tracee_get(t) __up_tracee_get(t)
#define up_tracee_put(t) __up_tracee_put(t)
#endif /* UPOLICY_DEBUG */

/**
 * up_tracee_kill - Kill tracee
 *
 * @tracee: Tracee
 */
void up_tracee_kill(struct up_tracee *tracee);

/**
 * __up_tracee_validate - Validates the current tracee and fixes it up if needed.
 * Returns 0 on success or error value on failure.
 *
 * When an error value is returned the calling function MUST free all
 * memory it has potentially allocated before the call and return
 * this function's return value.
 */
int __up_tracee_validate(void);

static inline int up_tracee_validate(void) {
	if (likely(!current_upolicy()))
		return 0;
	return __up_tracee_validate();
}

#endif /* __KERNEL__ */

#endif /* _KUPOLICY_TRACEE_H */
