/* tracer.c
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
#include <linux/module.h>
#include <linux/list.h>
#include <linux/signal.h>
#include <linux/slab.h>
#include <linux/spinlock.h>

#include <kupolicy/context.h>
#include <kupolicy/tracer.h>
#include <kupolicy/types.h>
#include <kupolicy/upolicy.h>

/* function declarations */
static void up_tracer_free(struct up_tracer* tracer);

/*
 * Helper function that tries to find an unused context id.
 * Using the max_ctx_id field in up_tracer this should
 * usually take a single iteration only.
 *
 * @tracer: Tracer
 */
static up_ctx_id find_unused_ctx_id(struct up_tracer *tracer) {
  up_ctx_id current_id = 0;
  struct up_context *ctx = NULL;
  struct list_head *tmp = NULL;
  int found = 0;

  /*
   * This function tries to find an unused context ID as efficiently
   * as possible:
   *
   * - Simplest and fastest case: max_ctx_id < UP_CTX_ID_MAX
   *   In this case we increment max_ctx_id and return that value.
   *
   * - Slow case: max_ctx_id == UP_CTX_ID_MAX
   *   In this case we start at value 1 and need to re-iterate over
   *   all contexts that exist (O(UP_CTX_ID_MAX*n)!).
   *   This should only be the case when UP_CTX_ID_MAX contexts
   *   have been allocated already and the context with 
   *   id=UP_CTX_ID_MAX is still present.
   */
  if (tracer->max_ctx_id < UP_CTX_ID_MAX) {
    return ++tracer->max_ctx_id;
  }

  /* Handle the slower case... */
  current_id = UP_CTX_ID_UNKNOWN + 1;
  do {
    found = 1;
    list_for_each(tmp, &tracer->contexts_list) {
      ctx = list_entry(tmp, struct up_context, list);
      if (ctx->id == current_id) {
	found = 0;
	current_id++;
	break;
      }
    }

    /* 
     * We can safely check for current_id < UP_CTX_ID_MAX, because
     * max_ctx_id >= UP_CTX_ID_MAX, see above.
     * This helps cutting the worst-case speed by one iteration over
     * 65535 entries...
     */
  } while(!found && current_id < UP_CTX_ID_MAX);
  

  if (unlikely(current_id) == UP_CTX_ID_MAX) {
    /* This is only the case when _all_ IDs are in use already. */
    return UP_CTX_ID_UNKNOWN;
  }
  
  return current_id;
}

static inline void put_ctx_id(struct up_tracer *tracer,
			      up_ctx_id id) {
  if (id == tracer->max_ctx_id) {
    tracer->max_ctx_id--;
  }
}

struct up_tracer* up_tracer_alloc(struct upolicy* up, gfp_t gfp) {
  struct up_tracer* tracer = NULL;

  tracer = kzalloc(sizeof(struct up_tracer), gfp);

  if (unlikely(!tracer))
    goto out;

  INIT_LIST_HEAD(&tracer->contexts_list);
  rwlock_init(&tracer->contexts_rwlock);

  atomic_set(&tracer->usage, 1);
  atomic_set(&tracer->tracee_count, 0);

  up_context_init(&tracer->null_context, tracer);
  /* Drop one reference held by tracer->null_context. */
  up_tracer_put(tracer);

  /*
   * Increment usage count of null_context by one, so up_context_free is never
   * called for the null context. The reasons why we do not want this are:
   *  - null_context was never allocated directly, but is part of the tracer.
   *    Thus kfree() should NEVER be called on it.
   *  - null_context is holding the initial reference on the tracer, which should not be
   *    put when null_context is not referenced anymore.
   */
  atomic_inc(&tracer->null_context.usage);

 out:
  return tracer;
}

static void up_tracer_free(struct up_tracer* tracer) {
  if (unlikely(!tracer))
    return;

  /* When this function is called the tracer's usage count MUST be 0. */
  if (unlikely(atomic_read(&tracer->usage) > 0)) {
    up_dprintk(TRACER, "Called for tracer@%p with usage > 0!\n",
	       tracer);
    return;
  }

  up_dprintk(TRACER, "Free'ing tracer@%p.\n", tracer);
  
  /* 
   * There is no need to iterate over all contexts, because
   * usage indicates whether contexts are still attached.
   * Contexts should be removed by using up_tracer_detach_all.
   */
  kfree(tracer);

  /* 
   * We need to call module_put here when a tracer is free'd
   * because the netlink INIT command did a module_get. 
   */
  module_put(THIS_MODULE); 
}

int
up_tracer_attach_ctx(struct up_tracer* tracer,
		     struct up_context* ctx)
{
  unsigned long flags;
  int error = 0;

  if (unlikely(ctx->list.next || ctx->list.prev)) {
    return -EEXIST;
  }

  if (unlikely(tracer != ctx->tracer))
  	return -EINVAL;

  write_lock_irqsave(&tracer->contexts_rwlock, flags);
  ctx->id = find_unused_ctx_id(tracer);
  if (unlikely(!ctx->id)) {
    error = -ENOSPC;
    goto out;
  }
  list_add(&ctx->list, &tracer->contexts_list);

 out:
  write_unlock_irqrestore(&tracer->contexts_rwlock, flags);
  return error;
}

struct up_context*
up_tracer_find_ctx(struct up_tracer* tracer,
		   up_ctx_id ctx_id) {
  struct up_context* ctx = NULL;
  struct list_head* tmp = NULL;
  unsigned long flags;
  up_dprintk(TRACER, "tracer@%p: looking up context with id=%d\n", tracer, ctx_id);
  read_lock_irqsave(&tracer->contexts_rwlock, flags);
  list_for_each(tmp, &tracer->contexts_list) {
    ctx = list_entry(tmp, struct up_context, list);
    if (ctx->id == ctx_id) {
      /* Increment the reference count by 1. */
      ctx = up_context_get(ctx);
      goto out;
    }
  }

  /* Fall-through: not found. */
  ctx = NULL;
 out:
  read_unlock_irqrestore(&tracer->contexts_rwlock, flags);
  up_dprintk(TRACER, "tracer@%p: context@%p", tracer, ctx);
  return ctx;
}

void up_tracer_detach_ctx(struct up_tracer *tracer,
			  struct up_context *ctx)
{
  unsigned long flags;

  BUG_ON(ctx->list.next == LIST_POISON1 &&
	       ctx->list.prev == LIST_POISON2);

  write_lock_irqsave(&tracer->contexts_rwlock, flags);
  list_del(&ctx->list);
  put_ctx_id(tracer, ctx->id);
  write_unlock_irqrestore(&tracer->contexts_rwlock, flags);

  /* Kill all left-over tracees. */
  up_context_killtracees(ctx);

  /*
   * Decrement context usage count that was incremented by
   * up_context_alloc.
   *
   * This should cause the context to be free'd as soon as
   * all tracees have exited.
   */
  up_context_put(ctx);
}

void up_tracer_detach_all(struct up_tracer *tracer) {
  unsigned long flags;
  struct list_head *tmp, *tmp2;
  struct up_context* ctx;
  /* 
   * Keep an additional reference so the tracer itself is
   * not free'd whilst iterating over the context list.
   */
  struct up_tracer* t2 = up_tracer_get(tracer);
  up_dprintk(TRACER, "Detaching all contexts from tracer@%p.\n", t2);

  up_context_killtracees(&tracer->null_context);

  write_lock_irqsave(&tracer->contexts_rwlock, flags);
  list_for_each_safe(tmp, tmp2, &tracer->contexts_list) {
    ctx = list_entry(tmp, struct up_context, list);
    list_del(&ctx->list);
    up_context_killtracees(ctx);
    up_context_put(ctx);
  }
  tracer->max_ctx_id = 0;
  write_unlock_irqrestore(&tracer->contexts_rwlock, flags);
  /* 
   * Drop the additional reference again. 
   * This may cause the tracer to be free'd right now.
   */
  up_tracer_put(t2);
}

void __up_tracer_put(struct up_tracer* tracer) {
	BUG_ON(atomic_read(&tracer->usage) == 0);

  if(atomic_dec_and_test(&tracer->usage)) {
    up_tracer_free(tracer);
  } else {
    up_dprintk(REFCOUNT, "tracer@%p,usage=%d\n", tracer, atomic_read(&tracer->usage));
  }
}
