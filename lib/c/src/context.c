/* context.c
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
#include <stdlib.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#include <netlink/netlink.h>

#include <upolicy/context.h>
#include <upolicy/core.h>
#include <upolicy/internal.h>
#include <upolicy/list.h>
#include <upolicy/netlink.h>

struct fork_mgmt_page_base {
	sem_t usage_bitmap_semaphore;
};

#define MGMT_MAX_NUM_SEMAPHORES (SIZEOF_PAGE/sizeof(sem_t))
#define MGMT_USAGE_BITS_PER_ENTRY (8 * sizeof(unsigned long))
#define MGMT_NUM_USAGE_ENTRIES ((MGMT_MAX_NUM_SEMAPHORES/MGMT_USAGE_BITS_PER_ENTRY) \
		+ (MGMT_MAX_NUM_SEMAPHORES % MGMT_USAGE_BITS_PER_ENTRY > 0 ? 1 : 0))
#define MGMT_BYTES_UNUSED (SIZEOF_PAGE - (sizeof(struct fork_mgmt_page_base) \
		+ MGMT_NUM_USAGE_ENTRIES * sizeof(unsigned long)))
#define MGMT_NUM_SEMAPHORES (MGMT_BYTES_UNUSED / sizeof(sem_t) )
#define MGMT_ENTRY_ALLUSED ((unsigned long)-1)

struct fork_mgmt_page {
	struct fork_mgmt_page_base base;
	unsigned long usage_bitmap[MGMT_NUM_USAGE_ENTRIES];
	sem_t semaphores[MGMT_NUM_SEMAPHORES];
};

struct fork_info {
	pid_t pid;
	struct upolicy_context *ctx;
	struct list_entry entry;
};

static struct fork_mgmt_page *fork_mgmt_page = NULL;
static struct list fork_mgmt_list = LIST_INITIALIZER;
/* TODO: replace fork_mgmt_list semaphore with mutex */
static sem_t fork_mgmt_list_semaphore;
static sem_t fork_mgmt_semaphore;
static struct list ctx_list = LIST_INITIALIZER;
static struct list ctx_create_list = LIST_INITIALIZER;
static pthread_rwlock_t ctx_create_list_rwlock = PTHREAD_RWLOCK_INITIALIZER;
static pthread_rwlock_t ctx_list_rwlock = PTHREAD_RWLOCK_INITIALIZER;
static up_ctx_id ctx_local_id = 0;
static pid_t initializer_pid = 0;

static int __ctx_list_add(struct upolicy_context *ctx, struct list *list, pthread_rwlock_t *rwlock) {
	int rc = 0;

	assert(ctx != NULL);
	assert(list != NULL);
	assert(rwlock != NULL);

	if ((rc = pthread_rwlock_wrlock(rwlock))) {
		return rc;
	}

	list_append(list, &ctx->entry);
	pthread_rwlock_unlock(rwlock);
	return rc;
}

static int __ctx_list_del(struct upolicy_context *ctx, struct list *list, pthread_rwlock_t *rwlock) {
	int rc = 0;

	assert(ctx != NULL);
	assert(list != NULL);
	assert(rwlock != NULL);

	if ((rc = pthread_rwlock_wrlock(rwlock))) {
		return rc;
	}
	list_remove(list, &ctx->entry);
	pthread_rwlock_unlock(rwlock);
	return rc;
}

static struct upolicy_context *__upolicy_context_find(up_ctx_id id, struct list *list, pthread_rwlock_t *rwlock) {
	struct upolicy_context *ctx = NULL;
	struct list_entry *entry;
	int rc = 0;

	if ((rc = pthread_rwlock_rdlock(rwlock))) {
		return NULL;
	}

	list_foreach(list, entry) {
		ctx = list_entry(entry, struct upolicy_context, entry);
		if (ctx->id == id)
			break;
	}

	if (entry == NULL && id != 0) {
		up_dprintf(CONTEXT, "could not find ctx with id=%u in %s list\n",
				id, list == &ctx_create_list ? "create" : "context");
		ctx = NULL;
	}

	pthread_rwlock_unlock(rwlock);
	return ctx;
}

static inline int ctx_create_list_add(struct upolicy_context *ctx) {
	return __ctx_list_add(ctx, &ctx_create_list, &ctx_create_list_rwlock);
}

static inline int ctx_create_list_del(struct upolicy_context *ctx) {
	return __ctx_list_del(ctx, &ctx_create_list, &ctx_create_list_rwlock);
}

static inline int ctx_list_add(struct upolicy_context *ctx) {
	return __ctx_list_add(ctx, &ctx_list, &ctx_list_rwlock);
}

static inline int ctx_list_del(struct upolicy_context *ctx) {
	return __ctx_list_del(ctx, &ctx_list, &ctx_list_rwlock);
}

static inline int __verify_op(uint64_t *evmask, uint64_t *notifymask, void *func_question,
		void *func_notify, const char * func_name, enum UP_EVENT ev) {
	uint64_t flag = upolicy_ev_flag(ev);

	if (func_question && func_notify) {
		up_eprintf("Op %s defined in both question_ops and notify_ops.", func_name);
		return -EINVAL;
	} else if (func_question) {
		if (ev <= UPOLICY_EV_LAST_NOTIFY_ONLY) {
			up_eprintf("Question op %s defined but event is notify-only.", func_name);
			return -EINVAL;
		}
		*evmask |= flag;
		up_dprintf(CONTEXT, "Question op %s enabled: flag=%x,evmask=%x", func_name,
				flag, *evmask);
	} else if (func_notify) {
		*notifymask |= flag;
		up_dprintf(CONTEXT, "Notify op %s enabled: flag=%x,notifymask=%x", func_name, flag,
				*notifymask);
	}
	return 0;
}

static int verify_ops(struct upolicy_context *ctx, uint64_t *evmask,
		uint64_t *notifymask) {
	int rc = 0;
	*evmask = *notifymask = 0;

	/* Verify all ops */
#define verify_op(func, ev) \
	if ((rc = __verify_op(evmask, notifymask, \
			ctx->question_ops ? ctx->question_ops-> func : NULL, \
			ctx->notify_ops ? ctx->notify_ops-> func : NULL, \
			#func, UPOLICY_EVENT(ev)))) \
		return rc;

	verify_op(all_tracees_exited, CTX_ALL_TRACEES_EXITED);
	verify_op(tracer_init, TRACER_INIT);
	verify_op(clone, CLONE);
	verify_op(open, OPEN);
	verify_op(symlink, SYMLINK);
	verify_op(socket_accept, SOCKET_ACCEPT);
	verify_op(socket_bind, SOCKET_BIND);
	verify_op(socket_connect, SOCKET_CONNECT);
	verify_op(socket_create, SOCKET_CREATE);
	verify_op(socket_listen, SOCKET_LISTEN);
	verify_op(kill, KILL);
	verify_op(exec, EXEC);
	verify_op(ptrace_attach, PTRACE_ATTACH);
	verify_op(tracee_started, TRACEE_STARTED);
	verify_op(tracee_exited, TRACEE_EXITED);
#undef verify_op

	up_dprintf(CONTEXT, "OK: evmask=%x, notifymask=%x", *evmask, *notifymask);
	if (*evmask == 0 && *notifymask == 0) {
		up_eprintf("No handlers defined.");
		return -EINVAL;
	}
	return 0;
}

int upolicy_context_create(struct upolicy_context *ctx) {
	struct nl_msg *msg;
	struct up_nlhdr *nlhdr;
	int rc;
	uint64_t evmask, notifymask;

	if (!ctx) {
		up_eprintf("context is NULL");
		return -EINVAL;
	}

	if (!ctx->question_ops && !ctx->notify_ops) {
		up_eprintf("both question_ops and notify_ops missing.");
		return -EINVAL;
	}

	if ((rc = verify_ops(ctx, &evmask, &notifymask))) {
		up_eprintf("verify_ops failed: %s (%d)\n", strerror(rc), rc);
		return rc;
	}

	if (sem_init(&ctx->created_sem, 0, 0)) {
		up_eprintf("sem_init failed: %s (%d)\n", strerror(errno), errno);
		return -errno;
	}

	msg = upolicy_msg_init(&nlhdr, UPOLICY_COMMAND(CTX_CREATE));
	if (!msg) {
		up_eprintf("could not init CTX_CREATE message.");
		sem_destroy(&ctx->created_sem);
		return -ENOMEM;
	}

	/* Set the local context id... */
	ctx->id = ctx_local_id++;
	nla_put_u16(msg, UP_NLA_UCONTEXT_ID, ctx->id);
	nla_put_u64(msg, UP_NLA_EVENTMASK, evmask);
	nla_put_u64(msg, UP_NLA_NOTIFYMASK, notifymask);

	if ((rc = ctx_create_list_add(ctx))) {
		/* Insert failed */
		up_eprintf("insert failed");
		sem_destroy(&ctx->created_sem);
		upolicy_msg_destroy(msg);
		return rc;
	}

	if ((rc = upolicy_msg_send_sync(msg)) < 0) {
		up_eprintf("msg_send_sync failed: %s (%d)", strerror(rc), rc);
		sem_destroy(&ctx->created_sem);
		return rc;
	}

	up_dprintf(CONTEXT, "waiting for context creation...");
	sem_wait(&ctx->created_sem);
	sem_destroy(&ctx->created_sem);
	up_dprintf(CONTEXT, "context created, ctx@%p, id=%u", ctx, ctx->id);

	ctx_create_list_del(ctx);
	ctx_list_add(ctx);
	return 0;
}

int upolicy_context_destroy(struct upolicy_context *ctx) {
	struct nl_msg* msg;
	struct up_nlhdr *nlhdr;
	int rc;

	if (!ctx) {
		up_eprintf("context is NULL");
		return -EINVAL;
	}


	if (!ctx->id) {
		up_eprintf("Invalid context ID.");
		return -EINVAL;
	}

	msg = upolicy_msg_init(&nlhdr, UPOLICY_COMMAND(CTX_DESTROY));

	if (!msg) {
		up_eprintf("msg_init for CTX_DESTROY failed.");
		return -ENOMEM;
	}

	nlhdr->context_id = ctx->id;
	if ((rc = upolicy_msg_send_sync(msg)) < 0) {
		up_eprintf("msg_send_sync failed: %s (%d)", strerror(rc), rc);
		return rc;
	}

	up_dprintf(CONTEXT, "ctx@%p, id=%u destroyed.", ctx, ctx->id);
	ctx->id = 0;
	ctx_list_del(ctx);
	return 0;
}

struct upolicy_context* upolicy_context_find(up_ctx_id id) {
	return __upolicy_context_find(id, &ctx_list, &ctx_list_rwlock);
}

__internal__ struct upolicy_context* upolicy_context_find_create(up_ctx_id id) {
	return __upolicy_context_find(id, &ctx_create_list, &ctx_create_list_rwlock);
}

static void __put_mgmt_semaphore(int sem_id) {
	int usage_idx = sem_id / (8 * sizeof(unsigned long));
	int usage_bit = sem_id % (8 * sizeof(unsigned long));

	assert(sem_destroy(&fork_mgmt_page->semaphores[sem_id]) == 0);

	assert(sem_wait(&fork_mgmt_page->base.usage_bitmap_semaphore) == 0);

	fork_mgmt_page->usage_bitmap[usage_idx] &= ~(1 << usage_bit);

	assert(sem_post(&fork_mgmt_page->base.usage_bitmap_semaphore) == 0);
	assert(sem_post(&fork_mgmt_semaphore) == 0);
}

static int __get_mgmt_semaphore(void) {
	int sem_id = -1;
	int i = 0;
	assert(sem_wait(&fork_mgmt_semaphore) == 0);
	assert(sem_wait(&fork_mgmt_page->base.usage_bitmap_semaphore) == 0);
	for(i = 0; i < MGMT_NUM_USAGE_ENTRIES; i++) {
		if (fork_mgmt_page->usage_bitmap[i] != MGMT_ENTRY_ALLUSED) {
			/*
			 * Find the unused bit and return its index.
			 */
			int sem_id_base = i * (8 * sizeof(unsigned long));
			int j = 0;
			for(j = 0; j < (8 * sizeof(unsigned long)); j++) {
				unsigned long flag = 1 << j;
				if (!(fork_mgmt_page->usage_bitmap[i] & flag)) {
					fork_mgmt_page->usage_bitmap[i] |= flag;
					sem_id = sem_id_base + j;
					break;
				}
			}

			if (sem_id >= 0)
				break;
		}
	}
	assert(sem_post(&fork_mgmt_page->base.usage_bitmap_semaphore) == 0);
	if (sem_id < 0) {
		assert(sem_post(&fork_mgmt_semaphore) == 0);
	}
	else {
		assert(sem_init(&fork_mgmt_page->semaphores[sem_id], 1, 0) == 0);
	}
	return sem_id;
}

pid_t upolicy_context_fork(struct upolicy_context *ctx) {
	pid_t tracee_pid = 0;
	sem_t *created_semaphore;
	int sem_id = __get_mgmt_semaphore();
	struct fork_info *fork_info = NULL;

	assert(ctx != NULL);

	if (sem_id < 0) {
		up_eprintf("no/invalid semaphore.");
		return -EFAULT;
	}

	fork_info = malloc(sizeof(struct fork_info));

	if (fork_info == NULL) {
		up_eprintf("alloc fork_info failed.");
		__put_mgmt_semaphore(sem_id);
		return -ENOMEM;
	}

	fork_info->ctx = ctx;
	fork_info->entry.next = fork_info->entry.prev = NULL;

	created_semaphore = &fork_mgmt_page->semaphores[sem_id];

	up_dprintf(CONTEXT, "about to fork into context #%d", fork_info->ctx->id);
	tracee_pid = fork();

	if (tracee_pid < 0) {
		up_eprintf("fork() failed: %s (%d)", strerror(errno), errno);
		__put_mgmt_semaphore(sem_id);
		return tracee_pid;
	}

	if (tracee_pid == 0) {
		/* In child */
		int fd = 0;
		up_dprintf(CONTEXT, "[CHILD] waiting for created_semaphore...");
		if (sem_wait(created_semaphore)) {
			up_eprintf("sem_wait failed: %s (%d).", strerror(errno), errno);
			return -errno;
		}
		__put_mgmt_semaphore(sem_id);
		up_dprintf(CONTEXT, "[CHILD] cleaning up upolicy structures...");
		upolicy_cleanup();
		up_dprintf(CONTEXT, "[CHILD] cleanup complete.");

		/*
		 * Trigger an event in the kernel so we get the NEW_TRACEE event
		 * and can act upon it...
		 */
		up_dprintf(CONTEXT, "[CHILD] running again, open(/)...");
		fd = open("/", O_CLOEXEC|O_RDONLY);
		if (fd >= 0) {
			close(fd);
		}
		up_dprintf(CONTEXT, "[CHILD] fully initialized.");
	} else {
		/* In parent */

		up_dprintf(CONTEXT, "[PARENT] Child started, pid=%d", tracee_pid);
		fork_info->pid = tracee_pid;
		upolicy_set_tracees_active();

		assert(sem_wait(&fork_mgmt_list_semaphore) == 0);
		list_prepend(&fork_mgmt_list, &fork_info->entry);
		assert(sem_post(&fork_mgmt_list_semaphore) == 0);

		up_dprintf(CONTEXT, "[PARENT] Child added to fork_mgmt_list, waking up child.");
		sem_post(created_semaphore);
		/* Allow the child to start up... */

		up_dprintf(CONTEXT, "[PARENT] fork done.");
	}
	return tracee_pid;
}


static void mgmt_page_init(void) {
	int i = 0;
	assert(sizeof(struct fork_mgmt_page) <= SIZEOF_PAGE);
	assert(sem_init(&fork_mgmt_semaphore, 0, MGMT_NUM_SEMAPHORES) == 0);

	fork_mgmt_page = mmap(NULL, SIZEOF_PAGE, PROT_READ|PROT_WRITE, MAP_SHARED|MAP_ANONYMOUS,
			-1, 0);
	assert(fork_mgmt_page != NULL);

	for(i = 0; i < MGMT_NUM_USAGE_ENTRIES; i++) {
		fork_mgmt_page->usage_bitmap[i] = 0;
	}
	assert(sem_init(&fork_mgmt_page->base.usage_bitmap_semaphore, 1, 1) == 0);
	assert(sem_init(&fork_mgmt_list_semaphore, 0, 1) == 0);
	initializer_pid = getpid();
	up_dprintf(CONTEXT, "management page initialized.");
}

static void mgmt_page_cleanup(void) {
	if (fork_mgmt_page != NULL) {
		if (getpid() == initializer_pid)
			sem_destroy(&fork_mgmt_page->base.usage_bitmap_semaphore);
		munmap(fork_mgmt_page, SIZEOF_PAGE);
	}
	sem_destroy(&fork_mgmt_semaphore);

	up_dprintf(CONTEXT, "management page finalized.");
}

__internal__ up_ctx_id upolicy_context_find_newtracee(pid_t pid) {
	struct list_entry *entry;
	struct fork_info *fork_info;
	up_ctx_id ctx_id = 0;

	assert(sem_wait(&fork_mgmt_list_semaphore) == 0);

	list_foreach(&fork_mgmt_list, entry) {
		fork_info = list_entry(entry, struct fork_info, entry);

		if (fork_info->pid == pid) {
			up_dprintf(CONTEXT,
					"Found starting new tracee with pid=%d. Setting context to id=%d", pid,
					fork_info->ctx->id);
			list_remove(&fork_mgmt_list, entry);
			ctx_id = fork_info->ctx->id;
			free(fork_info);
			break;
		}
	}
	if (ctx_id == 0) {
		up_dprintf(CONTEXT, "New tracee with pid=%d not found.", pid);
	}
	assert(sem_post(&fork_mgmt_list_semaphore) == 0);
	return ctx_id;
}

__internal__ void upolicy_context_cleanup(void) {
	struct list_entry *entry, *tmp;

	pthread_rwlock_destroy(&ctx_create_list_rwlock);
	pthread_rwlock_destroy(&ctx_list_rwlock);

	list_foreach_safe(&fork_mgmt_list, entry, tmp) {
		struct fork_info *fork_info = list_entry(entry, struct fork_info, entry);
		free(fork_info);
	}
	list_init(&fork_mgmt_list);

	list_init(&ctx_list);
	list_init(&ctx_create_list);
	ctx_local_id = 0;

	pthread_rwlock_init(&ctx_create_list_rwlock, NULL);
	pthread_rwlock_init(&ctx_list_rwlock, NULL);

	mgmt_page_cleanup();
	initializer_pid = 0;
}

__internal__ void upolicy_context_init(void) {
	mgmt_page_init();
}
