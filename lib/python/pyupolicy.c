/* pyupolicy.c
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

#include <Python.h>
#include <structmember.h>
#include <frameobject.h>

#include <arpa/inet.h>
#include <pthread.h>
#include <linux/un.h>

#include <upolicy/context.h>
#include <upolicy/core.h>
#include <upolicy/netlink.h>
#include <upolicy/types.h>
#include <upolicy/version.h>

#define PYUPOLICY_LOGGER_NAME "upolicy"

enum PYUPOLICY_EVENT_TYPE {
	PYUPOLICY_EVTYPE_NOTIFICATION,
	PYUPOLICY_EVTYPE_QUESTION,
	PYUPOLICY_EVTYPE_MAX
};

#define HANDLER_COUNT sizeof(struct upolicy_ops)/sizeof(void *)

typedef struct {
  PyObject_HEAD
  struct upolicy_context context;
  struct upolicy_ops notify_ops;
  struct upolicy_ops question_ops;
  PyObject* handlers[HANDLER_COUNT+1];
} ContextObject;

typedef struct {
	PyObject_HEAD
	struct upolicy_event_info info;
} EventInfoObject;

typedef struct {
	PyObject_HEAD
	struct sockaddr* sa;
} SockAddrObject;

static unsigned int is_initialized = 0;

static PyObject *BaseException = NULL;
static PyObject *InitException = NULL;
static PyObject *ContextCreateException = NULL;
static PyObject *ForkException = NULL;

static PyObject *logger = NULL;
static PyObject *loggingLevels[__UPOLICY_LOG_MAX];
static const char *loggingNames[__UPOLICY_LOG_MAX] = {
		[UPOLICY_LOG_DEBUG] = "DEBUG",
		[UPOLICY_LOG_WARNING] = "WARNING",
		[UPOLICY_LOG_ERROR] = "ERROR",
};

typedef void (*handler_init_func)(ContextObject *contextObject,
		int is_notification);
static PyObject* _log(enum UPOLICY_LOG_LEVEL level, const char *file_name,
		const char *func_name, int line_no, const char *fmt, ...);
static PyObject* _vlog(enum UPOLICY_LOG_LEVEL level, const char *file_name,
		const char *func_name, int line_no, const char *fmt, va_list va);

#define LOG(level, fmt, ...) \
	_log(level, __FILE__, __func__, __LINE__, fmt, ##__VA_ARGS__)

#ifdef UPOLICY_DEBUG
#define log_debug(fmt, ...) \
	LOG(UPOLICY_LOG_DEBUG, fmt, ##__VA_ARGS__)
#else /* !UPOLICY_DEBUG */
#define log_debug(fmt, ...)
#endif /* UPOLICY_DEBUG */

#define log_error(fmt, ...) \
	LOG(UPOLICY_LOG_ERROR, fmt, ##__VA_ARGS__)
#define log_warning(fmt, ...) \
	LOG(UPOLICY_LOG_WARNING, fmt, ##__VA_ARGS__)

struct evhandler_info {
	const char *name;
	handler_init_func init_func;
};

#define EVHANDLER_INIT_FUNC_NAME(NAME) evinit_ ##NAME
#define EVHANDLER_INIT_FUNC_DECL(NAME) static void EVHANDLER_INIT_FUNC_NAME(NAME) \
	(ContextObject *contextObject, int is_notification)

#define EVHANDLER_FUNC_NAME(NAME) evhandler_ ##NAME
#define EVHANDLER_FUNC_DECL(NAME, ...) \
		static upolicy_decision EVHANDLER_FUNC_NAME(NAME) \
			(struct upolicy_event_info *info, ##__VA_ARGS__)

#define EVHANDLER_BEGIN { PyGILState_STATE gstate; \
		upolicy_decision decision = UP_DECISION(DENY); \
		gstate = PyGILState_Ensure();

#define EVHANDLER_END \
	PyGILState_Release(gstate); \
	return decision; \
	}

static EventInfoObject* EventInfo_from_C(struct upolicy_event_info *info);
static SockAddrObject* SockAddr_from_StructSockaddr(struct sockaddr* addr);
static upolicy_decision _evhandler_call(ContextObject *ctx, int handler_idx,
		struct upolicy_event_info *info, ...);

#define EVHANDLER_CALL(NAME, INFO, ...) \
	decision = _evhandler_call((ContextObject*) (INFO)->ctx->user, \
			(offsetof(struct upolicy_ops, NAME) / sizeof(void *)), INFO, \
		##__VA_ARGS__, NULL)


#define EVHANDLER_INIT_FUNC_DEF(NAME) EVHANDLER_INIT_FUNC_DECL(NAME) { \
	if (is_notification) { \
		contextObject->notify_ops. NAME = EVHANDLER_FUNC_NAME(NAME); \
	} else { \
		contextObject->question_ops. NAME = EVHANDLER_FUNC_NAME(NAME); \
	} \
	log_debug("set %s_ops->%s.", is_notification ? "notify" : "question", \
			#NAME); \
}

#define EVHANDLER_ITEM(NAME) \
	[offsetof(struct upolicy_ops, NAME)/sizeof(void *)] = \
	{ .name = #NAME, .init_func = EVHANDLER_INIT_FUNC_NAME(NAME) }

/* BEGIN event handler init function declarations */
EVHANDLER_INIT_FUNC_DECL(all_tracees_exited);
EVHANDLER_INIT_FUNC_DECL(tracer_init);
EVHANDLER_INIT_FUNC_DECL(clone);
EVHANDLER_INIT_FUNC_DECL(kill);
EVHANDLER_INIT_FUNC_DECL(exec);
EVHANDLER_INIT_FUNC_DECL(open);
EVHANDLER_INIT_FUNC_DECL(symlink);
EVHANDLER_INIT_FUNC_DECL(socket_accept);
EVHANDLER_INIT_FUNC_DECL(socket_bind);
EVHANDLER_INIT_FUNC_DECL(socket_create);
EVHANDLER_INIT_FUNC_DECL(socket_connect);
EVHANDLER_INIT_FUNC_DECL(socket_listen);
EVHANDLER_INIT_FUNC_DECL(ptrace_attach);
EVHANDLER_INIT_FUNC_DECL(tracee_exited);
EVHANDLER_INIT_FUNC_DECL(tracee_started);
/* END event handler init function declarations */

/* BEGIN event handler functions */
EVHANDLER_FUNC_DECL(all_tracees_exited) {
	EVHANDLER_BEGIN;
	EVHANDLER_CALL(all_tracees_exited, info);
	EVHANDLER_END;
	return UP_DECISION(DENY);
}

EVHANDLER_FUNC_DECL(tracer_init) {
	EVHANDLER_BEGIN;
	EVHANDLER_CALL(tracer_init, info);
	EVHANDLER_END;
	return UP_DECISION(DENY);
}

EVHANDLER_FUNC_DECL(clone, u_int32_t flags) {
	EVHANDLER_BEGIN;
	EVHANDLER_CALL(clone, info, "flags", PyInt_FromLong(flags));
	EVHANDLER_END;
	return UP_DECISION(DENY);
}

EVHANDLER_FUNC_DECL(kill, pid_t pid, int signo) {
	EVHANDLER_BEGIN;
	EVHANDLER_CALL(kill, info, "pid", PyInt_FromLong(pid),
			"signal", PyInt_FromLong(signo));
	EVHANDLER_END;
	return UP_DECISION(DENY);
}

EVHANDLER_FUNC_DECL(exec, const char *path) {
	EVHANDLER_BEGIN;
	EVHANDLER_CALL(exec, info, "path", PyString_FromString(path));
	EVHANDLER_END;
	return UP_DECISION(DENY);
}

EVHANDLER_FUNC_DECL(open, const char *path, mode_t mode) {
	EVHANDLER_BEGIN;
	EVHANDLER_CALL(open, info, "path", PyString_FromString(path), "mode",
			PyInt_FromLong(mode));
	EVHANDLER_END;
	return UP_DECISION(DENY);
}

EVHANDLER_FUNC_DECL(symlink, const char *source, const char *destination) {
	EVHANDLER_BEGIN;
	EVHANDLER_CALL(symlink, info, "source", PyString_FromString(source),
			"destination", PyString_FromString(destination));
	EVHANDLER_END;
	return UP_DECISION(DENY);
}

EVHANDLER_FUNC_DECL(socket_accept, int family, struct sockaddr *local_address,
		int local_addrlen, struct sockaddr *remote_address, int remote_addrlen) {
	SockAddrObject *local_addr = SockAddr_from_StructSockaddr(local_address);
	SockAddrObject *remote_addr = SockAddr_from_StructSockaddr(remote_address);

	if (!local_addr || !remote_addr) {
		Py_XDECREF(local_addr);
		Py_XDECREF(remote_addr);
		LOG(UPOLICY_LOG_DEBUG, "SockAddr_from_StructSockaddr failed.");
		return UP_DECISION(DENY);
	}
	EVHANDLER_BEGIN;
	EVHANDLER_CALL(socket_accept, info, "family", PyLong_FromLong(family),
			"local_address", local_addr,
			"local_addresslen", PyLong_FromLong(local_addrlen),
			"remote_address", remote_addr,
			"remote_addresslen", PyLong_FromLong(remote_addrlen));
	EVHANDLER_END;

	return UP_DECISION(DENY);
}

EVHANDLER_FUNC_DECL(socket_bind, int family, struct sockaddr *address,
		int addrlen) {
	SockAddrObject *addr = SockAddr_from_StructSockaddr(address);
	if (!addr) {
		LOG(UPOLICY_LOG_DEBUG, "SockAddr_from_StructSockaddr failed.");
		return UP_DECISION(DENY);
	}

	EVHANDLER_BEGIN;
	EVHANDLER_CALL(socket_bind, info, "family", PyLong_FromLong(family),
			"address", addr,
			"addresslen", PyLong_FromLong(addrlen));
	EVHANDLER_END;

	return UP_DECISION(DENY);
}

EVHANDLER_FUNC_DECL(socket_connect, int family,  struct sockaddr *local_address,
		int local_addrlen, struct sockaddr *remote_address, int remote_addrlen) {
	SockAddrObject *local_addr = SockAddr_from_StructSockaddr(local_address);
	SockAddrObject *remote_addr = SockAddr_from_StructSockaddr(remote_address);

	if (!local_addr || !remote_addr) {
		Py_XDECREF(local_addr);
		Py_XDECREF(remote_addr);
		LOG(UPOLICY_LOG_DEBUG, "SockAddr_from_StructSockaddr failed.");
		return UP_DECISION(DENY);
	}
	EVHANDLER_BEGIN;
	EVHANDLER_CALL(socket_connect, info, "family", PyLong_FromLong(family),
			"local_address", local_addr,
			"local_addresslen", PyLong_FromLong(local_addrlen),
			"remote_address", remote_addr,
			"remote_addresslen", PyLong_FromLong(remote_addrlen));
	EVHANDLER_END;
	return UP_DECISION(DENY);
}

EVHANDLER_FUNC_DECL(socket_create, int family, int type, int protocol) {
	EVHANDLER_BEGIN;
	EVHANDLER_CALL(socket_create, info, "family", PyInt_FromLong(family),
			"type", PyInt_FromLong(type), "protocol", PyInt_FromLong(protocol));
	EVHANDLER_END;
	return UP_DECISION(DENY);
}

EVHANDLER_FUNC_DECL(socket_listen, int family, struct sockaddr *address,
		int addrlen) {
	SockAddrObject *addr = SockAddr_from_StructSockaddr(address);

	if (!addr) {
		LOG(UPOLICY_LOG_DEBUG, "SockAddr_from_StructSockaddr failed.");
		return UP_DECISION(DENY);
	}

	EVHANDLER_BEGIN;
	EVHANDLER_CALL(socket_listen, info, "family", PyLong_FromLong(family),
			"address", addr,
			"addresslen", PyLong_FromLong(addrlen));
	EVHANDLER_END;
	return UP_DECISION(DENY);
}

EVHANDLER_FUNC_DECL(ptrace_attach, pid_t pid, unsigned int mode) {
	EVHANDLER_BEGIN;
	EVHANDLER_CALL(ptrace_attach, info, "pid", PyInt_FromLong(pid), "mode",
			PyInt_FromLong(mode));
	EVHANDLER_END;
	return UP_DECISION(DENY);
}

EVHANDLER_FUNC_DECL(tracee_exited) {
	EVHANDLER_BEGIN;
	EVHANDLER_CALL(tracee_exited, info);
	EVHANDLER_END;
	return UP_DECISION(ALLOW);
}

EVHANDLER_FUNC_DECL(tracee_started) {
	EVHANDLER_BEGIN;
	EVHANDLER_CALL(tracee_started, info);
	EVHANDLER_END;
	return UP_DECISION(ALLOW);
}

/* END event handler function declarations */

static const struct evhandler_info evhandler_info_map[HANDLER_COUNT + 1] = {
		EVHANDLER_ITEM(all_tracees_exited),
		EVHANDLER_ITEM(tracer_init),
		EVHANDLER_ITEM(clone),
		EVHANDLER_ITEM(kill),
		EVHANDLER_ITEM(exec),
		EVHANDLER_ITEM(open),
		EVHANDLER_ITEM(symlink),
		EVHANDLER_ITEM(socket_accept),
		EVHANDLER_ITEM(socket_bind),
		EVHANDLER_ITEM(socket_create),
		EVHANDLER_ITEM(socket_connect),
		EVHANDLER_ITEM(socket_listen),
		EVHANDLER_ITEM(ptrace_attach),
		EVHANDLER_ITEM(tracee_exited),
		EVHANDLER_ITEM(tracee_started),
};

/* BEGIN event handler init function definitions */
EVHANDLER_INIT_FUNC_DEF(all_tracees_exited);
EVHANDLER_INIT_FUNC_DEF(tracer_init);
EVHANDLER_INIT_FUNC_DEF(clone);
EVHANDLER_INIT_FUNC_DEF(kill);
EVHANDLER_INIT_FUNC_DEF(exec);
EVHANDLER_INIT_FUNC_DEF(open);
EVHANDLER_INIT_FUNC_DEF(symlink);
EVHANDLER_INIT_FUNC_DEF(socket_accept);
EVHANDLER_INIT_FUNC_DEF(socket_bind);
EVHANDLER_INIT_FUNC_DEF(socket_create);
EVHANDLER_INIT_FUNC_DEF(socket_connect);
EVHANDLER_INIT_FUNC_DEF(socket_listen);
EVHANDLER_INIT_FUNC_DEF(ptrace_attach);
EVHANDLER_INIT_FUNC_DEF(tracee_exited);
EVHANDLER_INIT_FUNC_DEF(tracee_started);
/* END event handler init funcs */

static PyObject* _vlog(enum UPOLICY_LOG_LEVEL level, const char *file_name,
		const char *func_name, int line_no, const char *fmt, va_list va) {
	PyObject *result = NULL;
	char buf[1024];

	vsnprintf(buf, sizeof(buf), fmt, va);
	buf[sizeof(buf)-1] = 0x0;

	Py_XINCREF(logger);
	if (logger) {
		PyObject *logLevel = NULL;
		PyObject *record = NULL;

		logLevel = loggingLevels[level];
		Py_INCREF(logLevel);

		if (!(record = PyObject_CallMethod(logger, "makeRecord", "sOsisOOs",
				PYUPOLICY_LOGGER_NAME, logLevel, file_name, line_no, buf,
				Py_BuildValue(""), Py_BuildValue(""), func_name))) {
			PyErr_Print();
		} else {
			result = PyObject_CallMethod(logger, "handle", "O", record);
		}
	} else {
		PyErr_SetString(PyExc_TypeError, "internal logger not set up");
	}
	Py_XDECREF(logger);

	return result;
}

static PyObject* _log(enum UPOLICY_LOG_LEVEL level,
		const char *file_name, const char *func_name, int line_no, const char *fmt,
		...)
{
	PyObject *result = NULL;
	va_list va;
	va_start(va, fmt);
	result = _vlog(level, file_name, func_name, line_no, fmt, va);
	va_end(va);
	return result;
}

static void install_event_handler(ContextObject *contextObj, PyObject* cb, int ev_index, int is_notification) {
	if (contextObj->handlers[ev_index] != NULL) {
		/* Handler already exists, fail silently. */
		log_warning("Event %s already has callback (%s) installed, not installing %s.",
				evhandler_info_map[ev_index].name,
				PyObject_REPR(contextObj->handlers[ev_index]),
				PyObject_REPR(cb));
		return;
	}

	evhandler_info_map[ev_index].init_func(contextObj, is_notification);
	Py_INCREF(cb);
	contextObj->handlers[ev_index] = cb;
}

static upolicy_decision _evhandler_call(ContextObject *ctx, int handler_idx,
		struct upolicy_event_info *info, ...) {
	PyObject *handler = NULL;
	upolicy_decision decision = UP_DECISION(DENY);

	if (info->is_notification)
		decision = UP_DECISION(ALLOW);

	Py_INCREF(ctx);
	handler = ctx->handlers[handler_idx];
	Py_INCREF(handler);

	if (handler) {
		va_list va;
		PyObject *kwd_dict = PyDict_New();
		PyObject *result = NULL;

		if (kwd_dict) {
			va_start(va, info);
			const char *name = NULL;
			PyObject *value = NULL;
			PyObject *empty_tuple = PyTuple_New(0);

			EventInfoObject *ev_info = EventInfo_from_C(info);
			Py_INCREF(ev_info);

			if (!ev_info) {
				log_error("Could not create event info object...");
				PyErr_Print();
				PyErr_Clear();
				Py_DECREF(kwd_dict);
				Py_DECREF(ctx);
				Py_DECREF(handler);
				return UP_DECISION(DENY);
			}

			PyDict_SetItemString(kwd_dict, "event_info",
					(PyObject*) ev_info);
			PyDict_SetItemString(kwd_dict, "event_name",
					PyString_FromString(evhandler_info_map[handler_idx].name));

			do {
				name = va_arg(va, const char *);
				if (name) {
					value = va_arg(va, PyObject*);

					if (!value) {
						log_error("Value for argument %s missing.", name);
						break;
					}

					PyDict_SetItemString(kwd_dict, name, value);
				}
			} while (name != NULL);
			va_end(va);
			/* dict building finished. */

			log_debug("Invoking %s(arguments=%s)...",
					PyObject_REPR(handler), PyObject_REPR(kwd_dict));
			log_debug("BEFORE RefCounts: handler=%d, kwargs=%d", Py_REFCNT(handler), Py_REFCNT(kwd_dict));

			result = PyObject_Call(handler, empty_tuple, kwd_dict);

			if (!result) {
				PyErr_Print();
				PyErr_Clear();
				Py_DECREF(kwd_dict);
				log_error("Handler %s raised exception.", PyObject_REPR(handler));
			}

			log_debug("AFTER RefCounts: handler=%d, kwargs=%d",
					Py_REFCNT(handler), Py_REFCNT(kwd_dict));

			if (!info->is_notification && result && PyInt_Check(result)) {
				decision = PyInt_AS_LONG(result);
				if (decision < 0 || decision >= __UP_DECISION_MAX) {
					log_error("Handler %s returned invalid value %d.",
							PyObject_REPR(handler), decision);
					decision = UP_DECISION(DENY);
				}
			} else if (!info->is_notification) {
				log_error("Handler %s did not return valid decision, defaulting to DENY.",
						PyObject_REPR(handler));
				decision = UP_DECISION(DENY);
			}
			Py_XDECREF(info);
			Py_XDECREF(result);
		}
		Py_DECREF(kwd_dict);

	}
	Py_DECREF(handler);
	Py_DECREF(ctx);

	return decision;
}


static void Context_dealloc(ContextObject *self) {
	int i = 0;

  /* Call destroy only for contexts with an ID > 0 */
  if (self->context.id > 0) {
    upolicy_context_destroy(&self->context);
    log_debug("Context @%p with id %d destroyed.", self,
    		self->context.id);

    /* Drop references to all handler functions */
    for(i = 0; i < HANDLER_COUNT; i++) {
    		if (self->handlers[i]) {
    			Py_DECREF(self->handlers[i]);
    		}
    		self->handlers[i] = NULL;
    	}
  } else {
  	log_debug("Context @%p not destroyed: id was 0.", self);
  }

  self->ob_type->tp_free((PyObject*) self);
}

static PyObject* Context_new(PyTypeObject *type, PyObject *args,
			     PyObject *kwds)
{
  return type->tp_alloc(type, 0);
}

static PyObject* Context_fork(PyObject *self) {
  ContextObject *ctx = (ContextObject*) self;
  int rc = 0;

  Py_BEGIN_ALLOW_THREADS;
  rc = upolicy_context_fork(&ctx->context);
  Py_END_ALLOW_THREADS;

  if (rc < 0) {
  	PyErr_SetFromErrno(ForkException);
  	return NULL;
  }
  else if (rc == 0) {
  	/*
  	 * PyOS_AfterFork needs to be called in the child so the Python interpreter
  	 * stays usable and the function can actually return.
  	 */
  	PyOS_AfterFork();
  }
  return PyInt_FromLong(rc);
}

static PyObject *Context_id_getter(PyObject *self, void *closure) {
	ContextObject *ctx = (ContextObject*) self;
	return PyInt_FromLong(ctx->context.id);
}

static int Context_init(ContextObject *self, PyObject *args,
			PyObject *kwds)
{
	PyObject *kw_notifications = NULL;
	PyObject *kw_questions = NULL;
	int rc = 0;
	int i = 0;

	memset(&self->context, 0, sizeof(struct upolicy_context));
	self->context.question_ops = &self->question_ops;
	self->context.notify_ops = &self->notify_ops;
	self->context.user = (void*) self;

	if (!is_initialized) {
		PyErr_SetString(InitException, "upolicy not initialized.");
		return -1;
	}

	if (!PyDict_Check(kwds)) {
		PyErr_SetString(InitException, "keyword arguments not a dict.");
		return -1;
	}

	kw_notifications = PyDict_GetItemString(kwds, "notifications");
	kw_questions = PyDict_GetItemString(kwds, "questions");

	if (!PyDict_Check(kw_notifications)) {
		PyErr_SetString(InitException, "notifications kwarg not a dict.");
		return -1;
	}

	if (!PyDict_Check(kw_questions)) {
		PyErr_SetString(InitException, "questions kwarg not a dict.");
		return -1;
	}

	log_debug("Checking handlers...");
	for(i = 0; i < HANDLER_COUNT; i++) {
		log_debug("Checking event %s...", evhandler_info_map[i].name);
		PyObject *cb = PyDict_GetItemString(kw_questions, evhandler_info_map[i].name);
		if (cb && PyCallable_Check(cb)) {

			/* Handler found. */
			log_debug("Installing question handler for %s.", evhandler_info_map[i].name);
			install_event_handler(self, cb, i, 0);
		} else {
			cb = PyDict_GetItemString(kw_notifications, evhandler_info_map[i].name);
			if (cb && PyCallable_Check(cb)) {
				/* Handler found. */
				log_debug("Installing notification handler for %s.", evhandler_info_map[i].name);
				install_event_handler(self, cb, i, 1);
			}
		}
	}

	log_debug("Creating context...");
  Py_BEGIN_ALLOW_THREADS;
  rc = upolicy_context_create(&self->context);
  Py_END_ALLOW_THREADS;
  if (rc < 0) {
    PyErr_SetString(ContextCreateException, "context creation failed.");
    return -1;
  }

  log_debug("Context %s initialized.", PyObject_REPR((PyObject*)self));
  return 0;
}

static PyObject* EventInfo_is_notification(PyObject *self) {
	EventInfoObject *ev_info = (EventInfoObject*) self;
	if (ev_info->info.is_notification)
		Py_RETURN_TRUE;
	Py_RETURN_FALSE;
}

static PyObject* EventInfo_decide(PyObject *self, PyObject *args) {
	upolicy_decision decision;
	EventInfoObject *ev_info = (EventInfoObject *) self;

	if (!PyArg_ParseTuple(args, "i", &decision)) {
		PyErr_SetString(PyExc_ValueError, "Invalid parameters.");
		return NULL;
	}

	/* Ignore notifications... */
	if (ev_info->info.is_notification)
		return PyLong_FromLong(0);


	return PyLong_FromLong(upolicy_event_decide(&ev_info->info, decision));
}

static PyObject *EventInfo_pid_getter(PyObject *self, void *closure) {
	EventInfoObject *ev_info = (EventInfoObject*) self;
	return PyInt_FromLong(ev_info->info.pid);
}

static PyObject *EventInfo_tid_getter(PyObject *self, void *closure) {
	EventInfoObject *ev_info = (EventInfoObject*) self;
	return PyInt_FromLong(ev_info->info.tid);
}

static PyObject *EventInfo_context_getter(PyObject *self, void *closure) {
	EventInfoObject *ev_info = (EventInfoObject*) self;
	ContextObject *ctx;

	if (!ev_info->info.ctx || !ev_info->info.ctx->user) {
		PyErr_SetString(PyExc_TypeError, "Event Info has not been initialized correctly.");
		return NULL;
	}

	ctx = (ContextObject*) ev_info->info.ctx->user;
	Py_INCREF(ctx);
	return (PyObject*)ctx;
}

static int EventInfo_init(EventInfoObject *self, PyObject *args,
			PyObject *kwds) {
	return 0;
}

static void EventInfo_dealloc(EventInfoObject *self) {
  self->ob_type->tp_free((PyObject *) self);
}

static PyObject* EventInfo_new(PyTypeObject *type, PyObject *args,
		PyObject *kwds) {
  EventInfoObject *self = NULL;

  self = (EventInfoObject*) type->tp_alloc(type, 0);

  if (self != NULL) {
    memset(&self->info, 0, sizeof(struct upolicy_event_info));
  }

  return (PyObject *) self;
}

static int SockAddr_init(SockAddrObject *self, PyObject *args,
			PyObject *kwds) {
	return 0;
}

static void SockAddr_dealloc(SockAddrObject *self) {
	if (self->sa) {
		free(self->sa);
		self->sa = NULL;
	}
	self->ob_type->tp_free((PyObject *) self);
}

static PyObject* SockAddr_port_getter(PyObject *self, void *closure) {
	SockAddrObject *sa_self = (SockAddrObject*) self;
	long port = -1;
	struct sockaddr_in *sin;
	struct sockaddr_in6 *sin6;
	struct sockaddr_nl *snl;

	if (sa_self->sa) {

		switch(sa_self->sa->sa_family) {
			case AF_INET:
				sin = (struct sockaddr_in *) sa_self->sa;
				port = sin->sin_port;
				break;
			case AF_INET6:
				sin6 = (struct sockaddr_in6 *) sa_self->sa;
				port = sin6->sin6_port;
				break;
			case AF_NETLINK:
				snl = (struct sockaddr_nl *) sa_self->sa;
				port = snl->nl_pid;
				break;
			default:
				port = -1;
				break;
		}
	}

	return PyLong_FromLong(port);
}

static PyObject* SockAddr_family_getter(PyObject *self, void *closure) {
	SockAddrObject *sa_self = (SockAddrObject*) self;
	long family = -1;

	if (sa_self->sa) {
		family = sa_self->sa->sa_family;
	}

	return PyLong_FromLong(family);
}

static PyObject* SockAddr_groups_getter(PyObject *self, void *closure) {
	SockAddrObject *sa_self = (SockAddrObject *) self;
	struct sockaddr_nl *snl;
	if (sa_self->sa->sa_family != AF_NETLINK) {
		PyErr_SetString(PyExc_NotImplementedError, "groups is only supported for AF_NETLINK addresses.");
		return NULL;
	}
	snl = (struct sockaddr_nl *) sa_self->sa;
	return PyLong_FromLong(snl->nl_groups);
}

static PyObject* SockAddr_flowinfo_getter(PyObject *self, void *closure) {
	SockAddrObject *sa_self = (SockAddrObject *) self;
	struct sockaddr_in6 *sin6;
	if (sa_self->sa->sa_family != AF_INET6) {
		PyErr_SetString(PyExc_NotImplementedError, "flowinfo is only supported for AF_INET6 addresses.");
		return NULL;
	}

	sin6 = (struct sockaddr_in6 *) sa_self->sa;
	return PyLong_FromLong(sin6->sin6_flowinfo);
}

static PyObject* SockAddr_scope_id_getter(PyObject *self, void *closure) {
	SockAddrObject *sa_self = (SockAddrObject *) self;
	struct sockaddr_in6 *sin6;
	if (sa_self->sa->sa_family != AF_INET6) {
		PyErr_SetString(PyExc_NotImplementedError, "scope_id is only supported for AF_INET6 addresses.");
		return NULL;
	}

	sin6 = (struct sockaddr_in6 *) sa_self->sa;

	return PyLong_FromLong(sin6->sin6_scope_id);
}

static PyObject* SockAddr_address_getter(PyObject *self, void *closure) {
	SockAddrObject *sa_self = (SockAddrObject *) self;
	char addr_string[256];
	const char *result = NULL;

	if (sa_self->sa->sa_family == AF_INET || sa_self->sa->sa_family == AF_INET6) {
		result = inet_ntop(sa_self->sa->sa_family, sa_self->sa, addr_string,
				sizeof(addr_string));
		if (!result) {
			PyErr_SetFromErrno(PyExc_BufferError);
			return NULL;
		}
		return PyString_FromString(addr_string);
	} else if (sa_self->sa->sa_family == AF_UNIX) {
		struct sockaddr_un *sun = (struct sockaddr_un *) sa_self->sa;
		strncpy(addr_string, sun->sun_path, sizeof(addr_string));
		return PyString_FromString(addr_string);
	}

	PyErr_Format(PyExc_NotImplementedError, "Unsupported address family %d",
			sa_self->sa->sa_family);
	return NULL;
}

static PyObject* SockAddr_new(PyTypeObject *type, PyObject *args,
		PyObject *kwds) {
	SockAddrObject *self = NULL;

	self = (SockAddrObject *) type->tp_alloc(type, 0);

	if (self != NULL) {
		self->sa = NULL;
	}

	return (PyObject *) self;
}

static void pyupolicy_log_handler(enum UPOLICY_LOG_LEVEL level,
		const char *file_name, const char *func_name, int line_no,
		const char *fmt, va_list va) {
	PyObject *result = NULL;

	if (level < 0 || level >= __UPOLICY_LOG_MAX)
		return;

	if (!loggingLevels[level])
		return;

	PyGILState_STATE gstate;
	gstate = PyGILState_Ensure();

	result = _vlog(level, file_name, func_name, line_no, fmt, va);
	if (!result) {
		PyErr_Print();
		PyErr_Clear();
	}
	Py_XDECREF(result);

	PyGILState_Release(gstate);
}

static PyObject *pyupolicy_initialize(PyObject *self, PyObject *args)
{
	int rc = 0;

	if (!is_initialized) {
		enum UPOLICY_LOG_LEVEL i = 0;
		for(i = 0; i < __UPOLICY_LOG_MAX; i++) {
			upolicy_log_set_handler(i, pyupolicy_log_handler);
		}

		Py_BEGIN_ALLOW_THREADS;
		rc = upolicy_init();
		Py_END_ALLOW_THREADS;
		if (rc) {
			PyErr_SetString(InitException, "upolicy initialization failed.");
			return NULL;
		}
		is_initialized = 1;

	}

	Py_RETURN_NONE;
}

static PyObject *pyupolicy_cleanup(PyObject *self, PyObject *args) {
	if (is_initialized) {
		upolicy_cleanup();
		is_initialized = 0;
	}

	Py_RETURN_NONE;
}

static PyObject *pyupolicy_is_initialized(PyObject *self, PyObject *args)
{
	if (is_initialized)
		Py_RETURN_TRUE;
	Py_RETURN_FALSE;
}

static PyObject *pyupolicy_join(PyObject *self, PyObject *args) {
	int rc;

	if (!is_initialized) {
		PyErr_SetString(InitException, "upolicy not initialized.");
		return NULL;
	}

	Py_BEGIN_ALLOW_THREADS;
	rc = upolicy_join();
	Py_END_ALLOW_THREADS;

	if (rc < 0) {
		PyErr_SetFromErrno(PyExc_TypeError);
		return NULL;
	}
	Py_RETURN_NONE;
}

static PyObject *pyupolicy_version(PyObject *self, PyObject *args) {
  PyObject *result;
  PyObject *major, *minor, *patch;

  major = PyInt_FromLong(UPOLICY_VERSION_MAJOR);
  if (!major)
	  return major;

  minor = PyInt_FromLong(UPOLICY_VERSION_MINOR);
  if (!minor)
	  return minor;

  patch = PyInt_FromLong(UPOLICY_VERSION_PATCH);
  if (!patch)
	  return patch;

  result = PyTuple_Pack(3, major, minor, patch);

  return result;
}

static PyObject* debug_flags_setclr(PyObject *self, PyObject *args, int clear) {
	PyObject *result = NULL;
	Py_ssize_t i = 0;
	PyObject *arg_tuple = NULL;

	if (PyTuple_Check(args)) {
		arg_tuple = args;
		Py_INCREF(arg_tuple);
	} else {
		arg_tuple = PyTuple_New(1);
		if (arg_tuple) {
			PyTuple_SetItem(arg_tuple, 0, args);
		}
	}

	if (arg_tuple) {
		for(i = 0; i < PyTuple_Size(arg_tuple); i++) {
			PyObject *value = PyTuple_GetItem(arg_tuple, i);
			if (PyInt_Check(value)) {
				int int_value = PyInt_AsLong(value);
				if (int_value >= 0 && int_value < __UPOLICY_DEBUG_MAX) {
					if (clear) {
						up_debug_flag_clear(int_value);
					} else {
						up_debug_flag_set(int_value);
					}
				}
			}
		}
		result = Py_BuildValue("");
	}

	Py_XDECREF(arg_tuple);
	return result;
}

static PyObject* pyupolicy_debug_flags_clear(PyObject *self, PyObject *args) {
	return debug_flags_setclr(self, args, 1);
}

static PyObject* pyupolicy_debug_flags_set(PyObject *self, PyObject *args) {
	return debug_flags_setclr(self, args, 0);
}

static PyObject* pyupolicy_debug_flags_setall(PyObject *self, PyObject *args) {
	up_debug_flags_set(UPOLICY_DEBUG_CONTEXT, UPOLICY_DEBUG_CORE, UPOLICY_DEBUG_LIB,
			UPOLICY_DEBUG_NETLINK);
	return Py_BuildValue("");
}

static PyMethodDef Context_methods[] = {
  {
    .ml_name = "fork",
    .ml_meth = (PyCFunction)Context_fork,
    .ml_flags = METH_NOARGS,
    .ml_doc = "Fork child and place it in given context",
  },
  { NULL } /* Sentinel */
};

static PyMethodDef EventInfo_methods[] = {
	{
		.ml_name = "is_notification",
		.ml_meth = (PyCFunction)EventInfo_is_notification,
		.ml_flags = METH_NOARGS,
		.ml_doc = "Check whether event is a notification",
	},
	{
		.ml_name = "decide",
		.ml_meth = (PyCFunction)EventInfo_decide,
		.ml_flags = METH_VARARGS,
		.ml_doc = "Send event decision to kernel",
	},
	{ NULL } /* Sentinel */
};

static PyMethodDef SockAddr_methods[] = {
	{ NULL } /* Sentinel */
};

static PyMethodDef pyupolicy_methods[] = {
  { .ml_name = "version",
  	.ml_meth = pyupolicy_version,
  	.ml_flags = METH_NOARGS,
    .ml_doc = "Get upolicy version tuple"
  },
  { .ml_name = "initialize",
  	.ml_meth = pyupolicy_initialize,
  	.ml_flags = METH_NOARGS,
    .ml_doc = "Initialize upolicy",
  },
  {
  	.ml_name = "cleanup",
  	.ml_meth = pyupolicy_cleanup,
  	.ml_flags = METH_NOARGS,
  	.ml_doc = "Finalize upolicy",
  },
  { .ml_name = "is_initialized",
  	.ml_meth = pyupolicy_is_initialized,
  	.ml_flags = METH_NOARGS,
    .ml_doc = "Check whether upolicy has been initialized"
  },
  {
  	.ml_name = "join",
  	.ml_meth = pyupolicy_join,
  	.ml_flags = METH_NOARGS,
  	.ml_doc = "Wait for all tracees to exit",
  },
  {
  	.ml_name = "debug_flags_set",
  	.ml_meth = pyupolicy_debug_flags_set,
  	.ml_flags = METH_VARARGS,
  	.ml_doc = "Sets upolicy debug flags",
  },
  {
  	.ml_name = "debug_flags_clear",
  	.ml_meth = pyupolicy_debug_flags_clear,
  	.ml_flags = METH_VARARGS,
  	.ml_doc = "Clears upolicy debug flags",
  },
  {
  	.ml_name = "debug_flags_setall",
  	.ml_meth = pyupolicy_debug_flags_setall,
  	.ml_flags = METH_NOARGS,
  	.ml_doc = "Set all upolicy debug flags",
  },
  { NULL } /* Sentinel */
};


static PyGetSetDef Context_getset[] = {
  {
  	.name = "id",
  	.get = Context_id_getter,
  	.doc = "Context ID",
  },
	{ NULL } /* Sentinel */
};

static PyGetSetDef EventInfo_getset[] = {
	{
		.name = "context",
		.get = EventInfo_context_getter,
		.doc = "Context",
	},
	{
		.name = "pid",
		.get = EventInfo_pid_getter,
		.doc = "Tracee Process ID",
	},
	{
		.name = "tid",
		.get = EventInfo_tid_getter,
		.doc = "Tracee Thread ID",
	},
	{ NULL } /* Sentinel */
};

static PyGetSetDef SockAddr_getset[] = {
	{
		.name = "family",
		.get = SockAddr_family_getter,
		.doc = "Address family",
	},
	{
		.name = "port",
		.get = SockAddr_port_getter,
		.doc = "Port number",
	},
	{
		.name = "address",
		.get = SockAddr_address_getter,
		.doc = "Address",
	},
	{
		.name = "flowinfo",
		.get = SockAddr_flowinfo_getter,
		.doc = "Flow Info (AF_INET6 only)",
	},
	{
		.name = "scope_id",
		.get = SockAddr_scope_id_getter,
		.doc = "Scope ID (AF_INET6 only)",
	},
	{
		.name = "groups",
		.get = SockAddr_groups_getter,
		.doc = "Groups (AF_NETLINK only)",
	},
	{ NULL } /* Sentinel */
};

static PyTypeObject ContextType = {
  PyObject_HEAD_INIT(NULL)
  .tp_name = "_upolicy.Context",
  .tp_basicsize = sizeof(ContextObject),
  .tp_flags = Py_TPFLAGS_DEFAULT | Py_TPFLAGS_BASETYPE,
  .tp_doc = "upolicy Context",
  .tp_dealloc = (destructor)Context_dealloc,
  .tp_methods = Context_methods,
  /*.tp_members = Context_members,*/
  .tp_init = (initproc)Context_init,
  .tp_new = Context_new,
  .tp_getset = Context_getset,
};

static PyTypeObject EventInfoType = {
		PyObject_HEAD_INIT(NULL)
		.tp_name = "_upolicy.EventInfo",
		.tp_basicsize = sizeof(EventInfoObject),
		.tp_flags = Py_TPFLAGS_DEFAULT,
		.tp_doc = "upolicy Event Information",
		.tp_dealloc = (destructor)EventInfo_dealloc,
		.tp_methods = EventInfo_methods,
		/*.tp_members = EventInfo_members,*/
		.tp_init = (initproc)EventInfo_init,
		.tp_new = EventInfo_new,
		.tp_getset = EventInfo_getset,
};

static PyTypeObject SockAddrType = {
		PyObject_HEAD_INIT(NULL)
		.tp_name = "_upolicy.SockAddr",
		.tp_basicsize = sizeof(SockAddrObject),
		.tp_flags = Py_TPFLAGS_DEFAULT,
		.tp_doc = "upolicy struct sockaddr wrapper",
		.tp_dealloc = (destructor) SockAddr_dealloc,
		.tp_methods = SockAddr_methods,
		.tp_init = (initproc) SockAddr_init,
		.tp_new = SockAddr_new,
		.tp_getset = SockAddr_getset,
};

static EventInfoObject* EventInfo_from_C(struct upolicy_event_info *info) {
	EventInfoObject *evinfo = PyObject_New(EventInfoObject, &EventInfoType);
	if (evinfo) {
		memcpy(&evinfo->info, info, sizeof(struct upolicy_event_info));
	}
	return evinfo;
}

static SockAddrObject* SockAddr_from_StructSockaddr(struct sockaddr* addr) {
	struct sockaddr *copy = NULL;
	SockAddrObject *sa = NULL;

	size_t copy_size = 0;
	switch(addr->sa_family) {
		case AF_INET:
			copy_size = sizeof(struct sockaddr_in);
			break;
		case AF_INET6:
			copy_size = sizeof(struct sockaddr_in6);
			break;
		case AF_UNIX:
			copy_size = sizeof(struct sockaddr_un);
			break;
		case AF_NETLINK:
			copy_size = sizeof(struct sockaddr_nl);
			break;
		default:
			copy_size = 0;
			break;
	}

	if (copy_size == 0)
		return NULL;

	sa = (SockAddrObject*) PyObject_New(SockAddrObject, &SockAddrType);
	if (!sa) {
		return NULL;
	}

	copy = malloc(copy_size);
	memcpy(copy, addr, copy_size);

	sa->sa = copy;
	return sa;
}

static void pyupolicy_atfork(void) {
	is_initialized = 0;
	//log_debug("Reset initialization state after fork.");
	printf("Init state reset.\n");
}

#ifndef PyMODINIT_FUNC
#define PyMODINIT_FUNC void
#endif
PyMODINIT_FUNC
init_upolicy(void)
{
  PyObject *m = NULL;
  PyObject *loggingModule = NULL;
  PyObject *loggingDict = NULL;
  PyObject *loggingLogger = NULL;
  enum UPOLICY_LOG_LEVEL i = 0;

  /* Needed so we can call into Python from non-Python threads */
  PyEval_InitThreads();

  pthread_atfork(NULL, NULL, pyupolicy_atfork);

  if (PyType_Ready(&ContextType) < 0 || PyType_Ready(&EventInfoType) < 0)
    return;

  loggingModule = PyImport_ImportModule("logging");
  if (!loggingModule)
  	return;

  loggingDict = PyModule_GetDict(loggingModule);
  if (!loggingModule)
  	return;

  loggingLogger = PyDict_GetItemString(loggingDict, "Logger");
  if (!loggingLogger)
  	return;

  logger = PyObject_CallMethod(loggingModule, "getLogger", "s", PYUPOLICY_LOGGER_NAME);
  if (!logger)
  	return;

  for(i = 0; i < __UPOLICY_LOG_MAX; i++) {
  	if (loggingNames[i]) {
  		PyObject *levelObject = PyDict_GetItemString(loggingDict, loggingNames[i]);
  		if (!levelObject)
  			return;
  		loggingLevels[i] = levelObject;
  	}
  }

  /* Add exceptions */
  BaseException = PyErr_NewExceptionWithDoc("_upolicy.BaseException",
		  "upolicy base exception", NULL, NULL);
  InitException = PyErr_NewExceptionWithDoc("_upolicy.InitException",
  		  "upolicy initialization exception", BaseException, NULL);
  ContextCreateException = PyErr_NewExceptionWithDoc(
		  "_upolicy.ContextCreateException",
		  "upolicy context create exception", BaseException, NULL);
  ForkException = PyErr_NewExceptionWithDoc(
  		"_upolicy.ForkException",
  		"upolicy fork exception", BaseException, NULL);

  if (InitException == NULL || BaseException == NULL
  		|| ContextCreateException == NULL || ForkException == NULL) {
	  if (InitException != NULL)
		  Py_DECREF(InitException);
	  if (BaseException != NULL)
		  Py_DECREF(BaseException);
	  if (ContextCreateException != NULL)
		  Py_DECREF(ContextCreateException);
	  if (ForkException != NULL)
	  	Py_DECREF(ForkException);
	  return;
  }

  m = Py_InitModule3("_upolicy", pyupolicy_methods,
  		    "upolicy Python bindings");

  if (m == NULL) {
	  Py_DECREF(BaseException);
	  Py_DECREF(InitException);
	  Py_DECREF(ContextCreateException);
	  Py_DECREF(ForkException);
	  return;
  }


  Py_INCREF(BaseException);
  Py_INCREF(InitException);
  Py_INCREF(ContextCreateException);
  Py_INCREF(ForkException);
  Py_INCREF((PyObject*)&ContextType);

  PyModule_AddObject(m, "BaseException", BaseException);
  PyModule_AddObject(m, "InitException", InitException);
  PyModule_AddObject(m, "ContextCreateException", ContextCreateException);
  PyModule_AddObject(m, "ForkException", ForkException);
  PyModule_AddObject(m, "Context", (PyObject *) &ContextType);
  PyModule_AddObject(m, "EventInfo", (PyObject *) &EventInfoType);
  PyModule_AddObject(m, "SockAddr", (PyObject *) &SockAddrType);

  PyModule_AddIntConstant(m, "NOTIFICATION", PYUPOLICY_EVTYPE_NOTIFICATION);
  PyModule_AddIntConstant(m, "QUESTION", PYUPOLICY_EVTYPE_QUESTION);
  PyModule_AddIntConstant(m, "ALLOW", UP_DECISION(ALLOW));
  PyModule_AddIntConstant(m, "DENY", UP_DECISION(DENY));
  PyModule_AddIntConstant(m, "KILL", UP_DECISION(KILL));
  PyModule_AddIntConstant(m, "POSTPONE", UP_DECISION(POSTPONE));

  PyModule_AddIntConstant(m, "DEBUG_CONTEXT", UPOLICY_DEBUG_CONTEXT);
  PyModule_AddIntConstant(m, "DEBUG_CORE", UPOLICY_DEBUG_CORE);
  PyModule_AddIntConstant(m, "DEBUG_LIB", UPOLICY_DEBUG_LIB);
  PyModule_AddIntConstant(m, "DEBUG_NETLINK", UPOLICY_DEBUG_NETLINK);

  PyModule_AddIntConstant(m, "FAMILY_IPv4", AF_INET);
  PyModule_AddIntConstant(m, "FAMILY_IPv6", AF_INET6);
  PyModule_AddIntConstant(m, "FAMILY_UNIX", AF_UNIX);
  PyModule_AddIntConstant(m, "FAMILY_NETLINK", AF_NETLINK);

  PyModule_AddStringConstant(m, "LOGGER_NAME", PYUPOLICY_LOGGER_NAME);
}
