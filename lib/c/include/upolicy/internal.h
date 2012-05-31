/* internal.h
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
#ifndef UPOLICY_INTERNAL_H
#define UPOLICY_INTERNAL_H

#include <stdio.h>
#include <stdarg.h>

#include <upolicy/types.h>

#if __GNUC__ >= 4
#define __internal__ __attribute__ ((visibility ("internal")))
#else
#define __internal__
#endif

/* forward declarations */
struct upolicy_context;

#include <upolicy/core.h>

__internal__ struct upolicy_context* upolicy_context_find_create(up_ctx_id id);
__internal__ up_ctx_id upolicy_context_find_newtracee(pid_t pid);
__internal__ void upolicy_context_cleanup(void);
__internal__ void upolicy_context_init(void);

__internal__  int upolicy_netlink_init(void);
__internal__ void upolicy_netlink_cleanup(void);
__internal__ void upolicy_set_tracees_active();

__internal__
void __up_vprintf(const char *file_name, const char *func_name, int line_no,
		enum UPOLICY_LOG_LEVEL level, const char *fmt, va_list va);

static inline void __up_printf(const char *file_name, const char *func_name,
		int line_no, enum UPOLICY_LOG_LEVEL level, const char *fmt, ...) {
	va_list va;
	va_start(va, fmt);
	__up_vprintf(file_name, func_name, line_no, level, fmt, va);
	va_end(va);
}

#define up_printf(typ, fmt, ...) __up_printf(__FILE__, __func__, __LINE__, typ, \
	fmt, ## __VA_ARGS__)

#define up_eprintf(fmt, ...) up_printf(UPOLICY_LOG_ERROR, fmt, ## __VA_ARGS__)
#define up_wprintf(fmt, ...) up_printf(UPOLICY_LOG_WARNING, fmt, ## __VA_ARGS__)

#ifdef UPOLICY_DEBUG
__internal__
extern u_int32_t up_debug_flags;

static inline void __up_dprintf(enum UPOLICY_DEBUG_FLAGS dflag, const char *file_name,
		const char *func_name,
		int line_no, const char *fmt, ...) {
	if ((up_debug_flags & __UPOLICY_DEBUG_FLAG(dflag))) {
		va_list va;
		va_start(va, fmt);
		__up_vprintf(file_name, func_name, line_no, UPOLICY_LOG_DEBUG, fmt, va);
		va_end(va);
	}
}
#define up_dprintf(debug_name, fmt, ...) \
	__up_dprintf(UPOLICY_DEBUG_FLAG(debug_name), __FILE__, __func__, __LINE__, fmt, \
			## __VA_ARGS__)
#else
#define up_dprintf(debug_name, fmt, ...) /* no-op */
#endif /* UPOLICY_DEBUG */

#endif /* UPOLICY_INTERNAL_H */
