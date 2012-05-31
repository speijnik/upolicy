/* lib.c
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

#include <stdio.h>
#include <stdarg.h>

#include <upolicy/internal.h>
#include <upolicy/types.h>

static const char *log_level_names[__UPOLICY_LOG_MAX] = {
		[UPOLICY_LOG_DEBUG] = "debug",
		[UPOLICY_LOG_WARNING] = "warning",
		[UPOLICY_LOG_ERROR] = "error",
};

#ifdef UPOLICY_DEBUG
#define DEFAULT_LOG_HANDLER upolicy_log_stderr
#else /* !UPOLICY_DEBUG */
#define DEFAULT_LOG_HANDLER NULL
#endif /* UPOLICY_DEBUG */

static upolicy_log_handler log_handlers[__UPOLICY_LOG_MAX] = {
		[UPOLICY_LOG_DEBUG] = DEFAULT_LOG_HANDLER,
		[UPOLICY_LOG_WARNING] = DEFAULT_LOG_HANDLER,
		[UPOLICY_LOG_ERROR] = DEFAULT_LOG_HANDLER,
};


__internal__
u_int32_t up_debug_flags = UPOLICY_DEBUG_FLAG_DEFAULT;

__internal__
void __up_vprintf(const char *file_name, const char *func_name, int line_no,
		enum UPOLICY_LOG_LEVEL level, const char *fmt, va_list va) {
	if (level < 0 || level >= __UPOLICY_LOG_MAX) {
		up_eprintf("Invalid debug level %d.", level);
		return;
	}

	if (log_handlers[level]) {
		log_handlers[level](level, file_name, func_name, line_no, fmt, va);
	}
}

void __up_debug_flag_set(enum UPOLICY_DEBUG_FLAGS flag, ...) {
	va_list va;
	va_start(va, flag);
	do {
		up_debug_flags |= __UPOLICY_DEBUG_FLAG(flag);
		flag = va_arg(va, enum UPOLICY_DEBUG_FLAGS);
	} while(flag != __UPOLICY_DEBUG_MIN);
	va_end(va);
}

void up_debug_flag_clear(enum UPOLICY_DEBUG_FLAGS flag) {
	up_debug_flags &= ~(__UPOLICY_DEBUG_FLAG(flag));
}

u_int32_t up_debug_flag_get(void) {
	return up_debug_flags;
}

const char *upolicy_log_name(enum UPOLICY_LOG_LEVEL level) {
	if (level < 0 || level >= __UPOLICY_LOG_MAX)
		return "unknown";
	return log_level_names[level];
}

void upolicy_log_stderr(enum UPOLICY_LOG_LEVEL level, const char *file_name,
		const char *func_name, int line_no, const char *fmt, va_list va) {
	fprintf(stderr, "[upolicy:%8s] (%s:%d) ", upolicy_log_name(level),
			func_name, line_no);
	vfprintf(stderr, fmt, va);
	fprintf(stderr, "\n");
}

void upolicy_log_set_handler(enum UPOLICY_LOG_LEVEL level,
		upolicy_log_handler handler) {
	if (level < 0 || level >= __UPOLICY_LOG_MAX) {
		up_eprintf("Invalid log level %d.", level);
		return;
	}

	log_handlers[level] = handler;
}

