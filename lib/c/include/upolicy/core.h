/* core.h
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
#ifndef UPOLICY_CORE_H
#define UPOLICY_CORE_H

#include <upolicy/types.h>

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

/**
 * @defgroup Core Core
 * @{
 */

/**
 * Initialize upolicy
 */
int upolicy_init(void);

/**
 * Finalize upolicy
 */
void upolicy_cleanup(void);

/**
 * Set debug flag
 * @param flag First debug flag
 * @param ... Debug flags
 *
 * NOTE: The last flag MUST be NULL.
 */
void __up_debug_flag_set(enum UPOLICY_DEBUG_FLAGS flag, ...);

/**
 * Get current debug flag
 * @returns Debug flag (mask)
 */
u_int32_t up_debug_flag_get(void);

/**
 * Clear given debug flag
 * @param flag Flag to clear
 */
void up_debug_flag_clear(enum UPOLICY_DEBUG_FLAGS flag);

/**
 * Set debug flags
 * @param flag0 First flag
 * @param ... Flags
 */
#define up_debug_flags_set(flag0, ...) __up_debug_flag_set(flag0, ##__VA_ARGS__, NULL)

/**
 * Set a single debug flag
 * @param flag Flag
 */
#define up_debug_flag_set(flag) __up_debug_flag_set(flag, NULL)

/**
 * Convert log level to log level name
 * @param level Log level
 * @returns Log level name
 */
const char *upolicy_log_name(enum UPOLICY_LOG_LEVEL level);

/**
 * Set handler for given log level
 * @param level Log level
 * @param handler Handler
 */
void upolicy_log_set_handler(enum UPOLICY_LOG_LEVEL level,
		upolicy_log_handler handler);

/**
 * Log handler that writes log messages to stderr.
 *
 * @see upolicy_log_handler
 */
void upolicy_log_stderr(enum UPOLICY_LOG_LEVEL level, const char *file_name,
		const char *func_name, int line_no, const char *fmt, va_list va);

/**
 * @}
 */

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* !UPOLICY_CORE_H */
