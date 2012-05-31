/* types.h
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
#ifndef UPOLICY_TYPES_H
#define UPOLICY_TYPES_H

#include <linux/types.h>
#include <kupolicy/types.h>
#include <kupolicy/netlink.h>

#include <stdarg.h>

/**
 * @defgroup Types Types
 * @{
 */

typedef enum UP_EV_DECISION upolicy_decision; /**< upolicy event decision */

/**
 * Log levels
 */
enum UPOLICY_LOG_LEVEL {
	UPOLICY_LOG_DEBUG, /**< debug log level */
	UPOLICY_LOG_WARNING, /**< warning log level */
	UPOLICY_LOG_ERROR, /**< error log level */
	__UPOLICY_LOG_MAX, /**< maximum log level value */
};

/**
 * Log handler function pointer.
 *
 * @param level Log level (@see UPOLICY_LOG_LEVEL)
 * @param file_name Name of file the logging call originated from
 * @param func_name Name of function the logging call originated from
 * @param line_no   Line number of file the logging call originated from
 * @param fmt       Format string
 * @param va        va list for format string
 */
typedef void (*upolicy_log_handler)(enum UPOLICY_LOG_LEVEL level,
		const char *file_name, const char *func_name, int line_no, const char *fmt,
		va_list va);

/** debug flags */
enum UPOLICY_DEBUG_FLAGS {
	__UPOLICY_DEBUG_MIN,   /**< Minimum flag, always 0. Used internally. */
	UPOLICY_DEBUG_CORE,    /**< core debug messages */
	UPOLICY_DEBUG_CONTEXT, /**< context debug messages */
	UPOLICY_DEBUG_LIST,    /**< list debug messages */
	UPOLICY_DEBUG_NETLINK, /**< netlink debug messages */
	UPOLICY_DEBUG_LIB,     /**< library (misc) debug messages */
	__UPOLICY_DEBUG_MAX,   /**< Maximum flag (plus 1) */
};

/**
 * All debug flags set.
 */
#define UPOLICY_DEBUG_FLAG_ALL (UPOLICY_DEBUG_FLAG(__UPOLICY_DEBUG_MAX) - 1)

/**
 * Convert UPOLICY_DEBUG_FLAGS value to actual flag.
 *
 * @param X debug flag value
 */
#define __UPOLICY_DEBUG_FLAG(X) (1 << X)

/**
 * Shortcut macro which prepends the NAME parameter with UPOLICY_DEBUG_ and calls
 * @ref __UPOLICY_DEBUG_FLAG.
 *
 * @param NAME Debug flag name (without UPOLICY_DEBUG_ prefix)
 */
#define UPOLICY_DEBUG_FLAG(NAME) __UPOLICY_DEBUG_FLAG(UPOLICY_DEBUG_ ##NAME)

/**
 * Default debug flag
 */
#define UPOLICY_DEBUG_FLAG_DEFAULT 0

/**
 * @}
 */

#endif /* UPOLICY_TYPES_H */
