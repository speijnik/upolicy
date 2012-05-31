/* list.h
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
#ifndef UPOLICY_LIST_H
#define UPOLICY_LIST_H

/**
 * @addtogroup Misc Miscellaneous
 * @{
 */

#ifndef NULL
#define NULL (void*)0
#endif /* NULL */

/**
 * Structure holding a list entry
 */
struct list_entry {
  struct list_entry *next; /**< next pointer */
  struct list_entry *prev; /**< prev pointer */
};

/**
 * Structure holding a list head
 */
struct list {
  struct list_entry *head; /**< head of the list */
  struct list_entry *tail; /**< tail of the list */
};

/**
 * Initialize list
 *
 * @param list Pointer to struct list
 *
 * This is equivalent to @ref LIST_INITIALIZER.
 */
static inline void list_init(struct list *list) {
	list->head = list->tail = NULL;
}

/**
 * Prepend entry to list
 * @param list Pointer to struct list
 * @param entry Pointer to struct list_entry
 */
static inline void list_prepend(struct list *list, struct list_entry *entry) {
	if (list->head == NULL) {
		list->head = list->tail = entry;
		entry->prev = NULL;
		entry->next = NULL;
	} else {
		list->head->prev = entry;
		entry->next = list->head;
		entry->prev = NULL;
		list->head = entry;
	}
}

/**
 * Append entry to list
 * @param list Pointer to struct list
 * @param entry Pointer to struct list_entry
 */
static inline void list_append(struct list *list, struct list_entry *entry) {
	if (list->head == NULL) {
		list->head = list->tail = entry;
		entry->prev = NULL;
		entry->next = NULL;
	} else {
		list->tail->next = entry;
		entry->prev = list->tail;
		entry->next = NULL;
		list->tail = entry;
	}
}

/**
 * Remove entry from list
 * @param list Pointer to struct list
 * @param entry Pointer to struct list_entry
 */
static inline void list_remove(struct list *list, struct list_entry *entry) {
	if (list->head == entry && list->tail == entry) {
		list->head = list->tail = NULL;
	} else if (list->head == entry) {
		list->head = entry->next;

		if (entry->next != NULL) {
			entry->next->prev = NULL;
		}
	} else if (list->tail == entry) {
		list->tail = entry->prev;

		if (entry->prev != NULL) {
			entry->prev->next = NULL;
		}
	} else {
		entry->prev->next = entry->next;
		entry->next->prev = entry->prev;
	}
}

/**
 * Macro for iterating over list entries
 *
 * @param list Pointer to struct list
 * @param entry Pointer to struct list_entry
 */
#define list_foreach(list, entry) \
		for(entry = (list)->head; entry != NULL; entry = (entry)->next)

/**
 * Macro for iterating over list entries (deletion safe version).
 *
 * @param list Pointer to struct list
 * @param entry_a Pointer to struct list_entry
 * @param entry_b Pointer to struct list_entry (temporary)
 */
#define list_foreach_safe(list, entry_a, entry_b) \
		for(entry_a = (list)->head, entry_b = (entry_a) ? (entry_a)->next : NULL; \
				entry_a != NULL; \
				entry_a = entry_b, entry_b = (entry_b) ? (entry_b)->next : NULL)

/**
 * Initializes @ref list
 *
 * Usage: struct list my_list = LIST_INITIALIZER;
 */
#define LIST_INITIALIZER { .head = NULL, .tail = NULL }

#if __GNUC__ >= 4
#ifndef offsetof
#define offsetof(T, m) __builtin_offsetof(T, m)
#endif /* offsetof */
#else /* __GNUC__ < 4 */
#error "GCC too old, no offsetof support."
#endif /* __GNUC__ >= 4 */

/**
 * Macro for getting a pointer to the enclosing struct from a struct list_entry
 *
 * @param entry Pointer to struct list_entry
 * @param type Type of enclosing struct
 * @param member Name of the struct list_entry member
 * @returns Pointer to structure containing the list_entry.
 */
#define list_entry(entry, type, member) (type *)((void*)entry - offsetof(type, member))

/**
 * @}
 */

#endif /* UPOLICY_LIST_H */
