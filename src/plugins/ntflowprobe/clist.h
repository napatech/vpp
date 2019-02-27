/*
 * clist.h - circular doubly linked list implementation
 *
 * Copyright (c) 2016 Cisco and/or its affiliates.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at:
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
#ifndef __included_clist_h__
#define __included_clist_h__

typedef struct clist_s {
  struct clist_s *next;
  struct clist_s *prev;
} clist_t;

#define clist_head_init(head) \
do { \
  (head)->next = (head); \
  (head)->prev = (head); \
} while(0)

#define clist_insert_after(head, entry) \
do { \
  clist_t *tmp = (head)->next; \
  (head)->next = (entry); \
  (entry)->next = tmp; \
  tmp->prev = (entry); \
  (entry)->prev = (head); \
} while(0)

#define clist_insert_before(head, entry) \
do { \
  clist_t *tmp = (head)->prev; \
  (head)->prev = (entry); \
  (entry)->prev = tmp; \
  tmp->next = (entry); \
  (entry)->next = (head); \
} while(0)

#define clist_remove(entry) \
do { \
  (entry)->next->prev = (entry)->prev; \
  (entry)->prev->next = (entry)->next; \
} while(0)

#define container_of(ptr, type, member) (type*)((char*)ptr - offsetof(type, member))
#define clist_for_each(cur, head, member) \
  for (cur = container_of((head)->next, typeof(*(cur)), member); \
       &(cur)->member != (head); \
       (cur) = container_of((cur)->member.next, typeof(*(cur)), member))

#define clist_for_each_safe(cur, n, head, member) \
  for (cur = container_of((head)->next, typeof(*(cur)), member), \
       n = container_of((cur)->member.next, typeof(*(cur)), member); \
       &(cur)->member != (head); \
       cur = n, n = container_of((n)->member.next, typeof(*(n)), member))

#endif
