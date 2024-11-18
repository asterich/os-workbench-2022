#include "co.h"
#include <assert.h>
#include <stdlib.h>
#include <setjmp.h>
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdio.h>

#define STACK_SIZE (1024 * 64)

#ifndef container_of
#define container_of(ptr, type, member)                                                                                \
    ({                                                                                                                 \
        const typeof(((type *) 0)->member) *__mptr = (ptr);                                                            \
        (type *) ((char *) __mptr - offsetof(type, member));                                                           \
    })
#endif

/**
 * list_entry - get the struct for this entry
 * @ptr:	the &struct list_head pointer.
 * @type:	the type of the struct this is embedded in.
 * @member:	the name of the list_head within the struct.
 */
#define list_entry(ptr, type, member) container_of(ptr, type, member)

typedef struct list_head {
  struct list_head *next;
} list_head_t;

void list_init(list_head_t *head) {
  head->next = head;
}

/* not including head. */
size_t list_len(list_head_t *head) {
  size_t len = 0;
  list_head_t *p = head->next;
  while (p != head) {
    len++;
    p = p->next;
  }
  return len;
}

void list_append_tail(list_head_t *head, list_head_t *newnode) {
  list_head_t *p = head;
  while (p->next != head) {
    p = p->next;
  }

  p->next = newnode;
  newnode->next = head;
}

void list_remove(list_head_t *head, list_head_t *delnode) {
  if (!delnode) {
    return;
  }

  list_head_t *p = head;

  while (p->next != head) {
    if (p->next == delnode) {
      break;
    }
    p = p->next;
  }

  if (p->next == head) {
    return;
  }

  p->next = delnode->next;
  delnode->next = NULL;
}

/**
 * list_first_entry - get the first element from a list
 * @ptr:	the list head to take the element from.
 * @type:	the type of the struct this is embedded in.
 * @member:	the name of the list_head within the struct.
 *
 * Note, that list is expected to be not empty.
 */
#define list_first_entry(ptr, type, member) list_entry((ptr)->next, type, member)
/**
 * list_next_entry - get the next element in list
 * @pos:	the type * to cursor
 * @member:	the name of the list_head within the struct.
 */
#define list_next_entry(pos, member) list_entry((pos)->member.next, typeof(*(pos)), member)

#define list_for_each_entry(pos, head, member) \
    for (pos = list_first_entry(head, typeof(*pos), member); \
         &pos->member != (head); \
         pos = list_next_entry(pos, member))

static inline void stack_switch_call(void *sp, void *entry, uintptr_t arg) {
  asm volatile (
#if __x86_64__
    "movq %%rsp, %%rcx;"
    "movq %0, %%rsp;"
    "movq %2, %%rdi;"
    "sub  $0x8, %%rsp;"
    "push %%rcx;"
    "call *%1;"
    "pop %%rsp"
      :
      : "b"((uintptr_t)sp), "d"(entry), "a"(arg)
      : "memory", "rcx"
#else
    "movl %0, %%esp; movl %2, 4(%0); jmp *%1"
      : : "b"((uintptr_t)sp - 8), "d"(entry), "a"(arg) : "memory"
#endif
  );
}

enum co_status {
  CO_NEW = 1,   // 新创建，还未执行过
  CO_RUNNABLE,  // 已经执行过，yield了
  CO_WAITING,   // 在 co_wait 上等待
  CO_DEAD,      // 已经结束，但还未释放资源
};

const char *status_map[] = {
  "empty",
  "new",
  "runnable",
  "waiting",
  "dead",
};

struct co {
  char *name;
  void (*func)(void *); // co_start 指定的入口地址和参数
  void *arg;

  enum co_status status;  // 协程的状态
  struct co *    waiter;  // 是否有其他协程在等待当前协程
  jmp_buf        context; // 寄存器现场 (setjmp.h)
  uint8_t        stack[STACK_SIZE]; // 协程的堆栈

  list_head_t co_list; 
} __attribute__((aligned(16)));

list_head_t coroutine_list;
int initialized = 0;
struct co *curr_co = NULL;

struct co *co_alloc(const char *name, void (*func)(void *), void *arg) {
  struct co *new_co = (struct co *)calloc(1, sizeof(struct co));
  new_co->name = (char *)calloc(strlen(name) + 1, sizeof(char));
  list_append_tail(&coroutine_list, &new_co->co_list);
  new_co->status = CO_NEW;
  new_co->waiter = NULL;
  strcpy(new_co->name, name);
  new_co->func = func;
  new_co->arg = arg;
  return new_co;
}

void co_free(struct co *co) {
  list_remove(&coroutine_list, &co->co_list);
  free(co->name);
  free(co);
}

struct co *co_start(const char *name, void (*func)(void *), void *arg) {
  if (!curr_co) {
    /// Initialize coroutine_list.
    list_init(&coroutine_list);

    /// main() not initialized to a coroutine yet.
    curr_co = co_alloc("main", NULL, NULL);
    // setjmp(curr_co->context);
    curr_co->status = CO_RUNNABLE; /// set it to avoid CO_NEW
  }

  struct co *new_co = co_alloc(name, func, arg);
  return new_co;
}

void co_wait(struct co *co) {
  /// Set the status of current coroutine to CO_WAITING.
  curr_co->status = CO_WAITING;

  /// Set the waiter.
  co->waiter = curr_co;

  /// When the coroutine we're waiting for is not dead,
  /// switch to another coroutine.
  while (co->status != CO_DEAD) {
    co_yield();
  }

  /// It's dead, free it.
  co_free(co);

  /// Reap coroutine "main".
  if (list_len(&coroutine_list) == 1) {
    printf("curr_co\'s name is: %s\n", curr_co->name);
    struct co *main_co = list_entry(coroutine_list.next, struct co, co_list);
    printf("main_co\'s name is: %s\n", main_co->name);
    assert(curr_co == main_co);
    if (!strcmp(main_co->name, "main")) {
      co_free(main_co);
    } else {
      perror("The coroutine freeing in the end is not main coroutine");
    }
    curr_co = NULL;
  }
}

void co_yield() {
  /// If setjmp's return value is not 0,
  /// it must be another coroutine yielding.
  /// Ignore it.
  if (setjmp(curr_co->context) > 0) {
    return;
  }

  /// Find a coroutine to run.
  /// You can find at least one coroutine.
  struct co *exec_co = NULL;
  list_for_each_entry(exec_co, &coroutine_list, co_list) {
    printf("%s is at status: %s\n", exec_co->name, status_map[exec_co->status]);
    if (exec_co == curr_co) {
      continue;
    }
    if (exec_co->status == CO_NEW
        || exec_co->status == CO_RUNNABLE
        || exec_co->status == CO_WAITING) {
      break;
    }
  }

  struct co *old_co = curr_co;
  curr_co = exec_co;
  switch (exec_co->status) {
    /// CO_NEW
    /// Context has not set yet. Jump directly.
    case CO_NEW:
    {
      exec_co->status = CO_RUNNABLE;
      stack_switch_call(exec_co->stack + STACK_SIZE - 0x10, exec_co->func, (uintptr_t)exec_co->arg);

      /// When coroutine returns, %rip goes here.
      /// Set status to CO_DEAD.
      printf("coroutine %s is dead.\n", exec_co->name);
      exec_co->status = CO_DEAD;
    }
    break;

    /// CO_RUNNABLE and CO_WAITING
    /// Context has already set. Just use longjmp().
    case CO_RUNNABLE:
    case CO_WAITING:
    {
      longjmp(exec_co->context, 1);
    }
    break;

    default:
      perror("co_yield status");
      return;
  }
}
