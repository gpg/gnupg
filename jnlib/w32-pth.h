/* w32-pth.h - GNU Pth emulation for W32 (MS Windows).
 * Copyright (c) 1999-2003 Ralf S. Engelschall <rse@engelschall.com>
 * Copyright (C) 2004 g10 Code GmbH
 *
 * This file is part of GnuPG.
 *
 * GnuPG is free software; you can redistribute it and/or modify it
 * under the terms of the GNU Lesser General Public License as
 * published by the Free Software Foundation; either version 2.1 of
 * the License, or (at your option) any later version.
 *
 * GnuPG is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA 
 *
 * ------------------------------------------------------------------
 * This code is based on Ralf Engelschall's GNU Pth, a non-preemptive
 * thread scheduling library which can be found at
 * http://www.gnu.org/software/pth/.
 */

/* Note that this header is usually used through a symlinked pth.h
   file.  This is needed so that we don't have a pth.h file here which
   would conflict if a system really has pth available. */
#ifndef W32_PTH_H
#define W32_PTH_H

#include <windows.h>  /* We need this for sockaddr et al.  FIXME: too
                         heavyweight - may be we should factor such
                         code out to a second header and adjust all
                         user files to include it only if required. */ 

#ifndef W32_PTH_HANDLE_INTERNAL
#define W32_PTH_HANDLE_INTERNAL  int
#endif


/* Filedescriptor blocking modes.  */
enum
  {
    PTH_FDMODE_ERROR = -1,
    PTH_FDMODE_POLL  =  0,
    PTH_FDMODE_BLOCK,
    PTH_FDMODE_NONBLOCK
  };


/* Mutex values. */
#define PTH_MUTEX_INITIALIZED  (1<<0)
#define PTH_MUTEX_LOCKED       (1<<1)

/* Note: We can't do static initialization, thus we don't define the
   initializer PTH_MUTEX_INIT.  */


#define PTH_KEY_INIT	       (1<<0)


/* Event subject classes. */
#define PTH_EVENT_FD           (1<<1)
#define PTH_EVENT_SELECT       (1<<2)
#define PTH_EVENT_SIGS         (1<<3)
#define PTH_EVENT_TIME         (1<<4)
#define PTH_EVENT_MSG          (1<<5)
#define PTH_EVENT_MUTEX        (1<<6)
#define PTH_EVENT_COND         (1<<7)
#define PTH_EVENT_TID          (1<<8)
#define PTH_EVENT_FUNC         (1<<9)



/* Event occurrence restrictions. */
#define PTH_UNTIL_OCCURRED     (1<<11)
#define PTH_UNTIL_FD_READABLE  (1<<12)
#define PTH_UNTIL_FD_WRITEABLE (1<<13)
#define PTH_UNTIL_FD_EXCEPTION (1<<14)
#define PTH_UNTIL_TID_NEW      (1<<15)
#define PTH_UNTIL_TID_READY    (1<<16)
#define PTH_UNTIL_TID_WAITING  (1<<17)
#define PTH_UNTIL_TID_DEAD     (1<<18)


/* Event structure handling modes. */
#define PTH_MODE_REUSE         (1<<20)
#define PTH_MODE_CHAIN         (1<<21)
#define PTH_MODE_STATIC        (1<<22)


/* Attribute commands for pth_attr_get and pth_attr_set(). */
enum
  {
    PTH_ATTR_PRIO,           /* RW [int]           Priority of thread.  */
    PTH_ATTR_NAME,           /* RW [char *]        Name of thread.  */
    PTH_ATTR_JOINABLE,       /* RW [int]           Thread detachment type.  */
    PTH_ATTR_CANCEL_STATE,   /* RW [unsigned int]  Thread cancellation state.*/
    PTH_ATTR_STACK_SIZE,     /* RW [unsigned int]  Stack size. */
    PTH_ATTR_STACK_ADDR,     /* RW [char *]        Stack lower address. */
    PTH_ATTR_DISPATCHES,     /* RO [int]           Total number of
                                                   thread dispatches. */
    PTH_ATTR_TIME_SPAWN,     /* RO [pth_time_t]    Time thread was spawned.  */
    PTH_ATTR_TIME_LAST,      /* RO [pth_time_t]    Time thread was
                                                   last dispatched.  */
    PTH_ATTR_TIME_RAN,       /* RO [pth_time_t]    Time thread was running.  */
    PTH_ATTR_START_FUNC,     /* RO [void *(*)(void *)] Thread start function.*/
    PTH_ATTR_START_ARG,      /* RO [void *]        Thread start argument.  */
    PTH_ATTR_STATE,          /* RO [pth_state_t]   Scheduling state. */
    PTH_ATTR_EVENTS,         /* RO [pth_event_t]   Events the thread 
                                                   is waiting for.  */
    PTH_ATTR_BOUND           /* RO [int]           Whether object is 
                                                   bound to thread. */
  };



/* Queries for pth_ctrl(). */
#define PTH_CTRL_GETAVLOAD            (1<<1)
#define PTH_CTRL_GETPRIO              (1<<2)
#define PTH_CTRL_GETNAME              (1<<3)
#define PTH_CTRL_GETTHREADS_NEW       (1<<4)
#define PTH_CTRL_GETTHREADS_READY     (1<<5)
#define PTH_CTRL_GETTHREADS_RUNNING   (1<<6)
#define PTH_CTRL_GETTHREADS_WAITING   (1<<7)
#define PTH_CTRL_GETTHREADS_SUSPENDED (1<<8)
#define PTH_CTRL_GETTHREADS_DEAD      (1<<9)
#define PTH_CTRL_DUMPSTATE            (1<<10)

#define PTH_CTRL_GETTHREADS           (  PTH_CTRL_GETTHREADS_NEW       \
                                       | PTH_CTRL_GETTHREADS_READY     \
                                       | PTH_CTRL_GETTHREADS_RUNNING   \
                                       | PTH_CTRL_GETTHREADS_WAITING   \
                                       | PTH_CTRL_GETTHREADS_SUSPENDED \
                                       | PTH_CTRL_GETTHREADS_DEAD        )


/* Event status codes. */
typedef enum
  {
    PTH_STATUS_PENDING,
    PTH_STATUS_OCCURRED,
    PTH_STATUS_FAILED
  }
pth_status_t;


/* Event deallocation types. */
enum 
  {
    PTH_FREE_THIS,
    PTH_FREE_ALL 
  };


/* The Pth thread handle object.  */
typedef void *pth_t;


/* The Mutex object.  */
typedef W32_PTH_HANDLE_INTERNAL pth_mutex_t;


/* The Event object.  */
struct pth_event_s;
typedef struct pth_event_s *pth_event_t;


/* The Attribute object.  */
struct pth_attr_s;
typedef struct pth_attr_s *pth_attr_t;


/* The Key object.  */
typedef int pth_key_t;


/* The Pth time object.  */
typedef struct timeval pth_time_t;


/* Function prototypes. */
int pth_init (void);
int pth_kill (void);
long pth_ctrl (unsigned long query, ...);

int pth_read_ev (int fd, void *buffer, size_t size, pth_event_t ev);
int pth_read (int fd,  void *buffer, size_t size);
int pth_write_ev (int fd, const void *buffer, size_t size, pth_event_t ev);
int pth_write (int fd, const void *buffer, size_t size);

int pth_select (int nfds, fd_set *rfds, fd_set *wfds, fd_set *efds,
		const struct timeval *timeout);

int pth_accept (int fd, struct sockaddr *addr, int *addrlen);
int pth_accept_ev (int fd, struct sockaddr *addr, int *addrlen,
                   pth_event_t hd);

int pth_connect (int fd, struct sockaddr *name, int namelen);


int pth_mutex_release (pth_mutex_t *hd);
int pth_mutex_acquire(pth_mutex_t *hd, int try_only, pth_event_t ev_extra);
int pth_mutex_init (pth_mutex_t *hd);


pth_attr_t pth_attr_new (void);
int pth_attr_destroy (pth_attr_t hd);
int pth_attr_set (pth_attr_t hd, int field, ...);

pth_t pth_spawn (pth_attr_t hd, void *(*func)(void *), void *arg);
pth_t pth_self (void);
int pth_join (pth_t hd, void **value);
int pth_abort (pth_t hd);
void pth_exit (void *value);

unsigned int pth_waitpid (unsigned int, int *status, int options);
int pth_wait (pth_event_t hd);

int pth_sleep (int n);
pth_time_t pth_timeout (long sec, long usec);



pth_event_t pth_event_isolate (pth_event_t hd);
int pth_event_free (pth_event_t hd, int mode);
int pth_event_status (pth_event_t hd);
int pth_event_occurred (pth_event_t hd);
pth_event_t pth_event_concat (pth_event_t ev, ...);
pth_event_t pth_event (unsigned long spec, ...);



/*-- pth_util.c --*/

/* void sigemptyset (struct sigset_s * ss); */

/* int sigaddset (struct sigset_s * ss, int signo); */



#endif /*W32_PTH_H*/
