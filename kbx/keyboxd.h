/* keyboxd.h - Global definitions for keyboxd
 * Copyright (C) 2018 Werner Koch
 *
 * This file is part of GnuPG.
 *
 * GnuPG is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 *
 * GnuPG is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, see <https://www.gnu.org/licenses/>.
 */

#ifndef KEYBOXD_H
#define KEYBOXD_H

#ifdef GPG_ERR_SOURCE_DEFAULT
#error GPG_ERR_SOURCE_DEFAULT already defined
#endif
#define GPG_ERR_SOURCE_DEFAULT  GPG_ERR_SOURCE_KEYBOX
#include <gpg-error.h>

#include <gcrypt.h>
#include "../common/util.h"
#include "../common/membuf.h"
#include "../common/sysutils.h" /* (gnupg_fd_t) */


/* A large struct name "opt" to keep global flags */
struct
{
  unsigned int debug;  /* Debug flags (DBG_foo_VALUE) */
  int verbose;         /* Verbosity level */
  int quiet;           /* Be as quiet as possible */
  int dry_run;         /* Don't change any persistent data */
  int batch;           /* Batch mode */

  /* True if we are running detached from the tty. */
  int running_detached;

} opt;


/* Bit values for the --debug option.  */
#define DBG_MPI_VALUE	  2	/* debug mpi details */
#define DBG_CRYPTO_VALUE  4	/* debug low level crypto */
#define DBG_MEMORY_VALUE  32	/* debug memory allocation stuff */
#define DBG_CACHE_VALUE   64	/* debug the caching */
#define DBG_MEMSTAT_VALUE 128	/* show memory statistics */
#define DBG_HASHING_VALUE 512	/* debug hashing operations */
#define DBG_IPC_VALUE     1024  /* Enable Assuan debugging.  */

/* Test macros for the debug option.  */
#define DBG_CRYPTO  (opt.debug & DBG_CRYPTO_VALUE)
#define DBG_MEMORY  (opt.debug & DBG_MEMORY_VALUE)
#define DBG_CACHE   (opt.debug & DBG_CACHE_VALUE)
#define DBG_HASHING (opt.debug & DBG_HASHING_VALUE)
#define DBG_IPC     (opt.debug & DBG_IPC_VALUE)

/* Forward reference for local definitions in command.c.  */
struct server_local_s;

#if SIZEOF_UNSIGNED_LONG == 8
# define SERVER_CONTROL_MAGIC 0x6b6579626f786420
#else
# define SERVER_CONTROL_MAGIC 0x6b627864
#endif

/* Collection of data per session (aka connection). */
struct server_control_s
{
  unsigned long magic;/* Always has SERVER_CONTROL_MAGIC.  */
  int refcount;       /* Count additional references to this object.  */

  /* Private data used to fire up the connection thread.  We use this
   * structure do avoid an extra allocation for only a few bytes while
   * spawning a new connection thread.  */
  struct {
    gnupg_fd_t fd;
  } thread_startup;

  /* Private data of the server (kbxserver.c). */
  struct server_local_s *server_local;

  /* Environment settings for the connection.  */
  char *lc_messages;

  /* Miscellaneous info on the connection.  */
  unsigned long client_pid;
  int client_uid;

};


/* This is a special version of the usual _() gettext macro.  It
 * assumes a server connection control variable with the name "ctrl"
 * and uses that to translate a string according to the locale set for
 * the connection.  The macro LunderscoreIMPL is used by i18n to
 * actually define the inline function when needed.  */
#if defined (ENABLE_NLS) || defined (USE_SIMPLE_GETTEXT)
#define L_(a) keyboxd_Lunderscore (ctrl, (a))
#define LunderscorePROTO                                            \
  static inline const char *keyboxd_Lunderscore (ctrl_t ctrl,       \
                                                 const char *string)  \
    GNUPG_GCC_ATTR_FORMAT_ARG(2);
#define LunderscoreIMPL                                         \
  static inline const char *                                    \
  keyboxd_Lunderscore (ctrl_t ctrl, const char *string)         \
  {                                                             \
    return ctrl? i18n_localegettext (ctrl->lc_messages, string) \
      /*     */: gettext (string);                              \
  }
#else
#define L_(a) (a)
#endif


/*-- keyboxd.c --*/
void kbxd_exit (int rc) GPGRT_ATTR_NORETURN;
void kbxd_set_progress_cb (void (*cb)(ctrl_t ctrl, const char *what,
                                      int printchar, int current, int total),
                           ctrl_t ctrl);
const char *get_kbxd_socket_name (void);
int get_kbxd_active_connection_count (void);
void kbxd_sighup_action (void);


/*-- kbxserver.c --*/
void kbxd_start_command_handler (ctrl_t, gnupg_fd_t, unsigned int);

#endif /*KEYBOXD_H*/
