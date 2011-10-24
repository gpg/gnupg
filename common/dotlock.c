/* dotlock.c - dotfile locking
 * Copyright (C) 1998, 2000, 2001, 2003, 2004,
 *               2005, 2006, 2008, 2010, 2011 Free Software Foundation, Inc.
 *
 * This file is part of JNLIB, which is a subsystem of GnuPG.
 *
 * JNLIB is free software; you can redistribute it and/or modify it
 * under the terms of either
 *
 *   - the GNU Lesser General Public License as published by the Free
 *     Software Foundation; either version 3 of the License, or (at
 *     your option) any later version.
 *
 * or
 *
 *   - the GNU General Public License as published by the Free
 *     Software Foundation; either version 2 of the License, or (at
 *     your option) any later version.
 *
 * or both in parallel, as here.
 *
 * JNLIB is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copies of the GNU General Public License
 * and the GNU Lesser General Public License along with this program;
 * if not, see <http://www.gnu.org/licenses/>.
 *
 * ALTERNATIVELY, this file may be distributed under the terms of the
 * following license, in which case the provisions of this license are
 * required INSTEAD OF the GNU Lesser General License or the GNU
 * General Public License. If you wish to allow use of your version of
 * this file only under the terms of the GNU Lesser General License or
 * the GNU General Public License, and not to allow others to use your
 * version of this file under the terms of the following license,
 * indicate your decision by deleting this paragraph and the license
 * below.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, and the entire permission notice in its entirety,
 *    including the disclaimer of warranties.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. The name of the author may not be used to endorse or promote
 *    products derived from this software without specific prior
 *    written permission.
 *
 * THIS SOFTWARE IS PROVIDED ``AS IS'' AND ANY EXPRESS OR IMPLIED
 * WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT,
 * INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED
 * OF THE POSSIBILITY OF SUCH DAMAGE.
 */

/*
   Overview:
   =========

   This module implements advisory file locking in a portable way.
   Due to the problems with POSIX fcntl locking a separate lock file
   is used.  It would be possible to use fcntl locking on this lock
   file and thus avoid the weird auto unlock bug of POSIX while still
   having an unproved better performance of fcntl locking.  However
   there are still problems left, thus we resort to use a hardlink
   which has the well defined property that a link call will fail if
   the target file already exists.

   Given that hardlinks are also available on NTFS file systems since
   Windows XP; it will be possible to enhance this module to use
   hardlinks even on Windows and thus allow Windows and Posix clients
   to use locking on the same directory.  This is not yet implemented;
   instead we use a lockfile on Windows along with W32 style file
   locking.

   On FAT file systems hardlinks are not supported.  Thus this method
   does not work.  Our solution is to use a O_EXCL locking instead.
   Querying the type of the file system is not easy to do in a
   portable way (e.g. Linux has a statfs, BSDs have a the same call
   but using different structures and constants).  What we do instead
   is to check at runtime whether link(2) works for a specific lock
   file.


   How to use:
   ===========

   At program initialization time, the module should be explicitly
   initialized:

      dotlock_create (NULL, 0);

   This installs an atexit handler and may also initialize mutex etc.
   It is optional for non-threaded applications.  Only the first call
   has an effect.  This needs to be done before any extra threads are
   started.

   To create a lock file (which  prepares it but does not take the
   lock) you do:

     dotlock_t h

     h = dotlock_create (fname, 0);
     if (!h)
       error ("error creating lock file: %s\n", strerror (errno));

   It is important to handle the error.  For example on a read-only
   file system a lock can't be created (but is usually not needed).
   FNAME is the file you want to lock; the actual lockfile is that
   name with the suffix ".lock" appended.  On success a handle to be
   used with the other functions is returned or NULL on error.  Note
   that the handle shall only be used by one thread at a time.  This
   function creates a unique file temporary file (".#lk*") in the same
   directory as FNAME and returns a handle for further operations.
   The module keeps track of theses unique files so that they will be
   unlinked using the atexit handler.  If you don't need the lock file
   anymore, you may also explicitly remove it with a call to:

     dotlock_destroy (h);

   To actually lock the file, you use:

     if (dotlock_take (h, -1))
       error ("error taking lock: %s\n", strerror (errno));

   This function will wait until the lock is acquired.  If an
   unexpected error occurs if will return non-zero and set ERRNO.  If
   you pass (0) instead of (-1) the function does not wait in case the
   file is already locked but returns -1 and sets ERRNO to EACCES.
   Any other positive value for the second parameter is considered a
   timeout valuie in milliseconds.

   To release the lock you call:

     if (dotlock_release (h))
       error ("error releasing lock: %s\n", strerror (errno));

   or, if the lock file is not anymore needed, you may just call
   dotlock_destroy.  However dotlock_release does some extra checks
   before releasing the lock and prints diagnostics to help detecting
   bugs.

   If you want to explicitly destroy all lock files you may call

     dotlock_remove_lockfiles ();

   which is the core of the installed atexit handler.  In case your
   application wants to disable locking completely it may call

     disable_locking ()

   before any locks are created.

   There are two convenience functions to store an integer (e.g. a
   file descriptor) value with the handle:

     void dotlock_set_fd (dotlock_t h, int fd);
     int  dotlock_get_fd (dotlock_t h);

   If nothing has been stored dotlock_get_fd returns -1.



   How to build:
   =============

   This module was originally developed for GnuPG but later changed to
   allow its use without any GnuPG dependency.  If you want to use it
   with you application you may simply use it and it should figure out
   most things automagically.

   You may use the common config.h file to pass macros, but take care
   to pass -DHAVE_CONFIG_H to the compiler.  Macros used by this
   module are:

     DOTLOCK_USE_PTHREAD  - Define if POSIX threads are in use.

     DOTLOCK_GLIB_LOGGING - Define this to use Glib logging functions.

     DOTLOCK_EXT_SYM_PREFIX - Prefix all external symbols with the
                              string to which this macro evaluates.

     GNUPG_MAJOR_VERSION - Defined when used by GnuPG.

     HAVE_DOSISH_SYSTEM  - Defined for Windows etc.  Will be
                           automatically defined if a the target is
                           Windows.

     HAVE_POSIX_SYSTEM   - Internally defined to !HAVE_DOSISH_SYSTEM.

     HAVE_SIGNAL_H       - Should be defined on Posix systems.  If config.h
                           is not used defaults to defined.

     DIRSEP_C            - Separation character for file name parts.
                           Usually not redefined.

     EXTSEP_S            - Separation string for file name suffixes.
                           Usually not redefined.

     HAVE_W32CE_SYSTEM   - Currently only used by GnuPG.

   Note that there is a test program t-dotlock which has compile
   instructions at its end.  At least for SMBFS and CIFS it is
   important that 64 bit versions of stat are used; most programming
   environments do this these days, just in case you want to compile
   it on the command line, remember to pass -D_FILE_OFFSET_BITS=64


   Bugs:
   =====

   On Windows this module is not yet thread-safe.


   Miscellaneous notes:
   ====================

   On hardlinks:
   - Hardlinks are supported under Windows with NTFS since XP/Server2003.
   - In Linux 2.6.33 both SMBFS and CIFS seem to support hardlinks.
   - NFS supports hard links.  But there are solvable problems.
   - FAT does not support links

   On the file locking API:
   - CIFS on Linux 2.6.33 supports several locking methods.
     SMBFS seems not to support locking.  No closer checks done.
   - NFS supports Posix locks.  flock is emulated in the server.
     However there are a couple of problems; see below.
   - FAT does not support locks.
   - An advantage of fcntl locking is that R/W locks can be
     implemented which is not easy with a straight lock file.

   On O_EXCL:
   - Does not work reliable on NFS
   - Should work on CIFS and SMBFS but how can we delete lockfiles?

   On NFS problems:
   - Locks vanish if the server crashes and reboots.
   - Client crashes keep the lock in the server until the client
     re-connects.
   - Communication problems may return unreliable error codes.  The
     MUA Postfix's workaround is to compare the link count after
     seeing an error for link.  However that gives a race.  If using a
     unique file to link to a lockfile and using stat to check the
     link count instead of looking at the error return of link(2) is
     the best solution.
   - O_EXCL seems to have a race and may re-create a file anyway.

*/

#ifdef HAVE_CONFIG_H
# include <config.h>
#endif

/* Some quick replacements for stuff we usually expect to be defined
   in config.h.  Define HAVE_POSIX_SYSTEM for better readability. */
#if !defined (HAVE_DOSISH_SYSTEM) && defined(_WIN32)
# define HAVE_DOSISH_SYSTEM 1
#endif
#if !defined (HAVE_DOSISH_SYSTEM) && !defined (HAVE_POSIX_SYSTEM)
# define HAVE_POSIX_SYSTEM 1
#endif

/* With no config.h assume that we have sitgnal.h.  */
#if !defined (HAVE_CONFIG_H) && defined (HAVE_POSIX_SYSTEM)
# define HAVE_SIGNAL_H 1
#endif

/* Standard headers.  */
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <ctype.h>
#include <errno.h>
#include <unistd.h>
#ifdef  HAVE_DOSISH_SYSTEM
# define WIN32_LEAN_AND_MEAN  /* We only need the OS core stuff.  */
# include <windows.h>
#else
# include <sys/types.h>
# include <sys/stat.h>
# include <sys/utsname.h>
#endif
#include <sys/types.h>
#include <sys/time.h>
#include <sys/stat.h>
#include <fcntl.h>
#ifdef HAVE_SIGNAL_H
# include <signal.h>
#endif
#ifdef DOTLOCK_USE_PTHREAD
# include <pthread.h>
#endif

#ifdef DOTLOCK_GLIB_LOGGING
# include <glib.h>
#endif

#ifdef GNUPG_MAJOR_VERSION
# include "libjnlib-config.h"
#endif
#ifdef HAVE_W32CE_SYSTEM
# include "utf8conv.h"  /* WindowsCE requires filename conversion.  */
#endif

#include "dotlock.h"


/* Define constants for file name construction.  */
#if !defined(DIRSEP_C) && !defined(EXTSEP_S)
# ifdef HAVE_DOSISH_SYSTEM
#  define DIRSEP_C '\\'
#  define EXTSEP_S "."
#else
#  define DIRSEP_C '/'
#  define EXTSEP_S "."
# endif
#endif

/* In GnuPG we use wrappers around the malloc fucntions.  If they are
   not defined we assume that this code is used outside of GnuPG and
   fall back to the regular malloc functions.  */
#ifndef jnlib_malloc
# define jnlib_malloc(a)     malloc ((a))
# define jnlib_calloc(a,b)   calloc ((a), (b))
# define jnlib_free(a)	     free ((a))
#endif

/* Wrapper to set ERRNO.  */
#ifndef jnlib_set_errno
# ifdef HAVE_W32CE_SYSTEM
#  define jnlib_set_errno(e)  gpg_err_set_errno ((e))
# else
#  define jnlib_set_errno(e)  do { errno = (e); } while (0)
# endif
#endif

/* Gettext macro replacement.  */
#ifndef _
# define _(a) (a)
#endif

#ifdef GNUPG_MAJOR_VERSION
# define my_info_0(a)       log_info ((a))
# define my_info_1(a,b)     log_info ((a), (b))
# define my_info_2(a,b,c)   log_info ((a), (b), (c))
# define my_info_3(a,b,c,d) log_info ((a), (b), (c), (d))
# define my_error_0(a)      log_error ((a))
# define my_error_1(a,b)    log_error ((a), (b))
# define my_error_2(a,b,c)  log_error ((a), (b), (c))
# define my_debug_1(a,b)    log_debug ((a), (b))
# define my_fatal_0(a)      log_fatal ((a))
#elif defined (DOTLOCK_GLIB_LOGGING)
# define my_info_0(a)       g_message ((a))
# define my_info_1(a,b)     g_message ((a), (b))
# define my_info_2(a,b,c)   g_message ((a), (b), (c))
# define my_info_3(a,b,c,d) g_message ((a), (b), (c), (d))
# define my_error_0(a)      g_warning ((a))
# define my_error_1(a,b)    g_warning ((a), (b))
# define my_error_2(a,b,c)  g_warning ((a), (b), (c))
# define my_debug_1(a,b)    g_debug ((a), (b))
# define my_fatal_0(a)      g_error ((a))
#else
# define my_info_0(a)       fprintf (stderr, (a))
# define my_info_1(a,b)     fprintf (stderr, (a), (b))
# define my_info_2(a,b,c)   fprintf (stderr, (a), (b), (c))
# define my_info_3(a,b,c,d) fprintf (stderr, (a), (b), (c), (d))
# define my_error_0(a)      fprintf (stderr, (a))
# define my_error_1(a,b)    fprintf (stderr, (a), (b))
# define my_error_2(a,b,c)  fprintf (stderr, (a), (b), (c))
# define my_debug_1(a,b)    fprintf (stderr, (a), (b))
# define my_fatal_0(a)      do { fprintf (stderr,(a)); fflush (stderr); \
                                 abort (); } while (0)
#endif





/* The object describing a lock.  */
struct dotlock_handle
{
  struct dotlock_handle *next;
  char *lockname;            /* Name of the actual lockfile.          */
  unsigned int locked:1;     /* Lock status.                          */
  unsigned int disable:1;    /* If true, locking is disabled.         */
  unsigned int use_o_excl:1; /* Use open (O_EXCL) for locking.        */

  int extra_fd;              /* A place for the caller to store an FD.  */

#ifdef HAVE_DOSISH_SYSTEM
  HANDLE lockhd;       /* The W32 handle of the lock file.      */
#else /*!HAVE_DOSISH_SYSTEM */
  char *tname;         /* Name of the lockfile template.        */
  size_t nodename_off; /* Offset in TNAME of the nodename part. */
  size_t nodename_len; /* Length of the nodename part.          */
#endif /*!HAVE_DOSISH_SYSTEM */
};


/* A list of of all lock handles.  The volatile attribute might help
   if used in an atexit handler.  */
static volatile dotlock_t all_lockfiles;
#ifdef DOTLOCK_USE_PTHREAD
static pthread_mutex_t all_lockfiles_mutex = PTHREAD_MUTEX_INITIALIZER;
# define LOCK_all_lockfiles() do {                               \
        if (pthread_mutex_lock (&all_lockfiles_mutex))           \
          my_fatal_0 ("locking all_lockfiles_mutex failed\n");   \
      } while (0)
# define UNLOCK_all_lockfiles() do {                             \
        if (pthread_mutex_unlock (&all_lockfiles_mutex))         \
          my_fatal_0 ("unlocking all_lockfiles_mutex failed\n"); \
      } while (0)
#else  /*!DOTLOCK_USE_PTHREAD*/
# define LOCK_all_lockfiles()   do { } while (0)
# define UNLOCK_all_lockfiles() do { } while (0)
#endif /*!DOTLOCK_USE_PTHREAD*/

/* If this has the value true all locking is disabled.  */
static int never_lock;





/* Entirely disable all locking.  This function should be called
   before any locking is done.  It may be called right at startup of
   the process as it only sets a global value.  */
void
dotlock_disable (void)
{
  never_lock = 1;
}


#ifdef HAVE_POSIX_SYSTEM
static int
maybe_deadlock (dotlock_t h)
{
  dotlock_t r;
  int res = 0;

  LOCK_all_lockfiles ();
  for (r=all_lockfiles; r; r = r->next)
    {
      if ( r != h && r->locked )
        {
          res = 1;
          break;
        }
    }
  UNLOCK_all_lockfiles ();
  return res;
}
#endif /*HAVE_POSIX_SYSTEM*/


/* Read the lock file and return the pid, returns -1 on error.  True
   will be stored in the integer at address SAME_NODE if the lock file
   has been created on the same node. */
#ifdef HAVE_POSIX_SYSTEM
static int
read_lockfile (dotlock_t h, int *same_node )
{
  char buffer_space[10+1+70+1]; /* 70 is just an estimated value; node
                                   names are usually shorter. */
  int fd;
  int pid = -1;
  char *buffer, *p;
  size_t expected_len;
  int res, nread;

  *same_node = 0;
  expected_len = 10 + 1 + h->nodename_len + 1;
  if ( expected_len >= sizeof buffer_space)
    {
      buffer = jnlib_malloc (expected_len);
      if (!buffer)
        return -1;
    }
  else
    buffer = buffer_space;

  if ( (fd = open (h->lockname, O_RDONLY)) == -1 )
    {
      int e = errno;
      my_info_2 ("error opening lockfile `%s': %s\n",
                 h->lockname, strerror(errno) );
      if (buffer != buffer_space)
        jnlib_free (buffer);
      jnlib_set_errno (e); /* Need to return ERRNO here. */
      return -1;
    }

  p = buffer;
  nread = 0;
  do
    {
      res = read (fd, p, expected_len - nread);
      if (res == -1 && errno == EINTR)
        continue;
      if (res < 0)
        {
          my_info_1 ("error reading lockfile `%s'\n", h->lockname );
          close (fd);
          if (buffer != buffer_space)
            jnlib_free (buffer);
          jnlib_set_errno (0); /* Do not return an inappropriate ERRNO. */
          return -1;
        }
      p += res;
      nread += res;
    }
  while (res && nread != expected_len);
  close(fd);

  if (nread < 11)
    {
      my_info_1 ("invalid size of lockfile `%s'\n", h->lockname);
      if (buffer != buffer_space)
        jnlib_free (buffer);
      jnlib_set_errno (0); /* Better don't return an inappropriate ERRNO. */
      return -1;
    }

  if (buffer[10] != '\n'
      || (buffer[10] = 0, pid = atoi (buffer)) == -1
      || !pid )
    {
      my_error_2 ("invalid pid %d in lockfile `%s'\n", pid, h->lockname);
      if (buffer != buffer_space)
        jnlib_free (buffer);
      jnlib_set_errno (0);
      return -1;
    }

  if (nread == expected_len
      && !memcmp (h->tname+h->nodename_off, buffer+11, h->nodename_len)
      && buffer[11+h->nodename_len] == '\n')
    *same_node = 1;

  if (buffer != buffer_space)
    jnlib_free (buffer);
  return pid;
}
#endif /*HAVE_POSIX_SYSTEM */


/* Check whether the file system which stores TNAME supports
   hardlinks.  Instead of using the non-portable statsfs call which
   differs between various Unix versions, we do a runtime test.
   Returns: 0 supports hardlinks; 1 no hardlink support, -1 unknown
   (test error).  */
#ifdef HAVE_POSIX_SYSTEM
static int
use_hardlinks_p (const char *tname)
{
  char *lname;
  struct stat sb;
  unsigned int nlink;
  int res;

  if (stat (tname, &sb))
    return -1;
  nlink = (unsigned int)sb.st_nlink;

  lname = jnlib_malloc (strlen (tname) + 1 + 1);
  if (!lname)
    return -1;
  strcpy (lname, tname);
  strcat (lname, "x");

  link (tname, lname);

  if (stat (tname, &sb))
    res = -1;  /* Ooops.  */
  else if (sb.st_nlink == nlink + 1)
    res = 0;   /* Yeah, hardlinks are supported.  */
  else
    res = 1;   /* No hardlink support.  */

  unlink (lname);
  jnlib_free (lname);
  return res;
}
#endif /*HAVE_POSIX_SYSTEM */



#ifdef  HAVE_POSIX_SYSTEM
/* Locking core for Unix.  It used a temporary file and the link
   system call to make locking an atomic operation. */
static dotlock_t
dotlock_create_unix (dotlock_t h, const char *file_to_lock)
{
  int  fd = -1;
  char pidstr[16];
  const char *nodename;
  const char *dirpart;
  int dirpartlen;
  struct utsname utsbuf;
  size_t tnamelen;

  snprintf (pidstr, sizeof pidstr, "%10d\n", (int)getpid() );

  /* Create a temporary file. */
  if ( uname ( &utsbuf ) )
    nodename = "unknown";
  else
    nodename = utsbuf.nodename;

  if ( !(dirpart = strrchr (file_to_lock, DIRSEP_C)) )
    {
      dirpart = EXTSEP_S;
      dirpartlen = 1;
    }
  else
    {
      dirpartlen = dirpart - file_to_lock;
      dirpart = file_to_lock;
    }

  LOCK_all_lockfiles ();
  h->next = all_lockfiles;
  all_lockfiles = h;

  tnamelen = dirpartlen + 6 + 30 + strlen(nodename) + 10 + 1;
  h->tname = jnlib_malloc (tnamelen + 1);
  if (!h->tname)
    {
      all_lockfiles = h->next;
      UNLOCK_all_lockfiles ();
      jnlib_free (h);
      return NULL;
    }
  h->nodename_len = strlen (nodename);

  snprintf (h->tname, tnamelen, "%.*s/.#lk%p.", dirpartlen, dirpart, h );
  h->nodename_off = strlen (h->tname);
  snprintf (h->tname+h->nodename_off, tnamelen - h->nodename_off,
           "%s.%d", nodename, (int)getpid ());

  do
    {
      jnlib_set_errno (0);
      fd = open (h->tname, O_WRONLY|O_CREAT|O_EXCL,
                 S_IRUSR|S_IRGRP|S_IROTH|S_IWUSR );
    }
  while (fd == -1 && errno == EINTR);

  if ( fd == -1 )
    {
      all_lockfiles = h->next;
      UNLOCK_all_lockfiles ();
      my_error_2 (_("failed to create temporary file `%s': %s\n"),
                  h->tname, strerror(errno));
      jnlib_free (h->tname);
      jnlib_free (h);
      return NULL;
    }
  if ( write (fd, pidstr, 11 ) != 11 )
    goto write_failed;
  if ( write (fd, nodename, strlen (nodename) ) != strlen (nodename) )
    goto write_failed;
  if ( write (fd, "\n", 1 ) != 1 )
    goto write_failed;
  if ( close (fd) )
    goto write_failed;

  /* Check whether we support hard links.  */
  switch (use_hardlinks_p (h->tname))
    {
    case 0: /* Yes.  */
      break;
    case 1: /* No.  */
      unlink (h->tname);
      h->use_o_excl = 1;
      break;
    default:
      my_error_2 ("can't check whether hardlinks are supported for `%s': %s\n",
                  h->tname, strerror(errno));
      goto write_failed;
    }

  h->lockname = jnlib_malloc (strlen (file_to_lock) + 6 );
  if (!h->lockname)
    {
      all_lockfiles = h->next;
      UNLOCK_all_lockfiles ();
      unlink (h->tname);
      jnlib_free (h->tname);
      jnlib_free (h);
      return NULL;
    }
  strcpy (stpcpy (h->lockname, file_to_lock), EXTSEP_S "lock");
  UNLOCK_all_lockfiles ();
  if (h->use_o_excl)
    my_debug_1 ("locking for `%s' done via O_EXCL\n", h->lockname);

  return h;

 write_failed:
  all_lockfiles = h->next;
  UNLOCK_all_lockfiles ();
  my_error_2 (_("error writing to `%s': %s\n"), h->tname, strerror (errno));
  close (fd);
  unlink (h->tname);
  jnlib_free (h->tname);
  jnlib_free (h);
  return NULL;
}
#endif /*HAVE_POSIX_SYSTEM*/


#ifdef HAVE_DOSISH_SYSTEM
/* Locking core for Windows.  This version does not need a temporary
   file but uses the plain lock file along with record locking.  We
   create this file here so that we later only need to do the file
   locking.  For error reporting it is useful to keep the name of the
   file in the handle.  */
static dotlock_t
dotlock_create_w32 (dotlock_t h, const char *file_to_lock)
{
  LOCK_all_lockfiles ();
  h->next = all_lockfiles;
  all_lockfiles = h;

  h->lockname = jnlib_malloc ( strlen (file_to_lock) + 6 );
  if (!h->lockname)
    {
      all_lockfiles = h->next;
      UNLOCK_all_lockfiles ();
      jnlib_free (h);
      return NULL;
    }
  strcpy (stpcpy(h->lockname, file_to_lock), EXTSEP_S "lock");

  /* If would be nice if we would use the FILE_FLAG_DELETE_ON_CLOSE
     along with FILE_SHARE_DELETE but that does not work due to a race
     condition: Despite the OPEN_ALWAYS flag CreateFile may return an
     error and we can't reliable create/open the lock file unless we
     would wait here until it works - however there are other valid
     reasons why a lock file can't be created and thus the process
     would not stop as expected but spin until Windows crashes.  Our
     solution is to keep the lock file open; that does not harm. */
  {
#ifdef HAVE_W32CE_SYSTEM
    wchar_t *wname = utf8_to_wchar (h->lockname);

    if (wname)
      h->lockhd = CreateFile (wname,
                              GENERIC_READ|GENERIC_WRITE,
                              FILE_SHARE_READ|FILE_SHARE_WRITE,
                              NULL, OPEN_ALWAYS, 0, NULL);
    else
      h->lockhd = INVALID_HANDLE_VALUE;
    jnlib_free (wname);
#else
    h->lockhd = CreateFile (h->lockname,
                            GENERIC_READ|GENERIC_WRITE,
                            FILE_SHARE_READ|FILE_SHARE_WRITE,
                            NULL, OPEN_ALWAYS, 0, NULL);
#endif
  }
  if (h->lockhd == INVALID_HANDLE_VALUE)
    {
      all_lockfiles = h->next;
      UNLOCK_all_lockfiles ();
      my_error_2 (_("can't create `%s': %s\n"), h->lockname, w32_strerror (-1));
      jnlib_free (h->lockname);
      jnlib_free (h);
      return NULL;
    }
  return h;
}
#endif /*HAVE_DOSISH_SYSTEM*/


/* Create a lockfile for a file name FILE_TO_LOCK and returns an
   object of type dotlock_t which may be used later to actually acquire
   the lock.  A cleanup routine gets installed to cleanup left over
   locks or other files used internally by the lock mechanism.

   Calling this function with NULL does only install the atexit
   handler and may thus be used to assure that the cleanup is called
   after all other atexit handlers.

   This function creates a lock file in the same directory as
   FILE_TO_LOCK using that name and a suffix of ".lock".  Note that on
   POSIX systems a temporary file ".#lk.<hostname>.pid[.threadid] is
   used.

   FLAGS must be 0.

   The function returns an new handle which needs to be released using
   destroy_dotlock but gets also released at the termination of the
   process.  On error NULL is returned.
 */

dotlock_t
dotlock_create (const char *file_to_lock, unsigned int flags)
{
  static int initialized;
  dotlock_t h;

  if ( !initialized )
    {
      atexit (dotlock_remove_lockfiles);
      initialized = 1;
    }

  if ( !file_to_lock )
    return NULL;  /* Only initialization was requested.  */

  if (flags)
    {
      jnlib_set_errno (EINVAL);
      return NULL;
    }

  h = jnlib_calloc (1, sizeof *h);
  if (!h)
    return NULL;
  h->extra_fd = -1;

  if (never_lock)
    {
      h->disable = 1;
      LOCK_all_lockfiles ();
      h->next = all_lockfiles;
      all_lockfiles = h;
      UNLOCK_all_lockfiles ();
      return h;
    }

#ifdef HAVE_DOSISH_SYSTEM
  return dotlock_create_w32 (h, file_to_lock);
#else /*!HAVE_DOSISH_SYSTEM */
  return dotlock_create_unix (h, file_to_lock);
#endif /*!HAVE_DOSISH_SYSTEM*/
}



/* Convenience function to store a file descriptor (or any any other
   integer value) in the context of handle H.  */
void
dotlock_set_fd (dotlock_t h, int fd)
{
  h->extra_fd = fd;
}

/* Convenience function to retrieve a file descriptor (or any any other
   integer value) stored in the context of handle H.  */
int
dotlock_get_fd (dotlock_t h)
{
  return h->extra_fd;
}



#ifdef HAVE_POSIX_SYSTEM
/* Unix specific code of destroy_dotlock.  */
static void
dotlock_destroy_unix (dotlock_t h)
{
  if (h->locked && h->lockname)
    unlink (h->lockname);
  if (h->tname && !h->use_o_excl)
    unlink (h->tname);
  jnlib_free (h->tname);
}
#endif /*HAVE_POSIX_SYSTEM*/


#ifdef HAVE_DOSISH_SYSTEM
/* Windows specific code of destroy_dotlock.  */
static void
dotlock_destroy_w32 (dotlock_t h)
{
  if (h->locked)
    {
      OVERLAPPED ovl;

      memset (&ovl, 0, sizeof ovl);
      UnlockFileEx (h->lockhd, 0, 1, 0, &ovl);
    }
  CloseHandle (h->lockhd);
}
#endif /*HAVE_DOSISH_SYSTEM*/


/* Destroy the locck handle H and release the lock.  */
void
dotlock_destroy (dotlock_t h)
{
  dotlock_t hprev, htmp;

  if ( !h )
    return;

  /* First remove the handle from our global list of all locks. */
  LOCK_all_lockfiles ();
  for (hprev=NULL, htmp=all_lockfiles; htmp; hprev=htmp, htmp=htmp->next)
    if (htmp == h)
      {
        if (hprev)
          hprev->next = htmp->next;
        else
          all_lockfiles = htmp->next;
        h->next = NULL;
        break;
      }
  UNLOCK_all_lockfiles ();

  /* Then destroy the lock. */
  if (!h->disable)
    {
#ifdef HAVE_DOSISH_SYSTEM
      dotlock_destroy_w32 (h);
#else /* !HAVE_DOSISH_SYSTEM */
      dotlock_destroy_unix (h);
#endif /* HAVE_DOSISH_SYSTEM */
      jnlib_free (h->lockname);
    }
  jnlib_free(h);
}



#ifdef HAVE_POSIX_SYSTEM
/* Unix specific code of make_dotlock.  Returns 0 on success and -1 on
   error.  */
static int
dotlock_take_unix (dotlock_t h, long timeout)
{
  int wtime = 0;
  int sumtime = 0;
  int pid;
  int lastpid = -1;
  int ownerchanged;
  const char *maybe_dead="";
  int same_node;

 again:
  if (h->use_o_excl)
    {
      /* No hardlink support - use open(O_EXCL).  */
      int fd;

      do
        {
          jnlib_set_errno (0);
          fd = open (h->lockname, O_WRONLY|O_CREAT|O_EXCL,
                     S_IRUSR|S_IRGRP|S_IROTH|S_IWUSR );
        }
      while (fd == -1 && errno == EINTR);

      if (fd == -1 && errno == EEXIST)
        ; /* Lock held by another process.  */
      else if (fd == -1)
        {
          my_error_2 ("lock not made: open(O_EXCL) of `%s' failed: %s\n",
                      h->lockname, strerror (errno));
          return -1;
        }
      else
        {
          char pidstr[16];

          snprintf (pidstr, sizeof pidstr, "%10d\n", (int)getpid());
          if (write (fd, pidstr, 11 ) == 11
              && write (fd, h->tname + h->nodename_off,h->nodename_len)
              == h->nodename_len
              && write (fd, "\n", 1) == 1
              && !close (fd))
            {
              h->locked = 1;
              return 0;
            }
          /* Write error.  */
          my_error_2 ("lock not made: writing to `%s' failed: %s\n",
                      h->lockname, strerror (errno));
          close (fd);
          unlink (h->lockname);
          return -1;
        }
    }
  else /* Standard method:  Use hardlinks.  */
    {
      struct stat sb;

      link (h->tname, h->lockname);

      if (stat (h->tname, &sb))
        {
          my_error_1 ("lock not made: Oops: stat of tmp file failed: %s\n",
                      strerror (errno));
          /* In theory this might be a severe error: It is possible
             that link succeeded but stat failed due to changed
             permissions.  We can't do anything about it, though.  */
          return -1;
        }

      if (sb.st_nlink == 2)
        {
          h->locked = 1;
          return 0; /* Okay.  */
        }
    }

  /* Check for stale lock files.  */
  if ( (pid = read_lockfile (h, &same_node)) == -1 )
    {
      if ( errno != ENOENT )
        {
          my_info_0 ("cannot read lockfile\n");
          return -1;
        }
      my_info_0 ("lockfile disappeared\n");
      goto again;
    }
  else if ( pid == getpid() && same_node )
    {
      my_info_0 ("Oops: lock already held by us\n");
      h->locked = 1;
      return 0; /* okay */
    }
  else if ( same_node && kill (pid, 0) && errno == ESRCH )
    {
      /* Note: It is unlikley that we get a race here unless a pid is
         reused too fast or a new process with the same pid as the one
         of the stale file tries to lock right at the same time as we.  */
      my_info_1 (_("removing stale lockfile (created by %d)\n"), pid);
      unlink (h->lockname);
      goto again;
    }

  if (lastpid == -1)
    lastpid = pid;
  ownerchanged = (pid != lastpid);

  if (timeout)
    {
      struct timeval tv;

      /* Wait until lock has been released.  We use increasing retry
         intervals of 50ms, 100ms, 200ms, 400ms, 800ms, 2s, 4s and 8s
         but reset it if the lock owner meanwhile changed.  */
      if (!wtime || ownerchanged)
        wtime = 50;
      else if (wtime < 800)
        wtime *= 2;
      else if (wtime == 800)
        wtime = 2000;
      else if (wtime < 8000)
        wtime *= 2;

      if (timeout > 0)
        {
          if (wtime > timeout)
            wtime = timeout;
          timeout -= wtime;
        }

      sumtime += wtime;
      if (sumtime >= 1500)
        {
          sumtime = 0;
          my_info_3 (_("waiting for lock (held by %d%s) %s...\n"),
                     pid, maybe_dead, maybe_deadlock(h)? _("(deadlock?) "):"");
        }


      tv.tv_sec = wtime / 1000;
      tv.tv_usec = (wtime % 1000) * 1000;
      select (0, NULL, NULL, NULL, &tv);
      goto again;
    }

  jnlib_set_errno (EACCES);
  return -1;
}
#endif /*HAVE_POSIX_SYSTEM*/


#ifdef HAVE_DOSISH_SYSTEM
/* Windows specific code of make_dotlock.  Returns 0 on success and -1 on
   error.  */
static int
dotlock_take_w32 (dotlock_t h, long timeout)
{
  int wtime = 0;
  int w32err;
  OVERLAPPED ovl;

 again:
  /* Lock one byte at offset 0.  The offset is given by OVL.  */
  memset (&ovl, 0, sizeof ovl);
  if (LockFileEx (h->lockhd, (LOCKFILE_EXCLUSIVE_LOCK
                              | LOCKFILE_FAIL_IMMEDIATELY), 0, 1, 0, &ovl))
    {
      h->locked = 1;
      return 0; /* okay */
    }

  w32err = GetLastError ();
  if (w32err != ERROR_LOCK_VIOLATION)
    {
      my_error_2 (_("lock `%s' not made: %s\n"),
                  h->lockname, w32_strerror (w32err));
      return -1;
    }

  if (timeout)
    {
      /* Wait until lock has been released.  We use retry intervals of
         50ms, 100ms, 200ms, 400ms, 800ms, 2s, 4s and 8s.  */
      if (!wtime)
        wtime = 50;
      else if (wtime < 800)
        wtime *= 2;
      else if (wtime == 800)
        wtime = 2000;
      else if (wtime < 8000)
        wtime *= 2;

      if (timeout > 0)
        {
          if (wtime > timeout)
            wtime = timeout;
          timeout -= wtime;
        }

      if (wtime >= 800)
        my_info_1 (_("waiting for lock %s...\n"), h->lockname);

      Sleep (wtime);
      goto again;
    }

  return -1;
}
#endif /*HAVE_DOSISH_SYSTEM*/


/* Take a lock on H.  A value of 0 for TIMEOUT returns immediately if
   the lock can't be taked, -1 waits forever (hopefully not), other
   values wait for TIMEOUT milliseconds.  Returns: 0 on success  */
int
dotlock_take (dotlock_t h, long timeout)
{
  int ret;

  if ( h->disable )
    return 0; /* Locks are completely disabled.  Return success. */

  if ( h->locked )
    {
      my_debug_1 ("Oops, `%s' is already locked\n", h->lockname);
      return 0;
    }

#ifdef HAVE_DOSISH_SYSTEM
  ret = dotlock_take_w32 (h, timeout);
#else /*!HAVE_DOSISH_SYSTEM*/
  ret = dotlock_take_unix (h, timeout);
#endif /*!HAVE_DOSISH_SYSTEM*/

  return ret;
}



#ifdef HAVE_POSIX_SYSTEM
/* Unix specific code of release_dotlock.  */
static int
dotlock_release_unix (dotlock_t h)
{
  int pid, same_node;

  pid = read_lockfile (h, &same_node);
  if ( pid == -1 )
    {
      my_error_0 ("release_dotlock: lockfile error\n");
      return -1;
    }
  if ( pid != getpid() || !same_node )
    {
      my_error_1 ("release_dotlock: not our lock (pid=%d)\n", pid);
      return -1;
    }

  if ( unlink( h->lockname ) )
    {
      my_error_1 ("release_dotlock: error removing lockfile `%s'\n",
                  h->lockname);
      return -1;
    }
  /* Fixme: As an extra check we could check whether the link count is
     now really at 1. */
  return 0;
}
#endif /*HAVE_POSIX_SYSTEM */


#ifdef HAVE_DOSISH_SYSTEM
/* Windows specific code of release_dotlock.  */
static int
dotlock_release_w32 (dotlock_t h)
{
  OVERLAPPED ovl;

  memset (&ovl, 0, sizeof ovl);
  if (!UnlockFileEx (h->lockhd, 0, 1, 0, &ovl))
    {
      my_error_2 ("release_dotlock: error removing lockfile `%s': %s\n",
                  h->lockname, w32_strerror (-1));
      return -1;
    }

  return 0;
}
#endif /*HAVE_DOSISH_SYSTEM */


/* Release a lock.  Returns 0 on success.  */
int
dotlock_release (dotlock_t h)
{
  int ret;

  /* To avoid atexit race conditions we first check whether there are
     any locks left.  It might happen that another atexit handler
     tries to release the lock while the atexit handler of this module
     already ran and thus H is undefined.  */
  LOCK_all_lockfiles ();
  ret = !all_lockfiles;
  UNLOCK_all_lockfiles ();
  if (ret)
    return 0;

  if ( h->disable )
    return 0;

  if ( !h->locked )
    {
      my_debug_1 ("Oops, `%s' is not locked\n", h->lockname);
      return 0;
    }

#ifdef HAVE_DOSISH_SYSTEM
  ret = dotlock_release_w32 (h);
#else
  ret = dotlock_release_unix (h);
#endif

  if (!ret)
    h->locked = 0;
  return ret;
}



/* Remove all lockfiles.  This is called by the atexit handler
   installed by this module but may also be called by other
   termination handlers.  */
void
dotlock_remove_lockfiles (void)
{
  dotlock_t h, h2;

  /* First set the lockfiles list to NULL so that for example
     dotlock_release is ware that this fucntion is currently
     running.  */
  LOCK_all_lockfiles ();
  h = all_lockfiles;
  all_lockfiles = NULL;
  UNLOCK_all_lockfiles ();

  while ( h )
    {
      h2 = h->next;
      dotlock_destroy (h);
      h = h2;
    }
}
