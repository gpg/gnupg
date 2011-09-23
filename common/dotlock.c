/* dotlock.c - dotfile locking
 * Copyright (C) 1998, 2000, 2001, 2003, 2004,
 *               2005, 2006, 2008, 2010, 2011 Free Software Foundation, Inc.
 *
 * This file is part of JNLIB, which is a subsystem of GnuPG.
 *
 * JNLIB is free software; you can redistribute it and/or modify it
 * under the terms of the GNU Lesser General Public License as
 * published by the Free Software Foundation; either version 3 of
 * the License, or (at your option) any later version.
 *
 * JNLIB is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this program; if not, see <http://www.gnu.org/licenses/>.
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


/* Standard headers.  */
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <ctype.h>
#include <errno.h>
#include <unistd.h>
#ifdef  HAVE_DOSISH_SYSTEM
# define WIN32_LEAN_AND_MEAN  /* We only need the OS core stuff.  */
# include <windows.h>
#else
# include <sys/utsname.h>
#endif
#include <sys/types.h>
#include <sys/time.h>
#include <sys/stat.h>
#include <fcntl.h>
#ifdef HAVE_SIGNAL_H
# include <signal.h>
#endif


#include "libjnlib-config.h"
#include "stringhelp.h"
#include "dotlock.h"
#ifdef HAVE_W32CE_SYSTEM
# include "utf8conv.h"  /* WindowsCE requires filename conversion.  */
#endif


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



/* The object describing a lock.  */
struct dotlock_handle
{
  struct dotlock_handle *next;
  char *lockname;      /* Name of the actual lockfile.          */
  int locked;          /* Lock status.                          */
  int disable;         /* If true, locking is disabled.         */

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

  for ( r=all_lockfiles; r; r = r->next )
    {
      if ( r != h && r->locked )
        return 1;
    }
  return 0;
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
      log_info ("error opening lockfile `%s': %s\n",
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
          log_info ("error reading lockfile `%s'", h->lockname );
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
      log_info ("invalid size of lockfile `%s'", h->lockname );
      if (buffer != buffer_space)
        jnlib_free (buffer);
      jnlib_set_errno (0); /* Better don't return an inappropriate ERRNO. */
      return -1;
    }

  if (buffer[10] != '\n'
      || (buffer[10] = 0, pid = atoi (buffer)) == -1
      || !pid )
    {
      log_error ("invalid pid %d in lockfile `%s'", pid, h->lockname );
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

#ifdef _REENTRANT
    /* fixme: aquire mutex on all_lockfiles */
#endif
  h->next = all_lockfiles;
  all_lockfiles = h;

  tnamelen = dirpartlen + 6 + 30 + strlen(nodename) + 10;
  h->tname = jnlib_malloc (tnamelen + 1);
  if (!h->tname)
    {
      all_lockfiles = h->next;
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
      log_error (_("failed to create temporary file `%s': %s\n"),
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

# ifdef _REENTRANT
  /* release mutex */
# endif
  h->lockname = jnlib_malloc ( strlen (file_to_lock) + 6 );
  if (!h->lockname)
    {
      all_lockfiles = h->next;
      unlink (h->tname);
      jnlib_free (h->tname);
      jnlib_free (h);
      return NULL;
    }
  strcpy (stpcpy (h->lockname, file_to_lock), EXTSEP_S "lock");
  return h;

 write_failed:
  all_lockfiles = h->next;
# ifdef _REENTRANT
  /* fixme: release mutex */
# endif
  log_error ( _("error writing to `%s': %s\n"), h->tname, strerror(errno) );
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
  h->next = all_lockfiles;
  all_lockfiles = h;

  h->lockname = jnlib_malloc ( strlen (file_to_lock) + 6 );
  if (!h->lockname)
    {
      all_lockfiles = h->next;
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

    h->lockhd = INVALID_HANDLE_VALUE;
    if (wname)
      h->lockhd = CreateFile (wname,
#else
    h->lockhd = CreateFile (h->lockname,
#endif
                            GENERIC_READ|GENERIC_WRITE,
                            FILE_SHARE_READ|FILE_SHARE_WRITE,
                            NULL, OPEN_ALWAYS, 0, NULL);
#ifdef HAVE_W32CE_SYSTEM
    jnlib_free (wname);
#endif
  }
  if (h->lockhd == INVALID_HANDLE_VALUE)
    {
      log_error (_("can't create `%s': %s\n"), h->lockname, w32_strerror (-1));
      all_lockfiles = h->next;
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

   The function returns an new handle which needs to be released using
   destroy_dotlock but gets also released at the termination of the
   process.  On error NULL is returned.
 */
dotlock_t
dotlock_create (const char *file_to_lock)
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

  h = jnlib_calloc (1, sizeof *h);
  if (!h)
    return NULL;

  if (never_lock)
    {
      h->disable = 1;
#ifdef _REENTRANT
      /* fixme: aquire mutex on all_lockfiles */
#endif
      h->next = all_lockfiles;
      all_lockfiles = h;
      return h;
    }

#ifdef HAVE_DOSISH_SYSTEM
  return dotlock_create_w32 (h, file_to_lock);
#else /*!HAVE_DOSISH_SYSTEM */
  return dotlock_create_unix (h, file_to_lock);
#endif /*!HAVE_DOSISH_SYSTEM*/
}



#ifdef HAVE_POSIX_SYSTEM
/* Unix specific code of destroy_dotlock.  */
static void
dotlock_destroy_unix (dotlock_t h)
{
  if (h->locked && h->lockname)
    unlink (h->lockname);
  if (h->tname)
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
/* Unix specific code of make_dotlock.  Returns 0 on success, -1 on
   error and 1 to try again.  */
static int
dotlock_take_unix (dotlock_t h, long timeout, int *backoff)
{
  int  pid;
  const char *maybe_dead="";
  int same_node;

  if ( !link(h->tname, h->lockname) )
    {
      /* fixme: better use stat to check the link count */
      h->locked = 1;
      return 0; /* okay */
    }
  if ( errno != EEXIST )
    {
      log_error ( "lock not made: link() failed: %s\n", strerror(errno) );
      return -1;
    }

  if ( (pid = read_lockfile (h, &same_node)) == -1 )
    {
      if ( errno != ENOENT )
        {
          log_info ("cannot read lockfile\n");
          return -1;
        }
      log_info( "lockfile disappeared\n");
      return 1; /* Try again.  */
    }
  else if ( pid == getpid() && same_node )
    {
      log_info( "Oops: lock already held by us\n");
      h->locked = 1;
      return 0; /* okay */
    }
  else if ( same_node && kill (pid, 0) && errno == ESRCH )
    {
      log_info (_("removing stale lockfile (created by %d)\n"), pid );
      unlink (h->lockname);
      return 1; /* Try again.  */
    }

  if ( timeout == -1 )
    {
      /* Wait until lock has been released. */
      struct timeval tv;

      log_info (_("waiting for lock (held by %d%s) %s...\n"),
                pid, maybe_dead, maybe_deadlock(h)? _("(deadlock?) "):"");

      /* We can't use sleep, cause signals may be blocked. */
      tv.tv_sec = 1 + *backoff;
      tv.tv_usec = 0;
      select (0, NULL, NULL, NULL, &tv);
      if ( *backoff < 10 )
        ++*backoff;
      return 1; /* Try again.  */
    }

  jnlib_set_errno (EACCES);
  return -1;
}
#endif /*HAVE_POSIX_SYSTEM*/


#ifdef HAVE_DOSISH_SYSTEM
/* Windows specific code of make_dotlock.  Returns 0 on success, -1 on
   error and 1 to try again.  */
static int
dotlock_take_w32 (dotlock_t h, long timeout, int *backoff)
{
  int w32err;
  OVERLAPPED ovl;

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
      log_error (_("lock `%s' not made: %s\n"),
                 h->lockname, w32_strerror (w32err));
      return -1;
    }

  if ( timeout == -1 )
    {
      /* Wait until lock has been released. */
      log_info (_("waiting for lock %s...\n"), h->lockname);
      Sleep ((1 + *backoff)*1000);
      if ( *backoff < 10 )
        ++*backoff;
      return 1; /* Try again.  */
    }

  return -1;
}
#endif /*HAVE_DOSISH_SYSTEM*/


/* Take a lock on H.  A value of 0 for TIMEOUT returns immediately if
   the lock can't be taked, -1 waits forever (hopefully not), other
   values are reserved (planned to be timeouts in milliseconds).
   Returns: 0 on success  */
int
dotlock_take (dotlock_t h, long timeout)
{
  int backoff = 0;
  int ret;

  if ( h->disable )
    return 0; /* Locks are completely disabled.  Return success. */

  if ( h->locked )
    {
      log_debug ("Oops, `%s' is already locked\n", h->lockname);
      return 0;
    }

  do
    {
#ifdef HAVE_DOSISH_SYSTEM
      ret = dotlock_take_w32 (h, timeout, &backoff);
#else /*!HAVE_DOSISH_SYSTEM*/
      ret = dotlock_take_unix (h, timeout, &backoff);
#endif /*!HAVE_DOSISH_SYSTEM*/
    }
  while (ret == 1);

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
      log_error( "release_dotlock: lockfile error\n");
      return -1;
    }
  if ( pid != getpid() || !same_node )
    {
      log_error( "release_dotlock: not our lock (pid=%d)\n", pid);
      return -1;
    }

  if ( unlink( h->lockname ) )
    {
      log_error ("release_dotlock: error removing lockfile `%s'\n",
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
      log_error ("release_dotlock: error removing lockfile `%s': %s\n",
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
  if (!all_lockfiles)
    return 0;

  if ( h->disable )
    return 0;

  if ( !h->locked )
    {
      log_debug("Oops, `%s' is not locked\n", h->lockname);
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



/* Remove all lockfiles.  This is usually called by the atexit handler
   installed by this module but may also be called by other
   termination handlers.  */
void
dotlock_remove_lockfiles (void)
{
  dotlock_t h, h2;

  h = all_lockfiles;
  all_lockfiles = NULL;

  while ( h )
    {
      h2 = h->next;
      dotlock_destroy (h);
      h = h2;
    }
}
