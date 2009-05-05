/* dotlock.c - dotfile locking
 * Copyright (C) 1998, 1999, 2000, 2001, 2004,
 *               2005, 2009 Free Software Foundation, Inc.
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
 * along with this program; if not, see <http://www.gnu.org/licenses/>.
 */

#include <config.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <ctype.h>
#include <errno.h>
#include <unistd.h>
#ifdef  HAVE_DOSISH_SYSTEM
# define WIN32_LEAN_AND_MEAN
# include <windows.h>
#else
# include <sys/utsname.h>
#endif
#include <sys/types.h>
#ifndef _WIN32
#include <sys/time.h>
#endif
#include <sys/stat.h>
#include <fcntl.h>
#include <signal.h>
#include "types.h"
#include "util.h"
#include "memory.h"
#include "i18n.h"


/* The object describing a lock.  */
struct dotlock_handle {
    struct dotlock_handle *next;
    char *tname;    /* name of lockfile template */
    char *lockname; /* name of the real lockfile */
    int locked;     /* lock status */
    int disable;    /* locking */
#ifdef HAVE_DOSISH_SYSTEM
    HANDLE lockhd;  /* The W32 handle of the lock file.  */
#else
    size_t nodename_off; /* Offset in TNAME to the nodename part. */
    size_t nodename_len; /* Length of the nodename part.  */
#endif
};


/* A list of of all lock handles. */
static volatile DOTLOCK all_lockfiles;

/* If this has the value true all locking is disabled.  */
static int never_lock;


#ifdef _REENTRANT
 /* fixme: acquire mutex on all_lockfiles */
# define lock_all_lockfiles(h)  do {  } while (0) 
# define unlock_all_lockfiles(h) do {  } while (0)
#else
# define lock_all_lockfiles(h)  do {  } while (0) 
# define unlock_all_lockfiles(h) do {  } while (0)
#endif



void
disable_dotlock(void)
{
  never_lock = 1;
}


/****************
 * Create a lockfile with the given name and return an object of
 * type DOTLOCK which may be used later to actually do the lock.
 * A cleanup routine gets installed to cleanup left over locks
 * or other files used together with the lockmechanism.
 * Althoug the function is called dotlock, this does not necessarily
 * mean that real lockfiles are used - the function may decide to
 * use fcntl locking.  Calling the function with NULL only install
 * the atexit handler and maybe used to assure that the cleanup
 * is called after all other atexit handlers.
 *
 * Notes: This function creates a lock file in the same directory
 *	  as file_to_lock with the name "file_to_lock.lock"
 *	  A temporary file ".#lk.<hostname>.pid[.threadid] is used.
 *	  This function does nothing for Windoze.
 */
DOTLOCK
create_dotlock( const char *file_to_lock )
{
    static int initialized;
    DOTLOCK h;
#ifndef HAVE_DOSISH_SYSTEM
    int fd = -1;
    char pidstr[16];
    struct utsname utsbuf;
    const char *nodename;
    const char *dirpart;
    int dirpartlen;
    size_t tnamelen;
    int n;
#endif /*!HAVE_DOSISH_SYSTEM*/

    if( !initialized ) {
	atexit( remove_lockfiles );
	initialized = 1;
    }
    if( !file_to_lock )
	return NULL;

    h = xmalloc_clear( sizeof *h );
    if( never_lock ) {
	h->disable = 1;
        lock_all_lockfiles (h);
	h->next = all_lockfiles;
	all_lockfiles = h;
	return h;
    }


#ifndef HAVE_DOSISH_SYSTEM
    snprintf (pidstr, sizeof pidstr, "%10d\n", (int)getpid() );

    /* create a temporary file */
    if( uname( &utsbuf ) )
	nodename = "unknown";
    else
	nodename = utsbuf.nodename;

# ifdef __riscos__
    {
        char *iter = (char *) nodename;
        for (; iter[0]; iter++)
            if (iter[0] == '.')
                iter[0] = '/';
    }
# endif /* __riscos__ */

    if( !(dirpart = strrchr( file_to_lock, DIRSEP_C )) ) {
	dirpart = EXTSEP_S;
	dirpartlen = 1;
    }
    else {
	dirpartlen = dirpart - file_to_lock;
	dirpart = file_to_lock;
    }

    lock_all_lockfiles (h);
    h->next = all_lockfiles;
    all_lockfiles = h;

    tnamelen = dirpartlen + 6+30+ strlen(nodename) + 10;
    h->tname = xmalloc (tnamelen + 1);
    h->nodename_len = strlen (nodename);

# ifndef __riscos__
    snprintf (h->tname, tnamelen, "%.*s/.#lk%p.%n%s.%d",
              dirpartlen, dirpart, (void *)h, &n, nodename, (int)getpid ());
# else /* __riscos__ */
    snprintf (h->tname, tnamelen, "%.*s.lk%p/%n%s/%d",
              dirpartlen, dirpart, (void *)h, &n, nodename, (int)getpid ());
# endif /* __riscos__ */
    h->nodename_off = n;

    do {
	errno = 0;
	fd = open (h->tname, O_WRONLY|O_CREAT|O_EXCL,
                   S_IRUSR|S_IRGRP|S_IROTH|S_IWUSR);
    } while( fd == -1 && errno == EINTR );
    if( fd == -1 ) {
	all_lockfiles = h->next;
	log_error( "failed to create temporary file `%s': %s\n",
					    h->tname, strerror(errno));
	xfree(h->tname);
	xfree(h);
	return NULL;
    }
    if (write (fd, pidstr, 11) != 11) 
      goto write_failed;
    if (write (fd, nodename, strlen (nodename)) != strlen (nodename))
      goto write_failed;
    if (write (fd, "\n", 1 ) != 1)
      goto write_failed;
    if (close (fd))
      goto write_failed;

    unlock_all_lockfiles (h);
    h->lockname = xmalloc( strlen(file_to_lock) + 6 );
    strcpy(stpcpy(h->lockname, file_to_lock), EXTSEP_S "lock");
    return h;

 write_failed:
    all_lockfiles = h->next;
    unlock_all_lockfiles (h);
    log_error ("error writing to `%s': %s\n", h->tname, strerror(errno));
    close (fd);
    unlink (h->tname);
    xfree (h->tname);
    xfree (h);
    return NULL;

#else /* HAVE_DOSISH_SYSTEM */

  /* The Windows version does not need a temporary file but uses the
     plain lock file along with record locking.  We create this file
     here so that we later do only need to do the file locking.  For
     error reporting it is useful to keep the name of the file in the
     handle.  */
  h->next = all_lockfiles;
  all_lockfiles = h;

  h->lockname = xmalloc ( strlen (file_to_lock) + 6 );
  strcpy (stpcpy(h->lockname, file_to_lock), EXTSEP_S "lock");

  /* If would be nice if we would use the FILE_FLAG_DELETE_ON_CLOSE
     along with FILE_SHARE_DELETE but that does not work due to a race
     condition: Despite the OPEN_ALWAYS flag CreateFile may return an
     error and we can't reliable create/open the lock file unless we
     would wait here until it works - however there are other valid
     reasons why a lock file can't be created and thus the process
     would not stop as expected but spin until Windows crashes.  Our
     solution is to keep the lock file open; that does not harm. */ 
  h->lockhd = CreateFile (h->lockname,
                          GENERIC_READ|GENERIC_WRITE,
                          FILE_SHARE_READ|FILE_SHARE_WRITE,
                          NULL, OPEN_ALWAYS, 0, NULL);
  if (h->lockhd == INVALID_HANDLE_VALUE)
    {
      log_error (_("can't create `%s': %s\n"), h->lockname, w32_strerror (-1));
      all_lockfiles = h->next;
      xfree (h->lockname);
      xfree (h);
      return NULL;
    }
  return h;

#endif /* HAVE_DOSISH_SYSTEM */
}


void
destroy_dotlock ( DOTLOCK h )
{
  DOTLOCK hprev, htmp;

  if (!h)
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

  /* Second destroy the lock. */
  if (!h->disable)
    {
#ifdef HAVE_DOSISH_SYSTEM
      if (h->locked)
        UnlockFile (h->lockhd, 0, 0, 1, 0);
      CloseHandle (h->lockhd);
#else
      if (h->locked && h->lockname)
        unlink (h->lockname);
      if (h->tname)
        unlink (h->tname);
      xfree (h->tname);
#endif
      xfree (h->lockname);
    }
  xfree(h);
}


#ifndef HAVE_DOSISH_SYSTEM
static int
maybe_deadlock( DOTLOCK h )
{
    DOTLOCK r;

    for( r=all_lockfiles; r; r = r->next ) {
	if( r != h && r->locked )
	    return 1;
    }
    return 0;
}
#endif /* !HAVE_DOSISH_SYSTEM */


/* Read the lock file and return the pid, returns -1 on error.  True
   will be stored in the integer at address SAME_NODE if the lock file
   has been created on the same node. */
#ifndef HAVE_DOSISH_SYSTEM
static int
read_lockfile (DOTLOCK h, int *same_node )
{
  char buffer_space[10+1+70+1]; /* 70 is just an estimated value; node
                                   names are usually shorter.  */
  int fd;
  int pid = -1;
  char *buffer, *p;
  size_t expected_len;
  int res, nread;
  
  *same_node = 0;
  expected_len = 10 + 1 + h->nodename_len + 1;
  if ( expected_len >= sizeof buffer_space)
    buffer = xmalloc (expected_len);
  else
    buffer = buffer_space;

  if ( (fd = open (h->lockname, O_RDONLY)) == -1 )
    {
      int e = errno;
      log_info ("error opening lockfile `%s': %s\n",
                h->lockname, strerror(errno) );
      if (buffer != buffer_space)
        xfree (buffer);
      errno = e; /* Need to return ERRNO here. */
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
            xfree (buffer);
          errno = 0; /* Do not return an inappropriate ERRNO. */
          return -1;
        }
      p += res;
      nread += res;
    }
  while (res && nread != expected_len);
  close (fd);

  if (nread < 11)
    {
      log_info ("invalid size of lockfile `%s'", h->lockname );
      if (buffer != buffer_space)
        xfree (buffer);
      errno = 0; /* Better don't return an inappropriate ERRNO. */
      return -1;
    }

  if (buffer[10] != '\n'
      || (buffer[10] = 0, pid = atoi (buffer)) == -1
#ifndef __riscos__
      || !pid 
#else /* __riscos__ */
      || (!pid && riscos_getpid())
#endif /* __riscos__ */
      )
    {
      log_error ("invalid pid %d in lockfile `%s'", pid, h->lockname );
      if (buffer != buffer_space)
        xfree (buffer);
      errno = 0;
      return -1;
    }

  if (nread == expected_len
      && !memcmp (h->tname+h->nodename_off, buffer+11, h->nodename_len) 
      && buffer[11+h->nodename_len] == '\n')
    *same_node = 1;

  if (buffer != buffer_space)
    xfree (buffer);
  return pid;
}
#endif /* !HAVE_DOSISH_SYSTEM */


/****************
 * Do a lock on H. A TIMEOUT of 0 returns immediately,
 * -1 waits forever (hopefully not), other
 * values are timeouts in milliseconds.
 * Returns: 0 on success
 */
int
make_dotlock( DOTLOCK h, long timeout )
{
  int backoff=0;
#ifndef HAVE_DOSISH_SYSTEM
  int  pid;
  const char *maybe_dead="";
  int same_node;
#endif  
 
  if (h->disable)
    return 0;

  if (h->locked)
    {
#ifndef __riscos__
      log_debug ("oops, `%s' is already locked\n", h->lockname);
#endif /* !__riscos__ */
      return 0;
    }
  
  for (;;)
    {
#ifndef HAVE_DOSISH_SYSTEM
# ifndef __riscos__
      if( !link(h->tname, h->lockname) )
        {
          /* fixme: better use stat to check the link count */
          h->locked = 1;
          return 0; /* okay */
	}
      if (errno != EEXIST)
        {
          log_error ("lock not made: link() failed: %s\n", strerror(errno));
          return -1;
	}
# else /* __riscos__ */
      if ( !riscos_renamefile(h->tname, h->lockname) )
        {
          h->locked = 1;
          return 0; /* okay */
        }
      if (errno != EEXIST)
        {
          log_error ("lock not made: rename() failed: %s\n", strerror(errno));
          return -1;
        }
# endif /* __riscos__ */

      if ((pid = read_lockfile (h, &same_node)) == -1 )
        {
          if (errno != ENOENT)
            {
              log_info ("cannot read lockfile\n");
              return -1;
	    }
          log_info ("lockfile disappeared\n");
          continue;
	}
      else if (pid == getpid ())
        {
          log_info ("Oops: lock already held by us\n");
          h->locked = 1;
          return 0; /* okay */
	}
      else if (same_node && kill(pid, 0) && errno == ESRCH)
        {
# ifndef __riscos__
          log_info (_("removing stale lockfile (created by %d)\n"), pid );
          unlink (h->lockname);
          continue;
# else /* __riscos__ */
          /* We are *pretty* sure that the other task is dead and
             therefore we remove the other lock file. */
          maybe_dead = " - probably dead - removing lock";
          unlink (h->lockname);
# endif /* __riscos__ */
	}

      if (timeout == -1)
        {
          struct timeval tv;

          log_info ("waiting for lock (held by %d%s) %s...\n",
                    pid, maybe_dead, maybe_deadlock(h)? "(deadlock?) ":"");


	    /* We can't use sleep, because signals may be blocked.  */
	    tv.tv_sec = 1 + backoff;
	    tv.tv_usec = 0;
	    select (0, NULL, NULL, NULL, &tv);
	    if (backoff < 10)
              backoff++ ;
	}
      else
        return -1;

#else /*HAVE_DOSISH_SYSTEM*/
      int w32err;
      
      if (LockFile (h->lockhd, 0, 0, 1, 0))
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
      
      if (timeout == -1) 
        {
          /* Wait until lock has been released. */
          log_info (_("waiting for lock %s...\n"), h->lockname);
          Sleep ((1 + backoff)*1000);
          if ( backoff < 10 )
            backoff++ ;
	}
      else
        return -1;
#endif /*HAVE_DOSISH_SYSTEM*/
    }
  /*NOTREACHED */
}


/****************
 * release a lock
 * Returns: 0 := success
 */
int
release_dotlock (DOTLOCK h)
{
#ifndef HAVE_DOSISH_SYSTEM
  int pid, same_node;
#endif

  /* To avoid atexit race conditions we first check whether there are
     any locks left.  It might happen that another atexit handler
     tries to release the lock while the atexit handler of this module
     already ran and thus H is undefined.  */
  if (!all_lockfiles)
    return 0;

  if (h->disable) 
    return 0;

  if (!h->locked)
    {
      log_debug("oops, `%s' is not locked\n", h->lockname );
      return 0;
    }

#ifndef HAVE_DOSISH_SYSTEM
  pid = read_lockfile (h, &same_node);
  if (pid == -1)
    {
      log_error ("release_dotlock: lockfile error\n");
      return -1;
    }
  if (pid != getpid () || !same_node)
    {
      log_error ("release_dotlock: not our lock (pid=%d)\n", pid);
      return -1;
    }
# ifndef __riscos__
  if (unlink (h->lockname))
    {
      log_error ("release_dotlock: error removing lockfile `%s'",
                 h->lockname);
      return -1;
    }
# else /* __riscos__ */
  if( riscos_renamefile(h->lockname, h->tname) ) 
    {
      log_error( "release_dotlock: error renaming lockfile `%s' to `%s'",
                 h->lockname, h->tname);
      return -1;
    }
# endif /* __riscos__ */

#else /*HAVE_DOSISH_SYSTEM*/

  if (!UnlockFile (h->lockhd, 0, 0, 1, 0))
    {
      log_error ("release_dotlock: error removing lockfile `%s': %s\n",
                 h->lockname, w32_strerror (-1));
      return -1;
    }
#endif /*HAVE_DOSISH_SYSTEM*/

  h->locked = 0;
  return 0;
}


void
remove_lockfiles()
{
#if !defined (HAVE_DOSISH_SYSTEM)
    DOTLOCK h, h2;

    h = all_lockfiles;
    all_lockfiles = NULL;

    while( h ) {
	h2 = h->next;
        destroy_dotlock (h);
	h = h2;
    }
#endif
}
