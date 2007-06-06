/* dotlock.c - dotfile locking
 * Copyright (C) 1998, 2000, 2001, 2003, 2004, 
 *               2005, 2006 Free Software Foundation, Inc.
 *
 * This file is part of JNLIB.
 *
 * JNLIB is free software; you can redistribute it and/or modify it
 * under the terms of the GNU Lesser General Public License as
 * published by the Free Software Foundation; either version 2.1 of
 * the License, or (at your option) any later version.
 *
 * JNLIB is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA
 * 02110-1301, USA.
 */

#include <config.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <ctype.h>
#include <errno.h>
#include <unistd.h>
#ifndef  HAVE_DOSISH_SYSTEM
#include <sys/utsname.h>
#endif
#include <sys/types.h>
#include <sys/time.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <signal.h>

#include "libjnlib-config.h"
#include "stringhelp.h"
#include "dotlock.h"

#if !defined(DIRSEP_C) && !defined(EXTSEP_C) \
    && !defined(DIRSEP_S) && !defined(EXTSEP_S)
#ifdef HAVE_DOSISH_SYSTEM
#define DIRSEP_C '\\'
#define EXTSEP_C '.'
#define DIRSEP_S "\\"
#define EXTSEP_S "."
#else
#define DIRSEP_C '/'
#define EXTSEP_C '.'
#define DIRSEP_S "/"
#define EXTSEP_S "."
#endif
#endif


struct dotlock_handle 
{
  struct dotlock_handle *next;
  char *tname;    /* Name of lockfile template.  */
  size_t nodename_off; /* Offset in TNAME of the nodename part. */
  size_t nodename_len; /* Length of the nodename part. */
  char *lockname; /* Name of the real lockfile.  */
  int locked;     /* Lock status.  */
  int disable;    /* When true, locking is disabled.  */
};


static volatile DOTLOCK all_lockfiles;
static int never_lock;

static int read_lockfile (DOTLOCK h, int *same_node);

void
disable_dotlock(void)
{
  never_lock = 1;
}

/****************
 * Create a lockfile with the given name and return an object of
 * type DOTLOCK which may be used later to actually do the lock.
 * A cleanup routine gets installed to cleanup left over locks
 * or other files used together with the lock mechanism.
 * Although the function is called dotlock, this does not necessarily
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
  int  fd = -1;
  char pidstr[16];
  const char *nodename;
  const char *dirpart;
  int dirpartlen;
#ifndef  HAVE_DOSISH_SYSTEM
  struct utsname utsbuf;
#endif

  if ( !initialized )
    {
      atexit( dotlock_remove_lockfiles );
      initialized = 1;
    }
  if ( !file_to_lock )
    return NULL;  /* Only initialization was requested.  */

  h = jnlib_xcalloc ( 1, sizeof *h );
  if( never_lock )
    {
      h->disable = 1;
#ifdef _REENTRANT
      /* fixme: aquire mutex on all_lockfiles */
#endif
      h->next = all_lockfiles;
      all_lockfiles = h;
      return h;
    }

#ifndef HAVE_DOSISH_SYSTEM
  sprintf (pidstr, "%10d\n", (int)getpid() );
  /* fixme: add the hostname to the second line (FQDN or IP addr?) */

  /* Create a temporary file. */
  if ( uname ( &utsbuf ) )
    nodename = "unknown";
  else
    nodename = utsbuf.nodename;
  
#ifdef __riscos__
  {
    char *iter = (char *) nodename;
    for (; iter[0]; iter++)
      if (iter[0] == '.')
        iter[0] = '/';
  }
#endif /* __riscos__ */

  if ( !(dirpart = strrchr ( file_to_lock, DIRSEP_C )) )
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

  h->tname = jnlib_xmalloc ( dirpartlen + 6+30+ strlen(nodename) + 11 );
  h->nodename_len = strlen (nodename);
#ifndef __riscos__
  sprintf (h->tname, "%.*s/.#lk%p.", dirpartlen, dirpart, h );
  h->nodename_off = strlen (h->tname);
  sprintf (h->tname+h->nodename_off, "%s.%d", nodename, (int)getpid ());
#else /* __riscos__ */
  sprintf (h->tname, "%.*s.lk%p/", dirpartlen, dirpart, h );
  h->nodename_off = strlen (h->tname);
  sprintf (h->tname+h->nodename_off, "%s/%d", nodename, (int)getpid () );
#endif /* __riscos__ */

  do 
    {
      errno = 0;
      fd = open (h->tname, O_WRONLY|O_CREAT|O_EXCL,
                 S_IRUSR|S_IRGRP|S_IROTH|S_IWUSR );
    } 
  while (fd == -1 && errno == EINTR);

  if ( fd == -1 ) 
    {
      all_lockfiles = h->next;
      log_error ( "failed to create temporary file `%s': %s\n",
                  h->tname, strerror(errno));
      jnlib_free(h->tname);
      jnlib_free(h);
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
#endif /* !HAVE_DOSISH_SYSTEM */
  h->lockname = jnlib_xmalloc ( strlen (file_to_lock) + 6 );
  strcpy (stpcpy(h->lockname, file_to_lock), EXTSEP_S "lock");
  return h;
 write_failed:
  all_lockfiles = h->next;
# ifdef _REENTRANT
  /* fixme: release mutex */
# endif
  log_error ( "error writing to `%s': %s\n", h->tname, strerror(errno) );
  close(fd);
  unlink(h->tname);
  jnlib_free(h->tname);
  jnlib_free(h);
  return NULL;
}


void
destroy_dotlock ( DOTLOCK h )
{
#ifndef HAVE_DOSISH_SYSTEM
  if ( h )
    {
      DOTLOCK hprev, htmp;
      
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
          if (h->locked && h->lockname)
            unlink (h->lockname);
          if (h->tname)
              unlink (h->tname);
          jnlib_free (h->tname);
          jnlib_free (h->lockname);
        }
      jnlib_free(h);
    }
#endif /*!HAVE_DOSISH_SYSTEM*/
}



static int
maybe_deadlock( DOTLOCK h )
{
  DOTLOCK r;

  for ( r=all_lockfiles; r; r = r->next )
    {
      if ( r != h && r->locked )
        return 1;
    }
  return 0;
}

/****************
 * Do a lock on H. A TIMEOUT of 0 returns immediately, -1 waits
 * forever (hopefully not), other values are reserved (should then be
 * timeouts in milliseconds).  Returns: 0 on success
 */
int
make_dotlock( DOTLOCK h, long timeout )
{
#ifdef HAVE_DOSISH_SYSTEM
  return 0;
#else
  int  pid;
  const char *maybe_dead="";
  int backoff=0;
  int same_node;

  if ( h->disable )
    return 0; /* Locks are completely disabled.  Return success. */

  if ( h->locked ) 
    {
#ifndef __riscos__
      log_debug("oops, `%s' is already locked\n", h->lockname );
#endif /* !__riscos__ */
      return 0;
    }

  for(;;)
    {
#ifndef __riscos__
      if ( !link(h->tname, h->lockname) )
        {
          /* fixme: better use stat to check the link count */
          h->locked = 1;
          return 0; /* okay */
	}
      if ( errno != EEXIST )
        {
          log_error( "lock not made: link() failed: %s\n", strerror(errno) );
          return -1;
	}
#else /* __riscos__ */
      if ( !renamefile(h->tname, h->lockname) ) 
        {
          h->locked = 1;
          return 0; /* okay */
        }
      if ( errno != EEXIST ) 
        {
          log_error( "lock not made: rename() failed: %s\n", strerror(errno) );
          return -1;
        }
#endif /* __riscos__ */

      if ( (pid = read_lockfile (h, &same_node)) == -1 ) 
        {
          if ( errno != ENOENT )
            {
              log_info ("cannot read lockfile\n");
              return -1;
	    }
          log_info( "lockfile disappeared\n");
          continue;
	}
      else if ( pid == getpid() && same_node )
        {
          log_info( "Oops: lock already held by us\n");
          h->locked = 1;
          return 0; /* okay */
	}
      else if ( same_node && kill (pid, 0) && errno == ESRCH )
        {
#ifndef __riscos__
          log_info ("removing stale lockfile (created by %d)", pid );
          unlink (h->lockname);
          continue;
#else /* __riscos__ */
          /* Under RISCOS we are *pretty* sure that the other task
             is dead and therefore we remove the stale lock file. */
          maybe_dead = " - probably dead - removing lock";
          unlink(h->lockname);
#endif /* __riscos__ */
	}

      if ( timeout == -1 ) 
        {
          /* Wait until lock has been released. */
          struct timeval tv;
          
          log_info ("waiting for lock (held by %d%s) %s...\n",
                    pid, maybe_dead, maybe_deadlock(h)? "(deadlock?) ":"");


          /* We can't use sleep, cause signals may be blocked. */
          tv.tv_sec = 1 + backoff;
          tv.tv_usec = 0;
          select(0, NULL, NULL, NULL, &tv);
          if ( backoff < 10 )
            backoff++ ;
	}
      else
        return -1;
    }
    /*NOTREACHED*/
#endif /* !HAVE_DOSISH_SYSTEM */
}


/****************
 * release a lock
 * Returns: 0 := success
 */
int
release_dotlock( DOTLOCK h )
{
#ifdef HAVE_DOSISH_SYSTEM
  return 0;
#else
  int pid, same_node;

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
      log_debug("oops, `%s' is not locked\n", h->lockname );
      return 0;
    }

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
#ifndef __riscos__
  if ( unlink( h->lockname ) )
    {
      log_error( "release_dotlock: error removing lockfile `%s'",
                 h->lockname);
      return -1;
    }
#else /* __riscos__ */
  if ( renamefile(h->lockname, h->tname) ) 
    {
      log_error( "release_dotlock: error renaming lockfile `%s' to `%s'",
                 h->lockname, h->tname);
      return -1;
    }
#endif /* __riscos__ */
  /* fixme: check that the link count is now 1 */
  h->locked = 0;
  return 0;
#endif /* !HAVE_DOSISH_SYSTEM */
}


/*
   Read the lock file and return the pid, returns -1 on error.  True
   will be stored at SAME_NODE if the lock file has been created on
   the same node.
 */
static int
read_lockfile (DOTLOCK h, int *same_node )
{
#ifdef HAVE_DOSISH_SYSTEM
  return 0;
#else
  char buffer_space[10+1+70+1]; /* 70 is just an estimated value; node
                                   name are usually shorter. */
  int fd, pid;
  char *buffer, *p;
  size_t expected_len;
  int res, nread;
  
  *same_node = 0;
  expected_len = 10 + 1 + h->nodename_len + 1;
  if ( expected_len >= sizeof buffer_space)
    buffer = jnlib_xmalloc (expected_len);
  else
    buffer = buffer_space;

  if ( (fd = open (h->lockname, O_RDONLY)) == -1 )
    {
      int e = errno;
      log_info ("error opening lockfile `%s': %s\n",
                h->lockname, strerror(errno) );
      if (buffer != buffer_space)
        jnlib_free (buffer);
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
            jnlib_free (buffer);
          errno = 0; /* Do not return an inappropriate ERRNO. */
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
      errno = 0; /* Do not return an inappropriate ERRNO. */
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
        jnlib_free (buffer);
      errno = 0;
      return -1;
    }

  if (nread == expected_len
      && !memcmp (h->tname+h->nodename_off, buffer+11, h->nodename_len) 
      && buffer[11+h->nodename_len] == '\n')
    *same_node = 1;

  if (buffer != buffer_space)
    jnlib_free (buffer);
  return pid;
#endif
}


void
dotlock_remove_lockfiles()
{
#ifndef HAVE_DOSISH_SYSTEM
  DOTLOCK h, h2;
  
  h = all_lockfiles;
  all_lockfiles = NULL;
    
  while ( h )
    {
      h2 = h->next;
      destroy_dotlock (h);
      h = h2;
    }
#endif
}

