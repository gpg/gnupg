/* dotlock.c - dotfile locking
 * Copyright (C) 1998, 1999, 2000, 2001, 2004,
 *               2005 Free Software Foundation, Inc.
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
#if !defined (HAVE_DOSISH_SYSTEM)
#include <sys/utsname.h>
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

struct dotlock_handle {
    struct dotlock_handle *next;
    char *tname;    /* name of lockfile template */
    char *lockname; /* name of the real lockfile */
    int locked;     /* lock status */
    int disable;    /* locking */
};


static volatile DOTLOCK all_lockfiles;
static int never_lock;

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
#if !defined (HAVE_DOSISH_SYSTEM)
    int fd = -1;
    char pidstr[16];
    struct utsname utsbuf;
    const char *nodename;
    const char *dirpart;
    int dirpartlen;
#endif

    if( !initialized ) {
	atexit( remove_lockfiles );
	initialized = 1;
    }
    if( !file_to_lock )
	return NULL;

    h = xmalloc_clear( sizeof *h );
    if( never_lock ) {
	h->disable = 1;
#ifdef _REENTRANT
	/* fixme: aquire mutex on all_lockfiles */
#endif
	h->next = all_lockfiles;
	all_lockfiles = h;
	return h;
    }


#if !defined (HAVE_DOSISH_SYSTEM)
    sprintf( pidstr, "%10d\n", (int)getpid() );
    /* fixme: add the hostname to the second line (FQDN or IP addr?) */

    /* create a temporary file */
    if( uname( &utsbuf ) )
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

    if( !(dirpart = strrchr( file_to_lock, DIRSEP_C )) ) {
	dirpart = EXTSEP_S;
	dirpartlen = 1;
    }
    else {
	dirpartlen = dirpart - file_to_lock;
	dirpart = file_to_lock;
    }

#ifdef _REENTRANT
    /* fixme: aquire mutex on all_lockfiles */
#endif
    h->next = all_lockfiles;
    all_lockfiles = h;

    h->tname = xmalloc( dirpartlen + 6+30+ strlen(nodename) + 11 );
#ifndef __riscos__
    sprintf( h->tname, "%.*s/.#lk%p.%s.%d",
	     dirpartlen, dirpart, (void *)h, nodename, (int)getpid() );
#else /* __riscos__ */
    sprintf( h->tname, "%.*s.lk%p/%s/%d",
	     dirpartlen, dirpart, (void *)h, nodename, (int)getpid() );
#endif /* __riscos__ */

    do {
	errno = 0;
	fd = open( h->tname, O_WRONLY|O_CREAT|O_EXCL,
			  S_IRUSR|S_IRGRP|S_IROTH|S_IWUSR );
    } while( fd == -1 && errno == EINTR );
    if( fd == -1 ) {
	all_lockfiles = h->next;
	log_error( "failed to create temporary file `%s': %s\n",
					    h->tname, strerror(errno));
	xfree(h->tname);
	xfree(h);
	return NULL;
    }
    if( write(fd, pidstr, 11 ) != 11 ) {
	all_lockfiles = h->next;
#ifdef _REENTRANT
	/* release mutex */
#endif
	log_fatal( "error writing to `%s': %s\n", h->tname, strerror(errno) );
	close(fd);
	unlink(h->tname);
	xfree(h->tname);
	xfree(h);
	return NULL;
    }
    if( close(fd) ) {
	all_lockfiles = h->next;
#ifdef _REENTRANT
	/* release mutex */
#endif
	log_error( "error closing `%s': %s\n", h->tname, strerror(errno));
	unlink(h->tname);
	xfree(h->tname);
	xfree(h);
	return NULL;
    }

#ifdef _REENTRANT
    /* release mutex */
#endif
#endif
    h->lockname = xmalloc( strlen(file_to_lock) + 6 );
    strcpy(stpcpy(h->lockname, file_to_lock), EXTSEP_S "lock");
    return h;
}


void
destroy_dotlock ( DOTLOCK h )
{
#if !defined (HAVE_DOSISH_SYSTEM)
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
	    xfree (h->tname);
	    xfree (h->lockname);
          }
	xfree(h);

      }
#endif
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

/****************
 * Read the lock file and return the pid, returns -1 on error.
 */
static int
read_lockfile( const char *name )
{
    int fd, pid;
    char pidstr[16];

    if( (fd = open(name, O_RDONLY)) == -1 ) {
	int e = errno;
	log_debug("error opening lockfile `%s': %s\n", name, strerror(errno) );
	errno = e;
	return -1;
    }
    if( read(fd, pidstr, 10 ) != 10 ) {  /* Read 10 digits w/o newline */
	log_debug("error reading lockfile `%s'", name );
	close(fd);
	errno = 0;
	return -1;
    }
    pidstr[10] = 0;  /* terminate pid string */
    close(fd);
    pid = atoi(pidstr);
#ifndef __riscos__
    if( !pid || pid == -1 ) {
#else /* __riscos__ */
    if( (!pid && riscos_getpid()) || pid == -1 ) {
#endif /* __riscos__ */
	log_error("invalid pid %d in lockfile `%s'", pid, name );
	errno = 0;
	return -1;
    }
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
#if defined (HAVE_DOSISH_SYSTEM)
    return 0;
#else
    int  pid;
    const char *maybe_dead="";
    int backoff=0;

    if( h->disable ) {
	return 0;
    }

    if( h->locked ) {
#ifndef __riscos__
	log_debug("oops, `%s' is already locked\n", h->lockname );
#endif /* !__riscos__ */
	return 0;
    }

    for(;;) {
#ifndef __riscos__
	if( !link(h->tname, h->lockname) ) {
	    /* fixme: better use stat to check the link count */
	    h->locked = 1;
	    return 0; /* okay */
	}
	if( errno != EEXIST ) {
	    log_error( "lock not made: link() failed: %s\n", strerror(errno) );
	    return -1;
	}
#else /* __riscos__ */
        if( !riscos_renamefile(h->tname, h->lockname) ) {
            h->locked = 1;
            return 0; /* okay */
        }
        if( errno != EEXIST ) {
	    log_error( "lock not made: rename() failed: %s\n", strerror(errno) );
	    return -1;
        }
#endif /* __riscos__ */
	if( (pid = read_lockfile(h->lockname)) == -1 ) {
	    if( errno != ENOENT ) {
		log_info("cannot read lockfile\n");
		return -1;
	    }
	    log_info( "lockfile disappeared\n");
	    continue;
	}
	else if( pid == getpid() ) {
	    log_info( "Oops: lock already held by us\n");
	    h->locked = 1;
	    return 0; /* okay */
	}
	else if( kill(pid, 0) && errno == ESRCH ) {
#ifndef __riscos__
	    maybe_dead = " - probably dead";
#if 0 /* we should not do this without checking the permissions */
	       /* and the hostname */
	    log_info( "removing stale lockfile (created by %d)", pid );
#endif
#else /* __riscos__ */
            /* we are *pretty* sure that the other task is dead and therefore
               we remove the other lock file */
            maybe_dead = " - probably dead - removing lock";
            unlink(h->lockname);
#endif /* __riscos__ */
	}
	if( timeout == -1 ) {
	    struct timeval tv;
	    log_info( "waiting for lock (held by %d%s) %s...\n",
		      pid, maybe_dead, maybe_deadlock(h)? "(deadlock?) ":"");


	    /* can't use sleep, cause signals may be blocked */
	    tv.tv_sec = 1 + backoff;
	    tv.tv_usec = 0;
	    select(0, NULL, NULL, NULL, &tv);
	    if( backoff < 10 )
		backoff++ ;
	}
	else
	    return -1;
    }
    /*not reached */
#endif
}


/****************
 * release a lock
 * Returns: 0 := success
 */
int
release_dotlock( DOTLOCK h )
{
#if defined (HAVE_DOSISH_SYSTEM)
    return 0;
#else
    int pid;

    /* To avoid atexit race conditions we first check whether there
       are any locks left.  It might happen that another atexit
       handler tries to release the lock while the atexit handler of
       this module already ran and thus H is undefined.  */
    if(!all_lockfiles)
        return 0;

    if( h->disable ) 
	return 0;

    if( !h->locked ) {
	log_debug("oops, `%s' is not locked\n", h->lockname );
	return 0;
    }

    pid = read_lockfile( h->lockname );
    if( pid == -1 ) {
	log_error( "release_dotlock: lockfile error\n");
	return -1;
    }
    if( pid != getpid() ) {
	log_error( "release_dotlock: not our lock (pid=%d)\n", pid);
	return -1;
    }
#ifndef __riscos__
    if( unlink( h->lockname ) ) {
	log_error( "release_dotlock: error removing lockfile `%s'",
							h->lockname);
	return -1;
    }
#else /* __riscos__ */
    if( riscos_renamefile(h->lockname, h->tname) ) {
	log_error( "release_dotlock: error renaming lockfile `%s' to `%s'",
							h->lockname, h->tname);
	return -1;
    }
#endif /* __riscos__ */
    /* fixme: check that the link count is now 1 */
    h->locked = 0;
    return 0;
#endif
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
