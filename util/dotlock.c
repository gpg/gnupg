/* dotlock.c - dotfile locking
 *	Copyright (C) 1998, 1999, 2000 Free Software Foundation, Inc.
 *
 * This file is part of GnuPG.
 *
 * GnuPG is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * GnuPG is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA
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

static int read_lockfile( const char *name );

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
    int  fd = -1;
    char pidstr[16];
  #ifndef  HAVE_DOSISH_SYSTEM
    struct utsname utsbuf;
  #endif
    const char *nodename;
    const char *dirpart;
    int dirpartlen;

    if( !initialized ) {
	atexit( remove_lockfiles );
	initialized = 1;
    }
    if( !file_to_lock )
	return NULL;

    h = m_alloc_clear( sizeof *h );
    if( never_lock ) {
	h->disable = 1;
      #ifdef _REENTRANT
	/* fixme: aquire mutex on all_lockfiles */
      #endif
	h->next = all_lockfiles;
	all_lockfiles = h;
	return h;
    }


#ifndef HAVE_DOSISH_SYSTEM
    sprintf( pidstr, "%10d\n", (int)getpid() );
    /* fixme: add the hostname to the second line (FQDN or IP addr?) */

    /* create a temporary file */
    if( uname( &utsbuf ) )
	nodename = "unknown";
    else
	nodename = utsbuf.nodename;

    if( !(dirpart = strrchr( file_to_lock, '/' )) ) {
	dirpart = ".";
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

    h->tname = m_alloc( dirpartlen + 6+30+ strlen(nodename) + 11 );
    sprintf( h->tname, "%.*s/.#lk%p.%s.%d",
	     dirpartlen, dirpart, h, nodename, (int)getpid() );

    do {
	errno = 0;
	fd = open( h->tname, O_WRONLY|O_CREAT|O_EXCL,
			  S_IRUSR|S_IRGRP|S_IROTH|S_IWUSR );
    } while( fd == -1 && errno == EINTR );
    if( fd == -1 ) {
	all_lockfiles = h->next;
	log_error( "failed to create temporary file `%s': %s\n",
					    h->tname, strerror(errno));
	m_free(h->tname);
	m_free(h);
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
	m_free(h->tname);
	m_free(h);
	return NULL;
    }
    if( close(fd) ) {
	all_lockfiles = h->next;
      #ifdef _REENTRANT
	/* release mutex */
      #endif
	log_error( "error closing `%s': %s\n", h->tname, strerror(errno));
	unlink(h->tname);
	m_free(h->tname);
	m_free(h);
	return NULL;
    }

  #ifdef _REENTRANT
    /* release mutex */
  #endif
#endif /* !HAVE_DOSISH_SYSTEM */
    h->lockname = m_alloc( strlen(file_to_lock) + 6 );
    strcpy(stpcpy(h->lockname, file_to_lock), ".lock");
    return h;
}

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
 * Do a lock on H. A TIMEOUT of 0 returns immediately,
 * -1 waits forever (hopefully not), other
 * values are timeouts in milliseconds.
 * Returns: 0 on success
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

    if( h->disable ) {
	return 0;
    }

    if( h->locked ) {
	log_debug("oops, `%s' is already locked\n", h->lockname );
	return 0;
    }

    for(;;) {
	if( !link(h->tname, h->lockname) ) {
	    /* fixme: better use stat to check the link count */
	    h->locked = 1;
	    return 0; /* okay */
	}
	if( errno != EEXIST ) {
	    log_error( "lock not made: link() failed: %s\n", strerror(errno) );
	    return -1;
	}
	if( (pid = read_lockfile(h->lockname)) == -1 ) {
	    if( errno != ENOENT ) {
		log_info("cannot read lockfile\n");
		return -1;
	    }
	    log_info( "lockfile disappeared\n");
	    continue;
	}
	else if( pid == getpid() ) {
	    log_info( "Oops: lock already hold by us\n");
	    h->locked = 1;
	    return 0; /* okay */
	}
	else if( kill(pid, 0) && errno == ESRCH ) {
	    maybe_dead = " - probably dead";
	 #if 0 /* we should not do this without checking the permissions */
	       /* and the hostname */
	    log_info( "removing stale lockfile (created by %d)", pid );
	 #endif
	}
	if( timeout == -1 ) {
	    struct timeval tv;
	    log_info( "waiting for lock (hold by %d%s) %s...\n",
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
    int pid;

    if( h->disable ) {
	return 0;
    }

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
    if( unlink( h->lockname ) ) {
	log_error( "release_dotlock: error removing lockfile `%s'",
							h->lockname);
	return -1;
    }
    /* fixme: check that the link count is now 1 */
    h->locked = 0;
    return 0;
#endif /* !HAVE_DOSISH_SYSTEM */
}


/****************
 * Read the lock file and return the pid, returns -1 on error.
 */
static int
read_lockfile( const char *name )
{
  #ifdef HAVE_DOSISH_SYSTEM
    return 0;
  #else
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
    if( !pid || pid == -1 ) {
	log_error("invalid pid %d in lockfile `%s'", pid, name );
	errno = 0;
	return -1;
    }
    return pid;
  #endif
}


void
remove_lockfiles()
{
  #ifndef HAVE_DOSISH_SYSTEM
    DOTLOCK h, h2;

    h = all_lockfiles;
    all_lockfiles = NULL;

    while( h ) {
	h2 = h->next;
	if( !h->disable ) {
	    if( h->locked )
		unlink( h->lockname );
	    unlink(h->tname);
	    m_free(h->tname);
	    m_free(h->lockname);
	}
	m_free(h);
	h = h2;
    }
  #endif
}

