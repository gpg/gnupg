/* dotlock.c - dotfile locking
 *	Copyright (C) 1998 Free Software Foundation, Inc.
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
#include <sys/utsname.h>
#include <sys/types.h>
#include <sys/time.h>
#include <sys/stat.h>
#include <fcntl.h>
#include "types.h"
#include "util.h"
#include "memory.h"


static int read_lockfile( const char *name );

/****************
 * Create a lockfile with the given name. A TIMEOUT of 0
 * returns immediately, -1 waits forever (hopefully not), other
 * values are timeouts in milliseconds.
 * Returns: a char pointer used as handle for release lock
 *	    or NULL in case of an error.
 *
 * Notes: This function creates a lock file in the same directory
 *	  as file_to_lock with the name "file_to_lock.lock"
 *	  A temporary file ".#lk.<hostname>.pid[.threadid] is used.
 *	  This function does nothing for Windoze.
 */
const char *
make_dotlock( const char *file_to_lock, long timeout )
{
    int  fd=-1, pid;
    char pidstr[16];
    const char *handle = NULL;
    char *lockname = NULL;
    char *tname = NULL;
    int have_tfile = 0;
    struct utsname uts;
    const char *dirpart;
    int dirpartlen;

    sprintf( pidstr, "%10d\n", getpid() );
    /* fixme: add the hostname to the second line (FQDN or IP addr?) */

    /* create a temporary file */
  #if SYS_NMLN < 8
    #error Aiiih
  #endif
    if( uname( &uts ) )
	strcpy( uts.nodename, "unknown" );

    if( !(dirpart = strrchr( file_to_lock, '/' )) ) {
	dirpart = ".";
	dirpartlen = 1;
    }
    else {
	dirpartlen = dirpart - file_to_lock;
	dirpart = file_to_lock;
    }

  #ifdef _THREAD_SAFE
    tname = m_alloc( dirpartlen + 6 + strlen(uts.nodename) + 11+ 20 );
    sprintf( tname, "%.*s/.#lk.%s.%d.%p",
		    dirpartlen, dirpart, uts.nodename, getpid(), &pid );
  #else
    tname = m_alloc( dirpartlen + 6 + strlen(uts.nodename) + 11 );
    sprintf( tname, "%.*s/.#lk.%s.%d",
		    dirpartlen, dirpart, uts.nodename, getpid() );
  #endif
    do {
	errno = 0;
	fd = open( tname, O_WRONLY|O_CREAT|O_EXCL,
			  S_IRUSR|S_IRGRP|S_IROTH|S_IWUSR );
    } while( fd == -1 && errno == EINTR );
    if( fd == -1 ) {
	log_error( "failed to create temporary file '%s': %s\n",
					      tname, strerror(errno));
	goto leave;
    }
    have_tfile = 1;
    if( write(fd, pidstr, 11 ) != 11 ) {
	log_fatal( "error writing to '%s': %s\n", tname, strerror(errno) );
	goto leave;
    }
    if( close(fd) ) {
	log_error( "error closing '%s': %s\n", tname, strerror(errno));
	goto leave;
    }
    fd = -1;

    lockname = m_alloc( strlen(file_to_lock) + 6 );
    strcpy(stpcpy(lockname, file_to_lock), ".lock");

  retry:
    if( !link(tname, lockname) ) {/* fixme: better use stat to check the link count */
	handle = lockname;
	lockname = NULL;
    }
    else if( errno == EEXIST ) {
	if( (pid = read_lockfile(lockname)) == -1 ) {
	    if( errno == ENOENT ) {
		log_info( "lockfile disappeared\n");
		goto retry;
	    }
	    log_info("cannot read lockfile\n");
	}
	else if( pid == getpid() ) {
	    log_info( "Oops: lock already hold by us\n");
	    handle = lockname;
	    lockname = NULL;
	}
      #if 0 /* we should not do this without checking the permissions */
	    /* and the hostname */
	else if( kill(pid, 0) && errno == ESRCH ) {
	    log_info( "removing stale lockfile (created by %d)", pid );
	    remove( lockname );
	    goto retry;
	}
      #endif
	if( timeout == -1 ) {
	    struct timeval tv;
	    log_info( "waiting for lock (hold by %d) ...\n", pid );
	    /* can't use sleep, cause signals may be blocked */
	    tv.tv_sec = 1;
	    tv.tv_usec = 0;
	    select(0, NULL, NULL, NULL, &tv);
	    goto retry;
	}
	/* fixme: implement timeouts */
    }
    else
	log_error( "lock not made: link() failed: %s\n", strerror(errno) );

  leave:
    if( fd != -1 )
	close(fd);
    if( have_tfile )
	remove(tname);
    m_free(tname);
    m_free(lockname);
    return handle;
}

/****************
 * Create a lockfile for a existing file
 * Returns: a char pointer used as handle for release lock
 *	    or NULL in case of an error.
 *
 * Notes: This function creates a lock file in the same directory
 *	  as file_to_lock with the name "lock.<inode-no>"
 *
 * int
 * make_inodelock( const char *file_to_lock )
 *
 */




/****************
 * release a lock
 * Returns: 0 := success
 */
int
release_dotlock( const char *lockfile )
{
    int pid = read_lockfile( lockfile );
    if( pid == -1 ) {
	log_error( "release_dotlock: lockfile error");
	return -1;
    }
    if( pid != getpid() ) {
	log_error( "release_dotlock: not our lock (pid=%d)", pid);
	return -1;
    }
    if( remove( lockfile ) ) {
	log_error( "release_dotlock: error removing lockfile '%s'",
							    lockfile);
	return -1;
    }
    m_free( (char*)lockfile );
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
	log_debug("error opening lockfile '%s': %s\n", name, strerror(errno) );
	errno = e;
	return -1;
    }
    if( read(fd, pidstr, 10 ) != 10 ) {
	log_debug("error reading lockfile '%s'", name );
	close(fd);
	errno = 0;
	return -1;
    }
    close(fd);
    pid = atoi(pidstr);
    if( !pid || pid == -1 ) {
	log_error("invalid pid %d in lockfile '%s'", pid, name );
	errno = 0;
	return -1;
    }
    return pid;
}

