/* dotlock.c - dotfile locking
 *	Copyright (C) 1998 Free Software Foundation, Inc.
 *
 * This file is part of GNUPG.
 *
 * GNUPG is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * GNUPG is distributed in the hope that it will be useful,
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
#include "types.h"
#include "util.h"
#include "memory.h"




#if 0
/****************
 * Create a lockfile with the given name. A TIMEOUT of 0
 * returns immediately, -1 waits forever (hopefully not), other
 * values are timeouts in milliseconds.
 * Returns: a char pointer used as handle for release lock
 *	    or NULL in case of an error.
 *
 * Notes: This function creates a lock file in the same directory
 *	  as file_to_lock with the name "file_to_lock.lock"
 *	  A temporary file ".#lk.<pid>.<hostname> is used.
 *	  This function does nothing for Windoze.
 */
const char *
make_dotlock( const char *file_to_lock, long timeout )
{
    int rc=-1, fd=-1, pid;
    char pidstr[16];
    char *tname = NULL;
    char *p;

    log_debug("dotlock_make: lock='%s'\n", lockfile );
    sprintf( pidstr, "%10d\n", getpid() );
    /* add the hostname to the second line (FQDN or IP addr?) */

    /* create a temporary file */
    tname = CreateTmpFile2( p, ".#lk" );
    free(p);
    if( !tname )
	log_fatal( "could not create temporary lock file '%s'\n");
    log_debug( "dotlock_make: tmpname='%s'\n", tname );
    chmod( tname, 0644 ); /* just in case an umask is set */
    if( !(fd = open( tname, O_WRONLY )) )
	log_fatal( "could not open temporary lock file '%s'\n", tname);
    if( write(fd, pidstr, 11 ) != 11 )
	log_fatal( "error writing to temporary lock file '%s'\n", tname);
    if( close(fd) ) {
	log_fatal( "error closing '%s'\n", tname);

  retry:
    if( !link(tname, lockfile) )
	rc = 0; /* okay */
    else if( errno != EEXIST )
	log_error( "lock not made: link() failed: %s\n", strerror(errno) );
    else { /* lock file already there */
	if( (pid = read_lockfile(lockfile)) == -1 ) {
	    if( errno == ENOENT ) {
		log_debug( "lockfile disappeared\n");
		goto retry;
	    }
	    log_debug("cannot read lockfile\n");
	}
	else if( pid == getpid() ) {
	    log_info( "Oops: lock already hold by us\n");
	    rc = 0;  /* okay */
	}
	else if( kill(pid, 0) && errno == ESRCH ) {
	    log_info( "removing stale lockfile (created by %d)", (int)pid );
	    remove( lockfile );
	    goto retry;
	}
	log_debug( "lock not made: lock file exists\n" );
    }

    if( tname ) {
	remove(tname);
	free(tname);
    }
    if( !rc )
	log_debug( "lock made\n");
    return rc;
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
    log_debug( "release_dotlock: released lockfile '%s'", lockfile);
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
	log_debug("error opening lockfile '%s'", name );
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
#endif
