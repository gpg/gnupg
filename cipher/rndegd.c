/* rndegd.c  -	interface to the EGD
 *	Copyright (C) 1999 Free Software Foundation, Inc.
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
#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include <errno.h>
#include <sys/time.h>
#include <sys/stat.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>
#include "types.h"
#include "util.h"
#include "ttyio.h"
#include "dynload.h"
#include "cipher.h"

#ifdef IS_MODULE
  #define _(a) (a)
#else
  #include "i18n.h"
#endif

#ifndef offsetof
#define offsetof(type, member) ((size_t) &((type *)0)->member)
#endif

static int
do_write( int fd, void *buf, size_t nbytes )
{
    size_t nleft = nbytes;
    ssize_t nwritten;

    while( nleft > 0 ) {
	nwritten = write( fd, buf, nleft);
	if( nwritten < 0 ) {
	    if( errno == EINTR )
		continue;
	    return -1;
	}
	nleft -= nwritten;
	buf = (char*)buf + nwritten;
    }
    return 0;
}

static int
do_read( int fd, void *buf, size_t nbytes )
{
    int n, nread = 0;

    do {
	do {
	    n = read(fd, (char*)buf + nread, nbytes );
	} while( n == -1 && errno == EINTR );
	if( n == -1 )
	    return -1;
	nread += n;
    } while( nread < nbytes );
    return nbytes;
}



/* fixme: level 1 is not yet handled */
static int
gather_random( void (*add)(const void*, size_t, int), int requester,
					  size_t length, int level )
{
    static int fd = -1;
    int n;
    byte buffer[256+2];
    int nbytes;
    int do_restart = 0;

    if( !length )
	return 0;


  restart:
    if( do_restart ) {
	if( fd != -1 ) {
	    close( fd );
	    fd = -1;
	}
    }
    if( fd == -1 ) {
	char *name = make_filename( g10_opt_homedir, "entropy", NULL );
	struct sockaddr_un addr;
	int addr_len;

	memset( &addr, 0, sizeof addr );
	addr.sun_family = AF_UNIX;
	strcpy( addr.sun_path, name );	  /* fixme: check that it is long enough */
	addr_len = offsetof( struct sockaddr_un, sun_path )
		   + strlen( addr.sun_path );

	fd = socket(AF_UNIX, SOCK_STREAM, 0);
	if( fd == -1 )
	    g10_log_fatal("can't create unix domain socket: %s\n",
							    strerror(errno) );
	if( connect( fd, (struct sockaddr*)&addr, addr_len) == -1 )
	    g10_log_fatal("can't connect to `%s': %s\n",
						    name, strerror(errno) );
	m_free(name);
    }
    do_restart = 0;

    nbytes = length < 255? length : 255;
    /* first time we do it with a non blocking request */
    buffer[0] = 1; /* non blocking */
    buffer[1] = nbytes;
    if( do_write( fd, buffer, 2 ) == -1 )
	g10_log_fatal("can't write to the EGD: %s\n", strerror(errno) );
    n = do_read( fd, buffer, 1 );
    if( n == -1 ) {
	g10_log_error("read error on EGD: %s\n", strerror(errno));
	do_restart = 1;
	goto restart;
    }
    n = buffer[0];
    if( n ) {
	n = do_read( fd, buffer, n );
	if( n == -1 ) {
	    g10_log_error("read error on EGD: %s\n", strerror(errno));
	    do_restart = 1;
	    goto restart;
	}
	(*add)( buffer, n, requester );
	length -= n;
    }

    if( length ) {
      #ifdef IS_MODULE
	fprintf( stderr,
      #else
	tty_printf(
      #endif
	 _("Please wait, entropy is being gathered. Do some work if it would\n"
	   "keep you from getting bored, because it will improve the quality\n"
	   "of the entropy.\n") );
    }
    while( length ) {
	nbytes = length < 255? length : 255;

	buffer[0] = 2; /* blocking */
	buffer[1] = nbytes;
	if( do_write( fd, buffer, 2 ) == -1 )
	    g10_log_fatal("can't write to the EGD: %s\n", strerror(errno) );
	n = do_read( fd, buffer, nbytes );
	if( n == -1 ) {
	    g10_log_error("read error on EGD: %s\n", strerror(errno));
	    do_restart = 1;
	    goto restart;
	}
	(*add)( buffer, n, requester );
	length -= n;
    }
    memset(buffer, 0, sizeof(buffer) );

    return 0; /* success */
}



#ifndef IS_MODULE
static
#endif
const char * const gnupgext_version = "RNDEGD ($Revision$)";

static struct {
    int class;
    int version;
    void *func;
} func_table[] = {
    { 40, 1, gather_random },
};


#ifndef IS_MODULE
static
#endif
void *
gnupgext_enum_func( int what, int *sequence, int *class, int *vers )
{
    void *ret;
    int i = *sequence;

    do {
	if ( i >= DIM(func_table) || i < 0 ) {
	    return NULL;
	}
	*class = func_table[i].class;
	*vers  = func_table[i].version;
	ret = func_table[i].func;
	i++;
    } while ( what && what != *class );

    *sequence = i;
    return ret;
}

#ifndef IS_MODULE
void
rndegd_constructor(void)
{
    register_internal_cipher_extension( gnupgext_version,
					gnupgext_enum_func );
}
#endif

