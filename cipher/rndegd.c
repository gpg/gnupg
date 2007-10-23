/* rndegd.c  -	interface to the EGD
 *	Copyright (C) 1999, 2000, 2001, 2002 Free Software Foundation, Inc.
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
#include "algorithms.h"
#include "cipher.h"
#include "i18n.h"


#ifndef offsetof
#define offsetof(type, member) ((size_t) &((type *)0)->member)
#endif

static int egd_socket = -1;

static int
do_write( int fd, void *buf, size_t nbytes )
{
    size_t nleft = nbytes;
    int nwritten;

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
  
  while (nbytes)
    {
      do {
        n = read(fd, (char*)buf + nread, nbytes );
      } while( n == -1 && errno == EINTR );
      if( n == -1 )
        return nread? nread:-1;
      else if( n == 0 ) {
        /* EGD probably died. */
        errno = ECONNRESET;
        return -1;
      }
      nread += n;
      nbytes -= n;
    } 
  return nread;
}

/* Connect to the EGD and return the file descriptor.  Return -1 on
   error.  With NOFAIL set to true, silently fail and return the
   error, otherwise print an error message and die. */
int
rndegd_connect_socket (int nofail)
{
  int fd;
  const char *bname = NULL;
  char *name;
  struct sockaddr_un addr;
  int addr_len;

  if (egd_socket != -1)
    {
      close (egd_socket);
      egd_socket = -1;
    }

#ifdef EGD_SOCKET_NAME
  bname = EGD_SOCKET_NAME;
#endif
  if ( !bname || !*bname )
    bname = "=entropy";
  
  if ( *bname == '=' && bname[1] )
    name = make_filename( g10_opt_homedir, bname+1 , NULL );
  else
    name = make_filename( bname , NULL );
  
  if ( strlen(name)+1 >= sizeof addr.sun_path ) 
    g10_log_fatal ("EGD socketname is too long\n");
  
  memset( &addr, 0, sizeof addr );
  addr.sun_family = AF_UNIX;
  strcpy( addr.sun_path, name );	  
  addr_len = (offsetof( struct sockaddr_un, sun_path )
              + strlen( addr.sun_path ));
  
  fd = socket(AF_UNIX, SOCK_STREAM, 0);
  if (fd == -1 && !nofail)
    g10_log_fatal("can't create unix domain socket: %s\n",
                  strerror(errno) );
  else if (connect (fd, (struct sockaddr*)&addr, addr_len) == -1)
    {
      if (!nofail)
        g10_log_fatal("can't connect to `%s': %s\n",
                      name, strerror(errno) );
      close (fd);
      fd = -1;
    }
  xfree(name);
  if (fd != -1)
    egd_socket = fd;
  return fd;
}


/****************
 * Note: we always use the highest level.
 * TO boost the performance we may want to add some
 * additional code for level 1
 *
 * Using a level of 0 should never block and better add nothing
 * to the pool.  So this is just a dummy for EGD.
 */
int
rndegd_gather_random( void (*add)(const void*, size_t, int), int requester,
					  size_t length, int level )
{
    int fd = egd_socket;
    int n;
    byte buffer[256+2];
    int nbytes;
    int do_restart = 0;

    if( !length )
	return 0;
    if( !level )
	return 0;

  restart:
    if (fd == -1 || do_restart)
      fd = rndegd_connect_socket (0);

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
	tty_printf(
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
    wipememory(buffer, sizeof(buffer) );

    return 0; /* success */
}
