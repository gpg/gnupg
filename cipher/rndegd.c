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
#include <sys/types.h>
#include <sys/stat.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include "types.h"
#include "util.h"
#include "ttyio.h"
#include "dynload.h"

#ifdef IS_MODULE
  #define _(a) (a)
#else
  #include "i18n.h"
#endif

static int gather_random( void (*add)(const void*, size_t, int), int requester,
					  size_t length, int level );

#ifdef IS_MODULE
static void tty_printf(const char *fmt, ... )
{
    g10_log_info("tty_printf not available (%s)\n", fmt );
}
#endif


static int
do_write( int fd, void *buf, size_t nbytes )
{
    size_t nleft = nbytes;
    ssize_t nwritten;

    while( nleft > 0 ) {
	nwritten = write( fd, buf, nleft);
	if( nwritten < 0 ) {
	    if( errno = EINTR )
		continue;
	    return -1;
	}
	nleft -= nwritten;
	buf = (char*)buf + nwritten;
    }
    return 0;
}

    my $bytes = shift;
    $msg = pack("CC", 0x01, $bytes);
    $s->syswrite($msg, length($msg));
    my $nread = $s->sysread($buf, 1);
    die unless $nread == 1;
    my $count = unpack("C",$buf);
    $nread = $s->sysread($buf, $count);
    die "didn't get all the entropy" unless $nread == $count;
    print "got $count bytes of entropy: ",unpack("H*",$buf),"\n";




static int
gather_random( void (*add)(const void*, size_t, int), int requester,
					  size_t length, int level )
{
    static int fd = -1;
    int n;
    int warn=0;
    byte buffer[768];

    if( fd == -1 ) {
	const char *name = "/tmp/entropy";
	struct sockaddr_un addr;
	int addr_len;

	memset( &addr, 0, sizeof addr );
	addr.sun_family = AF_UNIX;
	strcpy( addr.sun_path, name );	  /* fixme: check that it is long enough */
	addr_len = strlen(addr.sun_path) + sizeof addr.sun_family;

	fd = socket(AF_UNIX, SOCK_STREAM, 0);
	if( fd == -1 )
	    g10_log_fatal("can't create unix domain socket: %s\n",
							    strerror(errno) );
	if( connect( fd, (struct sockaddr*)&addr, addr_len) == -1 )
	    g10_log_fatal("can't connect to `%s': %s\n",
						    name, strerror(errno) );
    }

    if( do_write( fd, "\x01", 1 ) == -1 )
	g10_log_fatal("can't write to the EGD: %s\n", strerror(errno) );

    while( length ) {
	fd_set rfds;
	struct timeval tv;
	int rc;

	FD_ZERO(&rfds);
	FD_SET(fd, &rfds);
	tv.tv_sec = 3;
	tv.tv_usec = 0;
	if( !(rc=select(fd+1, &rfds, NULL, NULL, &tv)) ) {
	    if( !warn )
		tty_printf( _(
"\n"
"Not enough random bytes available.  Please do some other work to give\n"
"the OS a chance to collect more entropy! (Need %d more bytes)\n"), length );
	    warn = 0; /* set to 1 to print onyl one warning */
	    continue;
	}
	else if( rc == -1 ) {
	    tty_printf("select() error: %s\n", strerror(errno));
	    continue;
	}

	do {
	    int nbytes = length < sizeof(buffer)? length : sizeof(buffer);
	    n = read(fd, buffer, nbytes );
	    if( n >= 0 && n > nbytes ) {
		g10_log_error("bogus read from random device (n=%d)\n", n );
		n = nbytes;
	    }
	} while( n == -1 && errno == EINTR );
	if( n == -1 )
	    g10_log_fatal("read error on EGD: %s\n", strerror(errno));
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

