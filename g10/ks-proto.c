/* ks-proto.c  keyserver protocol handling
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

/****************
 * The extended HKP protocol:
 *
 *  GET /pks/lookup[/<gnupg_user_id>][?[op=<cmd>][&armor=0][&search=<keywords>]]
 *
 * Default is: "armor=1", "op=get". "search" is only allowed if gnupg_user_id
 * is not present.  GET maybe replaced by HEAD in which case only some status
 * information is returned.
 *
 * Hmmm, I don't like it, the better solution is to use:
 *
 *  /pks/gnupg/get for binary lookups
 *  /pks/gnupg/upd to update a key
 *  /pks/gnupg/ins to insert a new key
 *
 * Optional a version string can be inserted as in:
 *
 *  /pks/gnupg/v1.0/get
 *
 * Returned HTTP options:
 *  X-Key-Hash: <rmd160 hash value of the keyblock>
 *  X-Key-MTime: <last modification time>
 *  X-Key-LID: <local_key_id_used_for_update_etc>
 * [fixme: is X-.... allowed?]
 *
 */

#include <config.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <ctype.h>
#include "util.h"
#include "ks-proto.h"


static int
do_read( int fd, char *buffer, size_t bufsize, int *ret_nread )
{
    int n;
    fd_set rfds;
    struct timeval tv;
    int rc;

    *ret_nread = 0;
    do {
	FD_ZERO(&rfds);
	FD_SET(fd, &rfds);
	tv.tv_sec = 1;
	tv.tv_usec = 0;
	if( !(rc=select(fd+1, &rfds, NULL, NULL, &tv)) )
	    return 0; /* timeout */
	if( rc == -1 ) {
	    log_error("select() error: %s\n", strerror(errno));
	    return -1;
	}

	do {
	    n = read(fd, buffer, bufsize );
	    if( n >= 0 && n > bufsize )
		log_bug("bogus read from fd %d (n=%d)\n", fd, n );
	} while( n == -1 && errno == EINTR );
	if( n == -1 ) {
	    log_error("read error on fd %d: %s\n", fd, strerror(errno) );
	    return -1;
	}
    } while( !n );
    *ret_nread = n;
    return 0;
}


int
ks_get_request( int fd, KS_TRANS *req )
{
    char *p, *p2, buf[500];
    int nread, n;
    int state = 0;

    req->err = 0;
    req->data = NULL;
    while( !do_read( fd, buf, DIM(buf)-1, &nread ) {
	p = buf;
	if( !state ) {
	    /* replace the trailing LF with a 0 */
	    for(p2=p,n=0; n < nread && *p2 != '\n'; p2++ )
		;
	    if( *p2 != '\n' ) {
		req->err = KS_ERR_REQ_TOO_LONG;
		break;
	    }
	    *p2++ = 0;
	    n++;

	    /* now look at the request.  Note that the isspace() will work
	     * because there is still a CR before the 0 */
	    if(      (p[0] == 'G' || p[0] == 'g')
		  && (p[1] == 'E' || p[1] == 'e')
		  && (p[2] == 'T' || p[2] == 't') && isspace( p[3] ) ) {
		req->cmd = KS_REQ_GET;
		p += 4;
	    }
	    else if( (p[0] == 'H' || p[0] == 'h')
		  && (p[1] == 'E' || p[1] == 'e')
		  && (p[2] == 'A' || p[2] == 'a')
		  && (p[3] == 'D' || p[3] == 'd') && isspace( p[4] ) ) {
		req->cmd = KS_REQ_HEAD;
		p += 5;
	    }
	    else if( (p[0] == 'H' || p[0] == 'h')
		  && (p[1] == 'E' || p[1] == 'e')
		  && (p[2] == 'L' || p[2] == 'l')
		  && (p[3] == 'P' || p[3] == 'p') && isspace( p[4] ) ) {
		req->cmd = KS_REQ_HELP;
		p += 5;
	    }
	    else
		req->cmd = KS_REQ_UNKNOWN;
	    /* skip spaces, store args and remaining data */
	    while( *p == ' ' || *p == '\t' )
		p++;
	    /* fixme: remove trailing blanks from args */
	    req->args = p;
	    p = p2; /* p now points to the remaining n bytes in the buffer */
	    state = 1;
	}
	if( state == 1 ) {
	    /* read the option lines */
	}

    }
}


