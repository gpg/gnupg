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
 */

#include <config.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "util.h"
#include "ks-proto.h"

#if 0
/****************
 * Read a protocol line
 */
static int
read_line( FILE *fp )
{
    return -1;
}




/****************
 * Send a HKP request
 */
int
hkp_request( int operation, const char *user_id )
{

}





/************************************************
 ******* client communication stuff  ************
 ************************************************/

/****************
 * Initialisieren des clients
 * Es wird ein Handle zurückgegeben oder -1 bei einem fehler.
 * z.Z. ist nut eine Verbindung gleichzeitig möglich.
 * Wenn einer serverpid von 0 angegeben wird, so wird diese
 * der environment  variabeln ATEXDB_PID entnommen.
 */

int
hkp_open( const char *serverurl )
{
    const char *s;

    s = SERVER_NAME_TEMPLATE;
    client.serv_name = xmalloc(strlen(s) + 10 );
    sprintf(client.serv_name,s, serverpid );
    if( opt.verbose )
	Info("Using unix domain stream '%s'", client.serv_name );

    memset( &client.serv_addr, 0, sizeof client.serv_addr );
    client.serv_addr.sun_family = AF_UNIX;
    strcpy( client.serv_addr.sun_path, client.serv_name );
    client.serv_addr_len = strlen(client.serv_addr.sun_path)
			    + sizeof client.serv_addr.sun_family;

    client.sockfd = -1;
    if( DoCheckVersion() )
	return -1;
    return 0;
}


static int
DoConnect()
{
    if( client.sockfd != -1 )
	DoDisconnect();
    if( (client.sockfd = socket(AF_UNIX, SOCK_STREAM, 0)) == -1 ) {
	Error(1000,"can't open unix domain socket");
	return 1;
    }
    if( connect(client.sockfd, (struct sockaddr*)&client.serv_addr,
				client.serv_addr_len) == -1 ) {
	Error(1000,"can't connect to '%s'",client.serv_addr.sun_path);
	return 1;
    }

    return 0; /* okay */
}

static int
DoDisconnect()
{
    if( client.sockfd != -1 ) {
	close(client.sockfd);
	client.sockfd = -1;
    }
    return 0; /* okay */
}

/****************
 * NBYTES auf den aktuellen stream schreiben.
 */
static int
DoWrite( void *buf, size_t nbytes )
{
    size_t nleft = nbytes;
    ssize_t nwritten;

    while( nleft > 0 ) {
	/* FIXME: add EINTR handling */
	nwritten = write(client.sockfd, buf, nleft);
	if( nwritten < 0 ) {
	    Error(1000,"error writing to server");
	    return -1;
	}
	nleft -= nwritten;
	buf = (char*)buf + nwritten;
    }
    return 0;
}

static int
DoWriteStr( const char *s )
{
    return DoWrite((char *)s, strlen(s) );
}


static int
DoRead( void *buf, size_t buflen, size_t *ret_nread, int stop)
{
    size_t nleft = buflen;
    int nread;
    char *p;

    p = buf;
    while( nleft > 0 ) {
	/* FIXME: add EINTR handling */
	nread = read(client.sockfd, buf, stop? 1 : nleft);
	if( nread < 0 ) {
	    Error(1000,"error reading from server");
	    return -1;
	}
	else if( !nread )
	    break; /* EOF */
	nleft -= nread;
	buf = (char*)buf + nread;
	if( stop )
	    for(; p < (char*)buf ; p++ )
		if( *p == '\n' )
		    goto leave;
    }
  leave:
    if( ret_nread )
	*ret_nread = buflen - nleft;
    return 0;
}

/****************
 * Like DoRead(), but append the received data to the given strgbuf.
 * read a maximum of nbytes;
 */
static int
DoReadIntoStrgbuf( strgbuf_t *strgbuf, size_t nbytes, size_t *ret_nread)
{
    size_t ntotal, nleft;
    int nread;
    byte *p, buffer[1000];

    ntotal = 0;
    nleft = nbytes;
    while( nleft ) {
	nread = read(client.sockfd, buffer,
			    nleft > DIM(buffer)? DIM(buffer) : nleft);
	if( nread < 0 ) {
	    Error(1000,"error reading from server");
	    return -1;
	}
	else if( !nread )
	    break; /* EOF */
	nleft -= nread;
	ntotal += nread;
	/* ab in den stringbuffer */
	for(p=buffer; nread; nread--, p++ )
	    PutStrgbuf(strgbuf, *p );
    }

    if( ret_nread )
	*ret_nread = ntotal;
    return 0;
}


/****************
 * In retval wird das numerische argument nach OK zurückgegeben
 */
static int
DoRequest( char *request, long *retval )
{
    if( DoWrite(request, strlen(request)) )
	return -1;
    return DoWaitReply( retval );
}

static int
DoWaitReply( long *retval )
{
    char *p, buf[200]; /* enough room for messages */
    size_t nread;

    /* read but stop at the first newline */
    if( DoRead(buf, DIM(buf)-2, &nread, 1 ) )
	return -1;
    buf[DIM(buf)-1] = 0;
    /* fixme: should check, that we have the linefeed and otherwise
     * perform a dummy read */
    if( p = strchr(buf, '\n') )
	*p = 0;
    if( *buf == 'O' && buf[1] == 'K' && (buf[2]==' ' || !buf[2]) ) {
	if( retval )
	    *retval = buf[2]? strtol(buf+3, NULL, 10 ):0;
	return 0;
    }
    Error(0, "Server replied: %.60s", buf );
    return -1;
}












#endif



