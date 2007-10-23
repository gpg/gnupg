/* http.c  -  HTTP protocol handler
 * Copyright (C) 1999, 2001, 2002, 2003, 2004,
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
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <ctype.h>
#include <errno.h>

#ifdef _WIN32
#include <windows.h>
#else
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <time.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#endif

#include "util.h"
#include "iobuf.h"
#include "i18n.h"
#include "http.h"
#include "srv.h"

#ifdef _WIN32
#define sock_close(a)  closesocket(a)
#else
#define sock_close(a)  close(a)
#endif

#define MAX_LINELEN 20000  /* max. length of a HTTP line */
#define VALID_URI_CHARS "abcdefghijklmnopqrstuvwxyz"   \
			"ABCDEFGHIJKLMNOPQRSTUVWXYZ"   \
			"01234567890@"                 \
			"!\"#$%&'()*+,-./:;<=>?[\\]^_{|}~"

#ifndef EAGAIN
#define EAGAIN  EWOULDBLOCK
#endif

static int parse_uri( PARSED_URI *ret_uri, const char *uri );
static void release_parsed_uri( PARSED_URI uri );
static int do_parse_uri( PARSED_URI uri, int only_local_part );
static int remove_escapes( byte *string );
static int insert_escapes( byte *buffer, const byte *string,
					 const byte *special );
static URI_TUPLE parse_tuple( byte *string );
static int send_request( HTTP_HD hd, const char *auth, const char *proxy );
static byte *build_rel_path( PARSED_URI uri );
static int parse_response( HTTP_HD hd );

static int connect_server( const char *server, ushort port, unsigned int flags,
			   const char *srvtag );
static int write_server( int sock, const char *data, size_t length );

#ifdef _WIN32
static void
deinit_sockets (void)
{
    WSACleanup();
}

static void
init_sockets (void)
{
    static int initialized;
    static WSADATA wsdata;

    if (initialized)
        return;

    if( WSAStartup( 0x0101, &wsdata ) ) {
        log_error ("error initializing socket library: ec=%d\n", 
                    (int)WSAGetLastError () );
        return;
    }
    if( wsdata.wVersion < 0x0001 ) {
        log_error ("socket library version is %x.%x - but 1.1 needed\n",
                   LOBYTE(wsdata.wVersion), HIBYTE(wsdata.wVersion));
        WSACleanup();
        return;
    }
    atexit ( deinit_sockets );
    initialized = 1;
}
#endif /*_WIN32*/

static byte bintoasc[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
			 "abcdefghijklmnopqrstuvwxyz"
			 "0123456789+/";

/****************
 * create a radix64 encoded string.
 */

/* TODO: This is a duplicate of code in g10/armor.c modified to do the
   "=" padding.  Better to use a single copy in strgutil.c ? */
static char *
make_radix64_string( const byte *data, size_t len )
{
    char *buffer, *p;

    buffer = p = xmalloc( (len+2)/3*4 + 1 );
    for( ; len >= 3 ; len -= 3, data += 3 ) {
	*p++ = bintoasc[(data[0] >> 2) & 077];
	*p++ = bintoasc[(((data[0] <<4)&060)|((data[1] >> 4)&017))&077];
	*p++ = bintoasc[(((data[1]<<2)&074)|((data[2]>>6)&03))&077];
	*p++ = bintoasc[data[2]&077];
    }
    if( len == 2 ) {
	*p++ = bintoasc[(data[0] >> 2) & 077];
	*p++ = bintoasc[(((data[0] <<4)&060)|((data[1] >> 4)&017))&077];
	*p++ = bintoasc[((data[1]<<2)&074)];
	*p++ = '=';
    }
    else if( len == 1 ) {
	*p++ = bintoasc[(data[0] >> 2) & 077];
	*p++ = bintoasc[(data[0] <<4)&060];
	*p++ = '=';
	*p++ = '=';
    }
    *p = 0;
    return buffer;
}

int
http_open( HTTP_HD hd, HTTP_REQ_TYPE reqtype, const char *url,
	   char *auth, unsigned int flags, const char *proxy )
{
    int rc;

    if( !(reqtype == HTTP_REQ_GET || reqtype == HTTP_REQ_POST) )
	return G10ERR_INV_ARG;

    /* initialize the handle */
    memset( hd, 0, sizeof *hd );
    hd->sock = -1;
    hd->initialized = 1;
    hd->req_type = reqtype;
    hd->flags = flags;

    rc = parse_uri( &hd->uri, url );
    if( !rc ) {
	rc = send_request( hd, auth, proxy );
	if( !rc ) {
	    hd->fp_write = iobuf_sockopen( hd->sock , "w" );
	    if( hd->fp_write )
		return 0;
	    rc = G10ERR_GENERAL;
	}
    }

    if( !hd->fp_read && !hd->fp_write && hd->sock != -1 )
	sock_close( hd->sock );
    iobuf_close( hd->fp_read );
    iobuf_close( hd->fp_write);
    release_parsed_uri( hd->uri );
    hd->initialized = 0;

    return rc;
}


void
http_start_data( HTTP_HD hd )
{
    iobuf_flush ( hd->fp_write );
    if( !hd->in_data ) {
        write_server (hd->sock, "\r\n", 2);
	hd->in_data = 1;
    }
}


int
http_wait_response( HTTP_HD hd, unsigned int *ret_status )
{
    int rc;

    http_start_data( hd ); /* make sure that we are in the data */

#if 0
    hd->sock = dup( hd->sock ); 
    if( hd->sock == -1 )
	return G10ERR_GENERAL;
#endif
    iobuf_ioctl (hd->fp_write, 1, 1, NULL); /* keep the socket open */
    iobuf_close (hd->fp_write);
    hd->fp_write = NULL;
    /* We do not want the shutdown code anymore.  It used to be there
       to support old versions of pksd.  These versions are anyway
       unusable and the latest releases haven been fixed to properly
       handle HTTP 1.0. */
    /* if ( !(hd->flags & HTTP_FLAG_NO_SHUTDOWN) ) */
    /*     shutdown( hd->sock, 1 ); */
    hd->in_data = 0;

    hd->fp_read = iobuf_sockopen( hd->sock , "r" );
    if( !hd->fp_read )
	return G10ERR_GENERAL;

    rc = parse_response( hd );
    if( !rc && ret_status )
	*ret_status = hd->status_code;

    return rc;
}


int
http_open_document( HTTP_HD hd, const char *document, char *auth,
		    unsigned int flags, const char *proxy )
{
    int rc;

    rc = http_open(hd, HTTP_REQ_GET, document, auth, flags, proxy );
    if( rc )
	return rc;

    rc = http_wait_response( hd, NULL );
    if( rc )
	http_close( hd );

    return rc;
}


void
http_close( HTTP_HD hd )
{
    if( !hd || !hd->initialized )
	return;
    if( !hd->fp_read && !hd->fp_write && hd->sock != -1 )
	sock_close( hd->sock );
    iobuf_close( hd->fp_read );
    iobuf_close( hd->fp_write );
    release_parsed_uri( hd->uri );
    xfree( hd->buffer );
    hd->initialized = 0;
}



/****************
 * Parse an URI and put the result into the newly allocated ret_uri.
 * The caller must always use release_parsed_uri to releases the
 * resources (even on an error).
 */
static int
parse_uri( PARSED_URI *ret_uri, const char *uri )
{
   *ret_uri = xmalloc_clear( sizeof(**ret_uri) + strlen(uri) );
   strcpy( (*ret_uri)->buffer, uri );
   return do_parse_uri( *ret_uri, 0 );
}

static void
release_parsed_uri( PARSED_URI uri )
{
    if( uri )
    {
	URI_TUPLE r, r2;

	for( r = uri->query; r; r = r2 ) {
	    r2 = r->next;
	    xfree( r );
	}
	xfree( uri );
    }
}

static int
do_parse_uri( PARSED_URI uri, int only_local_part )
{
    URI_TUPLE *tail;
    char *p, *p2, *p3;
    int n;

    p = uri->buffer;
    n = strlen( uri->buffer );
    /* initialize all fields to an empty string or an empty list */
    uri->scheme = uri->host = uri->path = p + n;
    uri->port = 0;
    uri->params = uri->query = NULL;

    /* a quick validity check */
    if( strspn( p, VALID_URI_CHARS) != n )
	return G10ERR_BAD_URI; /* invalid characters found */

    if( !only_local_part ) {
	/* find the scheme */
	if( !(p2 = strchr( p, ':' ) ) || p2 == p )
	   return G10ERR_BAD_URI; /* No scheme */
	*p2++ = 0;
	strlwr( p );
	uri->scheme = p;
	if(strcmp(uri->scheme,"http")==0)
	  uri->port = 80;
	else
	  return G10ERR_INVALID_URI; /* Unsupported scheme */

	p = p2;

	/* find the hostname */
	if( *p != '/' )
	    return G10ERR_INVALID_URI; /* does not start with a slash */

	p++;
	if( *p == '/' ) {  /* there seems to be a hostname */
	    p++;
	    if( (p2 = strchr(p, '/')) )
		*p2++ = 0;

	    /* Check for username/password encoding */
	    if((p3=strchr(p,'@')))
	      {
		uri->auth=p;
		*p3++='\0';
		p=p3;
	      }

	    strlwr( p );
	    uri->host = p;
	    if( (p3=strchr( p, ':' )) ) {
		*p3++ = 0;
		uri->port = atoi( p3 );
	    }

	    uri->host = p;
	    if( (n = remove_escapes( uri->host )) < 0 )
		return G10ERR_BAD_URI;
	    if( n != strlen( p ) )
		return G10ERR_BAD_URI; /* hostname with a Nul in it */
	    p = p2 ? p2 : NULL;
	}
    } /* end global URI part */

    /* parse the pathname part */
    if( !p || !*p ) /* we don't have a path */
	return 0; /* and this is okay */

    /* todo: here we have to check params */

    /* do we have a query part */
    if( (p2 = strchr( p, '?' )) )
	*p2++ = 0;

    uri->path = p;
    if( (n = remove_escapes( p )) < 0 )
	return G10ERR_BAD_URI;
    if( n != strlen( p ) )
	return G10ERR_BAD_URI; /* path with a Nul in it */
    p = p2 ? p2 : NULL;

    if( !p || !*p ) /* we don't have a query string */
	return 0;   /* okay */

    /* now parse the query string */
    tail = &uri->query;
    for(;;) {
	URI_TUPLE elem;

	if( (p2 = strchr( p, '&' )) )
	    *p2++ = 0;
	if( !(elem = parse_tuple( p )) )
	    return G10ERR_BAD_URI;
	*tail = elem;
	tail = &elem->next;

	if( !p2 )
	   break; /* ready */
	p = p2;
    }

    return 0;
}



/****************
 * Remove all %xx escapes; this is done inplace.
 * Returns: new length of the string.
 */
static int
remove_escapes( byte *string )
{
    int n = 0;
    byte *p, *s;

    for(p=s=string; *s ; s++ ) {
	if( *s == '%' ) {
	    if( s[1] && s[2] && isxdigit(s[1]) && isxdigit(s[2]) ) {
		s++;
		*p  = *s >= '0' && *s <= '9' ? *s - '0' :
		      *s >= 'A' && *s <= 'F' ? *s - 'A' + 10 : *s - 'a' + 10 ;
		*p <<= 4;
		s++;
		*p |= *s >= '0' && *s <= '9' ? *s - '0' :
		      *s >= 'A' && *s <= 'F' ? *s - 'A' + 10 : *s - 'a' + 10 ;
		p++;
		n++;
	    }
	    else {
		*p++ = *s++;
		if( *s )
		   *p++ = *s++;
		if( *s )
		   *p++ = *s++;
		if( *s )
		   *p = 0;
		return -1; /* bad URI */
	    }
	}
	else
	{
	    *p++ = *s;
	    n++;
	}
    }
    *p = 0; /* always keep a string terminator */
    return n;
}


static int
insert_escapes( byte *buffer, const byte *string, const byte *special )
{
    int n = 0;

    for( ; *string; string++ ) {
	if( strchr( VALID_URI_CHARS, *string )
	    && !strchr( special, *string ) )  {
	    if( buffer )
		*buffer++ = *string;
	    n++;
	}
	else {
	    if( buffer ) {
		sprintf( buffer, "%%%02X", *string );
		buffer += 3;
	    }
	    n += 3;
	}
    }
    return n;
}


static URI_TUPLE
parse_tuple( byte *string )
{
    byte *p = string;
    byte *p2;
    int n;
    URI_TUPLE tuple;

    if( (p2 = strchr( p, '=' )) )
	*p2++ = 0;
    if( (n = remove_escapes( p )) < 0 )
	return NULL; /* bad URI */
    if( n != strlen( p ) )
       return NULL; /* name with a Nul in it */
    tuple = xmalloc_clear( sizeof *tuple );
    tuple->name = p;
    if( !p2 )  {
	/* we have only the name, so we assume an empty value string */
	tuple->value = p + strlen(p);
	tuple->valuelen = 0;
    }
    else { /* name and value */
	if( (n = remove_escapes( p2 )) < 0 ) {
	    xfree( tuple );
	    return NULL; /* bad URI */
	}
	tuple->value = p2;
	tuple->valuelen = n;
    }
    return tuple;
}


/****************
 * Send a HTTP request to the server
 * Returns 0 if the request was successful
 */
static int
send_request( HTTP_HD hd, const char *auth, const char *proxy )
{
    const byte *server;
    byte *request, *p;
    ushort port;
    int rc;
    char *proxy_authstr=NULL,*authstr=NULL;

    server = *hd->uri->host? hd->uri->host : "localhost";
    port   = hd->uri->port?  hd->uri->port : 80;

    if(proxy && *proxy)
      {
	PARSED_URI uri;

	rc = parse_uri( &uri, proxy );
	if (rc)
	  {
	    log_error("invalid HTTP proxy (%s): %s\n",proxy,g10_errstr(rc));
	    release_parsed_uri( uri );
	    return G10ERR_NETWORK;
	  }
	hd->sock = connect_server( *uri->host? uri->host : "localhost",
				   uri->port? uri->port : 80, 0, NULL );
	if(uri->auth)
	  {
	    char *x;
	    remove_escapes(uri->auth);
	    x=make_radix64_string(uri->auth,strlen(uri->auth));
	    proxy_authstr=xmalloc(52+strlen(x));
	    sprintf(proxy_authstr,"Proxy-Authorization: Basic %s\r\n",x);
	    xfree(x);
	  }

	release_parsed_uri( uri );
      }
    else
      hd->sock = connect_server( server, port, hd->flags, hd->uri->scheme );

    if(auth || hd->uri->auth)
      {
	char *x,*tempauth=NULL;

	if(auth)
	  {
	    tempauth=xstrdup(auth);
	    remove_escapes(tempauth);
	  }
	else if(hd->uri->auth)
	  remove_escapes(hd->uri->auth);

	x=make_radix64_string(tempauth?tempauth:hd->uri->auth,
			      strlen(tempauth?tempauth:hd->uri->auth));
	authstr=xmalloc(52+strlen(x));
	sprintf(authstr,"Authorization: Basic %s\r\n",x);
	xfree(x);
	xfree(tempauth);
      }

    if( hd->sock == -1 )
	return G10ERR_NETWORK;

    p = build_rel_path( hd->uri );

    request=xmalloc(strlen(server)*2 + strlen(p)
		    + (authstr?strlen(authstr):0)
		    + (proxy_authstr?strlen(proxy_authstr):0) + 65);
    if( proxy && *proxy )
      sprintf( request, "%s http://%s:%hu%s%s HTTP/1.0\r\n%s%s",
	       hd->req_type == HTTP_REQ_GET ? "GET" :
	       hd->req_type == HTTP_REQ_HEAD? "HEAD":
	       hd->req_type == HTTP_REQ_POST? "POST": "OOPS",
	       server, port,  *p == '/'? "":"/", p,
	       authstr?authstr:"",proxy_authstr?proxy_authstr:"" );
    else
      {
	char portstr[15];

	if(port!=80)
	  sprintf(portstr,":%u",port);

	sprintf( request, "%s %s%s HTTP/1.0\r\nHost: %s%s\r\n%s",
		 hd->req_type == HTTP_REQ_GET ? "GET" :
		 hd->req_type == HTTP_REQ_HEAD? "HEAD":
		 hd->req_type == HTTP_REQ_POST? "POST": "OOPS",
		 *p == '/'? "":"/", p, server, (port!=80)?portstr:"",
		 authstr?authstr:"");
      }

    xfree(p);

    rc = write_server( hd->sock, request, strlen(request) );
    xfree( request );
    xfree(proxy_authstr);
    xfree(authstr);

    return rc;
}


/****************
 * Build the relative path from the parsed URI.
 * Minimal implementation.
 */
static byte*
build_rel_path( PARSED_URI uri )
{
    URI_TUPLE r;
    byte *rel_path, *p;
    int n;

    /* count the needed space */
    n = insert_escapes( NULL, uri->path, "%;?&" );
    /* todo: build params */
    for( r=uri->query; r; r = r->next ) {
	n++; /* '?'/'&' */
	n += insert_escapes( NULL, r->name, "%;?&=" );
	n++; /* '='*/
	n += insert_escapes( NULL, r->value, "%;?&=" );
    }
    n++;

    /* now  allocate and copy */
    p = rel_path = xmalloc( n );
    n = insert_escapes( p, uri->path, "%;?&" );
    p += n;
    /* todo: add params */
    for( r=uri->query; r; r = r->next ) {
	*p++ = r == uri->query? '?':'&';
	n = insert_escapes( p, r->name, "%;?&=" );
	p += n;
	*p++ = '=';
	/* todo: use valuelen */
	n = insert_escapes( p, r->value, "%;?&=" );
	p += n;
    }
    *p = 0;
    return rel_path;
}



/***********************
 * Parse the response from a server.
 * Returns: errorcode and sets some fileds in the handle
 */
static int
parse_response( HTTP_HD hd )
{
    byte *line, *p, *p2;
    unsigned maxlen, len;

    /* Wait for the status line */
    do {
	maxlen = MAX_LINELEN;
	len = iobuf_read_line( hd->fp_read, &hd->buffer,
					    &hd->buffer_size, &maxlen );
	line = hd->buffer;
	if( !maxlen )
	    return -1; /* line has been truncated */
	if( !len )
	    return -1; /* eof */
    } while( !*line  );

    if( (p = strchr( line, '/')) )
	*p++ = 0;
    if( !p || strcmp( line, "HTTP" ) )
	return 0; /* assume http 0.9 */

    if( (p2 = strpbrk( p, " \t" ) ) ) {
	*p2++ = 0;
	p2 += strspn( p2, " \t" );
    }
    if( !p2 )
	return 0; /* assume http 0.9 */
    p = p2;
    /* todo: add HTTP version number check here */
    if( (p2 = strpbrk( p, " \t" ) ) )
	*p2++ = 0;
    if( !isdigit(p[0]) || !isdigit(p[1]) || !isdigit(p[2]) || p[3] ) {
	 /* malformed HTTP statuscode - assume HTTP 0.9 */
	hd->is_http_0_9 = 1;
	hd->status_code = 200;
	return 0;
    }
    hd->status_code = atoi( p );

    /* skip all the header lines and wait for the empty line */
    do {
	maxlen = MAX_LINELEN;
	len = iobuf_read_line( hd->fp_read, &hd->buffer,
			       &hd->buffer_size, &maxlen );
	line = hd->buffer;
	/* we ignore truncated lines */
	if( !len )
	    return -1; /* eof */
	/* time lineendings */
	if( (*line == '\r' && line[1] == '\n') || *line == '\n' )
	    *line = 0;
    } while( len && *line  );

    return 0;
}

#ifdef TEST
static int
start_server()
{
    struct sockaddr_in mya;
    struct sockaddr_in peer;
    int fd, client;
    fd_set rfds;
    int addrlen;
    int i;

    if( (fd=socket(AF_INET,SOCK_STREAM, 0)) == -1 ) {
	log_error("socket() failed: %s\n", strerror(errno));
	return -1;
    }
    i = 1;
    if( setsockopt( fd, SOL_SOCKET, SO_REUSEADDR, (byte*)&i, sizeof(i) ) )
	log_info("setsockopt(SO_REUSEADDR) failed: %s\n", strerror(errno) );

    mya.sin_family=AF_INET;
    memset(&mya.sin_addr, 0, sizeof(mya.sin_addr));
    mya.sin_port=htons(11371);

    if( bind( fd, (struct sockaddr *)&mya, sizeof(mya)) ) {
	log_error("bind to port 11371 failed: %s\n", strerror(errno) );
	sock_close( fd );
	return -1;
    }

    if( listen( fd, 5 ) ) {
	log_error("listen failed: %s\n", strerror(errno) );
	sock_close( fd );
	return -1;
    }

    for(;;) {
	FD_ZERO(&rfds);
	FD_SET( fd, &rfds );

	if( select( fd+1, &rfds, NULL, NULL, NULL) <= 0 )
	    continue; /* ignore any errors */

	if( !FD_ISSET( fd, &rfds ) )
	    continue;

	addrlen = sizeof peer;
	client = accept( fd, (struct sockaddr *)&peer, &addrlen);
	if( client == -1 )
	    continue; /* oops */

	log_info("connect from %s\n", inet_ntoa( peer.sin_addr ) );

	fflush(stdout);
	fflush(stderr);
	if( !fork() ) {
	    int c;
	    FILE *fp;

	    fp = fdopen( client , "r" );
	    while( (c=getc(fp)) != EOF )
		putchar(c);
	    fclose(fp);
	    exit(0);
	}
	sock_close( client );
    }


    return 0;
}
#endif


static int
connect_server( const char *server, ushort port, unsigned int flags,
		const char *srvtag )
{
  int sock=-1,srv,srvcount=0,connected=0,hostfound=0;
  struct srventry *srvlist=NULL;

#ifdef _WIN32
  unsigned long inaddr;

  init_sockets();
  /* Win32 gethostbyname doesn't handle IP addresses internally, so we
     try inet_addr first on that platform only. */
  if((inaddr=inet_addr(server))!=INADDR_NONE)
    {
      struct sockaddr_in addr;

      memset(&addr,0,sizeof(addr));

      if((sock=socket(AF_INET,SOCK_STREAM,0))==INVALID_SOCKET)
	{
	  log_error("error creating socket: ec=%d\n",(int)WSAGetLastError());
	  return -1;
	}

      addr.sin_family=AF_INET; 
      addr.sin_port=htons(port);
      memcpy(&addr.sin_addr,&inaddr,sizeof(inaddr));      

      if(connect(sock,(struct sockaddr *)&addr,sizeof(addr))==0)
	return sock;
      else
	{
	  sock_close(sock);
	  return -1;
	}
    }
#endif

#ifdef USE_DNS_SRV
  /* Do the SRV thing */
  if(flags&HTTP_FLAG_TRY_SRV && srvtag)
    {
      /* We're using SRV, so append the tags */
      if(1+strlen(srvtag)+6+strlen(server)+1<=MAXDNAME)
	{
	  char srvname[MAXDNAME];

	  strcpy(srvname,"_");
	  strcat(srvname,srvtag);
	  strcat(srvname,"._tcp.");
	  strcat(srvname,server);
	  srvcount=getsrv(srvname,&srvlist);
	}
    }
#endif

  if(srvlist==NULL)
    {
      /* Either we're not using SRV, or the SRV lookup failed.  Make
	 up a fake SRV record. */
      srvlist=xmalloc_clear(sizeof(struct srventry));
      srvlist->port=port;
      strncpy(srvlist->target,server,MAXDNAME);
      srvlist->target[MAXDNAME-1]='\0';
      srvcount=1;
    }

#ifdef HAVE_GETADDRINFO

  for(srv=0;srv<srvcount;srv++)
    {
      struct addrinfo hints,*res,*ai;
      char portstr[6];

      sprintf(portstr,"%u",srvlist[srv].port);
      memset(&hints,0,sizeof(hints));
      hints.ai_socktype=SOCK_STREAM;
      if(getaddrinfo(srvlist[srv].target,portstr,&hints,&res)==0)
	hostfound=1;
      else
	continue;

      for(ai=res;ai;ai=ai->ai_next)
	{
	  if((sock=socket(ai->ai_family,ai->ai_socktype,ai->ai_protocol))==-1)
	    {
	      log_error("error creating socket: %s\n",strerror(errno));
	      freeaddrinfo(res);
	      return -1;
	    }

	  if(connect(sock,ai->ai_addr,ai->ai_addrlen)==0)
	    {
	      connected=1;
	      break;
	    }

	  sock_close(sock);
	}

      freeaddrinfo(res);

      if(ai)
	break;
    }

#else /* !HAVE_GETADDRINFO */

  for(srv=0;srv<srvcount;srv++)
    {
      int i=0;
      struct hostent *host=NULL;
      struct sockaddr_in addr;

      memset(&addr,0,sizeof(addr));

      if((host=gethostbyname(srvlist[srv].target))==NULL)
	continue;

      hostfound=1;

      if((sock=socket(host->h_addrtype,SOCK_STREAM,0))==-1)
	{
	  log_error("error creating socket: %s\n",strerror(errno));
	  return -1;
	}

      addr.sin_family=host->h_addrtype;
      if(addr.sin_family!=AF_INET)
	{
	  log_error("%s: unknown address family\n",srvlist[srv].target);
	  return -1;
	}

      addr.sin_port=htons(srvlist[srv].port);

      /* Try all A records until one responds. */
      while(host->h_addr_list[i])
	{
	  if(host->h_length!=4)
	    {
	      log_error("%s: illegal address length\n",srvlist[srv].target);
	      return -1;
	    }

	  memcpy(&addr.sin_addr,host->h_addr_list[i],host->h_length);

	  if(connect(sock,(struct sockaddr *)&addr,sizeof(addr))==0)
	    {
	      connected=1;
	      break;
	    }

	  i++;
	}

      if(host->h_addr_list[i])
	break;

      sock_close(sock);
    }
#endif /* !HAVE_GETADDRINFO */

  xfree(srvlist);

  if(!connected)
    {
      int err=errno;
#ifdef _WIN32
      if(hostfound)
	log_error("%s: Unable to connect: ec=%d\n",server,(int)WSAGetLastError());
      else
	log_error("%s: Host not found: ec=%d\n",server,(int)WSAGetLastError());
#else
      if(hostfound)
	log_error("%s: %s\n",server,strerror(err));
      else
	log_error("%s: Host not found\n",server);
#endif
      if(sock!=-1)
	sock_close(sock);
      errno=err;
      return -1;
    }

  return sock;
}


static int
write_server( int sock, const char *data, size_t length )
{
    int nleft;

    nleft = length;
    while( nleft > 0 ) {
#ifdef _WIN32  
        int nwritten;

        nwritten = send (sock, data, nleft, 0);
        if ( nwritten == SOCKET_ERROR ) {
	    log_info ("write failed: ec=%d\n", (int)WSAGetLastError ());
	    return G10ERR_NETWORK;
        }
#else
	int nwritten = write( sock, data, nleft );
	if( nwritten == -1 ) {
	    if( errno == EINTR )
		continue;
	    if( errno == EAGAIN ) {
		struct timeval tv;

		tv.tv_sec =  0;
		tv.tv_usec = 50000;
		select(0, NULL, NULL, NULL, &tv);
		continue;
	    }
	    log_info("write failed: %s\n", strerror(errno));
	    return G10ERR_NETWORK;
	}
#endif
	nleft -=nwritten;
	data += nwritten;
    }

    return 0;
}

/**** Test code ****/
#ifdef TEST

int
main(int argc, char **argv)
{
    int rc;
    PARSED_URI uri;
    URI_TUPLE r;
    struct http_context hd;
    int c;

    log_set_name("http-test");
    if( argc == 1 ) {
	start_server();
	return 0;
    }

    if( argc != 2 ) {
	fprintf(stderr,"usage: http-test uri\n");
	return 1;
    }
    argc--; argv++;

    rc = parse_uri( &uri, *argv );
    if( rc ) {
	log_error("`%s': %s\n", *argv, g10_errstr(rc));
	release_parsed_uri( uri );
	return 1;
    }

    printf("Scheme: %s\n", uri->scheme );
    printf("Host  : %s\n", uri->host );
    printf("Port  : %u\n", uri->port );
    printf("Path  : %s\n", uri->path );
    for( r=uri->params; r; r = r->next ) {
	printf("Params: %s=%s", r->name, r->value );
	if( strlen( r->value ) != r->valuelen )
	    printf(" [real length=%d]", (int)r->valuelen );
	putchar('\n');
    }
    for( r=uri->query; r; r = r->next ) {
	printf("Query : %s=%s", r->name, r->value );
	if( strlen( r->value ) != r->valuelen )
	    printf(" [real length=%d]", (int)r->valuelen );
	putchar('\n');
    }
    release_parsed_uri( uri ); uri = NULL;

    rc = http_open_document( &hd, *argv, 0, NULL );
    if( rc ) {
	log_error("can't get `%s': %s\n", *argv, g10_errstr(rc));
	return 1;
    }
    log_info("open_http_document succeeded; status=%u\n", hd.status_code );
    while( (c=iobuf_get( hd.fp_read)) != -1 )
	putchar(c);
    http_close( &hd );
    return 0;
}
#endif /*TEST*/
