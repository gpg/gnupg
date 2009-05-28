/* http.c  -  HTTP protocol handler
 * Copyright (C) 1999, 2001, 2002, 2003, 2004, 2006,
 *               2009 Free Software Foundation, Inc.
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

/* Simple HTTP client implementation.  We try to keep the code as
   self-contained as possible.  There are some contraints however:

  - stpcpy is required
  - fixme: list other requirements.


  - With HTTP_USE_ESTREAM defined, all I/O is done through estream.
  - With HTTP_USE_GNUTLS support for https is provided (this also
    requires estream).
  - With HTTP_NO_WSASTARTUP the socket initialization is not done
    under Windows.  This is useful if the socket layer has already
    been initialized elsewhere.  This also avoids the installation of
    an exit handler to cleanup the socket layer.
*/

#ifdef HAVE_CONFIG_H
# include <config.h>
#endif
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <ctype.h>
#include <errno.h>
#include <unistd.h>

#ifdef HAVE_W32_SYSTEM
# include <windows.h>
#else /*!HAVE_W32_SYSTEM*/
# include <sys/types.h>
# include <sys/socket.h>
# include <sys/time.h>
# include <time.h>
# include <netinet/in.h>
# include <arpa/inet.h>
# include <netdb.h>
#endif /*!HAVE_W32_SYSTEM*/

#ifdef HTTP_USE_GNUTLS
# include <gnutls/gnutls.h>
/* For non-understandable reasons GNUTLS dropped the _t suffix from
   all types. yes, ISO-C might be read as this but there are still
   other name space conflicts and using _t is actually a Good
   Thing. */
typedef gnutls_session gnutls_session_t;
typedef gnutls_transport_ptr gnutls_transport_ptr_t;
#endif /*HTTP_USE_GNUTLS*/

#ifdef TEST
#undef USE_DNS_SRV
#endif

#include "util.h"
#include "i18n.h"
#include "http.h"
#ifdef USE_DNS_SRV
#include "srv.h"
#else /*!USE_DNS_SRV*/
/* If we are not compiling with SRV record support we provide stub
   data structures. */
#ifndef MAXDNAME
#define MAXDNAME 1025
#endif
struct srventry
{
  unsigned short priority;
  unsigned short weight;
  unsigned short port;
  int run_count;
  char target[MAXDNAME];
};
#endif/*!USE_DNS_SRV*/


#ifdef HAVE_W32_SYSTEM
#define sock_close(a)  closesocket(a)
#else
#define sock_close(a)  close(a)
#endif

#ifndef EAGAIN
#define EAGAIN  EWOULDBLOCK
#endif

#define HTTP_PROXY_ENV           "http_proxy"
#define MAX_LINELEN 20000  /* Max. length of a HTTP header line. */
#define VALID_URI_CHARS "abcdefghijklmnopqrstuvwxyz"   \
                        "ABCDEFGHIJKLMNOPQRSTUVWXYZ"   \
                        "01234567890@"                 \
                        "!\"#$%&'()*+,-./:;<=>?[\\]^_{|}~"

/* Define a prefix to map stream functions to the estream library. */
#ifdef HTTP_USE_ESTREAM
#define P_ES(a)  es_ ## a
#else
#define P_ES(a)  a
#endif
#ifndef HTTP_USE_GNUTLS
typedef void * gnutls_session_t;
#endif
#if defined(HTTP_USE_GNUTLS) && !defined(HTTP_USE_ESTREAM)
#error Use of GNUTLS also requires support for Estream
#endif

static gpg_error_t do_parse_uri (parsed_uri_t uri, int only_local_part);
static int remove_escapes (char *string);
static int insert_escapes (char *buffer, const char *string,
                           const char *special);
static uri_tuple_t parse_tuple (char *string);
static gpg_error_t send_request (http_t hd, const char *auth,const char *proxy,
				 const char *srvtag,strlist_t headers);
static char *build_rel_path (parsed_uri_t uri);
static gpg_error_t parse_response (http_t hd);

static int connect_server (const char *server, unsigned short port,
                           unsigned int flags, const char *srvtag);
static gpg_error_t write_server (int sock, const char *data, size_t length);

#ifdef HTTP_USE_ESTREAM
static ssize_t cookie_read (void *cookie, void *buffer, size_t size);
static ssize_t cookie_write (void *cookie, const void *buffer, size_t size);
static int cookie_close (void *cookie);

static es_cookie_io_functions_t cookie_functions =
  {
    cookie_read,
    cookie_write,
    NULL,
    cookie_close
  };

struct cookie_s 
{
  int fd;  /* File descriptor or -1 if already closed. */
  gnutls_session_t tls_session;  /* TLS session context or NULL if not used. */
  int keep_socket; /* Flag to communicate with teh close handler. */
};
typedef struct cookie_s *cookie_t;

#endif /*HTTP_USE_ESTREAM*/

#ifdef HTTP_USE_GNUTLS
static gpg_error_t (*tls_callback) (http_t, gnutls_session_t, int);
#endif /*HTTP_USE_GNUTLS*/


/* An object to save header lines. */
struct header_s
{
  struct header_s *next;
  char *value;    /* The value of the header (malloced).  */
  char name[1];   /* The name of the header (canonicalized). */
};
typedef struct header_s *header_t;


/* Our handle context. */
struct http_context_s 
{
  unsigned int status_code;
  int sock;
  int in_data;
#ifdef HTTP_USE_ESTREAM
  estream_t fp_read;
  estream_t fp_write;
  void *write_cookie;
#else /*!HTTP_USE_ESTREAM*/
  FILE *fp_read;
  FILE *fp_write;
#endif /*!HTTP_USE_ESTREAM*/
  void *tls_context;
  int is_http_0_9;
  parsed_uri_t uri;
  http_req_t req_type;
  char *buffer;          /* Line buffer. */
  size_t buffer_size;
  unsigned int flags;
  header_t headers;      /* Received headers. */
};




#if defined(HAVE_W32_SYSTEM) && !defined(HTTP_NO_WSASTARTUP)

#if GNUPG_MAJOR_VERSION == 1
#define REQ_WINSOCK_MAJOR  1
#define REQ_WINSOCK_MINOR  1
#else
#define REQ_WINSOCK_MAJOR  2
#define REQ_WINSOCK_MINOR  2
#endif


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

  if ( WSAStartup( MAKEWORD (REQ_WINSOCK_MINOR, REQ_WINSOCK_MAJOR), &wsdata ) ) 
    {
      log_error ("error initializing socket library: ec=%d\n", 
                 (int)WSAGetLastError () );
      return;
    }
  if ( LOBYTE(wsdata.wVersion) != REQ_WINSOCK_MAJOR  
       || HIBYTE(wsdata.wVersion) != REQ_WINSOCK_MINOR ) 
    {
      log_error ("socket library version is %x.%x - but %d.%d needed\n",
                 LOBYTE(wsdata.wVersion), HIBYTE(wsdata.wVersion),
                 REQ_WINSOCK_MAJOR, REQ_WINSOCK_MINOR);
      WSACleanup();
      return;
    }
  atexit ( deinit_sockets );
  initialized = 1;
}
#endif /*HAVE_W32_SYSTEM && !HTTP_NO_WSASTARTUP*/



/*
 * Helper function to create an HTTP header with hex encoded data.  A
 * new buffer is returned.  This buffer is the concatenation of the
 * string PREFIX, the hex-encoded DATA of length LEN and the string
 * SUFFIX.  On error NULL is returned and ERRNO set.
 */
static char *
make_header_line (const char *prefix, const char *suffix,
                   const void *data, size_t len )
{
  static unsigned char bintoasc[] = 
    "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    "abcdefghijklmnopqrstuvwxyz"
    "0123456789+/";
  const unsigned int *s = data;
  char *buffer, *p;

  buffer = xtrymalloc (strlen (prefix) + (len+2)/3*4 + strlen (suffix) + 1);
  if (!buffer)
    return NULL;
  p = stpcpy (buffer, prefix);
  for ( ; len >= 3 ; len -= 3, s += 3 )
    {
      *p++ = bintoasc[(s[0] >> 2) & 077];
      *p++ = bintoasc[(((s[0] <<4)&060)|((s[1] >> 4)&017))&077];
      *p++ = bintoasc[(((s[1]<<2)&074)|((s[2]>>6)&03))&077];
      *p++ = bintoasc[s[2]&077];
    }
  if ( len == 2 ) 
    {
      *p++ = bintoasc[(s[0] >> 2) & 077];
      *p++ = bintoasc[(((s[0] <<4)&060)|((s[1] >> 4)&017))&077];
      *p++ = bintoasc[((s[1]<<2)&074)];
      *p++ = '=';
    }
  else if ( len == 1 )
    {
      *p++ = bintoasc[(s[0] >> 2) & 077];
      *p++ = bintoasc[(s[0] <<4)&060];
      *p++ = '=';
      *p++ = '=';
    }
  strcpy (p, suffix);
  return buffer;
}




void
http_register_tls_callback ( gpg_error_t (*cb) (http_t, void *, int) )
{
#ifdef HTTP_USE_GNUTLS
  tls_callback = (gpg_error_t (*) (http_t, gnutls_session_t, int))cb;
#else
  (void)cb;
#endif  
}



/* Start a HTTP retrieval and return on success in R_HD a context
   pointer for completing the the request and to wait for the
   response. */
gpg_error_t
http_open (http_t *r_hd, http_req_t reqtype, const char *url, 
           const char *auth, unsigned int flags, const char *proxy,
           void *tls_context, const char *srvtag,strlist_t headers)
{
  gpg_error_t err;
  http_t hd;
  
  *r_hd = NULL;

  if (!(reqtype == HTTP_REQ_GET || reqtype == HTTP_REQ_POST))
    return gpg_error (GPG_ERR_INV_ARG);

  /* Create the handle. */
  hd = xtrycalloc (1, sizeof *hd);
  if (!hd)
    return gpg_error_from_syserror ();
  hd->sock = -1;
  hd->req_type = reqtype;
  hd->flags = flags;
  hd->tls_context = tls_context;

  err = http_parse_uri (&hd->uri, url);
  if (!err)
    err = send_request (hd, auth, proxy, srvtag, headers);
  
  if (err)
    {
      if (!hd->fp_read && !hd->fp_write && hd->sock != -1)
        sock_close (hd->sock);
      if (hd->fp_read)
        P_ES(fclose) (hd->fp_read);
      if (hd->fp_write)
        P_ES(fclose) (hd->fp_write);
      http_release_parsed_uri (hd->uri);
      xfree (hd);
    }
  else
    *r_hd = hd;
  return err;
}


void
http_start_data (http_t hd)
{
  if (!hd->in_data)
    {
#ifdef HTTP_USE_ESTREAM
      es_fputs ("\r\n", hd->fp_write);
      es_fflush (hd->fp_write);
#else
      fflush (hd->fp_write);
      write_server (hd->sock, "\r\n", 2);
#endif
      hd->in_data = 1;
    }
  else
    P_ES(fflush) (hd->fp_write);
}


gpg_error_t
http_wait_response (http_t hd)
{
  gpg_error_t err;

  /* Make sure that we are in the data. */
  http_start_data (hd);	

  /* We dup the socket, to cope with the fact that fclose closes the
     underlying socket. In TLS mode we don't do that because we can't
     close the socket gnutls is working on; instead we make sure that
     the fclose won't close the socket in this case. */
#ifdef HTTP_USE_ESTREAM
  if (hd->write_cookie)
    {
      /* The write cookie is only set in the TLS case. */
      cookie_t cookie = hd->write_cookie;
      cookie->keep_socket = 1;
    }
  else
#endif /*HTTP_USE_ESTREAM*/
    {
#ifdef HAVE_W32_SYSTEM
      HANDLE handle = (HANDLE)hd->sock;
      if (!DuplicateHandle (GetCurrentProcess(), handle,
			    GetCurrentProcess(), &handle, 0,
			    TRUE, DUPLICATE_SAME_ACCESS ))
	return gpg_error_from_syserror ();
      hd->sock = (int)handle;
#else
      hd->sock = dup (hd->sock);
#endif
      if (hd->sock == -1)
        return gpg_error_from_syserror ();
    }
  P_ES(fclose) (hd->fp_write);
  hd->fp_write = NULL;
#ifdef HTTP_USE_ESTREAM
  hd->write_cookie = NULL;
#endif

  if (!(hd->flags & HTTP_FLAG_NO_SHUTDOWN))
    shutdown (hd->sock, 1);
  hd->in_data = 0;

#ifdef HTTP_USE_ESTREAM
  {
    cookie_t cookie;

    cookie = xtrycalloc (1, sizeof *cookie);
    if (!cookie)
      return gpg_error_from_syserror ();
    cookie->fd = hd->sock;
    if (hd->uri->use_tls)
      cookie->tls_session = hd->tls_context;

    hd->fp_read = es_fopencookie (cookie, "r", cookie_functions);
    if (!hd->fp_read)
      {
        xfree (cookie);
        return gpg_error_from_syserror ();
      }
  }
#else /*!HTTP_USE_ESTREAM*/
  hd->fp_read = fdopen (hd->sock, "r");
  if (!hd->fp_read)
    return gpg_error_from_syserror ();
#endif /*!HTTP_USE_ESTREAM*/

  err = parse_response (hd);
  return err;
}


/* Convenience function to send a request and wait for the response.
   Closes the handle on error.  If PROXY is not NULL, this value will
   be used as an HTTP proxy and any enabled $http_proxy gets
   ignored. */
gpg_error_t
http_open_document (http_t *r_hd, const char *document, 
                    const char *auth, unsigned int flags, const char *proxy,
                    void *tls_context, const char *srvtag,strlist_t headers)
{
  gpg_error_t err;

  err = http_open (r_hd, HTTP_REQ_GET, document, auth, flags,
                   proxy, tls_context, srvtag, headers);
  if (err)
    return err;

  err = http_wait_response (*r_hd);
  if (err)
    http_close (*r_hd, 0);

  return err;
}


void
http_close (http_t hd, int keep_read_stream)
{
  if (!hd)
    return;
  if (!hd->fp_read && !hd->fp_write && hd->sock != -1)
    sock_close (hd->sock);
  if (hd->fp_read && !keep_read_stream)
    P_ES(fclose) (hd->fp_read);
  if (hd->fp_write)
    P_ES(fclose) (hd->fp_write);
  http_release_parsed_uri (hd->uri);
  while (hd->headers)
    {
      header_t tmp = hd->headers->next;
      xfree (hd->headers->value);
      xfree (hd->headers);
      hd->headers = tmp;
    }
  xfree (hd->buffer);
  xfree (hd);
}


#ifdef HTTP_USE_ESTREAM
estream_t
http_get_read_ptr (http_t hd)
{
  return hd?hd->fp_read:NULL;
}
estream_t
http_get_write_ptr (http_t hd)
{
  return hd?hd->fp_write:NULL;
}
#else /*!HTTP_USE_ESTREAM*/
FILE *
http_get_read_ptr (http_t hd)
{
  return hd?hd->fp_read:NULL;
}
FILE *
http_get_write_ptr (http_t hd)
{
  return hd?hd->fp_write:NULL;
}
#endif /*!HTTP_USE_ESTREAM*/
unsigned int
http_get_status_code (http_t hd)
{
  return hd?hd->status_code:0;
}



/*
 * Parse an URI and put the result into the newly allocated RET_URI.
 * The caller must always use release_parsed_uri() to releases the
 * resources (even on error).
 */
gpg_error_t
http_parse_uri (parsed_uri_t * ret_uri, const char *uri)
{
  *ret_uri = xcalloc (1, sizeof **ret_uri + strlen (uri));
  strcpy ((*ret_uri)->buffer, uri);
  return do_parse_uri (*ret_uri, 0);
}

void
http_release_parsed_uri (parsed_uri_t uri)
{
  if (uri)
    {
      uri_tuple_t r, r2;

      for (r = uri->query; r; r = r2)
	{
	  r2 = r->next;
	  xfree (r);
	}
      xfree (uri);
    }
}


static gpg_error_t
do_parse_uri (parsed_uri_t uri, int only_local_part)
{
  uri_tuple_t *tail;
  char *p, *p2, *p3, *pp;
  int n;

  p = uri->buffer;
  n = strlen (uri->buffer);

  /* Initialize all fields to an empty string or an empty list. */
  uri->scheme = uri->host = uri->path = p + n;
  uri->port = 0;
  uri->params = uri->query = NULL;
  uri->use_tls = 0;

  /* A quick validity check. */
  if (strspn (p, VALID_URI_CHARS) != n)
    return gpg_error (GPG_ERR_BAD_URI);	/* Invalid characters found. */

  if (!only_local_part)
    {
      /* Find the scheme. */
      if (!(p2 = strchr (p, ':')) || p2 == p)
	return gpg_error (GPG_ERR_BAD_URI); /* No scheme. */
      *p2++ = 0;
      for (pp=p; *pp; pp++)
       *pp = tolower (*(unsigned char*)pp);
      uri->scheme = p;
      if (!strcmp (uri->scheme, "http"))
        uri->port = 80;
#ifdef HTTP_USE_GNUTLS
      else if (!strcmp (uri->scheme, "https"))
        {
          uri->port = 443;
          uri->use_tls = 1;
        }
#endif
      else
	return gpg_error (GPG_ERR_INV_URI); /* Unsupported scheme */

      p = p2;

      /* Find the hostname */
      if (*p != '/')
	return gpg_error (GPG_ERR_INV_URI); /* Does not start with a slash. */

      p++;
      if (*p == '/') /* There seems to be a hostname. */
	{ 
	  p++;
	  if ((p2 = strchr (p, '/')))
	    *p2++ = 0;

          /* Check for username/password encoding */
          if ((p3 = strchr (p, '@')))
            {
              uri->auth = p;
              *p3++ = '\0';
              p = p3;
            }

          for (pp=p; *pp; pp++)
            *pp = tolower (*(unsigned char*)pp);

	  /* Handle an IPv6 literal */
	  if( *p == '[' && (p3=strchr( p, ']' )) )
	    {
	      *p3++ = '\0';
	      /* worst case, uri->host should have length 0, points to \0 */
	      uri->host = p + 1;
	      p = p3;
	    }
	  else
	    uri->host = p;

	  if ((p3 = strchr (p, ':')))
	    {
	      *p3++ = '\0';
	      uri->port = atoi (p3);
	    }

	  if ((n = remove_escapes (uri->host)) < 0)
	    return gpg_error (GPG_ERR_BAD_URI);
	  if (n != strlen (uri->host))
	    return gpg_error (GPG_ERR_BAD_URI);	/* Hostname incudes a Nul. */
	  p = p2 ? p2 : NULL;
	}
    } /* End global URI part. */

  /* Parse the pathname part */
  if (!p || !*p)
    return 0;  /* We don't have a path.  Okay. */

  /* TODO: Here we have to check params. */

  /* Do we have a query part? */
  if ((p2 = strchr (p, '?')))
    *p2++ = 0;

  uri->path = p;
  if ((n = remove_escapes (p)) < 0)
    return gpg_error (GPG_ERR_BAD_URI);
  if (n != strlen (p))
    return gpg_error (GPG_ERR_BAD_URI);	/* Path includes a Nul. */
  p = p2 ? p2 : NULL;

  if (!p || !*p)	
    return 0; /* We don't have a query string.  Okay. */

  /* Now parse the query string. */
  tail = &uri->query;
  for (;;)
    {
      uri_tuple_t elem;

      if ((p2 = strchr (p, '&')))
	*p2++ = 0;
      if (!(elem = parse_tuple (p)))
	return gpg_error (GPG_ERR_BAD_URI);
      *tail = elem;
      tail = &elem->next;

      if (!p2)
	break; /* Ready. */
      p = p2;
    }

  return 0;
}


/*
 * Remove all %xx escapes; this is done in-place.  Returns: New length
 * of the string.
 */
static int
remove_escapes (char *string)
{
  int n = 0;
  unsigned char *p, *s;

  for (p = s = (unsigned char*)string; *s; s++)
    {
      if (*s == '%')
	{
	  if (s[1] && s[2] && isxdigit (s[1]) && isxdigit (s[2]))
	    {
	      s++;
	      *p = *s >= '0' && *s <= '9' ? *s - '0' :
		*s >= 'A' && *s <= 'F' ? *s - 'A' + 10 : *s - 'a' + 10;
	      *p <<= 4;
	      s++;
	      *p |= *s >= '0' && *s <= '9' ? *s - '0' :
		*s >= 'A' && *s <= 'F' ? *s - 'A' + 10 : *s - 'a' + 10;
	      p++;
	      n++;
	    }
	  else
	    {
	      *p++ = *s++;
	      if (*s)
		*p++ = *s++;
	      if (*s)
		*p++ = *s++;
	      if (*s)
		*p = 0;
	      return -1; /* Bad URI. */
	    }
	}
      else
	{
	  *p++ = *s;
	  n++;
	}
    }
  *p = 0; /* Make sure to keep a string terminator. */
  return n;
}


static int
insert_escapes (char *buffer, const char *string,
		const char *special)
{
  const unsigned char *s = (const unsigned char*)string;
  int n = 0;

  for (; *s; s++)
    {
      if (strchr (VALID_URI_CHARS, *s) && !strchr (special, *s))
	{
	  if (buffer)
	    *(unsigned char*)buffer++ = *s;
	  n++;
	}
      else
	{
	  if (buffer)
	    {
	      sprintf (buffer, "%%%02X", *s);
	      buffer += 3;
	    }
	  n += 3;
	}
    }
  return n;
}


/* Allocate a new string from STRING using standard HTTP escaping as
   well as escaping of characters given in SPECIALS.  A common pattern
   for SPECIALS is "%;?&=". However it depends on the needs, for
   example "+" and "/: often needs to be escaped too.  Returns NULL on
   failure and sets ERRNO. */
char *
http_escape_string (const char *string, const char *specials)
{
  int n;
  char *buf;

  n = insert_escapes (NULL, string, specials);
  buf = xtrymalloc (n+1);
  if (buf)
    {
      insert_escapes (buf, string, specials);
      buf[n] = 0;
    }
  return buf;
}



static uri_tuple_t
parse_tuple (char *string)
{
  char *p = string;
  char *p2;
  int n;
  uri_tuple_t tuple;

  if ((p2 = strchr (p, '=')))
    *p2++ = 0;
  if ((n = remove_escapes (p)) < 0)
    return NULL; /* Bad URI. */
  if (n != strlen (p))
    return NULL; /* Name with a Nul in it. */
  tuple = xtrycalloc (1, sizeof *tuple);
  if (!tuple)
    return NULL; /* Out of core. */
  tuple->name = p;
  if (!p2) /* We have only the name, so we assume an empty value string. */
    {
      tuple->value = p + strlen (p);
      tuple->valuelen = 0;
      tuple->no_value = 1; /* Explicitly mark that we have seen no '='. */
    }
  else /* Name and value. */
    {
      if ((n = remove_escapes (p2)) < 0)
	{
	  xfree (tuple);
	  return NULL; /* Bad URI. */
	}
      tuple->value = p2;
      tuple->valuelen = n;
    }
  return tuple;
}


/*
 * Send a HTTP request to the server
 * Returns 0 if the request was successful
 */
static gpg_error_t
send_request (http_t hd, const char *auth,
	      const char *proxy,const char *srvtag,strlist_t headers)
{
  gnutls_session_t tls_session;
  gpg_error_t err;
  const char *server;
  char *request, *p;
  unsigned short port;
  const char *http_proxy = NULL;
  char *proxy_authstr = NULL;
  char *authstr = NULL;
  int save_errno;

  tls_session = hd->tls_context;
  if (hd->uri->use_tls && !tls_session)
    {
      log_error ("TLS requested but no GNUTLS context provided\n");
      return gpg_error (GPG_ERR_INTERNAL);
    }

  server = *hd->uri->host ? hd->uri->host : "localhost";
  port = hd->uri->port ? hd->uri->port : 80;

  if ( (proxy && *proxy)
       || ( (hd->flags & HTTP_FLAG_TRY_PROXY)
            && (http_proxy = getenv (HTTP_PROXY_ENV)) 
            && *http_proxy ))
    {
      parsed_uri_t uri;

      if (proxy)
	http_proxy = proxy;

      err = http_parse_uri (&uri, http_proxy);
      if (err)
	{
	  log_error ("invalid HTTP proxy (%s): %s\n",
		     http_proxy, gpg_strerror (err));
	  http_release_parsed_uri (uri);
	  return gpg_error (GPG_ERR_CONFIGURATION);

	}

      if (uri->auth)
        {
          remove_escapes (uri->auth);
          proxy_authstr = make_header_line ("Proxy-Authorization: Basic ",
                                            "\r\n",
                                            uri->auth, strlen(uri->auth));
          if (!proxy_authstr)
            {
              err = gpg_error_from_syserror ();
              http_release_parsed_uri (uri);
              return err;
            }
        }

      hd->sock = connect_server (*uri->host ? uri->host : "localhost",
				 uri->port ? uri->port : 80,
                                 hd->flags, srvtag);
      save_errno = errno;
      http_release_parsed_uri (uri);
    }
  else
    {
      hd->sock = connect_server (server, port, hd->flags, srvtag);
      save_errno = errno;
    }

  if (hd->sock == -1)
    {
      xfree (proxy_authstr);
      return (save_errno 
              ? gpg_error_from_errno (save_errno)
              : gpg_error (GPG_ERR_NOT_FOUND));
    }

#ifdef HTTP_USE_GNUTLS
  if (hd->uri->use_tls)
    {
      int rc;

      gnutls_transport_set_ptr (tls_session, (gnutls_transport_ptr_t)hd->sock);
      do
        {
          rc = gnutls_handshake (tls_session);
        }
      while (rc == GNUTLS_E_INTERRUPTED || rc == GNUTLS_E_AGAIN);
      if (rc < 0)
        {
          log_info ("TLS handshake failed: %s\n", gnutls_strerror (rc));
          xfree (proxy_authstr);
          return gpg_error (GPG_ERR_NETWORK);
        }

      if (tls_callback)
        {
          err = tls_callback (hd, tls_session, 0);
          if (err)
            {
              log_info ("TLS connection authentication failed: %s\n",
                        gpg_strerror (err));
              xfree (proxy_authstr);
              return err;
            }
        }
    }
#endif /*HTTP_USE_GNUTLS*/

  if (auth || hd->uri->auth)
    {
      char *myauth;
      
      if (auth)
        {
          myauth = xtrystrdup (auth);
          if (!myauth)
            {
              xfree (proxy_authstr);
              return gpg_error_from_syserror ();
            }
          remove_escapes (myauth);
        }
      else
        {
          remove_escapes (hd->uri->auth);
          myauth = hd->uri->auth;
        }

      authstr = make_header_line ("Authorization: Basic %s", "\r\n",
                                  myauth, strlen (myauth));
      if (auth)
        xfree (myauth);

      if (!authstr)
        {
          xfree (proxy_authstr);
          return gpg_error_from_syserror ();
        }
    }
  
  p = build_rel_path (hd->uri);
  if (!p)
    return gpg_error_from_syserror ();

  request = xtrymalloc (2 * strlen (server) 
                        + strlen (p)
                        + (authstr?strlen(authstr):0)
                        + (proxy_authstr?strlen(proxy_authstr):0)
                        + 100);
  if (!request)
    {
      err = gpg_error_from_syserror ();
      xfree (p);
      xfree (authstr);
      xfree (proxy_authstr);
      return err;
    }

  if (http_proxy && *http_proxy)
    {
      sprintf (request, "%s http://%s:%hu%s%s HTTP/1.0\r\n%s%s",
	       hd->req_type == HTTP_REQ_GET ? "GET" :
	       hd->req_type == HTTP_REQ_HEAD ? "HEAD" :
	       hd->req_type == HTTP_REQ_POST ? "POST" : "OOPS",
	       server, port, *p == '/' ? "" : "/", p,
	       authstr ? authstr : "",
               proxy_authstr ? proxy_authstr : "");
    }
  else
    {
      char portstr[35];
        
      if (port == 80)
        *portstr = 0;
      else
        sprintf (portstr, ":%u", port);

      sprintf (request, "%s %s%s HTTP/1.0\r\nHost: %s%s\r\n%s",
	       hd->req_type == HTTP_REQ_GET ? "GET" :
	       hd->req_type == HTTP_REQ_HEAD ? "HEAD" :
	       hd->req_type == HTTP_REQ_POST ? "POST" : "OOPS",
	       *p == '/' ? "" : "/", p, server, portstr,
               authstr? authstr:"");
    }
  xfree (p);


#ifdef HTTP_USE_ESTREAM
  /* First setup estream so that we can write even the first line
     using estream.  This is also required for the sake of gnutls. */
  {
    cookie_t cookie;

    cookie = xtrycalloc (1, sizeof *cookie);
    if (!cookie)
      {
        err = gpg_error_from_syserror ();
        goto leave;
      }
    cookie->fd = hd->sock;
    if (hd->uri->use_tls)
      {
        cookie->tls_session = tls_session;
        hd->write_cookie = cookie;
      }

    hd->fp_write = es_fopencookie (cookie, "w", cookie_functions);
    if (!hd->fp_write)
      {
        xfree (cookie);
        err = gpg_error_from_syserror ();
      }
    else if (es_fputs (request, hd->fp_write) || es_fflush (hd->fp_write))
      err = gpg_error_from_syserror ();
    else
      err = 0;

  if(err==0)
    for(;headers;headers=headers->next)
      {
	if ((es_fputs (headers->d, hd->fp_write) || es_fflush (hd->fp_write))
	    || (es_fputs("\r\n",hd->fp_write) || es_fflush(hd->fp_write)))
	  {
	    err = gpg_error_from_syserror ();
	    break;
	  }
      }
  }

 leave:

#else /*!HTTP_USE_ESTREAM*/
  /* We send out the start of the request through our own send
     function and only then assign a stdio stream.  This allows for
     better error reporting that through standard stdio means. */
  err = write_server (hd->sock, request, strlen (request));

  if(err==0)
    for(;headers;headers=headers->next)
      {
	err = write_server( hd->sock, headers->d, strlen(headers->d) );
	if(err)
	  break;
	err = write_server( hd->sock, "\r\n", 2 );
	if(err)
	  break;
      }

  if (!err)
    {
      hd->fp_write = fdopen (hd->sock, "w");
      if (!hd->fp_write)
        err = gpg_error_from_syserror ();
    }

#endif /*!HTTP_USE_ESTREAM*/

  xfree (request);
  xfree (authstr);
  xfree (proxy_authstr);

  return err;
}


/*
 * Build the relative path from the parsed URI.  Minimal
 * implementation.  May return NULL in case of memory failure; errno
 * is then set accordingly.
 */
static char *
build_rel_path (parsed_uri_t uri)
{
  uri_tuple_t r;
  char *rel_path, *p;
  int n;

  /* Count the needed space. */
  n = insert_escapes (NULL, uri->path, "%;?&");
  /* TODO: build params. */
  for (r = uri->query; r; r = r->next)
    {
      n++; /* '?'/'&' */
      n += insert_escapes (NULL, r->name, "%;?&=");
      if (!r->no_value)
	{
	  n++; /* '=' */
	  n += insert_escapes (NULL, r->value, "%;?&=");
	}
    }
  n++;

  /* Now allocate and copy. */
  p = rel_path = xtrymalloc (n);
  if (!p)
    return NULL;
  n = insert_escapes (p, uri->path, "%;?&");
  p += n;
  /* TODO: add params. */
  for (r = uri->query; r; r = r->next)
    {
      *p++ = r == uri->query ? '?' : '&';
      n = insert_escapes (p, r->name, "%;?&=");
      p += n;
      if (!r->no_value)
	{
	  *p++ = '=';
	  /* TODO: Use valuelen. */
	  n = insert_escapes (p, r->value, "%;?&=");
	  p += n;
	}
    }
  *p = 0;
  return rel_path;
}



/*
   Same as fgets() but if the buffer is too short a larger one will be
   allocated up to some limit *MAX_LENGTH.  A line is considered a
   byte stream ending in a LF.  Returns the length of the line. EOF is
   indicated by a line of length zero. The last LF may be missing due
   to an EOF.  If MAX_LENGTH is zero on return, the line has been
   truncated.  If the returned buffer is NULL, not enough memory was
   enable to increase it, the return value will also be 0 and some
   bytes might have been lost which should be no problem becuase
   out-of-memory is pretty fatal for most applications.

   If a line has been truncated, the file pointer is internally moved
   forward to the end of the line.

   Note: The returned buffer is allocated with enough extra space to
   append a CR,LF,Nul
 */
static size_t
my_read_line (
#ifdef HTTP_USE_ESTREAM
              estream_t fp,
#else
              FILE *fp,
#endif
              char **addr_of_buffer,
              size_t *length_of_buffer, size_t *max_length)
{
  int c;
  char *buffer = *addr_of_buffer;
  size_t length = *length_of_buffer;
  size_t nbytes = 0;
  size_t maxlen = *max_length;
  char *p;

  if (!buffer) /* Must allocate a new buffer. */
    {		
      length = 256;
      buffer = xtrymalloc (length);
      *addr_of_buffer = buffer;
      if (!buffer)
	{
	  *length_of_buffer = *max_length = 0;
	  return 0;
	}
      *length_of_buffer = length;
    }

  length -= 3; /* Reserve 3 bytes (cr,lf,eol). */
  p = buffer;
  while ((c = P_ES(getc) (fp)) != EOF)
    {
      if (nbytes == length) /* Increase the buffer. */
	{			
	  if (length > maxlen) /* Limit reached. */
	    {
	      /* Skip the rest of the line. */
	      while (c != '\n' && (c = P_ES(getc) (fp)) != EOF)
		;
	      *p++ = '\n'; /* Always append a LF (we reserved some space). */
	      nbytes++;
	      *max_length = 0; /* Indicate truncation */
	      break; /*(the while loop)*/
	    }
	  length += 3; /* Adjust for the reserved bytes. */
	  length += length < 1024 ? 256 : 1024;
	  *addr_of_buffer = xtryrealloc (buffer, length);
	  if (!*addr_of_buffer)
	    {
	      int save_errno = errno;
	      xfree (buffer);
	      *length_of_buffer = *max_length = 0;
	      errno = save_errno;
	      return 0;
	    }
	  buffer = *addr_of_buffer;
	  *length_of_buffer = length;
	  length -= 3; /* And re-adjust for the reservation. */
	  p = buffer + nbytes;
	}
      *p++ = c;
      nbytes++;
      if (c == '\n')
	break;
    }
  *p = 0; /* Make sure the line is a string. */

  return nbytes;
}


/* Transform a header name into a standard capitalized format; e.g.
   "Content-Type".  Conversion stops at the colon.  As usual we don't
   use the localized versions of ctype.h. */
static void
capitalize_header_name (char *name)
{
  int first = 1;

  for (; *name && *name != ':'; name++)
    {
      if (*name == '-')
        first = 1;
      else if (first)
        {
          if (*name >= 'a' && *name <= 'z')
            *name = *name - 'a' + 'A';
          first = 0;
        }
      else if (*name >= 'A' && *name <= 'Z')
        *name = *name - 'A' + 'a';
    }
}


/* Store an HTTP header line in LINE away.  Line continuation is
   supported as well as merging of headers with the same name. This
   function may modify LINE. */
static gpg_error_t
store_header (http_t hd, char *line)
{
  size_t n;
  char *p, *value;
  header_t h;

  n = strlen (line);
  if (n && line[n-1] == '\n')
    {
      line[--n] = 0;
      if (n && line[n-1] == '\r')
        line[--n] = 0;
    }
  if (!n)  /* we are never called to hit this. */
    return gpg_error (GPG_ERR_BUG);
  if (*line == ' ' || *line == '\t')
    {
      /* Continuation. This won't happen too often as it is not
         recommended.  We use a straightforward implementaion. */
      if (!hd->headers)
        return gpg_error (GPG_ERR_PROTOCOL_VIOLATION);
      n += strlen (hd->headers->value);
      p = xtrymalloc (n+1);
      if (!p)
        return gpg_error_from_syserror ();
      strcpy (stpcpy (p, hd->headers->value), line);
      xfree (hd->headers->value);
      hd->headers->value = p;
      return 0;
    }

  capitalize_header_name (line);
  p = strchr (line, ':');
  if (!p)
    return gpg_error (GPG_ERR_PROTOCOL_VIOLATION);
  *p++ = 0;
  while (*p == ' ' || *p == '\t')
    p++;
  value = p;
  
  for (h=hd->headers; h; h = h->next)
    if ( !strcmp (h->name, line) )
      break;
  if (h)
    {
      /* We have already seen a line with that name.  Thus we assume
         it is a comma separated list and merge them.  */
      p = xtrymalloc (strlen (h->value) + 1 + strlen (value)+ 1);
      if (!p)
        return gpg_error_from_syserror ();
      strcpy (stpcpy (stpcpy (p, h->value), ","), value);
      xfree (h->value);
      h->value = p;
      return 0;
    }

  /* Append a new header. */
  h = xtrymalloc (sizeof *h + strlen (line));
  if (!h)
    return gpg_error_from_syserror ();
  strcpy (h->name, line);
  h->value = xtrymalloc (strlen (value)+1);
  if (!h->value)
    {
      xfree (h);
      return gpg_error_from_syserror ();
    }
  strcpy (h->value, value);
  h->next = hd->headers;
  hd->headers = h;

  return 0;
}


/* Return the header NAME from the last response.  The returned value
   is valid as along as HD has not been closed and no othe request has
   been send. If the header was not found, NULL is returned.  Name
   must be canonicalized, that is the first letter of each dash
   delimited part must be uppercase and all other letters lowercase.
   Note that the context must have been opened with the
   HTTP_FLAG_NEED_HEADER. */
const char *
http_get_header (http_t hd, const char *name)
{
  header_t h;

  for (h=hd->headers; h; h = h->next)
    if ( !strcmp (h->name, name) )
      return h->value;
  return NULL;
}



/*
 * Parse the response from a server.
 * Returns: Errorcode and sets some files in the handle
 */
static gpg_error_t
parse_response (http_t hd)
{
  char *line, *p, *p2;
  size_t maxlen, len;

  /* Delete old header lines.  */
  while (hd->headers)
    {
      header_t tmp = hd->headers->next;
      xfree (hd->headers->value);
      xfree (hd->headers);
      hd->headers = tmp;
    }

  /* Wait for the status line. */
  do
    {
      maxlen = MAX_LINELEN;
      len = my_read_line (hd->fp_read, &hd->buffer, &hd->buffer_size, &maxlen);
      line = hd->buffer;
      if (!line)
	return gpg_error_from_syserror (); /* Out of core. */
      if (!maxlen)
	return gpg_error (GPG_ERR_TRUNCATED); /* Line has been truncated. */
      if (!len)
	return gpg_error (GPG_ERR_EOF);
      if ( (hd->flags & HTTP_FLAG_LOG_RESP) )
        log_info ("RESP: `%.*s'\n",
                  (int)strlen(line)-(*line&&line[1]?2:0),line);
    }
  while (!*line);

  if ((p = strchr (line, '/')))
    *p++ = 0;
  if (!p || strcmp (line, "HTTP"))
    return 0; /* Assume http 0.9. */

  if ((p2 = strpbrk (p, " \t")))
    {
      *p2++ = 0;
      p2 += strspn (p2, " \t");
    }
  if (!p2)
    return 0; /* Also assume http 0.9. */
  p = p2;
  /* TODO: Add HTTP version number check. */
  if ((p2 = strpbrk (p, " \t")))
    *p2++ = 0;
  if (!isdigit ((unsigned int)p[0]) || !isdigit ((unsigned int)p[1])
      || !isdigit ((unsigned int)p[2]) || p[3])
    {
      /* Malformed HTTP status code - assume http 0.9. */
      hd->is_http_0_9 = 1;
      hd->status_code = 200;
      return 0;
    }
  hd->status_code = atoi (p);

  /* Skip all the header lines and wait for the empty line. */
  do
    {
      maxlen = MAX_LINELEN;
      len = my_read_line (hd->fp_read, &hd->buffer, &hd->buffer_size, &maxlen);
      line = hd->buffer;
      if (!line)
	return gpg_error_from_syserror (); /* Out of core. */
      /* Note, that we can silently ignore truncated lines. */
      if (!len)
	return gpg_error (GPG_ERR_EOF);
      /* Trim line endings of empty lines. */
      if ((*line == '\r' && line[1] == '\n') || *line == '\n')
	*line = 0;
      if ( (hd->flags & HTTP_FLAG_LOG_RESP) )
        log_info ("RESP: `%.*s'\n",
                  (int)strlen(line)-(*line&&line[1]?2:0),line);
      if ( (hd->flags & HTTP_FLAG_NEED_HEADER) && *line )
        {
          gpg_error_t err = store_header (hd, line);
          if (err)
            return err;
        }
    }
  while (len && *line);

  return 0;
}

#if 0
static int
start_server ()
{
  struct sockaddr_in mya;
  struct sockaddr_in peer;
  int fd, client;
  fd_set rfds;
  int addrlen;
  int i;

  if ((fd = socket (AF_INET, SOCK_STREAM, 0)) == -1)
    {
      log_error ("socket() failed: %s\n", strerror (errno));
      return -1;
    }
  i = 1;
  if (setsockopt (fd, SOL_SOCKET, SO_REUSEADDR, (byte *) & i, sizeof (i)))
    log_info ("setsockopt(SO_REUSEADDR) failed: %s\n", strerror (errno));

  mya.sin_family = AF_INET;
  memset (&mya.sin_addr, 0, sizeof (mya.sin_addr));
  mya.sin_port = htons (11371);

  if (bind (fd, (struct sockaddr *) &mya, sizeof (mya)))
    {
      log_error ("bind to port 11371 failed: %s\n", strerror (errno));
      sock_close (fd);
      return -1;
    }

  if (listen (fd, 5))
    {
      log_error ("listen failed: %s\n", strerror (errno));
      sock_close (fd);
      return -1;
    }

  for (;;)
    {
      FD_ZERO (&rfds);
      FD_SET (fd, &rfds);

      if (select (fd + 1, &rfds, NULL, NULL, NULL) <= 0)
	continue;		/* ignore any errors */

      if (!FD_ISSET (fd, &rfds))
	continue;

      addrlen = sizeof peer;
      client = accept (fd, (struct sockaddr *) &peer, &addrlen);
      if (client == -1)
	continue;		/* oops */

      log_info ("connect from %s\n", inet_ntoa (peer.sin_addr));

      fflush (stdout);
      fflush (stderr);
      if (!fork ())
	{
	  int c;
	  FILE *fp;

	  fp = fdopen (client, "r");
	  while ((c = getc (fp)) != EOF)
	    putchar (c);
	  fclose (fp);
	  exit (0);
	}
      sock_close (client);
    }


  return 0;
}
#endif

/* Actually connect to a server.  Returns the file descriptor or -1 on
   error.  ERRNO is set on error. */
static int
connect_server (const char *server, unsigned short port,
                unsigned int flags, const char *srvtag)
{
  int sock = -1;
  int srvcount = 0;
  int hostfound = 0;
  int srv, connected;
  int last_errno = 0;
  struct srventry *serverlist = NULL;

  /* Not currently using the flags */
  (void)flags;

#ifdef HAVE_W32_SYSTEM
  unsigned long inaddr;

#ifndef HTTP_NO_WSASTARTUP
  init_sockets ();
#endif
  /* Win32 gethostbyname doesn't handle IP addresses internally, so we
     try inet_addr first on that platform only. */
  inaddr = inet_addr(server);
  if ( inaddr != INADDR_NONE )
    {
      struct sockaddr_in addr;
      
      memset(&addr,0,sizeof(addr));
      
      sock = socket(AF_INET,SOCK_STREAM,0);
      if ( sock==INVALID_SOCKET )
	{
	  log_error("error creating socket: ec=%d\n",(int)WSAGetLastError());
	  return -1;
	}

      addr.sin_family = AF_INET; 
      addr.sin_port = htons(port);
      memcpy (&addr.sin_addr,&inaddr,sizeof(inaddr));      

      if (!connect (sock,(struct sockaddr *)&addr,sizeof(addr)) )
	return sock;
      sock_close(sock);
      return -1;
    }
#endif /*HAVE_W32_SYSTEM*/

#ifdef USE_DNS_SRV
  /* Do the SRV thing */
  if (srvtag)
    {
      /* We're using SRV, so append the tags. */
      if (1+strlen (srvtag) + 6 + strlen (server) + 1 <= MAXDNAME)
	{
	  char srvname[MAXDNAME];

	  stpcpy (stpcpy (stpcpy (stpcpy (srvname,"_"), srvtag),
                           "._tcp."), server);
	  srvcount = getsrv (srvname, &serverlist);
	}
    }
#endif /*USE_DNS_SRV*/

  if (!serverlist)
    {
      /* Either we're not using SRV, or the SRV lookup failed.  Make
	 up a fake SRV record. */
      serverlist = xtrycalloc (1, sizeof *serverlist);
      if (!serverlist)
        return -1; /* Out of core.  */
      serverlist->port = port;
      strncpy (serverlist->target, server, MAXDNAME);
      serverlist->target[MAXDNAME-1] = '\0';
      srvcount = 1;
    }

#ifdef HAVE_GETADDRINFO
  connected = 0;
  for (srv=0; srv < srvcount && !connected; srv++)
    {
      struct addrinfo hints, *res, *ai;
      char portstr[35];

      sprintf (portstr, "%hu", port);
      memset (&hints, 0, sizeof (hints));
      hints.ai_socktype = SOCK_STREAM;
      if (getaddrinfo (serverlist[srv].target, portstr, &hints, &res))
        continue; /* Not found - try next one. */
      hostfound = 1;

      for (ai = res; ai && !connected; ai = ai->ai_next)
        {
          if (sock != -1)
            sock_close (sock);
          sock = socket (ai->ai_family, ai->ai_socktype, ai->ai_protocol);
          if (sock == -1)
            {
              int save_errno = errno;
              log_error ("error creating socket: %s\n", strerror (errno));
              freeaddrinfo (res);
              xfree (serverlist);
              errno = save_errno;
              return -1;
            }
          
          if (connect (sock, ai->ai_addr, ai->ai_addrlen))
            last_errno = errno;
          else
            connected = 1;
        }
      freeaddrinfo (res);
    }
#else /* !HAVE_GETADDRINFO */
  connected = 0;
  for (srv=0; srv < srvcount && !connected; srv++)
    {
      int i;
      struct hostent *host = NULL;
      struct sockaddr_in addr;

      /* Note: This code is not thread-safe.  */

      memset (&addr, 0, sizeof (addr));
      host = gethostbyname (serverlist[srv].target);
      if (!host)
        continue;
      hostfound = 1;

      if (sock != -1)
        sock_close (sock);
      sock = socket (host->h_addrtype, SOCK_STREAM, 0);
      if (sock == -1)
        {
          log_error (_("error creating socket: %s\n"), strerror (errno));
          xfree (serverlist);
          return -1;
        }
      
      addr.sin_family = host->h_addrtype;
      if (addr.sin_family != AF_INET)
	{
	  log_error ("unknown address family for `%s'\n",
                     serverlist[srv].target);
          xfree (serverlist);
	  return -1;
	}
      addr.sin_port = htons (serverlist[srv].port);
      if (host->h_length != 4)
        {
          log_error ("illegal address length for `%s'\n",
                     serverlist[srv].target);
          xfree (serverlist);
          return -1;
        }

      /* Try all A records until one responds. */
      for (i = 0; host->h_addr_list[i] && !connected; i++)
        {
          memcpy (&addr.sin_addr, host->h_addr_list[i], host->h_length);
          if (connect (sock, (struct sockaddr *) &addr, sizeof (addr)))
            last_errno = errno;
          else
            {
              connected = 1;
              break;
            }
        }
    }
#endif /* !HAVE_GETADDRINFO */

  xfree (serverlist);

  if (!connected)
    {
#ifdef HAVE_W32_SYSTEM
      log_error ("can't connect to `%s': %s%sec=%d\n",
                   server,
                   hostfound? "":_("host not found"),
                   hostfound? "":" - ", (int)WSAGetLastError());
#else
      log_error ("can't connect to `%s': %s\n",
                 server,
                 hostfound? strerror (last_errno):"host not found");
#endif
      if (sock != -1)
	sock_close (sock);
      errno = last_errno;
      return -1;
    }
  return sock;
}


static gpg_error_t
write_server (int sock, const char *data, size_t length)
{
  int nleft;

  nleft = length;
  while (nleft > 0)
    {
#ifdef HAVE_W32_SYSTEM
      int nwritten;
      
      nwritten = send (sock, data, nleft, 0);
      if ( nwritten == SOCKET_ERROR ) 
        {
          log_info ("network write failed: ec=%d\n", (int)WSAGetLastError ());
          return gpg_error (GPG_ERR_NETWORK);
        }
#else /*!HAVE_W32_SYSTEM*/
      int nwritten = write (sock, data, nleft);
      if (nwritten == -1)
	{
	  if (errno == EINTR)
	    continue;
	  if (errno == EAGAIN)
	    {
	      struct timeval tv;

	      tv.tv_sec = 0;
	      tv.tv_usec = 50000;
	      select (0, NULL, NULL, NULL, &tv);
	      continue;
	    }
	  log_info ("network write failed: %s\n", strerror (errno));
	  return gpg_error_from_syserror ();
	}
#endif /*!HAVE_W32_SYSTEM*/
      nleft -= nwritten;
      data += nwritten;
    }

  return 0;
}



#ifdef HTTP_USE_ESTREAM
/* Read handler for estream.  */
static ssize_t
cookie_read (void *cookie, void *buffer, size_t size)
{
  cookie_t c = cookie;
  int nread;

#ifdef HTTP_USE_GNUTLS
  if (c->tls_session)
    {
    again:
      nread = gnutls_record_recv (c->tls_session, buffer, size);
      if (nread < 0)
        {
          if (nread == GNUTLS_E_INTERRUPTED)
            goto again;
          if (nread == GNUTLS_E_AGAIN)
            {
              struct timeval tv;
              
              tv.tv_sec = 0;
              tv.tv_usec = 50000;
              select (0, NULL, NULL, NULL, &tv);
              goto again;
            }
          if (nread == GNUTLS_E_REHANDSHAKE)
            goto again; /* A client is allowed to just ignore this request. */
          log_info ("TLS network read failed: %s\n", gnutls_strerror (nread));
          errno = EIO;
          return -1;
        }
    }
  else
#endif /*HTTP_USE_GNUTLS*/
    {
      do
        {
#ifdef HAVE_W32_SYSTEM
          /* Under Windows we need to use recv for a socket.  */
          nread = recv (c->fd, buffer, size, 0);
#else          
          nread = read (c->fd, buffer, size);
#endif
        }
      while (nread == -1 && errno == EINTR);
    }

  return nread;
}

/* Write handler for estream.  */
static ssize_t
cookie_write (void *cookie, const void *buffer, size_t size)
{
  cookie_t c = cookie;
  int nwritten = 0;

#ifdef HTTP_USE_GNUTLS
  if (c->tls_session)
    {
      int nleft = size;
      while (nleft > 0)
        {
          nwritten = gnutls_record_send (c->tls_session, buffer, nleft); 
          if (nwritten <= 0)
            {
              if (nwritten == GNUTLS_E_INTERRUPTED)
                continue;
              if (nwritten == GNUTLS_E_AGAIN)
                {
                  struct timeval tv;
                  
                  tv.tv_sec = 0;
                  tv.tv_usec = 50000;
                  select (0, NULL, NULL, NULL, &tv);
                  continue;
                }
              log_info ("TLS network write failed: %s\n",
                        gnutls_strerror (nwritten));
              errno = EIO;
              return -1;
            }
          nleft -= nwritten;
          buffer += nwritten;
        }
    }
  else
#endif /*HTTP_USE_GNUTLS*/
    {
      if ( write_server (c->fd, buffer, size) )
        {
          errno = EIO;
          nwritten = -1;
        }
      else
        nwritten = size;
    }

  return nwritten;
}

/* Close handler for estream.  */
static int
cookie_close (void *cookie)
{
  cookie_t c = cookie;

  if (!c)
    return 0;

#ifdef HTTP_USE_GNUTLS
  if (c->tls_session && !c->keep_socket)
    {
      gnutls_bye (c->tls_session, GNUTLS_SHUT_RDWR);
    }
#endif /*HTTP_USE_GNUTLS*/
  if (c->fd != -1 && !c->keep_socket)
    sock_close (c->fd);

  xfree (c);
  return 0;
}
#endif /*HTTP_USE_ESTREAM*/




/**** Test code ****/
#ifdef TEST

static gpg_error_t
verify_callback (http_t hd, void *tls_context, int reserved)
{
  log_info ("verification of certificates skipped\n");
  return 0;
}



/* static void */
/* my_gnutls_log (int level, const char *text) */
/* { */
/*   fprintf (stderr, "gnutls:L%d: %s", level, text); */
/* } */

int
main (int argc, char **argv)
{
  int rc;
  parsed_uri_t uri;
  uri_tuple_t r;
  http_t hd;
  int c;
  gnutls_session_t tls_session = NULL;
#ifdef HTTP_USE_GNUTLS
  gnutls_certificate_credentials certcred;
  const int certprio[] = { GNUTLS_CRT_X509, 0 };
#endif /*HTTP_USE_GNUTLS*/
  header_t hdr;

#ifdef HTTP_USE_ESTREAM
  es_init ();
#endif
  log_set_prefix ("http-test", 1 | 4);
  if (argc == 1)
    {
      /*start_server (); */
      return 0;
    }

  if (argc != 2)
    {
      fprintf (stderr, "usage: http-test uri\n");
      return 1;
    }
  argc--;
  argv++;

#ifdef HTTP_USE_GNUTLS
  rc = gnutls_global_init ();
  if (rc)
    log_error ("gnutls_global_init failed: %s\n", gnutls_strerror (rc));
  rc = gnutls_certificate_allocate_credentials (&certcred);
  if (rc)
    log_error ("gnutls_certificate_allocate_credentials failed: %s\n",
               gnutls_strerror (rc));
/*   rc = gnutls_certificate_set_x509_trust_file */
/*     (certcred, "ca.pem", GNUTLS_X509_FMT_PEM); */
/*   if (rc) */
/*     log_error ("gnutls_certificate_set_x509_trust_file failed: %s\n", */
/*                gnutls_strerror (rc)); */
  rc = gnutls_init (&tls_session, GNUTLS_CLIENT);
  if (rc)
    log_error ("gnutls_init failed: %s\n", gnutls_strerror (rc));
  rc = gnutls_set_default_priority (tls_session);
  if (rc)
    log_error ("gnutls_set_default_priority failed: %s\n",
               gnutls_strerror (rc));
  rc = gnutls_certificate_type_set_priority (tls_session, certprio);
  if (rc)
    log_error ("gnutls_certificate_type_set_priority failed: %s\n",
               gnutls_strerror (rc));
  rc = gnutls_credentials_set (tls_session, GNUTLS_CRD_CERTIFICATE, certcred);
  if (rc)
    log_error ("gnutls_credentials_set failed: %s\n", gnutls_strerror (rc));
/*   gnutls_global_set_log_function (my_gnutls_log); */
/*   gnutls_global_set_log_level (4); */

  http_register_tls_callback (verify_callback);
#endif /*HTTP_USE_GNUTLS*/

  rc = http_parse_uri (&uri, *argv);
  if (rc)
    {
      log_error ("`%s': %s\n", *argv, gpg_strerror (rc));
      http_release_parsed_uri (uri);
      return 1;
    }

  printf ("Scheme: %s\n", uri->scheme);
  printf ("Host  : %s\n", uri->host);
  printf ("Port  : %u\n", uri->port);
  printf ("Path  : %s\n", uri->path);
  for (r = uri->params; r; r = r->next)
    {
      printf ("Params: %s", r->name);
      if (!r->no_value)
	{
	  printf ("=%s", r->value);
	  if (strlen (r->value) != r->valuelen)
	    printf (" [real length=%d]", (int) r->valuelen);
	}
      putchar ('\n');
    }
  for (r = uri->query; r; r = r->next)
    {
      printf ("Query : %s", r->name);
      if (!r->no_value)
	{
	  printf ("=%s", r->value);
	  if (strlen (r->value) != r->valuelen)
	    printf (" [real length=%d]", (int) r->valuelen);
	}
      putchar ('\n');
    }
  http_release_parsed_uri (uri);
  uri = NULL;

  rc = http_open_document (&hd, *argv, NULL, 
                           HTTP_FLAG_NO_SHUTDOWN | HTTP_FLAG_NEED_HEADER,
                           NULL, tls_session);
  if (rc)
    {
      log_error ("can't get `%s': %s\n", *argv, gpg_strerror (rc));
      return 1;
    }
  log_info ("open_http_document succeeded; status=%u\n",
            http_get_status_code (hd));
  for (hdr = hd->headers; hdr; hdr = hdr->next)
    printf ("HDR: %s: %s\n", hdr->name, hdr->value);
  switch (http_get_status_code (hd))
    {
    case 200:
      while ((c = P_ES(getc) (http_get_read_ptr (hd))) != EOF)
        putchar (c);
      break;
    case 301:
    case 302:
      printf ("Redirected to `%s'\n", http_get_header (hd, "Location"));
      break;
    }
  http_close (hd, 0);

#ifdef HTTP_USE_GNUTLS
  gnutls_deinit (tls_session);
  gnutls_certificate_free_credentials (certcred);
  gnutls_global_deinit ();
#endif /*HTTP_USE_GNUTLS*/

  return 0;
}
#endif /*TEST*/


/*
Local Variables:
compile-command: "gcc -I.. -I../gl -DTEST -DHAVE_CONFIG_H -Wall -O2 -g -o http-test http.c -L. -lcommon -L../jnlib -ljnlib -lgcrypt -lpth -lgnutls"
End:
*/
