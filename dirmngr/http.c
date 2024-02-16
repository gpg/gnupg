/* http.c  -  HTTP protocol handler
 * Copyright (C) 1999, 2001-2004, 2006, 2009, 2010,
 *               2011 Free Software Foundation, Inc.
 * Copyright (C) 1999, 2001-2004, 2006, 2009, 2010, 2011, 2014 Werner Koch
 * Copyright (C) 2015-2017, 2021, 2023 g10 Code GmbH
 *
 * This file is part of GnuPG.
 *
 * This file is free software; you can redistribute it and/or modify
 * it under the terms of either
 *
 *   - the GNU Lesser General Public License as published by the Free
 *     Software Foundation; either version 3 of the License, or (at
 *     your option) any later version.
 *
 * or
 *
 *   - the GNU General Public License as published by the Free
 *     Software Foundation; either version 2 of the License, or (at
 *     your option) any later version.
 *
 * or both in parallel, as here.
 *
 * This file is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, see <https://www.gnu.org/licenses/>.
 */

/* Simple HTTP client implementation.  We try to keep the code as
   self-contained as possible.  There are some constraints however:

  - estream is required.  We now require estream because it provides a
    very useful and portable asprintf implementation and the fopencookie
    function.
  - stpcpy is required
  - fixme: list other requirements.


  - With HTTP_USE_NTBTLS or HTTP_USE_GNUTLS support for https is
    provided (this also requires estream).

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
# ifdef HAVE_WINSOCK2_H
#  include <winsock2.h>
# endif
# include <windows.h>
# include <winhttp.h>
# define SECURITY_WIN32 1
# include <security.h>
#else /*!HAVE_W32_SYSTEM*/
# include <sys/types.h>
# include <sys/socket.h>
# include <sys/time.h>
# include <time.h>
# include <fcntl.h>
# include <netinet/in.h>
# include <arpa/inet.h>
# include <netdb.h>
#endif /*!HAVE_W32_SYSTEM*/

#ifdef WITHOUT_NPTH /* Give the Makefile a chance to build without Pth.  */
# undef USE_NPTH
#endif

#ifdef USE_NPTH
# include <npth.h>
#endif

#if defined (HTTP_USE_GNUTLS) && defined (HTTP_USE_NTBTLS)
# error Both, HTTP_USE_GNUTLS and HTTP_USE_NTBTLS, are defined.
#endif

#ifdef HTTP_USE_NTBTLS
# include <ntbtls.h>
#elif HTTP_USE_GNUTLS
# include <gnutls/gnutls.h>
# include <gnutls/x509.h>
#endif /*HTTP_USE_GNUTLS*/

#include <assuan.h>  /* We need the socket wrapper.  */

#include "../common/util.h"
#include "../common/i18n.h"
#include "../common/sysutils.h" /* (gnupg_fd_t) */
#include "dns-stuff.h"
#include "dirmngr-status.h"    /* (dirmngr_status_printf)  */
#include "http.h"
#include "http-common.h"


#ifdef USE_NPTH
# define my_select(a,b,c,d,e)  npth_select ((a), (b), (c), (d), (e))
# define my_accept(a,b,c)      npth_accept ((a), (b), (c))
#else
# define my_select(a,b,c,d,e)  select ((a), (b), (c), (d), (e))
# define my_accept(a,b,c)      accept ((a), (b), (c))
#endif

#ifdef HAVE_W32_SYSTEM
#define sock_close(a)  closesocket(a)
#else
#define sock_close(a)  close(a)
#endif

#ifndef EAGAIN
#define EAGAIN  EWOULDBLOCK
#endif
#ifndef INADDR_NONE  /* Slowaris is missing that.  */
#define INADDR_NONE  ((unsigned long)(-1))
#endif /*INADDR_NONE*/

#define HTTP_PROXY_ENV           "http_proxy"
#define MAX_LINELEN 20000  /* Max. length of a HTTP header line. */
#define VALID_URI_CHARS "abcdefghijklmnopqrstuvwxyz"   \
                        "ABCDEFGHIJKLMNOPQRSTUVWXYZ"   \
                        "01234567890@"                 \
                        "!\"#$%&'()*+,-./:;<=>?[\\]^_{|}~"

#if HTTP_USE_NTBTLS
typedef ntbtls_t         tls_session_t;
# define USE_TLS 1
#elif HTTP_USE_GNUTLS
typedef gnutls_session_t tls_session_t;
# define USE_TLS 1
#else
typedef void *tls_session_t;
# undef USE_TLS
#endif

static gpg_err_code_t do_parse_uri (parsed_uri_t uri, int only_local_part,
                                    int no_scheme_check, int force_tls);
static gpg_error_t parse_uri (parsed_uri_t *ret_uri, const char *uri,
                              int no_scheme_check, int force_tls);
static int remove_escapes (char *string);
static int insert_escapes (char *buffer, const char *string,
                           const char *special);
static uri_tuple_t parse_tuple (char *string);
static gpg_error_t send_request (http_t hd, const char *httphost,
                                 const char *auth,const char *proxy,
				 const char *srvtag, unsigned int timeout,
                                 strlist_t headers);
static char *build_rel_path (parsed_uri_t uri);
static gpg_error_t parse_response (http_t hd);

static gpg_error_t connect_server (const char *server, unsigned short port,
                                   unsigned int flags, const char *srvtag,
                                   unsigned int timeout, assuan_fd_t *r_sock);
static gpgrt_ssize_t read_server (assuan_fd_t sock, void *buffer, size_t size);
static gpg_error_t write_server (assuan_fd_t sock, const char *data, size_t length);

static gpgrt_ssize_t cookie_read (void *cookie, void *buffer, size_t size);
static gpgrt_ssize_t cookie_write (void *cookie,
                                   const void *buffer, size_t size);
static int cookie_close (void *cookie);
#if defined(HAVE_W32_SYSTEM) && defined(HTTP_USE_NTBTLS)
static gpgrt_ssize_t simple_cookie_read (void *cookie,
                                         void *buffer, size_t size);
static gpgrt_ssize_t simple_cookie_write (void *cookie,
                                          const void *buffer, size_t size);
#endif

/* A socket object used to a allow ref counting of sockets.  */
struct my_socket_s
{
  assuan_fd_t fd; /* The actual socket - shall never be ASSUAN_INVALID_FD.  */
  int refcount;   /* Number of references to this socket.  */
};
typedef struct my_socket_s *my_socket_t;


/* Cookie function structure and cookie object.  */
static es_cookie_io_functions_t cookie_functions =
  {
    cookie_read,
    cookie_write,
    NULL,
    cookie_close
  };


struct cookie_s
{
  /* Socket object or NULL if already closed. */
  my_socket_t sock;

  /* The session object or NULL if not used. */
  http_session_t session;

  /* True if TLS is to be used.  */
  int use_tls;

  /* Optional malloced buffer holding pending bytes for the read
   * function.  LEN gives the used length, SIZE the allocated length.
   * Used by the up_to_empty_line machinery. */
  struct {
    size_t size;
    size_t len;
    char *data;
  } pending;

  /* The remaining content length and a flag telling whether to use
     the content length.  */
  uint64_t content_length;
  unsigned int content_length_valid:1;

  /* If the next flag is set the read function will limit the returned
   * buffer to an empty line.  That is the the pattern "\n\r\n" is
   * detected and any further bytes are not returned to the caller.
   * The flag is then reset.  For technical reason we might have
   * already read more which will be then saved for the next call in
   * the PENDING buffer.  */
  unsigned int up_to_empty_line:1;
  unsigned int last_was_lf:1;      /* Helper to detect empty line.  */
  unsigned int last_was_lfcr:1;    /* Helper to detect empty line.  */
};
typedef struct cookie_s *cookie_t;


/* Simple cookie functions.  Here the cookie is an int with the
 * socket. */
#if defined(HAVE_W32_SYSTEM) && defined(HTTP_USE_NTBTLS)
static es_cookie_io_functions_t simple_cookie_functions =
  {
    simple_cookie_read,
    simple_cookie_write,
    NULL,
    NULL
  };
#endif

enum auth_negotiate_states
  {
    AUTH_NGT_NONE = 0,
    AUTH_NGT_RCVD = 1,
    AUTH_NGT_SENT = 2
  };

/* An object to store information about a proxy.  */
struct proxy_info_s
{
  parsed_uri_t uri;   /* The parsed proxy URL.   */
  int is_http_proxy;  /* This is an http proxy.  */

#ifdef HAVE_W32_SYSTEM
  CredHandle cred_handle;   /* Credential handle.       */
  wchar_t *spn;             /* Service principal name.  */
  CtxtHandle ctxt_handle;   /* Security context.        */
  unsigned long token_size; /* Max. length of a token.  */
  unsigned int cred_handle_valid:1;
  unsigned int ctxt_handle_valid:1;
#endif  /*HAVE_W32_SYSTEM*/

  unsigned char *outtoken;  /* The output token allocated with token_size. */
  unsigned long outtoklen;  /* The current length of the token.            */
};
typedef struct proxy_info_s *proxy_info_t;


#if SIZEOF_UNSIGNED_LONG == 8
# define HTTP_SESSION_MAGIC 0x0068545470534553 /* "hTTpSES" */
#else
# define HTTP_SESSION_MAGIC 0x68547365         /* "hTse"    */
#endif

/* The session object. */
struct http_session_s
{
  unsigned long magic;

  int refcount;    /* Number of references to this object.  */
#ifdef HTTP_USE_GNUTLS
  gnutls_certificate_credentials_t certcred;
#endif /*HTTP_USE_GNUTLS*/
#ifdef USE_TLS
  tls_session_t tls_session;
  struct {
    int done;      /* Verifciation has been done.  */
    int rc;        /* TLS verification return code.  */
    unsigned int status; /* Verification status.  */
  } verify;
  char *servername; /* Malloced server name.  */
#endif /*USE_TLS*/
  /* A callback function to log details of TLS certifciates.  */
  void (*cert_log_cb) (http_session_t, gpg_error_t, const char *,
                       const void **, size_t *);

  /* The flags passed to the session object.  */
  unsigned int flags;

  /* A per-session TLS verification callback.  */
  http_verify_cb_t verify_cb;
  void *verify_cb_value;

  /* The connect timeout */
  unsigned int connect_timeout;
};


/* An object to save header lines. */
struct header_s
{
  struct header_s *next;
  char *value;    /* The value of the header (malloced).  */
  char name[1];   /* The name of the header (canonicalized). */
};
typedef struct header_s *header_t;


#if SIZEOF_UNSIGNED_LONG == 8
# define HTTP_CONTEXT_MAGIC 0x0068545470435458 /* "hTTpCTX" */
#else
# define HTTP_CONTEXT_MAGIC 0x68546378         /* "hTcx"    */
#endif


/* Our handle context. */
struct http_context_s
{
  unsigned long magic;
  unsigned int status_code;
  my_socket_t sock;
  unsigned int in_data:1;
  unsigned int is_http_0_9:1;
  unsigned int keep_alive:1;  /* Keep the connection alive.  */
  estream_t fp_read;
  estream_t fp_write;
  void *write_cookie;
  void *read_cookie;
  http_session_t session;
  parsed_uri_t uri;
  http_req_t req_type;
  char *buffer;          /* Line buffer. */
  size_t buffer_size;
  unsigned int flags;
  header_t headers;      /* Received headers. */
};


/* Two flags to enable verbose and debug mode.  Although currently not
 * set-able a value > 1 for OPT_DEBUG enables debugging of the session
 * reference counting.  */
static int opt_verbose;
static int opt_debug;

/* The global callback for the verification function for GNUTLS.  */
static gpg_error_t (*tls_callback) (http_t, http_session_t, int);

/* The list of files with trusted CA certificates for GNUTLS.  */
static strlist_t tls_ca_certlist;

/* The list of files with extra trusted CA certificates for GNUTLS.  */
static strlist_t cfg_ca_certlist;

/* The global callback for net activity.  */
static void (*netactivity_cb)(void);



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


/* Create a new socket object.  Returns NULL and closes FD if not
   enough memory is available.  */
static my_socket_t
_my_socket_new (int lnr, assuan_fd_t fd)
{
  my_socket_t so;

  so = xtrymalloc (sizeof *so);
  if (!so)
    {
      int save_errno = errno;
      assuan_sock_close (fd);
      gpg_err_set_errno (save_errno);
      return NULL;
    }
  so->fd = fd;
  so->refcount = 1;
  if (opt_debug)
    log_debug ("http.c:%d:socket_new: object %p for fd %d created\n",
               lnr, so, (int)so->fd);
  return so;
}
#define my_socket_new(a) _my_socket_new (__LINE__, (a))

/* Bump up the reference counter for the socket object SO.  */
static my_socket_t
_my_socket_ref (int lnr, my_socket_t so)
{
  so->refcount++;
  if (opt_debug > 1)
    log_debug ("http.c:%d:socket_ref: object %p for fd %d refcount now %d\n",
               lnr, so, (int)so->fd, so->refcount);
  return so;
}
#define my_socket_ref(a) _my_socket_ref (__LINE__,(a))


/* Bump down the reference counter for the socket object SO.  If SO
   has no more references, close the socket and release the
   object.  */
static void
_my_socket_unref (int lnr, my_socket_t so,
                  void (*preclose)(void*), void *preclosearg)
{
  if (so)
    {
      so->refcount--;
      if (opt_debug > 1)
        log_debug ("http.c:%d:socket_unref: object %p for fd %d ref now %d\n",
                   lnr, so, (int)so->fd, so->refcount);

      if (!so->refcount)
        {
          if (preclose)
            preclose (preclosearg);
          assuan_sock_close (so->fd);
          xfree (so);
        }
    }
}
#define my_socket_unref(a,b,c) _my_socket_unref (__LINE__,(a),(b),(c))


#ifdef HTTP_USE_GNUTLS
static ssize_t
my_gnutls_read (gnutls_transport_ptr_t ptr, void *buffer, size_t size)
{
  my_socket_t sock = ptr;
#if USE_NPTH
  return npth_read (sock->fd, buffer, size);
#else
  return read (sock->fd, buffer, size);
#endif
}
static ssize_t
my_gnutls_write (gnutls_transport_ptr_t ptr, const void *buffer, size_t size)
{
  my_socket_t sock = ptr;
#if USE_NPTH
  return npth_write (sock->fd, buffer, size);
#else
  return write (sock->fd, buffer, size);
#endif
}
#endif /*HTTP_USE_GNUTLS*/


#ifdef HTTP_USE_NTBTLS
/* Connect the ntbls callback to our generic callback.  */
static gpg_error_t
my_ntbtls_verify_cb (void *opaque, ntbtls_t tls, unsigned int verify_flags)
{
  http_t hd = opaque;

  (void)verify_flags;

  log_assert (hd && hd->session && hd->session->verify_cb);
  log_assert (hd->magic == HTTP_CONTEXT_MAGIC);
  log_assert (hd->session->magic == HTTP_SESSION_MAGIC);

  return hd->session->verify_cb (hd->session->verify_cb_value,
                                 hd, hd->session,
                                 (hd->flags | hd->session->flags),
                                 tls);
}
#endif /*HTTP_USE_NTBTLS*/




/* This notification function is called by estream whenever stream is
   closed.  Its purpose is to mark the closing in the handle so
   that a http_close won't accidentally close the estream.  The function
   http_close removes this notification so that it won't be called if
   http_close was used before an es_fclose.  */
static void
fp_onclose_notification (estream_t stream, void *opaque)
{
  http_t hd = opaque;

  log_assert (hd->magic == HTTP_CONTEXT_MAGIC);
  if (hd->fp_read && hd->fp_read == stream)
    hd->fp_read = NULL;
  else if (hd->fp_write && hd->fp_write == stream)
    hd->fp_write = NULL;
}


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
  const unsigned char *s = data;
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
      *p = 0;
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
  *p = 0;
  strcpy (p, suffix);
  return buffer;
}




/* Set verbosity and debug mode for this module. */
void
http_set_verbose (int verbose, int debug)
{
  opt_verbose = verbose;
  opt_debug = debug;
}


/* Register a non-standard global TLS callback function.  If no
   verification is desired a callback needs to be registered which
   always returns NULL.  Only used for GNUTLS. */
void
http_register_tls_callback (gpg_error_t (*cb)(http_t, http_session_t, int))
{
  tls_callback = cb;
}


/* Register a CA certificate for future use.  The certificate is
   expected to be in FNAME.  PEM format is assume if FNAME has a
   suffix of ".pem".  If FNAME is NULL the list of CA files is
   removed.  Only used for GNUTLS. */
void
http_register_tls_ca (const char *fname)
{
  gpg_err_code_t ec;
  strlist_t sl;

  if (!fname)
    {
      free_strlist (tls_ca_certlist);
      tls_ca_certlist = NULL;
    }
  else
    {
      /* Warn if we can't access right now, but register it anyway in
         case it becomes accessible later */
      if ((ec = gnupg_access (fname, F_OK)))
        log_info (_("can't access '%s': %s\n"), fname, gpg_strerror (ec));
      sl = add_to_strlist (&tls_ca_certlist, fname);
      if (*sl->d && !strcmp (sl->d + strlen (sl->d) - 4, ".pem"))
        sl->flags = 1;
    }
}


/* Register a CA certificate for future use.  The certificate is
 * expected to be in FNAME.  PEM format is assume if FNAME has a
 * suffix of ".pem".  If FNAME is NULL the list of CA files is
 * removed.  This is a variant of http_register_tls_ca which puts the
 * certificate into a separate list enabled using HTTP_FLAG_TRUST_CFG.
 * Only used for GNUTLS.  */
void
http_register_cfg_ca (const char *fname)
{
  gpg_err_code_t ec;
  strlist_t sl;

  if (!fname)
    {
      free_strlist (cfg_ca_certlist);
      cfg_ca_certlist = NULL;
    }
  else
    {
      /* Warn if we can't access right now, but register it anyway in
         case it becomes accessible later */
      if ((ec = gnupg_access (fname, F_OK)))
        log_info (_("can't access '%s': %s\n"), fname, gpg_strerror (ec));
      sl = add_to_strlist (&cfg_ca_certlist, fname);
      if (*sl->d && !strcmp (sl->d + strlen (sl->d) - 4, ".pem"))
        sl->flags = 1;
    }
}


/* Register a callback which is called every time the HTTP mode has
 * made a successful connection to some server.  */
void
http_register_netactivity_cb (void (*cb)(void))
{
  netactivity_cb = cb;
}


/* Call the netactivity callback if any.  */
static void
notify_netactivity (void)
{
  if (netactivity_cb)
    netactivity_cb ();
}



#ifdef USE_TLS
/* Free the TLS session associated with SESS, if any.  */
static void
close_tls_session (http_session_t sess)
{
  if (sess->tls_session)
    {
# if HTTP_USE_NTBTLS
      /* FIXME!!
         Possibly, ntbtls_get_transport and close those streams.
         Somehow get SOCK to call my_socket_unref.
      */
      ntbtls_release (sess->tls_session);
# elif HTTP_USE_GNUTLS
      my_socket_t sock = gnutls_transport_get_ptr (sess->tls_session);
      my_socket_unref (sock, NULL, NULL);
      gnutls_deinit (sess->tls_session);
      if (sess->certcred)
        gnutls_certificate_free_credentials (sess->certcred);
# endif /*HTTP_USE_GNUTLS*/
      xfree (sess->servername);
      sess->tls_session = NULL;
    }
}
#endif /*USE_TLS*/


/* Release a session.  Take care not to release it while it is being
   used by a http context object.  */
static void
session_unref (int lnr, http_session_t sess)
{
  if (!sess)
    return;

  log_assert (sess->magic == HTTP_SESSION_MAGIC);

  sess->refcount--;
  if (opt_debug > 1)
    log_debug ("http.c:%d:session_unref: sess %p ref now %d\n",
               lnr, sess, sess->refcount);
  if (sess->refcount)
    return;

#ifdef USE_TLS
  close_tls_session (sess);
#endif /*USE_TLS*/

  sess->magic = 0xdeadbeef;
  xfree (sess);
}
#define http_session_unref(a) session_unref (__LINE__, (a))

void
http_session_release (http_session_t sess)
{
  http_session_unref (sess);
}


/* Create a write stream and store it in the fp_write member.  Also
 * store the tls flag and the session.  */
static gpg_error_t
make_fp_write (http_t hd, int use_tls, http_session_t session)
{
  cookie_t cookie;

  cookie = xtrycalloc (1, sizeof *cookie);
  if (!cookie)
    return gpg_error_from_syserror ();
  cookie->sock = my_socket_ref (hd->sock);
  cookie->use_tls = use_tls;
  if (session)
    cookie->session = http_session_ref (session);
  hd->fp_write = es_fopencookie (cookie, "w", cookie_functions);
  if (!hd->fp_write)
    {
      gpg_error_t err = gpg_error_from_syserror ();
      my_socket_unref (cookie->sock, NULL, NULL);
      if (session)
        http_session_unref (cookie->session);
      xfree (cookie);
      return err;
    }
  hd->write_cookie = cookie;  /* Cookie now owned by FP_WRITE.  */
  return 0;
}


/* Create a read stream and store it in the fp_read member.  Also
 * store the tls flag and the session.  */
static gpg_error_t
make_fp_read (http_t hd, int use_tls, http_session_t session)
{
  cookie_t cookie;

  cookie = xtrycalloc (1, sizeof *cookie);
  if (!cookie)
    return gpg_error_from_syserror ();
  cookie->sock = my_socket_ref (hd->sock);
  cookie->use_tls = use_tls;
  if (session)
    cookie->session = http_session_ref (session);
  hd->fp_read = es_fopencookie (cookie, "r", cookie_functions);
  if (!hd->fp_read)
    {
      gpg_error_t err = gpg_error_from_syserror ();
      my_socket_unref (cookie->sock, NULL, NULL);
      if (session)
        http_session_unref (cookie->session);
      xfree (cookie);
      return err;
    }
  hd->read_cookie = cookie;  /* Cookie now owned by FP_READ.  */
  return 0;
}


/* Create a new session object which is currently used to enable TLS
 * support.  It may eventually allow reusing existing connections.
 * Valid values for FLAGS are:
 *   HTTP_FLAG_TRUST_DEF - Use the CAs set with http_register_tls_ca
 *   HTTP_FLAG_TRUST_SYS - Also use the CAs defined by the system
 *   HTTP_FLAG_TRUST_CFG - Also use CAs set with http_register_cfg_ca
 *   HTTP_FLAG_NO_CRL    - Do not consult CRLs for https.
 */
gpg_error_t
http_session_new (http_session_t *r_session,
                  const char *intended_hostname, unsigned int flags,
                  http_verify_cb_t verify_cb, void *verify_cb_value)
{
  gpg_error_t err;
  http_session_t sess;

  *r_session = NULL;

  sess = xtrycalloc (1, sizeof *sess);
  if (!sess)
    return gpg_error_from_syserror ();
  sess->magic = HTTP_SESSION_MAGIC;
  sess->refcount = 1;
  sess->flags = flags;
  sess->verify_cb = verify_cb;
  sess->verify_cb_value = verify_cb_value;
  sess->connect_timeout = 0;

#if HTTP_USE_NTBTLS
  {
    (void)intended_hostname; /* Not needed because we do not preload
                              * certificates.  */

    err = ntbtls_new (&sess->tls_session, NTBTLS_CLIENT);
    if (err)
      {
        log_error ("ntbtls_new failed: %s\n", gpg_strerror (err));
        goto leave;
      }

  }
#elif HTTP_USE_GNUTLS
  {
    const char *errpos;
    int rc;
    strlist_t sl;
    int add_system_cas = !!(flags & HTTP_FLAG_TRUST_SYS);
    int is_hkps_pool;

    (void)intended_hostname;

    rc = gnutls_certificate_allocate_credentials (&sess->certcred);
    if (rc < 0)
      {
        log_error ("gnutls_certificate_allocate_credentials failed: %s\n",
                   gnutls_strerror (rc));
        err = gpg_error (GPG_ERR_GENERAL);
        goto leave;
      }

    /* Disabled for 2.2.19 to due problems with the standard hkps pool.  */
    /* is_hkps_pool = (intended_hostname */
    /*                 && !ascii_strcasecmp (intended_hostname, */
    /*                                       get_default_keyserver (1))); */
    is_hkps_pool = 0;

    /* If we are looking for the hkps pool from sks-keyservers.net,
     * then forcefully use its dedicated certificate authority.  */
    /* Disabled for 2.2.29 because the service had to be shutdown.  */
    /* if (is_hkps_pool) */
    /*   { */
    /*     char *pemname = make_filename_try (gnupg_datadir (), */
    /*                                        "sks-keyservers.netCA.pem", NULL); */
    /*     if (!pemname) */
    /*       { */
    /*         err = gpg_error_from_syserror (); */
    /*         log_error ("setting CA from file '%s' failed: %s\n", */
    /*                    pemname, gpg_strerror (err)); */
    /*       } */
    /*     else */
    /*       { */
    /*         rc = gnutls_certificate_set_x509_trust_file */
    /*           (sess->certcred, pemname, GNUTLS_X509_FMT_PEM); */
    /*         if (rc < 0) */
    /*           log_info ("setting CA from file '%s' failed: %s\n", */
    /*                     pemname, gnutls_strerror (rc)); */
    /*         xfree (pemname); */
    /*       } */
    /*         */
    /*     if (is_hkps_pool) */
    /*       add_system_cas = 0; */
    /*   } */

    /* Add configured certificates to the session.  */
    if ((flags & HTTP_FLAG_TRUST_DEF) && !is_hkps_pool)
      {
        for (sl = tls_ca_certlist; sl; sl = sl->next)
          {
            rc = gnutls_certificate_set_x509_trust_file
              (sess->certcred, sl->d,
               (sl->flags & 1)? GNUTLS_X509_FMT_PEM : GNUTLS_X509_FMT_DER);
            if (rc < 0)
              log_info ("setting CA from file '%s' failed: %s\n",
                        sl->d, gnutls_strerror (rc));
          }

        /* If HKP trust is requested and there are no HKP certificates
         * configured, also try the standard system certificates.  */
        if (!tls_ca_certlist)
          add_system_cas = 1;
      }

    /* Add system certificates to the session.  */
    if (add_system_cas)
      {
        static int shown;

        rc = gnutls_certificate_set_x509_system_trust (sess->certcred);
        if (rc < 0)
          log_info ("setting system CAs failed: %s\n", gnutls_strerror (rc));
        else if (!shown)
          {
            shown = 1;
            log_info ("number of system provided CAs: %d\n", rc);
          }
      }

    /* Add other configured certificates to the session.  */
    if ((flags & HTTP_FLAG_TRUST_CFG) && !is_hkps_pool)
      {
        for (sl = cfg_ca_certlist; sl; sl = sl->next)
          {
            rc = gnutls_certificate_set_x509_trust_file
              (sess->certcred, sl->d,
               (sl->flags & 1)? GNUTLS_X509_FMT_PEM : GNUTLS_X509_FMT_DER);
            if (rc < 0)
              log_info ("setting extra CA from file '%s' failed: %s\n",
                        sl->d, gnutls_strerror (rc));
          }
      }


    rc = gnutls_init (&sess->tls_session, GNUTLS_CLIENT);
    if (rc < 0)
      {
        log_error ("gnutls_init failed: %s\n", gnutls_strerror (rc));
        err = gpg_error (GPG_ERR_GENERAL);
        goto leave;
      }
    /* A new session has the transport ptr set to (void*(-1), we need
       it to be NULL.  */
    gnutls_transport_set_ptr (sess->tls_session, NULL);

    rc = gnutls_priority_set_direct (sess->tls_session,
                                     "NORMAL",
                                     &errpos);
    if (rc < 0)
      {
        log_error ("gnutls_priority_set_direct failed at '%s': %s\n",
                   errpos, gnutls_strerror (rc));
        err = gpg_error (GPG_ERR_GENERAL);
        goto leave;
      }

    rc = gnutls_credentials_set (sess->tls_session,
                                 GNUTLS_CRD_CERTIFICATE, sess->certcred);
    if (rc < 0)
      {
        log_error ("gnutls_credentials_set failed: %s\n", gnutls_strerror (rc));
        err = gpg_error (GPG_ERR_GENERAL);
        goto leave;
      }
  }
#else /*!HTTP_USE_GNUTLS && !HTTP_USE_NTBTLS*/
  {
    (void)intended_hostname;
    (void)flags;
  }
#endif /*!HTTP_USE_GNUTLS && !HTTP_USE_NTBTLS*/

  if (opt_debug > 1)
    log_debug ("http.c:session_new: sess %p created\n", sess);
  err = 0;

#if USE_TLS
 leave:
#endif /*USE_TLS*/
  if (err)
    http_session_unref (sess);
  else
    *r_session = sess;

  return err;
}


/* Increment the reference count for session SESS.  Passing NULL for
   SESS is allowed. */
http_session_t
http_session_ref (http_session_t sess)
{
  if (sess)
    {
      sess->refcount++;
      if (opt_debug > 1)
        log_debug ("http.c:session_ref: sess %p ref now %d\n",
                   sess, sess->refcount);
    }
  return sess;
}


void
http_session_set_log_cb (http_session_t sess,
                         void (*cb)(http_session_t, gpg_error_t,
                                    const char *hostname,
                                    const void **certs, size_t *certlens))
{
  sess->cert_log_cb = cb;
}


/* Set the TIMEOUT in milliseconds for the connection's connect
 * calls.  Using 0 disables the timeout.  */
void
http_session_set_timeout (http_session_t sess, unsigned int timeout)
{
  sess->connect_timeout = timeout;
}




/* Start a HTTP retrieval and on success store at R_HD a context
   pointer for completing the request and to wait for the response.
   If HTTPHOST is not NULL it is used for the Host header instead of a
   Host header derived from the URL. */
gpg_error_t
http_open (http_t *r_hd, http_req_t reqtype, const char *url,
           const char *httphost,
           const char *auth, unsigned int flags, const char *proxy,
           http_session_t session, const char *srvtag, strlist_t headers)
{
  gpg_error_t err;
  http_t hd;

  *r_hd = NULL;

  if (!(reqtype == HTTP_REQ_GET || reqtype == HTTP_REQ_POST))
    return gpg_err_make (default_errsource, GPG_ERR_INV_ARG);

  /* Create the handle. */
  hd = xtrycalloc (1, sizeof *hd);
  if (!hd)
    return gpg_error_from_syserror ();
  hd->magic = HTTP_CONTEXT_MAGIC;
  hd->req_type = reqtype;
  hd->flags = flags;
  hd->session = http_session_ref (session);

  err = parse_uri (&hd->uri, url, 0, !!(flags & HTTP_FLAG_FORCE_TLS));
  if (!err)
    err = send_request (hd, httphost, auth, proxy, srvtag,
                        hd->session? hd->session->connect_timeout : 0,
                        headers);

  if (err)
    {
      my_socket_unref (hd->sock, NULL, NULL);
      if (hd->fp_read)
        es_fclose (hd->fp_read);
      if (hd->fp_write)
        es_fclose (hd->fp_write);
      http_session_unref (hd->session);
      xfree (hd);
    }
  else
    *r_hd = hd;
  return err;
}


/* This function is useful to connect to a generic TCP service using
   this http abstraction layer.  This has the advantage of providing
   service tags and an estream interface.  TIMEOUT is in milliseconds. */
gpg_error_t
http_raw_connect (http_t *r_hd, const char *server, unsigned short port,
                  unsigned int flags, const char *srvtag, unsigned int timeout)
{
  gpg_error_t err = 0;
  http_t hd;

  *r_hd = NULL;

  if ((flags & HTTP_FLAG_FORCE_TOR))
    {
      int mode;

      if (assuan_sock_get_flag (ASSUAN_INVALID_FD, "tor-mode", &mode) || !mode)
        {
          log_error ("Tor support is not available\n");
          return gpg_err_make (default_errsource, GPG_ERR_NOT_IMPLEMENTED);
        }
      /* Non-blocking connects do not work with our Tor proxy because
       * we can't continue the Socks protocol after the EINPROGRESS.
       * Disable the timeout to use a blocking connect.  */
      timeout = 0;
    }

  /* Create the handle. */
  hd = xtrycalloc (1, sizeof *hd);
  if (!hd)
    return gpg_error_from_syserror ();
  hd->magic = HTTP_CONTEXT_MAGIC;
  hd->req_type = HTTP_REQ_OPAQUE;
  hd->flags = flags;

  /* Connect.  */
  {
    assuan_fd_t sock;

    err = connect_server (server, port, hd->flags, srvtag, timeout, &sock);
    if (err)
      {
        xfree (hd);
        return err;
      }
    hd->sock = my_socket_new (sock);
    if (!hd->sock)
      {
        err = gpg_err_make (default_errsource, gpg_err_code_from_syserror ());
        xfree (hd);
        return err;
      }
  }

  /* Setup estreams for reading and writing.  */
  err = make_fp_write (hd, 0, NULL);
  if (err)
    goto leave;

  err = make_fp_read (hd, 0, NULL);
  if (err)
    goto leave;

  /* Register close notification to interlock the use of es_fclose in
     http_close and in user code.  */
  err = es_onclose (hd->fp_write, 1, fp_onclose_notification, hd);
  if (!err)
    err = es_onclose (hd->fp_read, 1, fp_onclose_notification, hd);

 leave:
  if (err)
    {
      if (hd->fp_read)
        es_fclose (hd->fp_read);
      if (hd->fp_write)
        es_fclose (hd->fp_write);
      my_socket_unref (hd->sock, NULL, NULL);
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
      if (opt_debug || (hd->flags & HTTP_FLAG_LOG_RESP))
        log_debug ("http.c:request-header:start_data:\n");
      es_fputs ("\r\n", hd->fp_write);
      es_fflush (hd->fp_write);
      hd->in_data = 1;
    }
  else
    es_fflush (hd->fp_write);
}


gpg_error_t
http_wait_response (http_t hd)
{
  gpg_error_t err;
  cookie_t cookie;
  int use_tls;
  int newfpread;

  /* Make sure that we are in the data. */
  http_start_data (hd);

  /* Close the write stream.  Note that the reference counted socket
     object keeps the actual system socket open.  */
  cookie = hd->write_cookie;
  if (!cookie)
    return gpg_err_make (default_errsource, GPG_ERR_INTERNAL);

  use_tls = cookie->use_tls;
  if (!hd->keep_alive)
    {
      es_fclose (hd->fp_write);
      hd->fp_write = NULL;
      /* The close has released the cookie and thus we better set it
       * to NULL.  */
      hd->write_cookie = NULL;
    }

  /* Shutdown one end of the socket is desired.  As per HTTP/1.0 this
     is not required but some very old servers (e.g. the original pksd
     keyserver didn't worked without it.  */
  if (!hd->keep_alive && (hd->flags & HTTP_FLAG_SHUTDOWN))
    shutdown (FD2INT (hd->sock->fd), 1);
  hd->in_data = 0;

  /* Create a new cookie and a stream for reading.  */
  newfpread = 0;
  if (!hd->keep_alive || !hd->fp_read)
    {
      err = make_fp_read (hd, use_tls, hd->session);
      if (err)
        return err;
      newfpread = 1;
      ((cookie_t)(hd->read_cookie))->up_to_empty_line = 1;
    }

  err = parse_response (hd);

  if (!err && newfpread)
    err = es_onclose (hd->fp_read, 1, fp_onclose_notification, hd);

  return err;
}


/* Convenience function to send a request and wait for the response.
   Closes the handle on error.  If PROXY is not NULL, this value will
   be used as an HTTP proxy and any enabled $http_proxy gets
   ignored. */
gpg_error_t
http_open_document (http_t *r_hd, const char *document,
                    const char *auth, unsigned int flags, const char *proxy,
                    http_session_t session,
                    const char *srvtag, strlist_t headers)
{
  gpg_error_t err;

  err = http_open (r_hd, HTTP_REQ_GET, document, NULL, auth, flags,
                   proxy, session, srvtag, headers);
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

  log_assert (hd->magic == HTTP_CONTEXT_MAGIC);

  /* First remove the close notifications for the streams.  */
  if (hd->fp_read)
    es_onclose (hd->fp_read, 0, fp_onclose_notification, hd);
  if (hd->fp_write)
    es_onclose (hd->fp_write, 0, fp_onclose_notification, hd);

  /* Now we can close the streams.  */
  my_socket_unref (hd->sock, NULL, NULL);
  if (hd->fp_read && !keep_read_stream)
    es_fclose (hd->fp_read);
  if (hd->fp_write)
    es_fclose (hd->fp_write);
  http_session_unref (hd->session);
  hd->magic = 0xdeadbeef;
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

unsigned int
http_get_status_code (http_t hd)
{
  return hd?hd->status_code:0;
}

/* Return information pertaining to TLS.  If TLS is not in use for HD,
   NULL is returned.  WHAT is used ask for specific information:

     (NULL) := Only check whether TLS is in use.  Returns an
               unspecified string if TLS is in use.  That string may
               even be the empty string.
 */
const char *
http_get_tls_info (http_t hd, const char *what)
{
  (void)what;

  if (!hd)
    return NULL;

  return hd->uri->use_tls? "":NULL;
}



static gpg_error_t
parse_uri (parsed_uri_t *ret_uri, const char *uri,
           int no_scheme_check, int force_tls)
{
  gpg_err_code_t ec;

  *ret_uri = xtrycalloc (1, sizeof **ret_uri + 2 * strlen (uri) + 1);
  if (!*ret_uri)
    return gpg_err_make (default_errsource, gpg_err_code_from_syserror ());
  strcpy ((*ret_uri)->buffer, uri);
  strcpy ((*ret_uri)->buffer + strlen (uri) + 1, uri);
  (*ret_uri)->original = (*ret_uri)->buffer + strlen (uri) + 1;
  ec = do_parse_uri (*ret_uri, 0, no_scheme_check, force_tls);
  if (ec)
    {
      http_release_parsed_uri (*ret_uri);
      *ret_uri = NULL;
    }
  return gpg_err_make (default_errsource, ec);
}


/*
 * Parse an URI and put the result into the newly allocated RET_URI.
 * On success the caller must use http_release_parsed_uri() to
 * releases the resources.  If the HTTP_PARSE_NO_SCHEME_CHECK flag is
 * set, the function tries to parse the URL in the same way it would
 * do for an HTTP style URI.   */
gpg_error_t
http_parse_uri (parsed_uri_t *ret_uri, const char *uri,
                unsigned int flags)
{
  return parse_uri (ret_uri, uri, !!(flags & HTTP_PARSE_NO_SCHEME_CHECK), 0);
}


void
http_release_parsed_uri (parsed_uri_t uri)
{
  if (uri)
    {
      uri_tuple_t r, r2;

      for (r = uri->params; r; r = r2)
	{
	  r2 = r->next;
	  xfree (r);
	}
      for (r = uri->query; r; r = r2)
	{
	  r2 = r->next;
	  xfree (r);
	}
      xfree (uri);
    }
}


static gpg_err_code_t
do_parse_uri (parsed_uri_t uri, int only_local_part,
              int no_scheme_check, int force_tls)
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
  uri->is_http = 0;
  uri->opaque = 0;
  uri->v6lit = 0;
  uri->onion = 0;
  uri->explicit_port = 0;
  uri->off_host = 0;
  uri->off_path = 0;

  /* A quick validity check unless we have the opaque scheme. */
  if (strspn (p, VALID_URI_CHARS) != n
      && strncmp (p, "opaque:", 7))
    return GPG_ERR_BAD_URI;	/* Invalid characters found. */

  if (!only_local_part)
    {
      /* Find the scheme. */
      if (!(p2 = strchr (p, ':')) || p2 == p)
	return GPG_ERR_BAD_URI; /* No scheme. */
      *p2++ = 0;
      for (pp=p; *pp; pp++)
       *pp = tolower (*(unsigned char*)pp);
      uri->scheme = p;
      if (!strcmp (uri->scheme, "http") && !force_tls)
        {
          uri->port = 80;
          uri->is_http = 1;
        }
      else if (!strcmp (uri->scheme, "hkp") && !force_tls)
        {
          uri->port = 11371;
          uri->is_http = 1;
        }
#ifdef USE_TLS
      else if (!strcmp (uri->scheme, "https") || !strcmp (uri->scheme,"hkps")
               || (force_tls && (!strcmp (uri->scheme, "http")
                                 || !strcmp (uri->scheme,"hkp"))))
        {
          uri->port = 443;
          uri->is_http = 1;
          uri->use_tls = 1;
        }
#endif /*USE_TLS*/
      else if (!strcmp (uri->scheme, "opaque"))
        {
          uri->opaque = 1;
          uri->path = p2;
          return 0;
        }
      else if (!no_scheme_check)
	return GPG_ERR_INV_URI; /* Unsupported scheme */

      p = p2;

      if (*p == '/' && p[1] == '/' ) /* There seems to be a hostname. */
	{
          p += 2;
	  if ((p2 = strchr (p, '/')))
            {
              if (p2 - uri->buffer > 10000)
                return GPG_ERR_BAD_URI;
              uri->off_path = p2 - uri->buffer;
              *p2++ = 0;
            }
          else
            {
              n = (p - uri->buffer) + strlen (p);
              if (n > 10000)
                return GPG_ERR_BAD_URI;
              uri->off_path = n;
            }

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
              if (p - uri->buffer > 10000)
                return GPG_ERR_BAD_URI;
              uri->off_host = (p + 1) - uri->buffer;
              uri->v6lit = 1;
	      p = p3;
	    }
	  else
            {
              uri->host = p;
              if (p - uri->buffer > 10000)
                return GPG_ERR_BAD_URI;
              uri->off_host = p - uri->buffer;
            }

	  if ((p3 = strchr (p, ':')))
	    {
	      *p3++ = '\0';
	      uri->port = atoi (p3);
              uri->explicit_port = 1;
	    }

	  if ((n = remove_escapes (uri->host)) < 0)
	    return GPG_ERR_BAD_URI;
	  if (n != strlen (uri->host))
	    return GPG_ERR_BAD_URI;	/* Hostname includes a Nul. */
	  p = p2 ? p2 : NULL;
	}
      else if (uri->is_http)
	return GPG_ERR_INV_URI; /* No Leading double slash for HTTP.  */
      else
        {
          uri->opaque = 1;
          uri->path = p;
          if (is_onion_address (uri->path))
            uri->onion = 1;
          return 0;
        }

    } /* End global URI part. */

  /* Parse the pathname part if any.  */
  if (p && *p)
    {
      /* TODO: Here we have to check params. */

      /* Do we have a query part? */
      if ((p2 = strchr (p, '?')))
        *p2++ = 0;

      uri->path = p;
      if ((n = remove_escapes (p)) < 0)
        return GPG_ERR_BAD_URI;
      if (n != strlen (p))
        return GPG_ERR_BAD_URI;	/* Path includes a Nul. */
      p = p2 ? p2 : NULL;

      /* Parse a query string if any.  */
      if (p && *p)
        {
          tail = &uri->query;
          for (;;)
            {
              uri_tuple_t elem;

              if ((p2 = strchr (p, '&')))
                *p2++ = 0;
              if (!(elem = parse_tuple (p)))
                return GPG_ERR_BAD_URI;
              *tail = elem;
              tail = &elem->next;

              if (!p2)
                break; /* Ready. */
              p = p2;
            }
        }
    }

  if (is_onion_address (uri->host))
    uri->onion = 1;

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


/* If SPECIAL is NULL this function escapes in forms mode.  */
static size_t
escape_data (char *buffer, const void *data, size_t datalen,
             const char *special)
{
  int forms = !special;
  const unsigned char *s;
  size_t n = 0;

  if (forms)
    special = "%;?&=";

  for (s = data; datalen; s++, datalen--)
    {
      if (forms && *s == ' ')
        {
	  if (buffer)
	    *buffer++ = '+';
	  n++;
        }
      else if (forms && *s == '\n')
        {
	  if (buffer)
	    memcpy (buffer, "%0D%0A", 6);
	  n += 6;
        }
      else if (forms && *s == '\r' && datalen > 1 && s[1] == '\n')
        {
	  if (buffer)
	    memcpy (buffer, "%0D%0A", 6);
	  n += 6;
          s++;
          datalen--;
        }
      else if (strchr (VALID_URI_CHARS, *s) && !strchr (special, *s))
	{
	  if (buffer)
	    *(unsigned char*)buffer++ = *s;
	  n++;
	}
      else
	{
	  if (buffer)
	    {
	      snprintf (buffer, 4, "%%%02X", *s);
	      buffer += 3;
	    }
	  n += 3;
	}
    }
  return n;
}


static int
insert_escapes (char *buffer, const char *string,
		const char *special)
{
  return escape_data (buffer, string, strlen (string), special);
}


/* Allocate a new string from STRING using standard HTTP escaping as
   well as escaping of characters given in SPECIALS.  A common pattern
   for SPECIALS is "%;?&=". However it depends on the needs, for
   example "+" and "/: often needs to be escaped too.  Returns NULL on
   failure and sets ERRNO.  If SPECIAL is NULL a dedicated forms
   encoding mode is used. */
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

/* Allocate a new string from {DATA,DATALEN} using standard HTTP
   escaping as well as escaping of characters given in SPECIALS.  A
   common pattern for SPECIALS is "%;?&=".  However it depends on the
   needs, for example "+" and "/: often needs to be escaped too.
   Returns NULL on failure and sets ERRNO.  If SPECIAL is NULL a
   dedicated forms encoding mode is used. */
char *
http_escape_data (const void *data, size_t datalen, const char *specials)
{
  int n;
  char *buf;

  n = escape_data (NULL, data, datalen, specials);
  buf = xtrymalloc (n+1);
  if (buf)
    {
      escape_data (buf, data, datalen, specials);
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


/* Return true if STRING is likely "hostname:port" or only "hostname".  */
static int
is_hostname_port (const char *string)
{
  int colons = 0;

  if (!string || !*string)
    return 0;
  for (; *string; string++)
    {
      if (*string == ':')
        {
          if (colons)
            return 0;
          if (!string[1])
            return 0;
          colons++;
        }
      else if (!colons && strchr (" \t\f\n\v_@[]/", *string))
        return 0; /* Invalid characters in hostname. */
      else if (colons && !digitp (string))
        return 0; /* Not a digit in the port.  */
    }
  return 1;
}


/* Free the PROXY object.  */
static void
release_proxy_info (proxy_info_t proxy)
{
  if (!proxy)
    return;
  http_release_parsed_uri (proxy->uri);
  xfree (proxy->outtoken);
#ifdef HAVE_W32_SYSTEM
  if (proxy->ctxt_handle_valid)
    DeleteSecurityContext (&proxy->ctxt_handle);
  if (proxy->cred_handle_valid)
    FreeCredentialsHandle (&proxy->cred_handle);
#endif
  xfree (proxy);
}


/* Return an http session object.  If clear is set, the object is
 * destroyed.  On error nULL is returned.  */
#ifdef HAVE_W32_SYSTEM
static HINTERNET
w32_get_internet_session (int clear)
{
  static HINTERNET session;

  if (clear)
    {
      if (session)
        {
          WinHttpCloseHandle (session);
          session = NULL;
        }
      return NULL;
    }

  if (!session)
    {
      session = WinHttpOpen (L"GnuPG dirmngr",
                             WINHTTP_ACCESS_TYPE_NO_PROXY,
                             WINHTTP_NO_PROXY_NAME,
                             WINHTTP_NO_PROXY_BYPASS,
                             0);
      if (!session)
        {
          log_error ("WinHttpOpen failed: %s\n", w32_strerror (-1));
          return NULL;
        }
    }

  return session;
}
#endif /*HAVE_W32_SYSTEM*/


/* Return a proxy using a Windows API.  */
#ifdef HAVE_W32_SYSTEM
static char *
w32_get_proxy (const char *url)
{
  WINHTTP_AUTOPROXY_OPTIONS options = {0};
  WINHTTP_PROXY_INFO info;
  char *result = NULL;
  char *p;
  wchar_t *wurl;
  int defaultcfg = 0;

  wurl = utf8_to_wchar (url);
  if (!wurl)
    {
      log_error ("utf8_to_wchar failed: %s\n",
                 gpg_strerror (gpg_error_from_syserror ()));
      return NULL;
    }

  options.dwFlags = (WINHTTP_AUTOPROXY_ALLOW_AUTOCONFIG
                     | WINHTTP_AUTOPROXY_ALLOW_CM
                     | WINHTTP_AUTOPROXY_ALLOW_STATIC
                     | WINHTTP_AUTOPROXY_AUTO_DETECT
                     | WINHTTP_AUTOPROXY_SORT_RESULTS);
  options.dwAutoDetectFlags = (WINHTTP_AUTO_DETECT_TYPE_DHCP
                               | WINHTTP_AUTO_DETECT_TYPE_DNS_A);
  options.fAutoLogonIfChallenged = TRUE;

  if (opt_debug)
    log_debug ("calling WinHttpGetProxyForUrl (%s)\n", url);
  if (!WinHttpGetProxyForUrl (w32_get_internet_session (0),
                              wurl, &options, &info))
    {
      int ec = (int)GetLastError ();
      if (ec == ERROR_WINHTTP_AUTODETECTION_FAILED)
        {
          if (opt_debug)
            log_debug ("calling WinHttpGetDefaultProxyConfiguration\n");
          if (!WinHttpGetDefaultProxyConfiguration (&info))
            {
              if (opt_verbose)
                log_info ("WinHttpGetDefaultProxyConfiguration failed: "
                          "%s (%d)\n", w32_strerror (ec), ec);
              xfree (wurl);
              return NULL;
            }
          defaultcfg = 1;
        }
      else
        {
          if (opt_verbose)
            log_info ("WinHttpGetProxyForUrl failed: %s (%d)\n",
                      w32_strerror (ec), ec);
          xfree (wurl);
          return NULL;
        }
    }
  xfree (wurl);

  if (info.dwAccessType == WINHTTP_ACCESS_TYPE_NAMED_PROXY)
    {
      result = wchar_to_utf8 (info.lpszProxy);
      if (!result)
        log_error ("wchar_to_utf8 failed: %s\n",
                   gpg_strerror (gpg_error_from_syserror ()));
      else
        {
          if (opt_debug)
            log_debug ("proxies to use: '%s'\n", result);
          /* The returned proxies are delimited by whitespace or
           * semicolons.  We return only the first proxy.  */
          for (p=result; *p; p++)
            if (spacep (p) || *p == ';')
              {
                *p = 0;
                break;
              }
        }
    }
  else if (info.dwAccessType == WINHTTP_ACCESS_TYPE_NO_PROXY)
    {
      /* No proxy shall be used.  */
    }
  else
    log_error ("%s returned unexpected code %lu\n",
               defaultcfg? "WinHttpGetDefaultProxyConfiguration"
               :"WinHttpGetProxyForUrl", info.dwAccessType);

  if (info.lpszProxy)
    GlobalFree (info.lpszProxy);
  if (info.lpszProxyBypass)
    GlobalFree (info.lpszProxyBypass);
  return result;
}
#endif /*HAVE_W32_SYSTEM*/


/* Return the proxy to be used for the URL or host specified in HD.
 * If OVERRIDE_PROXY is not NULL and not empty, this proxy will be
 * used instead of any configured or dynamically determined proxy.  If
 * the function runs into an error an error code is returned and NULL
 * is stored at R_PROXY.  If the fucntion was successful and a proxy
 * is to be used, information on the procy is stored at R_PROXY; if no
 * proxy shall be used R_PROXY is set to NULL.  Caller should always
 * use release_proxy_info on the value stored at R_PROXY.  */
static gpg_error_t
get_proxy_for_url (http_t hd, const char *override_proxy, proxy_info_t *r_proxy)
{
  gpg_error_t err = 0;
  const char *proxystr, *s;
  proxy_info_t proxy;
#ifdef HAVE_W32_SYSTEM
  char *proxystrbuf = NULL;
#endif

  *r_proxy = NULL;

  if (override_proxy && *override_proxy)
    proxystr = override_proxy;
  else if (!(hd->flags & HTTP_FLAG_TRY_PROXY))
    return 0;  /* --honor-http-proxy not active  */
  else if ((s = getenv (HTTP_PROXY_ENV)) && *s)
    proxystr = s;
#ifdef HAVE_W32_SYSTEM
  else if (hd->uri && hd->uri->original
           && (proxystrbuf = w32_get_proxy (hd->uri->original)))
    proxystr = proxystrbuf;
#endif
  else
    return 0;  /* No proxy known.  */

  proxy = xtrycalloc (1, sizeof *proxy);
  if (!proxy)
    {
      err = gpg_error_from_syserror ();
      log_error ("error allocating memory for proxy\n");
      goto leave;
    }

  err = parse_uri (&proxy->uri, proxystr, 0, 0);
  if (gpg_err_code (err) == GPG_ERR_INV_URI
      && is_hostname_port (proxystr))
    {
      /* Retry assuming a "hostname:port" string.  */
      char *tmpname = strconcat ("http://", proxystr, NULL);
      if (!tmpname)
        err = gpg_error_from_syserror ();
      else if (!parse_uri (&proxy->uri, tmpname, 0, 0))
        err = 0;
      xfree (tmpname);
    }

  if (!err)
    {
      /* Get rid of the escapes in the authstring.  */
      if (proxy->uri->auth)
        remove_escapes (proxy->uri->auth);

      if (!strcmp (proxy->uri->scheme, "http"))
        proxy->is_http_proxy = 1;
      else if (!strcmp (proxy->uri->scheme, "socks4")
               || !strcmp (proxy->uri->scheme, "socks5h"))
        err = gpg_error (GPG_ERR_NOT_IMPLEMENTED);
      else
        err = gpg_error (GPG_ERR_INV_URI);

      if (err)
	{
	  log_error ("invalid HTTP proxy (%s): %s\n",
		     proxystr, gpg_strerror (err));
	  err = gpg_err_make (default_errsource, GPG_ERR_CONFIGURATION);
	}
      else if (opt_verbose)
        log_info ("using '%s' to proxy '%s'\n",
                  proxystr, hd->uri? hd->uri->original : NULL);
    }

 leave:
#ifdef HAVE_W32_SYSTEM
  xfree (proxystrbuf);
#endif
  if (err)
    xfree (proxy);
  else
    *r_proxy = proxy;
  return err;
}


/* Some checks done by send_request.  */
static gpg_error_t
send_request_basic_checks (http_t hd)
{
  int mode;

  if (hd->uri->use_tls && !hd->session)
    {
      log_error ("TLS requested but no session object provided\n");
      return gpg_error (GPG_ERR_INTERNAL);
    }
#ifdef USE_TLS
  if (hd->uri->use_tls && !hd->session->tls_session)
    {
      log_error ("TLS requested but no TLS context available\n");
      return gpg_error (GPG_ERR_INTERNAL);
    }
  if (opt_debug)
    log_debug ("Using TLS library: %s %s\n",
# if HTTP_USE_NTBTLS
               "NTBTLS", ntbtls_check_version (NULL)
# elif HTTP_USE_GNUTLS
               "GNUTLS", gnutls_check_version (NULL)
# else
               "?", "?"
# endif /*HTTP_USE_*TLS*/
               );
#endif /*USE_TLS*/

  if ((hd->flags & HTTP_FLAG_FORCE_TOR)
      && (assuan_sock_get_flag (ASSUAN_INVALID_FD, "tor-mode", &mode) || !mode))
    {
      log_error ("Tor support is not available\n");
      return gpg_error (GPG_ERR_NOT_IMPLEMENTED);
    }

  return 0;
}


/* Helper for send_request to set the servername.  */
static gpg_error_t
send_request_set_sni (http_t hd, const char *name)
{
  gpg_error_t err = 0;
# if HTTP_USE_GNUTLS
  int rc;
# endif

  /* Try to use SNI.  */
#ifdef USE_TLS
  if (hd->uri->use_tls)
    {
      xfree (hd->session->servername);
      hd->session->servername = xtrystrdup (name);
      if (!hd->session->servername)
        {
          err = gpg_error_from_syserror ();
          goto leave;
        }

# if HTTP_USE_NTBTLS
      err = ntbtls_set_hostname (hd->session->tls_session,
                                 hd->session->servername);
      if (err)
        {
          log_info ("ntbtls_set_hostname failed: %s\n", gpg_strerror (err));
          goto leave;
        }
# elif HTTP_USE_GNUTLS
      rc = gnutls_server_name_set (hd->session->tls_session,
                                   GNUTLS_NAME_DNS,
                                   hd->session->servername,
                                   strlen (hd->session->servername));
      if (rc < 0)
        log_info ("gnutls_server_name_set failed: %s\n", gnutls_strerror (rc));
# endif /*HTTP_USE_GNUTLS*/
    }
#endif /*USE_TLS*/

 leave:
  return err;
}


/* Run the NTBTLS handshake if needed.  */
#if HTTP_USE_NTBTLS
static gpg_error_t
run_ntbtls_handshake (http_t hd)
{
  gpg_error_t err;
  estream_t in, out;

  if (hd->uri->use_tls)
    {
      my_socket_ref (hd->sock);

      /* Until we support send/recv in estream under Windows we need
       * to use es_fopencookie.  */
#ifdef HAVE_W32_SYSTEM
      in = es_fopencookie ((void*)(unsigned int)hd->sock->fd, "rb",
                           simple_cookie_functions);
#else
      in = es_fdopen_nc (hd->sock->fd, "rb");
#endif
      if (!in)
        {
          err = gpg_error_from_syserror ();
          goto leave;
        }

#ifdef HAVE_W32_SYSTEM
      out = es_fopencookie ((void*)(unsigned int)hd->sock->fd, "wb",
                            simple_cookie_functions);
#else
      out = es_fdopen_nc (hd->sock->fd, "wb");
#endif
      if (!out)
        {
          err = gpg_error_from_syserror ();
          es_fclose (in);
          goto leave;
        }

      err = ntbtls_set_transport (hd->session->tls_session, in, out);
      if (err)
        {
          log_info ("TLS set_transport failed: %s <%s>\n",
                    gpg_strerror (err), gpg_strsource (err));
          es_fclose (in);
          es_fclose (out);
          goto leave;
        }

      if (hd->session->verify_cb)
        {
          err = ntbtls_set_verify_cb (hd->session->tls_session,
                                      my_ntbtls_verify_cb, hd);
          if (err)
            {
              log_error ("ntbtls_set_verify_cb failed: %s\n",
                         gpg_strerror (err));
              goto leave;
            }
        }

      while ((err = ntbtls_handshake (hd->session->tls_session)))
        {
          unsigned int tlevel, ttype;
          const char *s;

          s = ntbtls_get_last_alert (hd->session->tls_session, &tlevel, &ttype);
          if (s)
            log_info ("TLS alert: %s (%u.%u)\n", s, tlevel, ttype);

          switch (err)
            {
            default:
              log_info ("TLS handshake failed: %s <%s>\n",
                        gpg_strerror (err), gpg_strsource (err));
              goto leave;
            }
        }

      hd->session->verify.done = 0;

      /* Note that in contrast to GNUTLS NTBTLS uses a registered
       * callback to run the verification as part of the handshake.  */
      err = 0;
      /* FIXME: We could check that the CB has been called and if not
       * error out with this warning:
       * if (err)
       *   {
       *     log_info ("TLS connection authentication failed: %s <%s>\n",
       *               gpg_strerror (err), gpg_strsource (err));
       *     goto leave;
       *   }
       */
       }
  else
    err = 0;

 leave:
  return err;
}
#endif /*HTTP_USE_NTBTLS*/


/* Run the GNUTLS handshake if needed.  */
#if HTTP_USE_GNUTLS
static gpg_error_t
run_gnutls_handshake (http_t hd, const char *server)
{
  gpg_error_t err;
  int rc;

  if (hd->uri->use_tls)
    {
      my_socket_ref (hd->sock);
      gnutls_transport_set_ptr (hd->session->tls_session, hd->sock);
      gnutls_transport_set_pull_function (hd->session->tls_session,
                                          my_gnutls_read);
      gnutls_transport_set_push_function (hd->session->tls_session,
                                          my_gnutls_write);

    handshake_again:
      do
        {
          rc = gnutls_handshake (hd->session->tls_session);
        }
      while (rc == GNUTLS_E_INTERRUPTED || rc == GNUTLS_E_AGAIN);
      if (rc < 0)
        {
          if (rc == GNUTLS_E_WARNING_ALERT_RECEIVED
              || rc == GNUTLS_E_FATAL_ALERT_RECEIVED)
            {
              gnutls_alert_description_t alertno;
              const char *alertstr;

              alertno = gnutls_alert_get (hd->session->tls_session);
              alertstr = gnutls_alert_get_name (alertno);
              log_info ("TLS handshake %s: %s (alert %d)\n",
                        rc == GNUTLS_E_WARNING_ALERT_RECEIVED
                        ? "warning" : "failed",
                        alertstr, (int)alertno);
              if (alertno == GNUTLS_A_UNRECOGNIZED_NAME && server)
                log_info ("  (sent server name '%s')\n", server);

              if (rc == GNUTLS_E_WARNING_ALERT_RECEIVED)
                goto handshake_again;
            }
          else
            log_info ("TLS handshake failed: %s\n", gnutls_strerror (rc));
          err = gpg_error (GPG_ERR_NETWORK);
          goto leave;
        }

      hd->session->verify.done = 0;
      if (tls_callback)
        err = tls_callback (hd, hd->session, 0);
      else
        err = http_verify_server_credentials (hd->session);
      if (err)
        {
          log_info ("TLS connection authentication failed: %s\n",
                    gpg_strerror (err));
          goto leave;
        }
    }
  else
    err =0;

 leave:
  return err;
}
#endif /*HTTP_USE_GNUTLS*/


/* It INPUTSTRING is NULL get the intial token.  If INPUTSTRING is not
 * NULL, decode the string and use this as input from teh server.  On
 * success the final output token is stored at PROXY->OUTTOKEN and
 * OUTTOKLEN.  IF the authentication succeeded OUTTOKLEN is zero. */
static gpg_error_t
proxy_get_token (proxy_info_t proxy, const char *inputstring)
{
#ifdef HAVE_W32_SYSTEM
  gpg_error_t err;
  int rc;
  SecBuffer chlg_buf;       /* challenge buffer     */
  SecBufferDesc chlg_desc;  /* challenge descriptor */
  SecBuffer resp_buf;       /* response buffer      */
  SecBufferDesc resp_desc;  /* response descriptor  */
  unsigned long attrs;
  TimeStamp expiry;         /* (value not used)  */
  void *intoken = NULL;
  size_t intoklen;

  if (inputstring)
    {
      /* The input is expected in the token parameter but the paremter
       * name is often forgotten.  Thus we simply detect the parameter
       * name and skip it, assuming no other parameters are given.  */
      if (!strncmp (inputstring, "token=", 6))
        inputstring += 6;

      err = b64decode (inputstring, NULL, &intoken, &intoklen);
      /* Just to be safe that we don't overflow an ulong we check the
       * actual size against an arbitrary limit. */
      if (!err && intoklen > 65535)
        err = gpg_error (GPG_ERR_ERANGE);
      if (err || !intoklen)
        {
          log_error ("error decoding received auth token: %s\n",
                     err? gpg_strerror (err):"empty challenge token received");
          if (!err)
            err = gpg_error (GPG_ERR_BAD_AUTH);
          goto leave;
        }
    }

  if (!proxy->spn)
    {
      char *buffer = strconcat ("HTTP/", (*proxy->uri->host
                                          ?proxy->uri->host:"localhost"), NULL);
      if (!buffer)
        {
          err = gpg_error_from_syserror ();
          goto leave;
        }
      if (opt_debug)
        log_debug ("http.c:proxy_connect: using '%s' as SPN\n", buffer);
      proxy->spn = utf8_to_wchar (buffer);
      xfree (buffer);
      if (!proxy->spn)
        {
          err = gpg_error_from_syserror ();
          goto leave;
        }
    }

  if (!proxy->token_size || !proxy->outtoken)  /* Not yet initialized.  */
    {
      PSecPkgInfoW pinfo;

      rc = QuerySecurityPackageInfoW (NEGOSSP_NAME_W, &pinfo);
      if (rc)
        {
          log_error ("QSPI(Negotiate) failed: %s (%d)\n",
                     w32_strerror (rc), rc);
          err = gpg_error (GPG_ERR_BAD_AUTH);
          goto leave;
        }
      proxy->token_size = pinfo->cbMaxToken;
      FreeContextBuffer (pinfo);

      proxy->outtoken = xtrymalloc (proxy->token_size);
      if (!proxy->outtoken)
        {
          err = gpg_error_from_syserror ();
          goto leave;
        }
    }

  if (!proxy->cred_handle_valid)
    {
      rc = AcquireCredentialsHandleW (NULL, NEGOSSP_NAME_W,
                                      SECPKG_CRED_OUTBOUND, NULL,
                                      NULL, /* Current user */
                                      NULL, /* reserved */
                                      NULL, /* reserved */
                                      &proxy->cred_handle,
                                      NULL  /* expiry */);
      if (rc)
        {
          log_error ("ACH(Negotiate) failed: %s (%d)\n", w32_strerror (rc), rc);
          err = gpg_error (GPG_ERR_NO_AUTH);
          goto leave;
        }
      proxy->cred_handle_valid = 1;
    }

  /* Now generate our challenge-response message.  */
  if (intoken)
    {
      chlg_buf.BufferType = SECBUFFER_TOKEN;
      chlg_buf.pvBuffer   = intoken;
      chlg_buf.cbBuffer   = intoklen;
      chlg_desc.ulVersion = SECBUFFER_VERSION;
      chlg_desc.cBuffers  = 1;
      chlg_desc.pBuffers  = &chlg_buf;
    }

  resp_buf.BufferType = SECBUFFER_TOKEN;
  resp_buf.pvBuffer   = proxy->outtoken;
  resp_buf.cbBuffer   = proxy->token_size;
  resp_desc.ulVersion = SECBUFFER_VERSION;
  resp_desc.cBuffers  = 1;
  resp_desc.pBuffers  = &resp_buf;
  rc = InitializeSecurityContextW (&proxy->cred_handle,
                                   (intoken && proxy->ctxt_handle_valid)
                                   ? &proxy->ctxt_handle : NULL,
                                   proxy->spn, /* service principal name */
                                   ISC_REQ_CONFIDENTIALITY,
                                   0,    /* reserved */
                                   SECURITY_NATIVE_DREP,
                                   intoken? &chlg_desc : NULL,
                                   0,    /* reserved */
                                   &proxy->ctxt_handle, /* new context */
                                   &resp_desc,  /* the output.  */
                                   &attrs,      /* attribs of the context. */
                                   &expiry);
  switch (rc)
    {
    case SEC_E_OK:  /* All done and no more ISC expected.  */
      break;

    case SEC_I_COMPLETE_AND_CONTINUE:  /* Need to call CompleteAuthToken.  */
    case SEC_I_COMPLETE_NEEDED:
      rc = CompleteAuthToken (&proxy->ctxt_handle, &resp_desc);
      log_error ("CompleteAuthToken failed: %s (%d)\n", w32_strerror (rc), rc);
      err = gpg_error (GPG_ERR_NO_AUTH);
      goto leave;
      break;

    case SEC_I_CONTINUE_NEEDED: /* Send the new token to the client.  */
      break;

    default:
      log_error ("ISC(Negotiate) failed: %s (%d)\n", w32_strerror (rc), rc);
      err = gpg_error (GPG_ERR_NO_AUTH);
      goto leave;
    }

  proxy->outtoklen = resp_buf.cbBuffer;
  proxy->ctxt_handle_valid = 1;
  err = 0;

 leave:
  xfree (intoken);
  return err;

#else /*!HAVE_W32_SYSTEM*/

  (void)proxy;
  (void)inputstring;
  return gpg_error (GPG_ERR_NOT_IMPLEMENTED);

#endif /*!HAVE_W32_SYSTEM*/
}


/* Use the CONNECT method to proxy our TLS stream.  */
static gpg_error_t
run_proxy_connect (http_t hd, proxy_info_t proxy,
                   const char *httphost, const char *server,
                   unsigned short port)
{
  gpg_error_t err;
  int saved_flags = hd->flags;
  char *authhdr = NULL;
  char *request = NULL;
  char *tmpstr  = NULL;
  const char *s, *parms;
  unsigned int idx;
  int auth_basic = 0;
  enum auth_negotiate_states authstate = 0;
  unsigned int authpasses = 0;

  /* Authentication methods implemented here:
   * RFC-2617 - HTTP Authentication: Basic and Digest Access Authentication
   * RFC-4559 - SPNEGO-based Kerberos and NTLM HTTP Authentication
   */
  auth_basic = !!proxy->uri->auth;
  hd->keep_alive = !auth_basic; /* We may need to send more requests.  */

  /* For basic authentication we need to send just one request.  */
  if (auth_basic
      && !(authhdr = make_header_line ("Proxy-Authorization: Basic ",
                                       "\r\n",
                                       proxy->uri->auth,
                                       strlen (proxy->uri->auth))))
    {
      err = gpg_error_from_syserror ();
      goto leave;
    }

 again:
  xfree (request);
  request = es_bsprintf ("CONNECT %s:%hu HTTP/1.%c\r\nHost: %s:%hu\r\n%s%s",
                         httphost ? httphost : server,
                         port,
                         auth_basic? '0' : '1',
                         httphost ? httphost : server,
                         port,
                         authhdr ? authhdr : "",
                         hd->keep_alive? "Connection: keep-alive\r\n" : "");
  if (!request)
    {
      err = gpg_error_from_syserror ();
      goto leave;
    }

  if (opt_debug || (hd->flags & HTTP_FLAG_LOG_RESP))
    log_debug_with_string (request, "http.c:proxy:request:");

  if (!hd->fp_write)
    {
      err = make_fp_write (hd, 0, NULL);
      if (err)
        goto leave;
    }

  if (es_fputs (request, hd->fp_write) || es_fflush (hd->fp_write))
    {
      err = gpg_error_from_syserror ();
      goto leave;
    }

  /* Make sure http_wait_response doesn't close the stream.  */
  saved_flags = hd->flags;
  hd->flags &= ~HTTP_FLAG_SHUTDOWN;

  /* Get the response and set hd->fp_read  */
  err = http_wait_response (hd);
  if (err)
    goto leave;

  /* Reset state.  */
  es_clearerr (hd->fp_read);
  ((cookie_t)(hd->read_cookie))->up_to_empty_line = 1;
  hd->in_data = 0;

  if (hd->status_code >= 200 && hd->status_code < 300 )
    err = 0; /* Success.  */
  else if (hd->status_code == 407)
    {
      if (opt_debug)
        log_debug ("http.c:proxy_connect: 407 seen\n");
      parms = NULL;
      for (idx=0; (s = http_get_header (hd, "Proxy-Authenticate", idx)); idx++)
        {
          if (opt_debug)
            log_debug ("http.c:proxy_connect: method=%s\n", s);
          if (!parms)
            parms = has_leading_keyword (s, "Negotiate");
        }
      if (!parms)
        authstate = AUTH_NGT_NONE;
      else if (authstate == AUTH_NGT_NONE)
        authstate = AUTH_NGT_RCVD;

      switch (authstate)
        {
        case AUTH_NGT_NONE:
          if (opt_debug)
            log_debug ("http.c:proxy_connect: no supported auth method\n");
          err = gpg_error (GPG_ERR_NO_AUTH);
          break;

        case AUTH_NGT_RCVD:
          if (opt_debug)
            log_debug ("http.c:proxy_connect: using negotiate - init\n");
          err = proxy_get_token (proxy, NULL);
          if (err)
            goto leave;
          if (proxy->outtoklen)  /* Authentication needs to continue.  */
            {
              xfree (authhdr);
              authhdr = make_header_line ("Proxy-Authorization: Negotiate ",
                                          "\r\n",
                                          proxy->outtoken, proxy->outtoklen);
              if (!authhdr)
                {
                  err = gpg_error_from_syserror ();
                  goto leave;
                }
              authstate = AUTH_NGT_SENT;
              authpasses++;
              goto again;
            }
          break;

        case AUTH_NGT_SENT:
          if (opt_debug)
            log_debug ("http.c:proxy_connect: using negotiate - next\n");
          if (!*parms)
            {
              log_debug ("proxy authentication failed"
                         " due to server not accepting our challenge\n");
              err = gpg_error (GPG_ERR_BAD_AUTH);
              goto leave;
            }
          if (authpasses > 5)
            {
              log_error ("proxy authentication failed"
                         " due to too many passes\n");
              err = gpg_error (GPG_ERR_BAD_AUTH);
              goto leave;

            }
          err = proxy_get_token (proxy, parms);
          if (err)
            goto leave;
          if (proxy->outtoklen)  /* Authentication needs to continue.  */
            {
              xfree (authhdr);
              authhdr = make_header_line ("Proxy-Authorization: Negotiate ",
                                          "\r\n",
                                          proxy->outtoken, proxy->outtoklen);
              if (!authhdr)
                {
                  err = gpg_error_from_syserror ();
                  goto leave;
                }
              authpasses++;
              goto again;
            }
          break;

        default:
          BUG();
        }
    }
  else
    err = gpg_error (GPG_ERR_NO_DATA);

  if (err)
    {
      xfree (tmpstr);
      tmpstr = es_bsprintf ("%s:%hu", httphost ? httphost : server, port);
      log_error (_("error accessing '%s': http status %u\n"),
                 tmpstr ? tmpstr : "out of core",
                 http_get_status_code (hd));
      goto leave;
    }

 leave:
  if (hd->keep_alive)
    {
      es_fclose (hd->fp_write);
      hd->fp_write = NULL;
      /* The close has released the cookie and thus we better set it
       * to NULL.  */
      hd->write_cookie = NULL;
    }
  /* Restore flags, destroy stream, reset state.  */
  hd->flags = saved_flags;
  es_fclose (hd->fp_read);
  hd->fp_read = NULL;
  hd->read_cookie = NULL;
  hd->keep_alive = 0;
  hd->in_data = 0;

  xfree (request);
  xfree (authhdr);
  xfree (tmpstr);
  return err;
}


/* Make a request string using a standard proxy.  On success the
 * request is stored at R_REQUEST (and will never be NULL).  */
static gpg_error_t
mk_proxy_request (http_t hd, proxy_info_t proxy,
                  const char *httphost, const char *server,
                  unsigned short port, const char *relpath,
                  const char *authstr,
                  char **r_request)
{
  gpg_error_t err = 0;
  char *authhdr = NULL;
  char *request = NULL;

  *r_request = NULL;

  if (proxy->uri->auth
      && !(authhdr = make_header_line ("Proxy-Authorization: Basic ",
                                       "\r\n",
                                       proxy->uri->auth,
                                       strlen (proxy->uri->auth))))
    {
      err = gpg_error_from_syserror ();
      goto leave;
    }

  request = es_bsprintf ("%s %s://%s:%hu%s%s HTTP/1.0\r\n%s%s",
                         hd->req_type == HTTP_REQ_GET ? "GET" :
                         hd->req_type == HTTP_REQ_HEAD ? "HEAD" :
                         hd->req_type == HTTP_REQ_POST ? "POST" : "OOPS",
                         hd->uri->use_tls? "https" : "http",
                         httphost? httphost : server,
                         port, *relpath == '/' ? "" : "/", relpath,
                         authstr ? authstr : "",
                         authhdr ? authhdr : "");
  if (!request)
    {
      err = gpg_error_from_syserror ();
      goto leave;
    }
  *r_request = request;
  request = NULL;

 leave:
  xfree (request);
  xfree (authhdr);
  return err;
}


/* Make a request string using.  On success the request is stored at
 * R_REQUEST (and will never be NULL).  */
static gpg_error_t
mk_std_request (http_t hd,
                const char *httphost, const char *server,
                unsigned short port, const char *relpath,
                const char *authstr,
                char **r_request)
{
  gpg_error_t err = 0;
  char portstr[35];
  char *request = NULL;

  *r_request = NULL;

  if (port == (hd->uri->use_tls? 443 : 80))
    *portstr = 0;
  else
    snprintf (portstr, sizeof portstr, ":%u", port);

  request = es_bsprintf ("%s %s%s HTTP/1.0\r\nHost: %s%s\r\n%s",
                         hd->req_type == HTTP_REQ_GET ? "GET" :
                         hd->req_type == HTTP_REQ_HEAD ? "HEAD" :
                         hd->req_type == HTTP_REQ_POST ? "POST" : "OOPS",
                         *relpath == '/' ? "" : "/", relpath,
                         httphost? httphost : server,
                         portstr,
                         authstr? authstr:"");
  if (!request)
    {
      err = gpg_error_from_syserror ();
      goto leave;
    }
  *r_request = request;
  request = NULL;

 leave:
  xfree (request);
  return err;
}


/*
 * Send a HTTP request to the server
 * Returns 0 if the request was successful
 */
static gpg_error_t
send_request (http_t hd, const char *httphost, const char *auth,
	      const char *override_proxy,
              const char *srvtag, unsigned int timeout,
              strlist_t headers)
{
  gpg_error_t err;
  const char *server;
  char *request = NULL;
  char *relpath = NULL;
  unsigned short port;
  int use_http_proxy = 0;
  char *proxy_authstr = NULL;
  char *authstr = NULL;
  assuan_fd_t sock;
  proxy_info_t proxy = NULL;

  err = send_request_basic_checks (hd);
  if (err)
    goto leave;

  if ((hd->flags & HTTP_FLAG_FORCE_TOR))
    {
      /* Non-blocking connects do not work with our Tor proxy because
       * we can't continue the Socks protocol after the EINPROGRESS.
       * Disable the timeout to use a blocking connect.  */
      timeout = 0;
    }

  server = *hd->uri->host ? hd->uri->host : "localhost";
  port = hd->uri->port ? hd->uri->port : 80;

  if ((err = send_request_set_sni (hd, httphost? httphost : server)))
    goto leave;

  if ((err = get_proxy_for_url (hd, override_proxy, &proxy)))
    goto leave;

  if (proxy && proxy->is_http_proxy)
    {
      use_http_proxy = 1;  /* We want to use a proxy for the conenction.  */
      err = connect_server (*proxy->uri->host ? proxy->uri->host : "localhost",
                            proxy->uri->port ? proxy->uri->port : 80,
                            hd->flags, NULL, timeout, &sock);
    }
  else
    {
      err = connect_server (server, port, hd->flags, srvtag, timeout, &sock);
    }
  if (err)
    goto leave;

  hd->sock = my_socket_new (sock);
  if (!hd->sock)
    {
      err = gpg_error_from_syserror ();
      goto leave;
    }

  if (use_http_proxy && hd->uri->use_tls)
    {
      err = run_proxy_connect (hd, proxy, httphost, server, port);
      if (err)
        goto leave;

      /* We are done with the proxy, the code below will establish a
       * TLS session and talk directly to the target server.  Thus we
       * clear the flag to indicate this.  */
      use_http_proxy = 0;
    }

#if HTTP_USE_NTBTLS
  err = run_ntbtls_handshake (hd);
#elif HTTP_USE_GNUTLS
  err = run_gnutls_handshake (hd, server);
#else
  err = 0;
#endif
  if (err)
    goto leave;

  if (auth || hd->uri->auth)
    {
      char *myauth;

      if (auth)
        {
          myauth = xtrystrdup (auth);
          if (!myauth)
            {
              err = gpg_error_from_syserror ();
              goto leave;
            }
          remove_escapes (myauth);
        }
      else
        {
          remove_escapes (hd->uri->auth);
          myauth = hd->uri->auth;
        }

      authstr = make_header_line ("Authorization: Basic ", "\r\n",
                                  myauth, strlen (myauth));
      if (auth)  /* (Was allocated.)  */
        xfree (myauth);

      if (!authstr)
        {
          err = gpg_error_from_syserror ();
          goto leave;
        }
    }

  relpath = build_rel_path (hd->uri);
  if (!relpath)
    {
      err = gpg_error_from_syserror ();
      goto leave;
    }

  if (use_http_proxy)
    err = mk_proxy_request (hd, proxy, httphost, server, port,
                            relpath, authstr, &request);
  else
    err = mk_std_request (hd, httphost, server, port,
                          relpath, authstr, &request);
  if (err)
    goto leave;

  if (opt_debug || (hd->flags & HTTP_FLAG_LOG_RESP))
    log_debug_with_string (request, "http.c:request:");

  /* First setup estream so that we can write even the first line
     using estream.  This is also required for the sake of gnutls. */
  err = make_fp_write (hd, hd->uri->use_tls, hd->session);
  if (err)
    goto leave;

  if (es_fputs (request, hd->fp_write) || es_fflush (hd->fp_write))
    {
      err = gpg_error_from_syserror ();
      goto leave;
    }

  for (;headers; headers=headers->next)
    {
      if (opt_debug || (hd->flags & HTTP_FLAG_LOG_RESP))
        log_debug_with_string (headers->d, "http.c:request-header:");
      if ((es_fputs (headers->d, hd->fp_write) || es_fflush (hd->fp_write))
            || (es_fputs("\r\n",hd->fp_write) || es_fflush(hd->fp_write)))
        {
          err = gpg_error_from_syserror ();
          goto leave;
        }
    }

 leave:
  es_free (request);
  xfree (authstr);
  xfree (proxy_authstr);
  xfree (relpath);
  release_proxy_info (proxy);

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
static gpg_err_code_t
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
    return GPG_ERR_BUG;
  if (*line == ' ' || *line == '\t')
    {
      /* Continuation. This won't happen too often as it is not
         recommended.  We use a straightforward implementation. */
      if (!hd->headers)
        return GPG_ERR_PROTOCOL_VIOLATION;
      n += strlen (hd->headers->value);
      p = xtrymalloc (n+1);
      if (!p)
        return gpg_err_code_from_syserror ();
      strcpy (stpcpy (p, hd->headers->value), line);
      xfree (hd->headers->value);
      hd->headers->value = p;
      return 0;
    }

  capitalize_header_name (line);
  p = strchr (line, ':');
  if (!p)
    return GPG_ERR_PROTOCOL_VIOLATION;
  *p++ = 0;
  while (*p == ' ' || *p == '\t')
    p++;
  value = p;

  /* Check whether we have already seen a line with that name.  In
   * that case we assume it is a comma separated list and merge
   * them.  Of course there are a few exceptions.  */
  if (!strcmp (line, "Proxy-Authenticate")
      || !strcmp (line, "Www-Authenticate"))
    ; /* Better to have them separate.  */
  else
    {
      for (h=hd->headers; h; h = h->next)
        if ( !strcmp (h->name, line) )
          break;
      if (h)
        {
          p = strconcat (h->value, ",", value, NULL);
          if (!p)
            return gpg_err_code_from_syserror ();
          xfree (h->value);
          h->value = p;
          return 0;
        }
    }

  /* Append a new header. */
  h = xtrymalloc (sizeof *h + strlen (line));
  if (!h)
    return gpg_err_code_from_syserror ();
  strcpy (h->name, line);
  h->value = xtrymalloc (strlen (value)+1);
  if (!h->value)
    {
      xfree (h);
      return gpg_err_code_from_syserror ();
    }
  strcpy (h->value, value);
  h->next = hd->headers;
  hd->headers = h;

  return 0;
}


/* Return the header NAME from the last response.  The returned value
 * is valid as along as HD has not been closed and no other request
 * has been send. If the header was not found, NULL is returned.  NAME
 * must be canonicalized, that is the first letter of each dash
 * delimited part must be uppercase and all other letters lowercase.
 * SKIP gives the number of entries of the requested NAME to skip
 * before returning; this can be used to enumerate headers with the
 * same name (see store_header).
*/
const char *
http_get_header (http_t hd, const char *name, unsigned int skip)
{
  header_t h;

  for (h=hd->headers; h; h = h->next)
    if (!strcmp (h->name, name))
      {
        if (skip)
          skip--;
        else
          return h->value;
      }
  return NULL;
}


/* Return a newly allocated and NULL terminated array with pointers to
   header names.  The array must be released with xfree() and its
   content is only values as long as no other request has been
   send.  */
const char **
http_get_header_names (http_t hd)
{
  const char **array;
  size_t n;
  header_t h;

  for (n=0, h = hd->headers; h; h = h->next)
    n++;
  array = xtrycalloc (n+1, sizeof *array);
  if (array)
    {
      for (n=0, h = hd->headers; h; h = h->next)
        array[n++] = h->name;
    }

  return array;
}


/*
 * Parse the response from a server.
 * Returns: Errorcode and sets some files in the handle
 */
static gpg_err_code_t
parse_response (http_t hd)
{
  char *line, *p, *p2;
  size_t maxlen, len;
  cookie_t cookie = hd->read_cookie;
  const char *s;

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
      len = es_read_line (hd->fp_read, &hd->buffer, &hd->buffer_size, &maxlen);
      line = hd->buffer;
      if (!line)
	return gpg_err_code_from_syserror (); /* Out of core. */
      if (!maxlen)
	return GPG_ERR_TRUNCATED; /* Line has been truncated. */
      if (!len)
	return GPG_ERR_EOF;

      if (opt_debug || (hd->flags & HTTP_FLAG_LOG_RESP))
        log_debug_with_string (line, "http.c:response:\n");
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
      len = es_read_line (hd->fp_read, &hd->buffer, &hd->buffer_size, &maxlen);
      line = hd->buffer;
      if (!line)
	return gpg_err_code_from_syserror (); /* Out of core. */
      /* Note, that we can silently ignore truncated lines. */
      if (!len)
	return GPG_ERR_EOF;
      /* Trim line endings of empty lines. */
      if ((*line == '\r' && line[1] == '\n') || *line == '\n')
	*line = 0;
      if (opt_debug || (hd->flags & HTTP_FLAG_LOG_RESP))
        log_info ("http.c:RESP: '%.*s'\n",
                  (int)strlen(line)-(*line&&line[1]?2:0),line);
      if (*line)
        {
          gpg_err_code_t ec = store_header (hd, line);
          if (ec)
            return ec;
        }
    }
  while (len && *line);

  cookie->content_length_valid = 0;
  if (!(hd->flags & HTTP_FLAG_IGNORE_CL))
    {
      s = http_get_header (hd, "Content-Length", 0);
      if (s)
        {
          cookie->content_length_valid = 1;
          cookie->content_length = string_to_u64 (s);
        }
    }

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

      if (my_select (fd + 1, &rfds, NULL, NULL, NULL) <= 0)
	continue;		/* ignore any errors */

      if (!FD_ISSET (fd, &rfds))
	continue;

      addrlen = sizeof peer;
      client = my_accept (fd, (struct sockaddr *) &peer, &addrlen);
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



/* Return true if SOCKS shall be used.  This is the case if tor_mode
 * is enabled and the desired address is not the loopback address.
 * This function is basically a copy of the same internal function in
 * Libassuan.  */
static int
use_socks (struct sockaddr_storage *addr)
{
  int mode;

  if (assuan_sock_get_flag (ASSUAN_INVALID_FD, "tor-mode", &mode) || !mode)
    return 0;  /* Not in Tor mode.  */
  else if (addr->ss_family == AF_INET6)
    {
      struct sockaddr_in6 *addr_in6 = (struct sockaddr_in6 *)addr;
      const unsigned char *s;
      int i;

      s = (unsigned char *)&addr_in6->sin6_addr.s6_addr;
      if (s[15] != 1)
        return 1;   /* Last octet is not 1 - not the loopback address.  */
      for (i=0; i < 15; i++, s++)
        if (*s)
          return 1; /* Non-zero octet found - not the loopback address.  */

      return 0; /* This is the loopback address.  */
    }
  else if (addr->ss_family == AF_INET)
    {
      struct sockaddr_in *addr_in = (struct sockaddr_in *)addr;

      if (*(unsigned char*)&addr_in->sin_addr.s_addr == 127)
        return 0; /* Loopback (127.0.0.0/8) */

      return 1;
    }
  else
    return 0;
}


/* Wrapper around assuan_sock_new which takes the domain from an
 * address parameter.  */
static assuan_fd_t
my_sock_new_for_addr (struct sockaddr_storage *addr, int type, int proto)
{
  int domain;

  if (use_socks (addr))
    {
      /* Libassaun always uses 127.0.0.1 to connect to the socks
       * server (i.e. the Tor daemon).  */
      domain = AF_INET;
    }
  else
    domain = addr->ss_family;

  return assuan_sock_new (domain, type, proto);
}


/* Call WSAGetLastError and map it to a libgpg-error.  */
#ifdef HAVE_W32_SYSTEM
static gpg_error_t
my_wsagetlasterror (void)
{
  int wsaerr;
  gpg_err_code_t ec;

  wsaerr = WSAGetLastError ();
  switch (wsaerr)
    {
    case WSAENOTSOCK:        ec = GPG_ERR_EINVAL;       break;
    case WSAEWOULDBLOCK:     ec = GPG_ERR_EAGAIN;       break;
    case ERROR_BROKEN_PIPE:  ec = GPG_ERR_EPIPE;        break;
    case WSANOTINITIALISED:  ec = GPG_ERR_ENOSYS;       break;
    case WSAENOBUFS:         ec = GPG_ERR_ENOBUFS;      break;
    case WSAEMSGSIZE:        ec = GPG_ERR_EMSGSIZE;     break;
    case WSAECONNREFUSED:    ec = GPG_ERR_ECONNREFUSED; break;
    case WSAEISCONN:         ec = GPG_ERR_EISCONN;      break;
    case WSAEALREADY:        ec = GPG_ERR_EALREADY;     break;
    case WSAETIMEDOUT:       ec = GPG_ERR_ETIMEDOUT;    break;
    default:                 ec = GPG_ERR_EIO;          break;
    }

  return gpg_err_make (default_errsource, ec);
}
#endif /*HAVE_W32_SYSTEM*/


/* Connect SOCK and return GPG_ERR_ETIMEOUT if a connection could not
 * be established within TIMEOUT milliseconds.  0 indicates the
 * system's default timeout.  The other args are the usual connect
 * args.  On success 0 is returned, on timeout GPG_ERR_ETIMEDOUT, and
 * another error code for other errors.  On timeout the caller needs
 * to close the socket as soon as possible to stop an ongoing
 * handshake.
 *
 * This implementation is for well-behaving systems; see Stevens,
 * Network Programming, 2nd edition, Vol 1, 15.4.  */
static gpg_error_t
connect_with_timeout (assuan_fd_t sock,
                      struct sockaddr *addr, int addrlen,
                      unsigned int timeout)
{
  gpg_error_t err;
  int syserr;
  socklen_t slen;
  fd_set rset, wset;
  struct timeval tval;
  int n;

#ifndef HAVE_W32_SYSTEM
  int oflags;
# define RESTORE_BLOCKING()  do {  \
    fcntl (sock, F_SETFL, oflags); \
  } while (0)
#else /*HAVE_W32_SYSTEM*/
# define RESTORE_BLOCKING()  do {                       \
    unsigned long along = 0;                            \
    ioctlsocket (FD2INT (sock), FIONBIO, &along);       \
  } while (0)
#endif /*HAVE_W32_SYSTEM*/


  if (!timeout)
    {
      /* Shortcut.  */
      if (assuan_sock_connect (sock, addr, addrlen))
        err = gpg_err_make (default_errsource, gpg_err_code_from_syserror ());
      else
        err = 0;
      return err;
    }

  /* Switch the socket into non-blocking mode.  */
#ifdef HAVE_W32_SYSTEM
  {
    unsigned long along = 1;
    if (ioctlsocket (FD2INT (sock), FIONBIO, &along))
      return my_wsagetlasterror ();
  }
#else
  oflags = fcntl (sock, F_GETFL, 0);
  if (fcntl (sock, F_SETFL, oflags | O_NONBLOCK))
    return gpg_err_make (default_errsource, gpg_err_code_from_syserror ());
#endif

  /* Do the connect.  */
  if (!assuan_sock_connect (sock, addr, addrlen))
    {
      /* Immediate connect.  Restore flags. */
      RESTORE_BLOCKING ();
      return 0; /* Success.  */
    }
  err = gpg_err_make (default_errsource, gpg_err_code_from_syserror ());
  if (gpg_err_code (err) != GPG_ERR_EINPROGRESS
#ifdef HAVE_W32_SYSTEM
      && gpg_err_code (err) != GPG_ERR_EAGAIN
#endif
      )
    {
      RESTORE_BLOCKING ();
      return err;
    }

  FD_ZERO (&rset);
  FD_SET (FD2INT (sock), &rset);
  wset = rset;
  tval.tv_sec = timeout / 1000;
  tval.tv_usec = (timeout % 1000) * 1000;

  n = my_select (FD2INT(sock)+1, &rset, &wset, NULL, &tval);
  if (n < 0)
    {
      err = gpg_err_make (default_errsource, gpg_err_code_from_syserror ());
      RESTORE_BLOCKING ();
      return err;
    }
  if (!n)
    {
      /* Timeout: We do not restore the socket flags on timeout
       * because the caller is expected to close the socket.  */
      return gpg_err_make (default_errsource, GPG_ERR_ETIMEDOUT);
    }
  if (!FD_ISSET (sock, &rset) && !FD_ISSET (sock, &wset))
    {
      /* select misbehaved.  */
      return gpg_err_make (default_errsource, GPG_ERR_SYSTEM_BUG);
    }

  slen = sizeof (syserr);
  if (getsockopt (FD2INT(sock), SOL_SOCKET, SO_ERROR,
                  (void*)&syserr, &slen) < 0)
    {
      /* Assume that this is Solaris which returns the error in ERRNO.  */
      err = gpg_err_make (default_errsource, gpg_err_code_from_syserror ());
    }
  else if (syserr)
    err = gpg_err_make (default_errsource, gpg_err_code_from_errno (syserr));
  else
    err = 0; /* Connected.  */

  RESTORE_BLOCKING ();

  return err;

#undef RESTORE_BLOCKING
}


/* Actually connect to a server.  On success 0 is returned and the
 * file descriptor for the socket is stored at R_SOCK; on error an
 * error code is returned and ASSUAN_INVALID_FD is stored at R_SOCK.
 * TIMEOUT is the connect timeout in milliseconds.  Note that the
 * function tries to connect to all known addresses and the timeout is
 * for each one. */
static gpg_error_t
connect_server (const char *server, unsigned short port,
                unsigned int flags, const char *srvtag, unsigned int timeout,
                assuan_fd_t *r_sock)
{
  gpg_error_t err;
  assuan_fd_t sock = ASSUAN_INVALID_FD;
  unsigned int srvcount = 0;
  int hostfound = 0;
  int anyhostaddr = 0;
  int srv, connected, v4_valid, v6_valid;
  gpg_error_t last_err = 0;
  struct srventry *serverlist = NULL;

  *r_sock = ASSUAN_INVALID_FD;

#if defined(HAVE_W32_SYSTEM) && !defined(HTTP_NO_WSASTARTUP)
  init_sockets ();
#endif /*Windows*/

  check_inet_support (&v4_valid, &v6_valid);

  /* Onion addresses require special treatment.  */
  if (is_onion_address (server))
    {
#ifdef ASSUAN_SOCK_TOR

      if (opt_debug)
        log_debug ("http.c:connect_server:onion: name='%s' port=%hu\n",
                   server, port);
      sock = assuan_sock_connect_byname (server, port, 0, NULL,
                                         ASSUAN_SOCK_TOR);
      if (sock == ASSUAN_INVALID_FD)
        {
          err = gpg_err_make (default_errsource,
                              (errno == EHOSTUNREACH)? GPG_ERR_UNKNOWN_HOST
                              : gpg_err_code_from_syserror ());
          log_error ("can't connect to '%s': %s\n", server, gpg_strerror (err));
          return err;
        }

      notify_netactivity ();
      *r_sock = sock;
      return 0;

#else /*!ASSUAN_SOCK_TOR*/

      err = gpg_err_make (default_errsource, GPG_ERR_ENETUNREACH);
      return ASSUAN_INVALID_FD;

#endif /*!HASSUAN_SOCK_TOR*/
    }

  /* Do the SRV thing */
  if (srvtag)
    {
      err = get_dns_srv (server, srvtag, NULL, &serverlist, &srvcount);
      if (err)
        log_info ("getting '%s' SRV for '%s' failed: %s\n",
                  srvtag, server, gpg_strerror (err));
      /* Note that on error SRVCOUNT is zero.  */
      err = 0;
    }

  if (!serverlist)
    {
      /* Either we're not using SRV, or the SRV lookup failed.  Make
	 up a fake SRV record. */
      serverlist = xtrycalloc (1, sizeof *serverlist);
      if (!serverlist)
        return gpg_err_make (default_errsource, gpg_err_code_from_syserror ());

      serverlist->port = port;
      strncpy (serverlist->target, server, DIMof (struct srventry, target));
      serverlist->target[DIMof (struct srventry, target)-1] = '\0';
      srvcount = 1;
    }

  connected = 0;
  for (srv=0; srv < srvcount && !connected; srv++)
    {
      dns_addrinfo_t aibuf, ai;

      if (opt_debug)
        log_debug ("http.c:connect_server: trying name='%s' port=%hu\n",
                   serverlist[srv].target, port);
      err = resolve_dns_name (serverlist[srv].target, port, 0, SOCK_STREAM,
                              &aibuf, NULL);
      if (err)
        {
          log_info ("resolving '%s' failed: %s\n",
                    serverlist[srv].target, gpg_strerror (err));
          last_err = err;
          continue; /* Not found - try next one. */
        }
      hostfound = 1;

      for (ai = aibuf; ai && !connected; ai = ai->next)
        {
          if (ai->family == AF_INET
              && ((flags & HTTP_FLAG_IGNORE_IPv4) || !v4_valid))
            continue;
          if (ai->family == AF_INET6
              && ((flags & HTTP_FLAG_IGNORE_IPv6) || !v6_valid))
            continue;

          if (sock != ASSUAN_INVALID_FD)
            assuan_sock_close (sock);
          sock = my_sock_new_for_addr (ai->addr, ai->socktype, ai->protocol);
          if (sock == ASSUAN_INVALID_FD)
            {
              if (errno == EAFNOSUPPORT)
                {
                  if (ai->family == AF_INET)
                    v4_valid = 0;
                  if (ai->family == AF_INET6)
                    v6_valid = 0;
                  continue;
                }

              err = gpg_err_make (default_errsource,
                                  gpg_err_code_from_syserror ());
              log_error ("error creating socket: %s\n", gpg_strerror (err));
              free_dns_addrinfo (aibuf);
              xfree (serverlist);
              return err;
            }

          anyhostaddr = 1;
          err = connect_with_timeout (sock, (struct sockaddr *)ai->addr,
                                      ai->addrlen, timeout);
          if (err)
            {
              last_err = err;
            }
          else
            {
              connected = 1;
              notify_netactivity ();
            }
        }
      free_dns_addrinfo (aibuf);
    }

  xfree (serverlist);

  if (!connected)
    {
      if (!hostfound)
        {
          log_error ("can't connect to '%s': %s\n",
                     server, "host not found");
          /* If the resolver told us "no name" translate this in this
           * case to "unknown host".  */
          if (gpg_err_code (last_err) == GPG_ERR_NO_NAME)
            last_err = 0;
        }
      else if (!anyhostaddr)
        log_error ("can't connect to '%s': %s\n",
                   server, "no IP address for host");
      else
        {
#ifdef HAVE_W32_SYSTEM
        log_error ("can't connect to '%s': ec=%d\n",
                   server, (int)WSAGetLastError());
#else
        log_error ("can't connect to '%s': %s\n",
                   server, gpg_strerror (last_err));
#endif
        }
      err = last_err? last_err : gpg_err_make (default_errsource,
                                               GPG_ERR_UNKNOWN_HOST);
      if (sock != ASSUAN_INVALID_FD)
	assuan_sock_close (sock);
      return err;
    }

  *r_sock = sock;
  return 0;
}


/* Helper to read from a socket.  This handles npth things and
 * EINTR.  */
static gpgrt_ssize_t
read_server (assuan_fd_t sock, void *buffer, size_t size)
{
  int nread;

  do
    {
#ifdef HAVE_W32_SYSTEM
      /* Under Windows we need to use recv for a socket.  */
# if defined(USE_NPTH)
      npth_unprotect ();
# endif
      nread = recv (FD2INT (sock), buffer, size, 0);
# if defined(USE_NPTH)
      npth_protect ();
# endif

#else /*!HAVE_W32_SYSTEM*/

# ifdef USE_NPTH
      nread = npth_read (sock, buffer, size);
# else
      nread = read (sock, buffer, size);
# endif

#endif /*!HAVE_W32_SYSTEM*/
    }
  while (nread == -1 && errno == EINTR);

  return nread;
}


static gpg_error_t
write_server (assuan_fd_t sock, const char *data, size_t length)
{
  int nleft;
  int nwritten;

  nleft = length;
  while (nleft > 0)
    {
#if defined(HAVE_W32_SYSTEM)
# if defined(USE_NPTH)
      npth_unprotect ();
# endif
      nwritten = send (FD2INT (sock), data, nleft, 0);
# if defined(USE_NPTH)
      npth_protect ();
# endif
      if ( nwritten == SOCKET_ERROR )
        {
          log_info ("network write failed: ec=%d\n", (int)WSAGetLastError ());
          return gpg_error (GPG_ERR_NETWORK);
        }
#else /*!HAVE_W32_SYSTEM*/
# ifdef USE_NPTH
      nwritten = npth_write (sock, data, nleft);
# else
      nwritten = write (sock, data, nleft);
# endif
      if (nwritten == -1)
	{
	  if (errno == EINTR)
	    continue;
	  if (errno == EAGAIN)
	    {
	      struct timeval tv;

	      tv.tv_sec = 0;
	      tv.tv_usec = 50000;
	      my_select (0, NULL, NULL, NULL, &tv);
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



/* Read handler for estream.  */
static gpgrt_ssize_t
cookie_read (void *cookie, void *buffer, size_t size)
{
  cookie_t c = cookie;
  int nread;
  size_t offset = 0;

  if (c->content_length_valid)
    {
      if (!c->content_length)
        {
          c->content_length_valid = 0;
          return 0; /* EOF */
        }
      if (c->content_length < size)
        size = c->content_length;
    }

  if (c->pending.len)
    {
      offset = c->pending.len > size? size : c->pending.len;
      memcpy (buffer, c->pending.data, offset);
      c->pending.len -= offset;
    }

  if (offset >= size)
    nread = offset;
  else
#if HTTP_USE_NTBTLS
  if (c->use_tls && c->session && c->session->tls_session)
    {
      estream_t in, out;

      ntbtls_get_stream (c->session->tls_session, &in, &out);
      nread = es_fread ((char*)buffer+offset, 1, size-offset, in);
      if (opt_debug)
        log_debug ("TLS network read: %d/%zu\n", nread, size-offset);
      if (nread >= 0)
        nread += offset;
    }
  else
#elif HTTP_USE_GNUTLS
  if (c->use_tls && c->session && c->session->tls_session)
    {
    again:
      nread = gnutls_record_recv (c->session->tls_session,
                                  (char*)buffer+offset, size-offset);
      if (nread < 0)
        {
          if (nread == GNUTLS_E_INTERRUPTED)
            goto again;
          if (nread == GNUTLS_E_AGAIN)
            {
              struct timeval tv;

              tv.tv_sec = 0;
              tv.tv_usec = 50000;
              my_select (0, NULL, NULL, NULL, &tv);
              goto again;
            }
          if (nread == GNUTLS_E_REHANDSHAKE)
            goto again; /* A client is allowed to just ignore this request. */
          if (nread == GNUTLS_E_PREMATURE_TERMINATION)
            {
              /* The server terminated the connection.  Close the TLS
                 session, and indicate EOF using a short read.  */
              close_tls_session (c->session);
              return 0;
            }
          log_info ("TLS network read failed: %s\n", gnutls_strerror (nread));
          gpg_err_set_errno (EIO);
          return -1;
        }
      if (nread >= 0)
        nread += offset;
    }
  else
#endif /*HTTP_USE_GNUTLS*/
    {
      nread = read_server (c->sock->fd, (char*)buffer+offset, size-offset);
      if (opt_debug)
        log_debug ("network read: %d/%zu\n", nread, size);
      if (nread >= 0)
        nread += offset;
    }

  if (nread > 0 && c->up_to_empty_line)
    {
      gpg_error_t err;
      const char *s;
      size_t n;
      int extra;
      int lfcr_pending = 0;
      char *bufp = buffer;

      if (c->last_was_lf && nread > 1 && bufp[0] == '\r' && bufp[1] == '\n')
        {
          s = buffer;
          extra = 2;
        }
      else if (c->last_was_lf && bufp[0] == '\r')
        {
          lfcr_pending = 1;
          s = buffer;  /* Only to avoid the call to gnupg_memstr.  */
        }
      else if (c->last_was_lfcr && bufp[0] == '\n')
        {
          s = buffer;
          extra = 1;
        }
      else
        s = NULL;

      c->last_was_lfcr = c->last_was_lf = 0;

      if (!s)
        {
          s = gnupg_memstr (buffer, nread, "\n\r\n");
          extra = 3;
        }

      if (lfcr_pending)
        c->last_was_lfcr = 1;
      else if (s)
        {
          /* Save away the rest and return up to the LF.  */
          log_assert (!c->pending.len);
          n = (s+extra) - bufp;
          log_assert (n <= nread);
          c->pending.len = nread - n;
          if (!c->pending.data || c->pending.len >= c->pending.size)
            {
              xfree (c->pending.data);
              c->pending.size = c->pending.len + 256;  /* Some extra space.  */
              c->pending.data = xtrymalloc (c->pending.size);
              if (!c->pending.data)
                {
                  err = gpg_error_from_syserror ();
                  log_error ("error allocating network read buffer: %s\n",
                             gpg_strerror (err));
                  return -1;
                }
              memcpy (c->pending.data, bufp + n, c->pending.len);
            }
          else
            memcpy (c->pending.data, bufp + n, c->pending.len);
          nread = n;  /* Return everything up to the empty line.  */
          c->up_to_empty_line = 0;
        }
      else if (bufp[nread-1] == '\n')
        c->last_was_lf = 1;
      else if (nread > 1 && bufp[nread-2] == '\n' && bufp[nread-1] == '\r')
        c->last_was_lfcr = 1;
    }

  if (c->content_length_valid && nread > 0)
    {
      if (nread < c->content_length)
        c->content_length -= nread;
      else
        c->content_length = 0;
    }

  return (gpgrt_ssize_t)nread;
}

/* Write handler for estream.  */
static gpgrt_ssize_t
cookie_write (void *cookie, const void *buffer_arg, size_t size)
{
  const char *buffer = buffer_arg;
  cookie_t c = cookie;
  int nwritten = 0;

#if HTTP_USE_NTBTLS
  if (c->use_tls && c->session && c->session->tls_session)
    {
      estream_t in, out;

      ntbtls_get_stream (c->session->tls_session, &in, &out);
      if (size == 0)
        es_fflush (out);
      else
        nwritten = es_fwrite (buffer, 1, size, out);
      if (opt_debug)
        log_debug ("TLS network write: %d/%zu\n", nwritten, size);
    }
  else
#elif HTTP_USE_GNUTLS
  if (c->use_tls && c->session && c->session->tls_session)
    {
      int nleft = size;
      while (nleft > 0)
        {
          nwritten = gnutls_record_send (c->session->tls_session,
                                         buffer, nleft);
          if (nwritten <= 0)
            {
              if (nwritten == GNUTLS_E_INTERRUPTED)
                continue;
              if (nwritten == GNUTLS_E_AGAIN)
                {
                  struct timeval tv;

                  tv.tv_sec = 0;
                  tv.tv_usec = 50000;
                  my_select (0, NULL, NULL, NULL, &tv);
                  continue;
                }
              log_info ("TLS network write failed: %s\n",
                        gnutls_strerror (nwritten));
              gpg_err_set_errno (EIO);
              return -1;
            }
          nleft -= nwritten;
          buffer += nwritten;
        }
    }
  else
#endif /*HTTP_USE_GNUTLS*/
    {
      if ( write_server (c->sock->fd, buffer, size) )
        {
          gpg_err_set_errno (EIO);
          nwritten = -1;
        }
      else
        nwritten = size;
    }

  return (gpgrt_ssize_t)nwritten;
}


#if defined(HAVE_W32_SYSTEM) && defined(HTTP_USE_NTBTLS)
static gpgrt_ssize_t
simple_cookie_read (void *cookie, void *buffer, size_t size)
{
  assuan_fd_t sock = (assuan_fd_t)cookie;
  return read_server (sock, buffer, size);
}

static gpgrt_ssize_t
simple_cookie_write (void *cookie, const void *buffer_arg, size_t size)
{
  assuan_fd_t sock = (assuan_fd_t)cookie;
  const char *buffer = buffer_arg;
  int nwritten;

  if (write_server (sock, buffer, size))
    {
      gpg_err_set_errno (EIO);
      nwritten = -1;
    }
  else
    nwritten = size;

  return (gpgrt_ssize_t)nwritten;
}
#endif /*HAVE_W32_SYSTEM*/


#ifdef HTTP_USE_GNUTLS
/* Wrapper for gnutls_bye used by my_socket_unref.  */
static void
send_gnutls_bye (void *opaque)
{
  tls_session_t tls_session = opaque;
  int ret;

 again:
  do
    ret = gnutls_bye (tls_session, GNUTLS_SHUT_RDWR);
  while (ret == GNUTLS_E_INTERRUPTED);
  if (ret == GNUTLS_E_AGAIN)
    {
      struct timeval tv;

      tv.tv_sec = 0;
      tv.tv_usec = 50000;
      my_select (0, NULL, NULL, NULL, &tv);
      goto again;
    }
}
#endif /*HTTP_USE_GNUTLS*/

/* Close handler for estream.  */
static int
cookie_close (void *cookie)
{
  cookie_t c = cookie;

  if (!c)
    return 0;

#if HTTP_USE_NTBTLS
  if (c->use_tls && c->session && c->session->tls_session)
    {
      /* FIXME!! Possibly call ntbtls_close_notify for close
         of write stream.  */
      my_socket_unref (c->sock, NULL, NULL);
    }
  else
#elif HTTP_USE_GNUTLS
  if (c->use_tls && c->session && c->session->tls_session)
    my_socket_unref (c->sock, send_gnutls_bye, c->session->tls_session);
  else
#endif /*HTTP_USE_GNUTLS*/
    if (c->sock)
      my_socket_unref (c->sock, NULL, NULL);

  if (c->session)
    http_session_unref (c->session);
  xfree (c->pending.data);
  xfree (c);
  return 0;
}




/* Verify the credentials of the server.  Returns 0 on success and
   store the result in the session object.  Only used by GNUTLS.  */
gpg_error_t
http_verify_server_credentials (http_session_t sess)
{
#if HTTP_USE_GNUTLS
  static const char errprefix[] = "TLS verification of peer failed";
  int rc;
  unsigned int status;
  const char *hostname;
  const gnutls_datum_t *certlist;
  unsigned int certlistlen;
  gnutls_x509_crt_t cert;
  gpg_error_t err = 0;

  sess->verify.done = 1;
  sess->verify.status = 0;
  sess->verify.rc = GNUTLS_E_CERTIFICATE_ERROR;

  if (gnutls_certificate_type_get (sess->tls_session) != GNUTLS_CRT_X509)
    {
      log_error ("%s: %s\n", errprefix, "not an X.509 certificate");
      sess->verify.rc = GNUTLS_E_UNSUPPORTED_CERTIFICATE_TYPE;
      return gpg_error (GPG_ERR_GENERAL);
    }

  rc = gnutls_certificate_verify_peers2 (sess->tls_session, &status);
  if (rc)
    {
      log_error ("%s: %s\n", errprefix, gnutls_strerror (rc));
      if (!err)
        err = gpg_error (GPG_ERR_GENERAL);
    }
  else if (status)
    {
      gnutls_datum_t statusdat;

      log_error ("%s: status=0x%04x\n", errprefix, status);
      if (!gnutls_certificate_verification_status_print
          (status, GNUTLS_CRT_X509, &statusdat, 0))
        {
          log_info ("%s: %s\n", errprefix, statusdat.data);
          gnutls_free (statusdat.data);
        }

      sess->verify.status = status;
      if (!err)
        err = gpg_error (GPG_ERR_GENERAL);
    }

  hostname = sess->servername;
  if (!hostname || !strchr (hostname, '.'))
    {
      log_error ("%s: %s\n", errprefix, "hostname missing");
      if (!err)
        err = gpg_error (GPG_ERR_GENERAL);
    }

  certlist = gnutls_certificate_get_peers (sess->tls_session, &certlistlen);
  if (!certlistlen)
    {
      log_error ("%s: %s\n", errprefix, "server did not send a certificate");
      if (!err)
        err = gpg_error (GPG_ERR_GENERAL);

      /* Need to stop here.  */
      if (err)
        return err;
    }

  rc = gnutls_x509_crt_init (&cert);
  if (rc < 0)
    {
      if (!err)
        err = gpg_error (GPG_ERR_GENERAL);
      if (err)
        return err;
    }

  rc = gnutls_x509_crt_import (cert, &certlist[0], GNUTLS_X509_FMT_DER);
  if (rc < 0)
    {
      log_error ("%s: %s: %s\n", errprefix, "error importing certificate",
                 gnutls_strerror (rc));
      if (!err)
        err = gpg_error (GPG_ERR_GENERAL);
    }

  if (!gnutls_x509_crt_check_hostname (cert, hostname))
    {
      log_error ("%s: %s\n", errprefix, "hostname does not match");
      if (!err)
        err = gpg_error (GPG_ERR_GENERAL);
    }

  gnutls_x509_crt_deinit (cert);

  if (!err)
    sess->verify.rc = 0;

  if (sess->cert_log_cb)
    {
      const void *bufarr[10];
      size_t buflenarr[10];
      size_t n;

      for (n = 0; n < certlistlen && n < DIM (bufarr)-1; n++)
        {
          bufarr[n] = certlist[n].data;
          buflenarr[n] = certlist[n].size;
        }
      bufarr[n] = NULL;
      buflenarr[n] = 0;
      sess->cert_log_cb (sess, err, hostname, bufarr, buflenarr);
    }

  return err;
#else /*!HTTP_USE_GNUTLS*/
  (void)sess;
  return gpg_error (GPG_ERR_NOT_IMPLEMENTED);
#endif
}

/* Return the first query variable with the specified key.  If there
   is no such variable, return NULL.  */
struct uri_tuple_s *
uri_query_lookup (parsed_uri_t uri, const char *key)
{
  struct uri_tuple_s *t;

  for (t = uri->query; t; t = t->next)
    if (strcmp (t->name, key) == 0)
      return t;

  return NULL;
}

const char *
uri_query_value (parsed_uri_t url, const char *key)
{
  struct uri_tuple_s *t;
  t = uri_query_lookup (url, key);
  return t? t->value : NULL;
}



/* Return true if both URI point to the same host for the purpose of
 * redirection check.  A is the original host and B the host given in
 * the Location header.  As a temporary workaround a fixed list of
 * exceptions is also consulted.  */
static int
same_host_p (parsed_uri_t a, parsed_uri_t b)
{
  static struct
  {
    const char *from;  /* NULL uses the last entry from the table.  */
    const char *to;
  } allow[] =
  {
    { "protonmail.com", "api.protonmail.com" },
    { NULL,             "api.protonmail.ch"  },
    { "protonmail.ch",  "api.protonmail.com" },
    { NULL,             "api.protonmail.ch"  },
    { "pm.me",          "api.protonmail.ch"  }
  };
  static const char *subdomains[] =
    {
      "openpgpkey."
    };
  int i;
  const char *from;

  if (!a->host || !b->host)
    return 0;

  if (!ascii_strcasecmp (a->host, b->host))
    return 1;

  from = NULL;
  for (i=0; i < DIM (allow); i++)
    {
      if (allow[i].from)
        from = allow[i].from;
      if (!from)
        continue;
      if (!ascii_strcasecmp (from, a->host)
          && !ascii_strcasecmp (allow[i].to, b->host))
        return 1;
    }

  /* Also consider hosts the same if they differ only in a subdomain;
   * in both direction.  This allows to have redirection between the
   * WKD advanced and direct lookup methods. */
  for (i=0; i < DIM (subdomains); i++)
    {
      const char *subdom = subdomains[i];
      size_t subdomlen = strlen (subdom);

      if (!ascii_strncasecmp (a->host, subdom, subdomlen)
          && !ascii_strcasecmp (a->host + subdomlen, b->host))
        return 1;
      if (!ascii_strncasecmp (b->host, subdom, subdomlen)
          && !ascii_strcasecmp (b->host + subdomlen, a->host))
        return 1;
    }

  return 0;
}


/* Prepare a new URL for a HTTP redirect.  INFO has flags controlling
 * the operation, STATUS_CODE is used for diagnostics, LOCATION is the
 * value of the "Location" header, and R_URL reveives the new URL on
 * success or NULL or error.  Note that INFO->ORIG_URL is
 * required.  */
gpg_error_t
http_prepare_redirect (http_redir_info_t *info, unsigned int status_code,
                       const char *location, char **r_url)
{
  gpg_error_t err;
  parsed_uri_t locuri;
  parsed_uri_t origuri;
  char *newurl;
  char *p;

  *r_url = NULL;

  if (!info || !info->orig_url)
    return gpg_error (GPG_ERR_INV_ARG);

  if (!info->silent)
    log_info (_("URL '%s' redirected to '%s' (%u)\n"),
              info->orig_url, location? location:"[none]", status_code);

  if (!info->redirects_left)
    {
      if (!info->silent)
        log_error (_("too many redirections\n"));
      return gpg_error (GPG_ERR_NO_DATA);
    }
  info->redirects_left--;

  if (!location || !*location)
    return gpg_error (GPG_ERR_NO_DATA);

  err = http_parse_uri (&locuri, location, 0);
  if (err)
    return err;

  /* Make sure that an onion address only redirects to another
   * onion address, or that a https address only redirects to a
   * https address. */
  if (info->orig_onion && !locuri->onion)
    {
      dirmngr_status_printf (info->ctrl, "WARNING",
                             "http_redirect %u"
                             " redirect from onion to non-onion address"
                             " rejected",
                             err);
      http_release_parsed_uri (locuri);
      return gpg_error (GPG_ERR_FORBIDDEN);
    }
  if (!info->allow_downgrade && info->orig_https && !locuri->use_tls)
    {
      err = gpg_error (GPG_ERR_FORBIDDEN);
      dirmngr_status_printf (info->ctrl, "WARNING",
                             "http_redirect %u"
                             " redirect '%s' to '%s' rejected",
                             err, info->orig_url, location);
      http_release_parsed_uri (locuri);
      return err;
    }

  if (info->trust_location)
    {
      /* We trust the Location - return it verbatim.  */
      http_release_parsed_uri (locuri);
      newurl = xtrystrdup (location);
      if (!newurl)
        {
          err = gpg_error_from_syserror ();
          http_release_parsed_uri (locuri);
          return err;
        }
    }
  else if ((err = http_parse_uri (&origuri, info->orig_url, 0)))
    {
      http_release_parsed_uri (locuri);
      return err;
    }
  else if (same_host_p (origuri, locuri))
    {
      /* The host is the same or on an exception list and thus we can
       * take the location verbatim.  */
      http_release_parsed_uri (origuri);
      http_release_parsed_uri (locuri);
      newurl = xtrystrdup (location);
      if (!newurl)
        {
          err = gpg_error_from_syserror ();
          http_release_parsed_uri (locuri);
          return err;
        }
    }
  else
    {
      /* We take only the host and port from the URL given in the
       * Location.  This limits the effects of redirection attacks by
       * rogue hosts returning an URL to servers in the client's own
       * network.  We don't even include the userinfo because they
       * should be considered similar to the path and query parts.
       */
      if (!(locuri->off_path - locuri->off_host))
        {
          http_release_parsed_uri (origuri);
          http_release_parsed_uri (locuri);
          return gpg_error (GPG_ERR_BAD_URI);
        }
      if (!(origuri->off_path - origuri->off_host))
        {
          http_release_parsed_uri (origuri);
          http_release_parsed_uri (locuri);
          return gpg_error (GPG_ERR_BAD_URI);
        }

      newurl = xtrymalloc (strlen (origuri->original)
                           + (locuri->off_path - locuri->off_host) + 1);
      if (!newurl)
        {
          err = gpg_error_from_syserror ();
          http_release_parsed_uri (origuri);
          http_release_parsed_uri (locuri);
          return err;
        }
      /* Build new URL from
       *   uriguri:  scheme userinfo ---- ---- path rest
       *   locuri:   ------ -------- host port ---- ----
       */
      p = newurl;
      memcpy (p, origuri->original, origuri->off_host);
      p += origuri->off_host;
      memcpy (p, locuri->original + locuri->off_host,
              (locuri->off_path - locuri->off_host));
      p += locuri->off_path - locuri->off_host;
      strcpy (p, origuri->original + origuri->off_path);

      http_release_parsed_uri (origuri);
      http_release_parsed_uri (locuri);
      if (!info->silent)
        log_info (_("redirection changed to '%s'\n"), newurl);
      dirmngr_status_printf (info->ctrl, "WARNING",
                             "http_redirect_cleanup %u"
                             " changed from '%s' to '%s'",
                             0, info->orig_url, newurl);
    }

  *r_url = newurl;
  return 0;
}


/* Return string describing the http STATUS.  Returns an empty string
 * for an unknown status.  */
const char *
http_status2string (unsigned int status)
{
  switch (status)
    {
    case 500: return "Internal Server Error";
    case 501: return "Not Implemented";
    case 502: return "Bad Gateway";
    case 503: return "Service Unavailable";
    case 504: return "Gateway Timeout";
    case 505: return "HTTP version Not Supported";
    case 506: return "Variant Also Negation";
    case 507: return "Insufficient Storage";
    case 508: return "Loop Detected";
    case 510: return "Not Extended";
    case 511: return "Network Authentication Required";
    }

  return "";
}


/* Fucntion called on SIGHUP to flush internal variables.  */
void
http_reinitialize (void)
{
#ifdef HAVE_W32_SYSTEM
  w32_get_internet_session (1);  /* Clear our session.  */
#endif /*HAVE_W32_SYSTEM*/
}
