/* http.h  -  HTTP protocol handler
 * Copyright (C) 1999, 2000, 2001, 2003, 2006,
 *               2010 Free Software Foundation, Inc.
 * Copyright (C) 2015  g10 Code GmbH
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
#ifndef GNUPG_COMMON_HTTP_H
#define GNUPG_COMMON_HTTP_H

#include <gpg-error.h>

struct uri_tuple_s
{
  struct uri_tuple_s *next;
  const char *name;	/* A pointer into name. */
  char  *value;         /* A pointer to value (a Nul is always appended). */
  size_t valuelen;	/* The real length of the value; we need it
			   because the value may contain embedded Nuls. */
  int no_value;         /* True if no value has been given in the URL. */
};
typedef struct uri_tuple_s *uri_tuple_t;

struct parsed_uri_s
{
  /* All these pointers point into BUFFER; most stuff is not escaped. */
  char *scheme;	        /* Pointer to the scheme string (always lowercase). */
  unsigned int is_http:1; /* This is a HTTP style URI.   */
  unsigned int use_tls:1; /* Whether TLS should be used. */
  unsigned int opaque:1;/* Unknown scheme; PATH has the rest.  */
  unsigned int v6lit:1; /* Host was given as a literal v6 address.  */
  unsigned int onion:1; /* .onion address given.  */
  unsigned int explicit_port :1; /* The port was explicitly specified.  */
  char *auth;           /* username/password for basic auth.  */
  char *host; 	        /* Host (converted to lowercase). */
  unsigned short port;  /* Port (always set if the host is set). */
  char *path; 	        /* Path. */
  uri_tuple_t params;	/* ";xxxxx" */
  uri_tuple_t query;	/* "?xxx=yyy" */
  char buffer[1];	/* Buffer which holds a (modified) copy of the URI. */
};
typedef struct parsed_uri_s *parsed_uri_t;

struct uri_tuple_s *uri_query_lookup (parsed_uri_t uri, const char *key);

typedef enum
  {
    HTTP_REQ_GET  = 1,
    HTTP_REQ_HEAD = 2,
    HTTP_REQ_POST = 3,
    HTTP_REQ_OPAQUE = 4  /* Internal use.  */
  }
http_req_t;

/* We put the flag values into an enum, so that gdb can display them. */
enum
  {
    HTTP_FLAG_TRY_PROXY = 1,     /* Try to use a proxy.  */
    HTTP_FLAG_SHUTDOWN = 2,      /* Close sending end after the request.  */
    HTTP_FLAG_FORCE_TOR = 4,     /* Force a TOR connection.  */
    HTTP_FLAG_LOG_RESP = 8,      /* Log the server response.  */
    HTTP_FLAG_FORCE_TLS = 16,    /* Force the use of TLS.  */
    HTTP_FLAG_IGNORE_CL = 32,    /* Ignore content-length.  */
    HTTP_FLAG_IGNORE_IPv4 = 64,  /* Do not use IPv4.  */
    HTTP_FLAG_IGNORE_IPv6 = 128, /* Do not use IPv6.  */
    HTTP_FLAG_TRUST_DEF   = 256, /* Use the CAs configured for HKP.  */
    HTTP_FLAG_TRUST_SYS   = 512, /* Also use the system defined CAs.  */
    HTTP_FLAG_NO_CRL     = 1024  /* Do not consult CRLs for https.  */
  };


struct http_session_s;
typedef struct http_session_s *http_session_t;

struct http_context_s;
typedef struct http_context_s *http_t;

/* A TLS verify callback function.  */
typedef gpg_error_t (*http_verify_cb_t) (void *opaque,
                                         http_t http,
                                         http_session_t session,
                                         unsigned int flags,
                                         void *tls_context);

void http_set_verbose (int verbose, int debug);

void http_register_tls_callback (gpg_error_t (*cb)(http_t,http_session_t,int));
void http_register_tls_ca (const char *fname);
void http_register_netactivity_cb (void (*cb)(void));


gpg_error_t http_session_new (http_session_t *r_session,
                              const char *intended_hostname,
                              unsigned int flags,
                              http_verify_cb_t cb,
                              void *cb_value);
http_session_t http_session_ref (http_session_t sess);
void http_session_release (http_session_t sess);

void http_session_set_log_cb (http_session_t sess,
                              void (*cb)(http_session_t, gpg_error_t,
                                         const char *,
                                         const void **, size_t *));


gpg_error_t http_parse_uri (parsed_uri_t *ret_uri, const char *uri,
                            int no_scheme_check);

void http_release_parsed_uri (parsed_uri_t uri);

gpg_error_t http_raw_connect (http_t *r_hd,
                              const char *server, unsigned short port,
                              unsigned int flags, const char *srvtag);

gpg_error_t http_open (http_t *r_hd, http_req_t reqtype,
                       const char *url,
                       const char *httphost,
                       const char *auth,
                       unsigned int flags,
                       const char *proxy,
                       http_session_t session,
                       const char *srvtag,
                       strlist_t headers);

void http_start_data (http_t hd);

gpg_error_t http_wait_response (http_t hd);

void http_close (http_t hd, int keep_read_stream);

gpg_error_t http_open_document (http_t *r_hd,
                                const char *document,
                                const char *auth,
                                unsigned int flags,
                                const char *proxy,
                                http_session_t session,
                                const char *srvtag,
                                strlist_t headers);

estream_t http_get_read_ptr (http_t hd);
estream_t http_get_write_ptr (http_t hd);
unsigned int http_get_status_code (http_t hd);
const char *http_get_tls_info (http_t hd, const char *what);
const char *http_get_header (http_t hd, const char *name);
const char **http_get_header_names (http_t hd);
gpg_error_t http_verify_server_credentials (http_session_t sess);

char *http_escape_string (const char *string, const char *specials);
char *http_escape_data (const void *data, size_t datalen, const char *specials);


#endif /*GNUPG_COMMON_HTTP_H*/
