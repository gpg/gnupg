/* http.h  -  HTTP protocol handler
 * Copyright (C) 1999, 2000, 2001, 2003,
 *               2006 Free Software Foundation, Inc.
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
#ifndef GNUPG_COMMON_HTTP_H
#define GNUPG_COMMON_HTTP_H 

#include <gpg-error.h>
#ifdef HTTP_USE_ESTREAM
#include "estream.h"
#endif

struct uri_tuple_s {
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
  char *scheme;	        /* Pointer to the scheme string (lowercase). */
  int use_tls;          /* Whether TLS should be used. */
  char *auth;           /* username/password for basic auth */
  char *host; 	        /* Host (converted to lowercase). */
  unsigned short port;  /* Port (always set if the host is set). */
  char *path; 	        /* Path. */
  uri_tuple_t params;	/* ";xxxxx" */
  uri_tuple_t query;	/* "?xxx=yyy" */
  char buffer[1];	/* Buffer which holds a (modified) copy of the URI. */
};
typedef struct parsed_uri_s *parsed_uri_t;

typedef enum 
  {
    HTTP_REQ_GET  = 1,
    HTTP_REQ_HEAD = 2,
    HTTP_REQ_POST = 3
  } 
http_req_t;

/* We put the flag values into an enum, so that gdb can display them. */
enum
  { 
    HTTP_FLAG_TRY_PROXY = 1,
    HTTP_FLAG_NO_SHUTDOWN = 2,
    HTTP_FLAG_LOG_RESP = 4,
    HTTP_FLAG_NEED_HEADER = 8
  };

struct http_context_s;
typedef struct http_context_s *http_t;

void http_register_tls_callback (gpg_error_t (*cb) (http_t, void *, int));

gpg_error_t http_parse_uri (parsed_uri_t *ret_uri, const char *uri);

void http_release_parsed_uri (parsed_uri_t uri);

gpg_error_t http_open (http_t *r_hd, http_req_t reqtype,
                       const char *url,
                       const char *auth,
                       unsigned int flags,
                       const char *proxy,
                       void *tls_context,
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
                                void *tls_context,
				const char *srvtag,
				strlist_t headers);

#ifdef HTTP_USE_ESTREAM
estream_t http_get_read_ptr (http_t hd);
estream_t http_get_write_ptr (http_t hd);
#else /*!HTTP_USE_ESTREAM*/
FILE *http_get_read_ptr (http_t hd);
FILE *http_get_write_ptr (http_t hd);
#endif /*!HTTP_USE_ESTREAM*/
unsigned int http_get_status_code (http_t hd);
const char *http_get_header (http_t hd, const char *name);

char *http_escape_string (const char *string, const char *specials);


#endif /*GNUPG_COMMON_HTTP_H*/
