/* http.h  -  HTTP protocol handler
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
#ifndef G10_HTTP_H
#define G10_HTTP_H 1

#include "iobuf.h"

struct uri_tuple {
    struct uri_tuple *next;
    const char *name;	/* a pointer into name */
    char  *value;	/* a pointer to value (a Nul is always appended) */
    size_t valuelen;	/* and the real length of the value */
			/* because the value may contain embedded Nuls */
};
typedef struct uri_tuple *URI_TUPLE;

struct parsed_uri {
    /* all these pointers point into buffer; most stuff is not escaped */
    char *scheme;	/* pointer to the scheme string (lowercase) */
    char *host; 	/* host (converted to lowercase) */
    ushort port;	/* port (always set if the host is set) */
    char *path; 	/* the path */
    URI_TUPLE params;	/* ";xxxxx" */
    URI_TUPLE query;	/* "?xxx=yyy" */
    char buffer[1];	/* buffer which holds a (modified) copy of the URI */
};
typedef struct parsed_uri *PARSED_URI;

struct http_context {
    int initialized;
    unsigned int status_code;
    int socket;
    IOBUF fp_read;
    IOBUF fp_write;
    int is_http_0_9;
    PARSED_URI uri;
    byte *buffer;	   /* line buffer */
    unsigned buffer_size;
};
typedef struct http_context *HTTP_HD;

int open_http_document( HTTP_HD hd, const char *document, unsigned int flags );
void close_http_document( HTTP_HD hd );

#endif /*G10_HTTP_H*/
