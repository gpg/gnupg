/* rfc822parse.h - Simple mail and MIME parser
 * Copyright (C) 1999 Werner Koch, Duesseldorf
 * Copyright (C) 2003 g10 Code GmbH
 *
 * This file is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as
 * published by the Free Software Foundation; either version 2.1 of
 * the License, or (at your option) any later version.
 *
 * This file is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with this program; if not, see <https://www.gnu.org/licenses/>.
 */

#ifndef RFC822PARSE_H
#define RFC822PARSE_H

struct rfc822parse_context;
typedef struct rfc822parse_context *rfc822parse_t;

typedef enum
  {
    RFC822PARSE_OPEN = 1,
    RFC822PARSE_CLOSE,
    RFC822PARSE_CANCEL,
    RFC822PARSE_T2BODY,
    RFC822PARSE_FINISH,
    RFC822PARSE_RCVD_SEEN,
    RFC822PARSE_LEVEL_DOWN,
    RFC822PARSE_LEVEL_UP,
    RFC822PARSE_BOUNDARY,
    RFC822PARSE_LAST_BOUNDARY,
    RFC822PARSE_BEGIN_HEADER,
    RFC822PARSE_PREAMBLE,
    RFC822PARSE_EPILOGUE
  }
rfc822parse_event_t;

struct rfc822parse_field_context;
typedef struct rfc822parse_field_context *rfc822parse_field_t;


typedef int (*rfc822parse_cb_t) (void *opaque,
                                 rfc822parse_event_t event,
                                 rfc822parse_t msg);

int rfc822_valid_header_name_p (const char *name);
void rfc822_capitalize_header_name (char *name);

rfc822parse_t rfc822parse_open (rfc822parse_cb_t cb, void *opaque_value);

void rfc822parse_close (rfc822parse_t msg);

void rfc822parse_cancel (rfc822parse_t msg);
int rfc822parse_finish (rfc822parse_t msg);

int rfc822parse_insert (rfc822parse_t msg,
                        const unsigned char *line, size_t length);

char *rfc822parse_get_field (rfc822parse_t msg, const char *name, int which,
                             size_t *valueoff);

const char *rfc822parse_enum_header_lines (rfc822parse_t msg, void **context);

rfc822parse_field_t rfc822parse_parse_field (rfc822parse_t msg,
                                             const char *name,
                                             int which);

void rfc822parse_release_field (rfc822parse_field_t field);

const char *rfc822parse_query_parameter (rfc822parse_field_t ctx,
                                         const char *attr, int lower_value);

const char *rfc822parse_query_media_type (rfc822parse_field_t ctx,
                                          const char **subtype);

#endif /*RFC822PARSE_H */
