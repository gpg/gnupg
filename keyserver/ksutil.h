/* ksutil.h
 * Copyright (C) 2004, 2005 Free Software Foundation, Inc.
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

#ifndef _KSUTIL_H_
#define _KSUTIL_H_

#define GET    0
#define SEND   1
#define SEARCH 2

/* MAX_LINE must be 1 larger than the largest item we expect to
   receive. */
#define MAX_LINE    1080

#define MAX_COMMAND    6
#define MAX_OPTION   256
#define MAX_SCHEME    20
#define MAX_OPAQUE  1024
#define MAX_AUTH     128
#define MAX_HOST      80
#define MAX_PORT      10
#define URLMAX_PATH 1024
#define MAX_PROXY    128
#define MAX_URL     (MAX_SCHEME+1+3+MAX_AUTH+1+1+MAX_HOST+1+1 \
                     +MAX_PORT+1+1+URLMAX_PATH+1+50)

#define STRINGIFY(x) #x
#define MKSTRING(x) STRINGIFY(x)

#define BEGIN "-----BEGIN PGP PUBLIC KEY BLOCK-----"
#define END   "-----END PGP PUBLIC KEY BLOCK-----"

struct keylist
{
  char str[MAX_LINE];
  struct keylist *next;
};

/* 2 minutes seems reasonable */
#define DEFAULT_KEYSERVER_TIMEOUT 120

unsigned int set_timeout(unsigned int seconds);
int register_timeout(void);

enum ks_action {KS_UNKNOWN=0,KS_GET,KS_SEND,KS_SEARCH};

struct ks_options
{
  enum ks_action action;
  char *host;
  char *port;
  char *scheme;
  char *auth;
  char *path;
  char *opaque;
  struct
  {
    unsigned int include_disabled:1;
    unsigned int include_revoked:1;
    unsigned int include_subkeys:1;
    unsigned int check_cert:1;
  } flags;
  unsigned int verbose;
  unsigned int debug;
  unsigned int timeout;
  char *ca_cert_file;
};

struct ks_options *init_ks_options(void);
void free_ks_options(struct ks_options *opt);
int parse_ks_options(char *line,struct ks_options *opt);
const char *ks_action_to_string(enum ks_action action);
void print_nocr(FILE *stream,const char *str);

#endif /* !_KSUTIL_H_ */
