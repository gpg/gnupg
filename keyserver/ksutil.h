/* ksutil.h
 * Copyright (C) 2004, 2005, 2006 Free Software Foundation, Inc.
 *
 * This file is part of GNUPG.
 *
 * GNUPG is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 *
 * GNUPG is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, see <http://www.gnu.org/licenses/>.
 *
 * In addition, as a special exception, the Free Software Foundation
 * gives permission to link the code of the keyserver helper tools:
 * gpgkeys_ldap, gpgkeys_curl and gpgkeys_hkp with the OpenSSL
 * project's "OpenSSL" library (or with modified versions of it that
 * use the same license as the "OpenSSL" library), and distribute the
 * linked executables.  You must obey the GNU General Public License
 * in all respects for all of the code used other than "OpenSSL".  If
 * you modify this file, you may extend this exception to your version
 * of the file, but you are not obligated to do so.  If you do not
 * wish to do so, delete this exception statement from your version.
 */

#ifndef _KSUTIL_H_
#define _KSUTIL_H_

#ifdef HAVE_LIBCURL
#include <curl/curl.h>
#else
#include "curl-shim.h"
#endif

/* MAX_LINE must be at least 1 larger than the largest item we expect
   to receive, including the name tag ("COMMAND", "PORT", etc) and
   space between.  In practice, that means it should be
   strlen("OPAQUE")+1+sizeof_opaque+1 */
#define MAX_LINE       (6+1+1024+1)

#define MAX_COMMAND    7
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

#ifdef __riscos__
#define HTTP_PROXY_ENV           "GnuPG$HttpProxy"
#else
#define HTTP_PROXY_ENV           "http_proxy"
#endif

struct keylist
{
  char str[MAX_LINE];
  struct keylist *next;
};

/* 2 minutes seems reasonable */
#define DEFAULT_KEYSERVER_TIMEOUT 120

unsigned int set_timeout(unsigned int seconds);
int register_timeout(void);

enum ks_action {KS_UNKNOWN=0,KS_GET,KS_GETNAME,KS_SEND,KS_SEARCH};

enum ks_search_type {KS_SEARCH_SUBSTR,KS_SEARCH_EXACT,
		     KS_SEARCH_MAIL,KS_SEARCH_MAILSUB,
		     KS_SEARCH_KEYID_LONG,KS_SEARCH_KEYID_SHORT};

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
enum ks_search_type classify_ks_search(const char **search);

int curl_err_to_gpg_err(CURLcode error);

struct curl_writer_ctx
{
  struct
  {
    unsigned int initialized:1;
    unsigned int begun:1;
    unsigned int done:1;
    unsigned int armor:1;
  } flags;

  int armor_remaining;
  unsigned char armor_ctx[3];
  int markeridx,linelen;
  const char *marker;
  FILE *stream;
};

size_t curl_writer(const void *ptr,size_t size,size_t nmemb,void *cw_ctx);
void curl_writer_finalize(struct curl_writer_ctx *ctx);

#endif /* !_KSUTIL_H_ */
