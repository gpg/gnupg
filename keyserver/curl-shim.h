/* curl-shim.h
 * Copyright (C) 2005, 2006, 2007 Free Software Foundation, Inc.
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
 */

#ifndef _CURL_SHIM_H_
#define _CURL_SHIM_H_

#include "http.h"

typedef enum
  {
    CURLE_OK=0,
    CURLE_UNSUPPORTED_PROTOCOL=1,
    CURLE_COULDNT_CONNECT=7,
    CURLE_FTP_COULDNT_RETR_FILE=19,
    CURLE_HTTP_RETURNED_ERROR=22,
    CURLE_WRITE_ERROR=23
  } CURLcode;

typedef enum
  {
    CURLOPT_URL,
    CURLOPT_USERPWD,
    CURLOPT_WRITEFUNCTION,
    CURLOPT_FILE,
    CURLOPT_ERRORBUFFER,
    CURLOPT_FOLLOWLOCATION,
    CURLOPT_MAXREDIRS,
    CURLOPT_STDERR,
    CURLOPT_VERBOSE,
    CURLOPT_SSL_VERIFYPEER,
    CURLOPT_PROXY,
    CURLOPT_CAINFO,
    CURLOPT_POST,
    CURLOPT_POSTFIELDS,
    CURLOPT_FAILONERROR
  } CURLoption;

typedef size_t (*write_func)(char *buffer,size_t size,
			     size_t nitems,void *outstream);

typedef struct
{
  char *url;
  char *auth;
  char *errorbuffer;
  char *proxy;
  write_func writer;
  void *file;
  char *postfields;
  unsigned int status;
  FILE *errors;
  struct
  {
    unsigned int post:1;
    unsigned int failonerror:1;
    unsigned int verbose:1;
  } flags;
  struct http_context hd;
} CURL;

typedef struct
{
  const char **protocols;
} curl_version_info_data; 

#define CURL_ERROR_SIZE 256
#define CURL_GLOBAL_DEFAULT 0
#define CURLVERSION_NOW 0

CURLcode curl_global_init(long flags);
void curl_global_cleanup(void);
CURL *curl_easy_init(void);
CURLcode curl_easy_setopt(CURL *curl,CURLoption option,...);
CURLcode curl_easy_perform(CURL *curl);
void curl_easy_cleanup(CURL *curl);
char *curl_easy_escape(CURL *curl,char *str,int len);
#define curl_free(x) free(x)
#define curl_version() "GnuPG curl-shim "VERSION
curl_version_info_data *curl_version_info(int type);

#endif /* !_CURL_SHIM_H_ */
