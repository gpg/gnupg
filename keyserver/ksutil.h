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

/* 30 seconds seems reasonable */
#define DEFAULT_KEYSERVER_TIMEOUT 30

unsigned int set_timeout(unsigned int seconds);
int register_timeout(void);

#endif /* !_KSUTIL_H_ */
