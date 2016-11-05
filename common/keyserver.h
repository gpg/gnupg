/* keyserver.h - Public definitions for gpg keyserver helpers.
 * Copyright (C) 2001, 2002, 2011 Free Software Foundation, Inc.
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

#ifndef GNUPG_COMMON_KEYSERVER_H
#define GNUPG_COMMON_KEYSERVER_H

#define KEYSERVER_PROTO_VERSION    1

/* These are usable for return codes for the gpgkeys_ process, and
   also KEY FAILED codes. */
#define KEYSERVER_OK               0 /* not an error */
#define KEYSERVER_INTERNAL_ERROR   1 /* gpgkeys_ internal error */
#define KEYSERVER_NOT_SUPPORTED    2 /* operation not supported */
#define KEYSERVER_VERSION_ERROR    3 /* VERSION mismatch */
#define KEYSERVER_GENERAL_ERROR    4 /* keyserver internal error */
#define KEYSERVER_NO_MEMORY        5 /* out of memory */
#define KEYSERVER_KEY_NOT_FOUND    6 /* key not found */
#define KEYSERVER_KEY_EXISTS       7 /* key already exists */
#define KEYSERVER_KEY_INCOMPLETE   8 /* key incomplete (EOF) */
#define KEYSERVER_UNREACHABLE      9 /* unable to contact keyserver */

/* Must be 127 due to shell internal magic. */
#define KEYSERVER_SCHEME_NOT_FOUND 127

/* Object to hold information pertaining to a keyserver; it also
   allows building a list of keyservers.  Note that g10/options.h has
   a typedef for this.  FIXME: We should make use of the
   parse_uri_t. */
struct keyserver_spec
{
  struct keyserver_spec *next;
  char *uri;
  char *scheme;
  char *auth;
  char *host;
  char *port;
  char *path;
  char *opaque;
  strlist_t options;
  struct
  {
    unsigned int direct_uri:1;
  } flags;
};


#endif /*GNUPG_COMMON_KEYSERVER_H*/
