/* keyserver.h
 * Copyright (C) 2001, 2002, 2004 Free Software Foundation, Inc.
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

#ifndef _KEYSERVER_H_
#define _KEYSERVER_H_

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
#define KEYSERVER_TIMEOUT         10 /* timeout while accessing keyserver */

/* Must be 127 due to shell internal magic. */
#define KEYSERVER_SCHEME_NOT_FOUND 127

#endif /* !_KEYSERVER_H_ */
