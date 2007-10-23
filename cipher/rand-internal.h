/* rand-internal.h - header to glue the random functions
 *	Copyright (C) 1998, 1999, 2000, 2001 Free Software Foundation, Inc.
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
#ifndef G10_RAND_INTERNAL_H
#define G10_RAND_INTERNAL_H

int rndunix_gather_random (void (*add)(const void*, size_t, int),
                           int requester, size_t length, int level);
int rndlinux_gather_random (void (*add)(const void*, size_t, int),
                            int requester, size_t length, int level);
int rndegd_connect_socket (int nofail);
int rndegd_gather_random (void (*add)(const void*, size_t, int),
                          int requester, size_t length, int level );
int rndw32_gather_random (void (*add)(const void*, size_t, int),
                          int requester, size_t length, int level);
int rndw32_gather_random_fast (void (*add)(const void*, size_t, int),
                               int requester );
int rndriscos_gather_random (void (*add)(const void*, size_t, int),
                             int requester, size_t length, int level);


#endif /*G10_RAND_INTERNAL_H*/
