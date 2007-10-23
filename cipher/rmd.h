/* rmd.h - RIPE-MD hash functions
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
#ifndef G10_RMD_H
#define G10_RMD_H


/* we need this here because random.c must have direct access */
typedef struct {
    u32  h0,h1,h2,h3,h4;
    u32  nblocks;
    byte buf[64];
    int  count;
} RMD160_CONTEXT;

void rmd160_init( RMD160_CONTEXT *hd );
void rmd160_mixblock( RMD160_CONTEXT *hd, char *buffer );

#endif /*G10_RMD_H*/
