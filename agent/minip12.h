/* minip12.h - Global definitions for the minimal pkcs-12 implementation.
 *	Copyright (C) 2002 Free Software Foundation, Inc.
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

#ifndef MINIP12_H
#define MINIP12_H

#include <gcrypt.h>

GcryMPI *p12_parse (const unsigned char *buffer, size_t length,
                    const char *pw);

unsigned char *p12_build (GcryMPI *kparms, const char *pw, size_t *r_length);


#endif /*MINIP12_H*/
