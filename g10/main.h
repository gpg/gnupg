/* main.h
 *	Copyright (c) 1997 by Werner Koch (dd9jn)
 *
 * This file is part of G10.
 *
 * G10 is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * G10 is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA
 */
#ifndef G10_MAIN_H
#define G10_MAIN_H
#include "types.h"

/*-- encode.c --*/
int encode_symmetric( const char *filename );
int encode_store( const char *filename );
int encode_crypt( const char *filename, STRLIST remusr );

/*-- keygen.c --*/
void generate_keypair(void);

/*-- overwrite.c --*/
int overwrite_filep( const char *fname );

#endif /*G10_MAIN_H*/
