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
#include "iobuf.h"
#include "cipher.h"

#define DEFAULT_CIPHER_ALGO  CIPHER_ALGO_BLOWFISH
#define DEFAULT_PUBKEY_ALGO  PUBKEY_ALGO_ELGAMAL
#define DEFAULT_DIGEST_ALGO  DIGEST_ALGO_RMD160

/*-- encode.c --*/
int encode_symmetric( const char *filename );
int encode_store( const char *filename );
int encode_crypt( const char *filename, STRLIST remusr );

/*-- sign.c --*/
int sign_file( const char *filename, int detached, STRLIST locusr );

/*-- keygen.c --*/
void generate_keypair(void);

/*-- openfile.c --*/
int overwrite_filep( const char *fname );
IOBUF open_outfile( const char *fname );

/*-- seskey.c --*/
void make_session_key( DEK *dek );
MPI encode_session_key( DEK *dek, unsigned nbits );
MPI encode_rmd160_value( byte *md, unsigned len, unsigned nbits );
MPI encode_md5_value( byte *md, unsigned len, unsigned nbits );


#endif /*G10_MAIN_H*/
