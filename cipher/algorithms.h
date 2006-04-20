/* algorithms.h - prototypes for algorithm functions.
 * Copyright (C) 2002, 2003, 2006 Free Software Foundation, Inc.
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301,
 * USA.
 */
#ifndef GNUPG_ALGORITHMS_H
#define GNUPG_ALGORITHMS_H 1

const char *dynload_enum_module_names (int seq);

const char *
md5_get_info (int algo, size_t *contextsize,
              byte **r_asnoid, int *r_asnlen, int *r_mdlen,
              void (**r_init)( void *c ),
              void (**r_write)( void *c, byte *buf, size_t nbytes ),
              void (**r_final)( void *c ),
              byte *(**r_read)( void *c )
              );


const char *
rmd160_get_info (int algo, size_t *contextsize,
                 byte **r_asnoid, int *r_asnlen, int *r_mdlen,
                 void (**r_init)( void *c ),
                 void (**r_write)( void *c, byte *buf, size_t nbytes ),
                 void (**r_final)( void *c ),
                 byte *(**r_read)( void *c )
                 );

const char *
sha1_get_info (int algo, size_t *contextsize,
	       byte **r_asnoid, int *r_asnlen, int *r_mdlen,
	       void (**r_init)( void *c ),
	       void (**r_write)( void *c, byte *buf, size_t nbytes ),
	       void (**r_final)( void *c ),
	       byte *(**r_read)( void *c )
               );

const char *
sha224_get_info (int algo, size_t *contextsize,
		 byte **r_asnoid, int *r_asnlen, int *r_mdlen,
		 void (**r_init)( void *c ),
		 void (**r_write)( void *c, byte *buf, size_t nbytes ),
		 void (**r_final)( void *c ),
		 byte *(**r_read)( void *c )
		 );

const char *
sha256_get_info (int algo, size_t *contextsize,
		 byte **r_asnoid, int *r_asnlen, int *r_mdlen,
		 void (**r_init)( void *c ),
		 void (**r_write)( void *c, byte *buf, size_t nbytes ),
		 void (**r_final)( void *c ),
		 byte *(**r_read)( void *c )
		 );

const char *
sha384_get_info (int algo, size_t *contextsize,
		 byte **r_asnoid, int *r_asnlen, int *r_mdlen,
		 void (**r_init)( void *c ),
		 void (**r_write)( void *c, byte *buf, size_t nbytes ),
		 void (**r_final)( void *c ),
		 byte *(**r_read)( void *c )
		 );

const char *
sha512_get_info (int algo, size_t *contextsize,
		 byte **r_asnoid, int *r_asnlen, int *r_mdlen,
		 void (**r_init)( void *c ),
		 void (**r_write)( void *c, byte *buf, size_t nbytes ),
		 void (**r_final)( void *c ),
		 byte *(**r_read)( void *c )
		 );

const char *
des_get_info( int algo, size_t *keylen,
	      size_t *blocksize, size_t *contextsize,
	      int (**setkeyf)( void *c, const byte *key, unsigned keylen ),
	      void (**encryptf)( void *c, byte *outbuf, const byte *inbuf ),
	      void (**decryptf)( void *c, byte *outbuf, const byte *inbuf )
	      );

const char *
cast5_get_info( int algo, size_t *keylen,
		size_t *blocksize, size_t *contextsize,
		int (**setkeyf)( void *c, const byte *key, unsigned keylen ),
		void (**encryptf)( void *c, byte *outbuf, const byte *inbuf ),
		void (**decryptf)( void *c, byte *outbuf, const byte *inbuf )
		);


const char *
blowfish_get_info( int algo, size_t *keylen,
		   size_t *blocksize, size_t *contextsize,
		   int (**setkeyf)(void *c, const byte *key, unsigned keylen),
		   void (**encryptf)(void *c, byte *outbuf, const byte *inbuf),
		   void (**decryptf)(void *c, byte *outbuf, const byte *inbuf)
		 );

const char *
twofish_get_info( int algo, size_t *keylen,
		  size_t *blocksize, size_t *contextsize,
		  int (**setkeyf)( void *c, const byte *key, unsigned keylen ),
		  void (**encryptf)( void *c, byte *outbuf, const byte *inbuf),
		  void (**decryptf)( void *c, byte *outbuf, const byte *inbuf )
		  );

/* this is just a kludge for the time we have not yet changed the cipher
 * stuff to the scheme we use for random and digests */
const char *
rijndael_get_info( int algo, size_t *keylen,
		   size_t *blocksize, size_t *contextsize,
		   int (**setkeyf)( void *c, const byte *key, unsigned keylen),
		   void (**encryptf)(void *c, byte *outbuf, const byte *inbuf),
		   void (**decryptf)(void *c, byte *outbuf, const byte *inbuf)
		   );

const char *
idea_get_info( int algo, size_t *keylen,
               size_t *blocksize, size_t *contextsize,
               int (**setkeyf)( void *c, const byte *key, unsigned keylen ),
               void (**encryptf)( void *c, byte *outbuf, const byte *inbuf ),
               void (**decryptf)( void *c, byte *outbuf, const byte *inbuf )
               );

#endif /*GNUPG_ALGORITHMS_H*/
