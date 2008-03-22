/* cipher.c  -	cipher dispatcher
 * Copyright (C) 1998, 1999, 2000, 2001, 2002, 2003, 2004, 2005
 *               2007, 2008 Free Software Foundation, Inc.
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

#include <config.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <assert.h>
#include "util.h"
#include "errors.h"
#include "cipher.h"
#include "algorithms.h"

/* We have support for a DUMMY encryption cipher which comes handy to
   debug MDCs and similar things.  Because this is a bit dangerous it
   is not enabled. */
/*#define ALLOW_DUMMY 1 */

#define MAX_BLOCKSIZE 16
#define TABLE_SIZE 14

struct cipher_table_s {
    const char *name;
    int algo;
    size_t blocksize;
    size_t keylen;
    size_t contextsize; /* allocate this amount of context */
    int  (*setkey)( void *c, const byte *key, unsigned keylen );
    void (*encrypt)( void *c, byte *outbuf, const byte *inbuf );
    void (*decrypt)( void *c, byte *outbuf, const byte *inbuf );
};

static struct cipher_table_s cipher_table[TABLE_SIZE];
static int disabled_algos[TABLE_SIZE];


struct cipher_handle_s 
{
  int  algo;
  int  mode;
  size_t blocksize;
  
  /* The initialization vector.  To help code optimization we make
     sure that it is aligned on an unsigned long and u32 boundary.  */
  union {
    unsigned long dummy_ul_iv;         
    u32 dummy_u32_iv;
    unsigned char iv[MAX_BLOCKSIZE];	
  } u_iv;
  
  byte lastiv[MAX_BLOCKSIZE];
  int  unused;  /* in IV */
  int  (*setkey)( void *c, const byte *key, unsigned keylen );
  void (*encrypt)( void *c, byte *outbuf, const byte *inbuf );
  void (*decrypt)( void *c, byte *outbuf, const byte *inbuf );
  PROPERLY_ALIGNED_TYPE context;
};


#ifdef ALLOW_DUMMY
static int
dummy_setkey( void *c, byte *key, unsigned keylen ) { return 0; }
static void
dummy_encrypt_block( void *c, byte *outbuf, byte *inbuf ) { BUG(); }
static void
dummy_decrypt_block( void *c, byte *outbuf, byte *inbuf ) { BUG(); }
#ifdef __GNUC__
# warning DUMMY cipher module is enabled
#endif
#endif


/****************
 * Put the static entries into the table.
 */
static void
setup_cipher_table(void)
{
    int i=0;

#ifdef USE_AES
    cipher_table[i].algo = CIPHER_ALGO_AES;
    cipher_table[i].name = rijndael_get_info( cipher_table[i].algo,
					 &cipher_table[i].keylen,
					 &cipher_table[i].blocksize,
					 &cipher_table[i].contextsize,
					 &cipher_table[i].setkey,
					 &cipher_table[i].encrypt,
					 &cipher_table[i].decrypt     );
    if( !cipher_table[i].name )
	BUG();
    i++;
    cipher_table[i].algo = CIPHER_ALGO_AES192;
    cipher_table[i].name = rijndael_get_info( cipher_table[i].algo,
					 &cipher_table[i].keylen,
					 &cipher_table[i].blocksize,
					 &cipher_table[i].contextsize,
					 &cipher_table[i].setkey,
					 &cipher_table[i].encrypt,
					 &cipher_table[i].decrypt     );
    if( !cipher_table[i].name )
	BUG();
    i++;
    cipher_table[i].algo = CIPHER_ALGO_AES256;
    cipher_table[i].name = rijndael_get_info( cipher_table[i].algo,
					 &cipher_table[i].keylen,
					 &cipher_table[i].blocksize,
					 &cipher_table[i].contextsize,
					 &cipher_table[i].setkey,
					 &cipher_table[i].encrypt,
					 &cipher_table[i].decrypt     );
    if( !cipher_table[i].name )
	BUG();
    i++;
#endif

#ifdef USE_TWOFISH
    cipher_table[i].algo = CIPHER_ALGO_TWOFISH;
    cipher_table[i].name = twofish_get_info( cipher_table[i].algo,
					 &cipher_table[i].keylen,
					 &cipher_table[i].blocksize,
					 &cipher_table[i].contextsize,
					 &cipher_table[i].setkey,
					 &cipher_table[i].encrypt,
					 &cipher_table[i].decrypt     );
    if( !cipher_table[i].name )
	BUG();
    i++;
#endif

#ifdef USE_BLOWFISH
    cipher_table[i].algo = CIPHER_ALGO_BLOWFISH;
    cipher_table[i].name = blowfish_get_info( cipher_table[i].algo,
					 &cipher_table[i].keylen,
					 &cipher_table[i].blocksize,
					 &cipher_table[i].contextsize,
					 &cipher_table[i].setkey,
					 &cipher_table[i].encrypt,
					 &cipher_table[i].decrypt     );
    if( !cipher_table[i].name )
	BUG();
    i++;
#endif

#ifdef USE_CAST5
    cipher_table[i].algo = CIPHER_ALGO_CAST5;
    cipher_table[i].name = cast5_get_info( cipher_table[i].algo,
					 &cipher_table[i].keylen,
					 &cipher_table[i].blocksize,
					 &cipher_table[i].contextsize,
					 &cipher_table[i].setkey,
					 &cipher_table[i].encrypt,
					 &cipher_table[i].decrypt     );
    if( !cipher_table[i].name )
	BUG();
    i++;
#endif

    cipher_table[i].algo = CIPHER_ALGO_3DES;
    cipher_table[i].name = des_get_info( cipher_table[i].algo,
					 &cipher_table[i].keylen,
					 &cipher_table[i].blocksize,
					 &cipher_table[i].contextsize,
					 &cipher_table[i].setkey,
					 &cipher_table[i].encrypt,
					 &cipher_table[i].decrypt     );
    if( !cipher_table[i].name )
	BUG();
    i++;

#ifdef USE_CAMELLIA
    cipher_table[i].algo = CIPHER_ALGO_CAMELLIA128;
    cipher_table[i].name = camellia_get_info( cipher_table[i].algo,
					      &cipher_table[i].keylen,
					      &cipher_table[i].blocksize,
					      &cipher_table[i].contextsize,
					      &cipher_table[i].setkey,
					      &cipher_table[i].encrypt,
					      &cipher_table[i].decrypt     );
    if( !cipher_table[i].name )
	BUG();
    i++;
    cipher_table[i].algo = CIPHER_ALGO_CAMELLIA256;
    cipher_table[i].name = camellia_get_info( cipher_table[i].algo,
					      &cipher_table[i].keylen,
					      &cipher_table[i].blocksize,
					      &cipher_table[i].contextsize,
					      &cipher_table[i].setkey,
					      &cipher_table[i].encrypt,
					      &cipher_table[i].decrypt     );
    if( !cipher_table[i].name )
	BUG();
    i++;
#endif

#ifdef USE_IDEA
    cipher_table[i].algo = CIPHER_ALGO_IDEA;
    cipher_table[i].name = idea_get_info( cipher_table[i].algo,
					  &cipher_table[i].keylen,
					  &cipher_table[i].blocksize,
					  &cipher_table[i].contextsize,
					  &cipher_table[i].setkey,
					  &cipher_table[i].encrypt,
					  &cipher_table[i].decrypt     );
    if (cipher_table[i].name)
      i++;  /* Note that the loadable IDEA module may not be
	       available. */
#endif

#ifdef ALLOW_DUMMY
    cipher_table[i].algo = CIPHER_ALGO_DUMMY;
    cipher_table[i].name = "DUMMY";
    cipher_table[i].blocksize = 8;
    cipher_table[i].keylen = 128;
    cipher_table[i].contextsize = 0;
    cipher_table[i].setkey = dummy_setkey;
    cipher_table[i].encrypt = dummy_encrypt_block;
    cipher_table[i].decrypt = dummy_decrypt_block;
    i++;
#endif

    for( ; i < TABLE_SIZE; i++ )
	cipher_table[i].name = NULL;
}


/****************
 * Try to load all modules and return true if new modules are available
 */
static int
load_cipher_modules(void)
{
  static int initialized = 0;

  if (!initialized ) 
    {
      setup_cipher_table(); /* load static modules on the first call */
      initialized = 1;
      return 1;
    }
  return 0;
}

/****************
 * Map a string to the cipher algo
 */
int
string_to_cipher_algo( const char *string )
{
  int i;
  const char *s;

  /* kludge to alias RIJNDAEL to AES */
  if ( *string == 'R' || *string == 'r')
    {
      if (!ascii_strcasecmp (string, "RIJNDAEL"))
        string = "AES";
      else if (!ascii_strcasecmp (string, "RIJNDAEL192"))
        string = "AES192";
      else if (!ascii_strcasecmp (string, "RIJNDAEL256"))
        string = "AES256";
    }

  do
    {
      for(i=0; (s=cipher_table[i].name); i++ ) 
        {
          if( !ascii_strcasecmp( s, string ) )
            return cipher_table[i].algo;
        }
    } while( load_cipher_modules() );

    /* Didn't find it, so try the Sx format */
    if(string[0]=='S' || string[0]=='s')
      {
	long val;
	char *endptr;

	string++;

	val=strtol(string,&endptr,10);
	if(*string!='\0' && *endptr=='\0' && check_cipher_algo(val)==0)
	  return val;
      }

  return 0;
}

/****************
 * Map a cipher algo to a string
 */
const char *
cipher_algo_to_string( int algo )
{
    int i;

    do {
	for(i=0; cipher_table[i].name; i++ )
	    if( cipher_table[i].algo == algo )
		return cipher_table[i].name;
    } while( load_cipher_modules() );
    return NULL;
}


void
disable_cipher_algo( int algo )
{
    int i;

    for(i=0; i < DIM(disabled_algos); i++ ) {
	if( !disabled_algos[i] || disabled_algos[i] == algo ) {
	    disabled_algos[i] = algo;
	    return;
	}
    }
    /* fixme: we should use a linked list */
    log_fatal("can't disable cipher algo %d: table full\n", algo );
}

/****************
 * Return 0 if the cipher algo is available
 */
int
check_cipher_algo( int algo )
{
    int i;

    do {
       for(i=0; cipher_table[i].name; i++ )
	   if( cipher_table[i].algo == algo ) {
		for(i=0; i < DIM(disabled_algos); i++ ) {
		   if( disabled_algos[i] == algo )
		       return G10ERR_CIPHER_ALGO;
		}
		return 0; /* okay */
	   }
    } while( load_cipher_modules() );
    return G10ERR_CIPHER_ALGO;
}


unsigned
cipher_get_keylen( int algo )
{
    int i;
    unsigned len = 0;

    do {
	for(i=0; cipher_table[i].name; i++ ) {
	    if( cipher_table[i].algo == algo ) {
		len = cipher_table[i].keylen;
		if( !len )
		    log_bug("cipher %d w/o key length\n", algo );
		return len;
	    }
	}
    } while( load_cipher_modules() );
    log_bug("cipher %d not found\n", algo );
    return 0;
}

unsigned
cipher_get_blocksize( int algo )
{
    int i;
    unsigned len = 0;

    do {
	for(i=0; cipher_table[i].name; i++ ) {
	    if( cipher_table[i].algo == algo ) {
		len = cipher_table[i].blocksize;
		if( !len )
		    log_bug("cipher %d w/o blocksize\n", algo );
		return len;
	    }
	}
    } while( load_cipher_modules() );
    log_bug("cipher %d not found\n", algo );
    return 0;
}


/****************
 * Open a cipher handle for use with algorithm ALGO, in mode MODE
 * and put it into secure memory if SECURE is true.
 */
CIPHER_HANDLE
cipher_open( int algo, int mode, int secure )
{
    CIPHER_HANDLE hd;
    int i;

    fast_random_poll();
    do {
	for(i=0; cipher_table[i].name; i++ )
	    if( cipher_table[i].algo == algo )
		break;
    } while( !cipher_table[i].name && load_cipher_modules() );
    if( !cipher_table[i].name ) {
	log_fatal("cipher_open: algorithm %d not available\n", algo );
	return NULL;
    }

    /* ? perform selftest here and mark this with a flag in cipher_table ? */

    hd = secure ? xmalloc_secure_clear( sizeof *hd
					+ cipher_table[i].contextsize
					- sizeof(PROPERLY_ALIGNED_TYPE) )
		: xmalloc_clear( sizeof *hd + cipher_table[i].contextsize
					   - sizeof(PROPERLY_ALIGNED_TYPE)  );
    hd->algo = algo;
    hd->blocksize = cipher_table[i].blocksize;
    hd->setkey	= cipher_table[i].setkey;
    hd->encrypt = cipher_table[i].encrypt;
    hd->decrypt = cipher_table[i].decrypt;

    if( mode == CIPHER_MODE_AUTO_CFB ) {
	if( algo >= 100 )
	    hd->mode = CIPHER_MODE_CFB;
	else
	    hd->mode = CIPHER_MODE_PHILS_CFB;
    }
    else
	hd->mode = mode;

#ifdef ALLOW_DUMMY
    if( algo == CIPHER_ALGO_DUMMY )
	hd->mode = CIPHER_MODE_DUMMY;
#endif

    return hd;
}


void
cipher_close( CIPHER_HANDLE c )
{
    xfree(c);
}


int
cipher_setkey( CIPHER_HANDLE c, byte *key, unsigned keylen )
{
    return (*c->setkey)( &c->context.c, key, keylen );
}


void
cipher_setiv( CIPHER_HANDLE c, const byte *iv, unsigned ivlen )
{
    memset( c->u_iv.iv, 0, c->blocksize );
    if( iv ) {
	if( ivlen != c->blocksize )
	    log_info("WARNING: cipher_setiv: ivlen=%u blklen=%u\n",
					     ivlen, (unsigned)c->blocksize );
	if( ivlen > c->blocksize )
	    ivlen = c->blocksize;
	memcpy( c->u_iv.iv, iv, ivlen );
    }
    c->unused = 0;
}

static void
do_ecb_encrypt( CIPHER_HANDLE c, byte *outbuf, byte *inbuf, unsigned nblocks )
{
    unsigned n;

    for(n=0; n < nblocks; n++ ) {
	(*c->encrypt)( &c->context.c, outbuf, inbuf );
	inbuf  += c->blocksize;
	outbuf += c->blocksize;
    }
}

static void
do_ecb_decrypt( CIPHER_HANDLE c, byte *outbuf, byte *inbuf, unsigned nblocks )
{
    unsigned n;

    for(n=0; n < nblocks; n++ ) {
	(*c->decrypt)( &c->context.c, outbuf, inbuf );
	inbuf  += c->blocksize;
	outbuf += c->blocksize;
    }
}

static void
do_cbc_encrypt( CIPHER_HANDLE c, byte *outbuf, byte *inbuf, unsigned nblocks )
{
    unsigned int n;
    byte *ivp;
    int i;
    size_t blocksize = c->blocksize;

    for(n=0; n < nblocks; n++ ) {
	/* fixme: the xor should works on words and not on
	 * bytes.  Maybe it is a good idea to enhance the cipher backend
	 * API to allow for CBC handling in the backend */
	for(ivp=c->u_iv.iv,i=0; i < blocksize; i++ )
	    outbuf[i] = inbuf[i] ^ *ivp++;
	(*c->encrypt)( &c->context.c, outbuf, outbuf );
	memcpy(c->u_iv.iv, outbuf, blocksize );
	inbuf  += c->blocksize;
	outbuf += c->blocksize;
    }
}

static void
do_cbc_decrypt( CIPHER_HANDLE c, byte *outbuf, byte *inbuf, unsigned nblocks )
{
    unsigned int n;
    byte *ivp;
    int i;
    size_t blocksize = c->blocksize;

    for(n=0; n < nblocks; n++ ) {
	/* because outbuf and inbuf might be the same, we have
	 * to save the original ciphertext block.  We use lastiv
	 * for this here because it is not used otherwise */
	memcpy(c->lastiv, inbuf, blocksize );
	(*c->decrypt)( &c->context.c, outbuf, inbuf );
	for(ivp=c->u_iv.iv,i=0; i < blocksize; i++ )
	    outbuf[i] ^= *ivp++;
	memcpy(c->u_iv.iv, c->lastiv, blocksize );
	inbuf  += c->blocksize;
	outbuf += c->blocksize;
    }
}


static void
do_cfb_encrypt( CIPHER_HANDLE c, byte *outbuf, byte *inbuf, unsigned nbytes )
{
  byte *ivp;
  size_t blocksize = c->blocksize;
  size_t blocksize_x_2 = blocksize + blocksize;

  if ( nbytes <= c->unused )
    {
      /* Short enough to be encoded by the remaining XOR mask.  XOR
	 the input with the IV and store input into IV.  */
      for (ivp=c->u_iv.iv+c->blocksize - c->unused; nbytes; 
            nbytes--, c->unused-- )
	    *outbuf++ = (*ivp++ ^= *inbuf++);
	return;
    }
  
  if ( c->unused )
    {
      /* XOR the input with the IV and store input into IV.  */
      nbytes -= c->unused;
      for (ivp=c->u_iv.iv+blocksize - c->unused; c->unused; c->unused-- )
        *outbuf++ = (*ivp++ ^= *inbuf++);
    }

  /* Now we can process complete blocks.  We use a loop as long as we
     have at least 2 blocks and use conditions for the rest.  This
     also allows to use a bulk encryption function if available.  */
#ifdef USE_AES
  if (nbytes >= blocksize_x_2 
      && (c->algo == CIPHER_ALGO_AES
          || c->algo == CIPHER_ALGO_AES256
          || c->algo == CIPHER_ALGO_AES192))
    {
      unsigned int nblocks = nbytes / blocksize;
      rijndael_cfb_enc (&c->context.c, c->u_iv.iv, outbuf, inbuf, nblocks); 
      outbuf += nblocks * blocksize;
      inbuf  += nblocks * blocksize;
      nbytes -= nblocks * blocksize;
    }
  else
#endif /*USE_AES*/
    {
      while ( nbytes >= blocksize_x_2 )
        {
          int i;
          /* Encrypt the IV. */
          c->encrypt ( &c->context.c, c->u_iv.iv, c->u_iv.iv );
          /* XOR the input with the IV and store input into IV.  */
          for(ivp=c->u_iv.iv,i=0; i < blocksize; i++ )
            *outbuf++ = (*ivp++ ^= *inbuf++);
          nbytes -= blocksize;
        }
    }

  if ( nbytes >= blocksize )
    {
      int i;
      /* Save the current IV and then encrypt the IV. */
      memcpy( c->lastiv, c->u_iv.iv, blocksize );
      c->encrypt ( &c->context.c, c->u_iv.iv, c->u_iv.iv );
      /* XOR the input with the IV and store input into IV */
      for(ivp=c->u_iv.iv,i=0; i < blocksize; i++ )
        *outbuf++ = (*ivp++ ^= *inbuf++);
      nbytes -= blocksize;
    }
  if ( nbytes ) 
    {
      /* Save the current IV and then encrypt the IV. */
      memcpy (c->lastiv, c->u_iv.iv, blocksize );
      c->encrypt ( &c->context.c, c->u_iv.iv, c->u_iv.iv );
      c->unused = blocksize;
      /* Apply the XOR. */
      c->unused -= nbytes;
      for(ivp=c->u_iv.iv; nbytes; nbytes-- )
        *outbuf++ = (*ivp++ ^= *inbuf++);
    }
}


static void
do_cfb_decrypt( CIPHER_HANDLE c, byte *outbuf, byte *inbuf, unsigned nbytes )
{
  unsigned char *ivp;
  unsigned long temp;
  int i;
  size_t blocksize = c->blocksize;
  size_t blocksize_x_2 = blocksize + blocksize;
  
  if (nbytes <= c->unused)
    {
      /* Short enough to be encoded by the remaining XOR mask. */
      /* XOR the input with the IV and store input into IV. */
      for (ivp=c->u_iv.iv+blocksize - c->unused;
           nbytes; 
           nbytes--, c->unused--)
        {
          temp = *inbuf++;
          *outbuf++ = *ivp ^ temp;
          *ivp++ = temp;
        }
      return;
    }
  
  if (c->unused)
    {
      /* XOR the input with the IV and store input into IV. */
      nbytes -= c->unused;
      for (ivp=c->u_iv.iv+blocksize - c->unused; c->unused; c->unused-- )
        {
          temp = *inbuf++;
          *outbuf++ = *ivp ^ temp;
          *ivp++ = temp;
        }
    }
  
  /* Now we can process complete blocks.  We use a loop as long as we
     have at least 2 blocks and use conditions for the rest.  This
     also allows to use a bulk encryption function if available.  */
#ifdef USE_AES
  if (nbytes >= blocksize_x_2 
      && (c->algo == CIPHER_ALGO_AES
          || c->algo == CIPHER_ALGO_AES256
          || c->algo == CIPHER_ALGO_AES192))
    {
      unsigned int nblocks = nbytes / blocksize;
      rijndael_cfb_dec (&c->context.c, c->u_iv.iv, outbuf, inbuf, nblocks); 
      outbuf += nblocks * blocksize;
      inbuf  += nblocks * blocksize;
      nbytes -= nblocks * blocksize;
    }
  else
#endif /*USE_AES*/
    {
      while (nbytes >= blocksize_x_2 )
        {
          /* Encrypt the IV. */
          c->encrypt ( &c->context.c, c->u_iv.iv, c->u_iv.iv );
          /* XOR the input with the IV and store input into IV. */
          for (ivp=c->u_iv.iv,i=0; i < blocksize; i++ )
            {
              temp = *inbuf++;
              *outbuf++ = *ivp ^ temp;
              *ivp++ = temp;
            }
          nbytes -= blocksize;
        }
    }

  if (nbytes >= blocksize )
    {
      /* Save the current IV and then encrypt the IV. */
      memcpy ( c->lastiv, c->u_iv.iv, blocksize);
      c->encrypt ( &c->context.c, c->u_iv.iv, c->u_iv.iv );
      /* XOR the input with the IV and store input into IV */
      for (ivp=c->u_iv.iv,i=0; i < blocksize; i++ )
        {
          temp = *inbuf++;
          *outbuf++ = *ivp ^ temp;
          *ivp++ = temp;
        }
      nbytes -= blocksize;
    }

  if (nbytes)
    { 
      /* Save the current IV and then encrypt the IV. */
      memcpy ( c->lastiv, c->u_iv.iv, blocksize );
      c->encrypt ( &c->context.c, c->u_iv.iv, c->u_iv.iv );
      c->unused = blocksize;
      /* Apply the XOR. */
      c->unused -= nbytes;
      for (ivp=c->u_iv.iv; nbytes; nbytes-- )
        {
          temp = *inbuf++;
          *outbuf++ = *ivp ^ temp;
          *ivp++ = temp;
        }
    }
}


/****************
 * Encrypt INBUF to OUTBUF with the mode selected at open.
 * inbuf and outbuf may overlap or be the same.
 * Depending on the mode some some contraints apply to NBYTES.
 */
void
cipher_encrypt( CIPHER_HANDLE c, byte *outbuf, byte *inbuf, unsigned nbytes )
{
    switch( c->mode ) {
      case CIPHER_MODE_ECB:
	assert(!(nbytes%c->blocksize));
	do_ecb_encrypt(c, outbuf, inbuf, nbytes/c->blocksize );
	break;
      case CIPHER_MODE_CBC:
	assert(!(nbytes%c->blocksize));  
	do_cbc_encrypt(c, outbuf, inbuf, nbytes/c->blocksize );
	break;
      case CIPHER_MODE_CFB:
      case CIPHER_MODE_PHILS_CFB:
	do_cfb_encrypt(c, outbuf, inbuf, nbytes );
	break;
#ifdef ALLOW_DUMMY
      case CIPHER_MODE_DUMMY:
	if( inbuf != outbuf )
	    memmove( outbuf, inbuf, nbytes );
	break;
#endif
      default: log_fatal("cipher_encrypt: invalid mode %d\n", c->mode );
    }
}


/****************
 * Decrypt INBUF to OUTBUF with the mode selected at open.
 * inbuf and outbuf may overlap or be the same.
 * Depending on the mode some some contraints apply to NBYTES.
 */
void
cipher_decrypt( CIPHER_HANDLE c, byte *outbuf, byte *inbuf, unsigned nbytes )
{
    switch( c->mode ) {
      case CIPHER_MODE_ECB:
	assert(!(nbytes%c->blocksize));
	do_ecb_decrypt(c, outbuf, inbuf, nbytes/c->blocksize );
	break;
      case CIPHER_MODE_CBC:
	assert(!(nbytes%c->blocksize));
	do_cbc_decrypt(c, outbuf, inbuf, nbytes/c->blocksize );
	break;
      case CIPHER_MODE_CFB:
      case CIPHER_MODE_PHILS_CFB:
	do_cfb_decrypt(c, outbuf, inbuf, nbytes );
	break;
#ifdef ALLOW_DUMMY
      case CIPHER_MODE_DUMMY:
	if( inbuf != outbuf )
	    memmove( outbuf, inbuf, nbytes );
	break;
#endif
      default: log_fatal("cipher_decrypt: invalid mode %d\n", c->mode );
    }
}



/****************
 * Used for PGP's somewhat strange CFB mode. Only works if
 * the handle is in PHILS_CFB mode
 */
void
cipher_sync( CIPHER_HANDLE c )
{
    if( c->mode == CIPHER_MODE_PHILS_CFB && c->unused ) {
	memmove(c->u_iv.iv + c->unused, c->u_iv.iv, c->blocksize - c->unused );
	memcpy(c->u_iv.iv, c->lastiv + c->blocksize - c->unused, c->unused);
	c->unused = 0;
    }
}
