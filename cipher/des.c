/* des.c - DES and Triple-DES encryption/decryption Algorithm
 *	Copyright (C) 1998 Free Software Foundation, Inc.
 *
 * Please see below for more legal information!
 *
 * According to the definition of DES in FIPS PUB 46-2 from December 1993.
 * For a description of triple encryption, see:
 *   Bruce Schneier: Applied Cryptography. Second Edition.
 *   John Wiley & Sons, 1996. ISBN 0-471-12845-7. Pages 358 ff.
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


/*
 * Written by Michael Roth <mroth@nessie.de>, September 1998
 */


/*
 *  U S A G E
 * ===========
 *
 * For DES or Triple-DES encryption/decryption you must initialize a proper
 * encryption context with a key.
 *
 * A DES key is 64bit wide but only 56bits of the key are used. The remaining
 * bits are parity bits and they will _not_ checked in this implementation, but
 * simply ignored.
 *
 * For Tripple-DES you could use either two 64bit keys or three 64bit keys.
 * The parity bits will _not_ checked, too.
 *
 * After initializing a context with a key you could use this context to
 * encrypt or decrypt data in 64bit blocks in Electronic Codebook Mode.
 *
 * (In the examples below the slashes at the beginning and ending of comments
 * are omited.)
 *
 * DES Example
 * -----------
 *     unsigned char key[8];
 *     unsigned char plaintext[8];
 *     unsigned char ciphertext[8];
 *     unsigned char recoverd[8];
 *     des_ctx context;
 *
 *     * Fill 'key' and 'plaintext' with some data *
 *     ....
 *
 *     * Set up the DES encryption context *
 *     des_setkey(context, key);
 *
 *     * Encrypt the plaintext *
 *     des_ecb_encrypt(context, plaintext, ciphertext);
 *
 *     * To recover the orginal plaintext from ciphertext use: *
 *     des_ecb_decrypt(context, ciphertext, recoverd);
 *
 *
 * Triple-DES Example
 * ------------------
 *     unsigned char key1[8];
 *     unsigned char key2[8];
 *     unsigned char key3[8];
 *     unsigned char plaintext[8];
 *     unsigned char ciphertext[8];
 *     unsigned char recoverd[8];
 *     tripledes_ctx context;
 *
 *     * If you would like to use two 64bit keys, fill 'key1' and'key2'
 *	 then setup the encryption context: *
 *     tripledes_set2keys(context, key1, key2);
 *
 *     * To use three 64bit keys with Triple-DES use: *
 *     tripledes_set3keys(context, key1, key2, key3);
 *
 *     * Encrypting plaintext with Triple-DES *
 *     tripledes_ecb_encrypt(context, plaintext, ciphertext);
 *
 *     * Decrypting ciphertext to recover the plaintext with Triple-DES *
 *     tripledes_ecb_decrypt(context, ciphertext, recoverd);
 *
 *
 * Selftest
 * --------
 *     char *error_msg;
 *
 *     * To perform a selftest of this DES/Triple-DES implementation use the
 *	 function selftest(). It will return an error string if their are
 *	 some problems with this library. *
 *
 *     if ( (error_msg = selftest()) )
 *     {
 *	   fprintf(stderr, "An error in the DES/Tripple-DES implementation occured: %s\n", error_msg);
 *	   abort();
 *     }
 */


#include <config.h>
#include <string.h>	       /* memcpy, memcmp */
#include <assert.h>
#include "types.h"             /* for byte and u32 typedefs */
#include "util.h"              /* for log_fatal() */
#include "des.h"


/* Some defines/checks to support standalone modules */

#ifndef CIPHER_ALGO_3DES
  #define CIPHER_ALGO_3DES 2
#elif CIPHER_ALGO_3DES != 2
  #error CIPHER_ALGO_3DES is defined to a wrong value.
#endif

#ifndef G10ERR_WEAK_KEY
  #define G10ERR_WEAK_KEY 43
#elif G10ERR_WEAK_KEY != 43
  #error G10ERR_WEAK_KEY is defined to a wrong value.
#endif

#ifndef G10ERR_WRONG_KEYLEN
  #define G10ERR_WRONG_KEYLEN 44
#elif G10ERR_WRONG_KEYLEN != 44
  #error G10ERR_WRONG_KEYLEN is defined to a wrong value.
#endif



/* Macros used by the info function. */
#define FNCCAST_SETKEY(f)  ((int(*)(void*, byte*, unsigned))(f))
#define FNCCAST_CRYPT(f)   ((void(*)(void*, byte*, byte*))(f))


/*
 * Encryption/Decryption context of DES
 */
typedef struct _des_ctx
  {
    u32 encrypt_subkeys[32];
    u32 decrypt_subkeys[32];
  }
des_ctx[1];

/*
 * Encryption/Decryption context of Triple-DES
 */
typedef struct _tripledes_ctx
  {
    u32 encrypt_subkeys[96];
    u32 decrypt_subkeys[96];
  }
tripledes_ctx[1];


static void des_key_schedule (const byte *, u32 *);
static int des_setkey (struct _des_ctx *, const byte *);
static int des_ecb_crypt (struct _des_ctx *, const byte *, byte *, int);
static int tripledes_set2keys (struct _tripledes_ctx *, const byte *, const byte *);
static int tripledes_set3keys (struct _tripledes_ctx *, const byte *, const byte *, const byte *);
static int tripledes_ecb_crypt (struct _tripledes_ctx *, const byte *, byte *, int);
static int is_weak_key ( const byte *key );
static const char *selftest (void);






/*
 * The s-box values are permuted according to the 'primitive function P'
 */
static u32 sbox1[64] =
{
  0x00808200, 0x00000000, 0x00008000, 0x00808202, 0x00808002, 0x00008202, 0x00000002, 0x00008000,
  0x00000200, 0x00808200, 0x00808202, 0x00000200, 0x00800202, 0x00808002, 0x00800000, 0x00000002,
  0x00000202, 0x00800200, 0x00800200, 0x00008200, 0x00008200, 0x00808000, 0x00808000, 0x00800202,
  0x00008002, 0x00800002, 0x00800002, 0x00008002, 0x00000000, 0x00000202, 0x00008202, 0x00800000,
  0x00008000, 0x00808202, 0x00000002, 0x00808000, 0x00808200, 0x00800000, 0x00800000, 0x00000200,
  0x00808002, 0x00008000, 0x00008200, 0x00800002, 0x00000200, 0x00000002, 0x00800202, 0x00008202,
  0x00808202, 0x00008002, 0x00808000, 0x00800202, 0x00800002, 0x00000202, 0x00008202, 0x00808200,
  0x00000202, 0x00800200, 0x00800200, 0x00000000, 0x00008002, 0x00008200, 0x00000000, 0x00808002
};

static u32 sbox2[64] =
{
  0x40084010, 0x40004000, 0x00004000, 0x00084010, 0x00080000, 0x00000010, 0x40080010, 0x40004010,
  0x40000010, 0x40084010, 0x40084000, 0x40000000, 0x40004000, 0x00080000, 0x00000010, 0x40080010,
  0x00084000, 0x00080010, 0x40004010, 0x00000000, 0x40000000, 0x00004000, 0x00084010, 0x40080000,
  0x00080010, 0x40000010, 0x00000000, 0x00084000, 0x00004010, 0x40084000, 0x40080000, 0x00004010,
  0x00000000, 0x00084010, 0x40080010, 0x00080000, 0x40004010, 0x40080000, 0x40084000, 0x00004000,
  0x40080000, 0x40004000, 0x00000010, 0x40084010, 0x00084010, 0x00000010, 0x00004000, 0x40000000,
  0x00004010, 0x40084000, 0x00080000, 0x40000010, 0x00080010, 0x40004010, 0x40000010, 0x00080010,
  0x00084000, 0x00000000, 0x40004000, 0x00004010, 0x40000000, 0x40080010, 0x40084010, 0x00084000
};

static u32 sbox3[64] =
{
  0x00000104, 0x04010100, 0x00000000, 0x04010004, 0x04000100, 0x00000000, 0x00010104, 0x04000100,
  0x00010004, 0x04000004, 0x04000004, 0x00010000, 0x04010104, 0x00010004, 0x04010000, 0x00000104,
  0x04000000, 0x00000004, 0x04010100, 0x00000100, 0x00010100, 0x04010000, 0x04010004, 0x00010104,
  0x04000104, 0x00010100, 0x00010000, 0x04000104, 0x00000004, 0x04010104, 0x00000100, 0x04000000,
  0x04010100, 0x04000000, 0x00010004, 0x00000104, 0x00010000, 0x04010100, 0x04000100, 0x00000000,
  0x00000100, 0x00010004, 0x04010104, 0x04000100, 0x04000004, 0x00000100, 0x00000000, 0x04010004,
  0x04000104, 0x00010000, 0x04000000, 0x04010104, 0x00000004, 0x00010104, 0x00010100, 0x04000004,
  0x04010000, 0x04000104, 0x00000104, 0x04010000, 0x00010104, 0x00000004, 0x04010004, 0x00010100
};

static u32 sbox4[64] =
{
  0x80401000, 0x80001040, 0x80001040, 0x00000040, 0x00401040, 0x80400040, 0x80400000, 0x80001000,
  0x00000000, 0x00401000, 0x00401000, 0x80401040, 0x80000040, 0x00000000, 0x00400040, 0x80400000,
  0x80000000, 0x00001000, 0x00400000, 0x80401000, 0x00000040, 0x00400000, 0x80001000, 0x00001040,
  0x80400040, 0x80000000, 0x00001040, 0x00400040, 0x00001000, 0x00401040, 0x80401040, 0x80000040,
  0x00400040, 0x80400000, 0x00401000, 0x80401040, 0x80000040, 0x00000000, 0x00000000, 0x00401000,
  0x00001040, 0x00400040, 0x80400040, 0x80000000, 0x80401000, 0x80001040, 0x80001040, 0x00000040,
  0x80401040, 0x80000040, 0x80000000, 0x00001000, 0x80400000, 0x80001000, 0x00401040, 0x80400040,
  0x80001000, 0x00001040, 0x00400000, 0x80401000, 0x00000040, 0x00400000, 0x00001000, 0x00401040
};

static u32 sbox5[64] =
{
  0x00000080, 0x01040080, 0x01040000, 0x21000080, 0x00040000, 0x00000080, 0x20000000, 0x01040000,
  0x20040080, 0x00040000, 0x01000080, 0x20040080, 0x21000080, 0x21040000, 0x00040080, 0x20000000,
  0x01000000, 0x20040000, 0x20040000, 0x00000000, 0x20000080, 0x21040080, 0x21040080, 0x01000080,
  0x21040000, 0x20000080, 0x00000000, 0x21000000, 0x01040080, 0x01000000, 0x21000000, 0x00040080,
  0x00040000, 0x21000080, 0x00000080, 0x01000000, 0x20000000, 0x01040000, 0x21000080, 0x20040080,
  0x01000080, 0x20000000, 0x21040000, 0x01040080, 0x20040080, 0x00000080, 0x01000000, 0x21040000,
  0x21040080, 0x00040080, 0x21000000, 0x21040080, 0x01040000, 0x00000000, 0x20040000, 0x21000000,
  0x00040080, 0x01000080, 0x20000080, 0x00040000, 0x00000000, 0x20040000, 0x01040080, 0x20000080
};

static u32 sbox6[64] =
{
  0x10000008, 0x10200000, 0x00002000, 0x10202008, 0x10200000, 0x00000008, 0x10202008, 0x00200000,
  0x10002000, 0x00202008, 0x00200000, 0x10000008, 0x00200008, 0x10002000, 0x10000000, 0x00002008,
  0x00000000, 0x00200008, 0x10002008, 0x00002000, 0x00202000, 0x10002008, 0x00000008, 0x10200008,
  0x10200008, 0x00000000, 0x00202008, 0x10202000, 0x00002008, 0x00202000, 0x10202000, 0x10000000,
  0x10002000, 0x00000008, 0x10200008, 0x00202000, 0x10202008, 0x00200000, 0x00002008, 0x10000008,
  0x00200000, 0x10002000, 0x10000000, 0x00002008, 0x10000008, 0x10202008, 0x00202000, 0x10200000,
  0x00202008, 0x10202000, 0x00000000, 0x10200008, 0x00000008, 0x00002000, 0x10200000, 0x00202008,
  0x00002000, 0x00200008, 0x10002008, 0x00000000, 0x10202000, 0x10000000, 0x00200008, 0x10002008
};

static u32 sbox7[64] =
{
  0x00100000, 0x02100001, 0x02000401, 0x00000000, 0x00000400, 0x02000401, 0x00100401, 0x02100400,
  0x02100401, 0x00100000, 0x00000000, 0x02000001, 0x00000001, 0x02000000, 0x02100001, 0x00000401,
  0x02000400, 0x00100401, 0x00100001, 0x02000400, 0x02000001, 0x02100000, 0x02100400, 0x00100001,
  0x02100000, 0x00000400, 0x00000401, 0x02100401, 0x00100400, 0x00000001, 0x02000000, 0x00100400,
  0x02000000, 0x00100400, 0x00100000, 0x02000401, 0x02000401, 0x02100001, 0x02100001, 0x00000001,
  0x00100001, 0x02000000, 0x02000400, 0x00100000, 0x02100400, 0x00000401, 0x00100401, 0x02100400,
  0x00000401, 0x02000001, 0x02100401, 0x02100000, 0x00100400, 0x00000000, 0x00000001, 0x02100401,
  0x00000000, 0x00100401, 0x02100000, 0x00000400, 0x02000001, 0x02000400, 0x00000400, 0x00100001
};

static u32 sbox8[64] =
{
  0x08000820, 0x00000800, 0x00020000, 0x08020820, 0x08000000, 0x08000820, 0x00000020, 0x08000000,
  0x00020020, 0x08020000, 0x08020820, 0x00020800, 0x08020800, 0x00020820, 0x00000800, 0x00000020,
  0x08020000, 0x08000020, 0x08000800, 0x00000820, 0x00020800, 0x00020020, 0x08020020, 0x08020800,
  0x00000820, 0x00000000, 0x00000000, 0x08020020, 0x08000020, 0x08000800, 0x00020820, 0x00020000,
  0x00020820, 0x00020000, 0x08020800, 0x00000800, 0x00000020, 0x08020020, 0x00000800, 0x00020820,
  0x08000800, 0x00000020, 0x08000020, 0x08020000, 0x08020020, 0x08000000, 0x00020000, 0x08000820,
  0x00000000, 0x08020820, 0x00020020, 0x08000020, 0x08020000, 0x08000800, 0x08000820, 0x00000000,
  0x08020820, 0x00020800, 0x00020800, 0x00000820, 0x00000820, 0x00020020, 0x08000000, 0x08020800
};



/*
 * These two tables are part of the 'permuted choice 1' function.
 * In this implementation several speed improvements are done.
 */
u32 leftkey_swap[16] =
{
  0x00000000, 0x00000001, 0x00000100, 0x00000101,
  0x00010000, 0x00010001, 0x00010100, 0x00010101,
  0x01000000, 0x01000001, 0x01000100, 0x01000101,
  0x01010000, 0x01010001, 0x01010100, 0x01010101
};

u32 rightkey_swap[16] =
{
  0x00000000, 0x01000000, 0x00010000, 0x01010000,
  0x00000100, 0x01000100, 0x00010100, 0x01010100,
  0x00000001, 0x01000001, 0x00010001, 0x01010001,
  0x00000101, 0x01000101, 0x00010101, 0x01010101,
};



/*
 * Numbers of left shifts per round for encryption subkey schedule
 * To calculate the decryption key scheduling we just reverse the
 * ordering of the subkeys so we can omit the table for decryption
 * subkey schedule.
 */
static byte encrypt_rotate_tab[16] =
{
  1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1
};



/*
 * Table with weak DES keys sorted in ascending order.
 * In DES their are 64 known keys wich are weak. They are weak
 * because they produce only one, two or four different
 * subkeys in the subkey scheduling process.
 * The keys in this table have all their parity bits cleared.
 */
static byte weak_keys[64][8] =
{
  { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 },  { 0x00, 0x00, 0x1e, 0x1e, 0x00, 0x00, 0x0e, 0x0e },
  { 0x00, 0x00, 0xe0, 0xe0, 0x00, 0x00, 0xf0, 0xf0 },  { 0x00, 0x00, 0xfe, 0xfe, 0x00, 0x00, 0xfe, 0xfe },
  { 0x00, 0x1e, 0x00, 0x1e, 0x00, 0x0e, 0x00, 0x0e },  { 0x00, 0x1e, 0x1e, 0x00, 0x00, 0x0e, 0x0e, 0x00 },
  { 0x00, 0x1e, 0xe0, 0xfe, 0x00, 0x0e, 0xf0, 0xfe },  { 0x00, 0x1e, 0xfe, 0xe0, 0x00, 0x0e, 0xfe, 0xf0 },
  { 0x00, 0xe0, 0x00, 0xe0, 0x00, 0xf0, 0x00, 0xf0 },  { 0x00, 0xe0, 0x1e, 0xfe, 0x00, 0xf0, 0x0e, 0xfe },
  { 0x00, 0xe0, 0xe0, 0x00, 0x00, 0xf0, 0xf0, 0x00 },  { 0x00, 0xe0, 0xfe, 0x1e, 0x00, 0xf0, 0xfe, 0x0e },
  { 0x00, 0xfe, 0x00, 0xfe, 0x00, 0xfe, 0x00, 0xfe },  { 0x00, 0xfe, 0x1e, 0xe0, 0x00, 0xfe, 0x0e, 0xf0 },
  { 0x00, 0xfe, 0xe0, 0x1e, 0x00, 0xfe, 0xf0, 0x0e },  { 0x00, 0xfe, 0xfe, 0x00, 0x00, 0xfe, 0xfe, 0x00 },
  { 0x0e, 0x0e, 0x0e, 0x0e, 0xf0, 0xf0, 0xf0, 0xf0 },  { 0x1e, 0x00, 0x00, 0x1e, 0x0e, 0x00, 0x00, 0x0e },
  { 0x1e, 0x00, 0x1e, 0x00, 0x0e, 0x00, 0x0e, 0x00 },  { 0x1e, 0x00, 0xe0, 0xfe, 0x0e, 0x00, 0xf0, 0xfe },
  { 0x1e, 0x00, 0xfe, 0xe0, 0x0e, 0x00, 0xfe, 0xf0 },  { 0x1e, 0x1e, 0x00, 0x00, 0x0e, 0x0e, 0x00, 0x00 },
  { 0x1e, 0x1e, 0x1e, 0x1e, 0x0e, 0x0e, 0x0e, 0x0e },  { 0x1e, 0x1e, 0xe0, 0xe0, 0x0e, 0x0e, 0xf0, 0xf0 },
  { 0x1e, 0x1e, 0xfe, 0xfe, 0x0e, 0x0e, 0xfe, 0xfe },  { 0x1e, 0xe0, 0x00, 0xfe, 0x0e, 0xf0, 0x00, 0xfe },
  { 0x1e, 0xe0, 0x1e, 0xe0, 0x0e, 0xf0, 0x0e, 0xf0 },  { 0x1e, 0xe0, 0xe0, 0x1e, 0x0e, 0xf0, 0xf0, 0x0e },
  { 0x1e, 0xe0, 0xfe, 0x00, 0x0e, 0xf0, 0xfe, 0x00 },  { 0x1e, 0xfe, 0x00, 0xe0, 0x0e, 0xfe, 0x00, 0xf0 },
  { 0x1e, 0xfe, 0x1e, 0xfe, 0x0e, 0xfe, 0x0e, 0xfe },  { 0x1e, 0xfe, 0xe0, 0x00, 0x0e, 0xfe, 0xf0, 0x00 },
  { 0x1e, 0xfe, 0xfe, 0x1e, 0x0e, 0xfe, 0xfe, 0x0e },  { 0xe0, 0x00, 0x00, 0xe0, 0xf0, 0x00, 0x00, 0xf0 },
  { 0xe0, 0x00, 0x1e, 0xfe, 0xf0, 0x00, 0x0e, 0xfe },  { 0xe0, 0x00, 0xe0, 0x00, 0xf0, 0x00, 0xf0, 0x00 },
  { 0xe0, 0x00, 0xfe, 0x1e, 0xf0, 0x00, 0xfe, 0x0e },  { 0xe0, 0x1e, 0x00, 0xfe, 0xf0, 0x0e, 0x00, 0xfe },
  { 0xe0, 0x1e, 0x1e, 0xe0, 0xf0, 0x0e, 0x0e, 0xf0 },  { 0xe0, 0x1e, 0xe0, 0x1e, 0xf0, 0x0e, 0xf0, 0x0e },
  { 0xe0, 0x1e, 0xfe, 0x00, 0xf0, 0x0e, 0xfe, 0x00 },  { 0xe0, 0xe0, 0x00, 0x00, 0xf0, 0xf0, 0x00, 0x00 },
  { 0xe0, 0xe0, 0x1e, 0x1e, 0xf0, 0xf0, 0x0e, 0x0e },  { 0xe0, 0xe0, 0xfe, 0xfe, 0xf0, 0xf0, 0xfe, 0xfe },
  { 0xe0, 0xfe, 0x00, 0x1e, 0xf0, 0xfe, 0x00, 0x0e },  { 0xe0, 0xfe, 0x1e, 0x00, 0xf0, 0xfe, 0x0e, 0x00 },
  { 0xe0, 0xfe, 0xe0, 0xfe, 0xf0, 0xfe, 0xf0, 0xfe },  { 0xe0, 0xfe, 0xfe, 0xe0, 0xf0, 0xfe, 0xfe, 0xf0 },
  { 0xfe, 0x00, 0x00, 0xfe, 0xfe, 0x00, 0x00, 0xfe },  { 0xfe, 0x00, 0x1e, 0xe0, 0xfe, 0x00, 0x0e, 0xf0 },
  { 0xfe, 0x00, 0xe0, 0x1e, 0xfe, 0x00, 0xf0, 0x0e },  { 0xfe, 0x00, 0xfe, 0x00, 0xfe, 0x00, 0xfe, 0x00 },
  { 0xfe, 0x1e, 0x00, 0xe0, 0xfe, 0x0e, 0x00, 0xf0 },  { 0xfe, 0x1e, 0x1e, 0xfe, 0xfe, 0x0e, 0x0e, 0xfe },
  { 0xfe, 0x1e, 0xe0, 0x00, 0xfe, 0x0e, 0xf0, 0x00 },  { 0xfe, 0x1e, 0xfe, 0x1e, 0xfe, 0x0e, 0xfe, 0x0e },
  { 0xfe, 0xe0, 0x00, 0x1e, 0xfe, 0xf0, 0x00, 0x0e },  { 0xfe, 0xe0, 0x1e, 0x00, 0xfe, 0xf0, 0x0e, 0x00 },
  { 0xfe, 0xe0, 0xe0, 0xfe, 0xfe, 0xf0, 0xf0, 0xfe },  { 0xfe, 0xe0, 0xfe, 0xe0, 0xfe, 0xf0, 0xfe, 0xf0 },
  { 0xfe, 0xfe, 0x00, 0x00, 0xfe, 0xfe, 0x00, 0x00 },  { 0xfe, 0xfe, 0x1e, 0x1e, 0xfe, 0xfe, 0x0e, 0x0e },
  { 0xfe, 0xfe, 0xe0, 0xe0, 0xfe, 0xfe, 0xf0, 0xf0 },  { 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe }
};






/*
 * Macro to swap bits across two words
 */
#define DO_PERMUTATION(a, temp, b, offset, mask)	\
    temp = ((a>>offset) ^ b) & mask;			\
    b ^= temp;						\
    a ^= temp<<offset;


/*
 * This performs the 'initial permutation' for the data to be encrypted or decrypted
 */
#define INITIAL_PERMUTATION(left, temp, right)		\
    DO_PERMUTATION(left, temp, right, 4, 0x0f0f0f0f)	\
    DO_PERMUTATION(left, temp, right, 16, 0x0000ffff)	\
    DO_PERMUTATION(right, temp, left, 2, 0x33333333)	\
    DO_PERMUTATION(right, temp, left, 8, 0x00ff00ff)	\
    DO_PERMUTATION(left, temp, right, 1, 0x55555555)


/*
 * The 'inverse initial permutation'
 */
#define FINAL_PERMUTATION(left, temp, right)		\
    DO_PERMUTATION(left, temp, right, 1, 0x55555555)	\
    DO_PERMUTATION(right, temp, left, 8, 0x00ff00ff)	\
    DO_PERMUTATION(right, temp, left, 2, 0x33333333)	\
    DO_PERMUTATION(left, temp, right, 16, 0x0000ffff)	\
    DO_PERMUTATION(left, temp, right, 4, 0x0f0f0f0f)


/*
 * A full DES round including 'expansion function', 'sbox substitution'
 * and 'primitive function P' but without swapping the left and right word.
 */
#define DES_ROUND(from, to, work, subkey)		\
    work = ((from<<1) | (from>>31)) ^ *subkey++;	\
    to ^= sbox8[  work	    & 0x3f ];			\
    to ^= sbox6[ (work>>8)  & 0x3f ];			\
    to ^= sbox4[ (work>>16) & 0x3f ];			\
    to ^= sbox2[ (work>>24) & 0x3f ];			\
    work = ((from>>3) | (from<<29)) ^ *subkey++;	\
    to ^= sbox7[  work	    & 0x3f ];			\
    to ^= sbox5[ (work>>8)  & 0x3f ];			\
    to ^= sbox3[ (work>>16) & 0x3f ];			\
    to ^= sbox1[ (work>>24) & 0x3f ];


/*
 * Macros to convert 8 bytes from/to 32bit words
 */
#define READ_64BIT_DATA(data, left, right)					\
    left  = (data[0] << 24) | (data[1] << 16) | (data[2] << 8) | data[3];	\
    right = (data[4] << 24) | (data[5] << 16) | (data[6] << 8) | data[7];

#define WRITE_64BIT_DATA(data, left, right)					\
    data[0] = (left >> 24) &0xff; data[1] = (left >> 16) &0xff; 		\
    data[2] = (left >> 8) &0xff; data[3] = left &0xff;				\
    data[4] = (right >> 24) &0xff; data[5] = (right >> 16) &0xff;		\
    data[6] = (right >> 8) &0xff; data[7] = right &0xff;


/*
 * Handy macros for encryption and decryption of data
 */
#define des_ecb_encrypt(ctx, from, to)		des_ecb_crypt(ctx, from, to, 0)
#define des_ecb_decrypt(ctx, from, to)		des_ecb_crypt(ctx, from, to, 1)
#define tripledes_ecb_encrypt(ctx, from, to)	tripledes_ecb_crypt(ctx, from, to, 0)
#define tripledes_ecb_decrypt(ctx, from, to)	tripledes_ecb_crypt(ctx, from, to, 1)






/*
 * des_key_schedule():	  Calculate 16 subkeys pairs (even/odd) for
 *			  16 encryption rounds.
 *			  To calculate subkeys for decryption the caller
 *			  have to reorder the generated subkeys.
 *
 *    rawkey:	    8 Bytes of key data
 *    subkey:	    Array of at least 32 u32s. Will be filled
 *		    with calculated subkeys.
 *
 */
static void
des_key_schedule (const byte * rawkey, u32 * subkey)
{
  u32 left, right, work;
  int round;

  READ_64BIT_DATA (rawkey, left, right)

  DO_PERMUTATION (right, work, left, 4, 0x0f0f0f0f)
  DO_PERMUTATION (right, work, left, 0, 0x10101010)

  left = (leftkey_swap[(left >> 0) & 0xf] << 3) | (leftkey_swap[(left >> 8) & 0xf] << 2)
    | (leftkey_swap[(left >> 16) & 0xf] << 1) | (leftkey_swap[(left >> 24) & 0xf])
    | (leftkey_swap[(left >> 5) & 0xf] << 7) | (leftkey_swap[(left >> 13) & 0xf] << 6)
    | (leftkey_swap[(left >> 21) & 0xf] << 5) | (leftkey_swap[(left >> 29) & 0xf] << 4);

  left &= 0x0fffffff;

  right = (rightkey_swap[(right >> 1) & 0xf] << 3) | (rightkey_swap[(right >> 9) & 0xf] << 2)
    | (rightkey_swap[(right >> 17) & 0xf] << 1) | (rightkey_swap[(right >> 25) & 0xf])
    | (rightkey_swap[(right >> 4) & 0xf] << 7) | (rightkey_swap[(right >> 12) & 0xf] << 6)
    | (rightkey_swap[(right >> 20) & 0xf] << 5) | (rightkey_swap[(right >> 28) & 0xf] << 4);

  right &= 0x0fffffff;

  for (round = 0; round < 16; ++round)
    {
      left = ((left << encrypt_rotate_tab[round]) | (left >> (28 - encrypt_rotate_tab[round]))) & 0x0fffffff;
      right = ((right << encrypt_rotate_tab[round]) | (right >> (28 - encrypt_rotate_tab[round]))) & 0x0fffffff;

      *subkey++ = ((left << 4) & 0x24000000)
	| ((left << 28) & 0x10000000)
	| ((left << 14) & 0x08000000)
	| ((left << 18) & 0x02080000)
	| ((left << 6) & 0x01000000)
	| ((left << 9) & 0x00200000)
	| ((left >> 1) & 0x00100000)
	| ((left << 10) & 0x00040000)
	| ((left << 2) & 0x00020000)
	| ((left >> 10) & 0x00010000)
	| ((right >> 13) & 0x00002000)
	| ((right >> 4) & 0x00001000)
	| ((right << 6) & 0x00000800)
	| ((right >> 1) & 0x00000400)
	| ((right >> 14) & 0x00000200)
	| (right & 0x00000100)
	| ((right >> 5) & 0x00000020)
	| ((right >> 10) & 0x00000010)
	| ((right >> 3) & 0x00000008)
	| ((right >> 18) & 0x00000004)
	| ((right >> 26) & 0x00000002)
	| ((right >> 24) & 0x00000001);

      *subkey++ = ((left << 15) & 0x20000000)
	| ((left << 17) & 0x10000000)
	| ((left << 10) & 0x08000000)
	| ((left << 22) & 0x04000000)
	| ((left >> 2) & 0x02000000)
	| ((left << 1) & 0x01000000)
	| ((left << 16) & 0x00200000)
	| ((left << 11) & 0x00100000)
	| ((left << 3) & 0x00080000)
	| ((left >> 6) & 0x00040000)
	| ((left << 15) & 0x00020000)
	| ((left >> 4) & 0x00010000)
	| ((right >> 2) & 0x00002000)
	| ((right << 8) & 0x00001000)
	| ((right >> 14) & 0x00000808)
	| ((right >> 9) & 0x00000400)
	| ((right) & 0x00000200)
	| ((right << 7) & 0x00000100)
	| ((right >> 7) & 0x00000020)
	| ((right >> 3) & 0x00000011)
	| ((right << 2) & 0x00000004)
	| ((right >> 21) & 0x00000002);
    }
}



/*
 * Fill a DES context with subkeys calculated from a 64bit key.
 * Does not check parity bits, but simply ignore them.
 * Does not check for weak keys.
 */
static int
des_setkey (struct _des_ctx *ctx, const byte * key)
{
  int i;

  des_key_schedule (key, ctx->encrypt_subkeys);

  for(i=0; i<32; i+=2)
    {
      ctx->decrypt_subkeys[i]	= ctx->encrypt_subkeys[30-i];
      ctx->decrypt_subkeys[i+1] = ctx->encrypt_subkeys[31-i];
    }

  return 0;
}



/*
 * Electronic Codebook Mode DES encryption/decryption of data according
 * to 'mode'.
 */
static int
des_ecb_crypt (struct _des_ctx *ctx, const byte * from, byte * to, int mode)
{
  u32 left, right, work;
  u32 *keys;

  keys = mode ? ctx->decrypt_subkeys : ctx->encrypt_subkeys;

  READ_64BIT_DATA (from, left, right)
  INITIAL_PERMUTATION (left, work, right)

  DES_ROUND (right, left, work, keys) DES_ROUND (left, right, work, keys)
  DES_ROUND (right, left, work, keys) DES_ROUND (left, right, work, keys)
  DES_ROUND (right, left, work, keys) DES_ROUND (left, right, work, keys)
  DES_ROUND (right, left, work, keys) DES_ROUND (left, right, work, keys)
  DES_ROUND (right, left, work, keys) DES_ROUND (left, right, work, keys)
  DES_ROUND (right, left, work, keys) DES_ROUND (left, right, work, keys)
  DES_ROUND (right, left, work, keys) DES_ROUND (left, right, work, keys)
  DES_ROUND (right, left, work, keys) DES_ROUND (left, right, work, keys)

  FINAL_PERMUTATION (right, work, left)
  WRITE_64BIT_DATA (to, right, left)

  return 0;
}



/*
 * Fill a Triple-DES context with subkeys calculated from two 64bit keys.
 * Does not check the parity bits of the keys, but simply ignore them.
 * Does not check for weak keys.
 */
static int
tripledes_set2keys (struct _tripledes_ctx *ctx,
		    const byte * key1,
		    const byte * key2)
{
  int i;

  des_key_schedule (key1, ctx->encrypt_subkeys);
  des_key_schedule (key2, &(ctx->decrypt_subkeys[32]));

  for(i=0; i<32; i+=2)
    {
      ctx->decrypt_subkeys[i]	 = ctx->encrypt_subkeys[30-i];
      ctx->decrypt_subkeys[i+1]  = ctx->encrypt_subkeys[31-i];

      ctx->encrypt_subkeys[i+32] = ctx->decrypt_subkeys[62-i];
      ctx->encrypt_subkeys[i+33] = ctx->decrypt_subkeys[63-i];

      ctx->encrypt_subkeys[i+64] = ctx->encrypt_subkeys[i];
      ctx->encrypt_subkeys[i+65] = ctx->encrypt_subkeys[i+1];

      ctx->decrypt_subkeys[i+64] = ctx->decrypt_subkeys[i];
      ctx->decrypt_subkeys[i+65] = ctx->decrypt_subkeys[i+1];
    }

  return 0;
}



/*
 * Fill a Triple-DES context with subkeys calculated from three 64bit keys.
 * Does not check the parity bits of the keys, but simply ignore them.
 * Does not check for weak keys.
 */
static int
tripledes_set3keys (struct _tripledes_ctx *ctx,
		    const byte * key1,
		    const byte * key2,
		    const byte * key3)
{
  int i;

  des_key_schedule (key1, ctx->encrypt_subkeys);
  des_key_schedule (key2, &(ctx->decrypt_subkeys[32]));
  des_key_schedule (key3, &(ctx->encrypt_subkeys[64]));

  for(i=0; i<32; i+=2)
    {
      ctx->decrypt_subkeys[i]	 = ctx->encrypt_subkeys[94-i];
      ctx->decrypt_subkeys[i+1]  = ctx->encrypt_subkeys[95-i];

      ctx->encrypt_subkeys[i+32] = ctx->decrypt_subkeys[62-i];
      ctx->encrypt_subkeys[i+33] = ctx->decrypt_subkeys[63-i];

      ctx->decrypt_subkeys[i+64] = ctx->encrypt_subkeys[30-i];
      ctx->decrypt_subkeys[i+65] = ctx->encrypt_subkeys[31-i];
    }

  return 0;
}



/*
 * Electronic Codebook Mode Triple-DES encryption/decryption of data according to 'mode'.
 * Sometimes this mode is named 'EDE' mode (Encryption-Decryption-Encryption).
 */
static int
tripledes_ecb_crypt (struct _tripledes_ctx *ctx, const byte * from, byte * to, int mode)
{
  u32 left, right, work;
  u32 *keys;

  keys = mode ? ctx->decrypt_subkeys : ctx->encrypt_subkeys;

  READ_64BIT_DATA (from, left, right)
  INITIAL_PERMUTATION (left, work, right)

  DES_ROUND (right, left, work, keys) DES_ROUND (left, right, work, keys)
  DES_ROUND (right, left, work, keys) DES_ROUND (left, right, work, keys)
  DES_ROUND (right, left, work, keys) DES_ROUND (left, right, work, keys)
  DES_ROUND (right, left, work, keys) DES_ROUND (left, right, work, keys)
  DES_ROUND (right, left, work, keys) DES_ROUND (left, right, work, keys)
  DES_ROUND (right, left, work, keys) DES_ROUND (left, right, work, keys)
  DES_ROUND (right, left, work, keys) DES_ROUND (left, right, work, keys)
  DES_ROUND (right, left, work, keys) DES_ROUND (left, right, work, keys)

  DES_ROUND (left, right, work, keys) DES_ROUND (right, left, work, keys)
  DES_ROUND (left, right, work, keys) DES_ROUND (right, left, work, keys)
  DES_ROUND (left, right, work, keys) DES_ROUND (right, left, work, keys)
  DES_ROUND (left, right, work, keys) DES_ROUND (right, left, work, keys)
  DES_ROUND (left, right, work, keys) DES_ROUND (right, left, work, keys)
  DES_ROUND (left, right, work, keys) DES_ROUND (right, left, work, keys)
  DES_ROUND (left, right, work, keys) DES_ROUND (right, left, work, keys)
  DES_ROUND (left, right, work, keys) DES_ROUND (right, left, work, keys)

  DES_ROUND (right, left, work, keys) DES_ROUND (left, right, work, keys)
  DES_ROUND (right, left, work, keys) DES_ROUND (left, right, work, keys)
  DES_ROUND (right, left, work, keys) DES_ROUND (left, right, work, keys)
  DES_ROUND (right, left, work, keys) DES_ROUND (left, right, work, keys)
  DES_ROUND (right, left, work, keys) DES_ROUND (left, right, work, keys)
  DES_ROUND (right, left, work, keys) DES_ROUND (left, right, work, keys)
  DES_ROUND (right, left, work, keys) DES_ROUND (left, right, work, keys)
  DES_ROUND (right, left, work, keys) DES_ROUND (left, right, work, keys)

  FINAL_PERMUTATION (right, work, left)
  WRITE_64BIT_DATA (to, right, left)

  return 0;
}



/*
 * Check whether the 8 byte key is weak.
 * Dose not check the parity bits of the key but simple ignore them.
 */
static int
is_weak_key ( const byte *key )
{
  byte work[8];
  int i, left, right, middle, cmp_result;

  /* clear parity bits */
  for(i=0; i<8; ++i)
     work[i] = key[i] & 0xfe;

  /* binary search in the weak key table */
  left = 0;
  right = 63;
  while(1)
    {
      middle = (left + right) / 2;

      if ( !(cmp_result=memcmp(work, weak_keys[middle], 8)) )
	  return -1;

      if ( left == right )
	  break;

      if ( cmp_result > 0 )
	  left = middle + 1;
      else
	  right = middle - 1;
    }

  return 0;
}



/*
 * Performs a selftest of this DES/Triple-DES implementation.
 * Returns an string with the error text on failure.
 * Returns NULL if all is ok.
 */
static const char *
selftest (void)
{
  /*
   * Check if 'u32' is really 32 bits wide. This DES / 3DES implementation
   * need this.
   */
  if (sizeof (u32) != 4)
       return "Wrong word size for DES configured.";

  /*
   * DES Maintenance Test
   */
  {
    int i;
    byte key[8] =
    {0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55};
    byte input[8] =
    {0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff};
    byte result[8] =
    {0x24, 0x6e, 0x9d, 0xb9, 0xc5, 0x50, 0x38, 0x1a};
    byte temp1[8], temp2[8], temp3[8];
    des_ctx des;

    for (i = 0; i < 64; ++i)
      {
	des_setkey (des, key);
	des_ecb_encrypt (des, input, temp1);
	des_ecb_encrypt (des, temp1, temp2);
	des_setkey (des, temp2);
	des_ecb_decrypt (des, temp1, temp3);
	memcpy (key, temp3, 8);
	memcpy (input, temp1, 8);
      }
    if (memcmp (temp3, result, 8))
      return "DES maintenance test failed.";
  }


  /*
   * Triple-DES test  (Do somebody known on official test?)
   *
   * FIXME: This test doesn't use tripledes_set3keys() !
   */
  {
    int i;
    byte input[8] =
    {0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10};
    byte key1[8] =
    {0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0};
    byte key2[8] =
    {0x11, 0x22, 0x33, 0x44, 0xff, 0xaa, 0xcc, 0xdd};
    byte result[8] =
    {0x7b, 0x38, 0x3b, 0x23, 0xa2, 0x7d, 0x26, 0xd3};

    tripledes_ctx des3;

    for (i = 0; i < 16; ++i)
      {
	tripledes_set2keys (des3, key1, key2);
	tripledes_ecb_encrypt (des3, input, key1);
	tripledes_ecb_decrypt (des3, input, key2);
	tripledes_set3keys (des3, key1, input, key2);
	tripledes_ecb_encrypt (des3, input, input);
      }
    if (memcmp (input, result, 8))
      return "TRIPLE-DES test failed.";
  }


  /*
   * Check the weak key detection. We simply assume the table with
   * weak keys is ok and check every key in the table if it is
   * detected... (This test is a little bit stupid)
   */
  {
    int i;

    for (i = 0; i < 64; ++i)
	if (!is_weak_key(weak_keys[i]))
	    return "DES weak key detection failed";
  }

  return 0;
}


static int
do_tripledes_setkey ( struct _tripledes_ctx *ctx, byte *key, unsigned keylen )
{
    if( keylen != 24 )
	return G10ERR_WRONG_KEYLEN;

    tripledes_set3keys ( ctx, key, key+8, key+16);

    if( is_weak_key( key ) || is_weak_key( key+8 ) || is_weak_key( key+16 ) )
	return G10ERR_WEAK_KEY;

    return 0;
}


static void
do_tripledes_encrypt( struct _tripledes_ctx *ctx, byte *outbuf, byte *inbuf )
{
    tripledes_ecb_encrypt ( ctx, inbuf, outbuf );
}

static void
do_tripledes_decrypt( struct _tripledes_ctx *ctx, byte *outbuf, byte *inbuf )
{
    tripledes_ecb_decrypt ( ctx, inbuf, outbuf );
}


/****************
 * Return some information about the algorithm.  We need algo here to
 * distinguish different flavors of the algorithm.
 * Returns: A pointer to string describing the algorithm or NULL if
 *	    the ALGO is invalid.
 */
const char *
des_get_info( int algo, size_t *keylen,
		   size_t *blocksize, size_t *contextsize,
		   int	(**r_setkey)( void *c, byte *key, unsigned keylen ),
		   void (**r_encrypt)( void *c, byte *outbuf, byte *inbuf ),
		   void (**r_decrypt)( void *c, byte *outbuf, byte *inbuf )
		 )
{
    static int did_selftest = 0;

    if( !did_selftest ) {
	const char *s = selftest();
	if( s )
	    log_fatal("selftest failed: %s\n", s );
	did_selftest = 1;
    }


    if( algo == CIPHER_ALGO_3DES ) {
	*keylen = 192;
	*blocksize = 8;
	*contextsize = sizeof(struct _tripledes_ctx);
	*r_setkey = FNCCAST_SETKEY(do_tripledes_setkey);
	*r_encrypt= FNCCAST_CRYPT(do_tripledes_encrypt);
	*r_decrypt= FNCCAST_CRYPT(do_tripledes_decrypt);
	return "3DES";
    }
    return NULL;
}

