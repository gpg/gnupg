/* des.c
 *	Copyright (C) 1998 Free Software Foundation, Inc.
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

#include <config.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include "util.h"
#include "types.h"

#define DES_BLOCKSIZE 8
#define DES_ROUNDS 16

typedef struct {
    int tripledes;
} DES_context;


static const int IP[64] = {
  58, 50, 42, 34, 26, 18, 10,  2, 60, 52, 44, 36, 28, 20, 12, 4,
  62, 54, 46, 38, 30, 22, 14,  6, 64, 56, 48, 40, 32, 24, 16, 8,
  57, 49, 41, 33, 25, 17,  9,  1, 59, 51, 43, 35, 27, 19, 11, 3,
  61, 53, 45, 37, 29, 21, 13,  5, 63, 55, 47, 39, 31, 23, 15, 7
};

/* this is IP^(-1) */
static const int IPinv[64] = {
  40,  8, 48, 16, 56, 24, 64, 32, 39,  7, 47, 15, 55, 23, 63, 31,
  38,  6, 46, 14, 54, 22, 62, 30, 37,  5, 45, 13, 53, 21, 61, 29,
  36,  4, 44, 12, 52, 20, 60, 28, 35,  3, 43, 11, 51, 19, 59, 27,
  34,  2, 42, 10, 50, 18, 58, 26, 33,  1, 41,  9, 49, 17, 57, 25
};

static const int E[48] = {
  32,  1,  2,  3,  4,  5,  4,  5,  6,  7,  8,  9,
   8,  9, 10, 11, 12, 13, 12, 13, 14, 15, 16, 17,
  16, 17, 18, 19, 20, 21, 20, 21, 22, 23, 24, 25,
  24, 25, 26, 27, 28, 29, 28, 29, 30, 31, 32,  1
};

static const int P[32] = {
  16,  7, 20, 21, 29, 12, 28, 17,  1, 15, 23, 26,  5, 18, 31, 10,
  2,   8, 24, 14, 32, 27,  3,  9, 19, 13, 30,  6, 22, 11,  4, 25
};

static const int PC1[56] = {
  57, 49, 41, 33, 25, 17,  9, 1, 58, 50, 42, 34, 26, 18,
  10,  2, 59, 51, 43, 35, 27, 19, 11,  3, 60, 52, 44, 36,
  63, 55, 47, 39, 31, 23, 15,  7, 62, 54, 46, 38, 30, 22,
  14,  6, 61, 53, 45, 37, 29, 21, 13,  5, 28, 20, 12,  4
};

static const int PC2[48] = {
  14, 17, 11, 24,  1,  5,  3, 28, 15,  6, 21, 10,
  23, 19, 12,  4, 26,  8, 16,  7, 27, 20, 13,  2,
  41, 52, 31, 37, 47, 55, 30, 40, 51, 45, 33, 48,
  44, 49, 39, 56, 34, 53, 46, 42, 50, 36, 29, 32
};

/* S-boxes */
static const int sbox[8][4][16]= {
    { { 14,  4, 13,  1,  2, 15, 11,  8,  3, 10,  6, 12,  5,  9,  0,  7 },
      {  0, 15,  7,  4, 14,  2, 13,  1, 10,  6, 12, 11,  9,  5,  3,  8 },
      {  4,  1, 14,  8, 13,  6,  2, 11, 15, 12,  9,  7,  3, 10,  5,  0 },
      { 15, 12,  8,  2,  4,  9,  1,  7,  5, 11,  3, 14, 10,  0,  6, 13 }
    },
    { { 15,  1,  8, 14,  6, 11,  3,  4,  9,  7,  2, 13, 12,  0,  5, 10 },
      {  3, 13,  4,  7, 15,  2,  8, 14, 12,  0,  1, 10,  6,  9, 11,  5 },
      {  0, 14,  7, 11, 10,  4, 13,  1,  5,  8, 12,  6,  9,  3,  2, 15 },
      { 13,  8, 10,  1,  3, 15,  4,  2, 11,  6,  7, 12,  0,  5, 14,  9 }
    },
    { { 10,  0,  9, 14,  6,  3, 15,  5,  1, 13, 12,  7, 11,  4,  2,  8 },
      { 13,  7,  0,  9,  3,  4,  6, 10,  2,  8,  5, 14, 12, 11, 15,  1 },
      { 13,  6,  4,  9,  8, 15,  3,  0, 11,  1,  2, 12,  5, 10, 14,  7 },
      {  1, 10, 13,  0,  6,  9,  8,  7,  4, 15, 14,  3, 11,  5,  2, 12 }
    },
    { {  7, 13, 14,  3,  0,  6,  9, 10,  1,  2,  8,  5, 11, 12,  4, 15 },
      { 13,  8, 11,  5,  6, 15,  0,  3,  4,  7,  2, 12,  1, 10, 14,  9 },
      { 10,  6,  9,  0, 12, 11,  7, 13, 15,  1,  3, 14,  5,  2,  8,  4 },
      {  3, 15,  0,  6, 10,  1, 13,  8,  9,  4,  5, 11, 12,  7,  2, 14 }
    },
    { {  2, 12,  4,  1,  7, 10, 11,  6,  8,  5,  3, 15, 13,  0, 14,  9 },
      { 14, 11,  2, 12,  4,  7, 13,  1,  5,  0, 15, 10,  3,  9,  8,  6 },
      {  4,  2,  1, 11, 10, 13,  7,  8, 15,  9, 12,  5,  6,  3,  0, 14 },
      { 11,  8, 12,  7,  1, 14,  2, 13,  6, 15,  0,  9, 10,  4,  5,  3 }
    },
    { { 12,  1, 10, 15,  9,  2,  6,  8,  0, 13,  3,  4, 14,  7,  5, 11 },
      { 10, 15,  4,  2,  7, 12,  9,  5,  6,  1, 13, 14,  0, 11,  3,  8 },
      {  9, 14, 15,  5,  2,  8, 12,  3,  7,  0,  4, 10,  1, 13, 11,  6 },
      {  4,  3,  2, 12,  9,  5, 15, 10, 11, 14,  1,  7,  6,  0,  8, 13 }
    },
    { {  4, 11,  2, 14, 15,  0,  8, 13,  3, 12,  9,  7,  5, 10,  6,  1 },
      { 13,  0, 11,  7,  4,  9,  1, 10, 14,  3,  5, 12,  2, 15,  8,  6 },
      {  1,  4, 11, 13, 12,  3,  7, 14, 10, 15,  6,  8,  0,  5,  9,  2 },
      {  6, 11, 13,  8,  1,  4, 10,  7,  9,  5,  0, 15, 14,  2,  3, 12 }
    },
    { { 13,  2,  8,  4,  6, 15, 11,  1, 10,  9,  3, 14,  5,  0, 12,  7 },
      {  1, 15, 13,  8, 10,  3,  7,  4, 12,  5,  6, 11,  0, 14,  9,  2 },
      {  7, 11,  4,  1,  9, 12, 14,  2,  0,  6, 10, 13, 15,  3,  5,  8 },
      {  2,  1, 14,  7,  4, 10,  8, 13, 15, 12,  9,  0,  3,  5,  6, 11 }
    }
};

/*
 * How much to rotate each 28 bit half of the pc1 permutated
 *  56 bit key before using pc2 to give the i' key
 */
static const int rots[16] = {
  1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1
};


struct ip_table { u32 l, r };



static struct ip_table *ip_tbl, *ipinv_tbl;

static struct ip_table *
make_ip_table( int *bitno )
{
    struct ip_table *ip = m_alloc( 8*256* sizeof *ip );
    for(i=0; i < 8; i++ )

    return ip;
}


static void
gen_tables()
{
    ip_tbl = make_ip_table( IP );
    ipinv_tbl = make_ip_table( IPinv );
}







void
des_encrypt_block( DES_context *bc, byte *outbuf, byte *inbuf )
{
    u32 l, r;

    data =   inbuf[0] << 56 | inbuf[1] << 48 | inbuf[2] << 40 | inbuf[3] << 32
	   | inbuf[4] << 24 | inbuf[5] << 16 | inbuf[6] <<  8 | inbuf[7];

#define IP(L, R, B) \
	L  = ip[0][B[0]].l; R  = ip[0][B[0]].r; \
	L |= ip[1][B[1]].l; R |= ip[1][B[1]].r; \
	L |= ip[2][B[2]].l; R |= ip[2][B[2]].r; \
	L |= ip[3][B[3]].l; R |= ip[3][B[3]].r; \
	L |= ip[4][B[4]].l; R |= ip[4][B[4]].r; \
	L |= ip[5][B[5]].l; R |= ip[5][B[5]].r; \
	L |= ip[6][B[6]].l; R |= ip[6][B[6]].r; \
	L |= ip[7][B[7]].l; R |= ip[7][B[7]].r



    encrypt( bc, &d1, &d2 );
    outbuf[0] = (d1 >> 24) & 0xff;
    outbuf[1] = (d1 >> 16) & 0xff;
    outbuf[2] = (d1 >>	8) & 0xff;
    outbuf[3] =  d1	   & 0xff;
    outbuf[4] = (d2 >> 24) & 0xff;
    outbuf[5] = (d2 >> 16) & 0xff;
    outbuf[6] = (d2 >>	8) & 0xff;
    outbuf[7] =  d2	   & 0xff;
}


void
des_decrypt_block( BLOWFISH_context *bc, byte *outbuf, byte *inbuf )
{
    u32 d1, d2;

    d1 = inbuf[0] << 24 | inbuf[1] << 16 | inbuf[2] << 8 | inbuf[3];
    d2 = inbuf[4] << 24 | inbuf[5] << 16 | inbuf[6] << 8 | inbuf[7];
    decrypt( bc, &d1, &d2 );
    outbuf[0] = (d1 >> 24) & 0xff;
    outbuf[1] = (d1 >> 16) & 0xff;
    outbuf[2] = (d1 >>	8) & 0xff;
    outbuf[3] =  d1	   & 0xff;
    outbuf[4] = (d2 >> 24) & 0xff;
    outbuf[5] = (d2 >> 16) & 0xff;
    outbuf[6] = (d2 >>	8) & 0xff;
    outbuf[7] =  d2	   & 0xff;
}


static void
selftest()
{
}


void
des_3des_setkey( DES_context *c, byte *key, unsigned keylen )
{
    c->tripledes = 1;
}

void
des_setkey( DES_context *c, byte *key, unsigned keylen )
{
}


