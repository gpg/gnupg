/* mpi.h  -  Multi Precision Integers
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

#ifndef G10_MPI_H
#define G10_MPI_H

#include <stdio.h>
#include "iobuf.h"
#include "types.h"
#include "memory.h"


#define DBG_MPI     mpi_debug_mode
int mpi_debug_mode;

#if defined(__i386__)
  #define BITS_PER_MPI_LIMB  32
  #define BYTES_PER_MPI_LIMB  4
  #define BYTES_PER_MPI_LIMB2 8
  typedef unsigned long int mpi_limb_t;
  typedef   signed long int mpi_limb_signed_t;
#else
  #error add definions for this machine here
#endif

typedef struct {
    int alloced;    /* array size (# of allocated limbs) */
    int nlimbs;     /* number of valid limbs */
    int sign;	    /* indicates a negative number */
    int secure;     /* array mut be allocated in secure memory space */
    mpi_limb_t *d;  /* array with the limbs */
} *MPI;

#define MPI_NULL NULL

#define mpi_get_nlimbs(a) ((a)->nlimbs)

/*-- mpiutil.c --*/

#ifdef M_DEBUG
  #define mpi_alloc(n)	mpi_debug_alloc((n), M_DBGINFO( __LINE__ ) )
  #define mpi_alloc_secure(n)  mpi_debug_alloc_secure((n), M_DBGINFO( __LINE__ ) )
  #define mpi_free(a)	mpi_debug_free((a), M_DBGINFO(__LINE__) )
  #define mpi_resize(a,b) mpi_debug_resize((a),(b), M_DBGINFO(__LINE__) )
  #define mpi_copy(a)	  mpi_debug_copy((a), M_DBGINFO(__LINE__) )
  MPI mpi_debug_alloc( unsigned nlimbs, const char *info );
  MPI mpi_debug_alloc_secure( unsigned nlimbs, const char *info );
  void mpi_debug_free( MPI a, const char *info );
  void mpi_debug_resize( MPI a, unsigned nlimbs, const char *info );
  MPI  mpi_debug_copy( MPI a, const char *info	);
#else
  MPI mpi_alloc( unsigned nlimbs );
  MPI mpi_alloc_secure( unsigned nlimbs );
  void mpi_free( MPI a );
  void mpi_resize( MPI a, unsigned nlimbs );
  MPI  mpi_copy( MPI a );
#endif
void mpi_clear( MPI a );
void mpi_set( MPI w, MPI u);
void mpi_set_ui( MPI w, ulong u);
MPI  mpi_alloc_set_ui( unsigned long u);
void mpi_m_check( MPI a );
void mpi_swap( MPI a, MPI b);

/*-- mpicoder.c --*/
int mpi_encode( IOBUF out, MPI a );
int mpi_encode_csum( IOBUF out, MPI a, u16 *csum );
int mpi_write( IOBUF out, byte *a);
int mpi_write_csum( IOBUF out, byte *a, u16 *csum);
#ifdef M_DEBUG
  #define mpi_decode(a,b)   mpi_debug_decode((a),(b),  M_DBGINFO( __LINE__ ) )
  #define mpi_decode_buffer(a)	 mpi_debug_decode_buffer((a), M_DBGINFO( __LINE__ ) )
  MPI mpi_debug_decode(IOBUF inp, unsigned *nread, const char *info);
  MPI mpi_debug_decode_buffer(byte *buffer, const char *info );
#else
  MPI mpi_decode(IOBUF inp, unsigned *nread);
  MPI mpi_decode_buffer(byte *buffer );
#endif
byte *mpi_read(IOBUF inp, unsigned *ret_nread);
int mpi_fromstr(MPI val, const char *str);
int mpi_print( FILE *fp, MPI a, int mode );
u32 mpi_get_keyid( MPI a, u32 *keyid );

/*-- mpi-add.c --*/
void mpi_add_ui(MPI w, MPI u, ulong v );
void mpi_add(MPI w, MPI u, MPI v);
void mpi_sub_ui(MPI w, MPI u, ulong v );
void mpi_sub( MPI w, MPI u, MPI v);

/*-- mpi-mul.c --*/
void mpi_mul_ui(MPI w, MPI u, ulong v );
void mpi_mul_2exp( MPI w, MPI u, ulong cnt);
void mpi_mul( MPI w, MPI u, MPI v);

/*-- mpi-div.c --*/
ulong mpi_fdiv_r_ui( MPI rem, MPI dividend, ulong divisor );
void  mpi_fdiv_r( MPI rem, MPI dividend, MPI divisor );
void  mpi_fdiv_q( MPI quot, MPI dividend, MPI divisor );
void  mpi_fdiv_qr( MPI quot, MPI rem, MPI dividend, MPI divisor );
void  mpi_tdiv_r( MPI rem, MPI num, MPI den);
void  mpi_tdiv_qr( MPI quot, MPI rem, MPI num, MPI den);
int   mpi_divisible_ui(MPI dividend, ulong divisor );

/*-- mpi-gcd.c --*/
int mpi_gcd( MPI g, MPI a, MPI b );

/*-- mpi-pow.c --*/
void mpi_pow( MPI w, MPI u, MPI v);
void mpi_powm( MPI res, MPI base, MPI exp, MPI mod);

/*-- mpi-cmp.c --*/
int mpi_cmp_ui( MPI u, ulong v );
int mpi_cmp( MPI u, MPI v );

/*-- mpi-scan.c --*/
int mpi_getbyte( MPI a, unsigned index );
void mpi_putbyte( MPI a, unsigned index, int value );

/*-- mpi-bit.c --*/
unsigned mpi_get_nbits( MPI a );
int  mpi_test_bit( MPI a, unsigned n );
void mpi_set_bit( MPI a, unsigned n );
void mpi_clear_bit( MPI a, unsigned n );
void mpi_set_bytes( MPI a, unsigned nbits, byte (*fnc)(int), int opaque );

/*-- mpi-inv.c --*/
int  mpi_inv_mod( MPI x, MPI u, MPI v );


#endif /*G10_MPI_H*/
