/* misc.c -  miscellaneous functions
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
#if defined(__linux__) && defined(__alpha__)
  #include <asm/sysinfo.h>
  #include <asm/unistd.h>
#endif
#include "util.h"
#include "main.h"
#include "options.h"


const char *g10m_revision_string(int);
const char *g10c_revision_string(int);
const char *g10u_revision_string(int);

volatile void
pull_in_libs(void)
{
    g10m_revision_string(0);
    g10c_revision_string(0);
    g10u_revision_string(0);
}


#if defined(__linux__) && defined(__alpha__)
#warning using trap_unaligned
static int
setsysinfo(unsigned long op, void *buffer, unsigned long size,
		     int *start, void *arg, unsigned long flag)
{
    return syscall(__NR_osf_setsysinfo, op, buffer, size, start, arg, flag);
}

void
trap_unaligned(void)
{
    unsigned int buf[2];

    buf[0] = SSIN_UACPROC;
    buf[1] = UAC_SIGBUS | UAC_NOPRINT;
    setsysinfo(SSI_NVPAIRS, buf, 1, 0, 0, 0);
}
#else
void
trap_unaligned(void)
{  /* dummy */
}
#endif


u16
checksum_u16( unsigned n )
{
    u16 a;

    a  = (n >> 8) & 0xff;
    if( opt.emulate_bugs & 1 ) {
       a |= n & 0xff;
       log_debug("csum_u16 emulated for n=%u\n", n);
    }
    else
       a += n & 0xff;
    return a;
}

static u16
checksum_u16_nobug( unsigned n )
{
    u16 a;

    a  = (n >> 8) & 0xff;
    a += n & 0xff;
    return a;
}

u16
checksum( byte *p, unsigned n )
{
    u16 a;

    for(a=0; n; n-- )
	a += *p++;
    return a;
}

u16
checksum_mpi( MPI a )
{
    u16 csum;
    byte *buffer;
    unsigned nbytes;
    unsigned nbits;

    buffer = mpi_get_buffer( a, &nbytes, NULL );
    /* some versions of gpg encode wrong values for the length of an mpi
     * so that mpi_get_nbits() which counts the mpi yields another (shorter)
     * value than the one store with the mpi.  mpi_get_nbit_info() returns
     * this stored value if it is still available.
     */

    if( opt.emulate_bugs & 1 )
	nbits = 0;
    else
	nbits = mpi_get_nbit_info(a);
    if( !nbits )
       nbits = mpi_get_nbits(a);
    csum = checksum_u16( nbits );
    csum += checksum( buffer, nbytes );
    m_free( buffer );
    return csum;
}

/****************
 * This is the correct function
 */
u16
checksum_mpi_counted_nbits( MPI a )
{
    u16 csum;
    byte *buffer;
    unsigned nbytes;
    unsigned nbits;

    buffer = mpi_get_buffer( a, &nbytes, NULL );
    nbits = mpi_get_nbits(a);
    mpi_set_nbit_info(a,nbits);
    csum = checksum_u16_nobug( nbits );
    csum += checksum( buffer, nbytes );
    m_free( buffer );
    return csum;
}


u32
buffer_to_u32( const byte *buffer )
{
    unsigned long a;
    a =  *buffer << 24;
    a |= buffer[1] << 16;
    a |= buffer[2] << 8;
    a |= buffer[3];
    return a;
}

