/* rndw32.c  -	interface to the Winseed DLL
 *	Copyright (C) 1999 Free Software Foundation, Inc.
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

#include <config.h>
#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include <errno.h>
#include <string.h>

#include <windows.h>

#include "types.h"
#include "g10lib.h"
#include "util.h"
#include "dynload.h"


#ifdef IS_MODULE
  #define _(a) (a)
#else
  #include "i18n.h"
#endif


#define WIN32_SLOW_SEEDER	0
#define WIN32_FAST_SEEDER	1

#define PCP_SUCCESS		0
#define PCP_NULL_POINTER	1
#define PCP_SEEDER_FAILED	2
#define PCP_SEEDER_NO_MEM	3
#define PCP_SEEDER_TOO_SMALL	4
#define PCP_DLL_LOAD_FAILED	5
#define PCP_UNKNOWN_PLATFORM	6
#define PCP_ERROR_VERSION	7
#define PCP_DLL_FUNC		8
#define PCP_UNKNOWN_SEEDER_TYPE 9

typedef void *WIN32_SEEDER;

static WIN32_SEEDER (WINAPI *create_instance)( byte type, unsigned int *reason);
static void	    (WINAPI *delete_instance)( WIN32_SEEDER that );
static unsigned int (WINAPI *get_internal_seed_size)( WIN32_SEEDER that );
static void	    (WINAPI *set_internal_seed_size)( WIN32_SEEDER that,
						      unsigned int new_size);
static unsigned int (WINAPI *get_expected_seed_size)( WIN32_SEEDER that);
static unsigned int (WINAPI *get_seed)( WIN32_SEEDER that, byte *buffer,
					unsigned int *desired_length);

static WIN32_SEEDER slow_seeder, fast_seeder;
static byte *entropy_buffer;
static size_t entropy_buffer_size;

static char *entropy_dll;

/****************
 * Load and initialize the winseed DLL
 * NOTE: winseed is not part of the GnuPG distribution.  It should be available
 * at the GNU crypto FTP server site.
 * We do not load the DLL on demand to have a better control over the
 * location of the library.
 */
static void
load_and_init_winseed( void )
{
    int hInstance;
    void *addr;
    unsigned int reason = 0;
    unsigned int n1, n2;
    const char *dllname = entropy_dll? entropy_dll : "c:/gnupg/entropy.dll";

    hInstance = LoadLibrary( dllname );
    if( !hInstance )
	goto failure;
    if( !(addr = GetProcAddress( hInstance, "WS_create_instance" )) )
	goto failure;
    create_instance = addr;
    if( !(addr = GetProcAddress( hInstance, "WS_delete_instance" )) )
	goto failure;
    delete_instance = addr;
    if( !(addr = GetProcAddress( hInstance, "WS_get_internal_seed_size" )) )
	goto failure;
    get_internal_seed_size = addr;
    if( !(addr = GetProcAddress( hInstance, "WS_set_internal_seed_size" )) )
	goto failure;
    set_internal_seed_size = addr;
    if( !(addr = GetProcAddress( hInstance, "WS_get_expected_seed_size" )) )
	goto failure;
    get_expected_seed_size = addr;
    if( !(addr = GetProcAddress( hInstance, "WS_get_seed" )) )
	goto failure;
    get_seed = addr;

    /* we have all the functions - init the system */
    slow_seeder = create_instance( WIN32_SLOW_SEEDER, &reason);
    if( !slow_seeder ) {
	g10_log_fatal("error creating winseed slow seeder: rc=%u\n", reason );
	goto failure;
    }
    fast_seeder = create_instance( WIN32_FAST_SEEDER, &reason);
    if( !fast_seeder ) {
	g10_log_fatal("error creating winseed fast seeder: rc=%u\n", reason );
	goto failure;
    }
    g10_log_info("slow and fast seeders created.\n");
    n1 = get_internal_seed_size( slow_seeder );
    g10_log_info("slow buffer size=%u\n", n1);
    n2 = get_internal_seed_size( fast_seeder );
    g10_log_info("fast buffer size=%u\n", n2);

    entropy_buffer_size =  n1 > n2? n1: n2;
    entropy_buffer = g10_xmalloc( entropy_buffer_size );
    g10_log_info("using a buffer of size=%u\n", entropy_buffer_size );

    return;

  failure:
    g10_log_fatal("error loading winseed DLL `%s'\n", dllname );
}





/* Note: we always use the highest level.
 * TO boost the performance we may want to add some
 * additional code for level 1
 */
static int
gather_random( void (*add)(const void*, size_t, int), int requester,
					  size_t length, int level )
{
    unsigned int result;
    unsigned int nbytes;

    if( !slow_seeder )
	load_and_init_winseed();

    /* Our estimation on how much entropy we should use is very vague.
     * Winseed delivers some amount of entropy on each slow poll and
     * we add it to our random pool.  Depending on the required quality
     * level we adjust the requested length so that for higer quality
     * we make sure to add more entropy to our pool.  However, as we don't
     * like to waste any entropy collected by winseed, we always add
     * at least everything we got from winseed.
     */
    if( level > 1 )
	length *= 100;
    else if( level > 0 )
	length *= 10;

    for(;;) {
	nbytes = entropy_buffer_size;
	result = get_seed( slow_seeder, entropy_buffer, &nbytes);
	if( result ) {
	    g10_log_fatal("rndw32: get_seed(slow) failed: rc=%u\n", result);
	    return -1; /* actually never reached */
	}
	g10_log_info("rndw32: slow poll level %d, need %u, got %u\n",
		      level, (unsigned int)length, (unsigned int)nbytes );
	(*add)( entropy_buffer, nbytes, requester );
	if( length <= nbytes )
	    return 0; /* okay */
	length -= nbytes;
	g10_log_info("rndw32: need more\n");
    }
}

static int
gather_random_fast( void (*add)(const void*, size_t, int), int requester )
{
    unsigned int result;
    unsigned int nbytes;

    if( !fast_seeder )
	load_and_init_winseed();

    /* winseed delivers a constant ammount of entropy for a fast
     * poll.  We can simply use this and add it to the pool; no need
     * a loop like it is used in the slow poll */
    nbytes = entropy_buffer_size;
    result = get_seed( fast_seeder, entropy_buffer, &nbytes);
    if( result ) {
	g10_log_fatal("rndw32: get_seed(fast) failed: rc=%u\n", result);
	return -1; /* actually never reached */
    }
    /*g10_log_info("rndw32: fast poll got %u\n", (unsigned int)nbytes );*/
    (*add)( entropy_buffer, nbytes, requester );
    return 0;
}



#ifndef IS_MODULE
static
#endif
const char * const gnupgext_version = "RNDW32 ($Revision$)";

static struct {
    int class;
    int version;
    void *func;
} func_table[] = {
    { 40, 1, gather_random },
    { 41, 1, gather_random_fast },
};


#ifndef IS_MODULE
static
#endif
void *
gnupgext_enum_func( int what, int *sequence, int *class, int *vers )
{
    void *ret;
    int i = *sequence;

    do {
	if ( i >= DIM(func_table) || i < 0 ) {
	    return NULL;
	}
	*class = func_table[i].class;
	*vers  = func_table[i].version;
	ret = func_table[i].func;
	i++;
    } while ( what && what != *class );

    *sequence = i;
    return ret;
}

#ifdef USE_STATIC_RNDW32
void
rndw32_set_dll_name( const char *name )
{
    entropy_dll = m_strdup( name );
}
#endif

#ifndef IS_MODULE
void
rndw32_constructor(void)
{
    register_internal_cipher_extension( gnupgext_version,
					gnupgext_enum_func );
}
#endif

