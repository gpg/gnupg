/* memory.c  -	memory allocation
 *	Copyright (c) 1997 by Werner Koch (dd9jn)
 *
 * We use our own memory allocation functions instead of plain malloc(),
 * so that we can provide some special enhancements:
 *  a) functions to provide memory from a secure memory.
 *     Don't know how to handle it yet, but it may be possible to
 *     use memory which can't be swapped out.
 *  b) By looking at the requested allocation size we
 *     can reuse memory very quickly (e.g. MPI storage)
 *  c) A controlbyte gives us the opportunity to use only one
 *     free() function and do some overflow checking.
 *  d) memory checking and reporting if compiled with M_DEBUG
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

#include <config.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>

#include "types.h"
#include "memory.h"
#include "util.h"


#define MAGIC_NOR_BYTE 0x55
#define MAGIC_SEC_BYTE 0xcc
#define MAGIC_END_BYTE 0xaa

const void membug( const char *fmt, ... );

#ifdef M_DEBUG
  #undef m_alloc
  #undef m_alloc_clear
  #undef m_alloc_secure
  #undef m_alloc_secure_clear
  #undef m_realloc
  #undef m_free
  #undef m_check
  #define FNAME(a)  m_debug_ ##a
  #define FNAMEPRT  , const char *info
  #define FNAMEARG  , info
  #define store_len(p,n,m) do { add_entry(p,n,m, \
					info, __FUNCTION__);  } while(0)
#else
  #define FNAME(a)  m_ ##a
  #define FNAMEPRT
  #define FNAMEARG
  #define store_len(p,n,m) do { ((byte*))p[0] = n;		    \
				((byte*))p[2] = n >> 8 ;	    \
				((byte*))p[3] = n >> 16 ;	    \
				((byte*))p[4] = m? MAGIC_SEC_BYTE   \
						 : MAGIC_NOR_BYTE;  \
			      } while(0)
#endif


#ifdef M_DEBUG	/* stuff used for memory debuging */

struct info_entry {
    struct info_entry *next;
    unsigned count;	/* call count */
    const char *info;	/* the reference to the info string */
};

struct memtbl_entry {
    const void *user_p;  /* for reference: the pointer given to the user */
    size_t	user_n;  /* length requested by the user */
    struct memtbl_entry *next; /* to build a list of unused entries */
    const struct info_entry *info; /* points into the table with */
				   /* the info strings */
    unsigned inuse:1; /* this entry is in use */
    unsigned count:31;
};


#define INFO_BUCKETS 53
#define info_hash(p)  ( *(u32*)((p)) % INFO_BUCKETS )
static struct info_entry *info_strings[INFO_BUCKETS]; /* hash table */

static struct memtbl_entry *memtbl;  /* the table with the memory infos */
static unsigned memtbl_size;	/* number of allocated entries */
static unsigned memtbl_len;	/* number of used entries */
static struct memtbl_entry *memtbl_unused;/* to keep track of unused entries */

static void dump_table(void);
static void check_allmem( const char *info );

/****************
 * Put the new P into the debug table and return a pointer to the table entry.
 * mode is true for security. BY is the name of the function which called us.
 */
static void
add_entry( byte *p, unsigned n, int mode, const char *info, const char *by )
{
    unsigned index;
    struct memtbl_entry *e;
    struct info_entry *ie;

    if( memtbl_len < memtbl_size  )
	index = memtbl_len++;
    else {
	struct memtbl_entry *e;
	/* look for an used entry in the table. We take the first one,
	 * so that freed entries remain as long as possible in the table
	 * (free appends a new one)
	 */
	if( (e = memtbl_unused) ) {
	    index = e - memtbl;
	    memtbl_unused = e->next;
	    e->next = NULL;
	}
	else { /* no free entries in the table: extend the table */
	    if( !memtbl_size ) { /* first time */
		memtbl_size = 100;
		if( !(memtbl = calloc( memtbl_size, sizeof *memtbl )) )
		    membug("memory debug table malloc failed\n");
		index = 0;
		memtbl_len = 1;
		if( DBG_MEMSTAT )
		    atexit( dump_table );
	    }
	    else { /* realloc */
		unsigned n = memtbl_size / 4; /* enlarge by 25% */
		if(!(memtbl = realloc(memtbl, (memtbl_size+n)*sizeof *memtbl)))
		    membug("memory debug table realloc failed\n");
		memset(memtbl+memtbl_size, 0, n*sizeof *memtbl );
		memtbl_size += n;
		index = memtbl_len++;
	    }
	}
    }
    e = memtbl+index;
    if( e->inuse )
	membug("Ooops: entry %u is flagged as in use\n", index);
    e->user_p = p + 4;
    e->user_n = n;
    e->count++;
    if( e->next )
	membug("Ooops: entry is in free entry list\n");
    /* do we already have this info string */
    for( ie = info_strings[info_hash(info)]; ie; ie = ie->next )
	if( ie->info == info )
	    break;
    if( !ie ) { /* no: make a new entry */
	if( !(ie = malloc( sizeof *ie )) )
	    membug("can't allocate info entry\n");
	ie->next = info_strings[info_hash(info)];
	info_strings[info_hash(info)] = ie;
	ie->info = info;
	ie->count = 0;
    }
    ie->count++;
    e->info = ie;
    e->inuse = 1;

    /* put the index at the start of the memory */
    p[0] = index;
    p[1] = index >> 8 ;
    p[2] = index >> 16 ;
    p[3] = mode? MAGIC_SEC_BYTE : MAGIC_NOR_BYTE  ;
    if( DBG_MEMORY )
	log_debug( "%s allocates %u bytes using %s\n", info, e->user_n, by );
}



/****************
 * Check that the memory block is correct. The magic byte has already been
 * checked. Checks which are done here:
 *    - see wether the index points into our memory table
 *    - see wether P is the same as the one stored in the table
 *    - see wether we have already freed this block.
 */
struct memtbl_entry *
check_mem( const byte *p, const char *info )
{
    unsigned n;
    struct memtbl_entry *e;

    n  = p[0];
    n |= p[1] << 8;
    n |= p[2] << 16;

    if( n >= memtbl_len )
	membug("memory at %p corrupted: index=%u table_len=%u (%s)\n",
						 p+4, n, memtbl_len, info );
    e = memtbl+n;

    if( e->user_p != p+4 )
	membug("memory at %p corrupted: reference mismatch (%s)\n", p+4, info );
    if( !e->inuse )
	membug("memory at %p corrupted: marked as free (%s)\n", p+4, info );

    if( !(p[3] == MAGIC_NOR_BYTE || p[3] == MAGIC_SEC_BYTE) )
	membug("memory at %p corrupted: underflow=%02x (%s)\n", p+4, p[3], info );
    if( p[4+e->user_n] != MAGIC_END_BYTE )
	membug("memory at %p corrupted: overflow=%02x (%s)\n", p+4, p[4+e->user_n], info );
    if( e->info->count > 20000 )
	membug("memory at %p corrupted: count too high (%s)\n", p+4, info );
    return e;
}


/****************
 * free the entry and the memory (replaces free)
 */
static void
free_entry( byte *p, const char *info )
{
    struct memtbl_entry *e, *e2;

    check_allmem("add_entry");

    e = check_mem(p, info);
    if( DBG_MEMORY )
	log_debug( "%s frees %u bytes alloced by %s\n",
				info, e->user_n, e->info->info );
    if( !e->inuse ) {
	if( e->user_p == p + 4 )
	    membug("freeing an already freed pointer at %p\n", p+4 );
	else
	    membug("freeing pointer %p which is flagged as freed\n", p+4 );
    }

    e->inuse = 0;
    e->next = NULL;
    if( !memtbl_unused )
	memtbl_unused = e;
    else {
	for(e2=memtbl_unused; e2->next; e2 = e2->next )
	    ;
	e2->next = e;
    }
    memset(p,'f', e->user_n+5);
    free(p);
}

static void
dump_entry(struct memtbl_entry *e )
{
    unsigned n = e - memtbl;

    fprintf(stderr, "mem %4u%c %5u %p %5u %s (%u)\n",
	 n, e->inuse?'a':'u', e->count,  e->user_p, e->user_n,
			      e->info->info, e->info->count );


}

static void
dump_table(void)
{
    unsigned n;
    struct memtbl_entry *e;
    ulong sum = 0, chunks =0;

    for( e = memtbl, n = 0; n < memtbl_len; n++, e++ ) {
	dump_entry(e);
	if(e->inuse) {
	    sum += e->user_n;
	    chunks++;
	}
    }
    fprintf(stderr, "          memory used: %8lu bytes in %ld chunks\n",
							   sum, chunks );
}

static void
check_allmem( const char *info )
{
    unsigned n;
    struct memtbl_entry *e;

    for( e = memtbl, n = 0; n < memtbl_len; n++, e++ )
	if( e->inuse )
	    check_mem(e->user_p-4, info);
}

#endif /* M_DEBUG */

const void
membug( const char *fmt, ... )
{
    va_list arg_ptr ;

    fprintf(stderr, "\nMemory Error: " ) ;
    va_start( arg_ptr, fmt ) ;
    vfprintf(stderr,fmt,arg_ptr) ;
    va_end(arg_ptr);
    fflush(stderr);
  #ifdef M_DEBUG
    if( DBG_MEMSTAT )
	dump_table();
  #endif
    abort();
}


static void
out_of_core(size_t n)
{
    log_fatal("out of memory while allocating %u bytes\n", (unsigned)n );
}

/****************
 * Allocate memory of size n.
 * This function gives up if we do not have enough memory
 */
void *
FNAME(alloc)( size_t n FNAMEPRT )
{
    char *p;

    if( !(p = malloc( n + 5 )) )
	out_of_core(n);
    store_len(p,n,0);
    p[4+n] = MAGIC_END_BYTE; /* need to add the length somewhere */
    return p+4;
}

/****************
 * Allocate memory of size n from the secure memory pool.
 * This function gives up if we do not have enough memory
 */
void *
FNAME(alloc_secure)( size_t n FNAMEPRT )
{
    char *p;

    if( !(p = malloc( n + 5 )) ) /* fixme: should alloc from the secure heap*/
	out_of_core(n);
    store_len(p,n,1);
    p[4+n] = MAGIC_END_BYTE;
    return p+4;
}

void *
FNAME(alloc_clear)( size_t n FNAMEPRT )
{
    void *p;
    p = FNAME(alloc)( n FNAMEARG );
    memset(p, 0, n );
    return p;
}

void *
FNAME(alloc_secure_clear)( size_t n FNAMEPRT)
{
    void *p;
    p = FNAME(alloc_secure)( n FNAMEARG );
    memset(p, 0, n );
    return p;
}


/****************
 * realloc and clear the new space
 */
void *
FNAME(realloc)( void *a, size_t n FNAMEPRT )
{   /* FIXME: should be optimized :-) */
    unsigned char *p = a;
    void *b;
    size_t len = m_size(a);

    if( len >= n ) /* we don't shrink for now */
	return a;
    if( p[-1] == MAGIC_SEC_BYTE )
	b = FNAME(alloc_secure_clear)(n FNAMEARG);
    else
	b = FNAME(alloc_clear)(n FNAMEARG);
    FNAME(check)(NULL FNAMEARG);
    memcpy(b, a, len );
    FNAME(free)(p FNAMEARG);
    return b;
}



/****************
 * Free a pointer
 */
void
FNAME(free)( void *a FNAMEPRT )
{
    byte *p = a;

    if( !p )
	return;
  #ifdef M_DEBUG
    free_entry(p-4, info);
  #else
    m_check(p);
    free(p-4);
  #endif
}


void
FNAME(check)( const void *a FNAMEPRT )
{
    const byte *p = a;

  #ifdef M_DEBUG
    if( p )
	check_mem(p-4, info);
    else
	check_allmem(info);
  #else
    if( !p )
	return;
    if( !(p[-1] == MAGIC_NOR_BYTE || p[-1] == MAGIC_SEC_BYTE) )
	membug("memory at %p corrupted (underflow=%02x)\n", p, p[-1] );
    else if( p[m_size(p)] != MAGIC_END_BYTE )
	membug("memory at %p corrupted (overflow=%02x)\n", p, p[-1] );
  #endif
}


size_t
m_size( const void *a )
{
    const byte *p = a;
    size_t n;

  #ifdef M_DEBUG
    n = check_mem(p-4, "m_size")->user_n;
  #else
    n  = ((byte*)p[-4];
    n |= ((byte*)p[-3] << 8;
    n |= ((byte*)p[-2] << 16;
  #endif
    return n;
}


int
m_is_secure( const void *p )
{
    return p && ((byte*)p)[-1] == MAGIC_SEC_BYTE;
}

