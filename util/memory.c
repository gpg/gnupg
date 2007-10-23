/* memory.c  -	memory allocation
 * Copyright (C) 1998, 1999, 2001, 2005 Free Software Foundation, Inc.
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
 *
 *
 * We use our own memory allocation functions instead of plain malloc(),
 * so that we can provide some special enhancements:
 *  a) functions to provide memory from a secure memory.
 *  b) by looking at the requested allocation size we
 *     can reuse memory very quickly (e.g. MPI storage)
 *     (really needed?)
 *  c) memory usage reporting if compiled with M_DEBUG
 *  d) memory checking if compiled with M_GUARD
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

/* This is a very crude alignment check which does not work on all CPUs
 * IIRC, I once introduced it for testing on an Alpha.  We should better
 * replace this guard stuff with one provided by a modern malloc library
 */
#if SIZEOF_UNSIGNED_LONG == 8
#define EXTRA_ALIGN 4
#else
#define EXTRA_ALIGN 0
#endif

#if defined(M_DEBUG) || defined(M_GUARD)
  static void membug( const char *fmt, ... );
#endif

#ifdef M_DEBUG

#ifndef M_GUARD
#define M_GUARD 1
#endif
#undef xmalloc
#undef xmalloc_clear
#undef xmalloc_secure
#undef xmalloc_secure_clear
#undef xrealloc
#undef xfree
#undef m_check
#undef xstrdup
#define FNAME(a)   m_debug_ ##a
#define FNAMEX(a)  m_debug_ ##a
#define FNAMEXM(a) m_debug_ ##a
#define FNAMEPRT  , const char *info
#define FNAMEARG  , info
#ifndef __riscos__
#define store_len(p,n,m) do { add_entry(p,n,m, \
					info, __FUNCTION__);  } while(0)
#else
#define store_len(p,n,m) do { add_entry(p,n,m, \
	          info, __func__ );  } while(0)
#endif
#else
#define FNAME(a)   m_ ##a
#define FNAMEX(a)  x ##a
#define FNAMEXM(a) xm ##a
#define FNAMEPRT
#define FNAMEARG
#define store_len(p,n,m) do { ((byte*)p)[EXTRA_ALIGN+0] = n;		      \
				((byte*)p)[EXTRA_ALIGN+1] = n >> 8 ;	      \
				((byte*)p)[EXTRA_ALIGN+2] = n >> 16 ;	      \
				((byte*)p)[EXTRA_ALIGN+3] = m? MAGIC_SEC_BYTE \
						 : MAGIC_NOR_BYTE;  \
			      } while(0)
#endif


#ifdef M_GUARD
static long used_memory;
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

static struct memtbl_entry *memtbl;  /* the table with the memory info */
static unsigned memtbl_size;	/* number of allocated entries */
static unsigned memtbl_len;	/* number of used entries */
static struct memtbl_entry *memtbl_unused;/* to keep track of unused entries */

static void dump_table_at_exit(void);
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
	/* look for a used entry in the table.	We take the first one,
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
		atexit( dump_table_at_exit );
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
    e->user_p = p + EXTRA_ALIGN + 4;
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
    p[EXTRA_ALIGN+0] = index;
    p[EXTRA_ALIGN+1] = index >> 8 ;
    p[EXTRA_ALIGN+2] = index >> 16 ;
    p[EXTRA_ALIGN+3] = mode? MAGIC_SEC_BYTE : MAGIC_NOR_BYTE  ;
    if( DBG_MEMORY )
	log_debug( "%s allocates %u bytes using %s\n", info, e->user_n, by );
}



/****************
 * Check that the memory block is correct. The magic byte has already been
 * checked. Checks which are done here:
 *    - see whether the index points into our memory table
 *    - see whether P is the same as the one stored in the table
 *    - see whether we have already freed this block.
 */
struct memtbl_entry *
check_mem( const byte *p, const char *info )
{
    unsigned n;
    struct memtbl_entry *e;

    n  = p[EXTRA_ALIGN+0];
    n |= p[EXTRA_ALIGN+1] << 8;
    n |= p[EXTRA_ALIGN+2] << 16;

    if( n >= memtbl_len )
	membug("memory at %p corrupted: index=%u table_len=%u (%s)\n",
				      p+EXTRA_ALIGN+4, n, memtbl_len, info );
    e = memtbl+n;

    if( e->user_p != p+EXTRA_ALIGN+4 )
	membug("memory at %p corrupted: reference mismatch (%s)\n",
							p+EXTRA_ALIGN+4, info );
    if( !e->inuse )
	membug("memory at %p corrupted: marked as free (%s)\n",
							p+EXTRA_ALIGN+4, info );

    if( !(p[EXTRA_ALIGN+3] == MAGIC_NOR_BYTE
	|| p[EXTRA_ALIGN+3] == MAGIC_SEC_BYTE) )
	membug("memory at %p corrupted: underflow=%02x (%s)\n",
				 p+EXTRA_ALIGN+4, p[EXTRA_ALIGN+3], info );
    if( p[EXTRA_ALIGN+4+e->user_n] != MAGIC_END_BYTE )
	membug("memory at %p corrupted: overflow=%02x (%s)\n",
		     p+EXTRA_ALIGN+4, p[EXTRA_ALIGN+4+e->user_n], info );
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
	if( e->user_p == p + EXTRA_ALIGN+ 4 )
	    membug("freeing an already freed pointer at %p\n", p+EXTRA_ALIGN+4 );
	else
	    membug("freeing pointer %p which is flagged as freed\n", p+EXTRA_ALIGN+4 );
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
    if( m_is_secure(p+EXTRA_ALIGN+4) )
	secmem_free(p);
    else {
        memset(p,'f', e->user_n+5);
	free(p);
    }
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
dump_table_at_exit( void)
{
    if( DBG_MEMSTAT )
	dump_table();
}

static void
dump_table( void)
{
    unsigned n;
    struct memtbl_entry *e;
    ulong sum = 0, chunks =0;

    for( e = memtbl, n = 0; n < memtbl_len; n++, e++ ) {
	if(e->inuse) {
	    dump_entry(e);
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

    for( e = memtbl, n = 0; n < memtbl_len; n++, e++ ) {
	if( e->inuse ) {
#ifndef __riscos__
	    check_mem(e->user_p-4-EXTRA_ALIGN, info);
#else 
	    check_mem((const byte *) e->user_p-4-EXTRA_ALIGN, info);
#endif
        }
    }
}

#endif /* M_DEBUG */

#if defined(M_DEBUG) || defined(M_GUARD)
static void
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
#endif

void
m_print_stats( const char *prefix )
{
#ifdef M_DEBUG
    unsigned n;
    struct memtbl_entry *e;
    ulong sum = 0, chunks =0;

    for( e = memtbl, n = 0; n < memtbl_len; n++, e++ ) {
	if(e->inuse) {
	    sum += e->user_n;
	    chunks++;
	}
    }

    log_debug( "%s%smemstat: %8lu bytes in %ld chunks used\n",
		prefix? prefix:"", prefix? ": ":"", sum, chunks );
#elif defined(M_GUARD)
    log_debug( "%s%smemstat: %8ld bytes\n",
		prefix? prefix:"", prefix? ": ":"", used_memory );
#endif
}

void
m_dump_table( const char *prefix )
{
#ifdef M_DEBUG
    fprintf(stderr,"Memory-Table-Dump: %s\n", prefix);
    dump_table();
#endif
    m_print_stats( prefix );
}


static void
out_of_core(size_t n, int secure)
{
    log_error ("out of %s memory while allocating %u bytes\n",
               secure? "secure":"" ,(unsigned)n );
    if (secure) {
        /*secmem_dump_stats ();*/
        log_info ("(this may be caused by too many secret keys used "
                  "simultaneously or due to excessive large key sizes)\n");
    }
#if defined(M_GUARD) && defined(__riscos__)
    abort();
#endif
    exit (2);
}

/****************
 * Allocate memory of size n.
 * This function gives up if we do not have enough memory
 */
void *
FNAMEXM(alloc)( size_t n FNAMEPRT )
{
    char *p;

#ifdef M_GUARD
    if(!n)
      out_of_core(n,0); /* should never happen */
    if( !(p = malloc( n + EXTRA_ALIGN+5 )) )
	out_of_core(n,0);
    store_len(p,n,0);
    used_memory += n;
    p[4+EXTRA_ALIGN+n] = MAGIC_END_BYTE;
    return p+EXTRA_ALIGN+4;
#else
    /* mallocing zero bytes is undefined by ISO-C, so we better make
       sure that it won't happen */
    if (!n)
      n = 1;
    if( !(p = malloc( n )) )
	out_of_core(n,0);
    return p;
#endif
}

/****************
 * Allocate memory of size n from the secure memory pool.
 * This function gives up if we do not have enough memory
 */
void *
FNAMEXM(alloc_secure)( size_t n FNAMEPRT )
{
    char *p;

#ifdef M_GUARD
    if(!n)
      out_of_core(n,1); /* should never happen */
    if( !(p = secmem_malloc( n +EXTRA_ALIGN+ 5 )) )
	out_of_core(n,1);
    store_len(p,n,1);
    p[4+EXTRA_ALIGN+n] = MAGIC_END_BYTE;
    return p+EXTRA_ALIGN+4;
#else
    /* mallocing zero bytes is undefined by ISO-C, so we better make
       sure that it won't happen */
    if (!n)
      n = 1;
    if( !(p = secmem_malloc( n )) )
	out_of_core(n,1);
    return p;
#endif
}

void *
FNAMEXM(alloc_clear)( size_t n FNAMEPRT )
{
    void *p;
    p = FNAMEXM(alloc)( n FNAMEARG );
    memset(p, 0, n );
    return p;
}

void *
FNAMEXM(alloc_secure_clear)( size_t n FNAMEPRT)
{
    void *p;
    p = FNAMEXM(alloc_secure)( n FNAMEARG );
    memset(p, 0, n );
    return p;
}


/****************
 * realloc and clear the old space
 */
void *
FNAMEX(realloc)( void *a, size_t n FNAMEPRT )
{
    void *b;

#ifdef M_GUARD
    if( a ) {
#error "--enable-m-guard does not currently work"
        unsigned char *p = a;
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
    }
    else
        b = FNAME(alloc)(n FNAMEARG);
#else
    if( m_is_secure(a) ) {
	if( !(b = secmexrealloc( a, n )) )
	    out_of_core(n,1);
    }
    else {
	if( !(b = realloc( a, n )) )
	    out_of_core(n,0);
    }
#endif

    return b;
}



/****************
 * Free a pointer
 */
void
FNAMEX(free)( void *a FNAMEPRT )
{
    byte *p = a;

    if( !p )
	return;
#ifdef M_DEBUG
    free_entry(p-EXTRA_ALIGN-4, info);
#elif defined M_GUARD
    m_check(p);
    if( m_is_secure(a) )
	secmem_free(p-EXTRA_ALIGN-4);
    else {
	used_memory -= m_size(a);
	free(p-EXTRA_ALIGN-4);
    }
#else
    if( m_is_secure(a) )
	secmem_free(p);
    else
	free(p);
#endif
}


void
FNAME(check)( const void *a FNAMEPRT )
{
#ifdef M_GUARD
    const byte *p = a;

#ifdef M_DEBUG
    if( p )
	check_mem(p-EXTRA_ALIGN-4, info);
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
#endif
}


size_t
m_size( const void *a )
{
#ifndef M_GUARD
    log_debug("dummy m_size called\n");
    return 0;
#else
    const byte *p = a;
    size_t n;

#ifdef M_DEBUG
    n = check_mem(p-EXTRA_ALIGN-4, "m_size")->user_n;
#else
    n  = ((byte*)p)[-4];
    n |= ((byte*)p)[-3] << 8;
    n |= ((byte*)p)[-2] << 16;
#endif
    return n;
#endif
}


char *
FNAMEX(strdup)( const char *a FNAMEPRT )
{
    size_t n = strlen(a);
    char *p = FNAMEXM(alloc)(n+1 FNAMEARG);
    strcpy(p, a);
    return p;
}


/* Wrapper around xmalloc_clear to take the usual 2 arguments of a
   calloc style function. */
void *
xcalloc (size_t n, size_t m)
{
  size_t nbytes;

  nbytes = n * m; 
  if (m && nbytes / m != n) 
    out_of_core (nbytes, 0);
  return xmalloc_clear (nbytes);
}

/* Wrapper around xmalloc_csecure_lear to take the usual 2 arguments
   of a calloc style function. */
void *
xcalloc_secure (size_t n, size_t m)
{
  size_t nbytes;

  nbytes = n * m; 
  if (m && nbytes / m != n) 
    out_of_core (nbytes, 1);
  return xmalloc_secure_clear (nbytes);
}

