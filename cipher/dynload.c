/* dynload.c - load cipher extensions
 *	Copyright (C) 1998, 1999, 2001 Free Software Foundation, Inc.
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
#include <string.h>
#include <unistd.h>
#ifdef HAVE_DL_DLOPEN
  #include <dlfcn.h>
#elif defined(HAVE_DLD_DLD_LINK)
  #include <dld.h>
#elif defined(HAVE_DL_SHL_LOAD)
  #include <dl.h>
  #include <errno.h>
#endif
#ifdef __MINGW32__
  #include <windows.h>
#endif
#include "util.h"
#include "cipher.h"
#include "dynload.h"

#ifdef WITH_SYMBOL_UNDERSCORE
  #define SYMBOL_VERSION "_gnupgext_version"
  #define SYMBOL_ENUM	 "_gnupgext_enum_func"
#else
  #define SYMBOL_VERSION "gnupgext_version"
  #define SYMBOL_ENUM	 "gnupgext_enum_func"
#endif


#ifndef RTLD_NOW
  #define RTLD_NOW  1
#endif

#ifdef HAVE_DL_SHL_LOAD  /* HPUX has shl_load instead of dlopen */
#define HAVE_DL_DLOPEN
#define dlopen(PATHNAME,MODE) \
    ((void *) shl_load(PATHNAME, DYNAMIC_PATH | \
	      (((MODE) & RTLD_NOW) ? BIND_IMMEDIATE : BIND_DEFERRED), 0L))
#define dlclose(HANDLE) shl_unload((shl_t) (HANDLE))
#define dlerror() (errno == 0 ? NULL : strerror(errno))

static void *
dlsym(void *handle, char *name)
{
    void *addr;
    if (shl_findsym((shl_t *)&handle,name,(short)TYPE_UNDEFINED,&addr) != 0) {
      return NULL;
    }
    return addr;
}
#endif /*HAVE_DL_SHL_LOAD*/

#ifdef __MINGW32__
#define HAVE_DL_DLOPEN
#define USE_DYNAMIC_LINKING

static int last_error = 0;
    
void*
dlopen(const char *pathname, int mode)
{
	void *h = LoadLibrary( pathname );
	if (!h) {
	log_error( "LoadLibrary failed ec=%d\n", (int)GetLastError() );
	last_error = 1;
	return NULL;
	}
	return h;
}

int
dlclose( void *handle )
{
	last_error = 0;
	return	FreeLibrary( handle );
}

char*
dlerror(void)
{
	static char dlerrstr[10];
	if (last_error) {
	sprintf(dlerrstr, "%d", (int)GetLastError() );
	return dlerrstr;
	}
	return NULL;
}

void*
dlsym( void *handle, const char *name )
{
	void *h = GetProcAddress( handle, name );
	if (!h) {
	log_error( "GetProcAddress failed ec=%d\n", (int)GetLastError() );
	last_error = 1;
	return NULL;
	}
	return h;
}
#endif /*__MINGW32__*/





typedef struct ext_list {
    struct ext_list *next;
    int internal;
  #ifdef HAVE_DL_DLOPEN
    void *handle; /* handle from dlopen() */
  #else
    int handle;   /* if the function has been loaded, this is true */
  #endif
    int  failed;  /* already tried but failed */
    void * (*enumfunc)(int, int*, int*, int*);
    char *hintstr; /* pointer into name */
    char name[1];
} *EXTLIST;

static EXTLIST extensions;

typedef struct {
    EXTLIST r;
    int seq1;
    int seq2;
    void *sym;
    int reqalgo;
} ENUMCONTEXT;


#ifdef HAVE_DLD_DLD_LINK
static char *mainpgm_path;
static int did_dld_init;
static int dld_available;
#endif


/****************
 * Register an extension module.  The last registered module will
 * be loaded first.  A name may have a list of classes
 * appended; e.g:
 *	mymodule.so(1:17,3:20,3:109)
 * means that this module provides digest algorithm 17 and public key
 * algorithms 20 and 109.  This is only a hint but if it is there the
 * loader may decide to only load a module which claims to have a
 * requested algorithm.
 *
 * mainpgm is the path to the program which wants to load a module
 * it is only used in some environments.
 */
void
register_cipher_extension( const char *mainpgm, const char *fname )
{
    EXTLIST r, el, intex;
    char *p, *pe;

  #ifdef HAVE_DLD_DLD_LINK
    if( !mainpgm_path && mainpgm && *mainpgm )
	mainpgm_path = m_strdup(mainpgm);
  #endif
    if( *fname != '/' ) { /* do tilde expansion etc */
	char *tmp;

	if( strchr(fname, '/') )
	    tmp = make_filename(fname, NULL);
	else
	    tmp = make_filename(GNUPG_LIBDIR, fname, NULL);
	el = m_alloc_clear( sizeof *el + strlen(tmp) );
	strcpy(el->name, tmp );
	m_free(tmp);
    }
    else {
	el = m_alloc_clear( sizeof *el + strlen(fname) );
	strcpy(el->name, fname );
    }
    /* check whether we have a class hint */
    if( (p=strchr(el->name,'(')) && (pe=strchr(p+1,')')) && !pe[1] ) {
	*p = *pe = 0;
	el->hintstr = p+1;
    }
    else
	el->hintstr = NULL;

    /* check that it is not already registered */
    intex = NULL;
    for(r = extensions; r; r = r->next ) {
	if( !compare_filenames(r->name, el->name) ) {
	    log_info("extension `%s' already registered\n", el->name );
	    m_free(el);
	    return;
	}
	else if( r->internal )
	    intex = r;
    }
    /* and register */
    /* we put them after the internal extension modules */
    /* this is so that the external modules do not get loaded */
    /* as soon as the internal modules are requested */
    if( intex ) {
	el->next = intex->next;
	intex->next = el;
    }
    else {
	el->next = extensions;
	extensions = el;
    }
}

void
register_internal_cipher_extension(
			const char *module_id,
			void * (*enumfunc)(int, int*, int*, int*)
				  )
{
    EXTLIST r, el;

    el = m_alloc_clear( sizeof *el + strlen(module_id) );
    strcpy(el->name, module_id );
    el->internal = 1;

    /* check that it is not already registered */
    for(r = extensions; r; r = r->next ) {
	if( !compare_filenames(r->name, el->name) ) {
	    log_info("extension `%s' already registered\n", el->name );
	    m_free(el);
	    return;
	}
    }
    /* and register */
    el->enumfunc = enumfunc;
  #ifdef HAVE_DL_DLOPEN
    el->handle = (void*)1;
  #else
    el->handle = 1;
  #endif
    el->next = extensions;
    extensions = el;
}


static int
load_extension( EXTLIST el )
{
  #ifdef USE_DYNAMIC_LINKING
    char **name;
  #ifdef HAVE_DL_DLOPEN
    const char *err;
    int seq = 0;
    int class, vers;
    void *sym;
  #else
    unsigned long addr;
    int rc;
  #endif

  #ifndef __MINGW32__
    /* make sure we are not setuid */
    if( getuid() != geteuid() )
	log_bug("trying to load an extension while still setuid\n");
  #endif

    /* now that we are not setuid anymore, we can safely load modules */
  #ifdef HAVE_DL_DLOPEN
    el->handle = dlopen(el->name, RTLD_NOW);
    if( !el->handle ) {
	log_error("%s: error loading extension: %s\n", el->name, dlerror() );
	goto failure;
    }
    name = (char**)dlsym(el->handle, SYMBOL_VERSION);
    if( (err=dlerror()) ) {
	log_error("%s: not a gnupg extension: %s\n", el->name, err );
	goto failure;
    }
  #else /* have dld */
    if( !did_dld_init ) {
	did_dld_init = 1;
	if( !mainpgm_path )
	    log_error("DLD is not correctly initialized\n");
	else {
	    rc = dld_init( dld_find_executable(mainpgm_path) );
	    if( rc )
		log_error("DLD init failed: %s\n", dld_strerror(rc) );
	    else
		dld_available = 1;
	}
    }
    if( !dld_available ) {
	log_error("%s: DLD not available\n", el->name );
	goto failure;
    }

    rc = dld_link( el->name );
    if( rc ) {
	log_error("%s: error loading extension: %s\n",
				    el->name, dld_strerror(rc) );
	goto failure;
    }
    addr = dld_get_symbol(SYMBOL_VERSION);
    if( !addr ) {
	log_error("%s: not a gnupg extension: %s\n",
				el->name, dld_strerror(dld_errno) );
	goto failure;
    }
    name = (char**)addr;
  #endif

    if( g10_opt_verbose > 1 )
	log_info("%s: %s%s%s%s\n", el->name, *name,
		  el->hintstr? " (":"",
		  el->hintstr? el->hintstr:"",
		  el->hintstr? ")":"");

  #ifdef HAVE_DL_DLOPEN
    sym = dlsym(el->handle, SYMBOL_ENUM);
    if( (err=dlerror()) ) {
	log_error("%s: invalid gnupg extension: %s\n", el->name, err );
	goto failure;
    }
    el->enumfunc = (void *(*)(int,int*,int*,int*))sym;
  #else /* dld */
    addr = dld_get_func(SYMBOL_ENUM);
    if( !addr ) {
	log_error("%s: invalid gnupg extension: %s\n",
				el->name, dld_strerror(dld_errno) );
	goto failure;
    }
    rc = dld_function_executable_p(SYMBOL_ENUM);
    if( rc ) {
	log_error("%s: extension function is not executable: %s\n",
					el->name, dld_strerror(rc) );
	goto failure;
    }
    el->enumfunc = (void *(*)(int,int*,int*,int*))addr;
    el->handle = 1; /* mark as usable */
  #endif

  #ifdef HAVE_DL_DLOPEN
    if( g10_opt_verbose > 2 ) {
	/* list the contents of the module */
	while( (sym = (*el->enumfunc)(0, &seq, &class, &vers)) ) {
	    if( vers != 1 ) {
		log_info("%s: ignoring func with version %d\n",el->name,vers);
		continue;
	    }
	    switch( class ) {
	      case 11:
	      case 21:
	      case 31:
		log_info("%s: provides %s algorithm %d\n", el->name,
				class == 11? "md"     :
				class == 21? "cipher" : "pubkey",
						       *(int*)sym);
		break;
	      default:
		/*log_debug("%s: skipping class %d\n", el->name, class);*/
		break;
	    }
	}
    }
  #endif
    return 0;

  failure:
  #ifdef HAVE_DL_DLOPEN
    if( el->handle ) {
	dlclose(el->handle);
	el->handle = NULL;
    }
  #endif
    el->failed = 1;
  #endif /*USE_DYNAMIC_LINKING*/
    return -1;
}



int
enum_gnupgext_digests( void **enum_context,
	    int *algo,
	    const char *(**r_get_info)( int, size_t*,byte**, int*, int*,
				       void (**)(void*),
				       void (**)(void*,byte*,size_t),
				       void (**)(void*),byte *(**)(void*)) )
{
    EXTLIST r;
    ENUMCONTEXT *ctx;

    if( !*enum_context ) { /* init context */
	ctx = m_alloc_clear( sizeof( *ctx ) );
	ctx->r = extensions;
	ctx->reqalgo = *algo;
	*enum_context = ctx;
    }
    else if( !algo ) { /* release the context */
	m_free(*enum_context);
	*enum_context = NULL;
	return 0;
    }
    else
	ctx = *enum_context;

    for( r = ctx->r; r; r = r->next )  {
	int class, vers;

	if( r->failed )
	    continue;
	if( !r->handle && load_extension(r) )
	    continue;
	/* get a digest info function */
	if( ctx->sym )
	    goto inner_loop;
	while( (ctx->sym = (*r->enumfunc)(10, &ctx->seq1, &class, &vers)) ) {
	    void *sym;
	    /* must check class because enumfunc may be wrong coded */
	    if( vers != 1 || class != 10 )
		continue;
	  inner_loop:
	    *r_get_info = ctx->sym;
	    while( (sym = (*r->enumfunc)(11, &ctx->seq2, &class, &vers)) ) {
		if( vers != 1 || class != 11 )
		    continue;
		*algo = *(int*)sym;
		ctx->r = r;
		return 1;
	    }
	    ctx->seq2 = 0;
	}
	ctx->seq1 = 0;
    }
    ctx->r = r;
    return 0;
}

const char *
enum_gnupgext_ciphers( void **enum_context, int *algo,
		       size_t *keylen, size_t *blocksize, size_t *contextsize,
		       int  (**setkeyf)( void *c, byte *key, unsigned keylen ),
		       void (**encryptf)( void *c, byte *outbuf, byte *inbuf ),
		       void (**decryptf)( void *c, byte *outbuf, byte *inbuf )
		     )
{
    EXTLIST r;
    ENUMCONTEXT *ctx;
    const char * (*finfo)(int, size_t*, size_t*, size_t*,
			  int  (**)( void *, byte *, unsigned),
			  void (**)( void *, byte *, byte *),
			  void (**)( void *, byte *, byte *));

    if( !*enum_context ) { /* init context */
	ctx = m_alloc_clear( sizeof( *ctx ) );
	ctx->r = extensions;
	*enum_context = ctx;
    }
    else if( !algo ) { /* release the context */
	m_free(*enum_context);
	*enum_context = NULL;
	return NULL;
    }
    else
	ctx = *enum_context;

    for( r = ctx->r; r; r = r->next )  {
	int class, vers;

	if( r->failed )
	    continue;
	if( !r->handle && load_extension(r) )
	    continue;
	/* get a cipher info function */
	if( ctx->sym )
	    goto inner_loop;
	while( (ctx->sym = (*r->enumfunc)(20, &ctx->seq1, &class, &vers)) ) {
	    void *sym;
	    /* must check class because enumfunc may be wrong coded */
	    if( vers != 1 || class != 20 )
		continue;
	  inner_loop:
	    finfo = ctx->sym;
	    while( (sym = (*r->enumfunc)(21, &ctx->seq2, &class, &vers)) ) {
		const char *algname;
		if( vers != 1 || class != 21 )
		    continue;
		*algo = *(int*)sym;
		algname = (*finfo)( *algo, keylen, blocksize, contextsize,
				    setkeyf, encryptf, decryptf );
		if( algname ) {
		    ctx->r = r;
		    return algname;
		}
	    }
	    ctx->seq2 = 0;
	}
	ctx->seq1 = 0;
    }
    ctx->r = r;
    return NULL;
}

const char *
enum_gnupgext_pubkeys( void **enum_context, int *algo,
    int *npkey, int *nskey, int *nenc, int *nsig, int *use,
    int (**generate)( int algo, unsigned nbits, MPI *skey, MPI **retfactors ),
    int (**check_secret_key)( int algo, MPI *skey ),
    int (**encryptf)( int algo, MPI *resarr, MPI data, MPI *pkey ),
    int (**decryptf)( int algo, MPI *result, MPI *data, MPI *skey ),
    int (**sign)( int algo, MPI *resarr, MPI data, MPI *skey ),
    int (**verify)( int algo, MPI hash, MPI *data, MPI *pkey,
		    int (*cmp)(void *, MPI), void *opaquev ),
    unsigned (**get_nbits)( int algo, MPI *pkey ) )
{
    EXTLIST r;
    ENUMCONTEXT *ctx;
    const char * (*finfo)( int, int *, int *, int *, int *, int *,
			   int (**)( int, unsigned, MPI *, MPI **),
			   int (**)( int, MPI * ),
			   int (**)( int, MPI *, MPI , MPI * ),
			   int (**)( int, MPI *, MPI *, MPI * ),
			   int (**)( int, MPI *, MPI , MPI * ),
			   int (**)( int, MPI , MPI *, MPI *,
					    int (*)(void*,MPI), void *),
			   unsigned (**)( int , MPI * ) );

    if( !*enum_context ) { /* init context */
	ctx = m_alloc_clear( sizeof( *ctx ) );
	ctx->r = extensions;
	*enum_context = ctx;
    }
    else if( !algo ) { /* release the context */
	m_free(*enum_context);
	*enum_context = NULL;
	return NULL;
    }
    else
	ctx = *enum_context;

    for( r = ctx->r; r; r = r->next )  {
	int class, vers;

	if( r->failed )
	    continue;
	if( !r->handle && load_extension(r) )
	    continue;
	/* get a pubkey info function */
	if( ctx->sym )
	    goto inner_loop;
	while( (ctx->sym = (*r->enumfunc)(30, &ctx->seq1, &class, &vers)) ) {
	    void *sym;
	    if( vers != 1 || class != 30 )
		continue;
	  inner_loop:
	    finfo = ctx->sym;
	    while( (sym = (*r->enumfunc)(31, &ctx->seq2, &class, &vers)) ) {
		const char *algname;
		if( vers != 1 || class != 31 )
		    continue;
		*algo = *(int*)sym;
		algname = (*finfo)( *algo, npkey, nskey, nenc, nsig, use,
				    generate, check_secret_key, encryptf,
				    decryptf, sign, verify, get_nbits );
		if( algname ) {
		    ctx->r = r;
		    return algname;
		}
	    }
	    ctx->seq2 = 0;
	}
	ctx->seq1 = 0;
    }
    ctx->r = r;
    return NULL;
}


int (*
dynload_getfnc_gather_random())(void (*)(const void*, size_t, int), int,
							    size_t, int)
{
    EXTLIST r;
    void *sym;

    for( r = extensions; r; r = r->next )  {
	int seq, class, vers;

	if( r->failed )
	    continue;
	if( !r->handle && load_extension(r) )
	    continue;
	seq = 0;
	while( (sym = (*r->enumfunc)(40, &seq, &class, &vers)) ) {
	    if( vers != 1 || class != 40 )
		continue;
	    return (int (*)(void (*)(const void*, size_t, int), int,
							size_t, int))sym;
	}
    }
    return NULL;
}


void (*
dynload_getfnc_fast_random_poll())( void (*)(const void*, size_t, int), int)
{
    EXTLIST r;
    void *sym;

    for( r = extensions; r; r = r->next )  {
	int seq, class, vers;

	if( r->failed )
	    continue;
	if( !r->handle && load_extension(r) )
	    continue;
	seq = 0;
	while( (sym = (*r->enumfunc)(41, &seq, &class, &vers)) ) {
	    if( vers != 1 || class != 41 )
		continue;
	    return (void (*)( void (*)(const void*, size_t, int), int))sym;
	}
    }
    return NULL;
}

