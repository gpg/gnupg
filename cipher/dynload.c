/* dynload.c - load cipher extensions
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
#include <dlfcn.h>
#include "util.h"
#include "cipher.h"
#include "dynload.h"

typedef struct ext_list {
    struct ext_list *next;
    void *handle; /* handle from dlopen() */
    int  failed;  /* already tried but failed */
    void * (*enumfunc)(int, int*, int*, int*);
    char name[1];
} *EXTLIST;

static EXTLIST extensions;

typedef struct {
    EXTLIST r;
    int seq1;
    int seq2;
    void *sym;
} ENUMCONTEXT;

/****************
 * Register an extension module.  The last registered module will
 * be loaded first.
 */
void
register_cipher_extension( const char *fname )
{
    EXTLIST r, el;

    if( *fname != '/' ) { /* do tilde expansion etc */
	char *p ;

	if( strchr(fname, '/') )
	    p = make_filename(fname, NULL);
	else
	    p = make_filename(GNUPG_LIBDIR, fname, NULL);
	el = m_alloc_clear( sizeof *el + strlen(p) );
	strcpy(el->name, p );
	m_free(p);
    }
    else {
	el = m_alloc_clear( sizeof *el + strlen(fname) );
	strcpy(el->name, fname );
    }
    /* check that it is not already registered */
    for(r = extensions; r; r = r->next )
	if( !compare_filenames(r->name, el->name) ) {
	    log_debug("extension '%s' already registered\n", el->name );
	    m_free(el);
	    return;
	}
    log_debug("extension '%s' registered\n", el->name );
    /* and register */
    el->next = extensions;
    extensions = el;
}


static int
load_extension( EXTLIST el )
{
    char **name;
    void *sym;
    const char *err;
    int seq = 0;
    int class, vers;

    el->handle = dlopen(el->name, RTLD_LAZY);
    if( !el->handle ) {
	log_error("%s: error loading extension: %s\n", el->name, dlerror() );
	goto failure;
    }
    name = (char**)dlsym(el->handle, "gnupgext_version");
    if( (err=dlerror()) ) {
	log_error("%s: not a gnupg extension: %s\n", el->name, err );
	goto failure;
    }

    log_info("%s: version '%s'\n", el->name, *name );

    sym = dlsym(el->handle, "gnupgext_enum_func");
    if( (err=dlerror()) ) {
	log_error("%s: invalid gnupg extension: %s\n", el->name, err );
	goto failure;
    }
    el->enumfunc = (void *(*)(int,int*,int*,int*))sym;

    /* list the contents of the module */
    while( (sym = (*el->enumfunc)(0, &seq, &class, &vers)) ) {
	if( vers != 1 ) {
	    log_error("%s: ignoring func with version %d\n", el->name, vers);
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
	    log_debug("%s: skipping class %d\n", el->name, class);
	}
    }
    return 0;

  failure:
    if( el->handle ) {
	dlclose(el->handle);
	el->handle = NULL;
    }
    el->failed = 1;
    return -1;
}



const char *
enum_gnupgext_ciphers( void **enum_context, int *algo,
		       size_t *keylen, size_t *blocksize, size_t *contextsize,
		       void (**setkey)( void *c, byte *key, unsigned keylen ),
		       void (**encrypt)( void *c, byte *outbuf, byte *inbuf ),
		       void (**decrypt)( void *c, byte *outbuf, byte *inbuf )
		     )
{
    EXTLIST r;
    ENUMCONTEXT *ctx;
    const char * (*finfo)(int, size_t*, size_t*, size_t*,
			  void (**)( void *, byte *, unsigned),
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
				    setkey, encrypt, decrypt );
		log_debug("found algo %d (%s)\n", *algo, algname );
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

