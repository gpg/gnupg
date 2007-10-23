/* dynload.c - load cipher extensions
 *	Copyright (C) 1998, 1999, 2001, 2002 Free Software Foundation, Inc.
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
#include <unistd.h>
#include "util.h"
#include "cipher.h"
#include "algorithms.h"


typedef struct ext_list {
    struct ext_list *next;
    char name[1];
} *EXTLIST;

static EXTLIST extensions;

/* This is actually not used anymore but we keep a list of already 
 * set extensions modules here.   
 *
 * Here is the ancient comment:
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

    if( *fname != DIRSEP_C ) { /* do tilde expansion etc */
	char *tmp;

	if( strchr(fname, DIRSEP_C) )
	    tmp = make_filename(fname, NULL);
	else
	    tmp = make_filename(GNUPG_LIBDIR, fname, NULL);
	el = xmalloc_clear( sizeof *el + strlen(tmp) );
	strcpy(el->name, tmp );
	xfree(tmp);
    }
    else {
	el = xmalloc_clear( sizeof *el + strlen(fname) );
	strcpy(el->name, fname );
    }
    /* check whether we have a class hint */
    if( (p=strchr(el->name,'(')) && (pe=strchr(p+1,')')) && !pe[1] )
	*p = *pe = 0;

    /* check that it is not already registered */
    intex = NULL;
    for(r = extensions; r; r = r->next ) {
	if( !compare_filenames(r->name, el->name) ) {
	    log_info("extension `%s' already registered\n", el->name );
	    xfree(el);
	    return;
	}
    }
    /* and register */
    el->next = extensions;
    extensions = el;
}

/* Return the module name with index SEQ, return NULL as as indication
   for end of list. */
const char *
dynload_enum_module_names (int seq)
{
  EXTLIST el = extensions;

  for (; el && el->name && seq; el = el->next, seq--)
    ;
  return el? el->name:NULL;
}
