/* g10u.c  -  Wrapper for utility functions
 *	Copyright (C) 1998, 1999, 2000, 2001 Free Software Foundation, Inc.
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
#include "mpi.h"
#include "util.h"


/* FIXME: The modules should use functions from libgcrypt */

const char *g10u_revision_string(int dummy) { return "$Revision$"; }


void *g10_malloc( size_t n )	     { return m_alloc( n ); }
void *g10_calloc( size_t n )	     { return m_alloc_clear( n ); }
void *g10_malloc_secure( size_t n )  { return m_alloc_secure( n ); }
void *g10_calloc_secure( size_t n )  { return m_alloc_secure_clear( n ); }
void *g10_realloc( void *a, size_t n ) { return m_realloc( a, n ); }
void  g10_free( void *p )	     { m_free( p ); }
char *g10_strdup( const char * a)    { return m_strdup( a ); }

