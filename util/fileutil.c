/* fileutil.c -  file utilities
 *	Copyright (C) 1998 Free Software Foundation, Inc.
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
#include <stdarg.h>
#include <string.h>
#include <assert.h>
#include <unistd.h>
#include "util.h"
#include "memory.h"
#include "ttyio.h"


/***************
 * Extract from a given path the filename component.
 *
 */
char *
make_basename(const char *filepath)
{
    char *p;

    if ( !(p=strrchr(filepath, '/')) )
      #ifdef HAVE_DRIVE_LETTERS
	if ( !(p=strrchr(filepath, '\\')) )
	    if ( !(p=strrchr(filepath, ':')) )
      #endif
	      {
		return m_strdup(filepath);
	      }

    return m_strdup(p+1);
}



/***************
 * Extract from a given filename the path prepended to it.
 * If their isn't a path prepended to the filename, a dot
 * is returned ('.').
 *
 */
char *
make_dirname(const char *filepath)
{
    char *dirname;
    int  dirname_length;
    char *p;

    if ( !(p=strrchr(filepath, '/')) )
      #ifdef HAVE_DRIVE_LETTERS
	if ( !(p=strrchr(filepath, '\\')) )
	    if ( !(p=strrchr(filepath, ':')) )
      #endif
	      {
		return m_strdup(".");
	      }

    dirname_length = p-filepath;
    dirname = m_alloc(dirname_length+1);
    strncpy(dirname, filepath, dirname_length);
    dirname[dirname_length] = 0;

    return dirname;
}



/****************
 * Construct a filename from the NULL terminated list of parts.
 * Tilde expansion is done here.
 */
char *
make_filename( const char *first_part, ... )
{
    va_list arg_ptr ;
    size_t n;
    const char *s;
    char *name, *home, *p;

    va_start( arg_ptr, first_part ) ;
    n = strlen(first_part)+1;
    while( (s=va_arg(arg_ptr, const char *)) )
	n += strlen(s) + 1;
    va_end(arg_ptr);

    home = NULL;
    if( *first_part == '~' && first_part[1] == '/'
			   && (home = getenv("HOME")) && *home )
	n += strlen(home);

    name = m_alloc(n);
    p = home ? stpcpy(stpcpy(name,home), first_part+1)
	     : stpcpy(name, first_part);
    va_start( arg_ptr, first_part ) ;
    while( (s=va_arg(arg_ptr, const char *)) )
	p = stpcpy(stpcpy(p,"/"), s);
    va_end(arg_ptr);

    return name;
}


int
compare_filenames( const char *a, const char *b )
{
    /* ? check whether this is an absolute filename and
     * resolve symlinks?
     */
  #ifdef HAVE_DRIVE_LETTERS
    return stricmp(a,b);
  #else
    return strcmp(a,b);
  #endif
}


/****************
 * A simple function to decide whether the filename is stdout
 * or a real filename.
 */
const char *
print_fname_stdout( const char *s )
{
    if( !s || (*s == '-' && !s[1]) )
	return "[stdout]";
    return s;
}


const char *
print_fname_stdin( const char *s )
{
    if( !s || (*s == '-' && !s[1]) )
	return "[stdin]";
    return s;
}


