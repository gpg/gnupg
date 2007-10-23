/* fileutil.c -  file utilities
 * Copyright (C) 1998, 2003, 2005, 2007 Free Software Foundation, Inc.
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
#include <stdarg.h>
#include <string.h>
#include <assert.h>
#include <unistd.h>
#include <sys/types.h>
#ifdef HAVE_PWD_H
#include <pwd.h>
#endif
#include <ctype.h>
#ifdef HAVE_W32_SYSTEM
# define WIN32_LEAN_AND_MEAN
# include <windows.h>
#else /*!HAVE_W32_SYSTEM*/
# include <sys/types.h>
# include <sys/stat.h>
# include <unistd.h>
#endif /*!HAVE_W32_SYSTEM*/


#include "util.h"
#include "memory.h"
#include "ttyio.h"


/***************
 * Extract from a given path the filename component.
 *
 */
char *
make_basename(const char *filepath, const char *inputpath)
{
#ifdef __riscos__
    return riscos_make_basename(filepath, inputpath);
#endif

    char *p;

    if ( !(p=strrchr(filepath, DIRSEP_C)) )
#ifdef HAVE_DRIVE_LETTERS
	if ( !(p=strrchr(filepath, '\\')) )
	    if ( !(p=strrchr(filepath, ':')) )
#endif
	      {
		return xstrdup(filepath);
	      }

    return xstrdup(p+1);
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

    if ( !(p=strrchr(filepath, DIRSEP_C)) )
#ifdef HAVE_DRIVE_LETTERS
	if ( !(p=strrchr(filepath, '\\')) )
	    if ( !(p=strrchr(filepath, ':')) )
#endif
	      {
		return xstrdup(EXTSEP_S);
	      }

    dirname_length = p-filepath;
    dirname = xmalloc(dirname_length+1);
    strncpy(dirname, filepath, dirname_length);
    dirname[dirname_length] = 0;

    return dirname;
}

/* Expand tildes.  Handles both the ~/foo and ~username/foo cases.
   Returns what the tilde expands to.  *name is advanced to be past
   the tilde expansion. */
static char *
untilde(const char **name)
{
  char *home=NULL;

  assert((*name)[0]=='~');

  if((*name)[1]==DIRSEP_C || (*name)[1]=='\0')
    {
      /* This is the "~/foo" or "~" case. */
      char *tmp=getenv("HOME");
      if(tmp)
	home=xstrdup(tmp);

#ifdef HAVE_GETPWUID
      if(!home)
	{
	  struct passwd *pwd;

	  pwd=getpwuid(getuid());
	  if(pwd)
	    home=xstrdup(pwd->pw_dir);
	}
#endif
      if(home)
	(*name)++;
    }
#ifdef HAVE_GETPWNAM
  else
    {
      /* This is the "~username" case. */
      char *user,*sep;
      struct passwd *pwd;

      user=xstrdup((*name)+1);

      sep=strchr(user,DIRSEP_C);
      if(sep)
	*sep='\0';

      pwd=getpwnam(user);
      if(pwd)
	{
	  home=xstrdup(pwd->pw_dir);
	  (*name)+=1+strlen(user);
	}

      xfree(user);
    }
#endif

  return home;
}

/*
  Construct a filename from the NULL terminated list of parts.  Tilde
  expansion is done here.  Note that FIRST_PART must never be NULL and
  that this function is guaranteed to return an allocated string.  */
char *
make_filename( const char *first_part, ... )
{
    va_list arg_ptr ;
    size_t n;
    const char *s;
    char *name, *p, *home=NULL;

    va_start( arg_ptr, first_part ) ;
    n = strlen(first_part)+1;
    while( (s=va_arg(arg_ptr, const char *)) )
	n += strlen(s) + 1;
    va_end(arg_ptr);

#ifndef __riscos__
    if(*first_part=='~')
      {
	home=untilde(&first_part);
	if(home)
	  n+=strlen(home);
      }
#endif
    name = xmalloc(n);
    p = home ? stpcpy(stpcpy(name,home), first_part)
	     : stpcpy(name, first_part);
    va_start( arg_ptr, first_part ) ;
    while( (s=va_arg(arg_ptr, const char *)) )
	p = stpcpy(stpcpy(p, DIRSEP_S), s);
    va_end(arg_ptr);
    xfree(home);

#ifndef __riscos__
    return name;
#else /* __riscos__ */
    p = riscos_gstrans(name);
    xfree(name);
    return p;
#endif /* __riscos__ */
}


/* Compare whether the filenames are identical.  This is a
   special version of strcmp() taking the semantics of filenames in
   account.  Note that this function works only on the supplied names
   without considereing any context like the current directory.  See
   also same_file_p(). */
int
compare_filenames (const char *a, const char *b)
{
#ifdef __riscos__
  int c = 0;
  char *abuf, *bbuf;
  
  abuf = riscos_gstrans(a);
  bbuf = riscos_gstrans(b);
  c = ascii_strcasecmp (abuf, bbuf);
  xfree(abuf);
  xfree(bbuf);
  
  return c;
#elif defined (HAVE_DRIVE_LETTERS)
  for ( ; *a && *b; a++, b++ ) 
    {
      if (*a != *b 
          && (toupper (*(const unsigned char*)a)
              != toupper (*(const unsigned char*)b) )
          && !((*a == '/' && *b == '\\') || (*a == '\\' && *b == '/')))
        break;
    }
  if ((*a == '/' && *b == '\\') || (*a == '\\' && *b == '/'))
    return 0;
  else
    return (toupper (*(const unsigned char*)a) 
            - toupper (*(const unsigned char*)b));
#else /*!HAVE_DRIVE_LETTERS*/
  return strcmp (a,b);
#endif
}

/* Check whether the files NAME1 and NAME2 are identical.  This is for
   example achieved by comparing the inode numbers of the files.  */
int
same_file_p (const char *name1, const char *name2)
{
  int yes;
      
  /* First try a shortcut.  */
  if (!compare_filenames (name1, name2))
    yes = 1;
  else
    {
#ifdef HAVE_W32_SYSTEM  
      HANDLE file1, file2;
      BY_HANDLE_FILE_INFORMATION info1, info2;
      
      file1 = CreateFile (name1, 0, 0, NULL, OPEN_EXISTING, 0, NULL);
      if (file1 == INVALID_HANDLE_VALUE)
        yes = 0; /* If we can't open the file, it is not the same.  */
      else
        {
          file2 = CreateFile (name2, 0, 0, NULL, OPEN_EXISTING, 0, NULL);
          if (file1 == INVALID_HANDLE_VALUE)
            yes = 0; /* If we can't open the file, it is not the same.  */
          else
            {
              yes = (GetFileInformationByHandle (file1, &info1)
                     && GetFileInformationByHandle (file2, &info2)
                     && info1.dwVolumeSerialNumber==info2.dwVolumeSerialNumber
                     && info1.nFileIndexHigh == info2.nFileIndexHigh
                     && info1.nFileIndexLow == info2.nFileIndexLow);
              CloseHandle (file2);
            }
          CloseHandle (file1);
        }
#else /*!HAVE_W32_SYSTEM*/
      struct stat info1, info2;
      
      yes = (!stat (name1, &info1) && !stat (name2, &info2)
             && info1.st_dev == info2.st_dev && info1.st_ino == info2.st_ino);
#endif /*!HAVE_W32_SYSTEM*/
    }
  return yes;
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

/****************
 * Check if the file is compressed.
 **/
int
is_file_compressed( const char *s, int *ret_rc )
{
    IOBUF a;
    byte buf[4];
    int i, rc = 0;
    int overflow;

    struct magic_compress_s {
        size_t len;
        byte magic[4];
    } magic[] = {
        { 3, { 0x42, 0x5a, 0x68, 0x00 } }, /* bzip2 */
        { 3, { 0x1f, 0x8b, 0x08, 0x00 } }, /* gzip */
        { 4, { 0x50, 0x4b, 0x03, 0x04 } }, /* (pk)zip */
    };
    
    if ( iobuf_is_pipe_filename (s) || !ret_rc )
        return 0; /* We can't check stdin or no file was given */

    a = iobuf_open( s );
    if ( a == NULL ) {
        *ret_rc = G10ERR_OPEN_FILE;
        return 0;
    }

    if ( iobuf_get_filelength( a, &overflow ) < 4 && !overflow) {
        *ret_rc = 0;
        goto leave;
    }

    if ( iobuf_read( a, buf, 4 ) == -1 ) {
        *ret_rc = G10ERR_READ_FILE;
        goto leave;
    }

    for ( i = 0; i < DIM( magic ); i++ ) {
        if ( !memcmp( buf, magic[i].magic, magic[i].len ) ) {
            *ret_rc = 0;
            rc = 1;
            break;
        }
    }

leave:    
    iobuf_close( a );
    return rc;
}
