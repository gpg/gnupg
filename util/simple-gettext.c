/* simple-gettext.c  - a simplified version of gettext.
 * Copyright (C) 1995, 1996, 1997, 1999 Free Software Foundation, Inc.
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

/* This is a simplified version of gettext written by Ulrich Drepper.
 * It is used for the Win32 version of GnuPG beucase all the overhead
 * of gettext is not needed and we have to do some special Win32 stuff.
 * I decided that this is far easier than to tweak gettext for the special
 * cases (I tried it but it is a lot of code).	wk 15.09.99
 */

#include <config.h>
#ifdef USE_SIMPLE_GETTEXT
#ifndef __MINGW32__
  #error This file can only be used with MinGW32
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <windows.h>
#include "types.h"
#include "util.h"


/* The magic number of the GNU message catalog format.	*/
#define MAGIC	      0x950412de
#define MAGIC_SWAPPED 0xde120495

/* Revision number of the currently used .mo (binary) file format.  */
#define MO_REVISION_NUMBER 0


/* Header for binary .mo file format.  */
struct mo_file_header
{
  /* The magic number.	*/
  u32 magic;
  /* The revision number of the file format.  */
  u32 revision;
  /* The number of strings pairs.  */
  u32 nstrings;
  /* Offset of table with start offsets of original strings.  */
  u32 orig_tab_offset;
  /* Offset of table with start offsets of translation strings.  */
  u32 trans_tab_offset;
  /* Size of hashing table.  */
  u32 hash_tab_size;
  /* Offset of first hashing entry.  */
  u32 hash_tab_offset;
};

struct string_desc
{
  /* Length of addressed string.  */
  u32 length;
  /* Offset of string in file.	*/
  u32 offset;
};



struct loaded_domain
{
  char *data;
  int must_swap;
  u32 nstrings;
  char *mapped;
  struct string_desc *orig_tab;
  struct string_desc *trans_tab;
  u32 hash_size;
  u32 *hash_tab;
};


static struct loaded_domain *the_domain;

static __inline__ u32
do_swap_u32( u32 i )
{
  return (i << 24) | ((i & 0xff00) << 8) | ((i >> 8) & 0xff00) | (i >> 24);
}

#define SWAPIT(flag, data) ((flag) ? do_swap_u32(data) : (data) )


/* We assume to have `unsigned long int' value with at least 32 bits.  */
#define HASHWORDBITS 32

/* The so called `hashpjw' function by P.J. Weinberger
   [see Aho/Sethi/Ullman, COMPILERS: Principles, Techniques and Tools,
   1986, 1987 Bell Telephone Laboratories, Inc.]  */

static __inline__ ulong
hash_string( const char *str_param )
{
    unsigned long int hval, g;
    const char *str = str_param;

    hval = 0;
    while (*str != '\0')
    {
	hval <<= 4;
	hval += (unsigned long int) *str++;
	g = hval & ((unsigned long int) 0xf << (HASHWORDBITS - 4));
	if (g != 0)
	{
	  hval ^= g >> (HASHWORDBITS - 8);
	  hval ^= g;
	}
    }
    return hval;
}


static struct loaded_domain *
load_domain( const char *filename )
{
    FILE *fp;
    size_t size;
    struct stat st;
    struct mo_file_header *data = NULL;
    struct loaded_domain *domain = NULL;
    size_t to_read;
    char *read_ptr;

    fp = fopen( filename, "rb" );
    if( !fp )
       return NULL; /* can't open the file */
    /* we must know about the size of the file */
    if( fstat( fileno(fp ), &st )
	|| (size = (size_t)st.st_size) != st.st_size
	|| size < sizeof (struct mo_file_header) ) {
	fclose( fp );
	return NULL;
    }

    data = malloc( size );
    if( !data ) {
	fclose( fp );
	return NULL; /* out of memory */
    }

    to_read = size;
    read_ptr = (char *) data;
    do {
	long int nb = fread( read_ptr, 1, to_read, fp );
	if( nb < to_read ) {
	    fclose (fp);
	    free(data);
	    return NULL; /* read error */
	}
	read_ptr += nb;
	to_read -= nb;
    } while( to_read > 0 );
    fclose (fp);

    /* Using the magic number we can test whether it really is a message
     * catalog file.  */
    if( data->magic != MAGIC && data->magic != MAGIC_SWAPPED ) {
	/* The magic number is wrong: not a message catalog file.  */
	free( data );
	return NULL;
    }

    domain = calloc( 1, sizeof *domain );
    if( !domain )  {
	free( data );
	return NULL;
    }
    domain->data = (char *) data;
    domain->must_swap = data->magic != MAGIC;

    /* Fill in the information about the available tables.  */
    switch( SWAPIT(domain->must_swap, data->revision) ) {
      case 0:
	domain->nstrings = SWAPIT(domain->must_swap, data->nstrings);
	domain->orig_tab = (struct string_desc *)
	  ((char *) data + SWAPIT(domain->must_swap, data->orig_tab_offset));
	domain->trans_tab = (struct string_desc *)
	  ((char *) data + SWAPIT(domain->must_swap, data->trans_tab_offset));
	domain->hash_size = SWAPIT(domain->must_swap, data->hash_tab_size);
	domain->hash_tab = (u32 *)
	  ((char *) data + SWAPIT(domain->must_swap, data->hash_tab_offset));
      break;

      default: /* This is an invalid revision.	*/
	free( data );
	free( domain );
	return NULL;
    }

    /* allocate an array to keep track of code page mappings */
    domain->mapped = calloc( 1, domain->nstrings );
    if( !domain->mapped ) {
	free( data );
	free( domain );
	return NULL;
    }

    return domain;
}


/****************
 * Set the file used for translations.	Pass a NULL to disable
 * translation.  A new filename may be set at anytime.
 * WARNING: After changing the filename you shoudl not access any data
 *	    retrieved by gettext().
 */
int
set_gettext_file( const char *filename )
{
    struct loaded_domain *domain = NULL;

    if( filename && *filename ) {
	if( filename[0] == '/'
	   #ifdef HAVE_DRIVE_LETTERS
	    || ( isalpha(filename[0])
		 && filename[1] == ':'
		 && (filename[2] == '/' || filename[2] == '\\') )
	   #endif
	   ) {
	    /* absolute path - use it as is */
	    domain = load_domain( filename );
	}
	else { /* relative path - append ".mo" and get dir from the environment */
	    char *buf = NULL;
	    char *dir;

	    dir = read_w32_registry_string( NULL,
					    "Control Panel\\Mingw32\\NLS",
					    "MODir" );
	    if( dir && (buf=malloc(strlen(dir)+strlen(filename)+1+3+1)) ) {
		strcpy(stpcpy(stpcpy(stpcpy( buf, dir),"/"), filename),".mo");
		domain = load_domain( buf );
		free(buf);
	    }
	    free(dir);
	}
	if( !domain )
	    return -1;
    }

    if( the_domain ) {
	free( the_domain->data );
	free( the_domain->mapped );
	free( the_domain );
	the_domain = NULL;
    }
    the_domain = domain;
    return NULL;
}


static const char*
get_string( struct loaded_domain *domain, u32 idx )
{
    char *p = domain->data + SWAPIT(domain->must_swap,
				    domain->trans_tab[idx].offset);
    if( !domain->mapped[idx] ) {
	byte *pp;

	domain->mapped[idx] = 1;
	/* we assume Latin1 -> CP 850 for now */
	for( pp=p; *pp; pp++ ) {
	    if( (*pp & 0x80) ) {
		switch( *pp ) {
		  /* ISO-8859-1 to IBM-CP-850 */
		  case 0xa0: *pp = '\xff' ; break;  /* nobreakspace */
		  case 0xa1: *pp = '\xad' ; break;  /* exclamdown */
		  case 0xa2: *pp = '\xbd' ; break;  /* cent */
		  case 0xa3: *pp = '\x9c' ; break;  /* sterling */
		  case 0xa4: *pp = '\xcf' ; break;  /* currency */
		  case 0xa5: *pp = '\xbe' ; break;  /* yen */
		  case 0xa6: *pp = '\xdd' ; break;  /* brokenbar */
		  case 0xa7: *pp = '\xf5' ; break;  /* section */
		  case 0xa8: *pp = '\xf9' ; break;  /* diaeresis */
		  case 0xa9: *pp = '\xb8' ; break;  /* copyright */
		  case 0xaa: *pp = '\xa6' ; break;  /* ordfeminine */
		  case 0xab: *pp = '\xae' ; break;  /* guillemotleft */
		  case 0xac: *pp = '\xaa' ; break;  /* notsign */
		  case 0xad: *pp = '\xf0' ; break;  /* hyphen */
		  case 0xae: *pp = '\xa9' ; break;  /* registered */
		  case 0xaf: *pp = '\xee' ; break;  /* macron */
		  case 0xb0: *pp = '\xf8' ; break;  /* degree */
		  case 0xb1: *pp = '\xf1' ; break;  /* plusminus */
		  case 0xb2: *pp = '\xfd' ; break;  /* twosuperior */
		  case 0xb3: *pp = '\xfc' ; break;  /* threesuperior */
		  case 0xb4: *pp = '\xef' ; break;  /* acute */
		  case 0xb5: *pp = '\xe6' ; break;  /* mu */
		  case 0xb6: *pp = '\xf4' ; break;  /* paragraph */
		  case 0xb7: *pp = '\xfa' ; break;  /* periodcentered */
		  case 0xb8: *pp = '\xf7' ; break;  /* cedilla */
		  case 0xb9: *pp = '\xfb' ; break;  /* onesuperior */
		  case 0xba: *pp = '\xa7' ; break;  /* masculine */
		  case 0xbb: *pp = '\xaf' ; break;  /* guillemotright */
		  case 0xbc: *pp = '\xac' ; break;  /* onequarter */
		  case 0xbd: *pp = '\xab' ; break;  /* onehalf */
		  case 0xbe: *pp = '\xf3' ; break;  /* threequarters */
		  case 0xbf: *pp = '\xa8' ; break;  /* questiondown */
		  case 0xc0: *pp = '\xb7' ; break;  /* Agrave */
		  case 0xc1: *pp = '\xb5' ; break;  /* Aacute */
		  case 0xc2: *pp = '\xb6' ; break;  /* Acircumflex */
		  case 0xc3: *pp = '\xc7' ; break;  /* Atilde */
		  case 0xc4: *pp = '\x8e' ; break;  /* Adiaeresis */
		  case 0xc5: *pp = '\x8f' ; break;  /* Aring */
		  case 0xc6: *pp = '\x92' ; break;  /* AE */
		  case 0xc7: *pp = '\x80' ; break;  /* Ccedilla */
		  case 0xc8: *pp = '\xd4' ; break;  /* Egrave */
		  case 0xc9: *pp = '\x90' ; break;  /* Eacute */
		  case 0xca: *pp = '\xd2' ; break;  /* Ecircumflex */
		  case 0xcb: *pp = '\xd3' ; break;  /* Ediaeresis */
		  case 0xcc: *pp = '\xde' ; break;  /* Igrave */
		  case 0xcd: *pp = '\xd6' ; break;  /* Iacute */
		  case 0xce: *pp = '\xd7' ; break;  /* Icircumflex */
		  case 0xcf: *pp = '\xd8' ; break;  /* Idiaeresis */
		  case 0xd0: *pp = '\xd1' ; break;  /* Eth */
		  case 0xd1: *pp = '\xa5' ; break;  /* Ntilde */
		  case 0xd2: *pp = '\xe3' ; break;  /* Ograve */
		  case 0xd3: *pp = '\xe0' ; break;  /* Oacute */
		  case 0xd4: *pp = '\xe2' ; break;  /* Ocircumflex */
		  case 0xd5: *pp = '\xe5' ; break;  /* Otilde */
		  case 0xd6: *pp = '\x99' ; break;  /* Odiaeresis */
		  case 0xd7: *pp = '\x9e' ; break;  /* multiply */
		  case 0xd8: *pp = '\x9d' ; break;  /* Ooblique */
		  case 0xd9: *pp = '\xeb' ; break;  /* Ugrave */
		  case 0xda: *pp = '\xe9' ; break;  /* Uacute */
		  case 0xdb: *pp = '\xea' ; break;  /* Ucircumflex */
		  case 0xdc: *pp = '\x9a' ; break;  /* Udiaeresis */
		  case 0xdd: *pp = '\xed' ; break;  /* Yacute */
		  case 0xde: *pp = '\xe8' ; break;  /* Thorn */
		  case 0xdf: *pp = '\xe1' ; break;  /* ssharp */
		  case 0xe0: *pp = '\x85' ; break;  /* agrave */
		  case 0xe1: *pp = '\xa0' ; break;  /* aacute */
		  case 0xe2: *pp = '\x83' ; break;  /* acircumflex */
		  case 0xe3: *pp = '\xc6' ; break;  /* atilde */
		  case 0xe4: *pp = '\x84' ; break;  /* adiaeresis */
		  case 0xe5: *pp = '\x86' ; break;  /* aring */
		  case 0xe6: *pp = '\x91' ; break;  /* ae */
		  case 0xe7: *pp = '\x87' ; break;  /* ccedilla */
		  case 0xe8: *pp = '\x8a' ; break;  /* egrave */
		  case 0xe9: *pp = '\x82' ; break;  /* eacute */
		  case 0xea: *pp = '\x88' ; break;  /* ecircumflex */
		  case 0xeb: *pp = '\x89' ; break;  /* ediaeresis */
		  case 0xec: *pp = '\x8d' ; break;  /* igrave */
		  case 0xed: *pp = '\xa1' ; break;  /* iacute */
		  case 0xee: *pp = '\x8c' ; break;  /* icircumflex */
		  case 0xef: *pp = '\x8b' ; break;  /* idiaeresis */
		  case 0xf0: *pp = '\xd0' ; break;  /* eth */
		  case 0xf1: *pp = '\xa4' ; break;  /* ntilde */
		  case 0xf2: *pp = '\x95' ; break;  /* ograve */
		  case 0xf3: *pp = '\xa2' ; break;  /* oacute */
		  case 0xf4: *pp = '\x93' ; break;  /* ocircumflex */
		  case 0xf5: *pp = '\xe4' ; break;  /* otilde */
		  case 0xf6: *pp = '\x94' ; break;  /* odiaeresis */
		  case 0xf7: *pp = '\xf6' ; break;  /* division */
		  case 0xf8: *pp = '\x9b' ; break;  /* oslash */
		  case 0xf9: *pp = '\x97' ; break;  /* ugrave */
		  case 0xfa: *pp = '\xa3' ; break;  /* uacute */
		  case 0xfb: *pp = '\x96' ; break;  /* ucircumflex */
		  case 0xfc: *pp = '\x81' ; break;  /* udiaeresis */
		  case 0xfd: *pp = '\xec' ; break;  /* yacute */
		  case 0xfe: *pp = '\xe7' ; break;  /* thorn */
		  case 0xff: *pp = '\x98' ; break;  /* ydiaeresis */
		  default  :  break;
		}
	    }
	}

    }
    return (const char*)p;
}



const char *
gettext( const char *msgid )
{
    struct loaded_domain *domain;
    size_t act = 0;
    size_t top, bottom;

    if( !(domain = the_domain) )
	goto not_found;

    /* Locate the MSGID and its translation.  */
    if( domain->hash_size > 2 && domain->hash_tab ) {
	/* Use the hashing table.  */
	u32 len = strlen (msgid);
	u32 hash_val = hash_string (msgid);
	u32 idx = hash_val % domain->hash_size;
	u32 incr = 1 + (hash_val % (domain->hash_size - 2));
	u32 nstr = SWAPIT (domain->must_swap, domain->hash_tab[idx]);

	if ( !nstr ) /* Hash table entry is empty.  */
	    goto not_found;

	if( SWAPIT(domain->must_swap,
		    domain->orig_tab[nstr - 1].length) == len
	    && !strcmp( msgid,
		       domain->data + SWAPIT(domain->must_swap,
				    domain->orig_tab[nstr - 1].offset)) )
	    return get_string( domain, nstr - 1 );

	for(;;) {
	    if (idx >= domain->hash_size - incr)
		idx -= domain->hash_size - incr;
	    else
		idx += incr;

	    nstr = SWAPIT(domain->must_swap, domain->hash_tab[idx]);
	    if( !nstr )
		goto not_found; /* Hash table entry is empty.  */

	    if ( SWAPIT(domain->must_swap,
				domain->orig_tab[nstr - 1].length) == len
		 && !strcmp (msgid,
			 domain->data + SWAPIT(domain->must_swap,
					   domain->orig_tab[nstr - 1].offset)))
		return get_string( domain, nstr-1 );
	}
	/* NOTREACHED */
    }

    /* Now we try the default method:  binary search in the sorted
       array of messages.  */
    bottom = 0;
    top = domain->nstrings;
    while( bottom < top ) {
	int cmp_val;

	act = (bottom + top) / 2;
	cmp_val = strcmp(msgid, domain->data
			       + SWAPIT(domain->must_swap,
					domain->orig_tab[act].offset));
	if (cmp_val < 0)
	    top = act;
	else if (cmp_val > 0)
	    bottom = act + 1;
	else
	    return get_string( domain, act );
    }

  not_found:
    return msgid;
}

#if 0
       unsigned int cp1, cp2;

       cp1 = GetConsoleCP();
       cp2 = GetConsoleOutputCP();

       log_info("InputCP=%u  OutputCP=%u\n", cp1, cp2 );

       if( !SetConsoleOutputCP( 1252 ) )
	   log_info("SetConsoleOutputCP failed: %d\n", (int)GetLastError() );

       cp1 = GetConsoleCP();
       cp2 = GetConsoleOutputCP();
       log_info("InputCP=%u  OutputCP=%u after switch1\n", cp1, cp2 );
#endif

#endif /* USE_SIMPLE_GETTEXT */
