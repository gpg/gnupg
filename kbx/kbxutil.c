/* kbxutil.c - The Keybox utility
 *	Copyright (C) 2000, 2001 Free Software Foundation, Inc.
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
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <unistd.h>

#include "../jnlib/logging.h"
#include "../jnlib/argparse.h"
#include "../jnlib/stringhelp.h"
#include "../common/i18n.h"
#include "keybox-defs.h"

#include <gcrypt.h>


enum cmd_and_opt_values {
  aNull = 0,
  oArmor	  = 'a',
  oDryRun	  = 'n',
  oOutput	  = 'o',
  oQuiet	  = 'q',
  oVerbose	  = 'v',
  
  aNoSuchCmd    = 500,   /* force other values not to be a letter */
  aFindByFpr,
  aFindByKid,
  aFindByUid,
  aStats,

  oDebug,
  oDebugAll,

  oNoArmor,
  

  aTest
};


static ARGPARSE_OPTS opts[] = {
  { 300, NULL, 0, N_("@Commands:\n ") },

/*   { aFindByFpr,  "find-by-fpr", 0, "|FPR| find key using it's fingerprnt" }, */
/*   { aFindByKid,  "find-by-kid", 0, "|KID| find key using it's keyid" }, */
/*   { aFindByUid,  "find-by-uid", 0, "|NAME| find key by user name" }, */
  { aStats,      "stats",       0, "show key statistics" }, 
  
  { 301, NULL, 0, N_("@\nOptions:\n ") },
  
/*   { oArmor, "armor",     0, N_("create ascii armored output")}, */
/*   { oArmor, "armour",     0, "@" }, */
/*   { oOutput, "output",    2, N_("use as output file")}, */
  { oVerbose, "verbose",   0, N_("verbose") },
  { oQuiet,	"quiet",   0, N_("be somewhat more quiet") },
  { oDryRun, "dry-run",   0, N_("do not make any changes") },
  
  { oDebug, "debug"     ,4|16, N_("set debugging flags")},
  { oDebugAll, "debug-all" ,0, N_("enable full debugging")},

  {0} /* end of list */
};


void myexit (int rc);

int keybox_errors_seen = 0;


static const char *
my_strusage( int level )
{
    const char *p;
    switch( level ) {
      case 11: p = "kbxutil (GnuPG)";
	break;
      case 13: p = VERSION; break;
      case 17: p = PRINTABLE_OS_NAME; break;
      case 19: p =
	    _("Please report bugs to " PACKAGE_BUGREPORT ".\n");
	break;
      case 1:
      case 40:	p =
	    _("Usage: kbxutil [options] [files] (-h for help)");
	break;
      case 41:	p =
	    _("Syntax: kbxutil [options] [files]\n"
	      "list, export, import Keybox data\n");
	break;


      default:	p = NULL;
    }
    return p;
}


static void
i18n_init(void)
{
#ifdef USE_SIMPLE_GETTEXT
    set_gettext_file( PACKAGE_GT );
#else
#ifdef ENABLE_NLS
    #ifdef HAVE_LC_MESSAGES
       setlocale( LC_TIME, "" );
       setlocale( LC_MESSAGES, "" );
    #else
       setlocale( LC_ALL, "" );
    #endif
    bindtextdomain( PACKAGE_GT, LOCALEDIR );
    textdomain( PACKAGE_GT );
#endif
#endif
}


/*  static void */
/*  wrong_args( const char *text ) */
/*  { */
/*      log_error("usage: kbxutil %s\n", text); */
/*      myexit ( 1 ); */
/*  } */


#if 0
static int
hextobyte( const byte *s )
{
    int c;

    if( *s >= '0' && *s <= '9' )
	c = 16 * (*s - '0');
    else if( *s >= 'A' && *s <= 'F' )
	c = 16 * (10 + *s - 'A');
    else if( *s >= 'a' && *s <= 'f' )
	c = 16 * (10 + *s - 'a');
    else
	return -1;
    s++;
    if( *s >= '0' && *s <= '9' )
	c += *s - '0';
    else if( *s >= 'A' && *s <= 'F' )
	c += 10 + *s - 'A';
    else if( *s >= 'a' && *s <= 'f' )
	c += 10 + *s - 'a';
    else
	return -1;
    return c;
}
#endif

#if 0
static char *
format_fingerprint ( const char *s )
{
    int i, c;
    byte fpr[20];

    for (i=0; i < 20 && *s; ) {
	if ( *s == ' ' || *s == '\t' ) {
	    s++;
	    continue;
	}
	c = hextobyte(s);
	if (c == -1) {
	    return NULL;
	}
	fpr[i++] = c;
	s += 2;
    }
    return gcry_xstrdup ( fpr );
}
#endif

#if 0
static int
format_keyid ( const char *s, u32 *kid )
{
    char helpbuf[9];
    switch ( strlen ( s ) ) {
      case 8:
	kid[0] = 0;
	kid[1] = strtoul( s, NULL, 16 );
	return 10;

      case 16:
	mem2str( helpbuf, s, 9 );
	kid[0] = strtoul( helpbuf, NULL, 16 );
	kid[1] = strtoul( s+8, NULL, 16 );
	return 11;
    }
    return 0; /* error */
}
#endif


int
main( int argc, char **argv )
{
  ARGPARSE_ARGS pargs;
  enum cmd_and_opt_values cmd = 0;
  
  set_strusage( my_strusage );
  /*log_set_name("kbxutil"); fixme */
#if 0
  /* check that the libraries are suitable.  Do it here because
   * the option parse may need services of the library */
  if ( !gcry_check_version ( "1.1.4" ) ) 
    {
      log_fatal(_("libgcrypt is too old (need %s, have %s)\n"),
                "1.1.4", gcry_check_version(NULL) );
    }
#endif

  /*create_dotlock(NULL); register locking cleanup */
  i18n_init();

  /* We need to use the gcry malloc function because jnlib does use them */
  keybox_set_malloc_hooks (gcry_malloc, gcry_realloc, gcry_free);
  ksba_set_malloc_hooks (gcry_malloc, gcry_realloc, gcry_free );


  pargs.argc = &argc;
  pargs.argv = &argv;
  pargs.flags=  1;  /* do not remove the args */
  while (arg_parse( &pargs, opts) )
    {
      switch (pargs.r_opt)
        {
        case oVerbose:
          /*opt.verbose++;*/
          /*gcry_control( GCRYCTL_SET_VERBOSITY, (int)opt.verbose );*/
          break;
        case oDebug:
          /*opt.debug |= pargs.r.ret_ulong; */
          break;
        case oDebugAll:
          /*opt.debug = ~0;*/
          break;

        case aFindByFpr:
        case aFindByKid:
        case aFindByUid:
        case aStats:
          cmd = pargs.r_opt;
          break;
          
        default:
          pargs.err = 2;
          break;
	}
    }
  if (log_get_errorcount(0) )
    myexit(2);
  
  if (!cmd)
      { /* default is to list a KBX file */
	if (!argc) 
          _keybox_dump_file (NULL, 0, stdout);
	else
          {
	    for (; argc; argc--, argv++) 
              _keybox_dump_file (*argv, 0, stdout);
          }
      }
  else if (cmd == aStats )
    {
	if (!argc) 
          _keybox_dump_file (NULL, 1, stdout);
	else
          {
	    for (; argc; argc--, argv++) 
              _keybox_dump_file (*argv, 1, stdout);
          }
    }
#if 0
  else if ( cmd == aFindByFpr ) 
    {
      char *fpr;
      if ( argc != 2 )
        wrong_args ("kbxfile foingerprint");
      fpr = format_fingerprint ( argv[1] );
      if ( !fpr )
        log_error ("invalid formatted fingerprint\n");
      else 
        {
          kbxfile_search_by_fpr ( argv[0], fpr );
          gcry_free ( fpr );
        }
    }
  else if ( cmd == aFindByKid ) 
    {
      u32 kid[2];
      int mode;
      
      if ( argc != 2 )
        wrong_args ("kbxfile short-or-long-keyid");
      mode = format_keyid ( argv[1], kid );
      if ( !mode )
        log_error ("invalid formatted keyID\n");
      else
        {
          kbxfile_search_by_kid ( argv[0], kid, mode );
	}
    }
  else if ( cmd == aFindByUid ) 
    {
      if ( argc != 2 )
        wrong_args ("kbxfile userID");
      kbxfile_search_by_uid ( argv[0], argv[1] );
    }
#endif
  else
      log_error ("unsupported action\n");
  
  myexit(0);
  return 8; /*NEVER REACHED*/
}


void
myexit( int rc )
{
  /*    if( opt.debug & DBG_MEMSTAT_VALUE ) {*/
/*  	gcry_control( GCRYCTL_DUMP_MEMORY_STATS ); */
/*  	gcry_control( GCRYCTL_DUMP_RANDOM_STATS ); */
  /*    }*/
/*      if( opt.debug ) */
/*  	gcry_control( GCRYCTL_DUMP_SECMEM_STATS ); */
    rc = rc? rc : log_get_errorcount(0)? 2 :
			keybox_errors_seen? 1 : 0;
    exit(rc );
}


