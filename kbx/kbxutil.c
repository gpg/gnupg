/* kbxutil.c - The Keybox utility
 * Copyright (C) 2000, 2001, 2004, 2007, 2011 Free Software Foundation, Inc.
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
 * along with this program; if not, see <https://www.gnu.org/licenses/>.
 */

#include <config.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <sys/stat.h>
#include <unistd.h>
#include <limits.h>
#include <assert.h>

#include <gpg-error.h>
#include "../common/logging.h"
#include "../common/argparse.h"
#include "../common/stringhelp.h"
#include "../common/utf8conv.h"
#include "../common/i18n.h"
#include "keybox-defs.h"
#include "../common/init.h"
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
  aImportOpenPGP,
  aFindDups,
  aCut,

  oDebug,
  oDebugAll,

  oNoArmor,
  oFrom,
  oTo,

  aTest
};


static ARGPARSE_OPTS opts[] = {
  { 300, NULL, 0, N_("@Commands:\n ") },

/*   { aFindByFpr,  "find-by-fpr", 0, "|FPR| find key using it's fingerprnt" }, */
/*   { aFindByKid,  "find-by-kid", 0, "|KID| find key using it's keyid" }, */
/*   { aFindByUid,  "find-by-uid", 0, "|NAME| find key by user name" }, */
  { aStats,      "stats",       0, "show key statistics" },
  { aImportOpenPGP, "import-openpgp", 0, "import OpenPGP keyblocks"},
  { aFindDups,    "find-dups",   0, "find duplicates" },
  { aCut,         "cut",         0, "export records" },

  { 301, NULL, 0, N_("@\nOptions:\n ") },

  { oFrom, "from", 4, "|N|first record to export" },
  { oTo,   "to",   4, "|N|last record to export" },
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
      case 11: p = "kbxutil (@GNUPG@)";
	break;
      case 13: p = VERSION; break;
      case 17: p = PRINTABLE_OS_NAME; break;
      case 19: p = _("Please report bugs to <@EMAIL@>.\n"); break;

      case 1:
      case 40:	p =
	    _("Usage: kbxutil [options] [files] (-h for help)");
	break;
      case 41:	p =
	    _("Syntax: kbxutil [options] [files]\n"
	      "List, export, import Keybox data\n");
	break;


      default:	p = NULL;
    }
    return p;
}


/* Used by gcry for logging */
static void
my_gcry_logger (void *dummy, int level, const char *fmt, va_list arg_ptr)
{
  (void)dummy;

  /* Map the log levels.  */
  switch (level)
    {
    case GCRY_LOG_CONT: level = GPGRT_LOG_CONT; break;
    case GCRY_LOG_INFO: level = GPGRT_LOG_INFO; break;
    case GCRY_LOG_WARN: level = GPGRT_LOG_WARN; break;
    case GCRY_LOG_ERROR:level = GPGRT_LOG_ERROR; break;
    case GCRY_LOG_FATAL:level = GPGRT_LOG_FATAL; break;
    case GCRY_LOG_BUG:  level = GPGRT_LOG_BUG; break;
    case GCRY_LOG_DEBUG:level = GPGRT_LOG_DEBUG; break;
    default:            level = GPGRT_LOG_ERROR; break;
    }
  log_logv (level, fmt, arg_ptr);
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

static char *
read_file (const char *fname, size_t *r_length)
{
  FILE *fp;
  char *buf;
  size_t buflen;

  if (!strcmp (fname, "-"))
    {
      size_t nread, bufsize = 0;

      fp = stdin;
      buf = NULL;
      buflen = 0;
#define NCHUNK 8192
      do
        {
          bufsize += NCHUNK;
          if (!buf)
            buf = xtrymalloc (bufsize);
          else
            buf = xtryrealloc (buf, bufsize);
          if (!buf)
            log_fatal ("can't allocate buffer: %s\n", strerror (errno));

          nread = fread (buf+buflen, 1, NCHUNK, fp);
          if (nread < NCHUNK && ferror (fp))
            {
              log_error ("error reading '[stdin]': %s\n", strerror (errno));
              xfree (buf);
              return NULL;
            }
          buflen += nread;
        }
      while (nread == NCHUNK);
#undef NCHUNK

    }
  else
    {
      struct stat st;

      fp = fopen (fname, "rb");
      if (!fp)
        {
          log_error ("can't open '%s': %s\n", fname, strerror (errno));
          return NULL;
        }

      if (fstat (fileno(fp), &st))
        {
          log_error ("can't stat '%s': %s\n", fname, strerror (errno));
          fclose (fp);
          return NULL;
        }

      buflen = st.st_size;
      buf = xtrymalloc (buflen+1);
      if (!buf)
        log_fatal ("can't allocate buffer: %s\n", strerror (errno));
      if (fread (buf, buflen, 1, fp) != 1)
        {
          log_error ("error reading '%s': %s\n", fname, strerror (errno));
          fclose (fp);
          xfree (buf);
          return NULL;
        }
      fclose (fp);
    }

  *r_length = buflen;
  return buf;
}


static void
dump_fpr (const unsigned char *buffer, size_t len)
{
  int i;

  for (i=0; i < len; i++, buffer++)
    {
      if (len == 20)
        {
          if (i == 10)
            putchar (' ');
          printf (" %02X%02X", buffer[0], buffer[1]);
          i++; buffer++;
        }
      else
        {
          if (i && !(i % 8))
            putchar (' ');
          printf (" %02X", buffer[0]);
        }
    }
}


static void
dump_openpgp_key (keybox_openpgp_info_t info, const unsigned char *image)
{
  printf ("pub %2d %02X%02X%02X%02X",
          info->primary.algo,
          info->primary.keyid[4], info->primary.keyid[5],
          info->primary.keyid[6], info->primary.keyid[7] );
  dump_fpr (info->primary.fpr, info->primary.fprlen);
  putchar ('\n');
  if (info->nsubkeys)
    {
      struct _keybox_openpgp_key_info *k;

      k = &info->subkeys;
      do
        {
          printf ("sub %2d %02X%02X%02X%02X",
                  k->algo,
                  k->keyid[4], k->keyid[5],
                  k->keyid[6], k->keyid[7] );
          dump_fpr (k->fpr, k->fprlen);
          putchar ('\n');
          k = k->next;
        }
      while (k);
    }
  if (info->nuids)
    {
      struct _keybox_openpgp_uid_info *u;

      u = &info->uids;
      do
        {
          printf ("uid\t\t%.*s\n", (int)u->len, image + u->off);
          u = u->next;
        }
      while (u);
    }
}


static void
import_openpgp (const char *filename, int dryrun)
{
  gpg_error_t err;
  char *buffer;
  size_t buflen, nparsed;
  unsigned char *p;
  struct _keybox_openpgp_info info;
  KEYBOXBLOB blob;

  buffer = read_file (filename, &buflen);
  if (!buffer)
    return;
  p = (unsigned char *)buffer;
  for (;;)
    {
      err = _keybox_parse_openpgp (p, buflen, &nparsed, &info);
      assert (nparsed <= buflen);
      if (err)
        {
          if (gpg_err_code (err) == GPG_ERR_NO_DATA)
            break;
          if (gpg_err_code (err) == GPG_ERR_UNSUPPORTED_ALGORITHM)
            {
              /* This is likely a v3 key packet with a non-RSA
                 algorithm.  These are keys from very early versions
                 of GnuPG (pre-OpenPGP).  */
            }
          else
            {
              fflush (stdout);
              log_info ("%s: failed to parse OpenPGP keyblock: %s\n",
                        filename, gpg_strerror (err));
            }
        }
      else
        {
          if (dryrun)
            dump_openpgp_key (&info, p);
          else
            {
              err = _keybox_create_openpgp_blob (&blob, &info, p, nparsed, 0);
              if (err)
                {
                  fflush (stdout);
                  log_error ("%s: failed to create OpenPGP keyblock: %s\n",
                             filename, gpg_strerror (err));
                }
              else
                {
                  err = _keybox_write_blob (blob, stdout);
                  _keybox_release_blob (blob);
                  if (err)
                    {
                      fflush (stdout);
                      log_error ("%s: failed to write OpenPGP keyblock: %s\n",
                                 filename, gpg_strerror (err));
                    }
                }
            }

          _keybox_destroy_openpgp_info (&info);
        }
      p += nparsed;
      buflen -= nparsed;
    }
  xfree (buffer);
}




int
main( int argc, char **argv )
{
  ARGPARSE_ARGS pargs;
  enum cmd_and_opt_values cmd = 0;
  unsigned long from = 0, to = ULONG_MAX;
  int dry_run = 0;

  early_system_init ();
  set_strusage( my_strusage );
  gcry_control (GCRYCTL_DISABLE_SECMEM);
  log_set_prefix ("kbxutil", GPGRT_LOG_WITH_PREFIX);

  /* Make sure that our subsystems are ready.  */
  i18n_init ();
  init_common_subsystems (&argc, &argv);

  gcry_set_log_handler (my_gcry_logger, NULL);

  /*create_dotlock(NULL); register locking cleanup */

  /* We need to use the gcry malloc function because jnlib uses them.  */
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
        case aImportOpenPGP:
        case aFindDups:
        case aCut:
          cmd = pargs.r_opt;
          break;

        case oFrom: from = pargs.r.ret_ulong; break;
        case oTo: to = pargs.r.ret_ulong; break;

        case oDryRun: dry_run = 1; break;

        default:
          pargs.err = 2;
          break;
	}
    }

  if (to < from)
    log_error ("record number of \"--to\" is lower than \"--from\" one\n");


  if (log_get_errorcount(0) )
    myexit(2);

  if (!cmd)
    { /* Default is to list a KBX file */
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
  else if (cmd == aFindDups )
    {
      if (!argc)
        _keybox_dump_find_dups (NULL, 0, stdout);
      else
        {
          for (; argc; argc--, argv++)
            _keybox_dump_find_dups (*argv, 0, stdout);
        }
    }
  else if (cmd == aCut )
    {
      if (!argc)
        _keybox_dump_cut_records (NULL, from, to, stdout);
      else
        {
          for (; argc; argc--, argv++)
            _keybox_dump_cut_records (*argv, from, to, stdout);
        }
    }
  else if (cmd == aImportOpenPGP)
    {
      if (!argc)
        import_openpgp ("-", dry_run);
      else
        {
          for (; argc; argc--, argv++)
            import_openpgp (*argv, dry_run);
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
