/* gpg.c - The GnuPG utility (main for gpg)
 *	Copyright (C) 1998, 1999, 2000 Free Software Foundation, Inc.
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

#include <gcrypt.h>

#include "packet.h"
#include "iobuf.h"
#include "util.h"
#include "main.h"
#include "options.h"
#include "keydb.h"
#include "filter.h"
#include "ttyio.h"
#include "i18n.h"
#include "gnupg-defs.h"
#include "kbx.h"


enum cmd_and_opt_values { aNull = 0,
    oArmor	  = 'a',
    aDetachedSign = 'b',
    aSym	  = 'c',
    aDecrypt	  = 'd',
    aEncr	  = 'e',
    oInteractive  = 'i',
    oKOption	  = 'k',
    oDryRun	  = 'n',
    oOutput	  = 'o',
    oQuiet	  = 'q',
    oRecipient	  = 'r',
    aSign	  = 's',
    oTextmodeShort= 't',
    oUser	  = 'u',
    oVerbose	  = 'v',
    oCompress	  = 'z',
    oNotation	  = 'N',
    oBatch	  = 500,
    aClearsign,
    aStore,
    aKeygen,
    aSignEncr,
    aSignKey,
    aLSignKey,
    aListPackets,
    aEditKey,
    aDeleteKey,
    aDeleteSecretKey,
    aKMode,
    aKModeC,
    aImport,
    aFastImport,
    aVerify,
    aListKeys,
    aListSigs,
    aListSecretKeys,
    aSendKeys,
    aRecvKeys,
    aExport,
    aExportAll,
    aExportSecret,
    aCheckKeys,
    aGenRevoke,
    aPrimegen,
    aPrintMD,
    aPrintHMAC,
    aPrintMDs,
    aCheckTrustDB,
    aUpdateTrustDB,
    aFixTrustDB,
    aListTrustDB,
    aListTrustPath,
    aExportOwnerTrust,
    aImportOwnerTrust,
    aDeArmor,
    aEnArmor,
    aGenRandom,

    oTextmode,
    oFingerprint,
    oWithFingerprint,
    oAnswerYes,
    oAnswerNo,
    oKeyring,
    oSecretKeyring,
    oDefaultKey,
    oDefRecipient,
    oDefRecipientSelf,
    oNoDefRecipient,
    oOptions,
    oDebug,
    oDebugAll,
    oStatusFD,
    oNoComment,
    oNoVersion,
    oEmitVersion,
    oCompletesNeeded,
    oMarginalsNeeded,
    oMaxCertDepth,
    oLoadExtension,
    oRFC1991,
    oOpenPGP,
    oCipherAlgo,
    oDigestAlgo,
    oCompressAlgo,
    oPasswdFD,
    oNoVerbose,
    oTrustDBName,
    oNoSecmemWarn,
    oNoArmor,
    oNoDefKeyring,
    oNoGreeting,
    oNoTTY,
    oNoOptions,
    oNoBatch,
    oHomedir,
    oWithColons,
    oWithKeyData,
    oSkipVerify,
    oCompressKeys,
    oCompressSigs,
    oAlwaysTrust,
    oEmuChecksumBug,
    oRunAsShmCP,
    oSetFilename,
    oSetPolicyURL,
    oUseEmbeddedFilename,
    oComment,
    oDefaultComment,
    oThrowKeyid,
    oForceV3Sigs,
    oForceMDC,
    oS2KMode,
    oS2KDigest,
    oS2KCipher,
    oCharset,
    oNotDashEscaped,
    oEscapeFrom,
    oLockOnce,
    oLockMultiple,
    oKeyServer,
    oEncryptTo,
    oNoEncryptTo,
    oLoggerFD,
    oUtf8Strings,
    oNoUtf8Strings,
    oDisableCipherAlgo,
    oDisablePubkeyAlgo,
    oAllowNonSelfsignedUID,
    oNoLiteral,
    oSetFilesize,
    oEntropyDLLName,

    aFindByFpr,
    aFindByKid,
    aFindByUid,
aTest };


static ARGPARSE_OPTS opts[] = {

    { 300, NULL, 0, N_("@Commands:\n ") },

    { aFindByFpr,  "find-by-fpr", 0, "|FPR| find key using it's fingerprnt" },
    { aFindByKid,  "find-by-kid", 0, "|KID| find key using it's keyid" },
    { aFindByUid,  "find-by-uid", 0, "|NAME| find key by user name" },

    { 301, NULL, 0, N_("@\nOptions:\n ") },

    { oArmor, "armor",     0, N_("create ascii armored output")},
    { oArmor, "armour",     0, "@" },
    { oCompress, NULL,	      1, N_("|N|set compress level N (0 disables)") },
    { oOutput, "output",    2, N_("use as output file")},
    { oVerbose, "verbose",   0, N_("verbose") },
    { oQuiet,	"quiet",   0, N_("be somewhat more quiet") },
    { oDryRun, "dry-run",   0, N_("do not make any changes") },
    { oOptions, "options"   , 2, N_("read options from file")},

    { oDebug, "debug"     ,4|16, N_("set debugging flags")},
    { oDebugAll, "debug-all" ,0, N_("enable full debugging")},


{0} };



int gpg_errors_seen = 0;


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
	    _("Please report bugs to <gnupg-bugs@gnu.org>.\n");
	break;
      case 1:
      case 40:	p =
	    _("Usage: kbxutil [options] [files] (-h for help)");
	break;
      case 41:	p =
	    _("Syntax: kbxutil [options] [files]\n"
	      "list, export, import KBX data\n");
	break;


      default:	p = NULL;
    }
    return p;
}


static void
i18n_init(void)
{
  #ifdef USE_SIMPLE_GETTEXT
    set_gettext_file( PACKAGE );
  #else
  #ifdef ENABLE_NLS
    #ifdef HAVE_LC_MESSAGES
       setlocale( LC_TIME, "" );
       setlocale( LC_MESSAGES, "" );
    #else
       setlocale( LC_ALL, "" );
    #endif
    bindtextdomain( PACKAGE, GNUPG_LOCALEDIR );
    textdomain( PACKAGE );
  #endif
  #endif
}


static void
wrong_args( const char *text )
{
    log_error("usage: kbxutil %s\n", text);
    gpg_exit ( 1 );
}


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



int
main( int argc, char **argv )
{
    ARGPARSE_ARGS pargs;
    enum cmd_and_opt_values cmd = 0;

    set_strusage( my_strusage );
    log_set_name("kbxutil");
    /* check that the libraries are suitable.  Do it here because
     * the option parse may need services of the library */
    if ( !gcry_check_version ( "1.1.0a" ) ) {
	log_fatal(_("libgcrypt is too old (need %s, have %s)\n"),
				VERSION, gcry_check_version(NULL) );
    }

    create_dotlock(NULL); /* register locking cleanup */
    i18n_init();


    pargs.argc = &argc;
    pargs.argv = &argv;
    pargs.flags=  1;  /* do not remove the args */
    while( arg_parse( &pargs, opts) ) {
	switch( pargs.r_opt ) {
	  case oVerbose:
		opt.verbose++;
		gcry_control( GCRYCTL_SET_VERBOSITY, (int)opt.verbose );
		break;
	  case oDebug: opt.debug |= pargs.r.ret_ulong; break;
	  case oDebugAll: opt.debug = ~0; break;

	  case aFindByFpr:
	  case aFindByKid:
	  case aFindByUid:
	    cmd = pargs.r_opt;
	    break;

	  default : pargs.err = 2; break;
	}
    }
    if( log_get_errorcount(0) )
	gpg_exit(2);

    if ( !cmd ) { /* default is to list a KBX file */
	if( !argc ) {
	    print_kbxfile( NULL );
	}
	else {
	    for ( ; argc; argc--, argv++ ) {
		print_kbxfile( *argv );
	    }
	}
    }
    else if ( cmd == aFindByFpr ) {
	char *fpr;
	if ( argc != 2 )
	    wrong_args ("kbxfile foingerprint");
	fpr = format_fingerprint ( argv[1] );
	if ( !fpr )
	    log_error ("invalid formatted fingerprint\n");
	else {
	    kbxfile_search_by_fpr ( argv[0], fpr );
	    gcry_free ( fpr );
	}
    }
    else if ( cmd == aFindByKid ) {
	u32 kid[2];
	int mode;

	if ( argc != 2 )
	    wrong_args ("kbxfile short-or-long-keyid");
	mode = format_keyid ( argv[1], kid );
	if ( !mode )
	    log_error ("invalid formatted keyID\n");
	else {
	    kbxfile_search_by_kid ( argv[0], kid, mode );
	}
    }
    else if ( cmd == aFindByUid ) {
	if ( argc != 2 )
	    wrong_args ("kbxfile userID");
	kbxfile_search_by_uid ( argv[0], argv[1] );
    }
    else
	log_error ("unsupported action\n");

    gpg_exit(0);
    return 8; /*NEVER REACHED*/
}


void
gpg_exit( int rc )
{
    if( opt.debug & DBG_MEMSTAT_VALUE ) {
	gcry_control( GCRYCTL_DUMP_MEMORY_STATS );
	gcry_control( GCRYCTL_DUMP_RANDOM_STATS );
    }
    if( opt.debug )
	gcry_control( GCRYCTL_DUMP_SECMEM_STATS );
    rc = rc? rc : log_get_errorcount(0)? 2 :
			gpg_errors_seen? 1 : 0;
    exit(rc );
}


