/* g10.c - The GnuPG utility (main for gpg)
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
#ifdef HAVE_DOSISH_SYSTEM
  #include <fcntl.h> /* for setmode() */
#endif


#include "packet.h"
#include "iobuf.h"
#include "memory.h"
#include "util.h"
#include "main.h"
#include "options.h"
#include "keydb.h"
#include "trustdb.h"
#include "mpi.h"
#include "cipher.h"
#include "filter.h"
#include "ttyio.h"
#include "i18n.h"
#include "status.h"
#include "g10defs.h"
#include "hkp.h"


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
    aVerifyFiles,
    aListKeys,
    aListSigs,
    aListSecretKeys,
    aSendKeys,
    aRecvKeys,
    aExport,
    aExportAll,
    aExportSecret,
    aExportSecretSub,
    aCheckKeys,
    aGenRevoke,
    aPrimegen,
    aPrintMD,
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
    oCommandFD,
    oQuickRandom,
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
    oLockNever,
    oKeyServer,
    oEncryptTo,
    oNoEncryptTo,
    oLoggerFD,
    oUtf8Strings,
    oNoUtf8Strings,
    oDisableCipherAlgo,
    oDisablePubkeyAlgo,
    oAllowNonSelfsignedUID,
    oAllowFreeformUID,
    oNoLiteral,
    oSetFilesize,
    oHonorHttpProxy,
    oFastListMode,
    oListOnly,
    oIgnoreTimeConflict,
    oShowSessionKey,
    oOverrideSessionKey,
    oNoRandomSeedFile,
    oNoAutoKeyRetrieve,
    oMergeOnly,
    oTryAllSecrets,
    oTrustedKey,
    oEmu3DESS2KBug,  /* will be removed in 1.1 */
    oEmuMDEncodeBug,
aTest };


static ARGPARSE_OPTS opts[] = {

    { 300, NULL, 0, N_("@Commands:\n ") },

    { aSign, "sign",      256, N_("|[file]|make a signature")},
    { aClearsign, "clearsign", 256, N_("|[file]|make a clear text signature") },
    { aDetachedSign, "detach-sign", 256, N_("make a detached signature")},
    { aEncr, "encrypt",   256, N_("encrypt data")},
    { aSym, "symmetric", 256, N_("encryption only with symmetric cipher")},
    { aStore, "store",     256, N_("store only")},
    { aDecrypt, "decrypt",   256, N_("decrypt data (default)")},
    { aVerify, "verify"   , 256, N_("verify a signature")},
    { aVerifyFiles, "verify-files" , 256, "@" },
    { aListKeys, "list-keys", 256, N_("list keys")},
    { aListKeys, "list-public-keys", 256, "@" },
    { aListSigs, "list-sigs", 256, N_("list keys and signatures")},
    { aCheckKeys, "check-sigs",256, N_("check key signatures")},
    { oFingerprint, "fingerprint", 256, N_("list keys and fingerprints")},
    { aListSecretKeys, "list-secret-keys", 256, N_("list secret keys")},
    { aKeygen,	   "gen-key",  256, N_("generate a new key pair")},
    { aDeleteKey, "delete-key",256, N_("remove key from the public keyring")},
    { aDeleteSecretKey, "delete-secret-key",256,
				    N_("remove key from the secret keyring")},
    { aSignKey,  "sign-key"   ,256, N_("sign a key")},
    { aLSignKey, "lsign-key"  ,256, N_("sign a key locally")},
    { aEditKey,  "edit-key"   ,256, N_("sign or edit a key")},
    { aGenRevoke, "gen-revoke",256, N_("generate a revocation certificate")},
    { aExport, "export"           , 256, N_("export keys") },
    { aSendKeys, "send-keys"     , 256, N_("export keys to a key server") },
    { aRecvKeys, "recv-keys"     , 256, N_("import keys from a key server") },
    { aExportAll, "export-all"    , 256, "@" },
    { aExportSecret, "export-secret-keys" , 256, "@" },
    { aExportSecretSub, "export-secret-subkeys" , 256, "@" },
    { aImport, "import",      256     , N_("import/merge keys")},
    { aFastImport, "fast-import",  256 , "@"},
    { aListPackets, "list-packets",256,N_("list only the sequence of packets")},
    { aExportOwnerTrust,
	      "export-ownertrust", 256, N_("export the ownertrust values")},
    { aImportOwnerTrust,
	      "import-ownertrust", 256 , N_("import ownertrust values")},
    { aUpdateTrustDB,
	      "update-trustdb",0 , N_("update the trust database")},
    { aCheckTrustDB,
	      "check-trustdb",0 , N_("|[NAMES]|check the trust database")},
    { aFixTrustDB, "fix-trustdb",0 , N_("fix a corrupted trust database")},
    { aDeArmor, "dearmor", 256, N_("De-Armor a file or stdin") },
    { aDeArmor, "dearmour", 256, "@" },
    { aEnArmor, "enarmor", 256, N_("En-Armor a file or stdin") },
    { aEnArmor, "enarmour", 256, "@" },
    { aPrintMD,  "print-md" , 256, N_("|algo [files]|print message digests")},
    { aPrimegen, "gen-prime" , 256, "@" },
    { aGenRandom, "gen-random" , 256, "@" },

    { 301, NULL, 0, N_("@\nOptions:\n ") },

    { oArmor, "armor",     0, N_("create ascii armored output")},
    { oArmor, "armour",     0, "@" },
    { oRecipient, "recipient", 2, N_("|NAME|encrypt for NAME")},
    { oRecipient, "remote-user", 2, "@"},  /* old option name */
    { oDefRecipient, "default-recipient" ,2,
				  N_("|NAME|use NAME as default recipient")},
    { oDefRecipientSelf, "default-recipient-self" ,0,
				N_("use the default key as default recipient")},
    { oNoDefRecipient, "no-default-recipient", 0, "@" },
    { oEncryptTo, "encrypt-to", 2, "@" },
    { oNoEncryptTo, "no-encrypt-to", 0, "@" },
    { oUser, "local-user",2, N_("use this user-id to sign or decrypt")},
    { oCompress, NULL,	      1, N_("|N|set compress level N (0 disables)") },
    { oTextmodeShort, NULL,   0, "@"},
    { oTextmode, "textmode",  0, N_("use canonical text mode")},
    { oOutput, "output",    2, N_("use as output file")},
    { oVerbose, "verbose",   0, N_("verbose") },
    { oQuiet,	"quiet",   0, N_("be somewhat more quiet") },
    { oNoTTY, "no-tty", 0, N_("don't use the terminal at all") },
    { oForceV3Sigs, "force-v3-sigs", 0, N_("force v3 signatures") },
    { oForceMDC, "force-mdc", 0, N_("always use a MDC for encryption") },
    { oDryRun, "dry-run",   0, N_("do not make any changes") },
  /*{ oInteractive, "interactive", 0, N_("prompt before overwriting") }, */
    { oBatch, "batch",     0, N_("batch mode: never ask")},
    { oAnswerYes, "yes",       0, N_("assume yes on most questions")},
    { oAnswerNo,  "no",        0, N_("assume no on most questions")},
    { oKeyring, "keyring"   ,2, N_("add this keyring to the list of keyrings")},
    { oSecretKeyring, "secret-keyring" ,2, N_("add this secret keyring to the list")},
    { oDefaultKey, "default-key" ,2, N_("|NAME|use NAME as default secret key")},
    { oKeyServer, "keyserver",2, N_("|HOST|use this keyserver to lookup keys")},
    { oCharset, "charset"   , 2, N_("|NAME|set terminal charset to NAME") },
    { oOptions, "options"   , 2, N_("read options from file")},

    { oDebug, "debug"     ,4|16, "@"},
    { oDebugAll, "debug-all" ,0, "@"},
    { oStatusFD, "status-fd" ,1, N_("|FD|write status info to this FD") },
    { oNoComment, "no-comment", 0,   "@"},
    { oCompletesNeeded, "completes-needed", 1, "@"},
    { oMarginalsNeeded, "marginals-needed", 1, "@"},
    { oMaxCertDepth,	"max-cert-depth", 1, "@" },
    { oTrustedKey, "trusted-key", 2, N_("|KEYID|ulimately trust this key")},
    { oLoadExtension, "load-extension" ,2, N_("|FILE|load extension module FILE")},
    { oRFC1991, "rfc1991",   0, N_("emulate the mode described in RFC1991")},
    { oOpenPGP, "openpgp", 0, N_("set all packet, cipher and digest options to OpenPGP behavior")},
    { oS2KMode, "s2k-mode",  1, N_("|N|use passphrase mode N")},
    { oS2KDigest, "s2k-digest-algo",2,
		N_("|NAME|use message digest algorithm NAME for passphrases")},
    { oS2KCipher, "s2k-cipher-algo",2,
		N_("|NAME|use cipher algorithm NAME for passphrases")},
    { oCipherAlgo, "cipher-algo", 2 , N_("|NAME|use cipher algorithm NAME")},
    { oDigestAlgo, "digest-algo", 2 , N_("|NAME|use message digest algorithm NAME")},
    { oCompressAlgo, "compress-algo", 1 , N_("|N|use compress algorithm N")},
    { oThrowKeyid, "throw-keyid", 0, N_("throw keyid field of encrypted packets")},
    { oNotation,   "notation-data", 2, N_("|NAME=VALUE|use this notation data")},

    { 302, NULL, 0, N_(
  "@\n(See the man page for a complete listing of all commands and options)\n"
		      )},

    { 303, NULL, 0, N_("@\nExamples:\n\n"
    " -se -r Bob [file]          sign and encrypt for user Bob\n"
    " --clearsign [file]         make a clear text signature\n"
    " --detach-sign [file]       make a detached signature\n"
    " --list-keys [names]        show keys\n"
    " --fingerprint [names]      show fingerprints\n"  ) },

  /* hidden options */
    { aExportOwnerTrust, "list-ownertrust",0 , "@"},  /* alias */
    { aPrintMDs, "print-mds" , 256, "@"}, /* old */
    { aListTrustDB, "list-trustdb",0 , "@"},
    { aListTrustPath, "list-trust-path",0, "@"},
    { oKOption, NULL,	 0, "@"},
    { oPasswdFD, "passphrase-fd",1, "@" },
    { oCommandFD, "command-fd",1, "@" },
    { oQuickRandom, "quick-random", 0, "@"},
    { oNoVerbose, "no-verbose", 0, "@"},
    { oTrustDBName, "trustdb-name", 2, "@" },
    { oNoSecmemWarn, "no-secmem-warning", 0, "@" }, /* used only by regression tests */
    { oNoArmor, "no-armor",   0, "@"},
    { oNoArmor, "no-armour",   0, "@"},
    { oNoDefKeyring, "no-default-keyring", 0, "@" },
    { oNoGreeting, "no-greeting", 0, "@" },
    { oNoOptions, "no-options", 0, "@" }, /* shortcut for --options /dev/null */
    { oHomedir, "homedir", 2, "@" },   /* defaults to "~/.gnupg" */
    { oNoBatch, "no-batch", 0, "@" },
    { oWithColons, "with-colons", 0, "@"},
    { oWithKeyData,"with-key-data", 0, "@"},
    { aListKeys, "list-key", 0, "@" }, /* alias */
    { aListSigs, "list-sig", 0, "@" }, /* alias */
    { aCheckKeys, "check-sig",0, "@" }, /* alias */
    { oSkipVerify, "skip-verify",0, "@" },
    { oCompressKeys, "compress-keys",0, "@"},
    { oCompressSigs, "compress-sigs",0, "@"},
    { oAlwaysTrust, "always-trust", 0, "@"},
    { oEmuChecksumBug, "emulate-checksum-bug", 0, "@"},
    { oRunAsShmCP, "run-as-shm-coprocess", 4, "@" },
    { oSetFilename, "set-filename", 2, "@" },
    { oSetPolicyURL, "set-policy-url", 2, "@" },
    { oComment, "comment", 2, "@" },
    { oDefaultComment, "default-comment", 0, "@" },
    { oNoVersion, "no-version", 0, "@"},
    { oEmitVersion, "emit-version", 0, "@"},
    { oNotDashEscaped, "not-dash-escaped", 0, "@" },
    { oEscapeFrom, "escape-from-lines", 0, "@" },
    { oLockOnce, "lock-once", 0, "@" },
    { oLockMultiple, "lock-multiple", 0, "@" },
    { oLockNever, "lock-never", 0, "@" },
    { oLoggerFD, "logger-fd",1, "@" },
    { oUseEmbeddedFilename, "use-embedded-filename", 0, "@" },
    { oUtf8Strings, "utf8-strings", 0, "@" },
    { oNoUtf8Strings, "no-utf8-strings", 0, "@" },
    { oWithFingerprint, "with-fingerprint", 0, "@" },
    { oDisableCipherAlgo,  "disable-cipher-algo", 2, "@" },
    { oDisablePubkeyAlgo,  "disable-pubkey-algo", 2, "@" },
    { oAllowNonSelfsignedUID, "allow-non-selfsigned-uid", 0, "@" },
    { oAllowFreeformUID, "allow-freeform-uid", 0, "@" },
    { oNoLiteral, "no-literal", 0, "@" },
    { oSetFilesize, "set-filesize", 20, "@" },
    { oHonorHttpProxy,"honor-http-proxy", 0, "@" },
    { oFastListMode,"fast-list-mode", 0, "@" },
    { oListOnly, "list-only", 0, "@"},
    { oIgnoreTimeConflict, "ignore-time-conflict", 0, "@" },
    { oShowSessionKey, "show-session-key", 0, "@" },
    { oOverrideSessionKey, "override-session-key", 2, "@" },
    { oNoRandomSeedFile,  "no-random-seed-file", 0, "@" },
    { oNoAutoKeyRetrieve, "no-auto-key-retrieve", 0, "@" },
    { oMergeOnly,	  "merge-only", 0, "@" },
    { oTryAllSecrets,  "try-all-secrets", 0, "@" },
    { oEmu3DESS2KBug,  "emulate-3des-s2k-bug", 0, "@"},
    { oEmuMDEncodeBug,	"emulate-md-encode-bug", 0, "@"},
{0} };



int g10_errors_seen = 0;

static int utf8_strings = 0;
static int maybe_setuid = 1;

static char *build_list( const char *text,
			 const char *(*mapf)(int), int (*chkf)(int) );
static void set_cmd( enum cmd_and_opt_values *ret_cmd,
			enum cmd_and_opt_values new_cmd );
static void print_hex( byte *p, size_t n );
static void print_mds( const char *fname, int algo );
static void add_notation_data( const char *string );
static int  check_policy_url( const char *s );

const char *
strusage( int level )
{
  static char *digests, *pubkeys, *ciphers;
    const char *p;
    switch( level ) {
      case 11: p = "gpg (GnuPG)";
	break;
      case 13: p = VERSION; break;
      case 17: p = PRINTABLE_OS_NAME; break;
      case 19: p =
	    _("Please report bugs to <gnupg-bugs@gnu.org>.\n");
	break;
      case 1:
      case 40:	p =
	    _("Usage: gpg [options] [files] (-h for help)");
	break;
      case 41:	p =
	    _("Syntax: gpg [options] [files]\n"
	      "sign, check, encrypt or decrypt\n"
	      "default operation depends on the input data\n");
	break;

      case 31: p = "\nHome: "; break;
      case 32: p = opt.homedir; break;
      case 33: p = _("\nSupported algorithms:\n"); break;
      case 34:
	if( !ciphers )
	    ciphers = build_list("Cipher: ", cipher_algo_to_string,
							check_cipher_algo );
	p = ciphers;
	break;
      case 35:
	if( !pubkeys )
	    pubkeys = build_list("Pubkey: ", pubkey_algo_to_string,
							check_pubkey_algo );
	p = pubkeys;
	break;
      case 36:
	if( !digests )
	    digests = build_list("Hash: ", digest_algo_to_string,
							check_digest_algo );
	p = digests;
	break;


      default:	p = default_strusage(level);
    }
    return p;
}


static char *
build_list( const char *text, const char * (*mapf)(int), int (*chkf)(int) )
{
    int i;
    const char *s;
    size_t n=strlen(text)+2;
    char *list, *p;

    if( maybe_setuid )
	secmem_init( 0 );    /* drop setuid */

    for(i=1; i < 110; i++ )
	if( !chkf(i) && (s=mapf(i)) )
	    n += strlen(s) + 2;
    list = m_alloc( 21 + n ); *list = 0;
    for(p=NULL, i=1; i < 110; i++ ) {
	if( !chkf(i) && (s=mapf(i)) ) {
	    if( !p )
		p = stpcpy( list, text );
	    else
		p = stpcpy( p, ", ");
	    p = stpcpy(p, s );
	}
    }
    if( p )
	p = stpcpy(p, "\n" );
    return list;
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
    bindtextdomain( PACKAGE, G10_LOCALEDIR );
    textdomain( PACKAGE );
  #endif
  #endif
}

static void
wrong_args( const char *text)
{
    fputs(_("usage: gpg [options] "),stderr);
    fputs(text,stderr);
    putc('\n',stderr);
    g10_exit(2);
}


static char *
make_username( const char *string )
{
    char *p;
    if( utf8_strings )
	p = m_strdup(string);
    else
	p = native_to_utf8( string );
    return p;
}


static void
set_debug(void)
{
    if( opt.debug & DBG_MEMORY_VALUE )
	memory_debug_mode = 1;
    if( opt.debug & DBG_MEMSTAT_VALUE )
	memory_stat_debug_mode = 1;
    if( opt.debug & DBG_MPI_VALUE )
	mpi_debug_mode = 1;
    if( opt.debug & DBG_CIPHER_VALUE )
	g10c_debug_mode = 1;
    if( opt.debug & DBG_IOBUF_VALUE )
	iobuf_debug_mode = 1;

}


static void
set_cmd( enum cmd_and_opt_values *ret_cmd, enum cmd_and_opt_values new_cmd )
{
    enum cmd_and_opt_values cmd = *ret_cmd;

    if( !cmd || cmd == new_cmd )
	cmd = new_cmd;
    else if( cmd == aSign && new_cmd == aEncr )
	cmd = aSignEncr;
    else if( cmd == aEncr && new_cmd == aSign )
	cmd = aSignEncr;
    else if( cmd == aKMode && new_cmd == aSym )
	cmd = aKModeC;
    else if(	( cmd == aSign	   && new_cmd == aClearsign )
	     || ( cmd == aClearsign && new_cmd == aSign )  )
	cmd = aClearsign;
    else {
	log_error(_("conflicting commands\n"));
	g10_exit(2);
    }

    *ret_cmd = cmd;
}



int
main( int argc, char **argv )
{
    ARGPARSE_ARGS pargs;
    IOBUF a;
    int rc=0;
    int orig_argc;
    char **orig_argv;
    const char *fname;
    char *username;
    int may_coredump;
    STRLIST sl, remusr= NULL, locusr=NULL;
    STRLIST nrings=NULL, sec_nrings=NULL;
    armor_filter_context_t afx;
    int detached_sig = 0;
    FILE *configfp = NULL;
    char *configname = NULL;
    unsigned configlineno;
    int parse_debug = 0;
    int default_config =1;
    int default_keyring = 1;
    int greeting = 0;
    int nogreeting = 0;
    int use_random_seed = 1;
    enum cmd_and_opt_values cmd = 0;
    const char *trustdb_name = NULL;
    char *def_cipher_string = NULL;
    char *def_digest_string = NULL;
    char *s2k_cipher_string = NULL;
    char *s2k_digest_string = NULL;
    int pwfd = -1;
    int with_fpr = 0; /* make an option out of --fingerprint */
  #ifdef USE_SHM_COPROCESSING
    ulong requested_shm_size=0;
  #endif

    trap_unaligned();
    secmem_set_flags( secmem_get_flags() | 2 ); /* suspend warnings */
    /* Please note that we may running SUID(ROOT), so be very CAREFUL
     * when adding any stuff between here and the call to
     * secmem_init()  somewhere after the option parsing
     */
    log_set_name("gpg");
    secure_random_alloc(); /* put random number into secure memory */
    may_coredump = disable_core_dumps();
    init_signals();
    create_dotlock(NULL); /* register locking cleanup */
    i18n_init();
    opt.command_fd = -1; /* no command fd */
    opt.compress = -1; /* defaults to standard compress level */
    /* note: if you change these lines, look at oOpenPGP */
    opt.def_cipher_algo = 0;
    opt.def_digest_algo = 0;
    opt.def_compress_algo = 2;
    opt.s2k_mode = 3; /* iterated+salted */
    opt.s2k_digest_algo = DIGEST_ALGO_SHA1;
    opt.s2k_cipher_algo = CIPHER_ALGO_CAST5;
    opt.completes_needed = 1;
    opt.marginals_needed = 3;
    opt.max_cert_depth = 5;
    opt.pgp2_workarounds = 1;
    opt.auto_key_retrieve = 1;
  #ifdef __MINGW32__
    opt.homedir = read_w32_registry_string( NULL, "Software\\GNU\\GnuPG", "HomeDir" );
  #else
    opt.homedir = getenv("GNUPGHOME");
  #endif
    if( !opt.homedir || !*opt.homedir ) {
	opt.homedir = GNUPG_HOMEDIR;
    }

    /* check whether we have a config file on the commandline */
    orig_argc = argc;
    orig_argv = argv;
    pargs.argc = &argc;
    pargs.argv = &argv;
    pargs.flags= 1|(1<<6);  /* do not remove the args, ignore version */
    while( arg_parse( &pargs, opts) ) {
	if( pargs.r_opt == oDebug || pargs.r_opt == oDebugAll )
	    parse_debug++;
	else if( pargs.r_opt == oOptions ) {
	    /* yes there is one, so we do not try the default one, but
	     * read the option file when it is encountered at the commandline
	     */
	    default_config = 0;
	}
	else if( pargs.r_opt == oNoOptions )
	    default_config = 0; /* --no-options */
	else if( pargs.r_opt == oHomedir )
	    opt.homedir = pargs.r.ret_str;
      #ifdef USE_SHM_COPROCESSING
	else if( pargs.r_opt == oRunAsShmCP ) {
	    /* does not make sense in a options file, we do it here,
	     * so that we are the able to drop setuid as soon as possible */
	    opt.shm_coprocess = 1;
	    requested_shm_size = pargs.r.ret_ulong;
	}
	else if ( pargs.r_opt == oStatusFD ) {
	    /* this is needed to ensure that the status-fd filedescriptor is
	     * initialized when init_shm_coprocessing() is called */
	    set_status_fd( pargs.r.ret_int );
	}
      #endif
    }


  #ifdef USE_SHM_COPROCESSING
    if( opt.shm_coprocess ) {
	init_shm_coprocessing(requested_shm_size, 1 );
    }
  #endif
    /* initialize the secure memory. */
    secmem_init( 16384 );
    maybe_setuid = 0;
    /* Okay, we are now working under our real uid */

    if( default_config )
	configname = make_filename(opt.homedir, "options", NULL );

    argc = orig_argc;
    argv = orig_argv;
    pargs.argc = &argc;
    pargs.argv = &argv;
    pargs.flags=  1;  /* do not remove the args */
  next_pass:
    if( configname ) {
	configlineno = 0;
	configfp = fopen( configname, "r" );
	if( !configfp ) {
	    if( default_config ) {
		if( parse_debug )
		    log_info(_("NOTE: no default option file `%s'\n"),
							    configname );
	    }
	    else {
		log_error(_("option file `%s': %s\n"),
				    configname, strerror(errno) );
		g10_exit(2);
	    }
	    m_free(configname); configname = NULL;
	}
	if( parse_debug && configname )
	    log_info(_("reading options from `%s'\n"), configname );
	default_config = 0;
    }

    while( optfile_parse( configfp, configname, &configlineno,
						&pargs, opts) ) {
	switch( pargs.r_opt ) {
	  case aCheckKeys: set_cmd( &cmd, aCheckKeys); break;
	  case aListPackets: set_cmd( &cmd, aListPackets); break;
	  case aImport: set_cmd( &cmd, aImport); break;
	  case aFastImport: set_cmd( &cmd, aFastImport); break;
	  case aSendKeys: set_cmd( &cmd, aSendKeys); break;
	  case aRecvKeys: set_cmd( &cmd, aRecvKeys); break;
	  case aExport: set_cmd( &cmd, aExport); break;
	  case aExportAll: set_cmd( &cmd, aExportAll); break;
	  case aListKeys: set_cmd( &cmd, aListKeys); break;
	  case aListSigs: set_cmd( &cmd, aListSigs); break;
	  case aExportSecret: set_cmd( &cmd, aExportSecret); break;
	  case aExportSecretSub: set_cmd( &cmd, aExportSecretSub); break;
	  case aDeleteSecretKey: set_cmd( &cmd, aDeleteSecretKey);
							greeting=1; break;
	  case aDeleteKey: set_cmd( &cmd, aDeleteKey); greeting=1; break;

	  case aDetachedSign: detached_sig = 1; set_cmd( &cmd, aSign ); break;
	  case aSym: set_cmd( &cmd, aSym); break;

	  case aDecrypt: set_cmd( &cmd, aDecrypt); break;

	  case aEncr: set_cmd( &cmd, aEncr); break;
	  case aSign: set_cmd( &cmd, aSign );  break;
	  case aKeygen: set_cmd( &cmd, aKeygen); greeting=1; break;
	  case aSignKey: set_cmd( &cmd, aSignKey); break;
	  case aLSignKey: set_cmd( &cmd, aLSignKey); break;
	  case aStore: set_cmd( &cmd, aStore); break;
	  case aEditKey: set_cmd( &cmd, aEditKey); greeting=1; break;
	  case aClearsign: set_cmd( &cmd, aClearsign); break;
	  case aGenRevoke: set_cmd( &cmd, aGenRevoke); break;
	  case aVerify: set_cmd( &cmd, aVerify); break;
	  case aVerifyFiles: set_cmd( &cmd, aVerifyFiles); break;
	  case aPrimegen: set_cmd( &cmd, aPrimegen); break;
	  case aGenRandom: set_cmd( &cmd, aGenRandom); break;
	  case aPrintMD: set_cmd( &cmd, aPrintMD); break;
	  case aPrintMDs: set_cmd( &cmd, aPrintMDs); break;
	  case aListTrustDB: set_cmd( &cmd, aListTrustDB); break;
	  case aCheckTrustDB: set_cmd( &cmd, aCheckTrustDB); break;
	  case aUpdateTrustDB: set_cmd( &cmd, aUpdateTrustDB); break;
	  case aFixTrustDB: set_cmd( &cmd, aFixTrustDB); break;
	  case aListTrustPath: set_cmd( &cmd, aListTrustPath); break;
	  case aDeArmor: set_cmd( &cmd, aDeArmor); break;
	  case aEnArmor: set_cmd( &cmd, aEnArmor); break;
	  case aExportOwnerTrust: set_cmd( &cmd, aExportOwnerTrust); break;
	  case aImportOwnerTrust: set_cmd( &cmd, aImportOwnerTrust); break;

	  case oArmor: opt.armor = 1; opt.no_armor=0; break;
	  case oOutput: opt.outfile = pargs.r.ret_str; break;
	  case oQuiet: opt.quiet = 1; break;
	  case oNoTTY: tty_no_terminal(1); break;
	  case oDryRun: opt.dry_run = 1; break;
	  case oInteractive: opt.interactive = 1; break;
	  case oVerbose: g10_opt_verbose++;
		    opt.verbose++; opt.list_sigs=1; break;
	  case oKOption: set_cmd( &cmd, aKMode ); break;

	  case oBatch: opt.batch = 1; greeting = 0; break;
	  case oAnswerYes: opt.answer_yes = 1; break;
	  case oAnswerNo: opt.answer_no = 1; break;
	  case oKeyring: append_to_strlist( &nrings, pargs.r.ret_str); break;
	  case oDebug: opt.debug |= pargs.r.ret_ulong; break;
	  case oDebugAll: opt.debug = ~0; break;
	  case oStatusFD: set_status_fd( pargs.r.ret_int ); break;
	  case oLoggerFD: log_set_logfile( NULL, pargs.r.ret_int ); break;
	  case oWithFingerprint:
		with_fpr=1; /*fall thru*/
	  case oFingerprint: opt.fingerprint++; break;
	  case oSecretKeyring: append_to_strlist( &sec_nrings, pargs.r.ret_str); break;
	  case oOptions:
	    /* config files may not be nested (silently ignore them) */
	    if( !configfp ) {
		m_free(configname);
		configname = m_strdup(pargs.r.ret_str);
		goto next_pass;
	    }
	    break;
	  case oNoArmor: opt.no_armor=1; opt.armor=0; break;
	  case oNoDefKeyring: default_keyring = 0; break;
	  case oNoGreeting: nogreeting = 1; break;
	  case oNoVerbose: g10_opt_verbose = 0;
			   opt.verbose = 0; opt.list_sigs=0; break;
	  case oQuickRandom: quick_random_gen(1); break;
	  case oNoComment: opt.no_comment=1; break;
	  case oNoVersion: opt.no_version=1; break;
	  case oEmitVersion: opt.no_version=0; break;
	  case oCompletesNeeded: opt.completes_needed = pargs.r.ret_int; break;
	  case oMarginalsNeeded: opt.marginals_needed = pargs.r.ret_int; break;
	  case oMaxCertDepth: opt.max_cert_depth = pargs.r.ret_int; break;
	  case oTrustDBName: trustdb_name = pargs.r.ret_str; break;
	  case oDefaultKey: opt.def_secret_key = pargs.r.ret_str; break;
	  case oDefRecipient:
		    if( *pargs.r.ret_str )
			opt.def_recipient = make_username(pargs.r.ret_str);
		    break;
	  case oDefRecipientSelf:
		    m_free(opt.def_recipient); opt.def_recipient = NULL;
		    opt.def_recipient_self = 1;
		    break;
	  case oNoDefRecipient:
		    m_free(opt.def_recipient); opt.def_recipient = NULL;
		    opt.def_recipient_self = 0;
		    break;
	  case oNoOptions: break; /* no-options */
	  case oHomedir: opt.homedir = pargs.r.ret_str; break;
	  case oNoBatch: opt.batch = 0; break;
	  case oWithKeyData: opt.with_key_data=1; /* fall thru */
	  case oWithColons: opt.with_colons=':'; break;

	  case oSkipVerify: opt.skip_verify=1; break;
	  case oCompressAlgo: opt.def_compress_algo = pargs.r.ret_int; break;
	  case oCompressKeys: opt.compress_keys = 1; break;
	  case aListSecretKeys: set_cmd( &cmd, aListSecretKeys); break;
	  case oAlwaysTrust: opt.always_trust = 1; break;
	  case oLoadExtension:
	    register_cipher_extension(orig_argc? *orig_argv:NULL,
				      pargs.r.ret_str);
	    break;
	  case oRFC1991:
	    opt.rfc1991 = 1;
	    opt.rfc2440 = 0;
	    opt.no_comment = 1;
	    opt.escape_from = 1;
	    break;
	  case oOpenPGP:
	    opt.rfc1991 = 0;
	    opt.rfc2440 = 1;
	    opt.pgp2_workarounds = 0;
	    opt.escape_from = 0;
	    opt.force_v3_sigs = 0;
	    opt.compress_keys = 0;	    /* not mandated  but we do it */
	    opt.compress_sigs = 0;	    /* ditto. */
	    opt.not_dash_escaped = 0;
	    opt.def_cipher_algo = 0;
	    opt.def_digest_algo = 0;
	    opt.def_compress_algo = 1;
            opt.s2k_mode = 3; /* iterated+salted */
	    opt.s2k_digest_algo = DIGEST_ALGO_SHA1;
	    opt.s2k_cipher_algo = CIPHER_ALGO_CAST5;
	    break;
	  case oEmuChecksumBug: opt.emulate_bugs |= EMUBUG_GPGCHKSUM; break;
	  case oEmu3DESS2KBug:	opt.emulate_bugs |= EMUBUG_3DESS2K; break;
	  case oEmuMDEncodeBug: opt.emulate_bugs |= EMUBUG_MDENCODE; break;
	  case oCompressSigs: opt.compress_sigs = 1; break;
	  case oRunAsShmCP:
	  #ifndef USE_SHM_COPROCESSING
	    /* not possible in the option file,
	     * but we print the warning here anyway */
	    log_error("shared memory coprocessing is not available\n");
	  #endif
	    break;
	  case oSetFilename: opt.set_filename = pargs.r.ret_str; break;
	  case oSetPolicyURL: opt.set_policy_url = pargs.r.ret_str; break;
	  case oUseEmbeddedFilename: opt.use_embedded_filename = 1; break;
	  case oComment: opt.comment_string = pargs.r.ret_str; break;
	  case oDefaultComment: opt.comment_string = NULL; break;
	  case oThrowKeyid: opt.throw_keyid = 1; break;
	  case oForceV3Sigs: opt.force_v3_sigs = 1; break;
	  case oForceMDC: opt.force_mdc = 1; break;
	  case oS2KMode:   opt.s2k_mode = pargs.r.ret_int; break;
	  case oS2KDigest: s2k_digest_string = m_strdup(pargs.r.ret_str); break;
	  case oS2KCipher: s2k_cipher_string = m_strdup(pargs.r.ret_str); break;

	  case oNoEncryptTo: opt.no_encrypt_to = 1; break;
	  case oEncryptTo: /* store the recipient in the second list */
	    sl = add_to_strlist2( &remusr, pargs.r.ret_str, utf8_strings );
	    sl->flags = 1;
	    break;
	  case oRecipient: /* store the recipient */
	    add_to_strlist2( &remusr, pargs.r.ret_str, utf8_strings );
	    break;
	  case oTextmodeShort: opt.textmode = 2; break;
	  case oTextmode: opt.textmode=1;  break;
	  case oUser: /* store the local users */
	    add_to_strlist2( &locusr, pargs.r.ret_str, utf8_strings );
	    break;
	  case oCompress: opt.compress = pargs.r.ret_int; break;
	  case oPasswdFD: pwfd = pargs.r.ret_int; break;
	  case oCommandFD: opt.command_fd = pargs.r.ret_int; break;
	  case oCipherAlgo: def_cipher_string = m_strdup(pargs.r.ret_str); break;
	  case oDigestAlgo: def_digest_string = m_strdup(pargs.r.ret_str); break;
	  case oNoSecmemWarn: secmem_set_flags( secmem_get_flags() | 1 ); break;
	  case oCharset:
	    if( set_native_charset( pargs.r.ret_str ) )
		log_error(_("%s is not a valid character set\n"),
						    pargs.r.ret_str);
	    break;
	  case oNotDashEscaped: opt.not_dash_escaped = 1; break;
	  case oEscapeFrom: opt.escape_from = 1; break;
	  case oLockOnce: opt.lock_once = 1; break;
	  case oLockNever: disable_dotlock(); break;
	  case oLockMultiple: opt.lock_once = 0; break;
	  case oKeyServer: opt.keyserver_name = pargs.r.ret_str; break;
	  case oNotation: add_notation_data( pargs.r.ret_str ); break;
	  case oUtf8Strings: utf8_strings = 1; break;
	  case oNoUtf8Strings: utf8_strings = 0; break;
	  case oDisableCipherAlgo:
		disable_cipher_algo( string_to_cipher_algo(pargs.r.ret_str) );
		break;
	  case oDisablePubkeyAlgo:
		disable_pubkey_algo( string_to_pubkey_algo(pargs.r.ret_str) );
		break;
	  case oAllowNonSelfsignedUID: opt.allow_non_selfsigned_uid = 1; break;
	  case oAllowFreeformUID: opt.allow_freeform_uid = 1; break;
	  case oNoLiteral: opt.no_literal = 1; break;
	  case oSetFilesize: opt.set_filesize = pargs.r.ret_ulong; break;
	  case oHonorHttpProxy: opt.honor_http_proxy = 1; break;
	  case oFastListMode: opt.fast_list_mode = 1; break;
	  case oListOnly: opt.list_only=1; break;
	  case oIgnoreTimeConflict: opt.ignore_time_conflict = 1; break;
	  case oNoRandomSeedFile: use_random_seed = 0; break;
	  case oNoAutoKeyRetrieve: opt.auto_key_retrieve = 0; break;
	  case oShowSessionKey: opt.show_session_key = 1; break;
	  case oOverrideSessionKey:
		opt.override_session_key = pargs.r.ret_str;
		break;
	  case oMergeOnly: opt.merge_only = 1; break;
	  case oTryAllSecrets: opt.try_all_secrets = 1; break;
          case oTrustedKey: register_trusted_key( pargs.r.ret_str ); break;

	  default : pargs.err = configfp? 1:2; break;
	}
    }
    if( configfp ) {
	fclose( configfp );
	configfp = NULL;
	m_free(configname); configname = NULL;
	goto next_pass;
    }
    m_free( configname ); configname = NULL;
    if( log_get_errorcount(0) )
	g10_exit(2);
    if( nogreeting )
	greeting = 0;

    if( greeting ) {
	fprintf(stderr, "%s %s; %s\n",
			strusage(11), strusage(13), strusage(14) );
	fprintf(stderr, "%s\n", strusage(15) );
    }
  #ifdef IS_DEVELOPMENT_VERSION
    if( !opt.batch ) {
	log_info("NOTE: THIS IS A DEVELOPMENT VERSION!\n");
	log_info("It is only intended for test purposes and should NOT be\n");
	log_info("used in a production environment or with production keys!\n");
    }
  #endif

    if( may_coredump && !opt.quiet )
	log_info(_("WARNING: program may create a core file!\n"));


    if (opt.no_literal) {
	log_info(_("NOTE: %s is not for normal use!\n"), "--no-literal");
	if (opt.textmode)
	    log_error(_("%s not allowed with %s!\n"),
		       "--textmode", "--no-literal" );
	if (opt.set_filename)
	    log_error(_("%s makes no sense with %s!\n"),
			"--set-filename", "--no-literal" );
    }
    if (opt.set_filesize)
	log_info(_("NOTE: %s is not for normal use!\n"), "--set-filesize");
    if( opt.batch )
	tty_batchmode( 1 );

    secmem_set_flags( secmem_get_flags() & ~2 ); /* resume warnings */

    set_debug();
    g10_opt_homedir = opt.homedir;

    /* must do this after dropping setuid, because string_to...
     * may try to load an module */
    if( def_cipher_string ) {
	opt.def_cipher_algo = string_to_cipher_algo(def_cipher_string);
	m_free(def_cipher_string); def_cipher_string = NULL;
	if( check_cipher_algo(opt.def_cipher_algo) )
	    log_error(_("selected cipher algorithm is invalid\n"));
    }
    if( def_digest_string ) {
	opt.def_digest_algo = string_to_digest_algo(def_digest_string);
	m_free(def_digest_string); def_digest_string = NULL;
	if( check_digest_algo(opt.def_digest_algo) )
	    log_error(_("selected digest algorithm is invalid\n"));
    }
    if( s2k_cipher_string ) {
	opt.s2k_cipher_algo = string_to_cipher_algo(s2k_cipher_string);
	m_free(s2k_cipher_string); s2k_cipher_string = NULL;
	if( check_cipher_algo(opt.s2k_cipher_algo) )
	    log_error(_("selected cipher algorithm is invalid\n"));
    }
    if( s2k_digest_string ) {
	opt.s2k_digest_algo = string_to_digest_algo(s2k_digest_string);
	m_free(s2k_digest_string); s2k_digest_string = NULL;
	if( check_digest_algo(opt.s2k_digest_algo) )
	    log_error(_("selected digest algorithm is invalid\n"));
    }
    if( opt.set_policy_url ) {
	if( check_policy_url( opt.set_policy_url ) )
	    log_error(_("the given policy URL is invalid\n"));
    }
    if( opt.def_compress_algo < 1 || opt.def_compress_algo > 2 )
	log_error(_("compress algorithm must be in range %d..%d\n"), 1, 2);
    if( opt.completes_needed < 1 )
	log_error(_("completes-needed must be greater than 0\n"));
    if( opt.marginals_needed < 2 )
	log_error(_("marginals-needed must be greater than 1\n"));
    if( opt.max_cert_depth < 1 || opt.max_cert_depth > 255 )
	log_error(_("max-cert-depth must be in range 1 to 255\n"));
    switch( opt.s2k_mode ) {
      case 0:
	log_info(_("NOTE: simple S2K mode (0) is strongly discouraged\n"));
	break;
      case 1: case 3: break;
      default:
	log_error(_("invalid S2K mode; must be 0, 1 or 3\n"));
    }


    if( log_get_errorcount(0) )
	g10_exit(2);

    /* set the random seed file */
    if( use_random_seed ) {
	char *p = make_filename(opt.homedir, "random_seed", NULL );
	set_random_seed_file(p);
	m_free(p);
    }

    if( !cmd && opt.fingerprint && !with_fpr ) {
	set_cmd( &cmd, aListKeys);
    }

    if( cmd == aKMode || cmd == aKModeC ) { /* kludge to be compatible to pgp */
	if( cmd == aKModeC ) {
	    opt.fingerprint = 1;
	    cmd = aKMode;
	}
	opt.list_sigs = 0;
	if( opt.verbose > 2 )
	    opt.check_sigs++;
	if( opt.verbose > 1 )
	    opt.list_sigs++;

	opt.verbose = opt.verbose > 1;
	g10_opt_verbose = opt.verbose;
    }


    /* kludge to let -sat generate a clear text signature */
    if( opt.textmode == 2 && !detached_sig && opt.armor && cmd == aSign )
	cmd = aClearsign;

    if( opt.verbose > 1 )
	set_packet_list_mode(1);

    /* add the keyrings, but not for some special commands and
     * not in case of "-kvv userid keyring" */
    if( cmd != aDeArmor && cmd != aEnArmor
	&& !(cmd == aKMode && argc == 2 ) ) {

	if( !sec_nrings && default_keyring )  /* add default secret rings */
	    add_keyblock_resource("secring.gpg", 0, 1);
	for(sl = sec_nrings; sl; sl = sl->next )
	    add_keyblock_resource( sl->d, 0, 1 );
	if( !nrings && default_keyring )  /* add default ring */
	    add_keyblock_resource("pubring.gpg", 0, 0);
	for(sl = nrings; sl; sl = sl->next )
	    add_keyblock_resource( sl->d, 0, 0 );
    }
    FREE_STRLIST(nrings);
    FREE_STRLIST(sec_nrings);


    if( pwfd != -1 )  /* read the passphrase now. */
	read_passphrase_from_fd( pwfd );

    fname = argc? *argv : NULL;

    switch( cmd ) {
      case aPrimegen:
      case aPrintMD:
      case aPrintMDs:
      case aGenRandom:
      case aDeArmor:
      case aEnArmor:
      case aFixTrustDB:
	break;
      case aKMode:
      case aListKeys:
      case aListSecretKeys:
      case aCheckKeys:
	if( opt.with_colons ) /* need this to list the trust */
	    rc = setup_trustdb(1, trustdb_name );
	break;
      case aExportOwnerTrust: rc = setup_trustdb( 0, trustdb_name ); break;
      case aListTrustDB: rc = setup_trustdb( argc? 1:0, trustdb_name ); break;
      default: rc = setup_trustdb(1, trustdb_name ); break;
    }
    if( rc )
	log_error(_("failed to initialize the TrustDB: %s\n"), g10_errstr(rc));


    switch( cmd ) {
      case aStore: /* only store the file */
	if( argc > 1 )
	    wrong_args(_("--store [filename]"));
	if( (rc = encode_store(fname)) )
	    log_error_f( print_fname_stdin(fname),
			"store failed: %s\n", g10_errstr(rc) );
	break;
      case aSym: /* encrypt the given file only with the symmetric cipher */
	if( argc > 1 )
	    wrong_args(_("--symmetric [filename]"));
	if( (rc = encode_symmetric(fname)) )
	    log_error_f(print_fname_stdin(fname),
			"symmetric encryption failed: %s\n",g10_errstr(rc) );
	break;

      case aEncr: /* encrypt the given file */
	if( argc > 1 )
	    wrong_args(_("--encrypt [filename]"));
	if( (rc = encode_crypt(fname,remusr)) )
	    log_error("%s: encryption failed: %s\n", print_fname_stdin(fname), g10_errstr(rc) );
	break;

      case aSign: /* sign the given file */
	sl = NULL;
	if( detached_sig ) { /* sign all files */
	    for( ; argc; argc--, argv++ )
		add_to_strlist( &sl, *argv );
	}
	else {
	    if( argc > 1 )
		wrong_args(_("--sign [filename]"));
	    if( argc ) {
		sl = m_alloc_clear( sizeof *sl + strlen(fname));
		strcpy(sl->d, fname);
	    }
	}
	if( (rc = sign_file( sl, detached_sig, locusr, 0, NULL, NULL)) )
	    log_error("signing failed: %s\n", g10_errstr(rc) );
	free_strlist(sl);
	break;

      case aSignEncr: /* sign and encrypt the given file */
	if( argc > 1 )
	    wrong_args(_("--sign --encrypt [filename]"));
	if( argc ) {
	    sl = m_alloc_clear( sizeof *sl + strlen(fname));
	    strcpy(sl->d, fname);
	}
	else
	    sl = NULL;
	if( (rc = sign_file(sl, detached_sig, locusr, 1, remusr, NULL)) )
	    log_error("%s: sign+encrypt failed: %s\n", print_fname_stdin(fname), g10_errstr(rc) );
	free_strlist(sl);
	break;

      case aClearsign: /* make a clearsig */
	if( argc > 1 )
	    wrong_args(_("--clearsign [filename]"));
	if( (rc = clearsign_file(fname, locusr, NULL)) )
	    log_error("%s: clearsign failed: %s\n", print_fname_stdin(fname), g10_errstr(rc) );
	break;

      case aVerify:
	if( (rc = verify_signatures( argc, argv ) ))
	    log_error("verify signatures failed: %s\n", g10_errstr(rc) );
	break;

      case aVerifyFiles:
	if( (rc = verify_files( argc, argv ) ))
	    log_error("verify files failed: %s\n", g10_errstr(rc) );
	break;

      case aDecrypt:
	if( argc > 1 )
	    wrong_args(_("--decrypt [filename]"));
	if( (rc = decrypt_message( fname ) ))
	    log_error("decrypt_message failed: %s\n", g10_errstr(rc) );
	break;


      case aSignKey: /* sign the key given as argument */
	if( argc != 1 )
	    wrong_args(_("--sign-key user-id"));
	username = make_username( fname );
	keyedit_menu(fname, locusr, NULL, 1 );
	m_free(username);
	break;

      case aLSignKey:
	if( argc != 1 )
	    wrong_args(_("--lsign-key user-id"));
	username = make_username( fname );
	keyedit_menu(fname, locusr, NULL, 2 );
	m_free(username);
	break;

      case aEditKey: /* Edit a key signature */
	if( !argc )
	    wrong_args(_("--edit-key user-id [commands]"));
	username = make_username( fname );
	if( argc > 1 ) {
	    sl = NULL;
	    for( argc--, argv++ ; argc; argc--, argv++ )
		append_to_strlist( &sl, *argv );
	    keyedit_menu( username, locusr, sl, 0 );
	    free_strlist(sl);
	}
	else
	    keyedit_menu(username, locusr, NULL, 0 );
	m_free(username);
	break;

      case aDeleteSecretKey:
	if( argc != 1 )
	    wrong_args(_("--delete-secret-key user-id"));
      case aDeleteKey:
	if( argc != 1 )
	    wrong_args(_("--delete-key user-id"));
	username = make_username( fname );
	if( (rc = delete_key(username, cmd==aDeleteSecretKey)) )
	    log_error("%s: delete key failed: %s\n", username, g10_errstr(rc) );
	m_free(username);
	break;


      case aCheckKeys:
	opt.check_sigs = 1;
      case aListSigs:
	opt.list_sigs = 1;
      case aListKeys:
	sl = NULL;
	for( ; argc; argc--, argv++ )
	    add_to_strlist2( &sl, *argv, utf8_strings );
	public_key_list( sl );
	free_strlist(sl);
	break;
      case aListSecretKeys:
	sl = NULL;
	for( ; argc; argc--, argv++ )
	    add_to_strlist2( &sl, *argv, utf8_strings );
	secret_key_list( sl );
	free_strlist(sl);
	break;

      case aKMode: /* list keyring -- NOTE: This will be removed soon */
	if( argc < 2 ) { /* -kv [userid] */
	    sl = NULL;
	    if (argc && **argv)
		add_to_strlist2( &sl, *argv, utf8_strings );
	    public_key_list( sl );
	    free_strlist(sl);
	}
	else if( argc == 2 ) { /* -kv userid keyring */
	    if( access( argv[1], R_OK ) ) {
		log_error(_("can't open %s: %s\n"),
			       print_fname_stdin(argv[1]), strerror(errno));
	    }
	    else {
		/* add keyring (default keyrings are not registered in this
		 * special case */
		add_keyblock_resource( argv[1], 0, 0 );
		sl = NULL;
		if (**argv)
		    add_to_strlist2( &sl, *argv, utf8_strings );
		public_key_list( sl );
		free_strlist(sl);
	    }
	}
	else
	    wrong_args(_("-k[v][v][v][c] [user-id] [keyring]") );
	break;

      case aKeygen: /* generate a key */
	if( opt.batch ) {
	    if( argc > 1 )
		wrong_args("--gen-key [parameterfile]");
	    generate_keypair( argc? *argv : NULL );
	}
	else {
	    if( argc )
		wrong_args("--gen-key");
	    generate_keypair(NULL);
	}
	break;

      case aFastImport:
      case aImport:
	import_keys( argc? argv:NULL, argc, (cmd == aFastImport) );
	break;

      case aExport:
      case aExportAll:
      case aSendKeys:
      case aRecvKeys:
	sl = NULL;
	for( ; argc; argc--, argv++ )
	    add_to_strlist2( &sl, *argv, utf8_strings );
	if( cmd == aSendKeys )
	    hkp_export( sl );
	else if( cmd == aRecvKeys )
	    hkp_import( sl );
	else
	    export_pubkeys( sl, (cmd == aExport) );
	free_strlist(sl);
	break;

      case aExportSecret:
	sl = NULL;
	for( ; argc; argc--, argv++ )
	    add_to_strlist2( &sl, *argv, utf8_strings );
	export_seckeys( sl );
	free_strlist(sl);
	break;

      case aExportSecretSub:
	sl = NULL;
	for( ; argc; argc--, argv++ )
	    add_to_strlist2( &sl, *argv, utf8_strings );
	export_secsubkeys( sl );
	free_strlist(sl);
	break;

      case aGenRevoke:
	if( argc != 1 )
	    wrong_args("--gen-revoke user-id");
	username =  make_username(*argv);
	gen_revoke( username );
	m_free( username );
	break;

      case aDeArmor:
	if( argc > 1 )
	    wrong_args("--dearmor [file]");
	rc = dearmor_file( argc? *argv: NULL );
	if( rc )
	    log_error(_("dearmoring failed: %s\n"), g10_errstr(rc));
	break;

      case aEnArmor:
	if( argc > 1 )
	    wrong_args("--enarmor [file]");
	rc = enarmor_file( argc? *argv: NULL );
	if( rc )
	    log_error(_("enarmoring failed: %s\n"), g10_errstr(rc));
	break;


      case aPrimegen:
	{   int mode = argc < 2 ? 0 : atoi(*argv);

	    if( mode == 1 && argc == 2 ) {
		mpi_print( stdout, generate_public_prime( atoi(argv[1]) ), 1);
	    }
	    else if( mode == 2 && argc == 3 ) {
		mpi_print( stdout, generate_elg_prime(
					     0, atoi(argv[1]),
					     atoi(argv[2]), NULL,NULL ), 1);
	    }
	    else if( mode == 3 && argc == 3 ) {
		MPI *factors;
		mpi_print( stdout, generate_elg_prime(
					     1, atoi(argv[1]),
					     atoi(argv[2]), NULL,&factors ), 1);
		putchar('\n');
		mpi_print( stdout, factors[0], 1 ); /* print q */
	    }
	    else if( mode == 4 && argc == 3 ) {
		MPI g = mpi_alloc(1);
		mpi_print( stdout, generate_elg_prime(
						 0, atoi(argv[1]),
						 atoi(argv[2]), g, NULL ), 1);
		putchar('\n');
		mpi_print( stdout, g, 1 );
		mpi_free(g);
	    }
	    else
		wrong_args("--gen-prime mode bits [qbits] ");
	    putchar('\n');
	}
	break;

      case aGenRandom:
	{
	    int level = argc ? atoi(*argv):0;
	    int count = argc > 1 ? atoi(argv[1]): 0;
	    int endless = !count;

	    if( argc < 1 || argc > 2 || level < 0 || level > 2 || count < 0 )
		wrong_args("--gen-random 0|1|2 [count]");

	    while( endless || count ) {
		byte *p;
		size_t n = !endless && count < 100? count : 100;

		p = get_random_bits( n*8, level, 0);
	      #ifdef HAVE_DOSISH_SYSTEM
		setmode ( fileno(stdout), O_BINARY );
	      #endif
		fwrite( p, n, 1, stdout );
		m_free(p);
		if( !endless )
		    count -= n;
	    }
	}
	break;

      case aPrintMD:
	if( argc < 1)
	    wrong_args("--print-md algo [files]");
	{
	    int all_algos = (**argv=='*' && !(*argv)[1]);
	    int algo = all_algos? 0 : string_to_digest_algo(*argv);

	    if( !algo && !all_algos )
		log_error(_("invalid hash algorithm `%s'\n"), *argv );
	    else {
		argc--; argv++;
		if( !argc )
		    print_mds(NULL, algo);
		else {
		    for(; argc; argc--, argv++ )
			print_mds(*argv, algo);
		}
	    }
	}
	break;

      case aPrintMDs: /* old option */
	if( !argc )
	    print_mds(NULL,0);
	else {
	    for(; argc; argc--, argv++ )
		print_mds(*argv,0);
	}
	break;

      case aListTrustDB:
	if( !argc )
	    list_trustdb(NULL);
	else {
	    for( ; argc; argc--, argv++ )
		list_trustdb( *argv );
	}
	break;

      case aUpdateTrustDB:
	if( argc )
	    wrong_args("--update-trustdb");
	update_trustdb();
	break;

      case aCheckTrustDB:
	if( !argc )
	    check_trustdb(NULL);
	else {
	    for( ; argc; argc--, argv++ ) {
		username = make_username( *argv );
		check_trustdb( username );
		m_free(username);
	    }
	}
	break;

      case aFixTrustDB:
	log_error("this command is not yet implemented.\n");
	log_error("A workaround is to use \"--export-ownertrust\", remove\n");
	log_error("the trustdb file and do an \"--import-ownertrust\".\n" );
	break;

      case aListTrustPath:
	if( !argc )
	    wrong_args("--list-trust-path <user-ids>");
	for( ; argc; argc--, argv++ ) {
	    username = make_username( *argv );
	    list_trust_path( username );
	    m_free(username);
	}
	break;

      case aExportOwnerTrust:
	if( argc )
	    wrong_args("--export-ownertrust");
	export_ownertrust();
	break;

      case aImportOwnerTrust:
	if( argc > 1 )
	    wrong_args("--import-ownertrust [file]");
	import_ownertrust( argc? *argv:NULL );
	break;

      case aListPackets:
	opt.list_packets=1;
      default:
	if( argc > 1 )
	    wrong_args(_("[filename]"));
	/* Issue some output for the unix newbie */
	if( !fname && !opt.outfile && isatty( fileno(stdin) )
		&& isatty( fileno(stdout) ) && isatty( fileno(stderr) ) )
	    log_info(_("Go ahead and type your message ...\n"));

	if( !(a = iobuf_open(fname)) )
	    log_error(_("can't open `%s'\n"), print_fname_stdin(fname));
	else {

	    if( !opt.no_armor ) {
		if( use_armor_filter( a ) ) {
		    memset( &afx, 0, sizeof afx);
		    iobuf_push_filter( a, armor_filter, &afx );
		}
	    }
	    if( cmd == aListPackets ) {
		set_packet_list_mode(1);
		opt.list_packets=1;
	    }
	    rc = proc_packets(NULL, a );
	    if( rc )
		log_error("processing message failed: %s\n", g10_errstr(rc) );
	    iobuf_close(a);
	}
	break;
    }

    /* cleanup */
    FREE_STRLIST(remusr);
    FREE_STRLIST(locusr);
    g10_exit(0);
    return 8; /*NEVER REACHED*/
}


void
g10_exit( int rc )
{
    update_random_seed_file();
    if( opt.debug & DBG_MEMSTAT_VALUE ) {
	m_print_stats("on exit");
	random_dump_stats();
    }
    if( opt.debug )
	secmem_dump_stats();
    secmem_term();
    rc = rc? rc : log_get_errorcount(0)? 2 :
			g10_errors_seen? 1 : 0;
    /*write_status( STATUS_LEAVE );*/
    exit(rc );
}




static void
print_hex( byte *p, size_t n )
{
    int i;

    if( n == 20 ) {
	for(i=0; i < n ; i++, i++, p += 2 ) {
	    if( i )
		putchar(' ');
	    if( i == 10 )
		putchar(' ');
	    printf("%02X%02X", *p, p[1] );
	}
    }
    else if( n == 24 ) {
	for(i=0; i < n ; i += 4, p += 4 ) {
	    if( i )
		putchar(' ');
	    if( i == 12 )
		putchar(' ');
	    printf("%02X%02X%02X%02X", *p, p[1], p[2], p[3] );
	}
    }
    else {
	for(i=0; i < n ; i++, p++ ) {
	    if( i )
		putchar(' ');
	    if( i && !(i%8) )
		putchar(' ');
	    printf("%02X", *p );
	}
    }
}

static void
print_hashline( MD_HANDLE md, int algo, const char *fname )
{
    int i, n;
    const byte *p;
    
    if ( fname ) {
        for (p = fname; *p; p++ ) {
            if ( *p <= 32 || *p > 127 || *p == ':' || *p == '%' )
                printf("%%%02X", *p );
            else 
                putchar( *p );
        }
    }
    putchar(':');
    printf("%d:", algo );
    p = md_read( md, algo );
    n = md_digest_length(algo);
    for(i=0; i < n ; i++, p++ ) 
        printf("%02X", *p );
    putchar(':');
    putchar('\n');
}

static void
print_mds( const char *fname, int algo )
{
    FILE *fp;
    char buf[1024];
    size_t n;
    MD_HANDLE md;
    char *pname;

    if( !fname ) {
	fp = stdin;
      #ifdef HAVE_DOSISH_SYSTEM
	setmode ( fileno(fp) , O_BINARY );
      #endif
	pname = m_strdup("[stdin]: ");
    }
    else {
	pname = m_alloc(strlen(fname)+3);
	strcpy(stpcpy(pname,fname),": ");
	fp = fopen( fname, "rb" );
    }
    if( !fp ) {
	log_error("%s%s\n", pname, strerror(errno) );
	m_free(pname);
	return;
    }

    md = md_open( 0, 0 );
    if( algo )
	md_enable( md, algo );
    else {
	md_enable( md, DIGEST_ALGO_MD5 );
	md_enable( md, DIGEST_ALGO_SHA1 );
	md_enable( md, DIGEST_ALGO_RMD160 );
	if( !check_digest_algo(DIGEST_ALGO_TIGER) )
	    md_enable( md, DIGEST_ALGO_TIGER );
    }

    while( (n=fread( buf, 1, DIM(buf), fp )) )
	md_write( md, buf, n );
    if( ferror(fp) )
	log_error("%s%s\n", pname, strerror(errno) );
    else {
	md_final(md);
        if ( opt.with_colons ) {
            if ( algo ) 
                print_hashline( md, algo, fname );
            else {
                print_hashline( md, DIGEST_ALGO_MD5, fname );
                print_hashline( md, DIGEST_ALGO_SHA1, fname );
                print_hashline( md, DIGEST_ALGO_RMD160, fname );
                if( !check_digest_algo(DIGEST_ALGO_TIGER) ) 
                    print_hashline( md, DIGEST_ALGO_TIGER, fname );
            }
        }
        else {
            if( algo ) {
                if( fname )
                    fputs( pname, stdout );
                print_hex(md_read(md, algo), md_digest_length(algo) );
            }
            else {
                printf(  "%s   MD5 = ", fname?pname:"" );
                print_hex(md_read(md, DIGEST_ALGO_MD5), 16 );
                printf("\n%s  SHA1 = ", fname?pname:""  );
                print_hex(md_read(md, DIGEST_ALGO_SHA1), 20 );
                printf("\n%sRMD160 = ", fname?pname:""  );
                print_hex(md_read(md, DIGEST_ALGO_RMD160), 20 );
                if( !check_digest_algo(DIGEST_ALGO_TIGER) ) {
                    printf("\n%s TIGER = ", fname?pname:""  );
                    print_hex(md_read(md, DIGEST_ALGO_TIGER), 24 );
                }
            }
            putchar('\n');
        }
    }
    md_close(md);

    if( fp != stdin )
	fclose(fp);
}


/****************
 * Check the supplied name,value string and add it to the notation
 * data to be used for signatures.
 */
static void
add_notation_data( const char *string )
{
    const char *s;
    const char *s2;
    STRLIST sl;
    int critical=0;
    int highbit=0;

    if( *string == '!' ) {
	critical = 1;
	string++;
    }
    s = string;

    if( !*s || (*s & 0x80) || (!isalpha(*s) && *s != '_') ) {
	log_error(_("the first character of a notation name "
		    "must be a letter or an underscore\n") );
	return;
    }
    for(s++; *s != '='; s++ ) {
	if( !*s || (*s & 0x80) || (!isalnum(*s) && *s != '_' && *s != '.' ) ) {
	    log_error(_("a notation name must have only letters, "
			"digits, dots or underscores and end with an '='\n") );
	    return;
	}
    }
    if( s[-1] == '.' || ((s2=strstr(string, "..")) && s2 < s ) ) {
	log_error(_("dots in a notation name must be surrounded "
		    "by other characters\n") );
	return;
    }
    /* we do only support printabe text - therefore we enforce the use
     * of only printable characters (an empty value is valid) */
    for( s++; *s ; s++ ) {
	if( iscntrl(*s) ) {
	    log_error(_("a notation value must not use "
			"any control characters\n") );
	    return;
	}
	else if( *s & 0x80 )
	    highbit = 1;
    }

    if( highbit )   /* must use UTF8 encoding */
	sl = add_to_strlist2( &opt.notation_data, string, utf8_strings );
    else
	sl = add_to_strlist( &opt.notation_data, string );

    if( critical )
	sl->flags |= 1;
}


static int
check_policy_url( const char *s )
{
    if( *s == '!' )
	s++;
    if( !*s )
	return -1;
    for(; *s ; s++ ) {
	if( (*s & 0x80) || iscntrl(*s) )
	    return -1;
    }
    return 0;
}

