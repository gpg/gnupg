/* g10.c - The GNUPG utility (main for gpg)
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
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>


#include "packet.h"
#include "iobuf.h"
#include "memory.h"
#include "util.h"
#include "main.h"
#include "options.h"
#include "keydb.h"
#include "mpi.h"
#include "cipher.h"
#include "filter.h"
#include "trustdb.h"
#include "ttyio.h"
#include "i18n.h"
#include "status.h"

#ifndef IS_G10MAINT
  #define IS_G10 1
#endif


static ARGPARSE_OPTS opts[] = {

    { 300, NULL, 0, N_("@Commands:\n ") },

  #ifdef IS_G10
    { 's', "sign",      0, N_("|[file]|make a signature")},
    { 539, "clearsign", 0, N_("|[file]|make a clear text signature") },
    { 'b', "detach-sign", 0, N_("make a detached signature")},
    { 'e', "encrypt",   0, N_("encrypt data")},
    { 'c', "symmetric", 0, N_("encryption only with symmetric cipher")},
    { 507, "store",     0, N_("store only")},
    { 'd', "decrypt",   0, N_("decrypt data (default)")},
    { 550, "verify"   , 0, N_("verify a signature")},
  #endif
    { 551, "list-keys", 0, N_("list keys")},
    { 552, "list-sigs", 0, N_("list keys and signatures")},
    { 508, "check-sigs",0, N_("check key signatures")},
    { 515, "fingerprint", 0, N_("list keys and fingerprints")},
    { 558, "list-secret-keys", 0, N_("list secret keys")},
  #ifdef IS_G10
    { 503, "gen-key",   0, N_("generate a new key pair")},
    { 554, "add-key",   0, N_("add a subkey to a key pair")},
    { 506, "sign-key"  ,0, N_("make a signature on a key in the keyring")},
    { 505, "delete-key",0, N_("remove key from the public keyring")},
    { 524, "edit-key"  ,0, N_("edit a key signature")},
    { 525, "change-passphrase", 0, N_("change the passphrase of your secret keyring")},
    { 542, "gen-revoke",0, N_("generate a revocation certificate")},
  #endif
    { 537, "export"          , 0, N_("export keys") },
    { 530, "import",      0     , N_("import/merge keys")},
    { 521, "list-packets",0,N_("list only the sequence of packets")},
  #ifdef IS_G10MAINT
    { 546, "dearmor", 0, N_("De-Armor a file or stdin") },
    { 547, "enarmor", 0, N_("En-Armor a file or stdin") },
    { 555, "print-md" , 0, N_("|algo [files]|print message digests")},
    { 516, "print-mds" , 0, N_("print all message digests")},
    { 513, "gen-prime" , 0, "@" },
    { 548, "gen-random" , 0, "@" },
  #endif

    { 301, NULL, 0, N_("@\nOptions:\n ") },

    { 'a', "armor",     0, N_("create ascii armored output")},
  #ifdef IS_G10
    { 'u', "local-user",2, N_("use this user-id to sign or decrypt")},
    { 'r', "remote-user", 2, N_("use this user-id for encryption")},
    { 'z', NULL,        1, N_("|N|set compress level N (0 disables)") },
    { 't', "textmode",  0, N_("use canonical text mode")},
  #endif
    { 'o', "output",    2, N_("use as output file")},
    { 'v', "verbose",   0, N_("verbose") },
    { 'n', "dry-run",   0, N_("do not make any changes") },
    { 500, "batch",     0, N_("batch mode: never ask")},
    { 501, "yes",       0, N_("assume yes on most questions")},
    { 502, "no",        0, N_("assume no on most questions")},
    { 509, "keyring"   ,2, N_("add this keyring to the list of keyrings")},
    { 517, "secret-keyring" ,2, N_("add this secret keyring to the list")},
    { 518, "options"   , 2, N_("read options from file")},

    { 510, "debug"     ,4|16, N_("set debugging flags")},
    { 511, "debug-all" ,0, N_("enable full debugging")},
    { 512, "status-fd" ,1, N_("|FD|write status info to this FD") },
    { 534, "no-comment", 0,   N_("do not write comment packets")},
    { 535, "completes-needed", 1, N_("(default is 1)")},
    { 536, "marginals-needed", 1, N_("(default is 3)")},
    { 560, "load-extension" ,2, N_("|file|load extension module")},
    { 561, "rfc1991",   0, N_("emulate the mode described in RFC1991")},
  #ifdef IS_G10
    { 527, "cipher-algo", 2 , N_("|NAME|use cipher algorithm NAME")},
    { 528, "pubkey-algo", 2 , N_("|NAME|use public key algorithm NAME")},
    { 529, "digest-algo", 2 , N_("|NAME|use message digest algorithm NAME")},
    { 556, "compress-algo", 1 , N_("|N|use compress algorithm N")},
  #else /* some dummies */
    { 527, "cipher-algo", 2 , "@"},
    { 528, "pubkey-algo", 2 , "@"},
    { 529, "digest-algo", 2 , "@"},
    { 556, "compress-algo", 1 , "@"},
  #endif

  #ifdef IS_G10
    { 302, NULL, 0, N_("@\nExamples:\n\n"
    " -se -r Bob [file]          sign and encrypt for user Bob\n"
    " -sat [file]                make a clear text signature\n"
    " -sb  [file]                make a detached signature\n"
    " -k   [userid]              show keys\n"
    " -kc  [userid]              show fingerprint\n"  ) },
  #endif

  /* hidden options */
  #ifdef IS_G10MAINT
    { 514, "test"      , 0, "@" },
    { 531, "list-trustdb",0 , "@"},
    { 533, "list-trust-path",0, "@"},
  #endif
  #ifdef IS_G10
    { 'k', NULL,        0, "@"},
    { 504, "delete-secret-key",0, "@" },
    { 524, "edit-sig"  ,0, "@"}, /* alias for edit-key */
    { 523, "passphrase-fd",1, "@" },
  #endif
    { 532, "quick-random", 0, "@"},
    { 526, "no-verbose", 0, "@"},
    { 538, "trustdb-name", 2, "@" },
    { 540, "no-secmem-warning", 0, "@" }, /* used only by regression tests */
    { 519, "no-armor",   0, "@"},
    { 520, "no-default-keyring", 0, "@" },
    { 522, "no-greeting", 0, "@" },
    { 541, "no-operation", 0, "@" },      /* used by regression tests */
    { 543, "no-options", 0, "@" }, /* shortcut for --options /dev/null */
    { 544, "homedir", 2, "@" },   /* defaults to "~/.gnupg" */
    { 545, "no-batch", 0, "@" },
    { 549, "with-colons", 0, "@"},
    { 551, "list-key", 0, "@" }, /* alias */
    { 552, "list-sig", 0, "@" }, /* alias */
    { 508, "check-sig",0, "@" }, /* alias */
    { 553, "skip-verify",0, "@" },
    { 557, "compress-keys",0, "@"},
    { 559, "always-trust", 0, "@"},

{0} };




enum cmd_values { aNull = 0,
    aSym, aStore, aEncr, aKeygen, aSign, aSignEncr,
    aSignKey, aClearsign, aListPackets, aEditSig, aDeleteKey, aDeleteSecretKey,
    aKMode, aKModeC, aChangePass, aImport, aVerify, aDecrypt, aListKeys,
    aListSigs, aKeyadd, aListSecretKeys,
    aExport, aCheckKeys, aGenRevoke, aPrimegen, aPrintMD, aPrintMDs,
    aListTrustDB, aListTrustPath, aDeArmor, aEnArmor, aGenRandom, aTest,
aNOP };


static char *build_list( const char *text,
			 const char *(*mapf)(int), int (*chkf)(int) );
static void set_cmd( enum cmd_values *ret_cmd,
			enum cmd_values new_cmd );
#ifdef IS_G10MAINT
static void print_hex( byte *p, size_t n );
static void print_mds( const char *fname, int algo );
static void do_test(int);
#endif

const char *
strusage( int level )
{
  static char *digests, *pubkeys, *ciphers;
    const char *p;
    switch( level ) {
      case 11: p =
	  #ifdef IS_G10MAINT
	    "gpgm (GNUPG)";
	  #else
	    "gpg (GNUPG)";
	  #endif
	break;
      case 13: p = VERSION; break;
      case 17: p = PRINTABLE_OS_NAME; break;
      case 19: p =
	    _("Please report bugs to <gnupg-bugs@gnu.org>.\n");
	break;
      case 1:
      case 40:	p =
	  #ifdef IS_G10MAINT
	    _("Usage: gpgm [options] [files] (-h for help)");
	  #else
	    _("Usage: gpg [options] [files] (-h for help)");
	  #endif
	break;
      case 41:	p =
	  #ifdef IS_G10MAINT
	    _("Syntax: gpgm [options] [files]\n"
	      "GNUPG maintenance utility\n");
	  #else
	    _("Syntax: gpg [options] [files]\n"
	      "sign, check, encrypt or decrypt\n"
	      "default operation depends on the input data\n");
	  #endif
	break;

      case 31: p = "\n"; break;
      case 32:
	if( !ciphers )
	    ciphers = build_list("Supported ciphers: ", cipher_algo_to_string,
							check_cipher_algo );
	p = ciphers;
	break;
      case 33:
	if( !pubkeys )
	    pubkeys = build_list("Supported pubkeys: ", pubkey_algo_to_string,
							check_pubkey_algo );
	p = pubkeys;
	break;
      case 34:
	if( !digests )
	    digests = build_list("Supported digests: ", digest_algo_to_string,
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
  #ifdef ENABLE_NLS
    #ifdef HAVE_LC_MESSAGES
       setlocale( LC_MESSAGES, "" );
    #else
       setlocale( LC_ALL, "" );
    #endif
    bindtextdomain( PACKAGE, G10_LOCALEDIR );
    textdomain( PACKAGE );
  #endif
}

static void
wrong_args( const char *text)
{
  #ifdef IS_G10MAINT
    fputs(_("usage: gpgm [options] "),stderr);
  #else
    fputs(_("usage: gpg [options] "),stderr);
  #endif
    fputs(text,stderr);
    putc('\n',stderr);
    g10_exit(2);
}

static void
set_debug(void)
{
    volatile char *p = g10_malloc(1);
    volatile MPI a = g10m_new(1);
    *p = g10c_get_random_byte( 0 );


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
set_cmd( enum cmd_values *ret_cmd, enum cmd_values new_cmd )
{
    enum cmd_values cmd = *ret_cmd;

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



static void
check_opts(void)
{
    if( !opt.def_cipher_algo || check_cipher_algo(opt.def_cipher_algo) )
	log_error(_("selected cipher algorithm is invalid\n"));
    if( !opt.def_pubkey_algo || check_pubkey_algo(opt.def_pubkey_algo) )
	log_error(_("selected pubkey algorithm is invalid\n"));
    if( opt.def_digest_algo && check_digest_algo(opt.def_digest_algo) )
	log_error(_("selected digest algorithm is invalid\n"));
    if( opt.def_compress_algo < 1 || opt.def_compress_algo > 2 )
	log_error(_("compress algorithm must be in range %d..%d\n"), 1, 2);
    if( opt.completes_needed < 1 )
	log_error(_("completes-needed must be greater than 0\n"));
    if( opt.marginals_needed < 2 )
	log_error(_("marginals-needed must be greater than 1\n"));
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
    STRLIST sl, remusr= NULL, locusr=NULL;
    int nrings=0, sec_nrings=0;
    armor_filter_context_t afx;
    int detached_sig = 0;
    FILE *configfp = NULL;
    char *configname = NULL;
    unsigned configlineno;
    int parse_debug = 0;
    int default_config =1;
    int errors=0;
    int default_keyring = 1;
    int greeting = 1;
    enum cmd_values cmd = 0;
    const char *trustdb_name = NULL;

    trap_unaligned();
  #ifdef IS_G10MAINT
    secmem_init( 0 );	   /* disable use of secmem */
    log_set_name("gpgm");
  #else
    /* Please note that we may running SUID(ROOT), so be very CAREFUL
     * when adding any stuff between here and the call to
     * secmem_init()  somewhere after the option parsing
     */
    log_set_name("gpg");
    secure_random_alloc(); /* put random number into secure memory */
    init_signals();
  #endif
    i18n_init();
    opt.compress = -1; /* defaults to standard compress level */
    /* fixme: set the next two to zero and decide where used */
    opt.def_cipher_algo = DEFAULT_CIPHER_ALGO;
    opt.def_pubkey_algo = DEFAULT_PUBKEY_ALGO;
    opt.def_digest_algo = 0;
    opt.def_compress_algo = 2;
    opt.completes_needed = 1;
    opt.marginals_needed = 3;
    opt.homedir = getenv("GNUPGHOME");
    if( !opt.homedir || !*opt.homedir ) {
      #ifdef __MINGW32__
	opt.homedir = "c:/gnupg";
      #else
	opt.homedir = "~/.gnupg";
      #endif
    }

    /* check whether we have a config file on the commandline */
    orig_argc = argc;
    orig_argv = argv;
    pargs.argc = &argc;
    pargs.argv = &argv;
    pargs.flags= 1|(1<<6);  /* do not remove the args, ignore version */
    while( arg_parse( &pargs, opts) ) {
	if( pargs.r_opt == 510 || pargs.r_opt == 511 )
	    parse_debug++;
	else if( pargs.r_opt == 518 ) {
	    /* yes there is one, so we do not try the default one, but
	     * read the option file when it is encountered at the commandline
	     */
	    default_config = 0;
	}
	else if( pargs.r_opt == 543 )
	    default_config = 0; /* --no-options */
	else if( pargs.r_opt == 544 )
	    opt.homedir = pargs.r.ret_str;
    }

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
		    log_info(_("note: no default option file '%s'\n"),
							    configname );
	    }
	    else {
		log_error(_("option file '%s': %s\n"),
				    configname, strerror(errno) );
		g10_exit(1);
	    }
	    m_free(configname); configname = NULL;
	}
	if( parse_debug && configname )
	    log_info(_("reading options from '%s'\n"), configname );
	default_config = 0;
    }

    while( optfile_parse( configfp, configname, &configlineno,
						&pargs, opts) ) {
	switch( pargs.r_opt ) {

	  case 'a': opt.armor = 1; opt.no_armor=0; break;
	#ifdef IS_G10
	  case 'b': detached_sig = 1; set_cmd( &cmd, aSign ); break;
	  case 'c': set_cmd( &cmd, aSym); break;
	  case 'd': set_cmd( &cmd, aDecrypt); break;
	  case 'e': set_cmd( &cmd, aEncr); break;
	  case 'r': /* store the remote users */
	    sl = m_alloc( sizeof *sl + strlen(pargs.r.ret_str));
	    strcpy(sl->d, pargs.r.ret_str);
	    sl->next = remusr;
	    remusr = sl;
	    break;
	  case 's': set_cmd( &cmd, aSign );  break;
	  case 't': opt.textmode=1;  break;
	  case 'u': /* store the local users */
	    sl = m_alloc( sizeof *sl + strlen(pargs.r.ret_str));
	    strcpy(sl->d, pargs.r.ret_str);
	    sl->next = locusr;
	    locusr = sl;
	    break;
	  case 'z': opt.compress = pargs.r.ret_int; break;
	  case 503: set_cmd( &cmd, aKeygen); break;
	  case 504: set_cmd( &cmd, aDeleteSecretKey); break;
	  case 505: set_cmd( &cmd, aDeleteKey); break;
	  case 506: set_cmd( &cmd, aSignKey); break;
	  case 507: set_cmd( &cmd, aStore); break;
	  case 523: set_passphrase_fd( pargs.r.ret_int ); break;
	  case 524: set_cmd( &cmd, aEditSig); break;
	  case 525: set_cmd( &cmd, aChangePass); break;
	  case 527:
	    opt.def_cipher_algo = string_to_cipher_algo(pargs.r.ret_str);
	    break;
	  case 528:
	    opt.def_pubkey_algo = string_to_pubkey_algo(pargs.r.ret_str);
	    break;
	  case 529:
	    opt.def_digest_algo = string_to_digest_algo(pargs.r.ret_str);
	    break;
	  case 539: set_cmd( &cmd, aClearsign); break;
	  case 540: secmem_set_flags( secmem_get_flags() | 1 ); break;
	  case 542: set_cmd( &cmd, aGenRevoke); break;
	  case 550: set_cmd( &cmd, aVerify); break;
	#else
	  case 527:
	  case 528:
	  case 529:
	    break;
	#endif /* !IS_G10 */

	#ifdef IS_G10MAINT
	  case 513: set_cmd( &cmd, aPrimegen); break;
	  case 514: set_cmd( &cmd, aTest); break;
	  case 516: set_cmd( &cmd, aPrintMDs); break;
	  case 531: set_cmd( &cmd, aListTrustDB); break;
	  case 533: set_cmd( &cmd, aListTrustPath); break;
	  case 540: break; /* dummy */
	  case 546: set_cmd( &cmd, aDeArmor); break;
	  case 547: set_cmd( &cmd, aEnArmor); break;
	  case 548: set_cmd( &cmd, aGenRandom); break;
	  case 555: set_cmd( &cmd, aPrintMD); break;
	#endif /* IS_G10MAINT */

	  case 'o': opt.outfile = pargs.r.ret_str; break;
	  case 'v': g10_opt_verbose++;
		    opt.verbose++; opt.list_sigs=1; break;
	  case 'k': set_cmd( &cmd, aKMode ); break;

	  case 500: opt.batch = 1; greeting = 0; break;
	  case 501: opt.answer_yes = 1; break;
	  case 502: opt.answer_no = 1; break;
	  case 508: set_cmd( &cmd, aCheckKeys); break;
	  case 509: add_keyring(pargs.r.ret_str); nrings++; break;
	  case 510: opt.debug |= pargs.r.ret_ulong; break;
	  case 511: opt.debug = ~0; break;
	  case 512: set_status_fd( pargs.r.ret_int ); break;
	  case 515: opt.fingerprint = 1; break;
	  case 517: add_secret_keyring(pargs.r.ret_str); sec_nrings++; break;
	  case 518:
	    /* config files may not be nested (silently ignore them) */
	    if( !configfp ) {
		m_free(configname);
		configname = m_strdup(pargs.r.ret_str);
		goto next_pass;
	    }
	    break;
	  case 519: opt.no_armor=1; opt.armor=0; break;
	  case 520: default_keyring = 0; break;
	  case 521: set_cmd( &cmd, aListPackets); break;
	  case 522: greeting = 0; break;
	  case 526: g10_opt_verbose = 0;
		    opt.verbose = 0; opt.list_sigs=0; break;
	  case 530: set_cmd( &cmd, aImport); break;
	  case 532: quick_random_gen(1); break;
	  case 534: opt.no_comment=1; break;
	  case 535: opt.completes_needed = pargs.r.ret_int; break;
	  case 536: opt.marginals_needed = pargs.r.ret_int; break;
	  case 537: set_cmd( &cmd, aExport); break;
	  case 538: trustdb_name = pargs.r.ret_str; break;
	  case 541: set_cmd( &cmd, aNOP); break;
	  case 543: break; /* no-options */
	  case 544: opt.homedir = pargs.r.ret_str; break;
	  case 545: opt.batch = 0; break;
	  case 549: opt.with_colons=':'; break;
	  case 551: set_cmd( &cmd, aListKeys); break;
	  case 552: set_cmd( &cmd, aListSigs); break;
	  case 553: opt.skip_verify=1; break;
	  case 554: set_cmd( &cmd, aKeyadd); break;
	  case 556: opt.def_compress_algo = pargs.r.ret_int; break;
	  case 557: opt.compress_keys = 1; break;
	  case 558: set_cmd( &cmd, aListSecretKeys); break;
	  case 559: opt.always_trust = 1; break;
	  case 560: register_cipher_extension(pargs.r.ret_str); break;
	  case 561: opt.rfc1991 = 1; break;
	  default : errors++; pargs.err = configfp? 1:2; break;
	}
    }
    if( configfp ) {
	fclose( configfp );
	configfp = NULL;
	m_free(configname); configname = NULL;
	goto next_pass;
    }
    m_free( configname ); configname = NULL;
    check_opts();
    if( log_get_errorcount(0) )
	g10_exit(2);

    if( greeting ) {
	tty_printf("%s %s; %s\n", strusage(11), strusage(13), strusage(14) );
	tty_printf("%s\n", strusage(15) );
    }

  #ifdef IS_G10
    /* initialize the secure memory. */
    secmem_init( 16384 );
    /* Okay, we are now working under our real uid */
  #endif

    /*write_status( STATUS_ENTER );*/

    set_debug();
    if( !cmd && opt.fingerprint )
	set_cmd( &cmd, aListKeys);

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
    if( opt.textmode && !detached_sig && opt.armor && cmd == aSign )
	cmd = aClearsign;

    if( opt.verbose > 1 )
	set_packet_list_mode(1);

    /* add the keyrings, but not for some special commands and
     * not in case of "-kvv userid keyring" */
    if( cmd != aDeArmor && cmd != aEnArmor
	&& !(cmd == aKMode && argc == 2 ) ) {
	if( !sec_nrings || default_keyring )  /* add default secret rings */
	    add_secret_keyring("secring.gpg");
	if( !nrings || default_keyring )  /* add default ring */
	    add_keyring("pubring.gpg");
    }

    if( argc )
	fname = *argv;
    else {
	fname = NULL;
	if( get_passphrase_fd() == 0 ) {
	    /* reading data and passphrase from stdin:
	     * we assume the first line is the passphrase, so
	     * we should read it now.
	     *
	     * We should do it here, but for now it is not needed.
	     * Anyway, this password scheme is not quite good
	     */
	}
    }

    switch( cmd ) {
      case aPrimegen:
      case aPrintMD:
      case aPrintMDs:
      case aGenRandom:
      case aDeArmor:
      case aEnArmor:
	break;
      case aKMode:
      case aListKeys:
      case aListSecretKeys:
      case aCheckKeys:
	if( opt.with_colons ) /* need this to list the trust */
	    rc = init_trustdb(1, trustdb_name );
	break;
      case aListTrustDB: rc = init_trustdb( argc? 1:0, trustdb_name ); break;
      default: rc = init_trustdb(1, trustdb_name ); break;
    }
    if( rc )
	log_error(_("failed to initialize the TrustDB: %s\n"), g10_errstr(rc));


    switch( cmd ) {
      case aStore: /* only store the file */
	if( argc > 1 )
	    wrong_args(_("--store [filename]"));
	if( (rc = encode_store(fname)) )
	    log_error("%s: store failed: %s\n",
				 print_fname_stdin(fname), g10_errstr(rc) );
	break;
    #ifdef IS_G10
      case aSym: /* encrypt the given file only with the symmetric cipher */
	if( argc > 1 )
	    wrong_args(_("--symmetric [filename]"));
	if( (rc = encode_symmetric(fname)) )
	    log_error("%s: symmetric encryption failed: %s\n",
			    print_fname_stdin(fname), g10_errstr(rc) );
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

      case aDecrypt:
	if( argc > 1 )
	    wrong_args(_("--decrypt [filename]"));
	if( (rc = decrypt_message( fname ) ))
	    log_error("decrypt_message failed: %s\n", g10_errstr(rc) );
	break;


      case aSignKey: /* sign the key given as argument */
	if( argc != 1 )
	    wrong_args(_("--sign-key username"));
	/* note: fname is the user id! */
	if( (rc = sign_key(fname, locusr)) )
	    log_error("%s: sign key failed: %s\n", print_fname_stdin(fname), g10_errstr(rc) );
	break;

      case aEditSig: /* Edit a key signature */
	if( argc != 1 )
	    wrong_args(_("--edit-sig username"));
	/* note: fname is the user id! */
	if( (rc = edit_keysigs(fname)) )
	    log_error("%s: edit signature failed: %s\n", print_fname_stdin(fname), g10_errstr(rc) );
	break;

      case aDeleteSecretKey:
	if( argc != 1 )
	    wrong_args(_("--delete-secret-key username"));
      case aDeleteKey:
	if( argc != 1 )
	    wrong_args(_("--delete-key username"));
	/* note: fname is the user id! */
	if( (rc = delete_key(fname, cmd==aDeleteSecretKey)) )
	    log_error("%s: delete key failed: %s\n", print_fname_stdin(fname), g10_errstr(rc) );
	break;

      case aChangePass: /* Change the passphrase */
	if( argc > 1 ) /* no arg: use default, 1 arg use this one */
	    wrong_args(_("--change-passphrase [username]"));
	/* note: fname is the user id! */
	if( (rc = change_passphrase(fname)) )
	    log_error("%s: change passphrase failed: %s\n", print_fname_stdin(fname),
						       g10_errstr(rc) );
	break;
      #endif /* IS_G10 */

      case aCheckKeys:
	opt.check_sigs = 1;
      case aListSigs:
	opt.list_sigs = 1;
      case aListKeys:
	public_key_list( argc, argv );
	break;
      case aListSecretKeys:
	secret_key_list( argc, argv );
	break;

      case aKMode: /* list keyring */
	if( argc < 2 )	/* -kv [userid] */
	    public_key_list( (argc && **argv)? 1:0, argv );
	else if( argc == 2 ) { /* -kv userid keyring */
	    if( access( argv[1], R_OK ) ) {
		log_error(_("can't open %s: %s\n"),
			       print_fname_stdin(argv[1]), strerror(errno));
	    }
	    else {
		/* add keyring (default keyrings are not registered in this
		 * special case */
		add_keyring( argv[1] );
		public_key_list( **argv?1:0, argv );
	    }
	}
	else
	    wrong_args(_("-k[v][v][v][c] [userid] [keyring]") );
	break;

    #ifdef IS_G10
      case aKeygen: /* generate a key (interactive) */
	if( argc )
	    wrong_args("--gen-key");
	generate_keypair();
	break;
      case aKeyadd: /* add a subkey (interactive) */
	if( argc != 1 )
	    wrong_args("--add-key userid");
	generate_subkeypair(*argv);
	break;
    #endif

      case aImport:
	if( !argc  ) {
	    rc = import_pubkeys( NULL );
	    if( rc )
		log_error("import failed: %s\n", g10_errstr(rc) );
	}
	for( ; argc; argc--, argv++ ) {
	    rc = import_pubkeys( *argv );
	    if( rc )
		log_error("import from '%s' failed: %s\n",
						*argv, g10_errstr(rc) );
	}
	break;

      case aExport:
	sl = NULL;
	for( ; argc; argc--, argv++ )
	    add_to_strlist( &sl, *argv );
	export_pubkeys( sl );
	free_strlist(sl);
	break;

    #ifdef IS_G10
      case aGenRevoke:
	if( argc != 1 )
	    wrong_args("--gen-revoke user-id");
	gen_revoke( *argv );
	break;
    #endif

    #ifdef IS_G10MAINT
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
	if( argc == 1 ) {
	    mpi_print( stdout, generate_public_prime( atoi(argv[0]) ), 1);
	    putchar('\n');
	}
	else if( argc == 2 ) {
	    mpi_print( stdout, generate_elg_prime( 0, atoi(argv[0]),
						   atoi(argv[1]), NULL,NULL ), 1);
	    putchar('\n');
	}
	else if( argc == 3 ) {
	    MPI g = mpi_alloc(1);
	    mpi_print( stdout, generate_elg_prime( 0, atoi(argv[0]),
						   atoi(argv[1]), g, NULL ), 1);
	    printf("\nGenerator: ");
	    mpi_print( stdout, g, 1 );
	    putchar('\n');
	    mpi_free(g);
	}
	else if( argc == 4 ) {
	    mpi_print( stdout, generate_elg_prime( 1, atoi(argv[0]),
						   atoi(argv[1]), NULL,NULL ), 1);
	    putchar('\n');
	}
	else
	    usage(1);
	break;

      case aGenRandom:
	if( argc < 1 || argc > 2 )
	    wrong_args("--gen-random level [hex]");
	{
	    int level = atoi(*argv);
	    for(;;) {
		int c = get_random_byte(level);
		if( argc == 1 ) {
		    printf("%02x", c );
		    fflush(stdout);
		}
		else
		    putchar(c&0xff);
	    }
	}
	break;

      case aPrintMD:
	if( argc < 1)
	    wrong_args("--print-md algo [file]");
	else {
	    int algo = string_to_digest_algo(*argv);

	    if( !algo )
		log_error(_("invalid hash algorithm '%s'\n"), *argv );
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

      case aPrintMDs:
	if( !argc )
	    print_mds(NULL,0);
	else {
	    for(; argc; argc--, argv++ )
		print_mds(*argv,0);
	}
	break;

      case aTest: do_test( argc? atoi(*argv): 1 ); break;

      case aListTrustDB:
	if( !argc )
	    list_trustdb(NULL);
	else {
	    for( ; argc; argc--, argv++ )
		list_trustdb( *argv );
	}
	break;

      case aListTrustPath:
	if( argc != 2 )
	    wrong_args("--list-trust-path [-- -]<maxdepth> <username>");
	list_trust_path( atoi(*argv), argv[1] );
	break;

     #endif /* IS_G10MAINT */


      case aNOP:
	break;

      case aListPackets:
	opt.list_packets=1;
      default:
	/* fixme: g10maint should do regular maintenace tasks here */
	if( argc > 1 )
	    wrong_args(_("[filename]"));
	if( !(a = iobuf_open(fname)) )
	    log_error(_("can't open '%s'\n"), print_fname_stdin(fname));
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
	    proc_packets( a );
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
    if( opt.debug )
	secmem_dump_stats();
    secmem_term();
    rc = rc? rc : log_get_errorcount(0)? 2:0;
    /*write_status( STATUS_LEAVE );*/
    exit(rc );
}

#ifdef IS_G10MAINT
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
print_mds( const char *fname, int algo )
{
    FILE *fp;
    char buf[1024];
    size_t n;
    MD_HANDLE md;
    char *pname;

    if( !fname ) {
	fp = stdin;
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
      #ifdef WITH_TIGER_HASH
	md_enable( md, DIGEST_ALGO_TIGER );
      #endif
    }

    while( (n=fread( buf, 1, DIM(buf), fp )) )
	md_write( md, buf, n );
    if( ferror(fp) )
	log_error("%s%s\n", pname, strerror(errno) );
    else {
	md_final(md);
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
	  #ifdef WITH_TIGER_HASH
	    printf("\n%s TIGER = ", fname?pname:""  );
			    print_hex(md_read(md, DIGEST_ALGO_TIGER), 24 );
	  #endif
	}
	putchar('\n');
    }
    md_close(md);

    if( fp != stdin )
	fclose(fp);
}



static void
do_test(int times)
{
    MPI base[4];
    MPI exp[4];
    MPI t1 = mpi_alloc(50);
    MPI t2 = mpi_alloc(50);
    MPI t3 = mpi_alloc(50);
    MPI tmp= mpi_alloc(50);
    MPI m =   mpi_alloc(50);
    MPI res = mpi_alloc(50);

    mpi_fromstr( m, "0x10000000000000000000000000" );
    base[0] = mpi_alloc_set_ui( 3 );
    mpi_fromstr( base[0], "0x145984358945989898495ffdd13" );
    base[1] = mpi_alloc_set_ui( 5 );
    mpi_fromstr( base[1], "0x000effff9999000000001100001" );
    base[2] = mpi_alloc_set_ui( 2 );
    mpi_fromstr( base[2], "0x499eeeaaaaa0444444545466672" );
    base[3] = NULL;
    exp[0]  = mpi_alloc_set_ui( 30 );
    exp[1]  = mpi_alloc_set_ui( 10 );
    mpi_fromstr( exp[1], "0x3457878888888888aabbbccccc1" );
    exp[2]  = mpi_alloc_set_ui( 24 );
    exp[3] = NULL;

    mpi_powm( t1, base[0], exp[0], m );
    mpi_powm( t2, base[1], exp[1], m );
    mpi_powm( t3, base[2], exp[2], m );
    mpi_mulm( tmp, t1, t2, m );
    mpi_mulm( t1, tmp, t3, m );
    log_mpidump("X=", t1 );


    mpi_mulpowm( res, base, exp, m );
    log_mpidump("X=", res );


    m_check(NULL);
}
#endif /* IS_G10MAINT */

