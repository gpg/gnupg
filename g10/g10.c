/* g10.c - The G10 utility
 *	Copyright (c) 1997 by Werner Koch (dd9jn)
 *
 * This file is part of G10.
 *
 * G10 is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * G10 is distributed in the hope that it will be useful,
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


enum cmd_values { aNull = 0,
    aSym, aStore, aEncr, aPrimegen, aKeygen, aSign, aSignEncr,
    aPrintMDs, aSignKey, aClearsig, aListPackets, aEditSig,
    aKMode, aKModeC, aChangePass, aImport, aListTrustDB,
    aListTrustPath, aExport,
aTest };


static void set_cmd( enum cmd_values *ret_cmd,
			enum cmd_values new_cmd );
static void print_hex( byte *p, size_t n );
static void print_mds( const char *fname );
static void do_test(int);

const char *
strusage( int level )
{
    const char *p;
    switch( level ) {
      case 10:
      case 0:	p = "g10 - v" VERSION "; "
		    "Copyright 1997 Werner Koch (dd9jn)\n" ; break;
      case 13:	p = "g10"; break;
      case 14:	p = VERSION; break;
      case 1:
      case 11:	p = "Usage: g10 [options] [files] (-h for help)";
		break;
      case 2:
      case 12:	p =
    _("Syntax: g10 [options] [files]\n"
      "sign, check, encrypt or decrypt\n"
      "default operation depends on the input data\n"); break;

      case 26:
	p = _("Please report bugs to <g10-bugs@isil.d.shuttle.de>.\n");
	break;

  #if !defined(HAVE_ZLIB_H) && defined(HAVE_RSA_CIPHER)
      case 30: p = _(
    "   NOTE: This version is compiled without ZLIB support;\n"
    "         you are not able to process compresssed data!\n"
    "WARNING: This version has RSA support! Your are not allowed to\n"
    "         use it inside the Unites States before Sep 30, 2000!\n" );
  #elif !defined(HAVE_ZLIB_H)
      case 30: p = _(
    "   NOTE: This version is compiled without ZLIB support;\n"
    "         you are not able to process compresssed data!\n");
  #elif defined(HAVE_RSA_CIPHER)
      case 30: p = _(
    "WARNING: This version has RSA support! Your are not allowed to\n"
    "         use it inside the Unites States before Sep 30, 2000!\n" );
  #else
      case 30: p = "";
  #endif
	break;
      default:	p = default_strusage(level);
    }
    return p;
}

static void
i18n_init(void)
{
  #ifdef HAVE_LIBINTL
    setlocale( LC_MESSAGES, "" );
    bindtextdomain( PACKAGE, G10_LOCALEDIR );
    textdomain( PACKAGE );
  #endif
}

static void
wrong_args( const char *text)
{
    fputs(_("Usage: g10 [options] "),stderr);
    fputs(text,stderr);
    putc('\n',stderr);
    g10_exit(2);
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
	cipher_debug_mode = 1;
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
    else {
	log_error(_("conflicting commands\n"));
	g10_exit(2);
    }

    *ret_cmd = cmd;
}


void
main( int argc, char **argv )
{
    static ARGPARSE_OPTS opts[] = {
    { 'a', "armor",     0, N_("create ascii armored output")},
    { 'v', "verbose",   0, N_("verbose") },
    { 'z', NULL,        1, N_("set compress level (0 disables)") },
    { 'n', "dry-run",   0, N_("don't make any changes") },
    { 'c', "symmetric", 0, N_("do only a symmetric encryption")},
    { 'o', "output",    2, N_("use as output file")},
    { 500, "batch",     0, N_("batch mode: never ask")},
    { 501, "yes",       0, N_("assume yes on most questions")},
    { 502, "no",        0, N_("assume no on most questions")},
    { 503, "gen-key",   0, N_("generate a new key pair")},
    { 504, "add-key",   0, N_("add key to the public keyring")},
    { 505, "delete-key",0, N_("remove key from public keyring")},
    { 506, "sign-key"  ,0, N_("make a signature on a key in the keyring")},
    { 507, "store",     0, N_("store only")},
    { 508, "check-key" ,0, N_("check signatures on a key in the keyring")},
    { 509, "keyring"   ,2, N_("add this keyring to the list of keyrings")},
    { 's', "sign",      0, N_("make a signature")},
    { 't', "textmode",  0, N_("use canonical text mode")},
    { 'b', "detach-sign", 0, N_("make a detached signature")},
    { 'e', "encrypt",   0, N_("encrypt data")},
    { 'd', "decrypt",   0, N_("decrypt data (default)")},
    { 'u', "local-user",2, N_("use this user-id to sign or decrypt")},
    { 'r', "remote-user", 2, N_("use this user-id for encryption")},
    { 'k', NULL      , 0, N_("list keys")},
    { 510, "debug"     ,4|16, N_("set debugging flags")},
    { 511, "debug-all" ,0, N_("enable full debugging")},
 /* { 512 unused */
    { 513, "gen-prime" , 0, "\r" },
    { 514, "test"      , 0, "\r" },
    { 515, "fingerprint", 0, N_("show the fingerprints")},
    { 516, "print-mds" , 0, N_("print all message digests")},
    { 517, "secret-keyring" ,2, N_("add this secret keyring to the list")},
    { 518, "options"   , 2, N_("read options from file")},
    { 519, "no-armor",   0, "\r"},
    { 520, "no-default-keyring", 0, "\r" },
    { 521, "list-packets",0,N_("list only the sequence of packets")},
    { 522, "no-greeting", 0, "\r" },
    { 523, "passphrase-fd",1, "\r" },
    { 524, "edit-sig"  ,0, N_("edit a key signature")},
    { 525, "change-passphrase", 0, N_("change the passphrase of your secret keyring")},
    { 526, "no-verbose", 0, "\r"},
    { 527, "cipher-algo", 2 , N_("select default cipher algorithm")},
    { 528, "pubkey-algo", 2 , N_("select default puplic key algorithm")},
    { 529, "digest-algo", 2 , N_("select default message digest algorithm")},
    { 530, "import",      0 , N_("put public keys into the trustdb")},
    { 531, "list-trustdb",0 , "\r"},
    { 532, "quick-random", 0, "\r"},
    { 533, "list-trust-path",0, "\r"},
    { 534, "no-comment", 0,   N_("do not write comment packets")},
    { 535, "completes-needed", 1, N_("(default is 1)")},
    { 536, "marginals-needed", 1, N_("(default is 3)")},
    { 537, "export", 0, N_("export all or the given keys") },

    {0} };
    ARGPARSE_ARGS pargs;
    IOBUF a;
    int rc=0;
    int orig_argc;
    char **orig_argv;
    const char *fname, *fname_print;
    STRLIST sl, remusr= NULL, locusr=NULL;
    int nrings=0, sec_nrings=0;
    armor_filter_context_t afx;
    const char *s;
    int detached_sig = 0;
    FILE *configfp = NULL;
    char *configname = NULL;
    unsigned configlineno;
    int parse_verbose = 0;
    int default_config =1;
    int errors=0;
    int default_keyring = 1;
    int greeting = 1;
    enum cmd_values cmd = 0;


    secmem_init( 16384 );

    i18n_init();
    opt.compress = -1; /* defaults to standard compress level */
    opt.def_cipher_algo = CIPHER_ALGO_BLOWFISH;
    opt.def_pubkey_algo = PUBKEY_ALGO_ELGAMAL;
    opt.def_digest_algo = DIGEST_ALGO_RMD160;
    opt.completes_needed = 1;
    opt.marginals_needed = 3;

    /* check wether we have a config file on the commandline */
    orig_argc = argc;
    orig_argv = argv;
    pargs.argc = &argc;
    pargs.argv = &argv;
    pargs.flags=  1;  /* do not remove the args */
    while( arg_parse( &pargs, opts) ) {
	if( pargs.r_opt == 'v' )
	    parse_verbose++;
	else if( pargs.r_opt == 518 ) {
	    /* yes there is one, so we do not try the default one, but
	     * read the option file when it is encountered at the commandline
	     */
	    default_config = 0;
	}
    }

    if( default_config )
	configname = make_filename("~/.g10", "options", NULL );

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
		if( parse_verbose > 1 )
		log_info(_("note: no default option file '%s'\n"), configname );
	    }
	    else
		log_fatal(_("option file '%s': %s\n"),
				    configname, strerror(errno) );
	    m_free(configname); configname = NULL;
	}
	if( parse_verbose > 1 )
	    log_info(_("reading options from '%s'\n"), configname );
	default_config = 0;
    }

    while( optfile_parse( configfp, configname, &configlineno,
						&pargs, opts) ) {
	switch( pargs.r_opt ) {
	  case 'v': opt.verbose++;
		    opt.list_sigs=1;
		    break;
	  case 'z': opt.compress = pargs.r.ret_int; break;
	  case 'a': opt.armor = 1; opt.no_armor=0; break;
	  case 'c': set_cmd( &cmd , aSym); break;
	  case 'o': opt.outfile = pargs.r.ret_str; break;
	  case 'e': set_cmd( &cmd, aEncr); break;
	  case 'b': detached_sig = 1;
	       /* fall trough */
	  case 's': set_cmd( &cmd, aSign );  break;
	  case 't': set_cmd( &cmd , aClearsig);  break;
	  case 'u': /* store the local users */
	    sl = m_alloc( sizeof *sl + strlen(pargs.r.ret_str));
	    strcpy(sl->d, pargs.r.ret_str);
	    sl->next = locusr;
	    locusr = sl;
	    break;
	  case 'r': /* store the remote users */
	    sl = m_alloc( sizeof *sl + strlen(pargs.r.ret_str));
	    strcpy(sl->d, pargs.r.ret_str);
	    sl->next = remusr;
	    remusr = sl;
	    break;
	  case 'k': set_cmd( &cmd, aKMode ); break;
	  case 500: opt.batch = 1; greeting = 0; break;
	  case 501: opt.answer_yes = 1; break;
	  case 502: opt.answer_no = 1; break;
	  case 503: set_cmd( &cmd, aKeygen); break;
	  case 506: set_cmd( &cmd, aSignKey); break;
	  case 507: set_cmd( &cmd, aStore); break;
	  case 508: opt.check_sigs = 1; opt.list_sigs = 1; break;
	  case 509: add_keyring(pargs.r.ret_str); nrings++; break;
	  case 510: opt.debug |= pargs.r.ret_ulong; break;
	  case 511: opt.debug = ~0; break;
	/*  case 512: */
	  case 513: set_cmd( &cmd, aPrimegen); break;
	  case 514: set_cmd( &cmd, aTest); break;
	  case 515: opt.fingerprint = 1; break;
	  case 516: set_cmd( &cmd, aPrintMDs); break;
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
	  case 523: set_passphrase_fd( pargs.r.ret_int ); break;
	  case 524: set_cmd( &cmd, aEditSig); break;
	  case 525: set_cmd( &cmd, aChangePass); break;
	  case 526: opt.verbose = 0; opt.list_sigs=0; break;
	  case 527:
	    opt.def_cipher_algo = string_to_cipher_algo(pargs.r.ret_str);
	    break;
	  case 528:
	    opt.def_pubkey_algo = string_to_pubkey_algo(pargs.r.ret_str);
	    break;
	  case 529:
	    opt.def_digest_algo = string_to_digest_algo(pargs.r.ret_str);
	    break;
	  case 530: set_cmd( &cmd, aImport); break;
	  case 531: set_cmd( &cmd, aListTrustDB); break;
	  case 532: quick_random_gen(1); break;
	  case 533: set_cmd( &cmd, aListTrustPath); break;
	  case 534: opt.no_comment=1; break;
	  case 535: opt.completes_needed = pargs.r.ret_int; break;
	  case 536: opt.marginals_needed = pargs.r.ret_int; break;
	  case 537: set_cmd( &cmd, aExport); break;
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
    if( !opt.def_cipher_algo || check_cipher_algo(opt.def_cipher_algo) ) {
	log_error(_("selected cipher algorithm is invalid\n"));
	errors++;
    }
    if( !opt.def_pubkey_algo || check_pubkey_algo(opt.def_pubkey_algo) ) {
	log_error(_("selected pubkey algorithm is invalid\n"));
	errors++;
    }
    if( !opt.def_digest_algo || check_digest_algo(opt.def_digest_algo) ) {
	log_error(_("selected digest algorithm is invalid\n"));
	errors++;
    }
    if( opt.completes_needed < 1 ) {
	log_error(_("completes-needed must be greater than 0\n"));
	errors++;
    }
    if( opt.marginals_needed < 2 ) {
	log_error(_("marginals-needed must be greater than 1\n"));
	errors++;
    }
    if( errors )
	g10_exit(2);


    set_debug();
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
    }
    if( opt.verbose > 1 )
	set_packet_list_mode(1);
    if( greeting ) {
	if( *(s=strusage(10))  )
	    tty_printf("%s", s);
	if( *(s=strusage(30))  )
	    tty_printf("%s", s);
    }

    if( !sec_nrings || default_keyring ) { /* add default secret rings */
	char *p = make_filename("~/.g10", "secring.g10", NULL );
	add_secret_keyring(p);
	m_free(p);
    }
    if( !nrings || default_keyring ) { /* add default ring */
	char *p = make_filename("~/.g10", "pubring.g10", NULL );
	add_keyring(p);
	m_free(p);
    }

    if( argc ) {
	fname_print = fname = *argv;
    }
    else {
	fname_print = "[stdin]";
	fname = NULL;
	if( get_passphrase_fd() == 0 ) {
	    /* reading data and passphrase form stdin:
	     * we assume the first line is the passphrase, so
	     * we read it now
	     */
	    /* FIXME: doit */
	}
    }

    switch( cmd ) {
      case aPrimegen:
      case aPrintMDs:
	break;
      case aListTrustDB: rc = init_trustdb( argc? 1:0 ); break;
      default: rc = init_trustdb(1); break;
    }
    if( rc )
	log_error(_("failed to initialize the TrustDB: %s\n"), g10_errstr(rc));


    switch( cmd ) {
      case aStore: /* only store the file */
	if( argc > 1 )
	    usage(1);
	if( (rc = encode_store(fname)) )
	    log_error("encode_store('%s'): %s\n",
				    fname_print, g10_errstr(rc) );
	break;

      case aSym: /* encrypt the given file only with the symmetric cipher */
	if( argc > 1 )
	    usage(1);
	if( (rc = encode_symmetric(fname)) )
	    log_error("encode_symmetric('%s'): %s\n", fname_print, g10_errstr(rc) );
	break;

      case aEncr: /* encrypt the given file */
	if( argc > 1 )
	    usage(1);
	if( (rc = encode_crypt(fname,remusr)) )
	    log_error("encode_crypt('%s'): %s\n", fname_print, g10_errstr(rc) );
	break;

      case aSign: /* sign the given file */
	sl = NULL;
	if( detached_sig ) { /* sign all files */
	    for( ; argc; argc--, argv++ )
		add_to_strlist( &sl, *argv );
	}
	else {
	    if( argc > 1 )
		usage(1);
	    if( argc ) {
		sl = m_alloc_clear( sizeof *sl + strlen(fname));
		strcpy(sl->d, fname);
	    }
	}
	if( (rc = sign_file( sl, detached_sig, locusr, 0, NULL, NULL)) )
	    log_error("sign_file: %s\n", g10_errstr(rc) );
	free_strlist(sl);
	break;

      case aSignEncr: /* sign and encrypt the given file */
	if( argc > 1 )
	    usage(1);
	if( argc ) {
	    sl = m_alloc_clear( sizeof *sl + strlen(fname));
	    strcpy(sl->d, fname);
	}
	else
	    sl = NULL;
	if( (rc = sign_file(sl, detached_sig, locusr, 1, remusr, NULL)) )
	    log_error("sign_file('%s'): %s\n", fname_print, g10_errstr(rc) );
	free_strlist(sl);
	break;


      case aSignKey: /* sign the key given as argument */
	if( argc != 1 )
	    usage(1);
	/* note: fname is the user id! */
	if( (rc = sign_key(fname, locusr)) )
	    log_error("sign_key('%s'): %s\n", fname_print, g10_errstr(rc) );
	break;

      case aEditSig: /* Edit a key signature */
	if( argc != 1 )
	    usage(1);
	/* note: fname is the user id! */
	if( (rc = edit_keysigs(fname)) )
	    log_error("edit_keysig('%s'): %s\n", fname_print, g10_errstr(rc) );
	break;

      case aChangePass: /* Chnage the passphrase */
	if( argc > 1 ) /* no arg: use default, 1 arg use this one */
	    usage(1);
	/* note: fname is the user id! */
	if( (rc = change_passphrase(fname)) )
	    log_error("change_passphrase('%s'): %s\n", fname_print,
						       g10_errstr(rc) );
	break;

      case aKMode: /* list keyring */
	if( !argc ) { /* list the default public keyrings */
	    int i, seq=0;
	    const char *s;

	    while( (s=get_keyring(seq++)) ) {
		if( !(a = iobuf_open(s)) ) {
		    log_error(_("can't open '%s'\n"), s);
		    continue;
		}
		if( seq > 1 )
		    putchar('\n');
		printf("%s\n", s );
		for(i=strlen(s); i; i-- )
		    putchar('-');
		putchar('\n');

		proc_packets( a );
		iobuf_close(a);
	    }

	}
	else if( argc == 1) { /* list the given keyring */
	    if( !(a = iobuf_open(fname)) )
		log_fatal(_("can't open '%s'\n"), fname_print);
	    proc_packets( a );
	    iobuf_close(a);
	}
	else
	    usage(1);
	break;

      case aPrimegen:
	if( argc == 1 ) {
	    mpi_print( stdout, generate_public_prime( atoi(argv[0]) ), 1);
	    putchar('\n');
	}
	else if( argc == 2 ) {
	    mpi_print( stdout, generate_elg_prime( atoi(argv[0]),
						   atoi(argv[1]), NULL ), 1);
	    putchar('\n');
	}
	else if( argc == 3 ) {
	    MPI g = mpi_alloc(1);
	    mpi_print( stdout, generate_elg_prime( atoi(argv[0]),
						   atoi(argv[1]), g ), 1);
	    printf("\nGenerator: ");
	    mpi_print( stdout, g, 1 );
	    putchar('\n');
	    mpi_free(g);
	}
	else
	    usage(1);
	break;

      case aPrintMDs:
	if( !argc )
	    print_mds(NULL);
	else {
	    for(; argc; argc--, argv++ )
		print_mds(*argv);
	}
	break;

      case aKeygen: /* generate a key (interactive) */
	if( argc )
	    usage(1);
	generate_keypair();
	break;

      case aTest: do_test( argc? atoi(*argv): 0 ); break;

      case aImport:
	if( !argc  )
	    usage(1);
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

      case aListPackets:
	opt.list_packets=1;
      default:
	if( argc > 1 )
	    usage(1);
	if( !(a = iobuf_open(fname)) )
	    log_fatal(_("can't open '%s'\n"), fname_print);
	if( !opt.no_armor ) {
	    /* push the armor filter, so it can peek at the input data */
	    memset( &afx, 0, sizeof afx);
	    iobuf_push_filter( a, armor_filter, &afx );
	}
	if( cmd == aListPackets ) {
	    set_packet_list_mode(1);
	    opt.list_packets=1;
	}
	proc_packets( a );
	iobuf_close(a);
	break;
    }

    /* cleanup */
    FREE_STRLIST(remusr);
    FREE_STRLIST(locusr);
    g10_exit(0);
}


void
g10_exit( int rc )
{
    if( opt.verbose )
	secmem_dump_stats();
    secmem_term();
    exit( rc? rc : log_get_errorcount(0)? 2:0 );
}


static void
print_hex( byte *p, size_t n )
{
    int i;

    if( n == 20 ) {
	for(i=0; i < n ; i++, i++, p += 2 ) {
	    if( i == 10 )
		putchar(' ');
	    printf(" %02X%02X", *p, p[1] );
	}
    }
    else {
	for(i=0; i < n ; i++, p++ ) {
	    if( i && !(i%8) )
		putchar(' ');
	    printf(" %02X", *p );
	}
    }
}

static void
print_mds( const char *fname )
{
    FILE *fp;
    char buf[1024];
    size_t n;
    MD_HANDLE md;

    if( !fname ) {
	fp = stdin;
	fname = "[stdin]";
    }
    else
	fp = fopen( fname, "rb" );
    if( !fp ) {
	log_error("%s: %s\n", fname, strerror(errno) );
	return;
    }

    md = md_open( DIGEST_ALGO_MD5, 0 );
    md_enable( md, DIGEST_ALGO_RMD160 );
    md_enable( md, DIGEST_ALGO_SHA1 );

    while( (n=fread( buf, 1, DIM(buf), fp )) )
	md_write( md, buf, n );
    if( ferror(fp) )
	log_error("%s: %s\n", fname, strerror(errno) );
    else {
	md_final(md);
	printf(  "%s:    MD5 =", fname ); print_hex(md_read(md, DIGEST_ALGO_MD5), 16 );
	printf("\n%s: RMD160 =", fname ); print_hex(md_read(md, DIGEST_ALGO_RMD160), 20 );
	printf("\n%s:   SHA1 =", fname ); print_hex(md_read(md, DIGEST_ALGO_SHA1), 20 );
	putchar('\n');
    }


    md_close(md);

    if( fp != stdin )
	fclose(fp);
}



static void
do_test(int times)
{
  #if 0
    MPI t = mpi_alloc( 50 );
    MPI m = mpi_alloc( 50 );
    MPI a = mpi_alloc( 50 );
    MPI b = mpi_alloc( 50 );
    MPI p = mpi_alloc( 50 );
    MPI x = mpi_alloc( 50 );

    /* output = b/(a^x) mod p */
    log_debug("invm %d times ", times);
    for( ; times > 0; times -- ) {
	mpi_fromstr(a, "0xef45678343589854354a4545545454554545455"
		       "aaaaaaaaaaaaa44444fffdecb33434343443331" );
	mpi_fromstr(b, "0x8765765589854354a4545545454554545455"
		       "aaaaaaa466577778decb36666343443331" );
	mpi_invm( t, a, b );
	fputc('.', stderr); fflush(stderr);
    }


    m_check(NULL);
  #endif
}

