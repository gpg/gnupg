/* g10maint.c - The G10 maintenance utility
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
#include "status.h"


enum cmd_values { aNull = 0,
    aPrimegen, aPrintMDs, aListPackets, aKMode, aKModeC,
    aListTrustDB, aListTrustPath, aDeArmor, aEnArmor,
aTest };


static char *build_list( const char *text,
			 const char *(*mapf)(int), int (*chkf)(int) );
static void set_cmd( enum cmd_values *ret_cmd,
			enum cmd_values new_cmd );
static void print_hex( byte *p, size_t n );
static void print_mds( const char *fname );
static void do_test(int);


const char *
strusage( int level )
{
  static char *digests, *pubkeys, *ciphers;
    const char *p;
    switch( level ) {
      case 11: p = "g10maint"; break;
      case 13: p = VERSION; break;
      case 17: p = PRINTABLE_OS_NAME; break;
      case 19: p = _(
"Please report bugs to <g10-bugs@isil.d.shuttle.de>."
	); break;
      case 1:
      case 40:	p = _(
"Usage: g10maint [options] [files] (-h for help)"
	); break;
      case 41:	p = _(
"Syntax: g10maint [options] [files]\n"
"G10 maintenance utility\n"
	); break;

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

    for(i=1; i < 100; i++ )
	if( !chkf(i) && (s=mapf(i)) )
	    n += strlen(s) + 2;
    list = m_alloc( 21 + n ); *list = 0;
    for(p=NULL, i=1; i < 100; i++ ) {
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
  #ifdef HAVE_LIBINTL
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
    fputs(_("Usage: g10maint [options] "),stderr);
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
    else if( cmd == aKMode && new_cmd == aKModeC )
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
    { 'v', "verbose",   0, N_("verbose") },
    { 'n', "dry-run",   0, N_("don't make any changes") },
    { 'o', "output",    2, N_("use as output file")},
    { 'c', NULL    ,    0, N_("check signatures")},
    { 500, "batch",     0, N_("batch mode: never ask")},
    { 501, "yes",       0, N_("assume yes on most questions")},
    { 502, "no",        0, N_("assume no on most questions")},
    { 509, "keyring"   ,2, N_("add this keyring to the list of keyrings")},
    { 'k', NULL      , 0, N_("list keys")},
    { 510, "debug"     ,4|16, N_("set debugging flags")},
    { 511, "debug-all" ,0, N_("enable full debugging")},
    { 512, "status-fd" ,1, N_("write status info to this fd") },
    { 513, "gen-prime" , 0, "\r" },
    { 514, "test"      , 0, "\r" },
    { 516, "print-mds" , 0, N_("print all message digests")},
    { 517, "secret-keyring" ,2, N_("add this secret keyring to the list")},
    { 518, "options"   , 2, N_("read options from file")},
    { 519, "no-armor",   0, "\r"},
    { 520, "no-default-keyring", 0, "\r" },
    { 521, "list-packets",0,N_("list only the sequence of packets")},
    { 522, "no-greeting", 0, "\r" },
    { 526, "no-verbose", 0, "\r"},
    { 531, "list-trustdb",0 , "\r"},
    { 533, "list-trust-path",0, "\r"},
    { 532, "quick-random", 0, "\r"},
    { 534, "no-comment", 0,   N_("do not write comment packets")},
    { 535, "completes-needed", 1, N_("(default is 1)")},
    { 536, "marginals-needed", 1, N_("(default is 3)")},
    { 538, "trustdb-name", 2, "\r" },
    { 540, "no-secmem-warning", 0, "\r" }, /* dummy */
    { 543, "no-options", 0, "\r" }, /* shortcut for --options /dev/null */
    { 544, "homedir", 2, "\r" },   /* defaults to "~/.g10" */
    { 545, "no-batch", 0, "\r" },
    { 546, "dearmor", 0, N_("De-Armor a file or stdin") },
    { 547, "enarmor", 0, N_("En-Armor a file or stdin") },

    {0} };
    ARGPARSE_ARGS pargs;
    IOBUF a;
    int rc=0;
    int orig_argc;
    char **orig_argv;
    const char *fname, *fname_print;
    STRLIST remusr= NULL, locusr=NULL;
    int nrings=0, sec_nrings=0;
    armor_filter_context_t afx;
    FILE *configfp = NULL;
    char *configname = NULL;
    unsigned configlineno;
    int parse_verbose = 0;
    int default_config =1;
    int errors=0;
    int default_keyring = 1;
    int greeting = 1;
    enum cmd_values cmd = 0;
    const char *trustdb_name = NULL;


    secmem_init( 0 ); /* disable use of secmem */

    log_set_name("g10maint");
    i18n_init();
    opt.compress = -1; /* defaults to standard compress level */
    opt.def_cipher_algo = CIPHER_ALGO_BLOWFISH;
    opt.def_pubkey_algo = PUBKEY_ALGO_ELGAMAL;
    opt.def_digest_algo = DIGEST_ALGO_RMD160;
    opt.completes_needed = 1;
    opt.marginals_needed = 3;
    opt.homedir = "~/.g10";

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
	  case 'o': opt.outfile = pargs.r.ret_str; break;
	  case 'k': set_cmd( &cmd, aKMode ); break;
	  case 'c': set_cmd( &cmd, aKModeC ); break;
	  case 500: opt.batch = 1; greeting = 0; break;
	  case 501: opt.answer_yes = 1; break;
	  case 502: opt.answer_no = 1; break;
	  case 508: opt.check_sigs = 1; opt.list_sigs = 1; break;
	  case 509: add_keyring(pargs.r.ret_str); nrings++; break;
	  case 510: opt.debug |= pargs.r.ret_ulong; break;
	  case 511: opt.debug = ~0; break;
	  case 512: set_status_fd( pargs.r.ret_int ); break;
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
	  case 531: set_cmd( &cmd, aListTrustDB); break;
	  case 532: quick_random_gen(1); break;
	  case 533: set_cmd( &cmd, aListTrustPath); break;
	  case 534: opt.no_comment=1; break;
	  case 535: opt.completes_needed = pargs.r.ret_int; break;
	  case 536: opt.marginals_needed = pargs.r.ret_int; break;
	  case 538: trustdb_name = pargs.r.ret_str; break;
	  case 540: break; /*dummy*/
	  case 543: break; /* no-options */
	  case 544: opt.homedir = pargs.r.ret_str; break;
	  case 545: opt.batch = 0; break;
	  case 546: set_cmd( &cmd, aDeArmor); break;
	  case 547: set_cmd( &cmd, aEnArmor); break;
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

    write_status( STATUS_ENTER );

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
	tty_printf("%s %s; %s\n", strusage(11), strusage(13), strusage(14) );
	tty_printf("%s", strusage(15) );
    }

    if( !sec_nrings || default_keyring ) { /* add default secret rings */
	char *p = make_filename(opt.homedir, "secring.g10", NULL );
	add_secret_keyring(p);
	m_free(p);
    }
    if( !nrings || default_keyring ) { /* add default ring */
	char *p = make_filename(opt.homedir, "pubring.g10", NULL );
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
      case aDeArmor:
      case aEnArmor:
	break;
      case aListTrustDB: rc = init_trustdb( argc? 1:0, trustdb_name ); break;
      default: rc = init_trustdb(1, trustdb_name ); break;
    }
    if( rc )
	log_error(_("failed to initialize the TrustDB: %s\n"), g10_errstr(rc));


    switch( cmd ) {
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
	    mpi_print( stdout, generate_elg_prime( atoi(argv[0]),
						   atoi(argv[1]), NULL,NULL ), 1);
	    putchar('\n');
	}
	else if( argc == 3 ) {
	    MPI g = mpi_alloc(1);
	    mpi_print( stdout, generate_elg_prime( atoi(argv[0]),
						   atoi(argv[1]), g, NULL ), 1);
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

      case aListPackets:
	opt.list_packets=1;
      default:	/* do regular maintenace tasks */
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
    rc = rc? rc : log_get_errorcount(0)? 2:0;
    write_status( STATUS_LEAVE );
    exit(rc );
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

