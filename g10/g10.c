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

enum cmd_values { aNull = 0,
    aSym, aStore, aEncr, aPrimegen, aKeygen, aSign, aSignEncr,
    aPrintMDs, aSignKey, aClearsig, aListPackets, aEditSig,
    aKMode, aKModeC, aChangePass,
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
    "Syntax: g10 [options] [files]\n"
    "sign, check, encrypt or decrypt\n"
    "default operation depends on the input data\n"; break;

      case 26:
	p = "Please report bugs to <g10-bugs@isil.d.shuttle.de>.\n";
	break;

      case 30: p = ""
  #ifndef HAVE_ZLIB_H
    "   NOTE: This version is compiled without ZLIB support;\n"
    "         you are not able to process compresssed data!\n"
  #endif
  #ifdef HAVE_RSA_CIPHER
    "WARNING: This version has RSA support! Your are not allowed to\n"
    "         use it inside the Unites States before Sep 30, 2000!\n"
  #endif
	;
	break;
      default:	p = default_strusage(level);
    }
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
	log_error("conflicting commands\n");
	exit(2);
    }

    *ret_cmd = cmd;
}


int
main( int argc, char **argv )
{
    static ARGPARSE_OPTS opts[] = {
    { 'a', "armor",     0, "create ascii armored output"},
    { 'v', "verbose",   0, "verbose" },
    { 'z', NULL,        1, "set compress level (0 disables)" },
    { 'n', "dry-run",   0, "don't make any changes" },
    { 'c', "symmetric", 0, "do only a symmetric encryption" },
    { 'o', "output",    2, "use as output file" },
    { 500, "batch",     0, "batch mode: never ask" },
    { 501, "yes",       0, "assume yes on most questions"},
    { 502, "no",        0, "assume no on most questions"},
    { 503, "gen-key",   0, "generate a new key pair" },
    { 504, "add-key",   0, "add key to the public keyring" },
    { 505, "delete-key",0, "remove key from public keyring" },
    { 506, "sign-key"  ,0, "make a signature on a key in the keyring" },
    { 507, "store",     0, "store only" },
    { 508, "check-key" ,0, "check signatures on a key in the keyring" },
    { 509, "keyring"   ,2, "add this keyring to the list of keyrings" },
    { 's', "sign",      0, "make a signature"},
    { 't', "textmode",  0, "use canonical text mode"},
    { 'b', "detach-sign", 0, "make a detached signature"},
    { 'e', "encrypt",   0, "encrypt data" },
    { 'd', "decrypt",   0, "decrypt data (default)" },
    { 'u', "local-user",2, "use this user-id to sign or decrypt" },
    { 'r', "remote-user", 2, "use this user-id for encryption" },
    { 'k', NULL      , 0, "list keys" },
    { 510, "debug"     ,4|16, "set debugging flags" },
    { 511, "debug-all" ,0, "enable full debugging"},
    { 512, "cache-all" ,0, "hold everything in memory"},
    { 513, "gen-prime" , 0, "\r" },
    { 514, "test"      , 0, "\r" },
    { 515, "fingerprint", 0, "show the fingerprints"},
    { 516, "print-mds" , 0, "print all message digests"},
    { 517, "secret-keyring" ,2, "add this secret keyring to the list" },
    { 518, "options"   , 2, "read options from file" },
    { 519, "no-armor",   0, "\r"},
    { 520, "no-default-keyring", 0, "\r" },
    { 521, "list-packets",0,"list only the sequence of packets"},
    { 522, "no-greeting", 0, "\r" },
    { 523, "passphrase-fd",1, "\r" },
    { 524, "edit-sig"  ,0, "edit a key signature" },
    { 525, "change-passphrase", 0, "change the passphrase of your secret keyring"},

    {0} };
    ARGPARSE_ARGS pargs;
    IOBUF a;
    int rc;
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


    opt.compress = -1; /* defaults to standard compress level */

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
		log_info("note: no default option file '%s'\n", configname );
	    }
	    else
		log_fatal("option file '%s': %s\n",
				    configname, strerror(errno) );
	    m_free(configname); configname = NULL;
	}
	if( parse_verbose > 1 )
	    log_info("reading options from '%s'\n", configname );
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
	  case 512: opt.cache_all = 1; break;
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
    if( errors )
	exit(2);

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
    }

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
	if( argc > 1 )
	    usage(1);
	if( (rc = sign_file(fname, detached_sig, locusr, 0, NULL)) )
	    log_error("sign_file('%s'): %s\n", fname_print, g10_errstr(rc) );
	break;

      case aSignEncr: /* sign and encrypt the given file */
	if( argc > 1 )
	    usage(1);
	if( (rc = sign_file(fname, detached_sig, locusr, 1, remusr)) )
	    log_error("sign_file('%s'): %s\n", fname_print, g10_errstr(rc) );
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

	    while( s=get_keyring(seq++) ) {
		if( !(a = iobuf_open(s)) ) {
		    log_error("can't open '%s'\n", s);
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
		log_fatal("can't open '%s'\n", fname_print);
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

      case aListPackets:
	opt.list_packets=1;
      default:
	if( argc > 1 )
	    usage(1);
	if( !(a = iobuf_open(fname)) )
	    log_fatal("can't open '%s'\n", fname_print);
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
    return log_get_errorcount(0)? 2:0;
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
    MD5HANDLE md5;
    RMDHANDLE rmd160;
    SHA1HANDLE sha1;

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

    md5    = md5_open(0);
    rmd160 = rmd160_open(0);
    sha1   = sha1_open(0);

    while( (n=fread( buf, 1, DIM(buf), fp )) ) {
	md5_write( md5, buf, n );
	rmd160_write( rmd160, buf, n );
	sha1_write( sha1, buf, n );
    }
    if( ferror(fp) )
	log_error("%s: %s\n", fname, strerror(errno) );
    else {
	byte *p;

	md5_final(md5);
	printf(  "%s:    MD5 =", fname ); print_hex(md5_read(md5), 16 );
	printf("\n%s: RMD160 =", fname ); print_hex(rmd160_final(rmd160), 20 );
	printf("\n%s:   SHA1 =", fname ); print_hex(sha1_final(sha1), 20 );
	putchar('\n');
    }


    md5_close(md5);
    rmd160_close(rmd160);
    sha1_close(sha1);

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

