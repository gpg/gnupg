/* gpd.c - The GnuPG daemon (keyserver)
 * Copyright (C) 1998, 1999 Free Software Foundation, Inc.
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

/****************
 * This is a spinning server for most purposes, the server does only
 * fork for updates (which may require signature checks and lengthy DB
 * operations).
 *
 * see ks-proto.c for the used protocol.
 * see ks-db.c	  for the layout of the database.
 */

#include <config.h>
#include <stdio.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <sys/types.h>
#include <sys/stat.h>

#include "util.h"
#include "cipher.h"
#include "options.h"
#include "main.h"


static ARGPARSE_OPTS opts[] = {
    { 'v', "verbose",   0, "verbose" },
    { 501, "options"   ,2, "read options from file"},
    { 502, "no-daemon", 0, "do not operate as a daemon" },
    { 510, "debug"     ,4|16, "set debugging flags"},
    { 511, "debug-all" ,0, "enable full debugging"},
{0} };



static char *build_list( const char *text,
			 const char * (*mapf)(int), int (*chkf)(int) );
static void become_daemon(void);

const char *
strusage( int level )
{
  static char *digests, *pubkeys, *ciphers;
    const char *p;
    switch( level ) {
      case 11: p = "gpgd (GNUPG)"; break;
      case 13: p = VERSION; break;
      case 17: p = PRINTABLE_OS_NAME; break;
      case 19: p =
	    "Please report bugs to <gnupg-bugs@gnu.org>.\n";
	break;
      case 1:
      case 40:	p = "Usage: gpgd [options] (-h for help)";
	break;
      case 41:	p = "Syntax: gpgd [options] [files]\n"
		    "GNUPG keyserver\n";
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


int
main( int argc, char **argv )
{
    ARGPARSE_ARGS pargs;
    int orig_argc;
    char **orig_argv;
    FILE *configfp = NULL;
    char *configname = NULL;
    unsigned configlineno;
    int parse_debug = 0;
    int default_config =1;
    int daemon = 1;

    secmem_init( 0 );	   /* disable use of secmem */
    log_set_name("gpgd");
    log_set_pid( getpid() );
    opt.compress = -1; /* defaults to standard compress level */
    opt.batch = 1;

    /* check whether we have a config file on the commandline */
    orig_argc = argc;
    orig_argv = argv;
    pargs.argc = &argc;
    pargs.argv = &argv;
    pargs.flags=  1;  /* do not remove the args */
    while( arg_parse( &pargs, opts) ) {
	if( pargs.r_opt == 510 || pargs.r_opt == 511 )
	    parse_debug++;
	else if( pargs.r_opt == 501 ) {
	    /* yes there is one, so we do not try the default one, but
	     * read the option file when it is encountered at the commandline
	     */
	    default_config = 0;
	}
    }

    if( default_config )
	configname = make_filename("/etc/gpgd.conf", NULL );

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
		    log_info("note: no default option file `%s'\n",
							    configname );
	    }
	    else {
		log_error("option file `%s': %s\n",
				    configname, strerror(errno) );
		g10_exit(1);
	    }
	    m_free(configname); configname = NULL;
	}
	if( parse_debug && configname )
	    log_info("reading options from `%s'\n", configname );
	default_config = 0;
    }

    while( optfile_parse( configfp, configname, &configlineno,
						&pargs, opts) ) {
	switch( pargs.r_opt ) {
	  case 'v': opt.verbose++; break;
	  case 501:
	    if( !configfp ) {
		m_free(configname);
		configname = m_strdup(pargs.r.ret_str);
		goto next_pass;
	    }
	    break;
	  case 502: daemon = 0; break;
	  case 510: opt.debug |= pargs.r.ret_ulong; break;
	  case 511: opt.debug = ~0; break;
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

    fprintf(stderr, "%s %s; %s\n", strusage(11), strusage(13), strusage(14) );
    fprintf(stderr, "%s\n", strusage(15) );

    set_debug();
    if( daemon )
	become_daemon();


    g10_exit(0);
    return 8; /*NEVER REACHED*/
}


void
g10_exit( int rc )
{
    secmem_term();
    rc = rc? rc : log_get_errorcount(0)? 2:0;
    exit(rc );
}


static void
become_daemon()
{
    long nfile;
    int i, n;
    int childpid;

    if( opt.verbose )
	log_info("becoming a daemon ...\n");
    fflush(NULL);

    /* FIXME: handle the TTY signals */

    if( (childpid = fork()) == -1 )
	log_fatal("can't fork first child: %s\n", strerror(errno));
    else if( childpid > 0 )
	exit(0); /* terminate parent */

    /* Disassociate from controlling terminal etc. */
    if( setsid() == -1 )
	log_fatal("setsid() failed: %s\n", strerror(errno) );

    log_set_pid( getpid() );
    /* close all files but not the log files */
    if( (nfile=sysconf( _SC_OPEN_MAX )) < 0 )
      #ifdef _POSIX_OPEN_MAX
	nfile = _POSIX_OPEN_MAX;
      #else
	nfile = 20; /* assume a common value */
      #endif
    n = fileno( stderr );
    for(i=0; i < nfile; i++ )
	if( i != n )
	    close(i);
    errno = 0;

    if( chdir("/") )
	log_fatal("chdir to root failed: %s\n", strerror(errno) );
    umask(0);

    /* do not let possible children become zombies */
    signal(SIGCHLD, SIG_IGN);
    if( opt.verbose )
	log_info("now running as daemon\n");
}



