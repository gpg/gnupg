/* g10.c - The G10 re-install utility
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
#include <stdio.h>
#include <stdlib.h>

#include "packet.h"
#include "iobuf.h"
#include "memory.h"
#include "util.h"
#include "main.h"
#include "options.h"
#include "keydb.h"
#include "mpi.h"
#include "cipher.h"


const char *
strusage( int level )
{
    const char *p;
    switch( level ) {
      case 10:
      case 0:	p = "g10 - v" VERSION "; "
		    "Copyright 1997 Werner Koch (dd9jn)" ; break;
      case 13:	p = "g10"; break;
      case 14:	p = VERSION; break;
      case 1:
      case 11:	p = "Usage: g10 [options] [files] (-h for help)";
		break;
      case 2:
      case 12:	p =
    "\nSyntax: g10 [options] [files]\n"
    "sign, check, encrypt or decrypt\n"
    "default operation depends on the input data\n"
  #ifndef HAVE_RSA_CIPHER
    "This version does not support RSA!\n"
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
}


int
main( int argc, char **argv )
{
    static ARGPARSE_OPTS opts[] = {
    { 'a', "armor",     0, "create ascii armored output"},
    { 'v', "verbose",   0, "verbose" },
    { 'z', NULL,        1, "set compress level (0 disables)" },
    { 'b', "batch",     0, "batch mode: never ask" },
    { 'n', "dry-run",   0, "don't make any changes" },
    { 'c', "symmetric", 0, "do only a symmetric encryption" },
    { 'o', "output",    2, "use as output file" },
    { 501, "yes",       0, "assume yes on most questions"},
    { 502, "no",        0, "assume no on most questions"},
    { 503, "make-key",  0, "generate a new key pair" },
    { 504, "add-key",   0, "add key to the public keyring" },
    { 505, "delete-key",0, "remove key from public keyring" },
    { 506, "sign-key"  ,0, "make a signature on a key in the keyring" },
    { 507, "store",     0, "store only" },
    { 508, "check-key" ,0, "check signatures on a key in the keyring" },
    { 509, "keyring"   ,2, "add this keyring to the list of keyrings" },
    { 's', "sign",      0, "make a signature"},
    { 'e', "encrypt",   0, "encrypt data" },
    { 'd', "decrypt",   0, "decrypt data (default)" },
    { 'c', "check",     0, "check a signature (default)" },
    { 'l', "local-user",2, "use this user-id to sign or decrypt" },
    { 'r', "remote-user", 2, "use this user-id for encryption" },
    { 510, "debug"     ,4|16, "set debugging flags" },
    { 511, "debug-all" ,0, "enable full debugging"},
    { 512, "cache-all" ,0, "hold everything in memory"},
    { 513, "gen-prime" , 1, "generate a prime of length n" },
    { 514, "gen-key"   , 0, "generate a key pair" },
    {0} };
    ARGPARSE_ARGS pargs = { &argc, &argv, 0 };
    IOBUF a;
    int rc;
    enum { aNull, aSym, aStore, aEncr, aPrimegen, aKeygen,
    } action = aNull;
    const char *fname, *fname_print;
    STRLIST sl, remusr= NULL;
    int nrings=0;

    opt.compress = -1; /* defaults to default compression level */
    while( arg_parse( &pargs, opts) ) {
	switch( pargs.r_opt ) {
	  case 'v': opt.verbose++; break;
	  case 'z':
	    opt.compress = pargs.r.ret_int;
	    break;
	  case 'a': opt.armor = 1; break;
	  case 'c': action = aSym; break;
	  case 'e': action = aEncr; break;
	  case 'o': opt.outfile = pargs.r.ret_str;
		    if( opt.outfile[0] == '-' && !opt.outfile[1] )
			opt.outfile_is_stdout = 1;
		    break;
	  case 'b': opt.batch = 1; break;
	  case 501: opt.answer_yes = 1; break;
	  case 502: opt.answer_no = 1; break;
	  case 507: action = aStore; break;
	  case 508: opt.check_sigs = 1; break;
	  case 509: add_keyring(pargs.r.ret_str); nrings++; break;
	  case 510: opt.debug |= pargs.r.ret_ulong; break;
	  case 511: opt.debug = ~0; break;
	  case 512: opt.cache_all = 1; break;
	  case 'r': /* store the remote users */
	    sl = m_alloc( sizeof *sl + strlen(pargs.r.ret_str));
	    strcpy(sl->d, pargs.r.ret_str);
	    sl->next = remusr;
	    remusr = sl;
	    break;
	  case 513: action = aPrimegen; break;
	  case 514: action = aKeygen; break;
	  default : pargs.err = 2; break;
	}
    }
    set_debug();
    if( opt.verbose > 1 )
	set_packet_list_mode(1);

    if( !nrings ) { /* add default rings */
	add_keyring("../keys/ring.pgp");
	add_keyring("../keys/pubring.g10");
    }

    if( argc ) {
	fname_print = fname = *argv;
    }
    else {
	fname_print = "[stdin]";
	fname = NULL;
    }

    switch( action ) {
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
	    log_error("encode_symmetric('%s'): %s\n",
				    fname_print, g10_errstr(rc) );
	break;

      case aEncr: /* encrypt the given file */
	if( argc > 1 )
	    usage(1);
	if( (rc = encode_crypt(fname,remusr)) )
	    log_error("encode_crypt('%s'): %s\n",
				    fname_print, g10_errstr(rc) );
	break;

      case aPrimegen:
	if( argc )
	    usage(1);
	mpi_print( stdout, generate_random_prime( pargs.r.ret_int ), 1);
	putchar('\n');
	break;

      case aKeygen: /* generate a key (interactive) */
	if( argc )
	    usage(1);
	generate_keypair();
	break;

      default:
	if( argc > 1 )
	    usage(1);
	if( !(a = iobuf_open(fname)) )
	    log_fatal("can't open '%s'\n", fname_print);
	proc_packets( a );
	iobuf_close(a);
	break;
    }

    /* cleanup */
    FREE_STRLIST(remusr);
    return 0;
}


