/* gpgv.c - The GnuPG signature verify utility
 * Copyright (C) 1998, 1999, 2000, 2001, 2002, 2005,
 *               2006 Free Software Foundation, Inc.
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
 * along with this program; if not, see <http://www.gnu.org/licenses/>.
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
#ifdef HAVE_LIBREADLINE
#include <stdio.h>
#include <readline/readline.h>
#endif

#define INCLUDED_BY_MAIN_MODULE 1
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
#include "cardglue.h"


enum cmd_and_opt_values { aNull = 0,
    oQuiet	  = 'q',
    oVerbose	  = 'v',
    oBatch	  = 500,
    oKeyring,
    oIgnoreTimeConflict,                      
    oStatusFD,
    oLoggerFD,
    oHomedir,
aTest };


static ARGPARSE_OPTS opts[] = {

    { 301, NULL, 0, N_("@\nOptions:\n ") },

    { oVerbose, "verbose",   0, N_("verbose") },
    { oQuiet,	"quiet",     0, N_("be somewhat more quiet") },
    { oKeyring, "keyring"   ,2, N_("take the keys from this keyring")},
    { oIgnoreTimeConflict, "ignore-time-conflict", 0, 
                           N_("make timestamp conflicts only a warning") },
    { oStatusFD, "status-fd" ,1, N_("|FD|write status info to this FD") },
    { oLoggerFD, "logger-fd",1, "@" },
    { oHomedir, "homedir", 2, "@" },   /* defaults to "~/.gnupg" */

{0} };



int g10_errors_seen = 0;

const char *
strusage( int level )
{
    const char *p;
    switch( level ) {
      case 11: p = "gpgv (GnuPG)";
	break;
      case 13: p = VERSION; break;
      case 17: p = PRINTABLE_OS_NAME; break;
      case 19: p =
	    _("Please report bugs to <gnupg-bugs@gnu.org>.\n");
	break;
      case 1:
      case 40:	p =
	    _("Usage: gpgv [options] [files] (-h for help)");
	break;
      case 41:	p =
	    _("Syntax: gpg [options] [files]\n"
	      "Check signatures against known trusted keys\n");
	break;

      default:	p = default_strusage(level);
    }
    return p;
}




static void
i18n_init(void)
{
#ifdef USE_SIMPLE_GETTEXT
    set_gettext_file (PACKAGE, "Software\\GNU\\GnuPG");
#else
#ifdef ENABLE_NLS
    setlocale( LC_ALL, "" );
    bindtextdomain (PACKAGE, LOCALEDIR);
    textdomain( PACKAGE );
#endif
#endif
}


int
main( int argc, char **argv )
{
    ARGPARSE_ARGS pargs;
    int rc=0;
    STRLIST sl;
    STRLIST nrings=NULL;
    unsigned configlineno;

    log_set_name("gpgv");
    init_signals();
    i18n_init();
    opt.command_fd = -1; /* no command fd */
    opt.pgp2_workarounds = 1;
    opt.keyserver_options.options|=KEYSERVER_AUTO_KEY_RETRIEVE;
    opt.trust_model = TM_ALWAYS;
    opt.batch = 1;

    opt.homedir = default_homedir ();

    tty_no_terminal(1);
    tty_batchmode(1);
    disable_dotlock();

    set_native_charset (NULL); /* Try to auto set the character set */
    
    pargs.argc = &argc;
    pargs.argv = &argv;
    pargs.flags=  1;  /* do not remove the args */
    while( optfile_parse( NULL, NULL, &configlineno, &pargs, opts) ) {
	switch( pargs.r_opt ) {
	  case oQuiet: opt.quiet = 1; break;
          case oVerbose: g10_opt_verbose++;
		  opt.verbose++; opt.list_sigs=1; break;
          case oKeyring: append_to_strlist( &nrings, pargs.r.ret_str); break;
	  case oStatusFD: set_status_fd( pargs.r.ret_int ); break;
	  case oLoggerFD: log_set_logfile( NULL, pargs.r.ret_int ); break;
	  case oHomedir: opt.homedir = pargs.r.ret_str; break;
	  case oIgnoreTimeConflict: opt.ignore_time_conflict = 1; break;
	  default : pargs.err = 2; break;
	}
    }

    if( log_get_errorcount(0) )
	g10_exit(2);

    g10_opt_homedir = opt.homedir;

    if( opt.verbose > 1 )
	set_packet_list_mode(1);

    if( !nrings )  /* no keyring given: use default one */
        keydb_add_resource ("trustedkeys" EXTSEP_S "gpg", 0, 0);
    for(sl = nrings; sl; sl = sl->next )
        keydb_add_resource (sl->d, 0, 0 );
    
    FREE_STRLIST(nrings);
    
    if( (rc = verify_signatures( argc, argv ) ))
        log_error("verify signatures failed: %s\n", g10_errstr(rc) );

    /* cleanup */
    g10_exit(0);
    return 8; /*NEVER REACHED*/
}


void
g10_exit( int rc )
{
    rc = rc? rc : log_get_errorcount(0)? 2 :
			g10_errors_seen? 1 : 0;
    exit(rc );
}


/* Stub:
 * We have to override the trustcheck from pkclist.c becuase 
 * this utility assumes that all keys in the keyring are trustworthy
 */
int
check_signatures_trust( PKT_signature *sig )
{
    return 0;
}

void
read_trust_options(byte *trust_model,ulong *created,ulong *nextcheck,
		   byte *marginals,byte *completes,byte *cert_depth) {}

/* Stub: 
 * We don't have the trustdb , so we have to provide some stub functions
 * instead
 */

int
cache_disabled_value(PKT_public_key *pk)
{
  return 0;
}

void
check_trustdb_stale(void) {}

int
get_validity_info (PKT_public_key *pk, PKT_user_id *uid)
{
    return '?';
}

unsigned int
get_validity (PKT_public_key *pk, PKT_user_id *uid)
{
  return 0;
}

const char *
trust_value_to_string (unsigned int value)
{
  return "err";
}

const char *
uid_trust_string_fixed(PKT_public_key *key,PKT_user_id *uid)
{
  return "err";
}

int
get_ownertrust_info (PKT_public_key *pk)
{
    return '?';
}

unsigned int
get_ownertrust (PKT_public_key *pk)
{
    return TRUST_UNKNOWN;
}


/* Stubs:
 * Because we only work with trusted keys, it does not make sense to
 * get them from a keyserver
 */

struct keyserver_spec *
keyserver_match(struct keyserver_spec *spec) { return NULL; }

int
keyserver_import_keyid( u32 *keyid, void *dummy )
{
    return -1;
}

int
keyserver_import_cert(const char *name) { return -1; }

int
keyserver_import_pka(const char *name,unsigned char *fpr) { return -1; }

int
keyserver_import_name(const char *name,struct keyserver_spec *spec)
{
  return -1;
}

int
keyserver_import_ldap(const char *name) { return -1; }

/* Stub:
 * No encryption here but mainproc links to these functions.
 */
int
get_session_key( PKT_pubkey_enc *k, DEK *dek )
{
    return G10ERR_GENERAL;
}
/* Stub: */
int
get_override_session_key( DEK *dek, const char *string )
{
    return G10ERR_GENERAL;
}
/* Stub: */
int
decrypt_data( void *procctx, PKT_encrypted *ed, DEK *dek )
{
    return G10ERR_GENERAL;
}


/* Stub:
 * No interactive commnds, so we don't need the helptexts
 */
void
display_online_help( const char *keyword )
{
}

/* Stub:
 * We don't use secret keys, but getkey.c links to this
 */
int
check_secret_key( PKT_secret_key *sk, int n )
{
    return G10ERR_GENERAL;
}

/* Stub:
 * No secret key, so no passphrase needed 
 */
DEK *
passphrase_to_dek( u32 *keyid, int pubkey_algo,
		   int cipher_algo, STRING2KEY *s2k, int mode,
                   const char *tmp, int *canceled)
{
  if (canceled)
    *canceled = 0;
  return NULL;
}

struct keyserver_spec *parse_preferred_keyserver(PKT_signature *sig) {return NULL;}
struct keyserver_spec *parse_keyserver_uri(const char *uri,int require_scheme,
                                           const char *configname,
                                           unsigned int configlineno)
{
  return NULL;
}

void free_keyserver_spec(struct keyserver_spec *keyserver) {}

/* Stubs to avoid linking to photoid.c */
void show_photos(const struct user_attribute *attrs,int count,PKT_public_key *pk) {}
int parse_image_header(const struct user_attribute *attr,byte *type,u32 *len) {return 0;}
char *image_type_to_string(byte type,int string) {return NULL;}

#ifdef ENABLE_CARD_SUPPORT
int agent_scd_getattr (const char *name, struct agent_card_info_s *info) {return 0;}
#endif /* ENABLE_CARD_SUPPORT */

/* Stubs to void linking to ../cipher/cipher.c */
int string_to_cipher_algo( const char *string ) { return 0; }
const char *cipher_algo_to_string( int algo ) { return "?";}
void disable_cipher_algo( int algo ) {}
int check_cipher_algo( int algo ) { return -1;}
unsigned int cipher_get_keylen( int algo ) { return 0; }
unsigned int cipher_get_blocksize( int algo ) {return 0;}
CIPHER_HANDLE cipher_open( int algo, int mode, int secure ) { return NULL;}
void cipher_close( CIPHER_HANDLE c ) {}
int cipher_setkey( CIPHER_HANDLE c, byte *key, unsigned keylen ) { return -1;}
void cipher_setiv( CIPHER_HANDLE c, const byte *iv, unsigned ivlen ){}
void cipher_encrypt( CIPHER_HANDLE c, byte *outbuf,
                     byte *inbuf, unsigned nbytes ) {}
void cipher_decrypt( CIPHER_HANDLE c, byte *outbuf,
                     byte *inbuf, unsigned nbytes ) {}
void cipher_sync( CIPHER_HANDLE c ) {}

/* Stubs to avoid linking to ../cipher/random.c */
void random_dump_stats(void) {}
int quick_random_gen( int onoff ) { return -1;}
void randomize_buffer( byte *buffer, size_t length, int level ) {}
int random_is_faked() { return -1;}
byte *get_random_bits( size_t nbits, int level, int secure ) { return NULL;}
void set_random_seed_file( const char *name ) {}
void update_random_seed_file() {}
void fast_random_poll() {}

/* Stubs to avoid linking of ../cipher/primegen.c */
void register_primegen_progress ( void (*cb)( void *, int), void *cb_data ) {}
MPI generate_secret_prime( unsigned  nbits ) { return NULL;}
MPI generate_public_prime( unsigned  nbits ) { return NULL;}
MPI generate_elg_prime( int mode, unsigned pbits, unsigned qbits,
                        MPI g, MPI **ret_factors ) { return NULL;}

/* Do not link to ../cipher/rndlinux.c */
void rndlinux_constructor(void) {}


/* Stubs to avoid linking to ../util/ttyio.c */
int tty_batchmode( int onoff ) { return 0; }
void tty_printf( const char *fmt, ... ) { }
void tty_fprintf (FILE *fp, const char *fmt, ... ) { }
void tty_print_string( const byte *p, size_t n ) { }
void tty_print_utf8_string( const byte *p, size_t n ) {}
void tty_print_utf8_string2( const byte *p, size_t n, size_t max_n ) {}
char *tty_get( const char *prompt ) { return NULL;}
char *tty_get_hidden( const char *prompt ) {return NULL; }
void tty_kill_prompt(void) {}
int tty_get_answer_is_yes( const char *prompt ) {return 0;}
int tty_no_terminal(int onoff) {return 0;}
#ifdef HAVE_LIBREADLINE
void tty_enable_completion(rl_completion_func_t *completer) {}
void tty_disable_completion(void) {}
#endif

/* We do not do any locking, so use these stubs here */
void disable_dotlock(void) {}
DOTLOCK create_dotlock( const char *file_to_lock ) { return NULL; }
void destroy_dotlock (DOTLOCK h) {}
int make_dotlock( DOTLOCK h, long timeout ) { return 0;}
int release_dotlock( DOTLOCK h ) {return 0;}
void remove_lockfiles(void) {}
