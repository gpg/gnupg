/* status.c
 * Copyright (C) 1998, 1999, 2000, 2001 Free Software Foundation, Inc.
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
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <signal.h>
#ifdef USE_SHM_COPROCESSING
  #ifdef USE_CAPABILITIES
    #include <sys/capability.h>
  #endif
  #ifdef HAVE_SYS_IPC_H
    #include <sys/types.h>
    #include <sys/ipc.h>
  #endif
  #ifdef HAVE_SYS_SHM_H
    #include <sys/shm.h>
  #endif
  #if defined(HAVE_MLOCK)
    #include <sys/mman.h>
  #endif
#endif
#include "util.h"
#include "status.h"
#include "ttyio.h"
#include "options.h"
#include "main.h"
#include "i18n.h"
#include "cipher.h" /* for progress functions */

#define CONTROL_D ('D' - 'A' + 1)



static FILE *statusfp;

#ifdef USE_SHM_COPROCESSING
  static int shm_id = -1;
  static volatile char *shm_area;
  static size_t shm_size;
  static int shm_is_locked;
#endif /*USE_SHM_COPROCESSING*/


static void
progress_cb ( void *ctx, int c )
{
    char buf[50];

    if ( c == '\n' )
	sprintf ( buf, "%.20s X 100 100", (char*)ctx );
    else
	sprintf ( buf, "%.20s %c 0 0", (char*)ctx, c );
    write_status_text ( STATUS_PROGRESS, buf );
}

static const char *
get_status_string ( int no ) 
{
    const char *s;

    switch( no ) {
      case STATUS_ENTER  : s = "ENTER"; break;
      case STATUS_LEAVE  : s = "LEAVE"; break;
      case STATUS_ABORT  : s = "ABORT"; break;
      case STATUS_GOODSIG: s = "GOODSIG"; break;
      case STATUS_SIGEXPIRED: s = "SIGEXPIRED"; break;
      case STATUS_KEYREVOKED: s = "KEYREVOKED"; break;
      case STATUS_BADSIG : s = "BADSIG"; break;
      case STATUS_ERRSIG : s = "ERRSIG"; break;
      case STATUS_BADARMOR : s = "BADARMOR"; break;
      case STATUS_RSA_OR_IDEA : s= "RSA_OR_IDEA"; break;
      case STATUS_TRUST_UNDEFINED: s = "TRUST_UNDEFINED"; break;
      case STATUS_TRUST_NEVER	 : s = "TRUST_NEVER"; break;
      case STATUS_TRUST_MARGINAL : s = "TRUST_MARGINAL"; break;
      case STATUS_TRUST_FULLY	 : s = "TRUST_FULLY"; break;
      case STATUS_TRUST_ULTIMATE : s = "TRUST_ULTIMATE"; break;
      case STATUS_GET_BOOL	 : s = "GET_BOOL"; break;
      case STATUS_GET_LINE	 : s = "GET_LINE"; break;
      case STATUS_GET_HIDDEN	 : s = "GET_HIDDEN"; break;
      case STATUS_GOT_IT	 : s = "GOT_IT"; break;
      case STATUS_SHM_INFO	 : s = "SHM_INFO"; break;
      case STATUS_SHM_GET	 : s = "SHM_GET"; break;
      case STATUS_SHM_GET_BOOL	 : s = "SHM_GET_BOOL"; break;
      case STATUS_SHM_GET_HIDDEN : s = "SHM_GET_HIDDEN"; break;
      case STATUS_NEED_PASSPHRASE: s = "NEED_PASSPHRASE"; break;
      case STATUS_VALIDSIG	 : s = "VALIDSIG"; break;
      case STATUS_SIG_ID	 : s = "SIG_ID"; break;
      case STATUS_ENC_TO	 : s = "ENC_TO"; break;
      case STATUS_NODATA	 : s = "NODATA"; break;
      case STATUS_BAD_PASSPHRASE : s = "BAD_PASSPHRASE"; break;
      case STATUS_NO_PUBKEY	 : s = "NO_PUBKEY"; break;
      case STATUS_NO_SECKEY	 : s = "NO_SECKEY"; break;
      case STATUS_NEED_PASSPHRASE_SYM: s = "NEED_PASSPHRASE_SYM"; break;
      case STATUS_DECRYPTION_FAILED: s = "DECRYPTION_FAILED"; break;
      case STATUS_DECRYPTION_OKAY: s = "DECRYPTION_OKAY"; break;
      case STATUS_MISSING_PASSPHRASE: s = "MISSING_PASSPHRASE"; break;
      case STATUS_GOOD_PASSPHRASE : s = "GOOD_PASSPHRASE"; break;
      case STATUS_GOODMDC	 : s = "GOODMDC"; break;
      case STATUS_BADMDC	 : s = "BADMDC"; break;
      case STATUS_ERRMDC	 : s = "ERRMDC"; break;
      case STATUS_IMPORTED	 : s = "IMPORTED"; break;
      case STATUS_IMPORT_RES	 : s = "IMPORT_RES"; break;
      case STATUS_FILE_START	 : s = "FILE_START"; break;
      case STATUS_FILE_DONE	 : s = "FILE_DONE"; break;
      case STATUS_FILE_ERROR	 : s = "FILE_ERROR"; break;
      case STATUS_BEGIN_DECRYPTION:s = "BEGIN_DECRYPTION"; break;
      case STATUS_END_DECRYPTION : s = "END_DECRYPTION"; break;
      case STATUS_BEGIN_ENCRYPTION:s = "BEGIN_ENCRYPTION"; break;
      case STATUS_END_ENCRYPTION : s = "END_ENCRYPTION"; break;
      case STATUS_DELETE_PROBLEM : s = "DELETE_PROBLEM"; break;
      case STATUS_PROGRESS	 : s = "PROGRESS"; break;
      case STATUS_SIG_CREATED	 : s = "SIG_CREATED"; break;
      case STATUS_SESSION_KEY	 : s = "SESSION_KEY"; break;
      case STATUS_NOTATION_NAME  : s = "NOTATION_NAME" ; break;
      case STATUS_NOTATION_DATA  : s = "NOTATION_DATA" ; break;
      case STATUS_POLICY_URL     : s = "POLICY_URL" ; break;
      case STATUS_BEGIN_STREAM   : s = "BEGIN_STREAM"; break;
      case STATUS_END_STREAM     : s = "END_STREAM"; break;
      case STATUS_KEY_CREATED    : s = "KEY_CREATED"; break;
      case STATUS_USERID_HINT    : s = "USERID_HINT"; break;
      case STATUS_UNEXPECTED     : s = "UNEXPECTED"; break;
      default: s = "?"; break;
    }
    return s;
}

void
set_status_fd ( int fd )
{
    static int last_fd = -1;

    if ( fd != -1 && last_fd == fd )
        return;

    if ( statusfp && statusfp != stdout && statusfp != stderr )
        fclose (statusfp);
    statusfp = NULL;
    if ( fd == -1 ) 
        return;

    if( fd == 1 )
	statusfp = stdout;
    else if( fd == 2 )
	statusfp = stderr;
    else
	statusfp = fdopen( fd, "w" );
    if( !statusfp ) {
	log_fatal("can't open fd %d for status output: %s\n",
                  fd, strerror(errno));
    }
    last_fd = fd;
    register_primegen_progress ( progress_cb, "primegen" );
    register_pk_dsa_progress ( progress_cb, "pk_dsa" );
    register_pk_elg_progress ( progress_cb, "pk_elg" );
}

int
is_status_enabled()
{
    return !!statusfp;
}

void
write_status ( int no )
{
    write_status_text( no, NULL );
}

void
write_status_text ( int no, const char *text)
{
    if( !statusfp )
	return;  /* not enabled */

    fputs ( "[GNUPG:] ", statusfp );
    fputs ( get_status_string (no), statusfp );
    if( text ) {
        putc ( ' ', statusfp );
        for (; *text; text++) {
            if (*text == '\n')
                fputs ( "\\n", statusfp );
            else if (*text == '\r')
                fputs ( "\\r", statusfp );
            else 
                putc ( *(const byte *)text,  statusfp );
        }
    }
    putc ('\n',statusfp);
    fflush (statusfp);
}


/*
 * Write a status line with a buffer using %XX escapes.  
 * If WRAP is > 0 wrap the line after this length. 
 */
void
write_status_buffer ( int no, const char *buffer, size_t len, int wrap )
{
    const char *s, *text;
    int esc;
    size_t n, count, dowrap;

    if( !statusfp )
	return;  /* not enabled */

    text = get_status_string (no);
    count = dowrap = 1;
    do {
        if (dowrap) {
            fprintf (statusfp, "[GNUPG:] %s ", text );
            count = dowrap = 0;
        }
        for (esc=0, s=buffer, n=len; n && !esc; s++, n-- ) {
            if ( *s == '%' || *(const byte*)s <= ' ' ) 
                esc = 1;
            if ( wrap && ++count > wrap ) {
                dowrap=1;
                break;
            }
        }
        if (esc) {
            s--; n++;
        }
        if (s != buffer) 
            fwrite (buffer, s-buffer, 1, statusfp );
        if ( esc ) {
            fprintf (statusfp, "%%%02X", *(const byte*)s );
            s++; n--;
        }
        buffer = s;
        len = n;
        if ( dowrap && len )
            putc ( '\n', statusfp );
    } while ( len );

    putc ('\n',statusfp);
    fflush (statusfp);
}


#ifdef USE_SHM_COPROCESSING

#ifndef IPC_RMID_DEFERRED_RELEASE
static void
remove_shmid( void )
{
    if( shm_id != -1 ) {
	shmctl ( shm_id, IPC_RMID, 0);
	shm_id = -1;
    }
}
#endif

void
init_shm_coprocessing ( ulong requested_shm_size, int lock_mem )
{
    char buf[100];
    struct shmid_ds shmds;

  #ifndef IPC_RMID_DEFERRED_RELEASE
    atexit( remove_shmid );
  #endif
    requested_shm_size = (requested_shm_size + 4095) & ~4095;
    if ( requested_shm_size > 2 * 4096 )
	log_fatal("too much shared memory requested; only 8k are allowed\n");
    shm_size = 4096 /* one page for us */ + requested_shm_size;

    shm_id = shmget( IPC_PRIVATE, shm_size, IPC_CREAT | 0700 );
    if ( shm_id == -1 )
	log_fatal("can't get %uk of shared memory: %s\n",
				(unsigned)shm_size/1024, strerror(errno));

  #if !defined(IPC_HAVE_SHM_LOCK) \
      && defined(HAVE_MLOCK) && !defined(HAVE_BROKEN_MLOCK)
    /* part of the old code which uses mlock */
    shm_area = shmat( shm_id, 0, 0 );
    if ( shm_area == (char*)-1 )
	log_fatal("can't attach %uk shared memory: %s\n",
				(unsigned)shm_size/1024, strerror(errno));
    log_debug("mapped %uk shared memory at %p, id=%d\n",
			    (unsigned)shm_size/1024, shm_area, shm_id );
    if( lock_mem ) {
      #ifdef USE_CAPABILITIES
	cap_set_proc( cap_from_text("cap_ipc_lock+ep") );
      #endif
	/* (need the cast for Solaris with Sun's workshop compilers) */
	if ( mlock ( (char*)shm_area, shm_size) )
	    log_info("locking shared memory %d failed: %s\n",
				shm_id, strerror(errno));
	else
	    shm_is_locked = 1;
      #ifdef USE_CAPABILITIES
	cap_set_proc( cap_from_text("cap_ipc_lock+p") );
      #endif
    }

  #ifdef IPC_RMID_DEFERRED_RELEASE
    if( shmctl( shm_id, IPC_RMID, 0) )
	log_fatal("shmctl IPC_RMDID of %d failed: %s\n",
					    shm_id, strerror(errno));
  #endif

    if( shmctl( shm_id, IPC_STAT, &shmds ) )
	log_fatal("shmctl IPC_STAT of %d failed: %s\n",
					    shm_id, strerror(errno));
    if( shmds.shm_perm.uid != getuid() ) {
	shmds.shm_perm.uid = getuid();
	if( shmctl( shm_id, IPC_SET, &shmds ) )
	    log_fatal("shmctl IPC_SET of %d failed: %s\n",
						shm_id, strerror(errno));
    }

  #else /* this is the new code which handles the changes in the SHM semantics
	 * introduced with Linux 2.4.  The changes is that we now change the
	 * permissions and then attach to the memory.
	 */

    if( lock_mem ) {
      #ifdef USE_CAPABILITIES
	cap_set_proc( cap_from_text("cap_ipc_lock+ep") );
      #endif
      #ifdef IPC_HAVE_SHM_LOCK
	if ( shmctl (shm_id, SHM_LOCK, 0) )
	    log_info("locking shared memory %d failed: %s\n",
				shm_id, strerror(errno));
	else
	    shm_is_locked = 1;
      #else
	log_info("Locking shared memory %d failed: No way to do it\n", shm_id );
      #endif
      #ifdef USE_CAPABILITIES
	cap_set_proc( cap_from_text("cap_ipc_lock+p") );
      #endif
    }

    if( shmctl( shm_id, IPC_STAT, &shmds ) )
	log_fatal("shmctl IPC_STAT of %d failed: %s\n",
					    shm_id, strerror(errno));
    if( shmds.shm_perm.uid != getuid() ) {
	shmds.shm_perm.uid = getuid();
	if( shmctl( shm_id, IPC_SET, &shmds ) )
	    log_fatal("shmctl IPC_SET of %d failed: %s\n",
						shm_id, strerror(errno));
    }

    shm_area = shmat( shm_id, 0, 0 );
    if ( shm_area == (char*)-1 )
	log_fatal("can't attach %uk shared memory: %s\n",
				(unsigned)shm_size/1024, strerror(errno));
    log_debug("mapped %uk shared memory at %p, id=%d\n",
			    (unsigned)shm_size/1024, shm_area, shm_id );

  #ifdef IPC_RMID_DEFERRED_RELEASE
    if( shmctl( shm_id, IPC_RMID, 0) )
	log_fatal("shmctl IPC_RMDID of %d failed: %s\n",
					    shm_id, strerror(errno));
  #endif

  #endif
    /* write info; Protocol version, id, size, locked size */
    sprintf( buf, "pv=1 pid=%d shmid=%d sz=%u lz=%u", (int)getpid(),
	    shm_id, (unsigned)shm_size, shm_is_locked? (unsigned)shm_size:0 );
    write_status_text( STATUS_SHM_INFO, buf );
}

/****************
 * Request a string from client
 * If bool, returns static string on true (do not free) or NULL for false
 */
static char *
do_shm_get( const char *keyword, int hidden, int bool )
{
    size_t n;
    byte *p;
    char *string;

    if( !shm_area )
	BUG();

    shm_area[0] = 0;  /* msb of length of control block */
    shm_area[1] = 32; /* and lsb */
    shm_area[2] = 1;  /* indicate that we are waiting on a reply */
    shm_area[3] = 0;  /* clear data available flag */

    write_status_text( bool? STATUS_SHM_GET_BOOL :
		       hidden? STATUS_SHM_GET_HIDDEN : STATUS_SHM_GET, keyword );

    do {
	pause_on_sigusr(1);
	if( shm_area[0] || shm_area[1] != 32 || shm_area[2] != 1 )
	    log_fatal("client modified shm control block - abort\n");
    } while( !shm_area[3] );
    shm_area[2] = 0; /* reset request flag */
    p = (byte*)shm_area+32;
    n = p[0] << 8 | p[1];
    p += 2;
    if( n+32+2+1 > 4095 )
	log_fatal("client returns too large data (%u bytes)\n", (unsigned)n );

    if( bool )
	return p[0]? "" : NULL;

    string = hidden? m_alloc_secure( n+1 ) : m_alloc( n+1 );
    memcpy(string, p, n );
    string[n] = 0; /* make sure it is a string */
    if( hidden ) /* invalidate the memory */
	memset( p, 0, n );

    return string;
}

#endif /* USE_SHM_COPROCESSING */

static int
myread(int fd, void *buf, size_t count)
{
    int rc;
    do {
        rc = read( fd, buf, count );
    } while ( rc == -1 && errno == EINTR );
    if ( !rc && count ) {
        static int eof_emmited=0;
        if ( eof_emmited < 3 ) {
            *(char*)buf = CONTROL_D;
            rc = 1;
            eof_emmited++;
        }
        else { /* Ctrl-D not caught - do something reasonable */
          #ifdef HAVE_DOSISH_SYSTEM
            raise (SIGINT);  /* nothing to hangup under DOS */
          #else
            raise (SIGHUP); /* no more input data */
          #endif
        }
    }    
    return rc;
}



/****************
 * Request a string from the client over the command-fd
 * If bool, returns static string on true (do not free) or NULL for false
 */
static char *
do_get_from_fd( const char *keyword, int hidden, int bool )
{
    int i, len;
    char *string;

    write_status_text( bool? STATUS_GET_BOOL :
		       hidden? STATUS_GET_HIDDEN : STATUS_GET_LINE, keyword );

    for( string = NULL, i = len = 200; ; i++ ) {
	if( i >= len-1 ) {
	    char *save = string;
	    len += 100;
	    string = hidden? m_alloc_secure ( len ) : m_alloc ( len );
	    if( save )
		memcpy(string, save, i );
	    else
		i=0;
	}
	/* Hmmm: why not use our read_line function here */
	if( myread( opt.command_fd, string+i, 1) != 1 || string[i] == '\n'  )
            break;
        else if ( string[i] == CONTROL_D ) {
            /* found ETX - cancel the line and return a sole ETX */
            string[0] = CONTROL_D;
            i=1;
            break;
        }
    }
    string[i] = 0;

    write_status( STATUS_GOT_IT );

    if( bool )	 /* Fixme: is this correct??? */
	return string[0] == 'Y' ? "" : NULL;

    return string;
}



int
cpr_enabled()
{
    if( opt.command_fd != -1 )
	return 1;
  #ifdef USE_SHM_COPROCESSING
    if( opt.shm_coprocess )
	return 1;
  #endif
    return 0;
}

char *
cpr_get_no_help( const char *keyword, const char *prompt )
{
    char *p;

    if( opt.command_fd != -1 )
	return do_get_from_fd ( keyword, 0, 0 );
  #ifdef USE_SHM_COPROCESSING
    if( opt.shm_coprocess )
	return do_shm_get( keyword, 0, 0 );
  #endif
    for(;;) {
	p = tty_get( prompt );
        return p;
    }
}

char *
cpr_get( const char *keyword, const char *prompt )
{
    char *p;

    if( opt.command_fd != -1 )
	return do_get_from_fd ( keyword, 0, 0 );
  #ifdef USE_SHM_COPROCESSING
    if( opt.shm_coprocess )
	return do_shm_get( keyword, 0, 0 );
  #endif
    for(;;) {
	p = tty_get( prompt );
	if( *p=='?' && !p[1] && !(keyword && !*keyword)) {
	    m_free(p);
	    display_online_help( keyword );
	}
	else
	    return p;
    }
}


char *
cpr_get_utf8( const char *keyword, const char *prompt )
{
    char *p;
    p = cpr_get( keyword, prompt );
    if( p ) {
	char *utf8 = native_to_utf8( p );
	m_free( p );
	p = utf8;
    }
    return p;
}

char *
cpr_get_hidden( const char *keyword, const char *prompt )
{
    char *p;

    if( opt.command_fd != -1 )
	return do_get_from_fd ( keyword, 1, 0 );
  #ifdef USE_SHM_COPROCESSING
    if( opt.shm_coprocess )
	return do_shm_get( keyword, 1, 0 );
  #endif
    for(;;) {
	p = tty_get_hidden( prompt );
	if( *p == '?' && !p[1] ) {
	    m_free(p);
	    display_online_help( keyword );
	}
	else
	    return p;
    }
}

void
cpr_kill_prompt(void)
{
    if( opt.command_fd != -1 )
	return;
  #ifdef USE_SHM_COPROCESSING
    if( opt.shm_coprocess )
	return;
  #endif
    tty_kill_prompt();
    return;
}

int
cpr_get_answer_is_yes( const char *keyword, const char *prompt )
{
    int yes;
    char *p;

    if( opt.command_fd != -1 )
	return !!do_get_from_fd ( keyword, 0, 1 );
  #ifdef USE_SHM_COPROCESSING
    if( opt.shm_coprocess )
	return !!do_shm_get( keyword, 0, 1 );
  #endif
    for(;;) {
	p = tty_get( prompt );
	trim_spaces(p); /* it is okay to do this here */
	if( *p == '?' && !p[1] ) {
	    m_free(p);
	    display_online_help( keyword );
	}
	else {
	    tty_kill_prompt();
	    yes = answer_is_yes(p);
	    m_free(p);
	    return yes;
	}
    }
}

int
cpr_get_answer_yes_no_quit( const char *keyword, const char *prompt )
{
    int yes;
    char *p;

    if( opt.command_fd != -1 )
	return !!do_get_from_fd ( keyword, 0, 1 );
  #ifdef USE_SHM_COPROCESSING
    if( opt.shm_coprocess )
	return !!do_shm_get( keyword, 0, 1 );
  #endif
    for(;;) {
	p = tty_get( prompt );
	trim_spaces(p); /* it is okay to do this here */
	if( *p == '?' && !p[1] ) {
	    m_free(p);
	    display_online_help( keyword );
	}
	else {
	    tty_kill_prompt();
	    yes = answer_is_yes_no_quit(p);
	    m_free(p);
	    return yes;
	}
    }
}

