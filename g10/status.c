/* status.c
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
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#ifdef USE_SHM_COPROCESSING
  #ifdef HAVE_SYS_IPC_H
    #include <sys/ipc.h>
  #endif
  #ifdef HAVE_SYS_SHM_H
    #include <sys/shm.h>
  #endif
#endif
#include "util.h"
#include "status.h"
#include "ttyio.h"
#include "options.h"
#include "main.h"
#include "i18n.h"

static int fd = -1;
#ifdef USE_SHM_COPROCESSING
  static int shm_id = -1;
  static volatile char *shm_area;
  static size_t shm_size;
  static int shm_is_locked;
#endif /*USE_SHM_COPROCESSING*/

void
set_status_fd ( int newfd )
{
    fd = newfd;
}


void
write_status ( int no )
{
    write_status_text( no, NULL );
}

void
write_status_text ( int no, const char *text)
{
    const char *s;

    if( fd == -1 )
	return;  /* not enabled */

    switch( no ) {
      case STATUS_ENTER  : s = "ENTER\n"; break;
      case STATUS_LEAVE  : s = "LEAVE\n"; break;
      case STATUS_ABORT  : s = "ABORT\n"; break;
      case STATUS_GOODSIG: s = "GOODSIG\n"; break;
      case STATUS_SIGEXPIRED: s = "SIGEXPIRED\n"; break;
      case STATUS_KEYREVOKED: s = "KEYREVOKED\n"; break;
      case STATUS_BADSIG : s = "BADSIG\n"; break;
      case STATUS_ERRSIG : s = "ERRSIG\n"; break;
      case STATUS_BADARMOR : s = "BADARMOR\n"; break;
      case STATUS_RSA_OR_IDEA : s= "RSA_OR_IDEA\n"; break;
      case STATUS_TRUST_UNDEFINED: s = "TRUST_UNDEFINED\n"; break;
      case STATUS_TRUST_NEVER	 : s = "TRUST_NEVER\n"; break;
      case STATUS_TRUST_MARGINAL : s = "TRUST_MARGINAL\n"; break;
      case STATUS_TRUST_FULLY	 : s = "TRUST_FULLY\n"; break;
      case STATUS_TRUST_ULTIMATE : s = "TRUST_ULTIMATE\n"; break;
      case STATUS_SHM_INFO	 : s = "SHM_INFO\n"; break;
      case STATUS_SHM_GET	 : s = "SHM_GET\n"; break;
      case STATUS_SHM_GET_BOOL	 : s = "SHM_GET_BOOL\n"; break;
      case STATUS_SHM_GET_HIDDEN : s = "SHM_GET_HIDDEN\n"; break;
      case STATUS_NEED_PASSPHRASE: s = "NEED_PASSPHRASE\n"; break;
      default: s = "?\n"; break;
    }

    write( fd, "[GNUPG:] ", 9 );
    if( text ) {
	write( fd, s, strlen(s)-1 );
	write( fd, " ", 1 );
	write( fd, text, strlen(text) );
	write( fd, "\n", 1 );
    }
    else
	write( fd, s, strlen(s) );
}


#ifdef USE_SHM_COPROCESSING
void
init_shm_coprocessing ( ulong requested_shm_size, int lock_mem )
{
    char buf[100];

    requested_shm_size = (requested_shm_size + 4095) & ~4095;
    if ( requested_shm_size > 2 * 4096 )
	log_fatal("too much shared memory requested; only 8k are allowed\n");
    shm_size = 4096 /* one page for us */ + requested_shm_size;

    shm_id = shmget( IPC_PRIVATE, shm_size, IPC_CREAT | 0700 );
    if ( shm_id == -1 )
	log_fatal("can't get %uk of shared memory: %s\n",
				(unsigned)shm_size/1024, strerror(errno));
    shm_area = shmat( shm_id, 0, 0 );
    if ( shm_area == (char*)-1 )
	log_fatal("can't attach %uk shared memory: %s\n",
				(unsigned)shm_size/1024, strerror(errno));
    log_info("mapped %uk shared memory at %p, id=%d\n",
			    (unsigned)shm_size/1024, shm_area, shm_id );
    if( lock_mem ) {
	if ( shmctl (shm_id, SHM_LOCK, 0) )
	    log_info("Locking shared memory %d failed: %s\n",
				shm_id, strerror(errno));
	else
	    shm_is_locked = 1;
    }

  #ifdef IPC_RMID_DEFERRED_RELEASE
    if ( shmctl ( shm_id, IPC_RMID, 0) )
	log_fatal("shmctl IPC_RMDID of %d failed: %s\n",
					    shm_id, strerror(errno));
  #else
    #error Must add a cleanup function
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

static void
display_help( const char *keyword )
{
    char *p;
    int hint = 0;

    tty_kill_prompt();
    if( !keyword ) {
	tty_printf(_("No help available") );
	hint++;
    }
    else {
	p = _(keyword);
	if( !strcmp( p, keyword ) ) {
	    tty_printf(_("No help available for '%s'"), keyword );
	    hint++;
	}
	else
	    tty_printf("%s", p );
    }
    tty_printf("\n");
    if( hint )
	tty_printf("You should set your LANG variable to a valid value.\n"
		   "Set LANG to \"en\" to see the English help texts.\n" );
}


int
cpr_enabled()
{
  #ifdef USE_SHM_COPROCESSING
    if( opt.shm_coprocess )
	return 1;
  #endif
    return 0;
}

char *
cpr_get( const char *keyword, const char *prompt )
{
    char *p;

  #ifdef USE_SHM_COPROCESSING
    if( opt.shm_coprocess )
	return do_shm_get( keyword, 0, 0 );
  #endif
    for(;;) {
	p = tty_get( prompt );
	if( *p == '?' && !p[1] ) {
	    m_free(p);
	    display_help( keyword );
	}
	else
	    return p;
    }
}

char *
cpr_get_hidden( const char *keyword, const char *prompt )
{
    char *p;

  #ifdef USE_SHM_COPROCESSING
    if( opt.shm_coprocess )
	return do_shm_get( keyword, 1, 0 );
  #endif
    for(;;) {
	p = tty_get_hidden( prompt );
	if( *p == '?' && !p[1] ) {
	    m_free(p);
	    display_help( keyword );
	}
	else
	    return p;
    }
}

void
cpr_kill_prompt(void)
{
  #ifdef USE_SHM_COPROCESSING
    if( opt.shm_coprocess )
	return;
  #endif
    return tty_kill_prompt();
}

int
cpr_get_answer_is_yes( const char *keyword, const char *prompt )
{
  #ifdef USE_SHM_COPROCESSING
    if( opt.shm_coprocess )
	return !!do_shm_get( keyword, 0, 1 );
  #endif
    return tty_get_answer_is_yes( prompt );
}

