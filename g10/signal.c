/* signal.c - signal handling
 *	Copyright (C) 1998 Free Software Foundation, Inc.
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
#include <signal.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <assert.h>

#include "options.h"
#include "errors.h"
#include "memory.h"
#include "util.h"
#include "main.h"
#include "ttyio.h"


static volatile int caught_fatal_sig = 0;
static volatile int caught_sigusr1 = 0;

static const char *
signal_name( int signum )
{
  #if defined(SYS_SIGLIST_DECLARED) && defined(NSIG)
    return (signum >= 0 && signum < NSIG) ? sys_siglist[signum] : "?";
  #else
    static char buf[20];
    sprintf(buf, "signal %d", signum );
    return buf;
  #endif
}

static RETSIGTYPE
got_fatal_signal( int sig )
{
    if( caught_fatal_sig )
	raise( sig );
    caught_fatal_sig = 1;

    fprintf( stderr, "\n%s: %s caught ... exiting\n",
	      log_get_name(), signal_name(sig) );
    secmem_term();
    exit( 8 );
}


static RETSIGTYPE
got_usr_signal( int sig )
{
    caught_sigusr1 = 1;
}

#ifndef HAVE_DOSISH_SYSTEM
static void
do_sigaction( int sig, struct sigaction *nact )
{
    struct sigaction oact;

    sigaction( sig, NULL, &oact );
    if( oact.sa_handler != SIG_IGN )
	sigaction( sig, nact, NULL);
}
#endif

void
init_signals()
{
  #ifndef HAVE_DOSISH_SYSTEM
    struct sigaction nact;

    nact.sa_handler = got_fatal_signal;
    sigemptyset( &nact.sa_mask );
    nact.sa_flags = 0;

    do_sigaction( SIGINT, &nact );
    do_sigaction( SIGHUP, &nact );
    do_sigaction( SIGTERM, &nact );
    do_sigaction( SIGQUIT, &nact );
    do_sigaction( SIGSEGV, &nact );
    nact.sa_handler = got_usr_signal;
    sigaction( SIGUSR1, &nact, NULL );
    nact.sa_handler = SIG_IGN;
    sigaction( SIGPIPE, &nact, NULL );
  #endif
}


void
pause_on_sigusr( int which )
{
  #ifndef HAVE_DOSISH_SYSTEM
    sigset_t mask, oldmask;

    assert( which == 1 );
    sigemptyset( &mask );
    sigaddset( &mask, SIGUSR1 );

    sigprocmask( SIG_BLOCK, &mask, &oldmask );
    while( !caught_sigusr1 )
	sigsuspend( &oldmask );
    caught_sigusr1 = 0;
    sigprocmask( SIG_UNBLOCK, &mask, NULL );
  #endif
}


static void
do_block( int block )
{
  #ifndef HAVE_DOSISH_SYSTEM
    static int is_blocked;
    static sigset_t oldmask;

    if( block ) {
	sigset_t newmask;

	if( is_blocked )
	    log_bug("signals are already blocked\n");
	sigfillset( &newmask );
	sigprocmask( SIG_BLOCK, &newmask, &oldmask );
	is_blocked = 1;
    }
    else {
	if( !is_blocked )
	    log_bug("signals are not blocked\n");
	sigprocmask( SIG_SETMASK, &oldmask, NULL );
	is_blocked = 0;
    }
  #endif /*HAVE_DOSISH_SYSTEM*/
}


void
block_all_signals()
{
    do_block(1);
}

void
unblock_all_signals()
{
    do_block(0);
}

