/* signal.c - signal handling
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
  #if SYS_SIGLIST_DECLARED
    return sys_siglist[signum];
  #else
    static char buf[20];
    sprintf( "signal %d", signum );
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


static void
do_sigaction( int sig, struct sigaction *nact )
{
    struct sigaction oact;

    sigaction( sig, NULL, &oact );
    if( oact.sa_handler != SIG_IGN )
	sigaction( sig, nact, NULL);
}

void
init_signals()
{
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
}


void
pause_on_sigusr( int which )
{
    sigset_t mask, oldmask;

    assert( which == 1 );
    sigemptyset( &mask );
    sigaddset( &mask, SIGUSR1 );

    sigprocmask( SIG_BLOCK, &mask, &oldmask );
    while( !caught_sigusr1 )
	sigsuspend( &oldmask );
    caught_sigusr1 = 0;
    sigprocmask( SIG_UNBLOCK, &mask, NULL );
}

