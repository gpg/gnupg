/* signal.c - signal handling
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

static void
init_one_signal (int sig, RETSIGTYPE (*handler)(int), int check_ign )
{
 #ifndef HAVE_DOSISH_SYSTEM
  #if HAVE_SIGACTION
    struct sigaction oact, nact;

    if (check_ign) {
        /* we don't want to change an IGN handler */
        sigaction (sig, NULL, &oact );
        if (oact.sa_handler == SIG_IGN )
            return;
    }

    nact.sa_handler = handler;
    sigemptyset (&nact.sa_mask);
    nact.sa_flags = 0;
    sigaction ( sig, &nact, NULL);
  #else 
    RETSIGTYPE (*ohandler)(int);

    ohandler = signal (sig, handler);
    if (check_ign && ohandler == SIG_IGN) {
        /* Change it back if it was already set to IGN */
        signal (sig, SIG_IGN);
    }
  #endif
 #endif /*!HAVE_DOSISH_SYSTEM*/
}

static const char *
get_signal_name( int signum )
{
  #if defined(SYS_SIGLIST_DECLARED) && defined(NSIG)
    return (signum >= 0 && signum < NSIG) ? sys_siglist[signum] : "?";
  #else
    return "some signal";
  #endif
}


static RETSIGTYPE
got_fatal_signal( int sig )
{
    const char *s;

    if( caught_fatal_sig )
	raise( sig );
    caught_fatal_sig = 1;

    secmem_term();
    /* better don't transtale these messages */
    write(2, "\n", 1 );
    s = log_get_name(); if( s ) write(2, s, strlen(s) );
    write(2, ": ", 2 );
    s = get_signal_name(sig); write(2, s, strlen(s) );
    write(2, " caught ... exiting\n", 21 );

    /* reset action to default action and raise signal again */
    init_one_signal (sig, SIG_DFL, 0);
    remove_lockfiles ();
    raise( sig );
}


static RETSIGTYPE
got_usr_signal( int sig )
{
    caught_sigusr1 = 1;
}


void
init_signals()
{
  #ifndef HAVE_DOSISH_SYSTEM
    init_one_signal (SIGINT, got_fatal_signal, 1 );
    init_one_signal (SIGHUP, got_fatal_signal, 1 );
    init_one_signal (SIGTERM, got_fatal_signal, 1 );
    init_one_signal (SIGQUIT, got_fatal_signal, 1 );
    init_one_signal (SIGSEGV, got_fatal_signal, 1 );
    init_one_signal (SIGUSR1, got_usr_signal, 0 );
    init_one_signal (SIGPIPE, SIG_IGN, 0 );
  #endif
}


void
pause_on_sigusr( int which )
{
  #ifndef HAVE_DOSISH_SYSTEM
   #ifdef HAVE_SIGPROCMASK
    sigset_t mask, oldmask;

    assert( which == 1 );
    sigemptyset( &mask );
    sigaddset( &mask, SIGUSR1 );

    sigprocmask( SIG_BLOCK, &mask, &oldmask );
    while( !caught_sigusr1 )
	sigsuspend( &oldmask );
    caught_sigusr1 = 0;
    sigprocmask( SIG_UNBLOCK, &mask, NULL );
   #else 
     assert (which == 1);
     sighold (SIGUSR1);
     while (!caught_sigusr1)
         sigpause(SIGUSR1);
     caught_sigusr1 = 0;
     sigrelse(SIGUSR1); ????
   #endif /*!HAVE_SIGPROCMASK*/
  #endif
}


static void
do_block( int block )
{
 #ifndef HAVE_DOSISH_SYSTEM
    static int is_blocked;
  #ifdef HAVE_SIGPROCMASK
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
  #else /*!HAVE_SIGPROCMASK*/
    static void (*disposition[MAXSIG])();
    int sig;

    if( block ) {
	if( is_blocked )
	    log_bug("signals are already blocked\n");
        for (sig=1; sig < MAXSIG; sig++) {
            disposition[sig] = sigset (sig, SIG_HOLD);
        }
	is_blocked = 1;
    }
    else {
	if( !is_blocked )
	    log_bug("signals are not blocked\n");
        for (sig=1; sig < MAXSIG; sig++) {
            sigset (sig, disposition[sig]);
        }
	is_blocked = 0;
    }
  #endif /*!HAVE_SIGPROCMASK*/
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
