/* signal.c - signal handling
 * Copyright (C) 1998, 1999, 2000, 2001, 2002, 2003, 2004,
 *               2005 Free Software Foundation, Inc.
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
#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <assert.h>
#ifdef HAVE_LIBREADLINE
#include <readline/readline.h>
#include <readline/history.h>
#endif

#include "options.h"
#include "errors.h"
#include "memory.h"
#include "util.h"
#include "main.h"
#include "ttyio.h"

#ifdef HAVE_DOSISH_SYSTEM
void init_signals(void) {}
void pause_on_sigusr(int which) {}
#else
static volatile int caught_fatal_sig = 0;
static volatile int caught_sigusr1 = 0;

static void
init_one_signal (int sig, RETSIGTYPE (*handler)(int), int check_ign )
{
#if defined(HAVE_SIGACTION) && defined(HAVE_STRUCT_SIGACTION)
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
}

static RETSIGTYPE
got_fatal_signal( int sig )
{
    const char *s;

    if( caught_fatal_sig )
	raise( sig );
    caught_fatal_sig = 1;

    secmem_term();

#ifdef HAVE_LIBREADLINE
    rl_free_line_state ();
    rl_cleanup_after_signal ();
#endif

    /* Better don't translate these messages. */
    write(2, "\n", 1 );
    s = log_get_name(); if( s ) write(2, s, strlen(s) );
    write(2, ": ", 2 );

#if HAVE_DECL_SYS_SIGLIST && defined(NSIG)
    s = (sig >= 0 && sig < NSIG) ? sys_siglist[sig] : "?";
    write (2, s, strlen(s) );
#else
    write (2, "signal ", 7 );
    if (sig < 0 || sig >=100)
        write (2, "?", 1);
    else {
        if (sig >= 10)
            write (2, "0123456789"+(sig/10), 1 );
        write (2, "0123456789"+(sig%10), 1 );
    }
#endif
    write(2, " caught ... exiting\n", 20 );

    /* Reset action to default action and raise signal again. */
    init_one_signal (sig, SIG_DFL, 0);
    remove_lockfiles ();
#ifdef __riscos__
    riscos_close_fds ();
#endif /* __riscos__ */
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
    init_one_signal (SIGINT, got_fatal_signal, 1 );
    init_one_signal (SIGHUP, got_fatal_signal, 1 );
    init_one_signal (SIGTERM, got_fatal_signal, 1 );
    init_one_signal (SIGQUIT, got_fatal_signal, 1 );
    init_one_signal (SIGSEGV, got_fatal_signal, 1 );
    init_one_signal (SIGUSR1, got_usr_signal, 0 );
    init_one_signal (SIGPIPE, SIG_IGN, 0 );
}


void
pause_on_sigusr( int which )
{
#if defined(HAVE_SIGPROCMASK) && defined(HAVE_SIGSET_T)
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
     sigrelse(SIGUSR1);
#endif /*! HAVE_SIGPROCMASK && HAVE_SIGSET_T */
}

/* Disabled - see comment in tdbio.c:tdbio_begin_transaction() */
#if 0
static void
do_block( int block )
{
    static int is_blocked;
#if defined(HAVE_SIGPROCMASK) && defined(HAVE_SIGSET_T)
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
#else /*! HAVE_SIGPROCMASK && HAVE_SIGSET_T */

#if defined(NSIG)
#define SIGSMAX (NSIG)
#elif defined(MAXSIG)
#define SIGSMAX (MAXSIG+1)
#else
#error "define SIGSMAX to the number of signals on your platform plus one"
#endif

    static void (*disposition[SIGSMAX])(int);
    int sig;

    if( block ) {
	if( is_blocked )
	    log_bug("signals are already blocked\n");
        for (sig=1; sig < SIGSMAX; sig++) {
            disposition[sig] = sigset (sig, SIG_HOLD);
        }
	is_blocked = 1;
    }
    else {
	if( !is_blocked )
	    log_bug("signals are not blocked\n");
        for (sig=1; sig < SIGSMAX; sig++) {
            sigset (sig, disposition[sig]);
        }
	is_blocked = 0;
    }
#endif /*! HAVE_SIGPROCMASK && HAVE_SIGSET_T */
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
#endif

#endif /* !HAVE_DOSISH_SYSTEM */
