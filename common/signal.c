/* signal.c - signal handling
 * Copyright (C) 1998, 1999, 2000, 2001, 2002,
 *               2005 Free Software Foundation, Inc.
 *
 * This file is part of GnuPG.
 *
 * This file is free software; you can redistribute it and/or modify
 * it under the terms of either
 *
 *   - the GNU Lesser General Public License as published by the Free
 *     Software Foundation; either version 3 of the License, or (at
 *     your option) any later version.
 *
 * or
 *
 *   - the GNU General Public License as published by the Free
 *     Software Foundation; either version 2 of the License, or (at
 *     your option) any later version.
 *
 * or both in parallel, as here.
 *
 * This file is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, see <https://www.gnu.org/licenses/>.
 */

#include <config.h>
#include <stdio.h>
#include <stdlib.h>
#ifdef HAVE_SIGNAL_H
# include <signal.h>
#endif
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <assert.h>

#include "util.h"


#ifndef HAVE_DOSISH_SYSTEM
static volatile int caught_fatal_sig;
static volatile int caught_sigusr1;
#endif
static void (*cleanup_fnc)(void);


#ifndef HAVE_DOSISH_SYSTEM
static void
init_one_signal (int sig, void (*handler)(int), int check_ign )
{
# ifdef HAVE_SIGACTION
  struct sigaction oact, nact;

  if (check_ign)
    {
      /* we don't want to change an IGN handler */
      sigaction (sig, NULL, &oact );
      if (oact.sa_handler == SIG_IGN )
        return;
    }

  nact.sa_handler = handler;
  sigemptyset (&nact.sa_mask);
  nact.sa_flags = 0;
  sigaction ( sig, &nact, NULL);
# else
  void (*ohandler)(int);

  ohandler = signal (sig, handler);
  if (check_ign && ohandler == SIG_IGN)
    {
      /* Change it back if it was already set to IGN */
      signal (sig, SIG_IGN);
    }
# endif
}
#endif /*!HAVE_DOSISH_SYSTEM*/

#ifndef HAVE_DOSISH_SYSTEM
static const char *
get_signal_name( int signum )
{
  /* Note that we can't use strsignal(), because it is not
     reentrant. */
#if HAVE_SIGDESCR_NP
  return sigdescr_np (signum);
#elif HAVE_DECL_SYS_SIGLIST && defined(NSIG)
  return (signum >= 0 && signum < NSIG) ? sys_siglist[signum] : "?";
#else
  return NULL;
#endif
}
#endif /*!HAVE_DOSISH_SYSTEM*/

#ifndef HAVE_DOSISH_SYSTEM
static void
got_fatal_signal (int sig)
{
  const char *s;

  if (caught_fatal_sig)
    raise (sig);
  caught_fatal_sig = 1;

  if (cleanup_fnc)
    cleanup_fnc ();
  /* Better don't translate these messages. */
  (void)write (2, "\n", 1 );
  s = log_get_prefix (NULL);
  if (s)
    (void)write(2, s, strlen (s));
  (void)write (2, ": signal ", 9 );
  s = get_signal_name(sig);
  if (s)
    (void) write (2, s, strlen(s) );
  else
    {
      /* We are in a signal handler so we can't use any kind of printf
         even not sprintf.  So we use a straightforward algorithm.  We
         got a report that on one particular system, raising a signal
         while in this handler, the parameter SIG get sclobbered and
         things are messed up because we modify its value.  Although
         this is a bug in that system, we will protect against it.  */
      if (sig < 0 || sig >= 100000)
        (void)write (2, "?", 1);
      else
        {
          int i, value, any=0;

          for (value=sig,i=10000; i; i /= 10)
            {
              if (value >= i || ((any || i==1) && !(value/i)))
                {
                  (void)write (2, &"0123456789"[value/i], 1);
                  if ((value/i))
                    any = 1;
                  value %= i;
                }
            }
        }
    }
  (void)write (2, " caught ... exiting\n", 20);

  /* Reset action to default action and raise signal again */
  init_one_signal (sig, SIG_DFL, 0);
  /* Fixme: remove_lockfiles ();*/
#ifdef __riscos__
  close_fds ();
#endif /* __riscos__ */
  raise( sig );
}
#endif /*!HAVE_DOSISH_SYSTEM*/

#ifndef HAVE_DOSISH_SYSTEM
static void
got_usr_signal (int sig)
{
  (void)sig;
  caught_sigusr1 = 1;
}
#endif /*!HAVE_DOSISH_SYSTEM*/

void
gnupg_init_signals (int mode, void (*fast_cleanup)(void))
{
  assert (!mode);

  cleanup_fnc = fast_cleanup;
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


static void
do_block (int block)
{
#ifdef HAVE_DOSISH_SYSTEM
  (void)block;
#else /*!HAVE_DOSISH_SYSTEM*/
  static int is_blocked;
#ifdef HAVE_SIGPROCMASK
  static sigset_t oldmask;

  if (block)
    {
      sigset_t newmask;

      if (is_blocked)
        log_bug ("signals are already blocked\n");
      sigfillset( &newmask );
      sigprocmask( SIG_BLOCK, &newmask, &oldmask );
      is_blocked = 1;
    }
  else
    {
      if (!is_blocked)
        log_bug("signals are not blocked\n");
      sigprocmask (SIG_SETMASK, &oldmask, NULL);
      is_blocked = 0;
    }
#else /*!HAVE_SIGPROCMASK*/
  static void (*disposition[MAXSIG])();
  int sig;

  if (block)
    {
      if (is_blocked)
        log_bug("signals are already blocked\n");
      for (sig=1; sig < MAXSIG; sig++)
        {
          disposition[sig] = sigset (sig, SIG_HOLD);
        }
      is_blocked = 1;
    }
  else
    {
      if (!is_blocked)
        log_bug ("signals are not blocked\n");
      for (sig=1; sig < MAXSIG; sig++) {
        sigset (sig, disposition[sig]);
      }
      is_blocked = 0;
    }
#endif /*!HAVE_SIGPROCMASK*/
#endif /*!HAVE_DOSISH_SYSTEM*/
}


void
gnupg_block_all_signals (void)
{
  do_block(1);
}

void
gnupg_unblock_all_signals (void)
{
  do_block(0);
}
