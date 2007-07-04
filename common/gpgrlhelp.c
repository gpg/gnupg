/* gpgrlhelp.c - A readline wrapper.
 *	Copyright (C) 2006 Free Software Foundation, Inc.
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

/* This module may by used by applications to initializes readline
   support.  It is required so that we can have hooks in other parts
   of libcommon without actually requiring to link against
   libreadline.  It works along with ttyio.c which is a proper part of
   libcommon. */

#include <config.h>
#include <stdlib.h>
#include <stddef.h>

#ifdef HAVE_LIBREADLINE
#define GNUPG_LIBREADLINE_H_INCLUDED
#include <stdio.h>
#include <readline/readline.h>
#include <readline/history.h>
#endif

#include "util.h"
#include "common-defs.h"


#ifdef HAVE_LIBREADLINE
static void
set_completer (rl_completion_func_t *completer)
{
  rl_attempted_completion_function = completer;
  rl_inhibit_completion = 0;
}

static void
inhibit_completion (int value)
{
  rl_inhibit_completion = value;
}

static void
cleanup_after_signal (void)
{
  rl_free_line_state ();
  rl_cleanup_after_signal ();
}

static void
init_stream (FILE *fp)
{
  rl_catch_signals = 0;
  rl_instream = rl_outstream = fp;
  rl_inhibit_completion = 1;
}

#endif /*HAVE_LIBREADLINE*/


/* Initialize our readline code.  This should be called as early as
   possible as it is actually a constructur.  */
void
gnupg_rl_initialize (void)
{
#ifdef HAVE_LIBREADLINE
  tty_private_set_rl_hooks (init_stream,
                            set_completer,
                            inhibit_completion,
                            cleanup_after_signal,
                            readline,
                            add_history);
  rl_readline_name = "GnuPG";
#endif
}




