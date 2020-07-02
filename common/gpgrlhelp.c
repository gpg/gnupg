/* gpgrlhelp.c - A readline wrapper.
 *	Copyright (C) 2006 Free Software Foundation, Inc.
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


/* Read or write the history to or from the file FILENAME.  The
 * behaviour depends on the flag WRITE_MODE:
 *
 * In read mode (WRITE_MODE is false) these semantics are used:
 *
 *   If NLINES is positive only this number of lines are read from the
 *   history and the history is always limited to that number of
 *   lines.  A negative value for NLINES is undefined.
 *
 *   If FILENAME is NULL the current history is cleared.  If NLINES is
 *   positive the number of lines stored in the history is limited to
 *   that number.  A negative value for NLINES is undefined.
 *
 * If WRITE_MODE is true these semantics are used:
 *
 *   If NLINES is negative the history and the history file are
 *   cleared; if it is zero the entire history is written to the file;
 *   if it is positive the history is written to the file and the file
 *   is truncated to this number of lines.
 *
 *   If FILENAME is NULL no file operations are done but if NLINES is
 *   negative the entire history is cleared.
 *
 * On success 0 is returned; on error -1 is returned and ERRNO is set.
 */
static int
read_write_history (const char *filename, int write_mode, int nlines)
{
  int rc;

  if (write_mode)
    {
      if (nlines < 0)
        clear_history ();
      rc = filename? write_history (filename) : 0;
      if (!rc && filename && nlines > 0)
        rc = history_truncate_file (filename, nlines);
      if (rc)
        {
          gpg_err_set_errno (rc);
          return -1;
        }
    }
  else
    {
      clear_history ();
      if (filename)
        {
          if (nlines)
            rc = read_history_range (filename, 0, nlines);
          else
            rc = read_history (filename);
          if (rc)
            {
              gpg_err_set_errno (rc);
              return -1;
            }
        }
      if (nlines > 0)
        stifle_history (nlines);
    }

  return 0;
}

#endif /*HAVE_LIBREADLINE*/


/* Initialize our readline code.  This should be called as early as
 * possible as it is actually a constructor.  */
void
gnupg_rl_initialize (void)
{
#ifdef HAVE_LIBREADLINE
  tty_private_set_rl_hooks (init_stream,
                            set_completer,
                            inhibit_completion,
                            cleanup_after_signal,
                            readline,
                            add_history,
                            read_write_history);
  rl_readline_name = GNUPG_NAME;
#endif
}
