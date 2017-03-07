/* g13-common.c - Common code for G13 modules
 * Copyright (C) 2009, 2015 Werner Koch
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
 * along with this program; if not, see <https://www.gnu.org/licenses/>.
 */


#include <config.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <errno.h>
#include <assert.h>

#include "g13-common.h"
#include <gcrypt.h>
#include <assuan.h>
#include "../common/i18n.h"
#include "../common/sysutils.h"



/* Global variable to keep an error count. */
int g13_errors_seen = 0;



/* Note: This function is used by signal handlers!. */
static void
emergency_cleanup (void)
{
  gcry_control (GCRYCTL_TERM_SECMEM);
}


/* Wrapper around gnupg_init_signals.  */
void
g13_init_signals (void)
{
  gnupg_init_signals (0, emergency_cleanup);
}


/* Install a regular exit handler to make real sure that the secure
   memory gets wiped out.  */
void
g13_install_emergency_cleanup (void)
{
  if (atexit (emergency_cleanup))
    {
      log_error ("atexit failed\n");
      g13_exit (2);
    }
}


/* Use this function instead of exit() in all g13 modules.  */
void
g13_exit (int rc)
{
  gcry_control (GCRYCTL_UPDATE_RANDOM_SEED_FILE);
  if (opt.debug & DBG_MEMSTAT_VALUE)
    {
      gcry_control( GCRYCTL_DUMP_MEMORY_STATS );
      gcry_control( GCRYCTL_DUMP_RANDOM_STATS );
    }
  if (opt.debug)
    gcry_control (GCRYCTL_DUMP_SECMEM_STATS );
  emergency_cleanup ();
  rc = rc? rc : log_get_errorcount(0)? 2 : g13_errors_seen? 1 : 0;
  exit (rc);
}
