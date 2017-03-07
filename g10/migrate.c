/* migrate.c - Migrate from earlier GnupG versions.
 * Copyright (C) 2014 Werner Koch
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
#include <errno.h>
#include <unistd.h>

#include "gpg.h"
#include "options.h"
#include "keydb.h"
#include "../common/util.h"
#include "main.h"
#include "call-agent.h"


#ifdef HAVE_DOSISH_SYSTEM
# define V21_MIGRATION_FNAME "gpg-v21-migrated"
#else
# define V21_MIGRATION_FNAME ".gpg-v21-migrated"
#endif


/* Check whether a default secring.gpg from GnuPG < 2.1 exists and
   import it if not yet done.  */
void
migrate_secring (ctrl_t ctrl)
{
  dotlock_t lockhd = NULL;
  char *secring = NULL;
  char *flagfile = NULL;
  char *agent_version = NULL;

  secring = make_filename (gnupg_homedir (), "secring" EXTSEP_S "gpg", NULL);
  if (access (secring, F_OK))
    goto leave; /* Does not exist or is not readable.  */
  flagfile = make_filename (gnupg_homedir (), V21_MIGRATION_FNAME, NULL);
  if (!access (flagfile, F_OK))
    goto leave; /* Does exist - fine.  */

  log_info ("starting migration from earlier GnuPG versions\n");

  lockhd = dotlock_create (flagfile, 0);
  if (!lockhd)
    {
      log_error ("can't allocate lock for '%s': %s\n",
                 flagfile, gpg_strerror (gpg_error_from_syserror ()));
      goto leave;
    }
  if (dotlock_take (lockhd, -1))
    {
      log_error ("can't lock '%s': %s\n",
                 flagfile, gpg_strerror (gpg_error_from_syserror ()));
      dotlock_destroy (lockhd);
      lockhd = NULL;
      goto leave;
    }

  if (!agent_get_version (ctrl, &agent_version))
    {
      if (!gnupg_compare_version (agent_version, "2.1.0"))
        {
          log_error ("error: GnuPG agent version \"%s\" is too old. ",
                     agent_version);
          log_info ("Please make sure that a recent gpg-agent is running.\n");
          log_info ("(restarting the user session may achieve this.)\n");
          log_info ("migration aborted\n");
          xfree (agent_version);
          goto leave;
        }
      xfree (agent_version);
    }
  else
    {
      log_error ("error: GnuPG agent unusable. "
                 "Please check that a GnuPG agent can be started.\n");
      log_error ("migration aborted\n");
      goto leave;
    }

  log_info ("porting secret keys from '%s' to gpg-agent\n", secring);
  if (!import_old_secring (ctrl, secring))
    {
      FILE *fp = fopen (flagfile, "w");
      if (!fp || fclose (fp))
        log_error ("error creating flag file '%s': %s\n",
                   flagfile, gpg_strerror (gpg_error_from_syserror ()));
      else
        log_info ("migration succeeded\n");
    }

 leave:
  if (lockhd)
    {
      dotlock_release (lockhd);
      dotlock_destroy (lockhd);
    }
  xfree (flagfile);
  xfree (secring);
}
