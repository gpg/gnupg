/* card-util.c - Utility functions for the OpenPGP card.
 *	Copyright (C) 2003 Free Software Foundation, Inc.
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
#include <string.h>
#include <errno.h>
#include <assert.h>

#include "gpg.h"
#include "util.h"
#include "i18n.h"
#include "options.h"
#include "main.h"
#include "call-agent.h"


/* Change the PIN of a an OpenPGP card.  This is an interactive
   function. */
void
change_pin (int chvno)
{
  struct agent_card_info_s info;
  int rc;
  int reset_mode = 0;

  rc = agent_learn (&info);
  if (rc)
    {
      log_error (_("OpenPGP card not available: %s\n"),
                  gpg_strerror (rc));
      return;
    }
  
  log_info (_("OpenPGP card no. %s detected\n"),
              info.serialno? info.serialno : "[none]");

  agent_release_card_info (&info);

  if (opt.batch)
    {
      log_error (_("sorry, can't do this in batch mode\n"));
      return;
    }

  for (;;)
    {
      char *answer;
      int reread = 0;

      tty_printf ("\n");
      tty_printf ("1 - change signature PIN\n"
                  "2 - change decryption and authentication PIN\n"
                  "3 - change Admin's PIN\n"
                  "R - toggle reset retry counter mode\n"
                  "Q - quit\n");
      tty_printf ("\n");
      if (reset_mode)
        {
          tty_printf ("Reset Retry Counter mode active\n");
          tty_printf ("\n");
        }

      answer = cpr_get("cardutil.change_pin.menu",_("Your selection? "));
      cpr_kill_prompt();
      if (strlen (answer) != 1)
        continue;

      rc = 0;
      if (reset_mode && *answer == '3')
        {
          tty_printf ("Sorry, reset of the Admin PIN's retry counter "
                      "is not possible.\n");
        }
      else if (*answer == '1'  || *answer == '2' || *answer == '3')
        {
          rc = agent_scd_change_pin (*answer - '0' + (reset_mode?100:0));
          if (rc)
            tty_printf ("Error changing/resetting the PIN: %s\n",
                        gpg_strerror (rc));
          else
            tty_printf ("New PIN successfully set.\n");
        }
      else if (*answer == 'r' || *answer == 'R')
        {
          reset_mode = !reset_mode;
        }
      else if (*answer == 'q' || *answer == 'Q')
        {
          break;
        }
    }

}





