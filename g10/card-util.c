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
#include "ttyio.h"
#include "status.h"
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

static const char *
get_manufacturer (unsigned int no)
{
  switch (no)
    {
    case 0:
    case 0xffff: return "test card";
    case 0x0001: return "PPC Card Systems";
    default: return "unknown";
    }
}


static void
print_sha1_fpr (FILE *fp, const unsigned char *fpr)
{
  int i;

  if (fpr)
    {
      for (i=0; i < 20 ; i+=2, fpr += 2 )
        {
          if (i == 10 )
            putc (' ', fp);
          fprintf (fp, " %02X%02X", *fpr, fpr[1]);
        }
    }
  else
    fputs (" [none]", fp);
  putc ('\n', fp);
}


static void
print_name (FILE *fp, const char *text, const char *name)
{
  fputs (text, fp);

  if (name && *name)
    print_utf8_string2 (fp, name, strlen (name), '\n');
  else
    fputs (_("[not set]"), fp);
  putc ('\n', fp);
}

static void
print_isoname (FILE *fp, const char *text, const char *name)
{
  fputs (text, fp);

  if (name && *name)
    {
      char *p, *given, *buf = xstrdup (name);

      given = strstr (buf, "<<");
      for (p=buf; *p; p++)
        if (*p == '<')
          *p = ' ';
      if (given && given[2])
        {
          *given = 0;
          given += 2;
          print_utf8_string2 (fp, given, strlen (given), '\n');
          if (*buf)
            putc (' ', fp);
        }
      print_utf8_string2 (fp, buf, strlen (buf), '\n');
      xfree (buf);
    }
  else
    fputs (_("[not set]"), fp);
  putc ('\n', fp);
}


/* Print all available information about the current card. */
void
card_status (FILE *fp)
{
  struct agent_card_info_s info;
  PKT_public_key *pk = xcalloc (1, sizeof *pk);
  int rc;

  rc = agent_learn (&info);
  if (rc)
    {
      log_error (_("OpenPGP card not available: %s\n"),
                  gpg_strerror (rc));
      return;
    }
  
  fprintf (fp, "Application ID ...: %s\n",
         info.serialno? info.serialno : "[none]");
  if (!info.serialno || strncmp (info.serialno, "D27600012401", 12) 
      || strlen (info.serialno) != 32 )
    {
      log_info ("not an OpenPGP card\n");
      agent_release_card_info (&info);
    }
  fprintf (fp, "Version ..........: %.1s%c.%.1s%c\n",
           info.serialno[12] == '0'?"":info.serialno+12,
           info.serialno[13],
           info.serialno[14] == '0'?"":info.serialno+14,
           info.serialno[15]);
  fprintf (fp, "Manufacturer .....: %s\n", 
           get_manufacturer (xtoi_2(info.serialno+16)*256
                             + xtoi_2 (info.serialno+18)));
  fprintf (fp, "Serial number ....: %.8s\n", info.serialno+20);
  
  print_isoname (fp, "Name of cardholder: ", info.disp_name);
  print_name (fp, "Language prefs ...: ", info.disp_lang);
  fprintf (fp,    "Sex ..............: %s\n", info.disp_sex == 1? _("male"):
           info.disp_sex == 2? _("female") : _("unspecified"));
  print_name (fp, "URL of public key : ", info.pubkey_url);
  print_name (fp, "Login data .......: ", info.login_data);
  fprintf (fp,    "Signature PIN ....: %s\n",
           info.chv1_cached? _("cached"): _("not cached"));
  fprintf (fp,    "Max. PIN lengths .: %d %d %d\n",
           info.chvmaxlen[0], info.chvmaxlen[1], info.chvmaxlen[2]);
  fprintf (fp,    "PIN retry counter : %d %d %d\n",
           info.chvretry[0], info.chvretry[1], info.chvretry[2]);
  fputs ("Signature key ....:", fp);
  print_sha1_fpr (fp, info.fpr1valid? info.fpr1:NULL);
  fputs ("Encryption key....:", fp);
  print_sha1_fpr (fp, info.fpr2valid? info.fpr2:NULL);
  fputs ("Authentication key:", fp);
  print_sha1_fpr (fp, info.fpr3valid? info.fpr3:NULL);
  fputs ("General key info..: ", fp); 
  if (info.fpr1valid && !get_pubkey_byfprint (pk, info.fpr1, 20))
    print_pubkey_info (fp, pk);
  else
    fputs ("[none]\n", fp);
  fprintf (fp,    "Signature counter : %lu\n", info.sig_counter);
  
  free_public_key (pk);
  agent_release_card_info (&info);
}










