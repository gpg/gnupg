/* card-util.c - Utility functions for the OpenPGP card.
 * Copyright (C) 2003-2005, 2009 Free Software Foundation, Inc.
 * Copyright (C) 2003-2005, 2009 Werner Koch
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
#ifdef HAVE_LIBREADLINE
# define GNUPG_LIBREADLINE_H_INCLUDED
# include <readline/readline.h>
#endif /*HAVE_LIBREADLINE*/

#if GNUPG_MAJOR_VERSION != 1
# include "gpg.h"
#endif /*GNUPG_MAJOR_VERSION != 1*/
#include "../common/util.h"
#include "../common/i18n.h"
#include "../common/ttyio.h"
#include "../common/status.h"
#include "options.h"
#include "main.h"
#include "keyserver-internal.h"

#if GNUPG_MAJOR_VERSION == 1
# include "cardglue.h"
#else /*GNUPG_MAJOR_VERSION!=1*/
# include "call-agent.h"
#endif /*GNUPG_MAJOR_VERSION!=1*/

#define CONTROL_D ('D' - 'A' + 1)


static void
write_sc_op_status (gpg_error_t err)
{
  switch (gpg_err_code (err))
    {
    case 0:
      write_status (STATUS_SC_OP_SUCCESS);
      break;
#if GNUPG_MAJOR_VERSION != 1
    case GPG_ERR_CANCELED:
    case GPG_ERR_FULLY_CANCELED:
      write_status_text (STATUS_SC_OP_FAILURE, "1");
      break;
    case GPG_ERR_BAD_PIN:
      write_status_text (STATUS_SC_OP_FAILURE, "2");
      break;
    default:
      write_status (STATUS_SC_OP_FAILURE);
      break;
#endif /* GNUPG_MAJOR_VERSION != 1 */
    }
}


/* Change the PIN of an OpenPGP card.  This is an interactive
   function. */
void
change_pin (int unblock_v2, int allow_admin)
{
  struct agent_card_info_s info;
  int rc;

  rc = agent_scd_learn (&info, 0);
  if (rc)
    {
      log_error (_("OpenPGP card not available: %s\n"),
                  gpg_strerror (rc));
      return;
    }

  log_info (_("OpenPGP card no. %s detected\n"),
              info.serialno? info.serialno : "[none]");

  if (opt.batch)
    {
      agent_release_card_info (&info);
      log_error (_("can't do this in batch mode\n"));
      return;
    }


  if (unblock_v2)
    {
      if (!info.is_v2)
        log_error (_("This command is only available for version 2 cards\n"));
      else if (!info.chvretry[1])
        log_error (_("Reset Code not or not anymore available\n"));
      else
        {
          rc = agent_scd_change_pin (2, info.serialno);
          write_sc_op_status (rc);
          if (rc)
            tty_printf ("Error changing the PIN: %s\n", gpg_strerror (rc));
          else
            tty_printf ("PIN changed.\n");
        }
    }
  else if (!allow_admin)
    {
      rc = agent_scd_change_pin (1, info.serialno);
      write_sc_op_status (rc);
      if (rc)
	tty_printf ("Error changing the PIN: %s\n", gpg_strerror (rc));
      else
        tty_printf ("PIN changed.\n");
    }
  else
    for (;;)
      {
	char *answer;

	tty_printf ("\n");
	tty_printf ("1 - change PIN\n"
		    "2 - unblock PIN\n"
		    "3 - change Admin PIN\n"
                    "4 - set the Reset Code\n"
		    "Q - quit\n");
	tty_printf ("\n");

	answer = cpr_get("cardutil.change_pin.menu",_("Your selection? "));
	cpr_kill_prompt();
	if (strlen (answer) != 1)
	  continue;

	if (*answer == '1')
	  {
            /* Change PIN.  */
	    rc = agent_scd_change_pin (1, info.serialno);
            write_sc_op_status (rc);
	    if (rc)
	      tty_printf ("Error changing the PIN: %s\n", gpg_strerror (rc));
	    else
              tty_printf ("PIN changed.\n");
	  }
	else if (*answer == '2')
	  {
            /* Unblock PIN.  */
	    rc = agent_scd_change_pin (101, info.serialno);
            write_sc_op_status (rc);
	    if (rc)
	      tty_printf ("Error unblocking the PIN: %s\n", gpg_strerror (rc));
	    else
              tty_printf ("PIN unblocked and new PIN set.\n");
          }
	else if (*answer == '3')
	  {
            /* Change Admin PIN.  */
	    rc = agent_scd_change_pin (3, info.serialno);
            write_sc_op_status (rc);
	    if (rc)
	      tty_printf ("Error changing the PIN: %s\n", gpg_strerror (rc));
	    else
              tty_printf ("PIN changed.\n");
	  }
	else if (*answer == '4')
	  {
            /* Set a new Reset Code.  */
	    rc = agent_scd_change_pin (102, info.serialno);
            write_sc_op_status (rc);
	    if (rc)
	      tty_printf ("Error setting the Reset Code: %s\n",
                          gpg_strerror (rc));
	    else
              tty_printf ("Reset Code set.\n");
	  }
	else if (*answer == 'q' || *answer == 'Q')
	  {
	    break;
	  }
      }

  agent_release_card_info (&info);
}


static void
print_sha1_fpr (estream_t fp, const unsigned char *fpr)
{
  int i;

  if (fpr)
    {
      for (i=0; i < 20 ; i+=2, fpr += 2 )
        {
          if (i == 10 )
            tty_fprintf (fp, " ");
          tty_fprintf (fp, " %02X%02X", *fpr, fpr[1]);
        }
    }
  else
    tty_fprintf (fp, " [none]");
  tty_fprintf (fp, "\n");
}


static void
print_sha1_fpr_colon (estream_t fp, const unsigned char *fpr)
{
  int i;

  if (fpr)
    {
      for (i=0; i < 20 ; i++, fpr++)
        es_fprintf (fp, "%02X", *fpr);
    }
  es_putc (':', fp);
}


static void
print_keygrip (estream_t fp, const unsigned char *grp)
{
  int i;

  if (opt.with_keygrip)
    {
      tty_fprintf (fp, "      keygrip ....: ");
      for (i=0; i < 20 ; i++, grp++)
        tty_fprintf (fp, "%02X", *grp);
      tty_fprintf (fp, "\n");
    }
}


static void
print_name (estream_t fp, const char *text, const char *name)
{
  tty_fprintf (fp, "%s", text);

  /* FIXME: tty_printf_utf8_string2 eats everything after and
     including an @ - e.g. when printing an url. */
  if (name && *name)
    {
      if (fp)
        print_utf8_buffer2 (fp, name, strlen (name), '\n');
      else
        tty_print_utf8_string2 (NULL, name, strlen (name), 0);
    }
  else
    tty_fprintf (fp, _("[not set]"));
  tty_fprintf (fp, "\n");
}

static void
print_isoname (estream_t fp, const char *text,
               const char *tag, const char *name)
{
  if (opt.with_colons)
    es_fprintf (fp, "%s:", tag);
  else
    tty_fprintf (fp, "%s", text);

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
          if (opt.with_colons)
            es_write_sanitized (fp, given, strlen (given), ":", NULL);
          else if (fp)
            print_utf8_buffer2 (fp, given, strlen (given), '\n');
          else
            tty_print_utf8_string2 (NULL, given, strlen (given), 0);

          if (opt.with_colons)
            es_putc (':', fp);
          else if (*buf)
            tty_fprintf (fp, " ");
        }

      if (opt.with_colons)
        es_write_sanitized (fp, buf, strlen (buf), ":", NULL);
      else if (fp)
        print_utf8_buffer2 (fp, buf, strlen (buf), '\n');
      else
        tty_print_utf8_string2 (NULL, buf, strlen (buf), 0);
      xfree (buf);
    }
  else
    {
      if (opt.with_colons)
        es_putc (':', fp);
      else
        tty_fprintf (fp, _("[not set]"));
    }

  if (opt.with_colons)
    es_fputs (":\n", fp);
  else
    tty_fprintf (fp, "\n");
}

/* Return true if the SHA1 fingerprint FPR consists only of zeroes. */
static int
fpr_is_zero (const char *fpr)
{
  int i;

  for (i=0; i < 20 && !fpr[i]; i++)
    ;
  return (i == 20);
}


/* Return true if the SHA1 fingerprint FPR consists only of 0xFF. */
static int
fpr_is_ff (const char *fpr)
{
  int i;

  for (i=0; i < 20 && fpr[i] == '\xff'; i++)
    ;
  return (i == 20);
}


/* Print all available information about the current card. */
static void
current_card_status (ctrl_t ctrl, estream_t fp,
                     char *serialno, size_t serialnobuflen)
{
  struct agent_card_info_s info;
  PKT_public_key *pk = xcalloc (1, sizeof *pk);
  kbnode_t keyblock = NULL;
  int rc;
  unsigned int uval;
  const unsigned char *thefpr;
  int i;
  char *pesc;

  if (serialno && serialnobuflen)
    *serialno = 0;

  rc = agent_scd_learn (&info, 0);
  if (rc)
    {
      if (opt.with_colons)
        es_fputs ("AID:::\n", fp);
      log_error (_("OpenPGP card not available: %s\n"), gpg_strerror (rc));
      xfree (pk);
      return;
    }

  if (opt.with_colons)
    es_fprintf (fp, "Reader:%s:", info.reader? info.reader : "");
  else
    tty_fprintf (fp, "Reader ...........: %s\n",
                 info.reader? info.reader : "[none]");
  if (opt.with_colons)
    es_fprintf (fp, "AID:%s:", info.serialno? info.serialno : "");
  else
    tty_fprintf (fp, "Application ID ...: %s\n",
                 info.serialno? info.serialno : "[none]");

  if (!info.serialno || strncmp (info.serialno, "D27600012401", 12)
      || strlen (info.serialno) != 32 )
    {
      const char *name1, *name2;
      if (info.apptype && !ascii_strcasecmp (info.apptype, "openpgp"))
        goto openpgp;
      else if (info.apptype && !ascii_strcasecmp (info.apptype, "NKS"))
        {
          name1 = "netkey";
          name2 = "NetKey";
        }
      else if (info.apptype && !ascii_strcasecmp (info.apptype, "DINSIG"))
        {
          name1 = "dinsig";
          name2 = "DINSIG";
        }
      else if (info.apptype && !ascii_strcasecmp (info.apptype, "P15"))
        {
          name1 = "pkcs15";
          name2 = "PKCS#15";
        }
      else if (info.apptype && !ascii_strcasecmp (info.apptype, "GELDKARTE"))
        {
          name1 = "geldkarte";
          name2 = "Geldkarte";
        }
      else if (info.apptype && !ascii_strcasecmp (info.apptype, "PIV"))
        {
          name1 = "piv";
          name2 = "PIV";
        }
      else
        {
          name1 = "unknown";
          name2 = "Unknown";
        }

      if (opt.with_colons)
        es_fprintf (fp, "%s-card:\n", name1);
      else
        tty_fprintf (fp, "Application type .: %s\n", name2);

      /* Try to update/create the shadow key here for non-OpenPGP cards. */
      agent_update_shadow_keys ();

      agent_release_card_info (&info);
      xfree (pk);
      return;
    }

 openpgp:
  if (!serialno)
    ;
  else if (strlen (info.serialno)+1 > serialnobuflen)
    log_error ("serial number longer than expected\n");
  else
    strcpy (serialno, info.serialno);

  if (opt.with_colons)
    es_fputs ("openpgp-card:\n", fp);
  else
    tty_fprintf (fp, "Application type .: %s\n", "OpenPGP");

  /* Try to update/create the shadow key here for OpenPGP cards. */
  agent_update_shadow_keys ();

  if (opt.with_colons)
    {
      es_fprintf (fp, "version:%.4s:\n", info.serialno+12);
      uval = xtoi_2(info.serialno+16)*256 + xtoi_2 (info.serialno+18);
      pesc = (info.manufacturer_name
              ? percent_escape (info.manufacturer_name, NULL) : NULL);
      es_fprintf (fp, "vendor:%04x:%s:\n", uval, pesc? pesc:"");
      xfree (pesc);
      es_fprintf (fp, "serial:%.8s:\n", info.serialno+20);

      print_isoname (fp, "Name of cardholder: ", "name", info.disp_name);

      es_fputs ("lang:", fp);
      if (info.disp_lang)
        es_write_sanitized (fp, info.disp_lang, strlen (info.disp_lang),
                            ":", NULL);
      es_fputs (":\n", fp);

      es_fprintf (fp, "sex:%c:\n", (info.disp_sex == 1? 'm':
                                 info.disp_sex == 2? 'f' : 'u'));

      es_fputs ("url:", fp);
      if (info.pubkey_url)
        es_write_sanitized (fp, info.pubkey_url, strlen (info.pubkey_url),
                            ":", NULL);
      es_fputs (":\n", fp);

      es_fputs ("login:", fp);
      if (info.login_data)
        es_write_sanitized (fp, info.login_data, strlen (info.login_data),
                            ":", NULL);
      es_fputs (":\n", fp);

      es_fprintf (fp, "forcepin:%d:::\n", !info.chv1_cached);
      for (i=0; i < DIM (info.key_attr); i++)
        if (info.key_attr[i].algo == PUBKEY_ALGO_RSA)
          es_fprintf (fp, "keyattr:%d:%d:%u:\n", i+1,
                      info.key_attr[i].algo, info.key_attr[i].nbits);
        else if (info.key_attr[i].algo == PUBKEY_ALGO_ECDH
                 || info.key_attr[i].algo == PUBKEY_ALGO_ECDSA
                 || info.key_attr[i].algo == PUBKEY_ALGO_EDDSA)
          es_fprintf (fp, "keyattr:%d:%d:%s:\n", i+1,
                      info.key_attr[i].algo, info.key_attr[i].curve);
      es_fprintf (fp, "maxpinlen:%d:%d:%d:\n",
                  info.chvmaxlen[0], info.chvmaxlen[1], info.chvmaxlen[2]);
      es_fprintf (fp, "pinretry:%d:%d:%d:\n",
                  info.chvretry[0], info.chvretry[1], info.chvretry[2]);
      es_fprintf (fp, "sigcount:%lu:::\n", info.sig_counter);
      if (info.extcap.kdf)
        {
          const char *setup;

          if (info.kdf_do_enabled == 0)
            setup = "off";
          else if (info.kdf_do_enabled == 1)
            setup = "single";
          else
            setup = "on";

          es_fprintf (fp, "kdf:%s:\n", setup);
        }

      for (i=0; i < 4; i++)
        {
          if (info.private_do[i])
            {
              es_fprintf (fp, "private_do:%d:", i+1);
              es_write_sanitized (fp, info.private_do[i],
                                  strlen (info.private_do[i]), ":", NULL);
              es_fputs (":\n", fp);
            }
        }

      es_fputs ("cafpr:", fp);
      print_sha1_fpr_colon (fp, info.cafpr1valid? info.cafpr1:NULL);
      print_sha1_fpr_colon (fp, info.cafpr2valid? info.cafpr2:NULL);
      print_sha1_fpr_colon (fp, info.cafpr3valid? info.cafpr3:NULL);
      es_putc ('\n', fp);
      es_fputs ("fpr:", fp);
      print_sha1_fpr_colon (fp, info.fpr1valid? info.fpr1:NULL);
      print_sha1_fpr_colon (fp, info.fpr2valid? info.fpr2:NULL);
      print_sha1_fpr_colon (fp, info.fpr3valid? info.fpr3:NULL);
      es_putc ('\n', fp);
      es_fprintf (fp, "fprtime:%lu:%lu:%lu:\n",
               (unsigned long)info.fpr1time, (unsigned long)info.fpr2time,
               (unsigned long)info.fpr3time);
      es_fputs ("grp:", fp);
      print_sha1_fpr_colon (fp, info.grp1);
      print_sha1_fpr_colon (fp, info.grp2);
      print_sha1_fpr_colon (fp, info.grp3);
      es_putc ('\n', fp);
    }
  else
    {
      tty_fprintf (fp, "Version ..........: %.1s%c.%.1s%c\n",
                   info.serialno[12] == '0'?"":info.serialno+12,
                   info.serialno[13],
                   info.serialno[14] == '0'?"":info.serialno+14,
                   info.serialno[15]);
      tty_fprintf (fp, "Manufacturer .....: %s\n",
                   info.manufacturer_name? info.manufacturer_name : "?");
      tty_fprintf (fp, "Serial number ....: %.8s\n", info.serialno+20);

      print_isoname (fp, "Name of cardholder: ", "name", info.disp_name);
      print_name (fp, "Language prefs ...: ", info.disp_lang);
      tty_fprintf (fp, "Salutation .......: %s\n",
                   info.disp_sex == 1? _("Mr."):
                   info.disp_sex == 2? _("Ms.") : "");
      print_name (fp, "URL of public key : ", info.pubkey_url);
      print_name (fp, "Login data .......: ", info.login_data);
      if (info.private_do[0])
        print_name (fp, "Private DO 1 .....: ", info.private_do[0]);
      if (info.private_do[1])
        print_name (fp, "Private DO 2 .....: ", info.private_do[1]);
      if (info.private_do[2])
        print_name (fp, "Private DO 3 .....: ", info.private_do[2]);
      if (info.private_do[3])
        print_name (fp, "Private DO 4 .....: ", info.private_do[3]);
      if (info.cafpr1valid)
        {
          tty_fprintf (fp, "CA fingerprint %d .:", 1);
          print_sha1_fpr (fp, info.cafpr1);
        }
      if (info.cafpr2valid)
        {
          tty_fprintf (fp, "CA fingerprint %d .:", 2);
          print_sha1_fpr (fp, info.cafpr2);
        }
      if (info.cafpr3valid)
        {
          tty_fprintf (fp, "CA fingerprint %d .:", 3);
          print_sha1_fpr (fp, info.cafpr3);
        }
      tty_fprintf (fp,    "Signature PIN ....: %s\n",
                   info.chv1_cached? _("not forced"): _("forced"));
      if (info.key_attr[0].algo)
        {
          tty_fprintf (fp,    "Key attributes ...:");
          for (i=0; i < DIM (info.key_attr); i++)
            if (info.key_attr[i].algo == PUBKEY_ALGO_RSA)
              tty_fprintf (fp, " rsa%u", info.key_attr[i].nbits);
            else if (info.key_attr[i].algo == PUBKEY_ALGO_ECDH
                     || info.key_attr[i].algo == PUBKEY_ALGO_ECDSA
                     || info.key_attr[i].algo == PUBKEY_ALGO_EDDSA)
              {
                const char *curve_for_print = "?";

                if (info.key_attr[i].curve)
                  {
                    const char *oid;
                    oid = openpgp_curve_to_oid (info.key_attr[i].curve,
                                                NULL, NULL);
                    if (oid)
                      curve_for_print = openpgp_oid_to_curve (oid, 0);
                  }
                tty_fprintf (fp, " %s", curve_for_print);
              }
          tty_fprintf (fp, "\n");
        }
      tty_fprintf (fp,    "Max. PIN lengths .: %d %d %d\n",
                   info.chvmaxlen[0], info.chvmaxlen[1], info.chvmaxlen[2]);
      tty_fprintf (fp,    "PIN retry counter : %d %d %d\n",
                   info.chvretry[0], info.chvretry[1], info.chvretry[2]);
      tty_fprintf (fp,    "Signature counter : %lu\n", info.sig_counter);
      if (info.extcap.kdf)
        {
          const char *setup;

          if (info.kdf_do_enabled == 0)
            setup = "off";
          else if (info.kdf_do_enabled == 1)
            setup = "single";
          else
            setup = "on";

          tty_fprintf (fp, "KDF setting ......: %s\n", setup);
        }
      tty_fprintf (fp, "Signature key ....:");
      print_sha1_fpr (fp, info.fpr1valid? info.fpr1:NULL);
      if (info.fpr1valid && info.fpr1time)
        {
          tty_fprintf (fp, "      created ....: %s\n",
                       isotimestamp (info.fpr1time));
          print_keygrip (fp, info.grp1);
        }
      tty_fprintf (fp, "Encryption key....:");
      print_sha1_fpr (fp, info.fpr2valid? info.fpr2:NULL);
      if (info.fpr2valid && info.fpr2time)
        {
          tty_fprintf (fp, "      created ....: %s\n",
                       isotimestamp (info.fpr2time));
          print_keygrip (fp, info.grp2);
        }
      tty_fprintf (fp, "Authentication key:");
      print_sha1_fpr (fp, info.fpr3valid? info.fpr3:NULL);
      if (info.fpr3valid && info.fpr3time)
        {
          tty_fprintf (fp, "      created ....: %s\n",
                       isotimestamp (info.fpr3time));
          print_keygrip (fp, info.grp3);
        }
      tty_fprintf (fp, "General key info..: ");

      thefpr = (info.fpr1valid? info.fpr1 : info.fpr2valid? info.fpr2 :
                info.fpr3valid? info.fpr3 : NULL);
      /* If the fingerprint is all 0xff, the key has no asssociated
         OpenPGP certificate.  */
      if ( thefpr && !fpr_is_ff (thefpr)
           && !get_pubkey_byfprint (ctrl, pk, &keyblock, thefpr, 20))
        {
          print_pubkey_info (ctrl, fp, pk);
          if (keyblock)
            print_card_key_info (fp, keyblock);
        }
      else
        tty_fprintf (fp, "[none]\n");
    }

  release_kbnode (keyblock);
  free_public_key (pk);
  agent_release_card_info (&info);
}


/* Print all available information for specific card with SERIALNO.
   Print all available information for current card when SERIALNO is NULL.
   Or print for all cards when SERIALNO is "all".  */
void
card_status (ctrl_t ctrl, estream_t fp, const char *serialno)
{
  int err;
  strlist_t card_list, sl;
  char *serialno0, *serialno1;
  int all_cards = 0;
  int any_card = 0;

  if (serialno == NULL)
    {
      current_card_status (ctrl, fp, NULL, 0);
      return;
    }

  if (!strcmp (serialno, "all"))
    all_cards = 1;

  err = agent_scd_serialno (&serialno0, NULL);
  if (err)
    {
      if (gpg_err_code (err) != GPG_ERR_ENODEV && opt.verbose)
        log_info (_("error getting serial number of card: %s\n"),
                  gpg_strerror (err));
      /* Nothing available.  */
      return;
    }

  err = agent_scd_cardlist (&card_list);

  for (sl = card_list; sl; sl = sl->next)
    {
      if (!all_cards && strcmp (serialno, sl->d))
        continue;

      if (any_card && !opt.with_colons)
        tty_fprintf (fp, "\n");
      any_card = 1;

      err = agent_scd_serialno (&serialno1, sl->d);
      if (err)
        {
          if (opt.verbose)
            log_info (_("error getting serial number of card: %s\n"),
                      gpg_strerror (err));
          continue;
        }

      current_card_status (ctrl, fp, NULL, 0);
      xfree (serialno1);

      if (!all_cards)
        goto leave;
    }

  /* Select the original card again.  */
  err = agent_scd_serialno (&serialno1, serialno0);
  xfree (serialno1);

 leave:
  xfree (serialno0);
  free_strlist (card_list);
}


static char *
get_one_name (const char *prompt1, const char *prompt2)
{
  char *name;
  int i;

  for (;;)
    {
      name = cpr_get (prompt1, prompt2);
      if (!name)
        return NULL;
      trim_spaces (name);
      cpr_kill_prompt ();
      for (i=0; name[i] && name[i] >= ' ' && name[i] <= 126; i++)
        ;

      /* The name must be in Latin-1 and not UTF-8 - lacking the code
         to ensure this we restrict it to ASCII. */
      if (name[i])
        tty_printf (_("Error: Only plain ASCII is currently allowed.\n"));
      else if (strchr (name, '<'))
        tty_printf (_("Error: The \"<\" character may not be used.\n"));
      else if (strstr (name, "  "))
        tty_printf (_("Error: Double spaces are not allowed.\n"));
      else
        return name;
      xfree (name);
    }
}



static int
change_name (void)
{
  char *surname = NULL, *givenname = NULL;
  char *isoname = NULL;
  char *p;
  int rc;

  surname = get_one_name ("keygen.smartcard.surname",
                                    _("Cardholder's surname: "));
  givenname = get_one_name ("keygen.smartcard.givenname",
                                       _("Cardholder's given name: "));
  if (!surname || !givenname || (!*surname && !*givenname))
    {
      xfree (surname);
      xfree (givenname);
      rc = gpg_error (GPG_ERR_CANCELED);
      goto leave;
    }

  isoname = xmalloc ( strlen (surname) + 2 + strlen (givenname) + 1);
  strcpy (stpcpy (stpcpy (isoname, surname), "<<"), givenname);
  xfree (surname);
  xfree (givenname);
  for (p=isoname; *p; p++)
    if (*p == ' ')
      *p = '<';

  if (strlen (isoname) > 39 )
    {
      tty_printf (_("Error: Combined name too long "
                    "(limit is %d characters).\n"), 39);
      xfree (isoname);
      rc = gpg_error (GPG_ERR_TOO_LARGE);
      goto leave;
    }

  rc = agent_scd_setattr ("DISP-NAME", isoname, strlen (isoname));
  if (rc)
    log_error ("error setting Name: %s\n", gpg_strerror (rc));

 leave:
  xfree (isoname);
  write_sc_op_status (rc);
  return rc;
}


static int
change_url (void)
{
  char *url;
  int rc;

  url = cpr_get ("cardedit.change_url", _("URL to retrieve public key: "));
  if (!url)
    return -1;
  trim_spaces (url);
  cpr_kill_prompt ();

  rc = agent_scd_setattr ("PUBKEY-URL", url, strlen (url));
  if (rc)
    log_error ("error setting URL: %s\n", gpg_strerror (rc));
  xfree (url);
  write_sc_op_status (rc);
  return rc;
}


/* Fetch the key from the URL given on the card or try to get it from
   the default keyserver.  */
static int
fetch_url (ctrl_t ctrl)
{
  int rc;
  struct agent_card_info_s info;

  memset(&info,0,sizeof(info));

  rc=agent_scd_getattr("PUBKEY-URL",&info);
  if(rc)
    log_error("error retrieving URL from card: %s\n",gpg_strerror(rc));
  else
    {
      rc=agent_scd_getattr("KEY-FPR",&info);
      if(rc)
	log_error("error retrieving key fingerprint from card: %s\n",
		  gpg_strerror(rc));
      else if (info.pubkey_url && *info.pubkey_url)
        {
          strlist_t sl = NULL;

          add_to_strlist (&sl, info.pubkey_url);
          rc = keyserver_fetch (ctrl, sl, KEYORG_URL);
          free_strlist (sl);
        }
      else if (info.fpr1valid)
	{
          rc = keyserver_import_fprint (ctrl, info.fpr1, 20, opt.keyserver, 0);
	}
    }

  return rc;
}


#define MAX_GET_DATA_FROM_FILE 16384

/* Read data from file FNAME up to MAX_GET_DATA_FROM_FILE characters.
   On error return -1 and store NULL at R_BUFFER; on success return
   the number of bytes read and store the address of a newly allocated
   buffer at R_BUFFER. */
static int
get_data_from_file (const char *fname, char **r_buffer)
{
  estream_t fp;
  char *data;
  int n;

  *r_buffer = NULL;

  fp = es_fopen (fname, "rb");
#if GNUPG_MAJOR_VERSION == 1
  if (fp && is_secured_file (fileno (fp)))
    {
      fclose (fp);
      fp = NULL;
      errno = EPERM;
    }
#endif
  if (!fp)
    {
      tty_printf (_("can't open '%s': %s\n"), fname, strerror (errno));
      return -1;
    }

  data = xtrymalloc (MAX_GET_DATA_FROM_FILE);
  if (!data)
    {
      tty_printf (_("error allocating enough memory: %s\n"), strerror (errno));
      es_fclose (fp);
      return -1;
    }

  n = es_fread (data, 1, MAX_GET_DATA_FROM_FILE, fp);
  es_fclose (fp);
  if (n < 0)
    {
      tty_printf (_("error reading '%s': %s\n"), fname, strerror (errno));
      xfree (data);
      return -1;
    }
  *r_buffer = data;
  return n;
}


/* Write LENGTH bytes from BUFFER to file FNAME.  Return 0 on
   success.  */
static int
put_data_to_file (const char *fname, const void *buffer, size_t length)
{
  estream_t fp;

  fp = es_fopen (fname, "wb");
#if GNUPG_MAJOR_VERSION == 1
  if (fp && is_secured_file (fileno (fp)))
    {
      fclose (fp);
      fp = NULL;
      errno = EPERM;
    }
#endif
  if (!fp)
    {
      tty_printf (_("can't create '%s': %s\n"), fname, strerror (errno));
      return -1;
    }

  if (length && es_fwrite (buffer, length, 1, fp) != 1)
    {
      tty_printf (_("error writing '%s': %s\n"), fname, strerror (errno));
      es_fclose (fp);
      return -1;
    }
  es_fclose (fp);
  return 0;
}


static int
change_login (const char *args)
{
  char *data;
  int n;
  int rc;

  if (args && *args == '<')  /* Read it from a file */
    {
      for (args++; spacep (args); args++)
        ;
      n = get_data_from_file (args, &data);
      if (n < 0)
        return -1;
    }
  else
    {
      data = cpr_get ("cardedit.change_login",
                      _("Login data (account name): "));
      if (!data)
        return -1;
      trim_spaces (data);
      cpr_kill_prompt ();
      n = strlen (data);
    }

  rc = agent_scd_setattr ("LOGIN-DATA", data, n);
  if (rc)
    log_error ("error setting login data: %s\n", gpg_strerror (rc));
  xfree (data);
  write_sc_op_status (rc);
  return rc;
}

static int
change_private_do (const char *args, int nr)
{
  char do_name[] = "PRIVATE-DO-X";
  char *data;
  int n;
  int rc;

  log_assert (nr >= 1 && nr <= 4);
  do_name[11] = '0' + nr;

  if (args && (args = strchr (args, '<')))  /* Read it from a file */
    {
      for (args++; spacep (args); args++)
        ;
      n = get_data_from_file (args, &data);
      if (n < 0)
        return -1;
    }
  else
    {
      data = cpr_get ("cardedit.change_private_do",
                      _("Private DO data: "));
      if (!data)
        return -1;
      trim_spaces (data);
      cpr_kill_prompt ();
      n = strlen (data);
    }

  rc = agent_scd_setattr (do_name, data, n);
  if (rc)
    log_error ("error setting private DO: %s\n", gpg_strerror (rc));
  xfree (data);
  write_sc_op_status (rc);
  return rc;
}


static int
change_cert (const char *args)
{
  char *data;
  int n;
  int rc;

  if (args && *args == '<')  /* Read it from a file */
    {
      for (args++; spacep (args); args++)
        ;
      n = get_data_from_file (args, &data);
      if (n < 0)
        return -1;
    }
  else
    {
      tty_printf ("usage error: redirection to file required\n");
      return -1;
    }

  rc = agent_scd_writecert ("OPENPGP.3", data, n);
  if (rc)
    log_error ("error writing certificate to card: %s\n", gpg_strerror (rc));
  xfree (data);
  write_sc_op_status (rc);
  return rc;
}


static int
read_cert (const char *args)
{
  const char *fname;
  void *buffer;
  size_t length;
  int rc;

  if (args && *args == '>')  /* Write it to a file */
    {
      for (args++; spacep (args); args++)
        ;
      fname = args;
    }
  else
    {
      tty_printf ("usage error: redirection to file required\n");
      return -1;
    }

  rc = agent_scd_readcert ("OPENPGP.3", &buffer, &length);
  if (rc)
    log_error ("error reading certificate from card: %s\n", gpg_strerror (rc));
  else
    rc = put_data_to_file (fname, buffer, length);
  xfree (buffer);
  write_sc_op_status (rc);
  return rc;
}


static int
change_lang (void)
{
  char *data, *p;
  int rc;

  data = cpr_get ("cardedit.change_lang",
                  _("Language preferences: "));
  if (!data)
    return -1;
  trim_spaces (data);
  cpr_kill_prompt ();

  if (strlen (data) > 8 || (strlen (data) & 1))
    {
      tty_printf (_("Error: invalid length of preference string.\n"));
      xfree (data);
      return -1;
    }

  for (p=data; *p && *p >= 'a' && *p <= 'z'; p++)
    ;
  if (*p)
    {
      tty_printf (_("Error: invalid characters in preference string.\n"));
      xfree (data);
      return -1;
    }

  rc = agent_scd_setattr ("DISP-LANG", data, strlen (data));
  if (rc)
    log_error ("error setting lang: %s\n", gpg_strerror (rc));
  xfree (data);
  write_sc_op_status (rc);
  return rc;
}


static int
change_sex (void)
{
  char *data;
  const char *str;
  int rc;

  data = cpr_get ("cardedit.change_sex",
                  _("Salutation (M = Mr., F = Ms., or space): "));
  if (!data)
    return -1;
  trim_spaces (data);
  cpr_kill_prompt ();

  if (!*data)
    str = "9";
  else if ((*data == 'M' || *data == 'm') && !data[1])
    str = "1";
  else if ((*data == 'F' || *data == 'f') && !data[1])
    str = "2";
  else
    {
      tty_printf (_("Error: invalid response.\n"));
      xfree (data);
      return -1;
    }

  rc = agent_scd_setattr ("DISP-SEX", str, 1);
  if (rc)
    log_error ("error setting salutation: %s\n", gpg_strerror (rc));
  xfree (data);
  write_sc_op_status (rc);
  return rc;
}


static int
change_cafpr (int fprno)
{
  char *data;
  const char *s;
  int i, c, rc;
  unsigned char fpr[20];

  data = cpr_get ("cardedit.change_cafpr", _("CA fingerprint: "));
  if (!data)
    return -1;
  trim_spaces (data);
  cpr_kill_prompt ();

  for (i=0, s=data; i < 20 && *s; )
    {
      while (spacep(s))
        s++;
      if (*s == ':')
        s++;
      while (spacep(s))
        s++;
      c = hextobyte (s);
      if (c == -1)
        break;
      fpr[i++] = c;
      s += 2;
    }
  xfree (data);
  if (i != 20 || *s)
    {
      tty_printf (_("Error: invalid formatted fingerprint.\n"));
      return -1;
    }

  rc = agent_scd_setattr (fprno==1?"CA-FPR-1":
                          fprno==2?"CA-FPR-2":
                          fprno==3?"CA-FPR-3":"x", fpr, 20);
  if (rc)
    log_error ("error setting cafpr: %s\n", gpg_strerror (rc));
  write_sc_op_status (rc);
  return rc;
}



static void
toggle_forcesig (void)
{
  struct agent_card_info_s info;
  int rc;
  int newstate;

  memset (&info, 0, sizeof info);
  rc = agent_scd_getattr ("CHV-STATUS", &info);
  if (rc)
    {
      log_error ("error getting current status: %s\n", gpg_strerror (rc));
      return;
    }
  newstate = !info.chv1_cached;
  agent_release_card_info (&info);

  rc = agent_scd_setattr ("CHV-STATUS-1", newstate? "\x01":"", 1);
  if (rc)
    log_error ("error toggling signature PIN flag: %s\n", gpg_strerror (rc));
  write_sc_op_status (rc);
}


/* Helper for the key generation/edit functions.  */
static int
get_info_for_key_operation (struct agent_card_info_s *info)
{
  int rc;

  memset (info, 0, sizeof *info);
  rc = agent_scd_getattr ("SERIALNO", info);
  if (!rc)
    rc = agent_scd_getattr ("APPTYPE", info);
  if (rc || !info->apptype || ascii_strcasecmp (info->apptype, "openpgp"))
    {
      log_error (_("key operation not possible: %s\n"),
                 rc ? gpg_strerror (rc) : _("not an OpenPGP card"));
      return rc? rc: -1;
    }
  rc = agent_scd_getattr ("KEY-FPR", info);
  if (!rc)
    rc = agent_scd_getattr ("CHV-STATUS", info);
  if (!rc)
    rc = agent_scd_getattr ("DISP-NAME", info);
  if (!rc)
    rc = agent_scd_getattr ("EXTCAP", info);
  if (!rc)
    rc = agent_scd_getattr ("KEY-ATTR", info);
  if (rc)
    log_error (_("error getting current key info: %s\n"), gpg_strerror (rc));
  return rc;
}


/* Helper for the key generation/edit functions.  */
static int
check_pin_for_key_operation (struct agent_card_info_s *info, int *forced_chv1)
{
  int rc = 0;

  *forced_chv1 = !info->chv1_cached;
  if (*forced_chv1)
    { /* Switch off the forced mode so that during key generation we
         don't get bothered with PIN queries for each
         self-signature. */
      rc = agent_scd_setattr ("CHV-STATUS-1", "\x01", 1);
      if (rc)
        {
          log_error ("error clearing forced signature PIN flag: %s\n",
                     gpg_strerror (rc));
          *forced_chv1 = 0;
        }
    }

  if (!rc)
    {
      /* Check the PIN now, so that we won't get asked later for each
         binding signature. */
      rc = agent_scd_checkpin (info->serialno);
      if (rc)
        {
          log_error ("error checking the PIN: %s\n", gpg_strerror (rc));
          write_sc_op_status (rc);
        }
  }
  return rc;
}

/* Helper for the key generation/edit functions.  */
static void
restore_forced_chv1 (int *forced_chv1)
{
  int rc;

  if (*forced_chv1)
    { /* Switch back to forced state. */
      rc = agent_scd_setattr ("CHV-STATUS-1", "", 1);
      if (rc)
        {
          log_error ("error setting forced signature PIN flag: %s\n",
                     gpg_strerror (rc));
        }
    }
}


/* Helper for the key generation/edit functions.  */
static void
show_card_key_info (struct agent_card_info_s *info)
{
  tty_fprintf (NULL, "Signature key ....:");
  print_sha1_fpr (NULL, info->fpr1valid? info->fpr1:NULL);
  tty_fprintf (NULL, "Encryption key....:");
  print_sha1_fpr (NULL, info->fpr2valid? info->fpr2:NULL);
  tty_fprintf (NULL, "Authentication key:");
  print_sha1_fpr (NULL, info->fpr3valid? info->fpr3:NULL);
  tty_printf ("\n");
}


/* Helper for the key generation/edit functions.  */
static int
replace_existing_key_p (struct agent_card_info_s *info, int keyno)
{
  log_assert (keyno >= 0 && keyno <= 3);

  if ((keyno == 1 && info->fpr1valid)
      || (keyno == 2 && info->fpr2valid)
      || (keyno == 3 && info->fpr3valid))
    {
      tty_printf ("\n");
      log_info ("WARNING: such a key has already been stored on the card!\n");
      tty_printf ("\n");
      if ( !cpr_get_answer_is_yes( "cardedit.genkeys.replace_key",
                                  _("Replace existing key? (y/N) ")))
        return -1;
      return 1;
    }
  return 0;
}


static void
show_keysize_warning (void)
{
  static int shown;

  if (shown)
    return;
  shown = 1;
  tty_printf
    (_("Note: There is no guarantee that the card "
       "supports the requested size.\n"
       "      If the key generation does not succeed, "
       "please check the\n"
       "      documentation of your card to see what "
       "sizes are allowed.\n"));
}


/* Ask for the size of a card key.  NBITS is the current size
   configured for the card.  Returns 0 to use the default size
   (i.e. NBITS) or the selected size.  */
static unsigned int
ask_card_rsa_keysize (unsigned int nbits)
{
  unsigned int min_nbits = 1024;
  unsigned int max_nbits = 4096;
  char *prompt, *answer;
  unsigned int req_nbits;

  for (;;)
    {
      prompt = xasprintf (_("What keysize do you want? (%u) "), nbits);
      answer = cpr_get ("cardedit.genkeys.size", prompt);
      cpr_kill_prompt ();
      req_nbits = *answer? atoi (answer): nbits;
      xfree (prompt);
      xfree (answer);

      if (req_nbits != nbits && (req_nbits % 32) )
        {
          req_nbits = ((req_nbits + 31) / 32) * 32;
          tty_printf (_("rounded up to %u bits\n"), req_nbits);
        }

      if (req_nbits == nbits)
        return 0;  /* Use default.  */

      if (req_nbits < min_nbits || req_nbits > max_nbits)
        {
          tty_printf (_("%s keysizes must be in the range %u-%u\n"),
                      "RSA", min_nbits, max_nbits);
        }
      else
        return req_nbits;
    }
}

/* Ask for the key attribute of a card key.  CURRENT is the current
   attribute configured for the card.  KEYNO is the number of the key
   used to select the prompt.  Returns NULL to use the default
   attribute or the selected attribute structure.  */
static struct key_attr *
ask_card_keyattr (int keyno, const struct key_attr *current)
{
  struct key_attr *key_attr = NULL;
  char *answer = NULL;
  int algo;

  tty_printf (_("Changing card key attribute for: "));
  if (keyno == 0)
    tty_printf (_("Signature key\n"));
  else if (keyno == 1)
    tty_printf (_("Encryption key\n"));
  else
    tty_printf (_("Authentication key\n"));

  tty_printf (_("Please select what kind of key you want:\n"));
  tty_printf (_("   (%d) RSA\n"), 1 );
  tty_printf (_("   (%d) ECC\n"), 2 );

  for (;;)
    {
      xfree (answer);
      answer = cpr_get ("cardedit.genkeys.algo", _("Your selection? "));
      cpr_kill_prompt ();
      algo = *answer? atoi (answer) : 0;

      if (!*answer || algo == 1 || algo == 2)
        break;
      else
        tty_printf (_("Invalid selection.\n"));
    }

  if (algo == 0)
    goto leave;

  key_attr = xmalloc (sizeof (struct key_attr));

  if (algo == 1)
    {
      unsigned int nbits, result_nbits;

      if (current->algo == PUBKEY_ALGO_RSA)
        nbits = current->nbits;
      else
        nbits = 2048;

      result_nbits = ask_card_rsa_keysize (nbits);
      if (result_nbits == 0)
        {
          if (current->algo == PUBKEY_ALGO_RSA)
            {
              xfree (key_attr);
              key_attr = NULL;
            }
          else
            result_nbits = nbits;
        }

      if (key_attr)
        {
          key_attr->algo = PUBKEY_ALGO_RSA;
          key_attr->nbits = result_nbits;
        }
    }
  else
    {
      const char *curve;
      const char *oid_str;

      if (current->algo == PUBKEY_ALGO_RSA)
        {
          if (keyno == 1)
            /* Encryption key */
            algo = PUBKEY_ALGO_ECDH;
          else /* Signature key or Authentication key */
            algo = PUBKEY_ALGO_ECDSA;
          curve = NULL;
        }
      else
        {
          algo = current->algo;
          curve = current->curve;
        }

      curve = ask_curve (&algo, NULL, curve);
      if (curve)
        {
          key_attr->algo = algo;
          oid_str = openpgp_curve_to_oid (curve, NULL, NULL);
          key_attr->curve = openpgp_oid_to_curve (oid_str, 0);
        }
      else
        {
          xfree (key_attr);
          key_attr = NULL;
        }
    }

 leave:
  if (key_attr)
    {
      if (key_attr->algo == PUBKEY_ALGO_RSA)
        tty_printf (_("The card will now be re-configured"
                      " to generate a key of %u bits\n"), key_attr->nbits);
      else if (key_attr->algo == PUBKEY_ALGO_ECDH
               || key_attr->algo == PUBKEY_ALGO_ECDSA
               || key_attr->algo == PUBKEY_ALGO_EDDSA)
        tty_printf (_("The card will now be re-configured"
                      " to generate a key of type: %s\n"), key_attr->curve),

      show_keysize_warning ();
    }

  return key_attr;
}



/* Change the key attribute of key KEYNO (0..2) and show an error
 * message if that fails.  */
static gpg_error_t
do_change_keyattr (int keyno, const struct key_attr *key_attr)
{
  gpg_error_t err = 0;
  char args[100];

  if (key_attr->algo == PUBKEY_ALGO_RSA)
    snprintf (args, sizeof args, "--force %d 1 rsa%u", keyno+1,
              key_attr->nbits);
  else if (key_attr->algo == PUBKEY_ALGO_ECDH
           || key_attr->algo == PUBKEY_ALGO_ECDSA
           || key_attr->algo == PUBKEY_ALGO_EDDSA)
    snprintf (args, sizeof args, "--force %d %d %s",
              keyno+1, key_attr->algo, key_attr->curve);
  else
    {
      log_error (_("public key algorithm %d (%s) is not supported\n"),
                 key_attr->algo, gcry_pk_algo_name (key_attr->algo));
      return gpg_error (GPG_ERR_PUBKEY_ALGO);
    }

  err = agent_scd_setattr ("KEY-ATTR", args, strlen (args));
  if (err)
    log_error (_("error changing key attribute for key %d: %s\n"),
               keyno+1, gpg_strerror (err));
  return err;
}


static void
key_attr (void)
{
  struct agent_card_info_s info;
  gpg_error_t err;
  int keyno;

  err = get_info_for_key_operation (&info);
  if (err)
    {
      log_error (_("error getting card info: %s\n"), gpg_strerror (err));
      return;
    }

  if (!(info.is_v2 && info.extcap.aac))
    {
      log_error (_("This command is not supported by this card\n"));
      goto leave;
    }

  for (keyno = 0; keyno < DIM (info.key_attr); keyno++)
    {
      struct key_attr *key_attr;

      if ((key_attr = ask_card_keyattr (keyno, &info.key_attr[keyno])))
        {
          err = do_change_keyattr (keyno, key_attr);
          xfree (key_attr);
          if (err)
            {
              /* Error: Better read the default key attribute again.  */
              agent_release_card_info (&info);
              if (get_info_for_key_operation (&info))
                goto leave;
              /* Ask again for this key. */
              keyno--;
            }
        }
    }

 leave:
  agent_release_card_info (&info);
}


static void
generate_card_keys (ctrl_t ctrl)
{
  struct agent_card_info_s info;
  int forced_chv1;
  int want_backup;

  if (get_info_for_key_operation (&info))
    return;

  if (info.extcap.ki)
    {
      char *answer;

      /* FIXME: Should be something like cpr_get_bool so that a status
         GET_BOOL will be emitted.  */
      answer = cpr_get ("cardedit.genkeys.backup_enc",
                        _("Make off-card backup of encryption key? (Y/n) "));

      want_backup = answer_is_yes_no_default (answer, 1/*(default to Yes)*/);
      cpr_kill_prompt ();
      xfree (answer);
    }
  else
    want_backup = 0;

  if ( (info.fpr1valid && !fpr_is_zero (info.fpr1))
       || (info.fpr2valid && !fpr_is_zero (info.fpr2))
       || (info.fpr3valid && !fpr_is_zero (info.fpr3)))
    {
      tty_printf ("\n");
      log_info (_("Note: keys are already stored on the card!\n"));
      tty_printf ("\n");
      if ( !cpr_get_answer_is_yes ("cardedit.genkeys.replace_keys",
                                   _("Replace existing keys? (y/N) ")))
        {
          agent_release_card_info (&info);
          return;
        }
    }

  /* If no displayed name has been set, we assume that this is a fresh
     card and print a hint about the default PINs.  */
  if (!info.disp_name || !*info.disp_name)
    {
      tty_printf ("\n");
      tty_printf (_("Please note that the factory settings of the PINs are\n"
                    "   PIN = '%s'     Admin PIN = '%s'\n"
                    "You should change them using the command --change-pin\n"),
                  "123456", "12345678");
      tty_printf ("\n");
    }


  if (check_pin_for_key_operation (&info, &forced_chv1))
    goto leave;

  generate_keypair (ctrl, 1, NULL, info.serialno, want_backup);

 leave:
  agent_release_card_info (&info);
  restore_forced_chv1 (&forced_chv1);
}


/* This function is used by the key edit menu to generate an arbitrary
   subkey. */
gpg_error_t
card_generate_subkey (ctrl_t ctrl, kbnode_t pub_keyblock)
{
  gpg_error_t err;
  struct agent_card_info_s info;
  int forced_chv1 = 0;
  int keyno;

  err = get_info_for_key_operation (&info);
  if (err)
    return err;

  show_card_key_info (&info);

  tty_printf (_("Please select the type of key to generate:\n"));

  tty_printf (_("   (1) Signature key\n"));
  tty_printf (_("   (2) Encryption key\n"));
  tty_printf (_("   (3) Authentication key\n"));

  for (;;)
    {
      char *answer = cpr_get ("cardedit.genkeys.subkeytype",
                              _("Your selection? "));
      cpr_kill_prompt();
      if (*answer == CONTROL_D)
        {
          xfree (answer);
          err = gpg_error (GPG_ERR_CANCELED);
          goto leave;
        }
      keyno = *answer? atoi(answer): 0;
      xfree(answer);
      if (keyno >= 1 && keyno <= 3)
        break; /* Okay. */
      tty_printf(_("Invalid selection.\n"));
    }

  if (replace_existing_key_p (&info, keyno) < 0)
    {
      err = gpg_error (GPG_ERR_CANCELED);
      goto leave;
    }

  err = check_pin_for_key_operation (&info, &forced_chv1);
  if (err)
    goto leave;

  err = generate_card_subkeypair (ctrl, pub_keyblock, keyno, info.serialno);

 leave:
  agent_release_card_info (&info);
  restore_forced_chv1 (&forced_chv1);
  return err;
}


/* Store the key at NODE into the smartcard and modify NODE to
   carry the serialno stuff instead of the actual secret key
   parameters.  USE is the usage for that key; 0 means any
   usage. */
int
card_store_subkey (KBNODE node, int use)
{
  struct agent_card_info_s info;
  int okay = 0;
  unsigned int nbits;
  int allow_keyno[3];
  int  keyno;
  PKT_public_key *pk;
  gpg_error_t err;
  char *hexgrip;
  int rc;
  gnupg_isotime_t timebuf;

  log_assert (node->pkt->pkttype == PKT_PUBLIC_KEY
              || node->pkt->pkttype == PKT_PUBLIC_SUBKEY);

  pk = node->pkt->pkt.public_key;

  if (get_info_for_key_operation (&info))
    return 0;

  if (!info.extcap.ki)
    {
      tty_printf ("The card does not support the import of keys\n");
      tty_printf ("\n");
      goto leave;
    }

  nbits = nbits_from_pk (pk);

  if (!info.is_v2 && nbits != 1024)
    {
      tty_printf ("You may only store a 1024 bit RSA key on the card\n");
      tty_printf ("\n");
      goto leave;
    }

  allow_keyno[0] = (!use || (use & (PUBKEY_USAGE_SIG|PUBKEY_USAGE_CERT)));
  allow_keyno[1] = (!use || (use & (PUBKEY_USAGE_ENC)));
  allow_keyno[2] = (!use || (use & (PUBKEY_USAGE_SIG|PUBKEY_USAGE_AUTH)));

  tty_printf (_("Please select where to store the key:\n"));

  if (allow_keyno[0])
    tty_printf (_("   (1) Signature key\n"));
  if (allow_keyno[1])
    tty_printf (_("   (2) Encryption key\n"));
  if (allow_keyno[2])
    tty_printf (_("   (3) Authentication key\n"));

  for (;;)
    {
      char *answer = cpr_get ("cardedit.genkeys.storekeytype",
                              _("Your selection? "));
      cpr_kill_prompt();
      if (*answer == CONTROL_D || !*answer)
        {
          xfree (answer);
          goto leave;
        }
      keyno = *answer? atoi(answer): 0;
      xfree(answer);
      if (keyno >= 1 && keyno <= 3 && allow_keyno[keyno-1])
        {
          if (info.is_v2 && !info.extcap.aac
              && info.key_attr[keyno-1].nbits != nbits)
            {
              tty_printf ("Key does not match the card's capability.\n");
            }
          else
            break; /* Okay. */
        }
      else
        tty_printf(_("Invalid selection.\n"));
    }

  if ((rc = replace_existing_key_p (&info, keyno)) < 0)
    goto leave;

  err = hexkeygrip_from_pk (pk, &hexgrip);
  if (err)
    goto leave;

  epoch2isotime (timebuf, (time_t)pk->timestamp);
  rc = agent_keytocard (hexgrip, keyno, rc, info.serialno, timebuf);

  if (rc)
    log_error (_("KEYTOCARD failed: %s\n"), gpg_strerror (rc));
  else
    okay = 1;
  xfree (hexgrip);

 leave:
  agent_release_card_info (&info);
  return okay;
}



/* Direct sending of an hex encoded APDU with error printing.  */
static gpg_error_t
send_apdu (const char *hexapdu, const char *desc, unsigned int ignore)
{
  gpg_error_t err;
  unsigned int sw;

  err = agent_scd_apdu (hexapdu, &sw);
  if (err)
    tty_printf ("sending card command %s failed: %s\n", desc,
                gpg_strerror (err));
  else if (!hexapdu
           || !strcmp (hexapdu, "undefined")
           || !strcmp (hexapdu, "reset-keep-lock")
           || !strcmp (hexapdu, "lock")
           || !strcmp (hexapdu, "trylock")
           || !strcmp (hexapdu, "unlock"))
    ; /* Ignore pseudo APDUs.  */
  else if (ignore == 0xffff)
    ; /* Ignore all status words.  */
  else if (sw != 0x9000)
    {
      switch (sw)
        {
        case 0x6285: err = gpg_error (GPG_ERR_OBJ_TERM_STATE); break;
        case 0x6982: err = gpg_error (GPG_ERR_BAD_PIN); break;
        case 0x6985: err = gpg_error (GPG_ERR_USE_CONDITIONS); break;
        default: err = gpg_error (GPG_ERR_CARD);
        }
      if (!(ignore && ignore == sw))
        tty_printf ("card command %s failed: %s (0x%04x)\n", desc,
                    gpg_strerror (err),  sw);
    }
  return err;
}


/* Do a factory reset after confirmation.  */
static void
factory_reset (void)
{
  struct agent_card_info_s info;
  gpg_error_t err;
  char *answer = NULL;
  int termstate = 0;
  int i;
  int locked = 0;

  /*  The code below basically does the same what this
      gpg-connect-agent script does:

        scd reset
        scd serialno undefined
        scd apdu 00 A4 04 00 06 D2 76 00 01 24 01
        scd apdu 00 20 00 81 08 40 40 40 40 40 40 40 40
        scd apdu 00 20 00 81 08 40 40 40 40 40 40 40 40
        scd apdu 00 20 00 81 08 40 40 40 40 40 40 40 40
        scd apdu 00 20 00 81 08 40 40 40 40 40 40 40 40
        scd apdu 00 20 00 83 08 40 40 40 40 40 40 40 40
        scd apdu 00 20 00 83 08 40 40 40 40 40 40 40 40
        scd apdu 00 20 00 83 08 40 40 40 40 40 40 40 40
        scd apdu 00 20 00 83 08 40 40 40 40 40 40 40 40
        scd apdu 00 e6 00 00
        scd apdu 00 44 00 00
        scd reset
        /echo Card has been reset to factory defaults

      but tries to find out something about the card first.
   */

  err = agent_scd_learn (&info, 0);
  if (gpg_err_code (err) == GPG_ERR_OBJ_TERM_STATE
      && gpg_err_source (err) == GPG_ERR_SOURCE_SCD)
    termstate = 1;
  else if (err)
    {
      log_error (_("OpenPGP card not available: %s\n"), gpg_strerror (err));
      goto leave;
    }

  if (!termstate)
    {
      log_info (_("OpenPGP card no. %s detected\n"),
                info.serialno? info.serialno : "[none]");
      if (!(info.status_indicator == 3 || info.status_indicator == 5))
        {
          /* Note: We won't see status-indicator 3 here because it is not
             possible to select a card application in termination state.  */
          log_error (_("This command is not supported by this card\n"));
          goto leave;
        }

      tty_printf ("\n");
      log_info (_("Note: This command destroys all keys stored on the card!\n"));
      tty_printf ("\n");
      if (!cpr_get_answer_is_yes ("cardedit.factory-reset.proceed",
                                  _("Continue? (y/N) ")))
        goto leave;


      answer = cpr_get ("cardedit.factory-reset.really",
                        _("Really do a factory reset? (enter \"yes\") "));
      cpr_kill_prompt ();
      trim_spaces (answer);
      if (strcmp (answer, "yes"))
        goto leave;

      /* We need to select a card application before we can send APDUs
         to the card without scdaemon doing anything on its own.  We
         then lock the connection so that other tools (e.g. Kleopatra)
         don't try a new select.  */
      err = send_apdu ("lock", "locking connection ", 0);
      if (err)
        goto leave;
      locked = 1;
      err = send_apdu ("reset-keep-lock", "reset", 0);
      if (err)
        goto leave;
      err = send_apdu ("undefined", "dummy select ", 0);
      if (err)
        goto leave;

      /* Select the OpenPGP application.  */
      err = send_apdu ("00A4040006D27600012401", "SELECT AID", 0);
      if (err)
        goto leave;

      /* Do some dummy verifies with wrong PINs to set the retry
         counter to zero.  We can't easily use the card version 2.1
         feature of presenting the admin PIN to allow the terminate
         command because there is no machinery in scdaemon to catch
         the verify command and ask for the PIN when the "APDU"
         command is used. */
      /* Here, the length of dummy wrong PIN is 32-byte, also
         supporting authentication with KDF DO.  */
      for (i=0; i < 4; i++)
        send_apdu ("0020008120"
                   "40404040404040404040404040404040"
                   "40404040404040404040404040404040", "VERIFY", 0xffff);
      for (i=0; i < 4; i++)
        send_apdu ("0020008320"
                   "40404040404040404040404040404040"
                   "40404040404040404040404040404040", "VERIFY", 0xffff);

      /* Send terminate datafile command.  */
      err = send_apdu ("00e60000", "TERMINATE DF", 0x6985);
      if (err)
        goto leave;
    }

  /* Send activate datafile command.  This is used without
     confirmation if the card is already in termination state.  */
  err = send_apdu ("00440000", "ACTIVATE DF", 0);
  if (err)
    goto leave;

  /* Finally we reset the card reader once more.  */
  err = send_apdu ("reset-keep-lock", "reset", 0);

  /* Then, connect the card again.  */
  if (!err)
    {
      char *serialno0;

      err = agent_scd_serialno (&serialno0, NULL);
      if (!err)
        xfree (serialno0);
    }

 leave:
  if (locked)
    send_apdu ("unlock", "unlocking connection ", 0);
  xfree (answer);
  agent_release_card_info (&info);
}


#define USER_PIN_DEFAULT "123456"
#define ADMIN_PIN_DEFAULT "12345678"
#define KDF_DATA_LENGTH_MIN  90
#define KDF_DATA_LENGTH_MAX 110

/* Generate KDF data.  */
static gpg_error_t
gen_kdf_data (unsigned char *data, int single_salt)
{
  const unsigned char h0[] = { 0x81, 0x01, 0x03,
                               0x82, 0x01, 0x08,
                               0x83, 0x04 };
  const unsigned char h1[] = { 0x84, 0x08 };
  const unsigned char h2[] = { 0x85, 0x08 };
  const unsigned char h3[] = { 0x86, 0x08 };
  const unsigned char h4[] = { 0x87, 0x20 };
  const unsigned char h5[] = { 0x88, 0x20 };
  unsigned char *p, *salt_user, *salt_admin;
  unsigned char s2k_char;
  unsigned int iterations;
  unsigned char count_4byte[4];
  gpg_error_t err = 0;

  p = data;

  s2k_char = encode_s2k_iterations (0);
  iterations = S2K_DECODE_COUNT (s2k_char);
  count_4byte[0] = (iterations >> 24) & 0xff;
  count_4byte[1] = (iterations >> 16) & 0xff;
  count_4byte[2] = (iterations >>  8) & 0xff;
  count_4byte[3] = (iterations & 0xff);

  memcpy (p, h0, sizeof h0);
  p += sizeof h0;
  memcpy (p, count_4byte, sizeof count_4byte);
  p += sizeof count_4byte;
  memcpy (p, h1, sizeof h1);
  salt_user = (p += sizeof h1);
  gcry_randomize (p, 8, GCRY_STRONG_RANDOM);
  p += 8;

  if (single_salt)
    salt_admin = salt_user;
  else
    {
      memcpy (p, h2, sizeof h2);
      p += sizeof h2;
      gcry_randomize (p, 8, GCRY_STRONG_RANDOM);
      p += 8;
      memcpy (p, h3, sizeof h3);
      salt_admin = (p += sizeof h3);
      gcry_randomize (p, 8, GCRY_STRONG_RANDOM);
      p += 8;
    }

  memcpy (p, h4, sizeof h4);
  p += sizeof h4;
  err = gcry_kdf_derive (USER_PIN_DEFAULT, strlen (USER_PIN_DEFAULT),
                         GCRY_KDF_ITERSALTED_S2K, DIGEST_ALGO_SHA256,
                         salt_user, 8, iterations, 32, p);
  p += 32;
  if (!err)
    {
      memcpy (p, h5, sizeof h5);
      p += sizeof h5;
      err = gcry_kdf_derive (ADMIN_PIN_DEFAULT, strlen (ADMIN_PIN_DEFAULT),
                             GCRY_KDF_ITERSALTED_S2K, DIGEST_ALGO_SHA256,
                             salt_admin, 8, iterations, 32, p);
    }

  return err;
}

/* Setup KDF data object which is used for PIN authentication.  */
static void
kdf_setup (const char *args)
{
  struct agent_card_info_s info;
  gpg_error_t err;
  unsigned char kdf_data[KDF_DATA_LENGTH_MAX];
  int single = (*args != 0);

  memset (&info, 0, sizeof info);

  err = agent_scd_getattr ("EXTCAP", &info);
  if (err)
    {
      log_error (_("error getting card info: %s\n"), gpg_strerror (err));
      return;
    }

  if (!info.extcap.kdf)
    {
      log_error (_("This command is not supported by this card\n"));
      goto leave;
    }

  err = gen_kdf_data (kdf_data, single);
  if (err)
    goto leave_error;

  err = agent_scd_setattr ("KDF", kdf_data,
                           single ? KDF_DATA_LENGTH_MIN : KDF_DATA_LENGTH_MAX);
  if (err)
    goto leave_error;

  err = agent_scd_getattr ("KDF", &info);

 leave_error:
  if (err)
    log_error (_("error for setup KDF: %s\n"), gpg_strerror (err));

 leave:
  agent_release_card_info (&info);
}



/* Data used by the command parser.  This needs to be outside of the
   function scope to allow readline based command completion.  */
enum cmdids
  {
    cmdNOP = 0,
    cmdQUIT, cmdADMIN, cmdHELP, cmdLIST, cmdDEBUG, cmdVERIFY,
    cmdNAME, cmdURL, cmdFETCH, cmdLOGIN, cmdLANG, cmdSEX, cmdCAFPR,
    cmdFORCESIG, cmdGENERATE, cmdPASSWD, cmdPRIVATEDO, cmdWRITECERT,
    cmdREADCERT, cmdUNBLOCK, cmdFACTORYRESET, cmdKDFSETUP,
    cmdKEYATTR,
    cmdINVCMD
  };

static struct
{
  const char *name;
  enum cmdids id;
  int admin_only;
  const char *desc;
} cmds[] =
  {
    { "quit"    , cmdQUIT  , 0, N_("quit this menu")},
    { "q"       , cmdQUIT  , 0, NULL },
    { "admin"   , cmdADMIN , 0, N_("show admin commands")},
    { "help"    , cmdHELP  , 0, N_("show this help")},
    { "?"       , cmdHELP  , 0, NULL },
    { "list"    , cmdLIST  , 0, N_("list all available data")},
    { "l"       , cmdLIST  , 0, NULL },
    { "debug"   , cmdDEBUG , 0, NULL },
    { "name"    , cmdNAME  , 1, N_("change card holder's name")},
    { "url"     , cmdURL   , 1, N_("change URL to retrieve key")},
    { "fetch"   , cmdFETCH , 0, N_("fetch the key specified in the card URL")},
    { "login"   , cmdLOGIN , 1, N_("change the login name")},
    { "lang"    , cmdLANG  , 1, N_("change the language preferences")},
    { "salutation",cmdSEX  , 1, N_("change card holder's salutation")},
    { "sex"       ,cmdSEX  , 1, NULL },  /* Backward compatibility.  */
    { "cafpr"   , cmdCAFPR , 1, N_("change a CA fingerprint")},
    { "forcesig", cmdFORCESIG, 1, N_("toggle the signature force PIN flag")},
    { "generate", cmdGENERATE, 1, N_("generate new keys")},
    { "passwd"  , cmdPASSWD, 0, N_("menu to change or unblock the PIN")},
    { "verify"  , cmdVERIFY, 0, N_("verify the PIN and list all data")},
    { "unblock" , cmdUNBLOCK,0, N_("unblock the PIN using a Reset Code") },
    { "factory-reset", cmdFACTORYRESET, 1, N_("destroy all keys and data")},
    { "kdf-setup", cmdKDFSETUP, 1, N_("setup KDF for PIN authentication")},
    { "key-attr", cmdKEYATTR, 1, N_("change the key attribute")},
    /* Note, that we do not announce these command yet. */
    { "privatedo", cmdPRIVATEDO, 0, NULL },
    { "readcert", cmdREADCERT, 0, NULL },
    { "writecert", cmdWRITECERT, 1, NULL },
    { NULL, cmdINVCMD, 0, NULL }
  };


#ifdef HAVE_LIBREADLINE

/* These two functions are used by readline for command completion. */

static char *
command_generator(const char *text,int state)
{
  static int list_index,len;
  const char *name;

  /* If this is a new word to complete, initialize now.  This includes
     saving the length of TEXT for efficiency, and initializing the
     index variable to 0. */
  if(!state)
    {
      list_index=0;
      len=strlen(text);
    }

  /* Return the next partial match */
  while((name=cmds[list_index].name))
    {
      /* Only complete commands that have help text */
      if(cmds[list_index++].desc && strncmp(name,text,len)==0)
	return strdup(name);
    }

  return NULL;
}

static char **
card_edit_completion(const char *text, int start, int end)
{
  (void)end;
  /* If we are at the start of a line, we try and command-complete.
     If not, just do nothing for now. */

  if(start==0)
    return rl_completion_matches(text,command_generator);

  rl_attempted_completion_over=1;

  return NULL;
}
#endif /*HAVE_LIBREADLINE*/

/* Menu to edit all user changeable values on an OpenPGP card.  Only
   Key creation is not handled here. */
void
card_edit (ctrl_t ctrl, strlist_t commands)
{
  enum cmdids cmd = cmdNOP;
  int have_commands = !!commands;
  int redisplay = 1;
  char *answer = NULL;
  int allow_admin=0;
  char serialnobuf[50];


  if (opt.command_fd != -1)
    ;
  else if (opt.batch && !have_commands)
    {
      log_error(_("can't do this in batch mode\n"));
      goto leave;
    }

  for (;;)
    {
      int arg_number;
      const char *arg_string = "";
      const char *arg_rest = "";
      char *p;
      int i;
      int cmd_admin_only;

      tty_printf("\n");
      if (redisplay)
        {
          if (opt.with_colons)
            {
              current_card_status (ctrl, es_stdout,
                                   serialnobuf, DIM (serialnobuf));
              fflush (stdout);
            }
          else
            {
              current_card_status (ctrl, NULL,
                                   serialnobuf, DIM (serialnobuf));
              tty_printf("\n");
            }
          redisplay = 0;
	}

      do
        {
          xfree (answer);
          if (have_commands)
            {
              if (commands)
                {
                  answer = xstrdup (commands->d);
                  commands = commands->next;
		}
              else if (opt.batch)
                {
                  answer = xstrdup ("quit");
		}
              else
                have_commands = 0;
	    }

	    if (!have_commands)
              {
		tty_enable_completion (card_edit_completion);
		answer = cpr_get_no_help("cardedit.prompt", _("gpg/card> "));
		cpr_kill_prompt();
		tty_disable_completion ();
              }
	    trim_spaces(answer);
	}
      while ( *answer == '#' );

      arg_number = 0; /* Yes, here is the init which egcc complains about */
      cmd_admin_only = 0;
      if (!*answer)
        cmd = cmdLIST; /* Default to the list command */
      else if (*answer == CONTROL_D)
        cmd = cmdQUIT;
      else
        {
          if ((p=strchr (answer,' ')))
            {
              *p++ = 0;
              trim_spaces (answer);
              trim_spaces (p);
              arg_number = atoi(p);
              arg_string = p;
              arg_rest = p;
              while (digitp (arg_rest))
                arg_rest++;
              while (spacep (arg_rest))
                arg_rest++;
            }

          for (i=0; cmds[i].name; i++ )
            if (!ascii_strcasecmp (answer, cmds[i].name ))
              break;

          cmd = cmds[i].id;
          cmd_admin_only = cmds[i].admin_only;
        }

      if (!allow_admin && cmd_admin_only)
	{
          tty_printf ("\n");
          tty_printf (_("Admin-only command\n"));
          continue;
        }

      switch (cmd)
        {
        case cmdHELP:
          for (i=0; cmds[i].name; i++ )
            if(cmds[i].desc
	       && (!cmds[i].admin_only || (cmds[i].admin_only && allow_admin)))
              tty_printf("%-14s %s\n", cmds[i].name, _(cmds[i].desc) );
          break;

	case cmdADMIN:
          if ( !strcmp (arg_string, "on") )
            allow_admin = 1;
          else if ( !strcmp (arg_string, "off") )
            allow_admin = 0;
          else if ( !strcmp (arg_string, "verify") )
            {
              /* Force verification of the Admin Command.  However,
                 this is only done if the retry counter is at initial
                 state.  */
              char *tmp = xmalloc (strlen (serialnobuf) + 6 + 1);
              strcpy (stpcpy (tmp, serialnobuf), "[CHV3]");
              allow_admin = !agent_scd_checkpin (tmp);
              xfree (tmp);
            }
          else /* Toggle. */
            allow_admin=!allow_admin;
	  if(allow_admin)
	    tty_printf(_("Admin commands are allowed\n"));
	  else
	    tty_printf(_("Admin commands are not allowed\n"));
	  break;

        case cmdVERIFY:
          agent_scd_checkpin (serialnobuf);
          redisplay = 1;
          break;

        case cmdLIST:
          redisplay = 1;
          break;

        case cmdNAME:
	  change_name ();
          break;

        case cmdURL:
	  change_url ();
          break;

	case cmdFETCH:
	  fetch_url (ctrl);
	  break;

        case cmdLOGIN:
	  change_login (arg_string);
          break;

        case cmdLANG:
	  change_lang ();
          break;

        case cmdSEX:
	  change_sex ();
          break;

        case cmdCAFPR:
          if ( arg_number < 1 || arg_number > 3 )
            tty_printf ("usage: cafpr N\n"
                        "       1 <= N <= 3\n");
          else
            change_cafpr (arg_number);
          break;

        case cmdPRIVATEDO:
          if ( arg_number < 1 || arg_number > 4 )
            tty_printf ("usage: privatedo N\n"
                        "       1 <= N <= 4\n");
          else
            change_private_do (arg_string, arg_number);
          break;

        case cmdWRITECERT:
          if ( arg_number != 3 )
            tty_printf ("usage: writecert 3 < FILE\n");
          else
            change_cert (arg_rest);
          break;

        case cmdREADCERT:
          if ( arg_number != 3 )
            tty_printf ("usage: readcert 3 > FILE\n");
          else
            read_cert (arg_rest);
          break;

        case cmdFORCESIG:
          toggle_forcesig ();
          break;

        case cmdGENERATE:
          generate_card_keys (ctrl);
          break;

        case cmdPASSWD:
          change_pin (0, allow_admin);
          break;

        case cmdUNBLOCK:
          change_pin (1, allow_admin);
          break;

        case cmdFACTORYRESET:
          factory_reset ();
          break;

        case cmdKDFSETUP:
          kdf_setup (arg_string);
          break;

        case cmdKEYATTR:
          key_attr ();
          break;

        case cmdQUIT:
          goto leave;

        case cmdNOP:
          break;

        case cmdINVCMD:
        default:
          tty_printf ("\n");
          tty_printf (_("Invalid command  (try \"help\")\n"));
          break;
        } /* End command switch. */
    } /* End of main menu loop. */

 leave:
  xfree (answer);
}
