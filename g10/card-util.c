/* card-util.c - Utility functions for the OpenPGP card.
 * Copyright (C) 2003, 2004, 2005, 2009 Free Software Foundation, Inc.
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
#include <string.h>
#include <errno.h>
#include <assert.h>
#ifdef HAVE_LIBREADLINE
# define GNUPG_LIBREADLINE_H_INCLUDED
# include <readline/readline.h>
#endif /*HAVE_LIBREADLINE*/

#if GNUPG_MAJOR_VERSION != 1
# include "gpg.h"
#endif /*GNUPG_MAJOR_VERSION != 1*/
#include "util.h"
#include "i18n.h"
#include "ttyio.h"
#include "status.h"
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


/* Change the PIN of a an OpenPGP card.  This is an interactive
   function. */
void
change_pin (int unblock_v2, int allow_admin)
{
  struct agent_card_info_s info;
  int rc;

  rc = agent_learn (&info);
  if (rc)
    {
      log_error (_("OpenPGP card not available: %s\n"),
                  gpg_strerror (rc));
      return;
    }
  
  log_info (_("OpenPGP card no. %s detected\n"),
              info.serialno? info.serialno : "[none]");

  agent_clear_pin_cache (info.serialno);

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

	rc = 0;
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

static const char *
get_manufacturer (unsigned int no)
{
  /* Note:  Make sure that there is no colon or linefeed in the string. */
  switch (no)
    {
    case 0x0001: return "PPC Card Systems";
    case 0x0002: return "Prism";
    case 0x0003: return "OpenFortress";
    case 0x0004: return "Wewid AB";
    case 0x0005: return "ZeitControl";

    case 0x002A: return "Magrathea";

    case 0xF517: return "FSIJ";

      /* 0x00000 and 0xFFFF are defined as test cards per spec,
         0xFFF00 to 0xFFFE are assigned for use with randomly created
         serial numbers.  */
    case 0x0000:
    case 0xffff: return "test card";
    default: return (no & 0xff00) == 0xff00? "unmanaged S/N range":"unknown";
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
            tty_fprintf (fp, " ");
          tty_fprintf (fp, " %02X%02X", *fpr, fpr[1]);
        }
    }
  else
    tty_fprintf (fp, " [none]");
  tty_fprintf (fp, "\n");
}


static void
print_sha1_fpr_colon (FILE *fp, const unsigned char *fpr)
{
  int i;

  if (fpr)
    {
      for (i=0; i < 20 ; i++, fpr++)
        fprintf (fp, "%02X", *fpr);
    }
  putc (':', fp);
}


static void
print_name (FILE *fp, const char *text, const char *name)
{
  tty_fprintf (fp, "%s", text);

  /* FIXME: tty_printf_utf8_string2 eats everything after and
     including an @ - e.g. when printing an url. */
  if (name && *name)
    {
      if (fp)
        print_utf8_string2 (fp, name, strlen (name), '\n');
      else
        tty_print_utf8_string2 (name, strlen (name), 0);
    }
  else
    tty_fprintf (fp, _("[not set]"));
  tty_fprintf (fp, "\n");
}

static void
print_isoname (FILE *fp, const char *text, const char *tag, const char *name)
{
  if (opt.with_colons)
    fprintf (fp, "%s:", tag);
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
            print_string (fp, given, strlen (given), ':');
          else if (fp)
            print_utf8_string2 (fp, given, strlen (given), '\n');
          else
            tty_print_utf8_string2 (given, strlen (given), 0);

          if (opt.with_colons)
            putc (':', fp);
          else if (*buf)
            tty_fprintf (fp, " ");
        }

      if (opt.with_colons)
        print_string (fp, buf, strlen (buf), ':');
      else if (fp)
        print_utf8_string2 (fp, buf, strlen (buf), '\n');
      else
        tty_print_utf8_string2 (buf, strlen (buf), 0);
      xfree (buf);
    }
  else
    {
      if (opt.with_colons)
        putc (':', fp);
      else
        tty_fprintf (fp, _("[not set]"));
    }

  if (opt.with_colons)
    fputs (":\n", fp);
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
void
card_status (FILE *fp, char *serialno, size_t serialnobuflen)
{
  struct agent_card_info_s info;
  PKT_public_key *pk = xcalloc (1, sizeof *pk);
  int rc;
  unsigned int uval;
  const unsigned char *thefpr;
  int i;

  if (serialno && serialnobuflen)
    *serialno = 0;

  rc = agent_learn (&info);
  if (rc)
    {
      if (opt.with_colons)
        fputs ("AID:::\n", fp);
      log_error (_("OpenPGP card not available: %s\n"),
                  gpg_strerror (rc));
      xfree (pk);
      return;
    }

  if (opt.with_colons)
    fprintf (fp, "AID:%s:", info.serialno? info.serialno : "");
  else
    tty_fprintf (fp, "Application ID ...: %s\n",
                 info.serialno? info.serialno : "[none]");
  if (!info.serialno || strncmp (info.serialno, "D27600012401", 12) 
      || strlen (info.serialno) != 32 )
    {
      if (info.apptype && !strcmp (info.apptype, "NKS"))
        {
          if (opt.with_colons)
            fputs ("netkey-card:\n", fp);
          log_info ("this is a NetKey card\n");
        }
      else if (info.apptype && !strcmp (info.apptype, "DINSIG"))
        {
          if (opt.with_colons)
            fputs ("dinsig-card:\n", fp);
          log_info ("this is a DINSIG compliant card\n");
        }
      else if (info.apptype && !strcmp (info.apptype, "P15"))
        {
          if (opt.with_colons)
            fputs ("pkcs15-card:\n", fp);
          log_info ("this is a PKCS#15 compliant card\n");
        }
      else if (info.apptype && !strcmp (info.apptype, "GELDKARTE"))
        {
          if (opt.with_colons)
            fputs ("geldkarte-card:\n", fp);
          log_info ("this is a Geldkarte compliant card\n");
        }
      else
        {
          if (opt.with_colons)
            fputs ("unknown:\n", fp);
        }
      log_info ("not an OpenPGP card\n");
      agent_release_card_info (&info);
      xfree (pk);
      return;
    }

  if (!serialno)
    ;
  else if (strlen (serialno)+1 > serialnobuflen)
    log_error ("serial number longer than expected\n");
  else 
    strcpy (serialno, info.serialno);

  if (opt.with_colons)
    fputs ("openpgp-card:\n", fp);


  if (opt.with_colons)
    {
      fprintf (fp, "version:%.4s:\n", info.serialno+12);
      uval = xtoi_2(info.serialno+16)*256 + xtoi_2 (info.serialno+18);
      fprintf (fp, "vendor:%04x:%s:\n", uval, get_manufacturer (uval));
      fprintf (fp, "serial:%.8s:\n", info.serialno+20);
      
      print_isoname (fp, "Name of cardholder: ", "name", info.disp_name);

      fputs ("lang:", fp);
      if (info.disp_lang)
        print_string (fp, info.disp_lang, strlen (info.disp_lang), ':');
      fputs (":\n", fp);

      fprintf (fp, "sex:%c:\n", (info.disp_sex == 1? 'm':
                                 info.disp_sex == 2? 'f' : 'u'));

      fputs ("url:", fp);
      if (info.pubkey_url)
        print_string (fp, info.pubkey_url, strlen (info.pubkey_url), ':');
      fputs (":\n", fp);

      fputs ("login:", fp);
      if (info.login_data)
        print_string (fp, info.login_data, strlen (info.login_data), ':');
      fputs (":\n", fp);

      fprintf (fp, "forcepin:%d:::\n", !info.chv1_cached);
      for (i=0; i < DIM (info.key_attr); i++)
        if (info.key_attr[0].algo)
          fprintf (fp, "keyattr:%d:%d:%u:\n", i+1,
                   info.key_attr[i].algo, info.key_attr[i].nbits);
      fprintf (fp, "maxpinlen:%d:%d:%d:\n",
                   info.chvmaxlen[0], info.chvmaxlen[1], info.chvmaxlen[2]);
      fprintf (fp, "pinretry:%d:%d:%d:\n",
                   info.chvretry[0], info.chvretry[1], info.chvretry[2]);
      fprintf (fp, "sigcount:%lu:::\n", info.sig_counter);

      for (i=0; i < 4; i++)
        {
          if (info.private_do[i])
            {
              fprintf (fp, "private_do:%d:", i+1);
              print_string (fp, info.private_do[i],
                            strlen (info.private_do[i]), ':');
              fputs (":\n", fp);
            }
        }

      fputs ("cafpr:", fp);
      print_sha1_fpr_colon (fp, info.cafpr1valid? info.cafpr1:NULL);
      print_sha1_fpr_colon (fp, info.cafpr2valid? info.cafpr2:NULL);
      print_sha1_fpr_colon (fp, info.cafpr3valid? info.cafpr3:NULL);
      putc ('\n', fp);
      fputs ("fpr:", fp);
      print_sha1_fpr_colon (fp, info.fpr1valid? info.fpr1:NULL);
      print_sha1_fpr_colon (fp, info.fpr2valid? info.fpr2:NULL);
      print_sha1_fpr_colon (fp, info.fpr3valid? info.fpr3:NULL);
      putc ('\n', fp);
      fprintf (fp, "fprtime:%lu:%lu:%lu:\n",
               (unsigned long)info.fpr1time, (unsigned long)info.fpr2time,
               (unsigned long)info.fpr3time);
    }
  else 
    {
      tty_fprintf (fp, "Version ..........: %.1s%c.%.1s%c\n",
                   info.serialno[12] == '0'?"":info.serialno+12,
                   info.serialno[13],
                   info.serialno[14] == '0'?"":info.serialno+14,
                   info.serialno[15]);
      tty_fprintf (fp, "Manufacturer .....: %s\n", 
                   get_manufacturer (xtoi_2(info.serialno+16)*256
                                     + xtoi_2 (info.serialno+18)));
      tty_fprintf (fp, "Serial number ....: %.8s\n", info.serialno+20);
      
      print_isoname (fp, "Name of cardholder: ", "name", info.disp_name);
      print_name (fp, "Language prefs ...: ", info.disp_lang);
      tty_fprintf (fp,    "Sex ..............: %s\n",
                   info.disp_sex == 1? _("male"):
                   info.disp_sex == 2? _("female") : _("unspecified"));
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
            tty_fprintf (fp, " %u%c",
                         info.key_attr[i].nbits,
                         info.key_attr[i].algo == 1? 'R':
                         info.key_attr[i].algo == 17? 'D': '?');
          tty_fprintf (fp, "\n");
        }
      tty_fprintf (fp,    "Max. PIN lengths .: %d %d %d\n",
                   info.chvmaxlen[0], info.chvmaxlen[1], info.chvmaxlen[2]);
      tty_fprintf (fp,    "PIN retry counter : %d %d %d\n",
                   info.chvretry[0], info.chvretry[1], info.chvretry[2]);
      tty_fprintf (fp,    "Signature counter : %lu\n", info.sig_counter);
      tty_fprintf (fp, "Signature key ....:");
      print_sha1_fpr (fp, info.fpr1valid? info.fpr1:NULL);
      if (info.fpr1valid && info.fpr1time)
        tty_fprintf (fp, "      created ....: %s\n",
                     isotimestamp (info.fpr1time));
      tty_fprintf (fp, "Encryption key....:");
      print_sha1_fpr (fp, info.fpr2valid? info.fpr2:NULL);
      if (info.fpr2valid && info.fpr2time)
        tty_fprintf (fp, "      created ....: %s\n",
                     isotimestamp (info.fpr2time));
      tty_fprintf (fp, "Authentication key:");
      print_sha1_fpr (fp, info.fpr3valid? info.fpr3:NULL);
      if (info.fpr3valid && info.fpr3time)
        tty_fprintf (fp, "      created ....: %s\n",
                     isotimestamp (info.fpr3time));
      tty_fprintf (fp, "General key info..: "); 

      thefpr = (info.fpr1valid? info.fpr1 : info.fpr2valid? info.fpr2 : 
                info.fpr3valid? info.fpr3 : NULL);
      /* If the fingerprint is all 0xff, the key has no asssociated
         OpenPGP certificate.  */
      if ( thefpr && !fpr_is_ff (thefpr) 
           && !get_pubkey_byfprint (pk, thefpr, 20))
        {
          KBNODE keyblock = NULL;

          print_pubkey_info (fp, pk);

          if ( !get_seckeyblock_byfprint (&keyblock, thefpr, 20) )
            print_card_key_info (fp, keyblock);
          else if ( !get_keyblock_byfprint (&keyblock, thefpr, 20) )
            {
              release_kbnode (keyblock);
              keyblock = NULL;
              
              if (!auto_create_card_key_stub (info.serialno,
                                              info.fpr1valid? info.fpr1:NULL,
                                              info.fpr2valid? info.fpr2:NULL,
                                              info.fpr3valid? info.fpr3:NULL))
                {
                  if ( !get_seckeyblock_byfprint (&keyblock, thefpr, 20) )
                    print_card_key_info (fp, keyblock);
                }
            }

          release_kbnode (keyblock);
        }
      else
        tty_fprintf (fp, "[none]\n");
    }
      
  free_public_key (pk);
  agent_release_card_info (&info);
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
  char *isoname, *p;
  int rc;

  surname = get_one_name ("keygen.smartcard.surname",
                                    _("Cardholder's surname: "));
  givenname = get_one_name ("keygen.smartcard.givenname",
                                       _("Cardholder's given name: "));
  if (!surname || !givenname || (!*surname && !*givenname))
    {
      xfree (surname);
      xfree (givenname);
      return -1; /*canceled*/
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
      return -1;
    }

  rc = agent_scd_setattr ("DISP-NAME", isoname, strlen (isoname), NULL );
  if (rc)
    log_error ("error setting Name: %s\n", gpg_strerror (rc));

  xfree (isoname);
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

  if (strlen (url) > 254 )
    {
      tty_printf (_("Error: URL too long "
                    "(limit is %d characters).\n"), 254);    
      xfree (url);
      return -1;
    }

  rc = agent_scd_setattr ("PUBKEY-URL", url, strlen (url), NULL );
  if (rc)
    log_error ("error setting URL: %s\n", gpg_strerror (rc));
  xfree (url);
  write_sc_op_status (rc);
  return rc;
}


/* Fetch the key from the URL given on the card or try to get it from
   the default keyserver.  */
static int
fetch_url(void)
{
  int rc;
  struct agent_card_info_s info;

  memset(&info,0,sizeof(info));

  rc=agent_scd_getattr("PUBKEY-URL",&info);
  if(rc)
    log_error("error retrieving URL from card: %s\n",gpg_strerror(rc));
  else
    {
      struct keyserver_spec *spec=NULL;

      rc=agent_scd_getattr("KEY-FPR",&info);
      if(rc)
	log_error("error retrieving key fingerprint from card: %s\n",
		  gpg_strerror(rc));
      else if (info.pubkey_url && *info.pubkey_url)
	{
	  spec=parse_keyserver_uri(info.pubkey_url,1,NULL,0);
	  if(spec && info.fpr1valid)
	    {
	      /* This is not perfectly right.  Currently, all card
		 fingerprints are 20 digits, but what about
		 fingerprints for a future v5 key?  We should get the
		 length from somewhere lower in the code.  In any
		 event, the fpr/keyid is not meaningful for straight
		 HTTP fetches, but using it allows the card to point
		 to HKP and LDAP servers as well. */
	      rc=keyserver_import_fprint(info.fpr1,20,spec);
	      free_keyserver_spec(spec);
	    }
	}
      else if (info.fpr1valid)
	{
          rc = keyserver_import_fprint (info.fpr1, 20, opt.keyserver);
	}
    }

  return rc;
}


/* Read data from file FNAME up to MAXLEN characters.  On error return
   -1 and store NULL at R_BUFFER; on success return the number of
   bytes read and store the address of a newly allocated buffer at
   R_BUFFER. */
static int
get_data_from_file (const char *fname, size_t maxlen, char **r_buffer)
{
  FILE *fp;
  char *data;
  int n;
  
  *r_buffer = NULL;

  fp = fopen (fname, "rb");
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
      tty_printf (_("can't open `%s': %s\n"), fname, strerror (errno));
      return -1;
    }
          
  data = xtrymalloc (maxlen? maxlen:1);
  if (!data)
    {
      tty_printf (_("error allocating enough memory: %s\n"), strerror (errno));
      fclose (fp);
      return -1;
    }

  if (maxlen)
    n = fread (data, 1, maxlen, fp);
  else
    n = 0;
  fclose (fp);
  if (n < 0)
    {
      tty_printf (_("error reading `%s': %s\n"), fname, strerror (errno));
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
  FILE *fp;
  
  fp = fopen (fname, "wb");
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
      tty_printf (_("can't create `%s': %s\n"), fname, strerror (errno));
      return -1;
    }
          
  if (length && fwrite (buffer, length, 1, fp) != 1)
    {
      tty_printf (_("error writing `%s': %s\n"), fname, strerror (errno));
      fclose (fp);
      return -1;
    }
  fclose (fp);
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
      n = get_data_from_file (args, 254, &data);
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

  if (n > 254 )
    {
      tty_printf (_("Error: Login data too long "
                    "(limit is %d characters).\n"), 254);    
      xfree (data);
      return -1;
    }

  rc = agent_scd_setattr ("LOGIN-DATA", data, n, NULL );
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

  assert (nr >= 1 && nr <= 4);
  do_name[11] = '0' + nr;

  if (args && (args = strchr (args, '<')))  /* Read it from a file */
    {
      for (args++; spacep (args); args++)
        ;
      n = get_data_from_file (args, 254, &data);
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

  if (n > 254 )
    {
      tty_printf (_("Error: Private DO too long "
                    "(limit is %d characters).\n"), 254);    
      xfree (data);
      return -1;
    }

  rc = agent_scd_setattr (do_name, data, n, NULL );
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
      n = get_data_from_file (args, 16384, &data);
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

  rc = agent_scd_setattr ("DISP-LANG", data, strlen (data), NULL );
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
                  _("Sex ((M)ale, (F)emale or space): "));
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
     
  rc = agent_scd_setattr ("DISP-SEX", str, 1, NULL );
  if (rc)
    log_error ("error setting sex: %s\n", gpg_strerror (rc));
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
                          fprno==3?"CA-FPR-3":"x", fpr, 20, NULL );
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

  rc = agent_scd_setattr ("CHV-STATUS-1", newstate? "\x01":"", 1, NULL);
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
  if (rc || !info->serialno || strncmp (info->serialno, "D27600012401", 12) 
      || strlen (info->serialno) != 32 )
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

  agent_clear_pin_cache (info->serialno);

  *forced_chv1 = !info->chv1_cached;
  if (*forced_chv1)
    { /* Switch off the forced mode so that during key generation we
         don't get bothered with PIN queries for each
         self-signature. */
      rc = agent_scd_setattr ("CHV-STATUS-1", "\x01", 1, info->serialno);
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
      rc = agent_scd_setattr ("CHV-STATUS-1", "", 1, NULL);
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
  assert (keyno >= 0 && keyno <= 3);

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
    (_("NOTE: There is no guarantee that the card "
       "supports the requested size.\n"
       "      If the key generation does not succeed, "
       "please check the\n"
       "      documentation of your card to see what "
       "sizes are allowed.\n"));
}


/* Ask for the size of a card key.  NBITS is the current size
   configured for the card.  KEYNO is the number of the key used to
   select the prompt.  Returns 0 to use the default size (i.e. NBITS)
   or the selected size.  */
static unsigned int
ask_card_keysize (int keyno, unsigned int nbits)
{
  unsigned int min_nbits = 1024;
  unsigned int max_nbits = 4096;
  char *prompt, *answer;
  unsigned int req_nbits;

  for (;;)
    {
      prompt = xasprintf 
        (keyno == 0?
         _("What keysize do you want for the Signature key? (%u) "):
         keyno == 1?
         _("What keysize do you want for the Encryption key? (%u) "):
         _("What keysize do you want for the Authentication key? (%u) "),
         nbits);
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
        {
          tty_printf (_("The card will now be re-configured "
                        "to generate a key of %u bits\n"), req_nbits);
          show_keysize_warning ();
          return req_nbits;
        }
    }
}


/* Change the size of key KEYNO (0..2) to NBITS and show an error
   message if that fails.  */
static gpg_error_t
do_change_keysize (int keyno, unsigned int nbits) 
{
  gpg_error_t err;
  char args[100];
  
  snprintf (args, sizeof args, "--force %d 1 %u", keyno+1, nbits);
  err = agent_scd_setattr ("KEY-ATTR", args, strlen (args), NULL);
  if (err)
    log_error (_("error changing size of key %d to %u bits: %s\n"), 
               keyno+1, nbits, gpg_strerror (err));
  return err;
}
 

static void
generate_card_keys (void)
{
  struct agent_card_info_s info;
  int forced_chv1;
  int want_backup;
  int keyno;

  if (get_info_for_key_operation (&info))
    return;

  if (info.extcap.ki)
    {
      char *answer;

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
      log_info (_("NOTE: keys are already stored on the card!\n"));
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
                    "   PIN = `%s'     Admin PIN = `%s'\n"
                    "You should change them using the command --change-pin\n"),
                  "123456", "12345678");
      tty_printf ("\n");
    }

  if (check_pin_for_key_operation (&info, &forced_chv1))
    goto leave;

  /* If the cards features changeable key attributes, we ask for the
     key size.  */
  if (info.is_v2 && info.extcap.aac)
    {
      unsigned int nbits;

      for (keyno = 0; keyno < DIM (info.key_attr); keyno++)
        {
          nbits = ask_card_keysize (keyno, info.key_attr[keyno].nbits);
          if (nbits && do_change_keysize (keyno, nbits))
            {
              /* Error: Better read the default key size again.  */
              agent_release_card_info (&info);
              if (get_info_for_key_operation (&info))
                goto leave;
              /* Ask again for this key size. */
              keyno--;
            }
        }
      /* Note that INFO has not be synced.  However we will only use
         the serialnumber and thus it won't harm.  */
    }
     
  generate_keypair (NULL, info.serialno, want_backup? opt.homedir:NULL);

 leave:
  agent_release_card_info (&info);
  restore_forced_chv1 (&forced_chv1);
}


/* This function is used by the key edit menu to generate an arbitrary
   subkey. */
int
card_generate_subkey (KBNODE pub_keyblock, KBNODE sec_keyblock)
{
  struct agent_card_info_s info;
  int okay = 0;
  int forced_chv1 = 0;
  int keyno;

  if (get_info_for_key_operation (&info))
    return 0;

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
          goto leave;
        }
      keyno = *answer? atoi(answer): 0;
      xfree(answer);
      if (keyno >= 1 && keyno <= 3)
        break; /* Okay. */
      tty_printf(_("Invalid selection.\n"));
    }

  if (replace_existing_key_p (&info, keyno))
    goto leave;

  if (check_pin_for_key_operation (&info, &forced_chv1))
    goto leave;

  /* If the cards features changeable key attributes, we ask for the
     key size.  */
  if (info.is_v2 && info.extcap.aac)
    {
      unsigned int nbits;

    ask_again:
      nbits = ask_card_keysize (keyno-1, info.key_attr[keyno-1].nbits);
      if (nbits && do_change_keysize (keyno-1, nbits))
        {
          /* Error: Better read the default key size again.  */
          agent_release_card_info (&info);
          if (get_info_for_key_operation (&info))
            goto leave;
          goto ask_again;
        }
      /* Note that INFO has not be synced.  However we will only use
         the serialnumber and thus it won't harm.  */
    }

  okay = generate_card_subkeypair (pub_keyblock, sec_keyblock,
                                   keyno, info.serialno);

 leave:
  agent_release_card_info (&info);
  restore_forced_chv1 (&forced_chv1);
  return okay;
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
  int rc;
  int keyno, i;
  PKT_secret_key *copied_sk = NULL;
  PKT_secret_key *sk;
  size_t n;
  const char *s;
  int allow_keyno[3];
  unsigned int nbits;


  assert (node->pkt->pkttype == PKT_SECRET_KEY
          || node->pkt->pkttype == PKT_SECRET_SUBKEY);
  sk = node->pkt->pkt.secret_key;

  if (get_info_for_key_operation (&info))
    return 0;

  if (!info.extcap.ki)
    {
      tty_printf ("The card does not support the import of keys\n");
      tty_printf ("\n");
      goto leave;
    }

  show_card_key_info (&info);

  nbits = nbits_from_sk (sk);

  if (!is_RSA (sk->pubkey_algo) || (!info.is_v2 && nbits != 1024) )
    {
      tty_printf ("You may only store a 1024 bit RSA key on the card\n");
      tty_printf ("\n");
      goto leave;
    }

  allow_keyno[0] = (!use || (use & (PUBKEY_USAGE_SIG)));
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

  if (replace_existing_key_p (&info, keyno))
    goto leave;

  /* Unprotect key.  */
  switch (is_secret_key_protected (sk) )
    {
    case 0: /* Not protected. */
      break;
    case -1:
      log_error (_("unknown key protection algorithm\n"));
      goto leave;
    default:
      if (sk->protect.s2k.mode == 1001)
        {
          log_error (_("secret parts of key are not available\n"));
          goto leave;
	}
      if (sk->protect.s2k.mode == 1002)
        {
          log_error (_("secret key already stored on a card\n"));
          goto leave;
	}
      /* We better copy the key before we unprotect it.  */
      copied_sk = sk = copy_secret_key (NULL, sk);
      rc = check_secret_key (sk, 0);
      if (rc)
        goto leave;
    }

  rc = save_unprotected_key_to_card (sk, keyno);
  if (rc)
    {
      log_error (_("error writing key to card: %s\n"), gpg_strerror (rc));
      goto leave;
    }

  /* Get back to the maybe protected original secret key.  */
  if (copied_sk)
    {
      free_secret_key (copied_sk);
      copied_sk = NULL; 
    }
  sk = node->pkt->pkt.secret_key;

  /* Get rid of the secret key parameters and store the serial numer. */
  n = pubkey_get_nskey (sk->pubkey_algo);
  for (i=pubkey_get_npkey (sk->pubkey_algo); i < n; i++)
    {
      gcry_mpi_release (sk->skey[i]);
      sk->skey[i] = NULL;
    }
  i = pubkey_get_npkey (sk->pubkey_algo);
  sk->skey[i] = gcry_mpi_set_opaque (NULL, xstrdup ("dummydata"), 10*8);
  sk->is_protected = 1;
  sk->protect.s2k.mode = 1002;
  s = info.serialno;
  for (sk->protect.ivlen=0; sk->protect.ivlen < 16 && *s && s[1];
       sk->protect.ivlen++, s += 2)
    sk->protect.iv[sk->protect.ivlen] = xtoi_2 (s);

  okay = 1;

 leave:
  if (copied_sk)
    free_secret_key (copied_sk);
  agent_release_card_info (&info);
  return okay;
}



/* Data used by the command parser.  This needs to be outside of the
   function scope to allow readline based command completion.  */
enum cmdids
  {
    cmdNOP = 0,
    cmdQUIT, cmdADMIN, cmdHELP, cmdLIST, cmdDEBUG, cmdVERIFY,
    cmdNAME, cmdURL, cmdFETCH, cmdLOGIN, cmdLANG, cmdSEX, cmdCAFPR,
    cmdFORCESIG, cmdGENERATE, cmdPASSWD, cmdPRIVATEDO, cmdWRITECERT,
    cmdREADCERT, cmdUNBLOCK,
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
    { "sex"     , cmdSEX   , 1, N_("change card holder's sex")},
    { "cafpr"   , cmdCAFPR , 1, N_("change a CA fingerprint")},
    { "forcesig", cmdFORCESIG, 1, N_("toggle the signature force PIN flag")},
    { "generate", cmdGENERATE, 1, N_("generate new keys")},
    { "passwd"  , cmdPASSWD, 0, N_("menu to change or unblock the PIN")},
    { "verify"  , cmdVERIFY, 0, N_("verify the PIN and list all data")},
    { "unblock" , cmdUNBLOCK,0, N_("unblock the PIN using a Reset Code") },
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
card_edit (strlist_t commands)
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
      if (redisplay )
        {
          if (opt.with_colons)
            {
              card_status (stdout, serialnobuf, DIM (serialnobuf));
              fflush (stdout);
            }
          else
            {
              card_status (NULL, serialnobuf, DIM (serialnobuf));
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
              tty_printf("%-10s %s\n", cmds[i].name, _(cmds[i].desc) );
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
	  fetch_url();
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
          generate_card_keys ();
          break;

        case cmdPASSWD:
          change_pin (0, allow_admin);
          break;

        case cmdUNBLOCK:
          change_pin (1, allow_admin);
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

