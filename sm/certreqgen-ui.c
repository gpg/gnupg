/* certreqgen-ui.c - Simple user interface for certreqgen.c
 * Copyright (C) 2007 Free Software Foundation, Inc.
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301,
 * USA.
 */

#include <config.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h> 
#include <time.h>
#include <assert.h>

#include "gpgsm.h"
#include <gcrypt.h>

#include "i18n.h"
#include "ttyio.h"
#include "membuf.h"


/* Prompt for lines and append them to MB.  */
static void
ask_mb_lines (membuf_t *mb, const char *prefix)
{
  char *answer = NULL;

  do 
    {
      xfree (answer);
      answer = tty_get ("> ");
      tty_kill_prompt ();
      trim_spaces (answer);
      if (*answer)
        {
          put_membuf_str (mb, prefix);
          put_membuf_str (mb, answer);
          put_membuf (mb, "\n", 1);
        }
    }
  while (*answer);
  xfree (answer);
}

/* Helper to store stuff in a membuf.  */
void
store_key_value_lf (membuf_t *mb, const char *key, const char *value)
{
  put_membuf_str (mb, key);
  put_membuf_str (mb, value);
  put_membuf (mb, "\n", 1);
}

/* Helper tp store a membuf create by mb_ask_lines into MB.  Returns
   -1 on error. */
int
store_mb_lines (membuf_t *mb, membuf_t *lines)
{
  char *p;

  if (get_membuf_len (lines))
    {
      put_membuf (lines, "", 1);
      p = get_membuf (lines, NULL);
      if (!p)
        return -1;
      put_membuf_str (mb, p);
      xfree (p);
    }
  return 0;
}


/* This function is used to create a certificate request from the
   command line.  In the past the similar gpgsm-gencert.sh script has
   been used for it; however that scripts requires a full Unix shell
   and thus is not suitable for the Windows port.  So here is the
   re-implementation.  */
void
gpgsm_gencertreq_tty (ctrl_t ctrl, FILE *output_fp)
{
  gpg_error_t err;
  char *answer;
  int selection;
  FILE *fp = NULL;
  int method;
  char *keytype;
  char *keygrip = NULL;
  unsigned int nbits;
  int minbits = 1024;
  int maxbits = 4096;
  int defbits = 2048;
  const char *keyusage;
  char *subject_name;
  membuf_t mb_email, mb_dns, mb_uri, mb_result;
  char *result = NULL;
  int i;
  const char *s, *s2;

  init_membuf (&mb_email, 100);
  init_membuf (&mb_dns, 100);
  init_membuf (&mb_uri, 100);
  init_membuf (&mb_result, 512);

  /* Get the type of the key.  */
  tty_printf (_("Please select what kind of key you want:\n"));
  tty_printf (_("   (%d) RSA\n"), 1 );
  tty_printf (_("   (%d) Existing key\n"), 2 );
  tty_printf (_("   (%d) Existing key from card\n"), 3 );

  do
    {
      answer = tty_get (_("Your selection? "));
      tty_kill_prompt ();
      selection = *answer? atoi (answer): 1;
      xfree (answer);
    }
  while (!(selection >= 1 && selection <= 3));
  method = selection;

  /* Get  size of the key.  */
  if (method == 1)
    {
      keytype = xstrdup ("RSA");
      for (;;)
        {
          answer = tty_getf (_("What keysize do you want? (%u) "), defbits);
          tty_kill_prompt ();
          nbits = *answer? atoi (answer): defbits;
          xfree (answer);
          if (nbits < minbits || nbits > maxbits)
            tty_printf(_("%s keysizes must be in the range %u-%u\n"),
                         "RSA", minbits, maxbits);
          else
            break; /* Okay.  */
        }
      tty_printf (_("Requested keysize is %u bits\n"), nbits);
      /* We round it up so that it better matches the word size.  */
      if (( nbits % 64))
        {
          nbits = ((nbits + 63) / 64) * 64;
          tty_printf (_("rounded up to %u bits\n"), nbits);
        }
    }
  else if (method == 2)
    {
      tty_printf ("Not yet supported; "
                  "use the gpgsm-gencert.sh script instead\n");
      keytype = xstrdup ("RSA"); 
      nbits = defbits; /* We need a dummy value.  */
    }
  else /* method == 3 */
    {
      tty_printf ("Not yet supported; "
                  "use the gpgsm-gencert.sh script instead\n");
      keytype = xstrdup ("card:foobar");
      nbits = defbits; /* We need a dummy value.  */
    }

  /* Ask for the key usage.  */
  tty_printf (_("Possible actions for a %s key:\n"), "RSA");
  tty_printf (_("   (%d) sign, encrypt\n"), 1 );
  tty_printf (_("   (%d) sign\n"), 2 );
  tty_printf (_("   (%d) encrypt\n"), 3 );
  do
    {
      answer = tty_get (_("Your selection? "));
      tty_kill_prompt ();
      selection = *answer? atoi (answer): 1;
      xfree (answer);
      switch (selection)
        {
        case 1: keyusage = "sign, encrypt"; break;
        case 2: keyusage = "sign"; break;
        case 3: keyusage = "encrypt"; break;
        default: keyusage = NULL; break;
        }
    }
  while (!keyusage);

  /* Get the subject name.  */
  answer = NULL;
  do
    {
      size_t erroff, errlen;

      xfree (answer);
      answer = tty_get (_("Enter the X.509 subject name: "));
      tty_kill_prompt ();
      trim_spaces (answer);
      if (!*answer)
        tty_printf (_("No subject name given\n"));
      else if ( (err = ksba_dn_teststr (answer, 0, &erroff, &errlen)) )
        {
          if (gpg_err_code (err) == GPG_ERR_UNKNOWN_NAME)
            tty_printf (_("Invalid subject name label `%.*s'\n"),
                        (int)errlen, answer+erroff);
          else
            {
              /* TRANSLATORS: The 22 in the second string is the
                 length of the first string up to the "%s".  Please
                 adjust it do the length of your translation.  The
                 second string is merely passed to atoi so you can
                 drop everything after the number.  */
              tty_printf (_("Invalid subject name `%s'\n"), answer);
              tty_printf ("%*s^\n",
                          atoi (_("22 translator: see "
                                  "certreg-ui.c:gpgsm_gencertreq_tty"))
                          + (int)erroff, "");
            }
          *answer = 0;
        }
    }
  while (!*answer);
  subject_name = answer;
  answer = NULL;

  /* Get the email addresses. */
  tty_printf (_("Enter email addresses"));
  tty_printf (_(" (end with an empty line):\n"));
  ask_mb_lines (&mb_email, "Name-Email: ");

  /* DNS names.  */
  tty_printf (_("Enter DNS names"));
  tty_printf (_(" (optional; end with an empty line):\n"));
  ask_mb_lines (&mb_email, "Name-DNS: ");

  /* URIs.  */
  tty_printf (_("Enter URIs"));
  tty_printf (_(" (optional; end with an empty line):\n"));
  ask_mb_lines (&mb_email, "Name-URI: ");


  /* Put it all together.  */
  store_key_value_lf (&mb_result, "Key-Type: ", keytype);
  {
    char numbuf[30];
    snprintf (numbuf, sizeof numbuf, "%u", nbits);
    store_key_value_lf (&mb_result, "Key-Length: ", numbuf);
  }
  store_key_value_lf (&mb_result, "Key-Usage: ", keyusage);
  store_key_value_lf (&mb_result, "Name-DN: ", subject_name);
  if (keygrip)
    store_key_value_lf (&mb_result, "Key-Grip: ", keygrip);
  if (store_mb_lines (&mb_result, &mb_email))
    goto mem_error;
  if (store_mb_lines (&mb_result, &mb_dns))
    goto mem_error;
  if (store_mb_lines (&mb_result, &mb_uri))
    goto mem_error;
  put_membuf (&mb_result, "", 1);
  result = get_membuf (&mb_result, NULL);
  if (!result)
    goto mem_error;

  tty_printf (_("Parameters to be used for the certificate request:\n"));
  for (s=result; (s2 = strchr (s, '\n')); s = s2+1, i++)
    tty_printf ("    %.*s\n", (int)(s2-s), s);
  tty_printf ("\n");


  if (!tty_get_answer_is_yes ("Really create request? (y/N) "))
     goto leave;

  /* Now create a parameter file and generate the key.  */
  fp = tmpfile ();
  if (!fp)
    {
      log_error (_("error creating temporary file: %s\n"), strerror (errno));
      goto leave;
    }
  fputs (result, fp);
  rewind (fp);
  tty_printf (_("Now creating certificate request.  "
                "This may take a while ...\n"));
  {
    int save_pem = ctrl->create_pem;
    ctrl->create_pem = 1; /* Force creation of PEM. */
    err = gpgsm_genkey (ctrl, -1, fp, output_fp);
    ctrl->create_pem = save_pem;
  }
  if (!err)
    tty_printf (_("Ready.  You should now send this request to your CA.\n"));


  goto leave;
 mem_error:
  log_error (_("resource problem: out or core\n"));
 leave:
  if (fp)
    fclose (fp);
  xfree (keytype);         
  xfree (subject_name);
  xfree (keygrip);
  xfree (get_membuf (&mb_email, NULL));
  xfree (get_membuf (&mb_dns, NULL));
  xfree (get_membuf (&mb_uri, NULL));
  xfree (get_membuf (&mb_result, NULL));
  xfree (result);
}
