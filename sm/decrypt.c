/* decrypt.c - Decrypt a message
 *	Copyright (C) 2001 Free Software Foundation, Inc.
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
#include <unistd.h> 
#include <time.h>
#include <assert.h>

#include <gcrypt.h>
#include <ksba.h>

#include "gpgsm.h"
#include "keydb.h"
#include "i18n.h"

static void
print_integer (unsigned char *p)
{
  unsigned long len;

  if (!p)
    log_printf ("none");
  else
    {
      len = (p[0] << 24) | (p[1] << 16) | (p[2] << 8) | p[3];
      for (p+=4; len; len--, p++)
        log_printf ("%02X", *p);
    }
}




/* Perform a decrypt operation.  */
int
gpgsm_decrypt (CTRL ctrl, int in_fd, FILE *out_fp)
{
  int rc;
  KsbaError err;
  Base64Context b64reader = NULL;
  Base64Context b64writer = NULL;
  KsbaReader reader;
  KsbaWriter writer;
  KsbaCMS cms = NULL;
  KsbaStopReason stopreason;
  KEYDB_HANDLE kh;
  int recp;
  FILE *in_fp = NULL;

  kh = keydb_new (0);
  if (!kh)
    {
      log_error (_("failed to allocated keyDB handle\n"));
      rc = GNUPG_General_Error;
      goto leave;
    }


  in_fp = fdopen ( dup (in_fd), "rb");
  if (!in_fp)
    {
      log_error ("fdopen() failed: %s\n", strerror (errno));
      rc = seterr (IO_Error);
      goto leave;
    }

  rc = gpgsm_create_reader (&b64reader, ctrl, in_fp, &reader);
  if (rc)
    {
      log_error ("can't create reader: %s\n", gnupg_strerror (rc));
      goto leave;
    }

  rc = gpgsm_create_writer (&b64reader, ctrl, out_fp, &writer);
  if (rc)
    {
      log_error ("can't create writer: %s\n", gnupg_strerror (rc));
      goto leave;
    }

  cms = ksba_cms_new ();
  if (!cms)
    {
      rc = seterr (Out_Of_Core);
      goto leave;
    }

  err = ksba_cms_set_reader_writer (cms, reader, writer);
  if (err)
    {
      log_debug ("ksba_cms_set_reader_writer failed: %s\n",
                 ksba_strerror (err));
      rc = map_ksba_err (err);
      goto leave;
    }

  /* parser loop */
  do 
    {
      err = ksba_cms_parse (cms, &stopreason);
      if (err)
        {
          log_debug ("ksba_cms_parse failed: %s\n", ksba_strerror (err));
          rc = map_ksba_err (err);
          goto leave;
        }
      log_debug ("ksba_cms_parse - stop reason %d\n", stopreason);

      if (stopreason == KSBA_SR_BEGIN_DATA
          || stopreason == KSBA_SR_DETACHED_DATA)
        {
          for (recp=0; recp < 1; recp++)
            {
              char *issuer;
              unsigned char *serial;
              char *enc_val;
              char *hexkeygrip = NULL;

              err = ksba_cms_get_issuer_serial (cms, recp, &issuer, &serial);
              if (err)
                log_error ("recp %d - error getting info: %s\n",
                           recp, ksba_strerror (err));
              else
                {
                  KsbaCert cert = NULL;

                  log_debug ("recp %d - issuer: `%s'\n",
                             recp, issuer? issuer:"[NONE]");
                  log_debug ("recp %d - serial: ", recp);
                  print_integer (serial);
                  log_printf ("\n");

                  keydb_search_reset (kh);
                  rc = keydb_search_issuer_sn (kh, issuer, serial);
                  if (rc)
                    {
                      log_debug ("failed to find the certificate: %s\n",
                                 gnupg_strerror(rc));
                      goto oops;
                    }

                  rc = keydb_get_cert (kh, &cert);
                  if (rc)
                    {
                      log_debug ("failed to get cert: %s\n", gnupg_strerror (rc));
                      goto oops;
                    }

                  hexkeygrip = gpgsm_get_keygrip_hexstring (cert);

                oops:
                  xfree (issuer);
                  xfree (serial);
                  ksba_cert_release (cert);
                }

              enc_val = ksba_cms_get_enc_val (cms, recp);
              if (!enc_val)
                log_error ("recp %d - error getting encrypted session key\n",
                           recp);
              else
                {
                  char *seskey;
                  size_t seskeylen;

                  log_debug ("recp %d - enc-val: `%s'\n",
                             recp, enc_val);

                  rc = gpgsm_agent_pkdecrypt (hexkeygrip,
                                              enc_val, strlen (enc_val),
                                              &seskey, &seskeylen);
                  if (rc)
                    log_debug ("problem: %s\n", gnupg_strerror (rc));
                  else
                    {
                      unsigned char *p;
                      log_debug ("plaintext=");
                      for (p=seskey; seskeylen; seskeylen--, p++)
                        log_printf (" %02X", *p);
                      log_printf ("\n");
                    }
                  xfree (enc_val);
                }
            }
        }



    }
  while (stopreason != KSBA_SR_READY);   

 leave:
  ksba_cms_release (cms);
  gpgsm_destroy_reader (b64reader);
  gpgsm_destroy_writer (b64writer);
  keydb_release (kh); 
  if (in_fp)
    fclose (in_fp);
  return rc;
}


