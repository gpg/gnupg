/* divert-scd.c - divert operations to the scdaemon 
 *	Copyright (C) 2002, 2003 Free Software Foundation, Inc.
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
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <assert.h>
#include <unistd.h>
#include <sys/stat.h>

#include "agent.h"
#include "sexp-parse.h"
#include "i18n.h"


static int
ask_for_card (CTRL ctrl, const unsigned char *shadow_info, char **r_kid)
{
  int rc, i;
  const unsigned char *s;
  size_t n;
  char *serialno;
  int no_card = 0;
  char *desc;
  char *want_sn, *want_kid;
  int want_sn_displen;

  *r_kid = NULL;
  s = shadow_info;
  if (*s != '(')
    return gpg_error (GPG_ERR_INV_SEXP);
  s++;
  n = snext (&s);
  if (!n)
    return gpg_error (GPG_ERR_INV_SEXP);
  want_sn = xtrymalloc (n*2+1);
  if (!want_sn)
    return out_of_core ();
  for (i=0; i < n; i++)
    sprintf (want_sn+2*i, "%02X", s[i]);
  s += n;
  /* We assume that a 20 byte serial number is a standard one which
     seems to have the property to have a zero in the last nibble.  We
     don't display this '0' because it may confuse the user */
  want_sn_displen = strlen (want_sn);
  if (want_sn_displen == 20 && want_sn[19] == '0')
    want_sn_displen--;

  n = snext (&s);
  if (!n)
    return gpg_error (GPG_ERR_INV_SEXP);
  want_kid = xtrymalloc (n+1);
  if (!want_kid)
    {
      gpg_error_t tmperr = out_of_core ();
      xfree (want_sn);
      return tmperr;
    }
  memcpy (want_kid, s, n);
  want_kid[n] = 0;

  for (;;)
    {
      rc = agent_card_serialno (ctrl, &serialno);
      if (!rc)
        {
          log_debug ("detected card with S/N %s\n", serialno);
          i = strcmp (serialno, want_sn);
          xfree (serialno);
          serialno = NULL;
          if (!i)
            {
              xfree (want_sn);
              *r_kid = want_kid;
              return 0; /* yes, we have the correct card */
            }
        }
      else if (gpg_err_code (rc) == GPG_ERR_CARD_NOT_PRESENT)
        {
          log_debug ("no card present\n");
          rc = 0;
          no_card = 1;
        }
      else
        {
          log_error ("error accesing card: %s\n", gpg_strerror (rc));
        }

      if (!rc)
        {
          /* We better reset the SCD now.  This is kludge required
             because the scdaemon is currently not always able to
             detect the presence of a card.  With a fully working
             scdaemon this would not be required; i.e. the pkcs#15
             support does not require it because OpenSC correclty
             detects a present card. */
          agent_reset_scd (ctrl);
          if (asprintf (&desc,
                    "%s:%%0A%%0A"
                    "  \"%.*s\"",
                    no_card? "Please insert the card with serial number" 
                    : "Please remove the current card and "
                    "insert the one with serial number",
                    want_sn_displen, want_sn) < 0)
            {
              rc = out_of_core ();
            }
          else
            {
              rc = agent_get_confirmation (ctrl, desc, NULL, NULL);
              free (desc);
            }
        }
      if (rc)
        {
          xfree (want_sn);
          xfree (want_kid);
          return rc;
        }
    }
}


/* Put the DIGEST into an DER encoded container and return it in R_VAL. */
static int
encode_md_for_card (const unsigned char *digest, size_t digestlen, int algo,
                    unsigned char **r_val, size_t *r_len)
{
  byte *frame;
  byte asn[100];
  size_t asnlen;

  asnlen = DIM(asn);
  if (gcry_md_algo_info (algo, GCRYCTL_GET_ASNOID, asn, &asnlen))
    {
      log_error ("no object identifier for algo %d\n", algo);
      return gpg_error (GPG_ERR_INTERNAL);
    }

  frame = xtrymalloc (asnlen + digestlen);
  if (!frame)
    return out_of_core ();
  memcpy (frame, asn, asnlen);
  memcpy (frame+asnlen, digest, digestlen);
  if (DBG_CRYPTO)
    log_printhex ("encoded hash:", frame, asnlen+digestlen);
      
  *r_val = frame;
  *r_len = asnlen+digestlen;
  return 0;
}


/* Callback used to ask for the PIN which should be set into BUF.  The
   buf has been allocated by the caller and is of size MAXBUF which
   includes the terminating null.  The function should return an UTF-8
   string with the passphrase, the buffer may optionally be padded
   with arbitrary characters */
static int 
getpin_cb (void *opaque, const char *info, char *buf, size_t maxbuf)
{
  struct pin_entry_info_s *pi;
  int rc;
  char *desc;
  CTRL ctrl = opaque;

  if (maxbuf < 2)
    return gpg_error (GPG_ERR_INV_VALUE);


  /* FIXME: keep PI and TRIES in OPAQUE.  Frankly this is a whole
     mess because we should call the card's verify function from the
     pinentry check pin CB. */
  pi = gcry_calloc_secure (1, sizeof (*pi) + 100);
  pi->max_length = maxbuf-1;
  pi->min_digits = 0;  /* we want a real passphrase */
  pi->max_digits = 8;
  pi->max_tries = 3;

  if ( asprintf (&desc, _("Please enter the PIN%s%s%s to unlock the card"), 
                 info? " (`":"",
                 info? info:"",
                 info? "')":"") < 0)
    desc = NULL;
  rc = agent_askpin (ctrl, desc?desc:info, NULL, pi);
  free (desc);
  if (!rc)
    {
      strncpy (buf, pi->pin, maxbuf-1);
      buf[maxbuf-1] = 0;
    }
  xfree (pi);
  return rc;
}




int
divert_pksign (CTRL ctrl, 
               const unsigned char *digest, size_t digestlen, int algo,
               const unsigned char *shadow_info, unsigned char **r_sig)
{
  int rc;
  char *kid;
  size_t siglen;
  char *sigval;
  unsigned char *data;
  size_t ndata;

  rc = ask_for_card (ctrl, shadow_info, &kid);
  if (rc)
    return rc;

  rc = encode_md_for_card (digest, digestlen, algo, 
                           &data, &ndata);
  if (rc)
    return rc;

  rc = agent_card_pksign (ctrl, kid, getpin_cb, ctrl,
                          data, ndata, &sigval, &siglen);
  if (!rc)
    *r_sig = sigval;
  xfree (data);
  xfree (kid);
  
  return rc;
}


/* Decrypt the the value given asn an S-expression in CIPHER using the
   key identified by SHADOW_INFO and return the plaintext in an
   allocated buffer in R_BUF.  */
int  
divert_pkdecrypt (CTRL ctrl,
                  const unsigned char *cipher,
                  const unsigned char *shadow_info,
                  char **r_buf, size_t *r_len)
{
  int rc;
  char *kid;
  const unsigned char *s;
  size_t n;
  const unsigned char *ciphertext;
  size_t ciphertextlen;
  char *plaintext;
  size_t plaintextlen;

  s = cipher;
  if (*s != '(')
    return gpg_error (GPG_ERR_INV_SEXP);
  s++;
  n = snext (&s);
  if (!n)
    return gpg_error (GPG_ERR_INV_SEXP); 
  if (!smatch (&s, n, "enc-val"))
    return gpg_error (GPG_ERR_UNKNOWN_SEXP); 
  if (*s != '(')
    return gpg_error (GPG_ERR_UNKNOWN_SEXP);
  s++;
  n = snext (&s);
  if (!n)
    return gpg_error (GPG_ERR_INV_SEXP); 
  if (!smatch (&s, n, "rsa"))
    return gpg_error (GPG_ERR_UNSUPPORTED_ALGORITHM); 
  if (*s != '(')
    return gpg_error (GPG_ERR_UNKNOWN_SEXP);
  s++;
  n = snext (&s);
  if (!n)
    return gpg_error (GPG_ERR_INV_SEXP); 
  if (!smatch (&s, n, "a"))
    return gpg_error (GPG_ERR_UNKNOWN_SEXP);
  n = snext (&s);
  if (!n)
    return gpg_error (GPG_ERR_UNKNOWN_SEXP); 
  ciphertext = s;
  ciphertextlen = n;

  rc = ask_for_card (ctrl, shadow_info, &kid);
  if (rc)
    return rc;

  rc = agent_card_pkdecrypt (ctrl, kid, getpin_cb, ctrl,
                             ciphertext, ciphertextlen,
                             &plaintext, &plaintextlen);
  if (!rc)
    {
      *r_buf = plaintext;
      *r_len = plaintextlen;
    }
  xfree (kid);
  return rc;
}


int  
divert_generic_cmd (CTRL ctrl, const char *cmdline, void *assuan_context)
{
  return agent_card_scd (ctrl, cmdline, getpin_cb, ctrl, assuan_context);
}





