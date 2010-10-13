/* divert-scd.c - divert operations to the scdaemon 
 *	Copyright (C) 2002, 2003, 2009 Free Software Foundation, Inc.
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
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <assert.h>
#include <unistd.h>
#include <sys/stat.h>

#include "agent.h"
#include "i18n.h"
#include "sexp-parse.h"


static int
ask_for_card (ctrl_t ctrl, const unsigned char *shadow_info, char **r_kid)
{
  int rc, i;
  char *serialno;
  int no_card = 0;
  char *desc;
  char *want_sn, *want_kid;
  int want_sn_displen;

  *r_kid = NULL;

  rc = parse_shadow_info (shadow_info, &want_sn, &want_kid);
  if (rc)
    return rc;

  /* We assume that a 20 byte serial number is a standard one which
     has the property to have a zero in the last nibble (Due to BCD
     representation).  We don't display this '0' because it may
     confuse the user.  */
  want_sn_displen = strlen (want_sn);
  if (want_sn_displen == 20 && want_sn[19] == '0')
    want_sn_displen--;

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
          log_error ("error accessing card: %s\n", gpg_strerror (rc));
        }

      if (!rc)
        {
          if (asprintf (&desc,
                    "%s:%%0A%%0A"
                    "  \"%.*s\"",
                        no_card
                        ? _("Please insert the card with serial number")
                        : _("Please remove the current card and "
                            "insert the one with serial number"),
                    want_sn_displen, want_sn) < 0)
            {
              rc = out_of_core ();
            }
          else
            {
              rc = agent_get_confirmation (ctrl, desc, NULL, NULL, 0);
              xfree (desc);
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
  unsigned char *frame;
  unsigned char asn[100];
  size_t asnlen;

  *r_val = NULL;
  *r_len = 0;

  asnlen = DIM(asn);
  if (!algo || gcry_md_test_algo (algo))
    return gpg_error (GPG_ERR_DIGEST_ALGO);
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
   with arbitrary characters.

   INFO gets displayed as part of a generic string.  However if the
   first character of INFO is a vertical bar all up to the next
   verical bar are considered flags and only everything after the
   second vertical bar gets displayed as the full prompt.

   Flags:

      'N' = New PIN, this requests a second prompt to repeat the
            PIN.  If the PIN is not correctly repeated it starts from
            all over.
      'A' = The PIN is an Admin PIN, SO-PIN or alike.
      'P' = The PIN is a PUK (Personal Unblocking Key).
      'R' = The PIN is a Reset Code.

   Example:

     "|AN|Please enter the new security officer's PIN"
     
   The text "Please ..." will get displayed and the flags 'A' and 'N'
   are considered.
 */
static int 
getpin_cb (void *opaque, const char *info, char *buf, size_t maxbuf)
{
  struct pin_entry_info_s *pi;
  int rc;
  ctrl_t ctrl = opaque;
  const char *ends, *s;
  int any_flags = 0;
  int newpin = 0;
  int resetcode = 0;
  int is_puk = 0;
  const char *again_text = NULL;
  const char *prompt = "PIN";

  if (buf && maxbuf < 2)
    return gpg_error (GPG_ERR_INV_VALUE);

  /* Parse the flags. */
  if (info && *info =='|' && (ends=strchr (info+1, '|')))
    {
      for (s=info+1; s < ends; s++)
        {
          if (*s == 'A')
            prompt = _("Admin PIN");
          else if (*s == 'P')
            {
              /* TRANSLATORS: A PUK is the Personal Unblocking Code
                 used to unblock a PIN. */
              prompt = _("PUK");
              is_puk = 1;
            }
          else if (*s == 'N')
            newpin = 1;
          else if (*s == 'R')
            {
              prompt = _("Reset Code");
              resetcode = 1;
            }
        }
      info = ends+1;
      any_flags = 1;
    }
  else if (info && *info == '|')
    log_debug ("pin_cb called without proper PIN info hack\n");

  /* If BUF has been passed as NULL, we are in keypad mode: The
     callback opens the popup and immediatley returns. */
  if (!buf)
    {
      if (maxbuf == 0) /* Close the pinentry. */
        {
          agent_popup_message_stop (ctrl);
          rc = 0;
        }
      else if (maxbuf == 1)  /* Open the pinentry. */
        {
          if (info)
            {
              char *desc;

              if ( asprintf (&desc,
                             _("%s%%0A%%0AUse the reader's keypad for input."),
                             info) < 0 )
                rc = gpg_error_from_syserror ();
              else
                {
                  rc = agent_popup_message_start (ctrl, desc, NULL);
                  xfree (desc);
                }
            }
          else
            rc = agent_popup_message_start (ctrl, NULL, NULL);
        }
      else
        rc = gpg_error (GPG_ERR_INV_VALUE);
      return rc;
    }

  /* FIXME: keep PI and TRIES in OPAQUE.  Frankly this is a whole
     mess because we should call the card's verify function from the
     pinentry check pin CB. */
 again:
  pi = gcry_calloc_secure (1, sizeof (*pi) + maxbuf + 10);
  if (!pi)
    return gpg_error_from_syserror ();
  pi->max_length = maxbuf-1;
  pi->min_digits = 0;  /* we want a real passphrase */
  pi->max_digits = 16;
  pi->max_tries = 3;

  if (any_flags)
    {
      rc = agent_askpin (ctrl, info, prompt, again_text, pi);
      again_text = NULL;
      if (!rc && newpin)
        {
          struct pin_entry_info_s *pi2;
          pi2 = gcry_calloc_secure (1, sizeof (*pi) + maxbuf + 10);
          if (!pi2)
            {
              rc = gpg_error_from_syserror ();
              xfree (pi);
              return rc;
            }
          pi2->max_length = maxbuf-1;
          pi2->min_digits = 0;
          pi2->max_digits = 16;
          pi2->max_tries = 1;
          rc = agent_askpin (ctrl,
                             (resetcode?
                              _("Repeat this Reset Code"):
                              is_puk?
                              _("Repeat this PUK"):
                              _("Repeat this PIN")),
                             prompt, NULL, pi2);
          if (!rc && strcmp (pi->pin, pi2->pin))
            {
              again_text = (resetcode? 
                            N_("Reset Code not correctly repeated; try again"):
                            is_puk?
                            N_("PUK not correctly repeated; try again"):
                            N_("PIN not correctly repeated; try again"));
              xfree (pi2);
              xfree (pi);
              goto again;
            }
          xfree (pi2);
        }
    }
  else
    {
      char *desc;
      if ( asprintf (&desc,
                     _("Please enter the PIN%s%s%s to unlock the card"), 
                     info? " (`":"",
                     info? info:"",
                     info? "')":"") < 0)
        desc = NULL;
      rc = agent_askpin (ctrl, desc?desc:info, prompt, NULL, pi);
      xfree (desc);
    }

  if (!rc)
    {
      strncpy (buf, pi->pin, maxbuf-1);
      buf[maxbuf-1] = 0;
    }
  xfree (pi);
  return rc;
}




int
divert_pksign (ctrl_t ctrl, 
               const unsigned char *digest, size_t digestlen, int algo,
               const unsigned char *shadow_info, unsigned char **r_sig)
{
  int rc;
  char *kid;
  size_t siglen;
  unsigned char *sigval = NULL;

  rc = ask_for_card (ctrl, shadow_info, &kid);
  if (rc)
    return rc;

  if (algo == MD_USER_TLS_MD5SHA1)
    {
      int save = ctrl->use_auth_call;
      ctrl->use_auth_call = 1;
      rc = agent_card_pksign (ctrl, kid, getpin_cb, ctrl,
                              digest, digestlen, &sigval, &siglen);
      ctrl->use_auth_call = save;
    }
  else
    {
      unsigned char *data;
      size_t ndata;

      rc = encode_md_for_card (digest, digestlen, algo, &data, &ndata);
      if (!rc)
        {
          rc = agent_card_pksign (ctrl, kid, getpin_cb, ctrl,
                                  data, ndata, &sigval, &siglen);
          xfree (data);
        }
    }

  if (!rc)
    *r_sig = sigval;

  xfree (kid);

  return rc;
}


/* Decrypt the the value given asn an S-expression in CIPHER using the
   key identified by SHADOW_INFO and return the plaintext in an
   allocated buffer in R_BUF.  */
int  
divert_pkdecrypt (ctrl_t ctrl,
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
divert_generic_cmd (ctrl_t ctrl, const char *cmdline, void *assuan_context)
{
  return agent_card_scd (ctrl, cmdline, getpin_cb, ctrl, assuan_context);
}





