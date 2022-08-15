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
 * along with this program; if not, see <https://www.gnu.org/licenses/>.
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
#include "../common/i18n.h"
#include "../common/sexp-parse.h"

/* Replace all linefeeds in STRING by "%0A" and return a new malloced
 * string.  May return NULL on memory error.  */
static char *
linefeed_to_percent0A (const char *string)
{
  const char *s;
  size_t n;
  char *buf, *p;

  for (n=0, s=string; *s; s++)
    if (*s == '\n')
      n += 3;
    else
      n++;
  p = buf = xtrymalloc (n+1);
  if (!buf)
    return NULL;
  for (s=string; *s; s++)
    if (*s == '\n')
      {
        memcpy (p, "%0A", 3);
        p += 3;
      }
    else
      *p++ = *s;
  *p = 0;
  return buf;
}


/* Ask for the card using SHADOW_INFO.  If GRIP is not NULL, the
 * function also tries to find additional information from the shadow
 * key file.  */
static int
ask_for_card (ctrl_t ctrl, const unsigned char *shadow_info,
              const unsigned char *grip, char **r_kid)
{
  int rc, i;
  char *serialno;
  int no_card = 0;
  char *desc;
  char *want_sn, *want_kid, *want_sn_disp;
  int got_sn_disp_from_meta = 0;
  int len;
  char *comment = NULL;

  *r_kid = NULL;

  rc = parse_shadow_info (shadow_info, &want_sn, &want_kid, NULL);
  if (rc)
    return rc;
  want_sn_disp = xtrystrdup (want_sn);
  if (!want_sn_disp)
    {
      rc = gpg_error_from_syserror ();
      xfree (want_sn);
      xfree (want_kid);
      xfree (comment);
      return rc;
    }

  if (grip)
    {
      nvc_t keymeta;
      const char *s;
      size_t snlen;
      nve_t item;
      char **tokenfields = NULL;

      rc = agent_keymeta_from_file (ctrl, grip, &keymeta);
      if (!rc)
        {
          snlen = strlen (want_sn);
          s = NULL;
          for (item = nvc_lookup (keymeta, "Token:");
               item;
               item = nve_next_value (item, "Token:"))
            if ((s = nve_value (item)) && !strncmp (s, want_sn, snlen))
              break;
          if (s && (tokenfields = strtokenize (s, " \t\n")))
            {
              if (tokenfields[0] && tokenfields[1] && tokenfields[2]
                  && tokenfields[3] && strlen (tokenfields[3]) > 1)
                {
                  xfree (want_sn_disp);
                  want_sn_disp = percent_plus_unescape (tokenfields[3], 0xff);
                  if (!want_sn_disp)
                    {
                      rc = gpg_error_from_syserror ();
                      xfree (tokenfields);
                      nvc_release (keymeta);
                      xfree (want_sn);
                      xfree (want_kid);
                      xfree (comment);
                      return rc;
                    }
                  got_sn_disp_from_meta = 1;
                }

              xfree (tokenfields);
            }

          if ((s = nvc_get_string (keymeta, "Label:")))
            comment = linefeed_to_percent0A (s);

          nvc_release (keymeta);
        }
    }

  len = strlen (want_sn_disp);
  if (got_sn_disp_from_meta)
    ; /* We got the the display S/N from the key file.  */
  else if (len == 32 && !strncmp (want_sn_disp, "D27600012401", 12))
    {
      /* This is an OpenPGP card - reformat  */
      memmove (want_sn_disp, want_sn_disp+16, 4);
      want_sn_disp[4] = ' ';
      memmove (want_sn_disp+5, want_sn_disp+20, 8);
      want_sn_disp[13] = 0;
    }
  else if (len == 20 && want_sn_disp[19] == '0')
    {
      /* We assume that a 20 byte serial number is a standard one
       * which has the property to have a zero in the last nibble (Due
       * to BCD representation).  We don't display this '0' because it
       * may confuse the user.  */
      want_sn_disp[19] = 0;
    }

  for (;;)
    {
      rc = agent_card_serialno (ctrl, &serialno, want_sn);
      if (!rc)
        {
          log_info ("detected card with S/N %s\n", serialno);
          i = strcmp (serialno, want_sn);
          xfree (serialno);
          serialno = NULL;
          if (!i)
            {
              xfree (want_sn_disp);
              xfree (want_sn);
              xfree (comment);
              *r_kid = want_kid;
              return 0; /* yes, we have the correct card */
            }
        }
      else if (gpg_err_code (rc) == GPG_ERR_ENODEV)
        {
          log_info ("no device present\n");
          rc = 0;
          no_card = 1;
        }
      else if (gpg_err_code (rc) == GPG_ERR_CARD_NOT_PRESENT)
        {
          log_info ("no card present\n");
          rc = 0;
          no_card = 2;
        }
      else
        {
          log_error ("error accessing card: %s\n", gpg_strerror (rc));
        }

      if (!rc)
        {
          if (asprintf (&desc,
                    "%s:%%0A%%0A"
                    "  %s%%0A"
                    "  %s",
                        no_card
                        ? L_("Please insert the card with serial number")
                        : L_("Please remove the current card and "
                             "insert the one with serial number"),
                        want_sn_disp, comment? comment:"") < 0)
            {
              rc = out_of_core ();
            }
          else
            {
              rc = agent_get_confirmation (ctrl, desc, NULL, NULL, 0);
              if (ctrl->pinentry_mode == PINENTRY_MODE_LOOPBACK &&
                  gpg_err_code (rc) == GPG_ERR_NO_PIN_ENTRY)
                rc = gpg_error (GPG_ERR_CARD_NOT_PRESENT);

              xfree (desc);
            }
        }
      if (rc)
        {
          xfree (want_sn_disp);
          xfree (want_sn);
          xfree (want_kid);
          xfree (comment);
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
    log_printhex (frame, asnlen+digestlen, "encoded hash:");

  *r_val = frame;
  *r_len = asnlen+digestlen;
  return 0;
}


/* Return true if STRING ends in "%0A". */
static int
has_percent0A_suffix (const char *string)
{
  size_t n;

  return (string
          && (n = strlen (string)) >= 3
          && !strcmp (string + n - 3, "%0A"));
}


/* Callback used to ask for the PIN which should be set into BUF.  The
   buf has been allocated by the caller and is of size MAXBUF which
   includes the terminating null.  The function should return an UTF-8
   string with the passphrase, the buffer may optionally be padded
   with arbitrary characters.

   If DESC_TEXT is not NULL it can be used as further informtion shown
   atop of the INFO message.

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
getpin_cb (void *opaque, const char *desc_text, const char *info,
           char *buf, size_t maxbuf)
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
            prompt = L_("Admin PIN");
          else if (*s == 'P')
            {
              /* TRANSLATORS: A PUK is the Personal Unblocking Code
                 used to unblock a PIN. */
              prompt = L_("PUK");
              is_puk = 1;
            }
          else if (*s == 'N')
            newpin = 1;
          else if (*s == 'R')
            {
              prompt = L_("Reset Code");
              resetcode = 1;
            }
        }
      info = ends+1;
      any_flags = 1;
    }
  else if (info && *info == '|')
    log_debug ("pin_cb called without proper PIN info hack\n");

  /* If BUF has been passed as NULL, we are in pinpad mode: The
     callback opens the popup and immediately returns. */
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
              const char *desc2;

              if (!strcmp (info, "--ack"))
                {
                  desc2 = L_("Push ACK button on card/token.");

                  if (desc_text)
                    {
                      desc = strconcat (desc_text,
                                        has_percent0A_suffix (desc_text)
                                        ? "%0A" : "%0A%0A",
                                        desc2, NULL);
                      desc2 = NULL;
                    }
                  else
                    desc = NULL;
                }
              else
                {
                  desc2 = NULL;

                  if (desc_text)
                    desc = strconcat (desc_text,
                                      has_percent0A_suffix (desc_text)
                                      ? "%0A" : "%0A%0A",
                                      info, "%0A%0A",
                                      L_("Use the reader's pinpad for input."),
                                      NULL);
                  else
                    desc = strconcat (info, "%0A%0A",
                                      L_("Use the reader's pinpad for input."),
                                      NULL);
                }

              if (!desc2 && !desc)
                rc = gpg_error_from_syserror ();
              else
                {
                  rc = agent_popup_message_start (ctrl,
                                                  desc2? desc2:desc, NULL);
                  xfree (desc);
                }
            }
          else
            rc = agent_popup_message_start (ctrl, desc_text, NULL);
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
      {
        char *desc2;

        if (desc_text)
          desc2 = strconcat (desc_text,
                             has_percent0A_suffix (desc_text)
                             ? "%0A" : "%0A%0A",
                             info, NULL);
        else
          desc2 = NULL;
        rc = agent_askpin (ctrl, desc2? desc2 : info,
                           prompt, again_text, pi, NULL, 0);
        xfree (desc2);
      }
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
                              L_("Repeat this Reset Code"):
                              is_puk?
                              L_("Repeat this PUK"):
                              L_("Repeat this PIN")),
                             prompt, NULL, pi2, NULL, 0);
          if (!rc && strcmp (pi->pin, pi2->pin))
            {
              again_text = (resetcode?
                            L_("Reset Code not correctly repeated; try again"):
                            is_puk?
                            L_("PUK not correctly repeated; try again"):
                            L_("PIN not correctly repeated; try again"));
              xfree (pi2);
              xfree (pi);
              goto again;
            }
          xfree (pi2);
        }
    }
  else
    {
      char *desc, *desc2;

      if ( asprintf (&desc,
                     L_("Please enter the PIN%s%s%s to unlock the card"),
                     info? " (":"",
                     info? info:"",
                     info? ")":"") < 0)
        desc = NULL;
      if (desc_text)
        desc2 = strconcat (desc_text,
                           has_percent0A_suffix (desc_text)
                           ? "%0A" : "%0A%0A",
                           desc, NULL);
      else
        desc2 = NULL;
      rc = agent_askpin (ctrl, desc2? desc2 : desc? desc : info,
                         prompt, NULL, pi, NULL, 0);
      xfree (desc2);
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



/* This function is used when a sign operation has been diverted to a
 * smartcard.  DESC_TEXT is the original text for a prompt has send by
 * gpg to gpg-agent.
 *
 * FIXME: Explain the other args.  */
int
divert_pksign (ctrl_t ctrl, const char *desc_text,
               const unsigned char *digest, size_t digestlen, int algo,
               const unsigned char *grip,
               const unsigned char *shadow_info, unsigned char **r_sig,
               size_t *r_siglen)
{
  int rc;
  char *kid;
  size_t siglen;
  unsigned char *sigval = NULL;

  (void)desc_text;

  rc = ask_for_card (ctrl, shadow_info, grip, &kid);
  if (rc)
    return rc;

  /* For OpenPGP cards we better use the keygrip as key reference.
   * This has the advantage that app-openpgp can check that the stored
   * key matches our expectation.  This is important in case new keys
   * have been created on the same card but the sub file has not been
   * updated.  In that case we would get a error from our final
   * signature checking code or, if the pubkey algo is different,
   * weird errors from the card (Conditions of use not satisfied).  */
  if (kid && grip && !strncmp (kid, "OPENPGP.", 8))
    {
      xfree (kid);
      kid = bin2hex (grip, KEYGRIP_LEN, NULL);
      if (!kid)
        return gpg_error_from_syserror ();
    }


  if (algo == MD_USER_TLS_MD5SHA1)
    {
      int save = ctrl->use_auth_call;
      ctrl->use_auth_call = 1;
      rc = agent_card_pksign (ctrl, kid, getpin_cb, ctrl, NULL,
                              algo, digest, digestlen, &sigval, &siglen);
      ctrl->use_auth_call = save;
    }
  else
    {
      unsigned char *data;
      size_t ndata;

      rc = encode_md_for_card (digest, digestlen, algo, &data, &ndata);
      if (!rc)
        {
          rc = agent_card_pksign (ctrl, kid, getpin_cb, ctrl, NULL,
                                  algo, data, ndata, &sigval, &siglen);
          xfree (data);
        }
    }

  if (!rc)
    {
      *r_sig = sigval;
      *r_siglen = siglen;
    }

  xfree (kid);

  return rc;
}


/* Decrypt the value given asn an S-expression in CIPHER using the
   key identified by SHADOW_INFO and return the plaintext in an
   allocated buffer in R_BUF.  The padding information is stored at
   R_PADDING with -1 for not known.  */
int
divert_pkdecrypt (ctrl_t ctrl, const char *desc_text,
                  const unsigned char *cipher,
                  const unsigned char *grip,
                  const unsigned char *shadow_info,
                  char **r_buf, size_t *r_len, int *r_padding)
{
  int rc;
  char *kid;
  const unsigned char *s;
  size_t n;
  int depth;
  const unsigned char *ciphertext;
  size_t ciphertextlen;
  char *plaintext;
  size_t plaintextlen;

  (void)desc_text;

  *r_padding = -1;
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

  /* First check whether we have a flags parameter and skip it.  */
  if (smatch (&s, n, "flags"))
    {
      depth = 1;
      if (sskip (&s, &depth) || depth)
        return gpg_error (GPG_ERR_INV_SEXP);
      if (*s != '(')
        return gpg_error (GPG_ERR_INV_SEXP);
      s++;
      n = snext (&s);
      if (!n)
        return gpg_error (GPG_ERR_INV_SEXP);
    }

  if (smatch (&s, n, "rsa"))
    {
      if (*s != '(')
        return gpg_error (GPG_ERR_UNKNOWN_SEXP);
      s++;
      n = snext (&s);
      if (!n)
        return gpg_error (GPG_ERR_INV_SEXP);
      if (!smatch (&s, n, "a"))
        return gpg_error (GPG_ERR_UNKNOWN_SEXP);
      n = snext (&s);
    }
  else if (smatch (&s, n, "ecdh"))
    {
      if (*s != '(')
        return gpg_error (GPG_ERR_UNKNOWN_SEXP);
      s++;
      n = snext (&s);
      if (!n)
        return gpg_error (GPG_ERR_INV_SEXP);
      if (smatch (&s, n, "s"))
        {
          n = snext (&s);
          s += n;
          if (*s++ != ')')
            return gpg_error (GPG_ERR_INV_SEXP);
          if (*s++ != '(')
            return gpg_error (GPG_ERR_UNKNOWN_SEXP);
          n = snext (&s);
          if (!n)
            return gpg_error (GPG_ERR_INV_SEXP);
        }
      if (!smatch (&s, n, "e"))
        return gpg_error (GPG_ERR_UNKNOWN_SEXP);
      n = snext (&s);
    }
  else
    return gpg_error (GPG_ERR_UNSUPPORTED_ALGORITHM);

  if (!n)
    return gpg_error (GPG_ERR_UNKNOWN_SEXP);
  ciphertext = s;
  ciphertextlen = n;

  rc = ask_for_card (ctrl, shadow_info, grip, &kid);
  if (rc)
    return rc;

  /* For OpenPGP cards we better use the keygrip as key reference.
   * This has the advantage that app-openpgp can check that the stored
   * key matches our expectation.  This is important in case new keys
   * have been created on the same card but the sub file has not been
   * updated.  In that case we would get a error from our final
   * signature checking code or, if the pubkey algo is different,
   * weird errors from the card (Conditions of use not satisfied).  */
  if (kid && grip && !strncmp (kid, "OPENPGP.", 8))
    {
      xfree (kid);
      kid = bin2hex (grip, KEYGRIP_LEN, NULL);
      if (!kid)
        return gpg_error_from_syserror ();
    }

  rc = agent_card_pkdecrypt (ctrl, kid, getpin_cb, ctrl, NULL,
                             ciphertext, ciphertextlen,
                             &plaintext, &plaintextlen, r_padding);
  if (!rc)
    {
      *r_buf = plaintext;
      *r_len = plaintextlen;
    }
  xfree (kid);
  return rc;
}

int
divert_writekey (ctrl_t ctrl, int force, const char *serialno,
                 const char *id, const char *keydata, size_t keydatalen)
{
  return agent_card_writekey (ctrl, force, serialno, id, keydata, keydatalen,
                              getpin_cb, ctrl);
}

int
divert_generic_cmd (ctrl_t ctrl, const char *cmdline, void *assuan_context)
{
  return agent_card_scd (ctrl, cmdline, getpin_cb, ctrl, assuan_context);
}
