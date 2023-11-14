/* call-agent.c - Divert GPGSM operations to the agent
 * Copyright (C) 2001, 2002, 2003, 2005, 2007,
 *               2008, 2009, 2010 Free Software Foundation, Inc.
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
#include <time.h>
#ifdef HAVE_LOCALE_H
#include <locale.h>
#endif

#include "gpgsm.h"
#include <gcrypt.h>
#include <assuan.h>
#include "../common/i18n.h"
#include "../common/asshelp.h"
#include "keydb.h" /* fixme: Move this to import.c */
#include "../common/membuf.h"
#include "../common/shareddefs.h"
#include "passphrase.h"


static assuan_context_t agent_ctx = NULL;


struct cipher_parm_s
{
  ctrl_t ctrl;
  assuan_context_t ctx;
  const unsigned char *ciphertext;
  size_t ciphertextlen;
};

struct genkey_parm_s
{
  ctrl_t ctrl;
  assuan_context_t ctx;
  const unsigned char *sexp;
  size_t sexplen;
};

struct learn_parm_s
{
  int error;
  ctrl_t ctrl;
  assuan_context_t ctx;
  membuf_t *data;
};

struct import_key_parm_s
{
  ctrl_t ctrl;
  assuan_context_t ctx;
  const void *key;
  size_t keylen;
};

struct sethash_inq_parm_s
{
  assuan_context_t ctx;
  const void *data;
  size_t datalen;
};

struct default_inq_parm_s
{
  ctrl_t ctrl;
  assuan_context_t ctx;
};


/* Print a warning if the server's version number is less than our
   version number.  Returns an error code on a connection problem.  */
static gpg_error_t
warn_version_mismatch (ctrl_t ctrl, assuan_context_t ctx,
                       const char *servername, int mode)
{
  return warn_server_version_mismatch (ctx, servername, mode,
                                       gpgsm_status2, ctrl,
                                       !opt.quiet);
}

/* Try to connect to the agent via socket or fork it off and work by
   pipes.  Handle the server's initial greeting */
static int
start_agent (ctrl_t ctrl)
{
  int rc;

  if (agent_ctx)
    rc = 0;      /* fixme: We need a context for each thread or
                    serialize the access to the agent (which is
                    suitable given that the agent is not MT. */
  else
    {
      rc = start_new_gpg_agent (&agent_ctx,
                                GPG_ERR_SOURCE_DEFAULT,
                                opt.agent_program,
                                opt.lc_ctype, opt.lc_messages,
                                opt.session_env,
                                opt.autostart, opt.verbose, DBG_IPC,
                                gpgsm_status2, ctrl);

      if (!opt.autostart && gpg_err_code (rc) == GPG_ERR_NO_AGENT)
        {
          static int shown;

          if (!shown)
            {
              shown = 1;
              log_info (_("no gpg-agent running in this session\n"));
            }
        }
      else if (!rc && !(rc = warn_version_mismatch (ctrl, agent_ctx,
                                                    GPG_AGENT_NAME, 0)))
        {
          /* Tell the agent that we support Pinentry notifications.  No
             error checking so that it will work also with older
             agents.  */
          assuan_transact (agent_ctx, "OPTION allow-pinentry-notify",
                           NULL, NULL, NULL, NULL, NULL, NULL);

          /* Pass on the pinentry mode.  */
          if (opt.pinentry_mode)
            {
              char *tmp = xasprintf ("OPTION pinentry-mode=%s",
                                     str_pinentry_mode (opt.pinentry_mode));
              rc = assuan_transact (agent_ctx, tmp,
                               NULL, NULL, NULL, NULL, NULL, NULL);
              xfree (tmp);
              if (rc)
                log_error ("setting pinentry mode '%s' failed: %s\n",
                           str_pinentry_mode (opt.pinentry_mode),
                           gpg_strerror (rc));
            }

          /* Pass on the request origin.  */
          if (opt.request_origin)
            {
              char *tmp = xasprintf ("OPTION pretend-request-origin=%s",
                                     str_request_origin (opt.request_origin));
              rc = assuan_transact (agent_ctx, tmp,
                               NULL, NULL, NULL, NULL, NULL, NULL);
              xfree (tmp);
              if (rc)
                log_error ("setting request origin '%s' failed: %s\n",
                           str_request_origin (opt.request_origin),
                           gpg_strerror (rc));
            }

          /* In DE_VS mode under Windows we require that the JENT RNG
           * is active.  */
#ifdef HAVE_W32_SYSTEM
          if (!rc && opt.compliance == CO_DE_VS)
            {
              if (assuan_transact (agent_ctx, "GETINFO jent_active",
                                   NULL, NULL, NULL, NULL, NULL, NULL))
                {
                  rc = gpg_error (GPG_ERR_FORBIDDEN);
                  log_error (_("%s is not compliant with %s mode\n"),
                             GPG_AGENT_NAME,
                             gnupg_compliance_option_string (opt.compliance));
                  gpgsm_status_with_error (ctrl, STATUS_ERROR,
                                           "random-compliance", rc);
                }
            }
#endif /*HAVE_W32_SYSTEM*/

        }
    }

  if (!ctrl->agent_seen)
    {
      ctrl->agent_seen = 1;
      audit_log_ok (ctrl->audit, AUDIT_AGENT_READY, rc);
    }

  return rc;
}

/* This is the default inquiry callback.  It mainly handles the
   Pinentry notifications.  */
static gpg_error_t
default_inq_cb (void *opaque, const char *line)
{
  gpg_error_t err = 0;
  struct default_inq_parm_s *parm = opaque;
  ctrl_t ctrl = parm->ctrl;

  if (has_leading_keyword (line, "PINENTRY_LAUNCHED"))
    {
      err = gpgsm_proxy_pinentry_notify (ctrl, line);
      if (err)
        log_error (_("failed to proxy %s inquiry to client\n"),
                   "PINENTRY_LAUNCHED");
      /* We do not pass errors to avoid breaking other code.  */
    }
  else if ((has_leading_keyword (line, "PASSPHRASE")
            || has_leading_keyword (line, "NEW_PASSPHRASE"))
           && opt.pinentry_mode == PINENTRY_MODE_LOOPBACK
           && have_static_passphrase ())
    {
      const char *s = get_static_passphrase ();
      assuan_begin_confidential (parm->ctx);
      err = assuan_send_data (parm->ctx, s, strlen (s));
      assuan_end_confidential (parm->ctx);
    }
  else
    log_error ("ignoring gpg-agent inquiry '%s'\n", line);

  return err;
}




/* This is the inquiry callback required by the SETHASH command.  */
static gpg_error_t
sethash_inq_cb (void *opaque, const char *line)
{
  gpg_error_t err = 0;
  struct sethash_inq_parm_s *parm = opaque;

  if (has_leading_keyword (line, "TBSDATA"))
    {
      err = assuan_send_data (parm->ctx, parm->data, parm->datalen);
    }
  else
    log_error ("ignoring gpg-agent inquiry '%s'\n", line);

  return err;
}


/* Call the agent to do a sign operation using the key identified by
 * the hex string KEYGRIP.  If DIGESTALGO is given (DIGEST,DIGESTLEN)
 * gives the to be signed hash created using the given algo.  If
 * DIGESTALGO is not given (i.e. zero) (DIGEST,DIGESTALGO) give the
 * entire data to-be-signed. */
int
gpgsm_agent_pksign (ctrl_t ctrl, const char *keygrip, const char *desc,
                    unsigned char *digest, size_t digestlen, int digestalgo,
                    unsigned char **r_buf, size_t *r_buflen )
{
  int rc, i;
  char *p, line[ASSUAN_LINELENGTH];
  membuf_t data;
  size_t len;
  struct default_inq_parm_s inq_parm;

  *r_buf = NULL;
  rc = start_agent (ctrl);
  if (rc)
    return rc;
  inq_parm.ctrl = ctrl;
  inq_parm.ctx = agent_ctx;

  if (digestalgo && digestlen*2 + 50 > DIM(line))
    return gpg_error (GPG_ERR_GENERAL);

  rc = assuan_transact (agent_ctx, "RESET", NULL, NULL, NULL, NULL, NULL, NULL);
  if (rc)
    return rc;

  snprintf (line, DIM(line), "SIGKEY %s", keygrip);
  rc = assuan_transact (agent_ctx, line, NULL, NULL, NULL, NULL, NULL, NULL);
  if (rc)
    return rc;

  if (desc)
    {
      snprintf (line, DIM(line), "SETKEYDESC %s", desc);
      rc = assuan_transact (agent_ctx, line,
                            NULL, NULL, NULL, NULL, NULL, NULL);
      if (rc)
        return rc;
    }

  if (!digestalgo)
    {
      struct sethash_inq_parm_s sethash_inq_parm;

      sethash_inq_parm.ctx = agent_ctx;
      sethash_inq_parm.data = digest;
      sethash_inq_parm.datalen = digestlen;
      rc = assuan_transact (agent_ctx, "SETHASH --inquire",
                            NULL, NULL, sethash_inq_cb, &sethash_inq_parm,
                            NULL, NULL);
    }
  else
    {
      snprintf (line, sizeof line, "SETHASH %d ", digestalgo);
      p = line + strlen (line);
      for (i=0; i < digestlen ; i++, p += 2 )
        sprintf (p, "%02X", digest[i]);
      rc = assuan_transact (agent_ctx, line,
                            NULL, NULL, NULL, NULL, NULL, NULL);
    }
  if (rc)
    return rc;

  init_membuf (&data, 1024);
  rc = assuan_transact (agent_ctx, "PKSIGN",
                        put_membuf_cb, &data, default_inq_cb, &inq_parm,
                        NULL, NULL);
  if (rc)
    {
      xfree (get_membuf (&data, &len));
      return rc;
    }
  *r_buf = get_membuf (&data, r_buflen);

  if (!gcry_sexp_canon_len (*r_buf, *r_buflen, NULL, NULL))
    {
      xfree (*r_buf); *r_buf = NULL;
      return gpg_error (GPG_ERR_INV_VALUE);
    }

  return *r_buf? 0 : out_of_core ();
}


/* Call the scdaemon to do a sign operation using the key identified by
   the hex string KEYID. */
int
gpgsm_scd_pksign (ctrl_t ctrl, const char *keyid, const char *desc,
                  unsigned char *digest, size_t digestlen, int digestalgo,
                  unsigned char **r_buf, size_t *r_buflen )
{
  int rc, i, pkalgo;
  char *p, line[ASSUAN_LINELENGTH];
  membuf_t data;
  size_t len;
  const char *hashopt;
  unsigned char *sigbuf;
  size_t sigbuflen;
  struct default_inq_parm_s inq_parm;
  gcry_sexp_t sig;

  (void)desc;

  *r_buf = NULL;

  switch(digestalgo)
    {
    case GCRY_MD_SHA1:  hashopt = "--hash=sha1"; break;
    case GCRY_MD_RMD160:hashopt = "--hash=rmd160"; break;
    case GCRY_MD_MD5:   hashopt = "--hash=md5"; break;
    case GCRY_MD_SHA256:hashopt = "--hash=sha256"; break;
    case GCRY_MD_SHA512:hashopt = "--hash=sha512"; break;
    default:
      return gpg_error (GPG_ERR_DIGEST_ALGO);
    }

  rc = start_agent (ctrl);
  if (rc)
    return rc;
  inq_parm.ctrl = ctrl;
  inq_parm.ctx = agent_ctx;

  if (digestlen*2 + 50 > DIM(line))
    return gpg_error (GPG_ERR_GENERAL);

  /* Get the key type from the scdaemon. */
  snprintf (line, DIM(line), "SCD READKEY %s", keyid);
  init_membuf (&data, 1024);
  rc = assuan_transact (agent_ctx, line,
                        put_membuf_cb, &data, NULL, NULL, NULL, NULL);
  if (rc)
    {
      xfree (get_membuf (&data, &len));
      return rc;
    }

  p = get_membuf (&data, &len);
  pkalgo = get_pk_algo_from_canon_sexp (p, len);
  xfree (p);
  if (!pkalgo)
    return gpg_error (GPG_ERR_WRONG_PUBKEY_ALGO);

  p = stpcpy (line, "SCD SETDATA " );
  for (i=0; i < digestlen ; i++, p += 2 )
    sprintf (p, "%02X", digest[i]);
  rc = assuan_transact (agent_ctx, line, NULL, NULL, NULL, NULL, NULL, NULL);
  if (rc)
    return rc;

  init_membuf (&data, 1024);

  snprintf (line, DIM(line), "SCD PKSIGN %s %s", hashopt, keyid);
  rc = assuan_transact (agent_ctx, line,
                        put_membuf_cb, &data, default_inq_cb, &inq_parm,
                        NULL, NULL);
  if (rc)
    {
      xfree (get_membuf (&data, &len));
      return rc;
    }
  sigbuf = get_membuf (&data, &sigbuflen);

  switch(pkalgo)
    {
    case GCRY_PK_RSA:
      rc = gcry_sexp_build (&sig, NULL, "(sig-val(rsa(s%b)))",
                            (int)sigbuflen, sigbuf);
      break;

    case GCRY_PK_ECC:
      rc = gcry_sexp_build (&sig, NULL, "(sig-val(ecdsa(r%b)(s%b)))",
                            (int)sigbuflen/2, sigbuf,
                            (int)sigbuflen/2, sigbuf + sigbuflen/2);
      break;

    case GCRY_PK_EDDSA:
      rc = gcry_sexp_build (&sig, NULL, "(sig-val(eddsa(r%b)(s%b)))",
                            (int)sigbuflen/2, sigbuf,
                            (int)sigbuflen/2, sigbuf + sigbuflen/2);
      break;

    default:
      rc = gpg_error (GPG_ERR_WRONG_PUBKEY_ALGO);
      break;
    }
  xfree (sigbuf);
  if (rc)
    return rc;

  rc = make_canon_sexp (sig, r_buf, r_buflen);
  gcry_sexp_release (sig);
  if (rc)
    return rc;

  log_assert (gcry_sexp_canon_len (*r_buf, *r_buflen, NULL, NULL));
  return  0;
}




/* Handle a CIPHERTEXT inquiry.  Note, we only send the data,
   assuan_transact takes care of flushing and writing the end */
static gpg_error_t
inq_ciphertext_cb (void *opaque, const char *line)
{
  struct cipher_parm_s *parm = opaque;
  int rc;

  if (has_leading_keyword (line, "CIPHERTEXT"))
    {
      assuan_begin_confidential (parm->ctx);
      rc = assuan_send_data (parm->ctx, parm->ciphertext, parm->ciphertextlen);
      assuan_end_confidential (parm->ctx);
    }
  else
    {
      struct default_inq_parm_s inq_parm = { parm->ctrl, parm->ctx };
      rc = default_inq_cb (&inq_parm, line);
    }

  return rc;
}


/* Call the agent to do a decrypt operation using the key identified by
   the hex string KEYGRIP. */
int
gpgsm_agent_pkdecrypt (ctrl_t ctrl, const char *keygrip, const char *desc,
                       ksba_const_sexp_t ciphertext,
                       char **r_buf, size_t *r_buflen )
{
  int rc;
  char line[ASSUAN_LINELENGTH];
  membuf_t data;
  struct cipher_parm_s cipher_parm;
  size_t n, len;
  char *p, *buf, *endp;
  size_t ciphertextlen;

  if (!keygrip || strlen(keygrip) != 40 || !ciphertext || !r_buf || !r_buflen)
    return gpg_error (GPG_ERR_INV_VALUE);
  *r_buf = NULL;

  ciphertextlen = gcry_sexp_canon_len (ciphertext, 0, NULL, NULL);
  if (!ciphertextlen)
    return gpg_error (GPG_ERR_INV_VALUE);

  rc = start_agent (ctrl);
  if (rc)
    return rc;

  rc = assuan_transact (agent_ctx, "RESET", NULL, NULL, NULL, NULL, NULL, NULL);
  if (rc)
    return rc;

  log_assert ( DIM(line) >= 50 );
  snprintf (line, DIM(line), "SETKEY %s", keygrip);
  rc = assuan_transact (agent_ctx, line, NULL, NULL, NULL, NULL, NULL, NULL);
  if (rc)
    return rc;

  if (desc)
    {
      snprintf (line, DIM(line), "SETKEYDESC %s", desc);
      rc = assuan_transact (agent_ctx, line,
                            NULL, NULL, NULL, NULL, NULL, NULL);
      if (rc)
        return rc;
    }

  init_membuf (&data, 1024);
  cipher_parm.ctrl = ctrl;
  cipher_parm.ctx = agent_ctx;
  cipher_parm.ciphertext = ciphertext;
  cipher_parm.ciphertextlen = ciphertextlen;
  rc = assuan_transact (agent_ctx, "PKDECRYPT",
                        put_membuf_cb, &data,
                        inq_ciphertext_cb, &cipher_parm, NULL, NULL);
  if (rc)
    {
      xfree (get_membuf (&data, &len));
      return rc;
    }

  /* Make sure it is 0 terminated so we can invoke strtoul safely.  */
  put_membuf (&data, "", 1);
  buf = get_membuf (&data, &len);
  if (!buf)
    return gpg_error (GPG_ERR_ENOMEM);
  log_assert (len); /* (we forced Nul termination.)  */

  if (*buf == '(')
    {
      if (len < 13 || memcmp (buf, "(5:value", 8) ) /* "(5:valueN:D)\0" */
        return gpg_error (GPG_ERR_INV_SEXP);
      /* Trim any spurious trailing Nuls: */
      while (buf[len-1] == 0)
        len--;
      if (buf[len-1] != ')')
        return gpg_error (GPG_ERR_INV_SEXP);
      len--; /* Drop the final close-paren: */
      p = buf + 8; /* Skip leading parenthesis and the value tag.  */
      len -= 8; /* Count only the data of the second part.  */
    }
  else
    {
      /* For compatibility with older gpg-agents handle the old style
         incomplete S-exps.  */
      len--;      /* Do not count the Nul.  */
      p = buf;
    }

  n = strtoul (p, &endp, 10);
  if (!n || *endp != ':')
    return gpg_error (GPG_ERR_INV_SEXP);
  endp++;
  if (endp-p+n != len)
    return gpg_error (GPG_ERR_INV_SEXP); /* Oops: Inconsistent S-Exp.  */

  memmove (buf, endp, n);

  *r_buflen = n;
  *r_buf = buf;
  return 0;
}





/* Handle a KEYPARMS inquiry.  Note, we only send the data,
   assuan_transact takes care of flushing and writing the end */
static gpg_error_t
inq_genkey_parms (void *opaque, const char *line)
{
  struct genkey_parm_s *parm = opaque;
  int rc;

  if (has_leading_keyword (line, "KEYPARAM"))
    {
      rc = assuan_send_data (parm->ctx, parm->sexp, parm->sexplen);
    }
  else
    {
      struct default_inq_parm_s inq_parm = { parm->ctrl, parm->ctx };
      rc = default_inq_cb (&inq_parm, line);
    }

  return rc;
}



/* Call the agent to generate a new key */
int
gpgsm_agent_genkey (ctrl_t ctrl,
                    ksba_const_sexp_t keyparms, ksba_sexp_t *r_pubkey)
{
  int rc;
  struct genkey_parm_s gk_parm;
  membuf_t data;
  size_t len;
  unsigned char *buf;
  gnupg_isotime_t timebuf;
  char line[ASSUAN_LINELENGTH];

  *r_pubkey = NULL;
  rc = start_agent (ctrl);
  if (rc)
    return rc;

  rc = assuan_transact (agent_ctx, "RESET", NULL, NULL, NULL, NULL, NULL, NULL);
  if (rc)
    return rc;

  init_membuf (&data, 1024);
  gk_parm.ctrl = ctrl;
  gk_parm.ctx = agent_ctx;
  gk_parm.sexp = keyparms;
  gk_parm.sexplen = gcry_sexp_canon_len (keyparms, 0, NULL, NULL);
  if (!gk_parm.sexplen)
    return gpg_error (GPG_ERR_INV_VALUE);
  gnupg_get_isotime (timebuf);
  snprintf (line, sizeof line, "GENKEY --timestamp=%s", timebuf);
  rc = assuan_transact (agent_ctx, line,
                        put_membuf_cb, &data,
                        inq_genkey_parms, &gk_parm, NULL, NULL);
  if (rc)
    {
      xfree (get_membuf (&data, &len));
      return rc;
    }
  buf = get_membuf (&data, &len);
  if (!buf)
    return gpg_error (GPG_ERR_ENOMEM);
  if (!gcry_sexp_canon_len (buf, len, NULL, NULL))
    {
      xfree (buf);
      return gpg_error (GPG_ERR_INV_SEXP);
    }
  *r_pubkey = buf;
  return 0;
}


/* Call the agent to read the public key part for a given keygrip.  If
   FROMCARD is true, the key is directly read from the current
   smartcard. In this case HEXKEYGRIP should be the keyID
   (e.g. OPENPGP.3). */
int
gpgsm_agent_readkey (ctrl_t ctrl, int fromcard, const char *hexkeygrip,
                     ksba_sexp_t *r_pubkey)
{
  int rc;
  membuf_t data;
  size_t len;
  unsigned char *buf;
  char line[ASSUAN_LINELENGTH];
  struct default_inq_parm_s inq_parm;

  *r_pubkey = NULL;
  rc = start_agent (ctrl);
  if (rc)
    return rc;
  inq_parm.ctrl = ctrl;
  inq_parm.ctx = agent_ctx;

  rc = assuan_transact (agent_ctx, "RESET",NULL, NULL, NULL, NULL, NULL, NULL);
  if (rc)
    return rc;

  snprintf (line, DIM(line), "%sREADKEY %s",
            fromcard? "SCD ":"", hexkeygrip);

  init_membuf (&data, 1024);
  rc = assuan_transact (agent_ctx, line,
                        put_membuf_cb, &data,
                        default_inq_cb, &inq_parm, NULL, NULL);
  if (rc)
    {
      xfree (get_membuf (&data, &len));
      return rc;
    }
  buf = get_membuf (&data, &len);
  if (!buf)
    return gpg_error (GPG_ERR_ENOMEM);
  if (!gcry_sexp_canon_len (buf, len, NULL, NULL))
    {
      xfree (buf);
      return gpg_error (GPG_ERR_INV_SEXP);
    }
  *r_pubkey = buf;
  return 0;
}



/* Take the serial number from LINE and return it verbatim in a newly
   allocated string.  We make sure that only hex characters are
   returned. */
static char *
store_serialno (const char *line)
{
  const char *s;
  char *p;

  for (s=line; hexdigitp (s); s++)
    ;
  p = xtrymalloc (s + 1 - line);
  if (p)
    {
      memcpy (p, line, s-line);
      p[s-line] = 0;
    }
  return p;
}


/* Callback for the gpgsm_agent_serialno function.  */
static gpg_error_t
scd_serialno_status_cb (void *opaque, const char *line)
{
  char **r_serialno = opaque;
  const char *keyword = line;
  int keywordlen;

  for (keywordlen=0; *line && !spacep (line); line++, keywordlen++)
    ;
  while (spacep (line))
    line++;

  if (keywordlen == 8 && !memcmp (keyword, "SERIALNO", keywordlen))
    {
      xfree (*r_serialno);
      *r_serialno = store_serialno (line);
    }

  return 0;
}


/* Call the agent to read the serial number of the current card.  */
int
gpgsm_agent_scd_serialno (ctrl_t ctrl, char **r_serialno)
{
  int rc;
  char *serialno = NULL;
  struct default_inq_parm_s inq_parm;

  *r_serialno = NULL;
  rc = start_agent (ctrl);
  if (rc)
    return rc;
  inq_parm.ctrl = ctrl;
  inq_parm.ctx = agent_ctx;

  rc = assuan_transact (agent_ctx, "SCD SERIALNO",
                        NULL, NULL,
                        default_inq_cb, &inq_parm,
                        scd_serialno_status_cb, &serialno);
  if (!rc && !serialno)
    rc = gpg_error (GPG_ERR_INTERNAL);
  if (rc)
    {
      xfree (serialno);
      return rc;
    }
  *r_serialno = serialno;
  return 0;
}



/* Callback for the gpgsm_agent_serialno function.  */
static gpg_error_t
scd_keypairinfo_status_cb (void *opaque, const char *line)
{
  strlist_t *listaddr = opaque;
  const char *keyword = line;
  int keywordlen;
  strlist_t sl;
  char *p;

  for (keywordlen=0; *line && !spacep (line); line++, keywordlen++)
    ;
  while (spacep (line))
    line++;

  if (keywordlen == 11 && !memcmp (keyword, "KEYPAIRINFO", keywordlen))
    {
      sl = append_to_strlist (listaddr, line);
      p = sl->d;
      /* Make sure that we only have two tokens so that future
       * extensions of the format won't change the format expected by
       * the caller.  */
      while (*p && !spacep (p))
        p++;
      if (*p)
        {
          while (spacep (p))
            p++;
          while (*p && !spacep (p))
            p++;
          if (*p)
            {
              *p++ = 0;
              while (spacep (p))
                p++;
              while (*p && !spacep (p))
                {
                  switch (*p++)
                    {
                    case 'c': sl->flags |= GCRY_PK_USAGE_CERT; break;
                    case 's': sl->flags |= GCRY_PK_USAGE_SIGN; break;
                    case 'e': sl->flags |= GCRY_PK_USAGE_ENCR; break;
                    case 'a': sl->flags |= GCRY_PK_USAGE_AUTH; break;
                    }
                }
            }
        }
    }

  return 0;
}


/* Call the agent to read the keypairinfo lines of the current card.
   The list is returned as a string made up of the keygrip, a space
   and the keyid.  The flags of the string carry the usage bits.  */
int
gpgsm_agent_scd_keypairinfo (ctrl_t ctrl, strlist_t *r_list)
{
  int rc;
  strlist_t list = NULL;
  struct default_inq_parm_s inq_parm;

  *r_list = NULL;
  rc = start_agent (ctrl);
  if (rc)
    return rc;
  inq_parm.ctrl = ctrl;
  inq_parm.ctx = agent_ctx;

  rc = assuan_transact (agent_ctx, "SCD LEARN --keypairinfo",
                        NULL, NULL,
                        default_inq_cb, &inq_parm,
                        scd_keypairinfo_status_cb, &list);
  if (!rc && !list)
    rc = gpg_error (GPG_ERR_NO_DATA);
  if (rc)
    {
      free_strlist (list);
      return rc;
    }
  *r_list = list;
  return 0;
}



static gpg_error_t
istrusted_status_cb (void *opaque, const char *line)
{
  struct rootca_flags_s *flags = opaque;
  const char *s;

  if ((s = has_leading_keyword (line, "TRUSTLISTFLAG")))
    {
      line = s;
      if (has_leading_keyword (line, "relax"))
        flags->relax = 1;
      else if (has_leading_keyword (line, "cm"))
        flags->chain_model = 1;
      else if (has_leading_keyword (line, "qual"))
        flags->qualified = 1;
      else if (has_leading_keyword (line, "de-vs"))
        flags->de_vs = 1;
    }
  return 0;
}



/* Ask the agent whether the certificate is in the list of trusted
   keys.  The certificate is either specified by the CERT object or by
   the fingerprint HEXFPR.  ROOTCA_FLAGS is guaranteed to be cleared
   on error. */
int
gpgsm_agent_istrusted (ctrl_t ctrl, ksba_cert_t cert, const char *hexfpr,
                       struct rootca_flags_s *rootca_flags)
{
  int rc;
  char line[ASSUAN_LINELENGTH];

  memset (rootca_flags, 0, sizeof *rootca_flags);

  if (cert && hexfpr)
    return gpg_error (GPG_ERR_INV_ARG);

  rc = start_agent (ctrl);
  if (rc)
    return rc;

  if (hexfpr)
    {
      snprintf (line, DIM(line), "ISTRUSTED %s", hexfpr);
    }
  else
    {
      char *fpr;

      fpr = gpgsm_get_fingerprint_hexstring (cert, GCRY_MD_SHA1);
      if (!fpr)
        {
          log_error ("error getting the fingerprint\n");
          return gpg_error (GPG_ERR_GENERAL);
        }

      snprintf (line, DIM(line), "ISTRUSTED %s", fpr);
      xfree (fpr);
    }

  rc = assuan_transact (agent_ctx, line, NULL, NULL, NULL, NULL,
                        istrusted_status_cb, rootca_flags);
  if (!rc)
    rootca_flags->valid = 1;
  return rc;
}

/* Ask the agent to mark CERT as a trusted Root-CA one */
int
gpgsm_agent_marktrusted (ctrl_t ctrl, ksba_cert_t cert)
{
  int rc;
  char *fpr, *dn, *dnfmt;
  char line[ASSUAN_LINELENGTH];
  struct default_inq_parm_s inq_parm;

  rc = start_agent (ctrl);
  if (rc)
    return rc;
  inq_parm.ctrl = ctrl;
  inq_parm.ctx = agent_ctx;

  fpr = gpgsm_get_fingerprint_hexstring (cert, GCRY_MD_SHA1);
  if (!fpr)
    {
      log_error ("error getting the fingerprint\n");
      return gpg_error (GPG_ERR_GENERAL);
    }

  dn = ksba_cert_get_issuer (cert, 0);
  if (!dn)
    {
      xfree (fpr);
      return gpg_error (GPG_ERR_GENERAL);
    }
  dnfmt = gpgsm_format_name2 (dn, 0);
  xfree (dn);
  if (!dnfmt)
    return gpg_error_from_syserror ();
  snprintf (line, DIM(line), "MARKTRUSTED %s S %s", fpr, dnfmt);
  ksba_free (dnfmt);
  xfree (fpr);

  rc = assuan_transact (agent_ctx, line, NULL, NULL,
                        default_inq_cb, &inq_parm, NULL, NULL);
  return rc;
}



/* Ask the agent whether the a corresponding secret key is available
   for the given keygrip */
int
gpgsm_agent_havekey (ctrl_t ctrl, const char *hexkeygrip)
{
  int rc;
  char line[ASSUAN_LINELENGTH];

  rc = start_agent (ctrl);
  if (rc)
    return rc;

  if (!hexkeygrip || strlen (hexkeygrip) != 40)
    return gpg_error (GPG_ERR_INV_VALUE);

  snprintf (line, DIM(line), "HAVEKEY %s", hexkeygrip);

  rc = assuan_transact (agent_ctx, line, NULL, NULL, NULL, NULL, NULL, NULL);
  return rc;
}


static gpg_error_t
learn_status_cb (void *opaque, const char *line)
{
  struct learn_parm_s *parm = opaque;
  const char *s;

  /* Pass progress data to the caller.  */
  if ((s = has_leading_keyword (line, "PROGRESS")))
    {
      line = s;
      if (parm->ctrl)
        {
          if (gpgsm_status (parm->ctrl, STATUS_PROGRESS, line))
            return gpg_error (GPG_ERR_ASS_CANCELED);
        }
    }
  return 0;
}

static gpg_error_t
learn_cb (void *opaque, const void *buffer, size_t length)
{
  struct learn_parm_s *parm = opaque;
  size_t len;
  char *buf;
  ksba_cert_t cert;
  int rc;
  char *string, *p, *pend;
  strlist_t sl;

  if (parm->error)
    return 0;

  if (buffer)
    {
      put_membuf (parm->data, buffer, length);
      return 0;
    }
  /* END encountered - process what we have */
  buf = get_membuf (parm->data, &len);
  if (!buf)
    {
      parm->error = gpg_error (GPG_ERR_ENOMEM);
      return 0;
    }

  if (gpgsm_status (parm->ctrl, STATUS_PROGRESS, "learncard C 0 0"))
    return gpg_error (GPG_ERR_ASS_CANCELED);

  /* FIXME: this should go into import.c */
  rc = ksba_cert_new (&cert);
  if (rc)
    {
      parm->error = rc;
      return 0;
    }
  rc = ksba_cert_init_from_mem (cert, buf, len);
  if (rc)
    {
      log_error ("failed to parse a certificate: %s\n", gpg_strerror (rc));
      ksba_cert_release (cert);
      parm->error = rc;
      return 0;
    }

  /* Ignore certificates matching certain extended usage flags.  */
  rc = ksba_cert_get_ext_key_usages (cert, &string);
  if (!rc)
    {
      p = string;
      while (p && (pend=strchr (p, ':')))
        {
          *pend++ = 0;
          for (sl=opt.ignore_cert_with_oid;
               sl && strcmp (sl->d, p); sl = sl->next)
            ;
          if (sl)
            {
              if (opt.verbose)
                log_info ("certificate ignored due to OID %s\n", sl->d);
              goto leave;
            }
          p = pend;
          if ((p = strchr (p, '\n')))
            p++;
        }
    }
  else if (gpg_err_code (rc) != GPG_ERR_NO_DATA)
    log_error (_("error getting key usage information: %s\n"),
               gpg_strerror (rc));
  xfree (string);
  string = NULL;


  /* We do not store a certifciate with missing issuers as ephemeral
     because we can assume that the --learn-card command has been used
     on purpose.  */
  rc = gpgsm_basic_cert_check (parm->ctrl, cert);
  if (rc && gpg_err_code (rc) != GPG_ERR_MISSING_CERT
      && gpg_err_code (rc) != GPG_ERR_MISSING_ISSUER_CERT)
    log_error ("invalid certificate: %s\n", gpg_strerror (rc));
  else
    {
      int existed;

      if (!keydb_store_cert (parm->ctrl, cert, 0, &existed))
        {
          if (opt.verbose > 1 && existed)
            log_info ("certificate already in DB\n");
          else if (opt.verbose && !existed)
            log_info ("certificate imported\n");
        }
    }

 leave:
  xfree (string);
  string = NULL;
  ksba_cert_release (cert);
  init_membuf (parm->data, 4096);
  return 0;
}

/* Call the agent to learn about a smartcard */
int
gpgsm_agent_learn (ctrl_t ctrl)
{
  int rc;
  struct learn_parm_s learn_parm;
  membuf_t data;
  size_t len;

  rc = start_agent (ctrl);
  if (rc)
    return rc;

  rc = warn_version_mismatch (ctrl, agent_ctx, SCDAEMON_NAME, 2);
  if (rc)
    return rc;

  init_membuf (&data, 4096);
  learn_parm.error = 0;
  learn_parm.ctrl = ctrl;
  learn_parm.ctx = agent_ctx;
  learn_parm.data = &data;
  rc = assuan_transact (agent_ctx, "LEARN --send",
                        learn_cb, &learn_parm,
                        NULL, NULL,
                        learn_status_cb, &learn_parm);
  xfree (get_membuf (&data, &len));
  if (rc)
    return rc;
  return learn_parm.error;
}


/* Ask the agent to change the passphrase of the key identified by
   HEXKEYGRIP. If DESC is not NULL, display instead of the default
   description message. */
int
gpgsm_agent_passwd (ctrl_t ctrl, const char *hexkeygrip, const char *desc)
{
  int rc;
  char line[ASSUAN_LINELENGTH];
  struct default_inq_parm_s inq_parm;

  rc = start_agent (ctrl);
  if (rc)
    return rc;
  inq_parm.ctrl = ctrl;
  inq_parm.ctx = agent_ctx;

  if (!hexkeygrip || strlen (hexkeygrip) != 40)
    return gpg_error (GPG_ERR_INV_VALUE);

  if (desc)
    {
      snprintf (line, DIM(line), "SETKEYDESC %s", desc);
      rc = assuan_transact (agent_ctx, line,
                            NULL, NULL, NULL, NULL, NULL, NULL);
      if (rc)
        return rc;
    }

  snprintf (line, DIM(line), "PASSWD %s", hexkeygrip);

  rc = assuan_transact (agent_ctx, line, NULL, NULL,
                        default_inq_cb, &inq_parm, NULL, NULL);
  return rc;
}



/* Ask the agent to pop up a confirmation dialog with the text DESC
   and an okay and cancel button.  */
gpg_error_t
gpgsm_agent_get_confirmation (ctrl_t ctrl, const char *desc)
{
  int rc;
  char line[ASSUAN_LINELENGTH];
  struct default_inq_parm_s inq_parm;

  rc = start_agent (ctrl);
  if (rc)
    return rc;
  inq_parm.ctrl = ctrl;
  inq_parm.ctx = agent_ctx;

  snprintf (line, DIM(line), "GET_CONFIRMATION %s", desc);

  rc = assuan_transact (agent_ctx, line, NULL, NULL,
                        default_inq_cb, &inq_parm, NULL, NULL);
  return rc;
}



/* Return 0 if the agent is alive.  This is useful to make sure that
   an agent has been started. */
gpg_error_t
gpgsm_agent_send_nop (ctrl_t ctrl)
{
  int rc;

  rc = start_agent (ctrl);
  if (!rc)
    rc = assuan_transact (agent_ctx, "NOP",
                          NULL, NULL, NULL, NULL, NULL, NULL);
  return rc;
}



static gpg_error_t
keyinfo_status_cb (void *opaque, const char *line)
{
  char **serialno = opaque;
  const char *s, *s2;

  if ((s = has_leading_keyword (line, "KEYINFO")) && !*serialno)
    {
      s = strchr (s, ' ');
      if (s && s[1] == 'T' && s[2] == ' ' && s[3])
        {
          s += 3;
          s2 = strchr (s, ' ');
          if ( s2 > s )
            {
              *serialno = xtrymalloc ((s2 - s)+1);
              if (*serialno)
                {
                  memcpy (*serialno, s, s2 - s);
                  (*serialno)[s2 - s] = 0;
                }
            }
        }
    }
  return 0;
}

/* Return the serial number for a secret key.  If the returned serial
   number is NULL, the key is not stored on a smartcard.  Caller needs
   to free R_SERIALNO.  */
gpg_error_t
gpgsm_agent_keyinfo (ctrl_t ctrl, const char *hexkeygrip, char **r_serialno)
{
  gpg_error_t err;
  char line[ASSUAN_LINELENGTH];
  char *serialno = NULL;

  *r_serialno = NULL;

  err = start_agent (ctrl);
  if (err)
    return err;

  if (!hexkeygrip || strlen (hexkeygrip) != 40)
    return gpg_error (GPG_ERR_INV_VALUE);

  snprintf (line, DIM(line), "KEYINFO %s", hexkeygrip);

  err = assuan_transact (agent_ctx, line, NULL, NULL, NULL, NULL,
                         keyinfo_status_cb, &serialno);
  if (!err && serialno)
    {
      /* Sanity check for bad characters.  */
      if (strpbrk (serialno, ":\n\r"))
        err = GPG_ERR_INV_VALUE;
    }
  if (err)
    xfree (serialno);
  else
    *r_serialno = serialno;
  return err;
}



/* Ask for the passphrase (this is used for pkcs#12 import/export.  On
   success the caller needs to free the string stored at R_PASSPHRASE.
   On error NULL will be stored at R_PASSPHRASE and an appropriate
   error code returned.  If REPEAT is true the agent tries to get a
   new passphrase (i.e. asks the user to confirm it).  */
gpg_error_t
gpgsm_agent_ask_passphrase (ctrl_t ctrl, const char *desc_msg, int repeat,
                            char **r_passphrase)
{
  gpg_error_t err;
  char line[ASSUAN_LINELENGTH];
  char *arg4 = NULL;
  membuf_t data;
  struct default_inq_parm_s inq_parm;
  int wasconf;

  *r_passphrase = NULL;

  err = start_agent (ctrl);
  if (err)
    return err;
  inq_parm.ctrl = ctrl;
  inq_parm.ctx = agent_ctx;

  if (desc_msg && *desc_msg && !(arg4 = percent_plus_escape (desc_msg)))
    return gpg_error_from_syserror ();

  snprintf (line, DIM(line), "GET_PASSPHRASE --data%s -- X X X %s",
            repeat? " --repeat=1 --check":"",
            arg4);
  xfree (arg4);

  init_membuf_secure (&data, 64);
  wasconf = assuan_get_flag (agent_ctx, ASSUAN_CONFIDENTIAL);
  assuan_begin_confidential (agent_ctx);
  err = assuan_transact (agent_ctx, line,
                         put_membuf_cb, &data,
                         default_inq_cb, &inq_parm, NULL, NULL);
  if (!wasconf)
    assuan_end_confidential (agent_ctx);

  if (err)
    xfree (get_membuf (&data, NULL));
  else
    {
      put_membuf (&data, "", 1);
      *r_passphrase = get_membuf (&data, NULL);
      if (!*r_passphrase)
        err = gpg_error_from_syserror ();
    }
  return err;
}



/* Retrieve a key encryption key from the agent.  With FOREXPORT true
   the key shall be use for export, with false for import.  On success
   the new key is stored at R_KEY and its length at R_KEKLEN.  */
gpg_error_t
gpgsm_agent_keywrap_key (ctrl_t ctrl, int forexport,
                         void **r_kek, size_t *r_keklen)
{
  gpg_error_t err;
  membuf_t data;
  size_t len;
  unsigned char *buf;
  char line[ASSUAN_LINELENGTH];
  struct default_inq_parm_s inq_parm;

  *r_kek = NULL;
  err = start_agent (ctrl);
  if (err)
    return err;
  inq_parm.ctrl = ctrl;
  inq_parm.ctx = agent_ctx;

  snprintf (line, DIM(line), "KEYWRAP_KEY %s",
            forexport? "--export":"--import");

  init_membuf_secure (&data, 64);
  err = assuan_transact (agent_ctx, line,
                         put_membuf_cb, &data,
                         default_inq_cb, &inq_parm, NULL, NULL);
  if (err)
    {
      xfree (get_membuf (&data, &len));
      return err;
    }
  buf = get_membuf (&data, &len);
  if (!buf)
    return gpg_error_from_syserror ();
  *r_kek = buf;
  *r_keklen = len;
  return 0;
}




/* Handle the inquiry for an IMPORT_KEY command.  */
static gpg_error_t
inq_import_key_parms (void *opaque, const char *line)
{
  struct import_key_parm_s *parm = opaque;
  gpg_error_t err;

  if (has_leading_keyword (line, "KEYDATA"))
    {
      assuan_begin_confidential (parm->ctx);
      err = assuan_send_data (parm->ctx, parm->key, parm->keylen);
      assuan_end_confidential (parm->ctx);
    }
  else
    {
      struct default_inq_parm_s inq_parm = { parm->ctrl, parm->ctx };
      err = default_inq_cb (&inq_parm, line);
    }

  return err;
}


/* Call the agent to import a key into the agent.  */
gpg_error_t
gpgsm_agent_import_key (ctrl_t ctrl, const void *key, size_t keylen)
{
  gpg_error_t err;
  struct import_key_parm_s parm;
  gnupg_isotime_t timebuf;
  char line[ASSUAN_LINELENGTH];

  err = start_agent (ctrl);
  if (err)
    return err;

  parm.ctrl   = ctrl;
  parm.ctx    = agent_ctx;
  parm.key    = key;
  parm.keylen = keylen;

  gnupg_get_isotime (timebuf);
  snprintf (line, sizeof line, "IMPORT_KEY --timestamp=%s", timebuf);
  err = assuan_transact (agent_ctx, line,
                         NULL, NULL, inq_import_key_parms, &parm, NULL, NULL);
  return err;
}



/* Receive a secret key from the agent.  KEYGRIP is the hexified
   keygrip, DESC a prompt to be displayed with the agent's passphrase
   question (needs to be plus+percent escaped).  On success the key is
   stored as a canonical S-expression at R_RESULT and R_RESULTLEN. */
gpg_error_t
gpgsm_agent_export_key (ctrl_t ctrl, const char *keygrip, const char *desc,
                        unsigned char **r_result, size_t *r_resultlen)
{
  gpg_error_t err;
  membuf_t data;
  size_t len;
  unsigned char *buf;
  char line[ASSUAN_LINELENGTH];
  struct default_inq_parm_s inq_parm;

  *r_result = NULL;

  err = start_agent (ctrl);
  if (err)
    return err;
  inq_parm.ctrl = ctrl;
  inq_parm.ctx = agent_ctx;

  if (desc)
    {
      snprintf (line, DIM(line), "SETKEYDESC %s", desc);
      err = assuan_transact (agent_ctx, line,
                             NULL, NULL, NULL, NULL, NULL, NULL);
      if (err)
        return err;
    }

  snprintf (line, DIM(line), "EXPORT_KEY %s", keygrip);

  init_membuf_secure (&data, 1024);
  err = assuan_transact (agent_ctx, line,
                         put_membuf_cb, &data,
                         default_inq_cb, &inq_parm, NULL, NULL);
  if (err)
    {
      xfree (get_membuf (&data, &len));
      return err;
    }
  buf = get_membuf (&data, &len);
  if (!buf)
    return gpg_error_from_syserror ();
  *r_result = buf;
  *r_resultlen = len;
  return 0;
}
