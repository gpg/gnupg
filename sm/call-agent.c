/* call-agent.c - divert operations to the agent
 *	Copyright (C) 2001, 2002, 2003, 2005 Free Software Foundation, Inc.
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
#ifdef HAVE_LOCALE_H
#include <locale.h>
#endif

#include "gpgsm.h"
#include <gcrypt.h>
#include <assuan.h>
#include "i18n.h"
#include "asshelp.h"
#include "keydb.h" /* fixme: Move this to import.c */
#include "membuf.h"


static assuan_context_t agent_ctx = NULL;


struct cipher_parm_s
{
  assuan_context_t ctx;
  const unsigned char *ciphertext;
  size_t ciphertextlen;
};

struct genkey_parm_s
{
  assuan_context_t ctx;
  const unsigned char *sexp;
  size_t sexplen;
};

struct learn_parm_s
{
  int error;
  assuan_context_t ctx;
  membuf_t *data;
};



/* Try to connect to the agent via socket or fork it off and work by
   pipes.  Handle the server's initial greeting */
static int
start_agent (ctrl_t ctrl)
{
  if (agent_ctx)
    return 0; /* fixme: We need a context for each thread or serialize
                 the access to the agent (which is suitable given that
                 the agent is not MT. */


  return start_new_gpg_agent (&agent_ctx,
                              GPG_ERR_SOURCE_DEFAULT,
                              opt.homedir,
                              opt.agent_program,
                              opt.display, opt.ttyname, opt.ttytype,
                              opt.lc_ctype, opt.lc_messages,
                              opt.verbose, DBG_ASSUAN,
                              gpgsm_status2, ctrl);

}



static int
membuf_data_cb (void *opaque, const void *buffer, size_t length)
{
  membuf_t *data = opaque;

  if (buffer)
    put_membuf (data, buffer, length);
  return 0;
}
  



/* Call the agent to do a sign operation using the key identified by
   the hex string KEYGRIP. */
int
gpgsm_agent_pksign (ctrl_t ctrl, const char *keygrip, const char *desc,
                    unsigned char *digest, size_t digestlen, int digestalgo,
                    unsigned char **r_buf, size_t *r_buflen )
{
  int rc, i;
  char *p, line[ASSUAN_LINELENGTH];
  membuf_t data;
  size_t len;

  *r_buf = NULL;
  rc = start_agent (ctrl);
  if (rc)
    return rc;

  if (digestlen*2 + 50 > DIM(line))
    return gpg_error (GPG_ERR_GENERAL);

  rc = assuan_transact (agent_ctx, "RESET", NULL, NULL, NULL, NULL, NULL, NULL);
  if (rc)
    return rc;

  snprintf (line, DIM(line)-1, "SIGKEY %s", keygrip);
  line[DIM(line)-1] = 0;
  rc = assuan_transact (agent_ctx, line, NULL, NULL, NULL, NULL, NULL, NULL);
  if (rc)
    return rc;

  if (desc)
    {
      snprintf (line, DIM(line)-1, "SETKEYDESC %s", desc);
      line[DIM(line)-1] = 0;
      rc = assuan_transact (agent_ctx, line,
                            NULL, NULL, NULL, NULL, NULL, NULL);
      if (rc)
        return rc;
    }

  sprintf (line, "SETHASH %d ", digestalgo);
  p = line + strlen (line);
  for (i=0; i < digestlen ; i++, p += 2 )
    sprintf (p, "%02X", digest[i]);
  rc = assuan_transact (agent_ctx, line, NULL, NULL, NULL, NULL, NULL, NULL);
  if (rc)
    return rc;

  init_membuf (&data, 1024);
  rc = assuan_transact (agent_ctx, "PKSIGN",
                        membuf_data_cb, &data, NULL, NULL, NULL, NULL);
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
  int rc, i;
  char *p, line[ASSUAN_LINELENGTH];
  membuf_t data;
  size_t len;
  const char *hashopt;
  unsigned char *sigbuf;
  size_t sigbuflen;

  *r_buf = NULL;

  switch(digestalgo)
    {
    case GCRY_MD_SHA1:  hashopt = "--hash=sha1"; break;
    case GCRY_MD_RMD160:hashopt = "--hash=rmd160"; break;
    case GCRY_MD_MD5:   hashopt = "--hash=md5"; break;
    case GCRY_MD_SHA256:hashopt = "--hash=sha256"; break;
    default: 
      return gpg_error (GPG_ERR_DIGEST_ALGO);
    }

  rc = start_agent (ctrl);
  if (rc)
    return rc;

  if (digestlen*2 + 50 > DIM(line))
    return gpg_error (GPG_ERR_GENERAL);

  p = stpcpy (line, "SCD SETDATA " );
  for (i=0; i < digestlen ; i++, p += 2 )
    sprintf (p, "%02X", digest[i]);
  rc = assuan_transact (agent_ctx, line, NULL, NULL, NULL, NULL, NULL, NULL);
  if (rc)
    return rc;

  init_membuf (&data, 1024);

  snprintf (line, DIM(line)-1, "SCD PKSIGN %s %s", hashopt, keyid);
  line[DIM(line)-1] = 0;
  rc = assuan_transact (agent_ctx, line,
                        membuf_data_cb, &data, NULL, NULL, NULL, NULL);
  if (rc)
    {
      xfree (get_membuf (&data, &len));
      return rc;
    }
  sigbuf = get_membuf (&data, &sigbuflen);

  /* Create an S-expression from it which is formatted like this:
     "(7:sig-val(3:rsa(1:sSIGBUFLEN:SIGBUF)))" Fixme: If a card ever
     creates non-RSA keys we need to change things. */
  *r_buflen = 21 + 11 + sigbuflen + 4;
  p = xtrymalloc (*r_buflen);
  *r_buf = (unsigned char*)p;
  if (!p)
    {
      xfree (sigbuf);
      return 0;
    }
  p = stpcpy (p, "(7:sig-val(3:rsa(1:s" );
  sprintf (p, "%u:", (unsigned int)sigbuflen);
  p += strlen (p);
  memcpy (p, sigbuf, sigbuflen);
  p += sigbuflen;
  strcpy (p, ")))");
  xfree (sigbuf);

  assert (gcry_sexp_canon_len (*r_buf, *r_buflen, NULL, NULL));
  return  0;
}




/* Handle a CIPHERTEXT inquiry.  Note, we only send the data,
   assuan_transact talkes care of flushing and writing the end */
static int
inq_ciphertext_cb (void *opaque, const char *keyword)
{
  struct cipher_parm_s *parm = opaque; 
  int rc;

  assuan_begin_confidential (parm->ctx);
  rc = assuan_send_data (parm->ctx, parm->ciphertext, parm->ciphertextlen);
  assuan_end_confidential (parm->ctx);
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

  assert ( DIM(line) >= 50 );
  snprintf (line, DIM(line)-1, "SETKEY %s", keygrip);
  line[DIM(line)-1] = 0;
  rc = assuan_transact (agent_ctx, line, NULL, NULL, NULL, NULL, NULL, NULL);
  if (rc)
    return rc;

  if (desc)
    {
      snprintf (line, DIM(line)-1, "SETKEYDESC %s", desc);
      line[DIM(line)-1] = 0;
      rc = assuan_transact (agent_ctx, line,
                            NULL, NULL, NULL, NULL, NULL, NULL);
      if (rc)
        return rc;
    }

  init_membuf (&data, 1024);
  cipher_parm.ctx = agent_ctx;
  cipher_parm.ciphertext = ciphertext;
  cipher_parm.ciphertextlen = ciphertextlen;
  rc = assuan_transact (agent_ctx, "PKDECRYPT",
                        membuf_data_cb, &data,
                        inq_ciphertext_cb, &cipher_parm, NULL, NULL);
  if (rc)
    {
      xfree (get_membuf (&data, &len));
      return rc;
    }

  put_membuf (&data, "", 1); /* Make sure it is 0 terminated. */
  buf = get_membuf (&data, &len);
  if (!buf)
    return gpg_error (GPG_ERR_ENOMEM);
  assert (len); /* (we forced Nul termination.)  */

  if (*buf == '(')
    {
      if (len < 13 || memcmp (buf, "(5:value", 8) ) /* "(5:valueN:D)\0" */
        return gpg_error (GPG_ERR_INV_SEXP);
      len -= 11;   /* Count only the data of the second part. */
      p = buf + 8; /* Skip leading parenthesis and the value tag. */
    }
  else
    {
      /* For compatibility with older gpg-agents handle the old style
         incomplete S-exps. */
      len--;      /* Do not count the Nul. */
      p = buf;
    }

  n = strtoul (p, &endp, 10);
  if (!n || *endp != ':')
    return gpg_error (GPG_ERR_INV_SEXP);
  endp++;
  if (endp-p+n > len)
    return gpg_error (GPG_ERR_INV_SEXP); /* Oops: Inconsistent S-Exp. */
  
  memmove (buf, endp, n);

  *r_buflen = n;
  *r_buf = buf;
  return 0;
}





/* Handle a KEYPARMS inquiry.  Note, we only send the data,
   assuan_transact takes care of flushing and writing the end */
static int
inq_genkey_parms (void *opaque, const char *keyword)
{
  struct genkey_parm_s *parm = opaque; 
  int rc;

  rc = assuan_send_data (parm->ctx, parm->sexp, parm->sexplen);
  return rc; 
}



/* Call the agent to generate a newkey */
int
gpgsm_agent_genkey (ctrl_t ctrl,
                    ksba_const_sexp_t keyparms, ksba_sexp_t *r_pubkey)
{
  int rc;
  struct genkey_parm_s gk_parm;
  membuf_t data;
  size_t len;
  unsigned char *buf;

  *r_pubkey = NULL;
  rc = start_agent (ctrl);
  if (rc)
    return rc;

  rc = assuan_transact (agent_ctx, "RESET", NULL, NULL, NULL, NULL, NULL, NULL);
  if (rc)
    return rc;

  init_membuf (&data, 1024);
  gk_parm.ctx = agent_ctx;
  gk_parm.sexp = keyparms;
  gk_parm.sexplen = gcry_sexp_canon_len (keyparms, 0, NULL, NULL);
  if (!gk_parm.sexplen)
    return gpg_error (GPG_ERR_INV_VALUE);
  rc = assuan_transact (agent_ctx, "GENKEY",
                        membuf_data_cb, &data, 
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

  *r_pubkey = NULL;
  rc = start_agent (ctrl);
  if (rc)
    return rc;

  rc = assuan_transact (agent_ctx, "RESET",NULL, NULL, NULL, NULL, NULL, NULL);
  if (rc)
    return rc;

  snprintf (line, DIM(line)-1, "%sREADKEY %s",
            fromcard? "SCD ":"", hexkeygrip);
  line[DIM(line)-1] = 0;

  init_membuf (&data, 1024);
  rc = assuan_transact (agent_ctx, line,
                        membuf_data_cb, &data, 
                        NULL, NULL, NULL, NULL);
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



static int
istrusted_status_cb (void *opaque, const char *line)
{
  struct rootca_flags_s *flags = opaque;

  if (!strncmp (line, "TRUSTLISTFLAG", 13) && (line[13]==' ' || !line[13]))
    {
      for (line += 13; *line == ' '; line++)
        ;
      if (!strncmp (line, "relax", 5) && (line[5] == ' ' || !line[5]))
        flags->relax = 1;
    }
  return 0;
}



/* Ask the agent whether the certificate is in the list of trusted
   keys.  ROOTCA_FLAGS is guaranteed to be cleared on error. */
int
gpgsm_agent_istrusted (ctrl_t ctrl, ksba_cert_t cert,
                       struct rootca_flags_s *rootca_flags)
{
  int rc;
  char *fpr;
  char line[ASSUAN_LINELENGTH];

  memset (rootca_flags, 0, sizeof *rootca_flags);

  rc = start_agent (ctrl);
  if (rc)
    return rc;

  fpr = gpgsm_get_fingerprint_hexstring (cert, GCRY_MD_SHA1);
  if (!fpr)
    {
      log_error ("error getting the fingerprint\n");
      return gpg_error (GPG_ERR_GENERAL);
    }

  snprintf (line, DIM(line)-1, "ISTRUSTED %s", fpr);
  line[DIM(line)-1] = 0;
  xfree (fpr);

  rc = assuan_transact (agent_ctx, line, NULL, NULL, NULL, NULL,
                        istrusted_status_cb, rootca_flags);
  return rc;
}

/* Ask the agent to mark CERT as a trusted Root-CA one */
int
gpgsm_agent_marktrusted (ctrl_t ctrl, ksba_cert_t cert)
{
  int rc;
  char *fpr, *dn;
  char line[ASSUAN_LINELENGTH];

  rc = start_agent (ctrl);
  if (rc)
    return rc;

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
  snprintf (line, DIM(line)-1, "MARKTRUSTED %s S %s", fpr, dn);
  line[DIM(line)-1] = 0;
  ksba_free (dn);
  xfree (fpr);

  rc = assuan_transact (agent_ctx, line, NULL, NULL, NULL, NULL, NULL, NULL);
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

  snprintf (line, DIM(line)-1, "HAVEKEY %s", hexkeygrip);
  line[DIM(line)-1] = 0;

  rc = assuan_transact (agent_ctx, line, NULL, NULL, NULL, NULL, NULL, NULL);
  return rc;
}


static int
learn_cb (void *opaque, const void *buffer, size_t length)
{
  struct learn_parm_s *parm = opaque;
  size_t len;
  char *buf;
  ksba_cert_t cert;
  int rc;

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

  rc = gpgsm_basic_cert_check (cert);
  if (gpg_err_code (rc) == GPG_ERR_MISSING_CERT)
    { /* For later use we store it in the ephemeral database. */
      log_info ("issuer certificate missing - storing as ephemeral\n");
      keydb_store_cert (cert, 1, NULL);
    }
  else if (rc)
    log_error ("invalid certificate: %s\n", gpg_strerror (rc));
  else
    {
      int existed;

      if (!keydb_store_cert (cert, 0, &existed))
        {
          if (opt.verbose > 1 && existed)
            log_info ("certificate already in DB\n");
          else if (opt.verbose && !existed)
            log_info ("certificate imported\n");
        }
    }

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

  init_membuf (&data, 4096);
  learn_parm.error = 0;
  learn_parm.ctx = agent_ctx;
  learn_parm.data = &data;
  rc = assuan_transact (agent_ctx, "LEARN --send",
                        learn_cb, &learn_parm, 
                        NULL, NULL, NULL, NULL);
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

  rc = start_agent (ctrl);
  if (rc)
    return rc;

  if (!hexkeygrip || strlen (hexkeygrip) != 40)
    return gpg_error (GPG_ERR_INV_VALUE);

  if (desc)
    {
      snprintf (line, DIM(line)-1, "SETKEYDESC %s", desc);
      line[DIM(line)-1] = 0;
      rc = assuan_transact (agent_ctx, line,
                            NULL, NULL, NULL, NULL, NULL, NULL);
      if (rc)
        return rc;
    }

  snprintf (line, DIM(line)-1, "PASSWD %s", hexkeygrip);
  line[DIM(line)-1] = 0;

  rc = assuan_transact (agent_ctx, line, NULL, NULL, NULL, NULL, NULL, NULL);
  return rc;
}



/* Ask the agent to pop up a confirmation dialog with the text DESC
   and an okay and cancel button.  */
gpg_error_t
gpgsm_agent_get_confirmation (ctrl_t ctrl, const char *desc)
{
  int rc;
  char line[ASSUAN_LINELENGTH];

  rc = start_agent (ctrl);
  if (rc)
    return rc;

  snprintf (line, DIM(line)-1, "GET_CONFIRMATION %s", desc);
  line[DIM(line)-1] = 0;

  rc = assuan_transact (agent_ctx, line, NULL, NULL, NULL, NULL, NULL, NULL);
  return rc;
}
