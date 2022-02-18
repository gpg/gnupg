/* call-dirmngr.c - Communication with the dirmngr
 * Copyright (C) 2002, 2003, 2005, 2007, 2008,
 *               2010  Free Software Foundation, Inc.
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
#include <assert.h>
#include <ctype.h>

#include "gpgsm.h"
#include <gcrypt.h>
#include <assuan.h>

#include "../common/i18n.h"
#include "keydb.h"
#include "../common/asshelp.h"


struct membuf {
  size_t len;
  size_t size;
  char *buf;
  int out_of_core;
};



/* fixme: We need a context for each thread or serialize the access to
   the dirmngr.  */
static assuan_context_t dirmngr_ctx = NULL;
static assuan_context_t dirmngr2_ctx = NULL;

static int dirmngr_ctx_locked;
static int dirmngr2_ctx_locked;

struct inq_certificate_parm_s {
  ctrl_t ctrl;
  assuan_context_t ctx;
  ksba_cert_t cert;
  ksba_cert_t issuer_cert;
};

struct isvalid_status_parm_s {
  ctrl_t ctrl;
  int seen;
  unsigned char fpr[20];
};


struct lookup_parm_s {
  ctrl_t ctrl;
  assuan_context_t ctx;
  void (*cb)(void *, ksba_cert_t);
  void *cb_value;
  struct membuf data;
  int error;
};

struct run_command_parm_s {
  ctrl_t ctrl;
  assuan_context_t ctx;
};



static gpg_error_t get_cached_cert (assuan_context_t ctx,
                                    const unsigned char *fpr,
                                    ksba_cert_t *r_cert);



/* A simple implementation of a dynamic buffer.  Use init_membuf() to
   create a buffer, put_membuf to append bytes and get_membuf to
   release and return the buffer.  Allocation errors are detected but
   only returned at the final get_membuf(), this helps not to clutter
   the code with out of core checks.  */

static void
init_membuf (struct membuf *mb, int initiallen)
{
  mb->len = 0;
  mb->size = initiallen;
  mb->out_of_core = 0;
  mb->buf = xtrymalloc (initiallen);
  if (!mb->buf)
      mb->out_of_core = 1;
}

static void
put_membuf (struct membuf *mb, const void *buf, size_t len)
{
  if (mb->out_of_core)
    return;

  if (mb->len + len >= mb->size)
    {
      char *p;

      mb->size += len + 1024;
      p = xtryrealloc (mb->buf, mb->size);
      if (!p)
        {
          mb->out_of_core = 1;
          return;
        }
      mb->buf = p;
    }
  memcpy (mb->buf + mb->len, buf, len);
  mb->len += len;
}

static void *
get_membuf (struct membuf *mb, size_t *len)
{
  char *p;

  if (mb->out_of_core)
    {
      xfree (mb->buf);
      mb->buf = NULL;
      return NULL;
    }

  p = mb->buf;
  *len = mb->len;
  mb->buf = NULL;
  mb->out_of_core = 1; /* don't allow a reuse */
  return p;
}


/* Print a warning if the server's version number is less than our
   version number.  Returns an error code on a connection problem.  */
static gpg_error_t
warn_version_mismatch (ctrl_t ctrl, assuan_context_t ctx,
                       const char *servername, int mode)
{
  gpg_error_t err;
  char *serverversion;
  const char *myversion = strusage (13);

  err = get_assuan_server_version (ctx, mode, &serverversion);
  if (err)
    log_error (_("error getting version from '%s': %s\n"),
               servername, gpg_strerror (err));
  else if (compare_version_strings (serverversion, myversion) < 0)
    {
      char *warn;

      warn = xtryasprintf (_("server '%s' is older than us (%s < %s)"),
                           servername, serverversion, myversion);
      if (!warn)
        err = gpg_error_from_syserror ();
      else
        {
          log_info (_("WARNING: %s\n"), warn);
          if (!opt.quiet)
            {
              log_info (_("Note: Outdated servers may lack important"
                          " security fixes.\n"));
              log_info (_("Note: Use the command \"%s\" to restart them.\n"),
                        "gpgconf --kill all");
            }
          gpgsm_status2 (ctrl, STATUS_WARNING, "server_version_mismatch 0",
                         warn, NULL);
          xfree (warn);
        }
    }
  xfree (serverversion);
  return err;
}


/* This function prepares the dirmngr for a new session.  The
   audit-events option is used so that other dirmngr clients won't get
   disturbed by such events.  */
static void
prepare_dirmngr (ctrl_t ctrl, assuan_context_t ctx, gpg_error_t err)
{
  strlist_t server;

  if (!err)
    err = warn_version_mismatch (ctrl, ctx, DIRMNGR_NAME, 0);

  if (!err)
    {
      err = assuan_transact (ctx, "OPTION audit-events=1",
			     NULL, NULL, NULL, NULL, NULL, NULL);
      if (gpg_err_code (err) == GPG_ERR_UNKNOWN_OPTION)
	err = 0;  /* Allow the use of old dirmngr versions.  */
    }
  audit_log_ok (ctrl->audit, AUDIT_DIRMNGR_READY, err);

  if (!ctx || err)
    return;

  server = opt.keyserver;
  while (server)
    {
      char line[ASSUAN_LINELENGTH];

      /* If the host is "ldap" we prefix the entire line with "ldap:"
       * to avoid an ambiguity on the server due to the introduction
       * of this optional prefix.  */
      snprintf (line, DIM (line), "LDAPSERVER %s%s",
                !strncmp (server->d, "ldap:", 5)? "ldap:":"",
                server->d);

      assuan_transact (ctx, line, NULL, NULL, NULL, NULL, NULL, NULL);
      /* The code below is not required because we don't return an error.  */
      /* err = [above call]  */
      /* if (gpg_err_code (err) == GPG_ERR_ASS_UNKNOWN_CMD) */
      /*   err = 0;  /\* Allow the use of old dirmngr versions.  *\/ */

      server = server->next;
    }
}



/* Return a new assuan context for a Dirmngr connection.  */
static gpg_error_t
start_dirmngr_ext (ctrl_t ctrl, assuan_context_t *ctx_r)
{
  gpg_error_t err;
  assuan_context_t ctx;

  if (opt.disable_dirmngr || ctrl->offline)
    return gpg_error (GPG_ERR_NO_DIRMNGR);

  if (*ctx_r)
    return 0;

  /* Note: if you change this to multiple connections, you also need
     to take care of the implicit option sending caching. */

  err = start_new_dirmngr (&ctx, GPG_ERR_SOURCE_DEFAULT,
                           opt.dirmngr_program,
                           opt.autostart, opt.verbose, DBG_IPC,
                           gpgsm_status2, ctrl);
  if (!opt.autostart && gpg_err_code (err) == GPG_ERR_NO_DIRMNGR)
    {
      static int shown;

      if (!shown)
        {
          shown = 1;
          log_info (_("no dirmngr running in this session\n"));
        }
    }
  prepare_dirmngr (ctrl, ctx, err);
  if (err)
    return err;

  *ctx_r = ctx;
  return 0;
}


static int
start_dirmngr (ctrl_t ctrl)
{
  gpg_error_t err;

  assert (! dirmngr_ctx_locked);
  dirmngr_ctx_locked = 1;

  err = start_dirmngr_ext (ctrl, &dirmngr_ctx);
  /* We do not check ERR but the existence of a context because the
     error might come from a failed command send to the dirmngr.
     Fixme: Why don't we close the drimngr context if we encountered
     an error in prepare_dirmngr?  */
  if (!dirmngr_ctx)
    dirmngr_ctx_locked = 0;
  return err;
}


static void
release_dirmngr (ctrl_t ctrl)
{
  (void)ctrl;

  if (!dirmngr_ctx_locked)
    log_error ("WARNING: trying to release a non-locked dirmngr ctx\n");
  dirmngr_ctx_locked = 0;
}


static int
start_dirmngr2 (ctrl_t ctrl)
{
  gpg_error_t err;

  assert (! dirmngr2_ctx_locked);
  dirmngr2_ctx_locked = 1;

  err = start_dirmngr_ext (ctrl, &dirmngr2_ctx);
  if (!dirmngr2_ctx)
    dirmngr2_ctx_locked = 0;
  return err;
}


static void
release_dirmngr2 (ctrl_t ctrl)
{
  (void)ctrl;

  if (!dirmngr2_ctx_locked)
    log_error ("WARNING: trying to release a non-locked dirmngr2 ctx\n");
  dirmngr2_ctx_locked = 0;
}



/* Handle a SENDCERT inquiry. */
static gpg_error_t
inq_certificate (void *opaque, const char *line)
{
  struct inq_certificate_parm_s *parm = opaque;
  const char *s;
  int rc;
  size_t n;
  const unsigned char *der;
  size_t derlen;
  int issuer_mode = 0;
  ksba_sexp_t ski = NULL;

  if ((s = has_leading_keyword (line, "SENDCERT")))
    {
      line = s;
    }
  else if ((s = has_leading_keyword (line, "SENDCERT_SKI")))
    {
      /* Send a certificate where a sourceKeyIdentifier is included. */
      line = s;
      ski = make_simple_sexp_from_hexstr (line, &n);
      line += n;
      while (*line == ' ')
        line++;
    }
  else if ((s = has_leading_keyword (line, "SENDISSUERCERT")))
    {
      line = s;
      issuer_mode = 1;
    }
  else if ((s = has_leading_keyword (line, "ISTRUSTED")))
    {
      /* The server is asking us whether the certificate is a trusted
         root certificate.  */
      char fpr[41];
      struct rootca_flags_s rootca_flags;

      line = s;

      for (s=line,n=0; hexdigitp (s); s++, n++)
        ;
      if (*s || n != 40)
        return gpg_error (GPG_ERR_ASS_PARAMETER);
      for (s=line, n=0; n < 40; s++, n++)
        fpr[n] = (*s >= 'a')? (*s & 0xdf): *s;
      fpr[n] = 0;

      if (!gpgsm_agent_istrusted (parm->ctrl, NULL, fpr, &rootca_flags))
        rc = assuan_send_data (parm->ctx, "1", 1);
      else
        rc = 0;
      return rc;
    }
  else
    {
      log_error ("unsupported certificate inquiry '%s'\n", line);
      return gpg_error (GPG_ERR_ASS_UNKNOWN_INQUIRE);
    }

  if (!*line)
    { /* Send the current certificate. */
      der = ksba_cert_get_image (issuer_mode? parm->issuer_cert : parm->cert,
                                 &derlen);
      if (!der)
        rc = gpg_error (GPG_ERR_INV_CERT_OBJ);
      else
        rc = assuan_send_data (parm->ctx, der, derlen);
    }
  else if (issuer_mode)
    {
      log_error ("sending specific issuer certificate back "
                 "is not yet implemented\n");
      rc = gpg_error (GPG_ERR_ASS_UNKNOWN_INQUIRE);
    }
  else
    { /* Send the given certificate. */
      int err;
      ksba_cert_t cert;

      err = gpgsm_find_cert (parm->ctrl, line, ski, &cert,
                             FIND_CERT_ALLOW_AMBIG|FIND_CERT_WITH_EPHEM);
      if (err)
        {
          log_error ("certificate not found: %s\n", gpg_strerror (err));
          rc = gpg_error (GPG_ERR_NOT_FOUND);
        }
      else
        {
          der = ksba_cert_get_image (cert, &derlen);
          if (!der)
            rc = gpg_error (GPG_ERR_INV_CERT_OBJ);
          else
            rc = assuan_send_data (parm->ctx, der, derlen);
          ksba_cert_release (cert);
        }
    }

  xfree (ski);
  return rc;
}


/* Take a 20 byte hexencoded string and put it into the provided
   20 byte buffer FPR in binary format. */
static int
unhexify_fpr (const char *hexstr, unsigned char *fpr)
{
  const char *s;
  int n;

  for (s=hexstr, n=0; hexdigitp (s); s++, n++)
    ;
  if (*s || (n != 40))
    return 0; /* no fingerprint (invalid or wrong length). */
  for (s=hexstr, n=0; *s; s += 2, n++)
    fpr[n] = xtoi_2 (s);
  return 1; /* okay */
}


static gpg_error_t
isvalid_status_cb (void *opaque, const char *line)
{
  struct isvalid_status_parm_s *parm = opaque;
  const char *s;

  if ((s = has_leading_keyword (line, "PROGRESS")))
    {
      if (parm->ctrl)
        {
          line = s;
          if (gpgsm_status (parm->ctrl, STATUS_PROGRESS, line))
            return gpg_error (GPG_ERR_ASS_CANCELED);
        }
    }
  else if ((s = has_leading_keyword (line, "ONLY_VALID_IF_CERT_VALID")))
    {
      parm->seen++;
      if (!*s || !unhexify_fpr (s, parm->fpr))
        parm->seen++; /* Bumb it to indicate an error. */
    }
  return 0;
}




/* Call the directory manager to check whether the certificate is valid
   Returns 0 for valid or usually one of the errors:

  GPG_ERR_CERTIFICATE_REVOKED
  GPG_ERR_NO_CRL_KNOWN
  GPG_ERR_CRL_TOO_OLD

  Values for USE_OCSP:
     0 = Do CRL check.
     1 = Do an OCSP check but fallback to CRL unless CRLS are disabled.
     2 = Do only an OCSP check using only the default responder.
 */
int
gpgsm_dirmngr_isvalid (ctrl_t ctrl,
                       ksba_cert_t cert, ksba_cert_t issuer_cert, int use_ocsp)
{
  static int did_options;
  int rc;
  char *certid, *certfpr;
  char line[ASSUAN_LINELENGTH];
  struct inq_certificate_parm_s parm;
  struct isvalid_status_parm_s stparm;

  keydb_close_all_files ();

  rc = start_dirmngr (ctrl);
  if (rc)
    return rc;

  certfpr = gpgsm_get_fingerprint_hexstring (cert, GCRY_MD_SHA1);
  certid = gpgsm_get_certid (cert);
  if (!certid)
    {
      log_error ("error getting the certificate ID\n");
      release_dirmngr (ctrl);
      return gpg_error (GPG_ERR_GENERAL);
    }

  if (opt.verbose > 1)
    {
      char *fpr = gpgsm_get_fingerprint_string (cert, GCRY_MD_SHA1);
      log_info ("asking dirmngr about %s%s\n", fpr,
                use_ocsp? " (using OCSP)":"");
      xfree (fpr);
    }

  parm.ctx = dirmngr_ctx;
  parm.ctrl = ctrl;
  parm.cert = cert;
  parm.issuer_cert = issuer_cert;

  stparm.ctrl = ctrl;
  stparm.seen = 0;
  memset (stparm.fpr, 0, 20);

  /* It is sufficient to send the options only once because we have
   * one connection per process only.  */
  if (!did_options)
    {
      if (opt.force_crl_refresh)
        assuan_transact (dirmngr_ctx, "OPTION force-crl-refresh=1",
                         NULL, NULL, NULL, NULL, NULL, NULL);
      did_options = 1;
    }
  snprintf (line, DIM(line), "ISVALID%s%s %s%s%s",
            use_ocsp == 2 || opt.no_crl_check ? " --only-ocsp":"",
            use_ocsp == 2? " --force-default-responder":"",
            certid,
            use_ocsp? " ":"",
            use_ocsp? certfpr:"");
  xfree (certid);
  xfree (certfpr);

  rc = assuan_transact (dirmngr_ctx, line, NULL, NULL,
                        inq_certificate, &parm,
                        isvalid_status_cb, &stparm);
  if (opt.verbose > 1)
    log_info ("response of dirmngr: %s\n", rc? gpg_strerror (rc): "okay");

  if (!rc && stparm.seen)
    {
      /* Need to also check the certificate validity. */
      if (stparm.seen != 1)
        {
          log_error ("communication problem with dirmngr detected\n");
          rc = gpg_error (GPG_ERR_INV_CRL);
        }
      else
        {
          ksba_cert_t rspcert = NULL;

          if (get_cached_cert (dirmngr_ctx, stparm.fpr, &rspcert))
            {
              /* Ooops: Something went wrong getting the certificate
                 from the dirmngr.  Try our own cert store now.  */
              KEYDB_HANDLE kh;

              kh = keydb_new ();
              if (!kh)
                rc = gpg_error (GPG_ERR_ENOMEM);
              if (!rc)
                rc = keydb_search_fpr (ctrl, kh, stparm.fpr);
              if (!rc)
                rc = keydb_get_cert (kh, &rspcert);
              if (rc)
                {
                  log_error ("unable to find the certificate used "
                             "by the dirmngr: %s\n", gpg_strerror (rc));
                  rc = gpg_error (GPG_ERR_INV_CRL);
                }
              keydb_release (kh);
            }

          if (!rc)
            {
              rc = gpgsm_cert_use_ocsp_p (rspcert);
              if (rc)
                rc = gpg_error (GPG_ERR_INV_CRL);
              else
                {
                  /* Note the no_dirmngr flag: This avoids checking
                     this certificate over and over again. */
                  rc = gpgsm_validate_chain (ctrl, rspcert, GNUPG_ISOTIME_NONE,
                                             NULL, 0, NULL,
                                             VALIDATE_FLAG_NO_DIRMNGR, NULL);
                  if (rc)
                    {
                      log_error ("invalid certificate used for CRL/OCSP: %s\n",
                                 gpg_strerror (rc));
                      rc = gpg_error (GPG_ERR_INV_CRL);
                    }
                }
            }
          ksba_cert_release (rspcert);
        }
    }
  release_dirmngr (ctrl);
  return rc;
}



/* Lookup helpers*/
static gpg_error_t
lookup_cb (void *opaque, const void *buffer, size_t length)
{
  struct lookup_parm_s *parm = opaque;
  size_t len;
  char *buf;
  ksba_cert_t cert;
  int rc;

  if (parm->error)
    return 0;

  if (buffer)
    {
      put_membuf (&parm->data, buffer, length);
      return 0;
    }
  /* END encountered - process what we have */
  buf = get_membuf (&parm->data, &len);
  if (!buf)
    {
      parm->error = gpg_error (GPG_ERR_ENOMEM);
      return 0;
    }

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
    }
  else
    {
      parm->cb (parm->cb_value, cert);
    }

  ksba_cert_release (cert);
  init_membuf (&parm->data, 4096);
  return 0;
}

/* Return a properly escaped pattern from NAMES.  The only error
   return is NULL to indicate a malloc failure. */
static char *
pattern_from_strlist (strlist_t names)
{
  strlist_t sl;
  int n;
  const char *s;
  char *pattern, *p;

  for (n=0, sl=names; sl; sl = sl->next)
    {
      for (s=sl->d; *s; s++, n++)
	{
          if (*s == '%' || *s == ' ' || *s == '+')
            n += 2;
	}
      n++;
    }

  p = pattern = xtrymalloc (n+1);
  if (!pattern)
    return NULL;

  for (sl=names; sl; sl = sl->next)
    {
      for (s=sl->d; *s; s++)
        {
          switch (*s)
            {
            case '%':
              *p++ = '%';
              *p++ = '2';
              *p++ = '5';
              break;
            case ' ':
              *p++ = '%';
              *p++ = '2';
              *p++ = '0';
              break;
            case '+':
              *p++ = '%';
              *p++ = '2';
              *p++ = 'B';
              break;
            default:
              *p++ = *s;
              break;
            }
        }
      *p++ = ' ';
    }
  if (p == pattern)
    *pattern = 0; /* is empty */
  else
    p[-1] = '\0'; /* remove trailing blank */

  return pattern;
}

static gpg_error_t
lookup_status_cb (void *opaque, const char *line)
{
  struct lookup_parm_s *parm = opaque;
  const char *s;

  if ((s = has_leading_keyword (line, "PROGRESS")))
    {
      if (parm->ctrl)
        {
          line = s;
          if (gpgsm_status (parm->ctrl, STATUS_PROGRESS, line))
            return gpg_error (GPG_ERR_ASS_CANCELED);
        }
    }
  else if ((s = has_leading_keyword (line, "TRUNCATED")))
    {
      if (parm->ctrl)
        {
          line = s;
          gpgsm_status (parm->ctrl, STATUS_TRUNCATED, line);
        }
    }
  return 0;
}


/* Run the Directory Manager's lookup command using the pattern
   compiled from the strings given in NAMES or from URI.  The caller
   must provide the callback CB which will be passed cert by cert.
   Note that CTRL is optional.  With CACHE_ONLY the dirmngr will
   search only its own key cache. */
int
gpgsm_dirmngr_lookup (ctrl_t ctrl, strlist_t names, const char *uri,
                      int cache_only,
                      void (*cb)(void*, ksba_cert_t), void *cb_value)
{
  int rc;
  char line[ASSUAN_LINELENGTH];
  struct lookup_parm_s parm;
  size_t len;
  assuan_context_t ctx;
  const char *s;

  if ((names && uri) || (!names && !uri))
    return gpg_error (GPG_ERR_INV_ARG);

  keydb_close_all_files ();

  /* The lookup function can be invoked from the callback of a lookup
     function, for example to walk the chain.  */
  if (!dirmngr_ctx_locked)
    {
      rc = start_dirmngr (ctrl);
      if (rc)
	return rc;
      ctx = dirmngr_ctx;
    }
  else if (!dirmngr2_ctx_locked)
    {
      rc = start_dirmngr2 (ctrl);
      if (rc)
	return rc;
      ctx = dirmngr2_ctx;
    }
  else
    {
      log_fatal ("both dirmngr contexts are in use\n");
    }

  if (names)
    {
      char *pattern = pattern_from_strlist (names);
      if (!pattern)
        {
          if (ctx == dirmngr_ctx)
            release_dirmngr (ctrl);
          else
            release_dirmngr2 (ctrl);

          return out_of_core ();
        }
      snprintf (line, DIM(line), "LOOKUP%s %s",
                cache_only? " --cache-only":"", pattern);
      xfree (pattern);
    }
  else
    {
      for (s=uri; *s; s++)
        if (*s <= ' ')
          {
            if (ctx == dirmngr_ctx)
              release_dirmngr (ctrl);
            else
              release_dirmngr2 (ctrl);
            return gpg_error (GPG_ERR_INV_URI);
          }
      snprintf (line, DIM(line), "LOOKUP --url %s", uri);
    }

  parm.ctrl = ctrl;
  parm.ctx = ctx;
  parm.cb = cb;
  parm.cb_value = cb_value;
  parm.error = 0;
  init_membuf (&parm.data, 4096);

  rc = assuan_transact (ctx, line, lookup_cb, &parm,
                        NULL, NULL, lookup_status_cb, &parm);
  xfree (get_membuf (&parm.data, &len));

  if (ctx == dirmngr_ctx)
    release_dirmngr (ctrl);
  else
    release_dirmngr2 (ctrl);

  if (rc)
      return rc;
  return parm.error;
}



static gpg_error_t
get_cached_cert_data_cb (void *opaque, const void *buffer, size_t length)
{
  struct membuf *mb = opaque;

  if (buffer)
    put_membuf (mb, buffer, length);
  return 0;
}

/* Return a certificate from the Directory Manager's cache.  This
   function only returns one certificate which must be specified using
   the fingerprint FPR and will be stored at R_CERT.  On error NULL is
   stored at R_CERT and an error code returned.  Note that the caller
   must provide the locked dirmngr context CTX. */
static gpg_error_t
get_cached_cert (assuan_context_t ctx,
                 const unsigned char *fpr, ksba_cert_t *r_cert)
{
  gpg_error_t err;
  char line[ASSUAN_LINELENGTH];
  char hexfpr[2*20+1];
  struct membuf mb;
  char *buf;
  size_t buflen = 0;
  ksba_cert_t cert;

  *r_cert = NULL;

  bin2hex (fpr, 20, hexfpr);
  snprintf (line, DIM(line), "LOOKUP --single --cache-only 0x%s", hexfpr);

  init_membuf (&mb, 4096);
  err = assuan_transact (ctx, line, get_cached_cert_data_cb, &mb,
                         NULL, NULL, NULL, NULL);
  buf = get_membuf (&mb, &buflen);
  if (err)
    {
      xfree (buf);
      return err;
    }
  if (!buf)
    return gpg_error (GPG_ERR_ENOMEM);

  err = ksba_cert_new (&cert);
  if (err)
    {
      xfree (buf);
      return err;
    }
  err = ksba_cert_init_from_mem (cert, buf, buflen);
  xfree (buf);
  if (err)
    {
      log_error ("failed to parse a certificate: %s\n", gpg_strerror (err));
      ksba_cert_release (cert);
      return err;
    }

  *r_cert = cert;
  return 0;
}



/* Run Command helpers*/

/* Fairly simple callback to write all output of dirmngr to stdout. */
static gpg_error_t
run_command_cb (void *opaque, const void *buffer, size_t length)
{
  (void)opaque;

  if (buffer)
    {
      if ( fwrite (buffer, length, 1, stdout) != 1 )
        log_error ("error writing to stdout: %s\n", strerror (errno));
    }
  return 0;
}

/* Handle inquiries from the dirmngr COMMAND. */
static gpg_error_t
run_command_inq_cb (void *opaque, const char *line)
{
  struct run_command_parm_s *parm = opaque;
  gpg_error_t err;
  const char *s;
  int rc = 0;
  ksba_cert_t cert = NULL;
  ksba_sexp_t ski = NULL;
  const unsigned char *der;
  size_t derlen, n;

  if ((s = has_leading_keyword (line, "SENDCERT")))
    {
      /* Send the given certificate.  */
      line = s;
      if (!*line)
        return gpg_error (GPG_ERR_ASS_PARAMETER);

      err = gpgsm_find_cert (parm->ctrl, line, NULL, &cert,
                             FIND_CERT_ALLOW_AMBIG);
      if (err)
        {
          log_error ("certificate not found: %s\n", gpg_strerror (err));
          rc = gpg_error (GPG_ERR_NOT_FOUND);
        }
      else
        {
          der = ksba_cert_get_image (cert, &derlen);
          if (!der)
            rc = gpg_error (GPG_ERR_INV_CERT_OBJ);
          else
            rc = assuan_send_data (parm->ctx, der, derlen);
        }
    }
  else if ((s = has_leading_keyword (line, "SENDCERT_SKI")))
    {
      /* Send a certificate where a sourceKeyIdentifier is included. */
      line = s;
      ski = make_simple_sexp_from_hexstr (line, &n);
      line += n;
      while (*line == ' ')
        line++;

      err = gpgsm_find_cert (parm->ctrl, line, ski, &cert,
                             FIND_CERT_ALLOW_AMBIG|FIND_CERT_WITH_EPHEM);
      if (err)
        {
          log_error ("certificate not found: %s\n", gpg_strerror (err));
          rc = gpg_error (GPG_ERR_NOT_FOUND);
        }
      else
        {
          der = ksba_cert_get_image (cert, &derlen);
          if (!der)
            rc = gpg_error (GPG_ERR_INV_CERT_OBJ);
          else
            rc = assuan_send_data (parm->ctx, der, derlen);
        }
    }
  else if ((s = has_leading_keyword (line, "PRINTINFO")))
    {
      /* Simply show the message given in the argument. */
      line = s;
      log_info ("dirmngr: %s\n", line);
    }
  else if ((s = has_leading_keyword (line, "ISTRUSTED")))
    {
      /* The server is asking us whether the certificate is a trusted
         root certificate.  */
      char fpr[41];
      struct rootca_flags_s rootca_flags;

      line = s;

      for (s=line,n=0; hexdigitp (s); s++, n++)
        ;
      if (*s || n != 40)
        return gpg_error (GPG_ERR_ASS_PARAMETER);
      for (s=line, n=0; n < 40; s++, n++)
        fpr[n] = (*s >= 'a')? (*s & 0xdf): *s;
      fpr[n] = 0;

      if (!gpgsm_agent_istrusted (parm->ctrl, NULL, fpr, &rootca_flags))
        rc = assuan_send_data (parm->ctx, "1", 1);
      else
        rc = 0;
      return rc;
    }
  else
    {
      log_error ("unsupported command inquiry '%s'\n", line);
      rc = gpg_error (GPG_ERR_ASS_UNKNOWN_INQUIRE);
    }

  ksba_cert_release (cert);
  xfree (ski);
  return rc;
}

static gpg_error_t
run_command_status_cb (void *opaque, const char *line)
{
  ctrl_t ctrl = opaque;
  const char *s;

  if (opt.verbose)
    {
      log_info ("dirmngr status: %s\n", line);
    }
  if ((s = has_leading_keyword (line, "PROGRESS")))
    {
      if (ctrl)
        {
          line = s;
          if (gpgsm_status (ctrl, STATUS_PROGRESS, line))
            return gpg_error (GPG_ERR_ASS_CANCELED);
        }
    }
  return 0;
}



/* Pass COMMAND to dirmngr and print all output generated by Dirmngr
   to stdout.  A couple of inquiries are defined (see above).  ARGC
   arguments in ARGV are given to the Dirmngr.  Spaces, plus and
   percent characters within the argument strings are percent escaped
   so that blanks can act as delimiters. */
int
gpgsm_dirmngr_run_command (ctrl_t ctrl, const char *command,
                           int argc, char **argv)
{
  int rc;
  int i;
  const char *s;
  char *line, *p;
  size_t len;
  struct run_command_parm_s parm;

  keydb_close_all_files ();

  rc = start_dirmngr (ctrl);
  if (rc)
    return rc;

  parm.ctrl = ctrl;
  parm.ctx = dirmngr_ctx;

  len = strlen (command) + 1;
  for (i=0; i < argc; i++)
    len += 1 + 3*strlen (argv[i]); /* enough space for percent escaping */
  line = xtrymalloc (len);
  if (!line)
    {
      release_dirmngr (ctrl);
      return out_of_core ();
    }

  p = stpcpy (line, command);
  for (i=0; i < argc; i++)
    {
      *p++ = ' ';
      for (s=argv[i]; *s; s++)
        {
          if (!isascii (*s))
            *p++ = *s;
          else if (*s == ' ')
            *p++ = '+';
          else if (!isprint (*s) || *s == '+')
            {
              sprintf (p, "%%%02X", *(const unsigned char *)s);
              p += 3;
            }
          else
            *p++ = *s;
        }
    }
  *p = 0;

  rc = assuan_transact (dirmngr_ctx, line,
                        run_command_cb, NULL,
                        run_command_inq_cb, &parm,
                        run_command_status_cb, ctrl);
  xfree (line);
  log_info ("response of dirmngr: %s\n", rc? gpg_strerror (rc): "okay");
  release_dirmngr (ctrl);
  return rc;
}
