/* call-dirmngr.c - communication with the dromngr
 * Copyright (C) 2002, 2003, 2005, 2007, 2008 Free Software Foundation, Inc.
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
#include <unistd.h>
#include <time.h>
#include <assert.h>
#include <ctype.h>

#include "gpgsm.h"
#include <gcrypt.h>
#include <assuan.h>

#include "i18n.h"
#include "keydb.h"


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

static int force_pipe_server = 0;

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


/* This function prepares the dirmngr for a new session.  The
   audit-events option is used so that other dirmngr clients won't get
   disturbed by such events.  */
static void
prepare_dirmngr (ctrl_t ctrl, assuan_context_t ctx, gpg_error_t err)
{
  struct keyserver_spec *server;

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
      char *user = server->user ? server->user : "";
      char *pass = server->pass ? server->pass : "";
      char *base = server->base ? server->base : "";

      snprintf (line, DIM (line) - 1, "LDAPSERVER %s:%i:%s:%s:%s",
		server->host, server->port, user, pass, base);
      line[DIM (line) - 1] = 0;

      err = assuan_transact (ctx, line, NULL, NULL, NULL, NULL, NULL, NULL);
      if (gpg_err_code (err) == GPG_ERR_ASS_UNKNOWN_CMD)
	err = 0;  /* Allow the use of old dirmngr versions.  */

      server = server->next;
    }
}



/* Try to connect to the agent via socket or fork it off and work by
   pipes.  Handle the server's initial greeting */
static int
start_dirmngr_ext (ctrl_t ctrl, assuan_context_t *ctx_r)
{
  int rc;
  char *infostr, *p;
  assuan_context_t ctx = NULL;
  int try_default = 0;

  if (opt.disable_dirmngr)
    return gpg_error (GPG_ERR_NO_DIRMNGR);

  if (*ctx_r)
    return 0;

  /* Note: if you change this to multiple connections, you also need
     to take care of the implicit option sending caching. */

#ifdef HAVE_W32_SYSTEM
  infostr = NULL;
  opt.prefer_system_dirmngr = 1;
#else
  infostr = force_pipe_server? NULL : getenv ("DIRMNGR_INFO");
#endif /*HAVE_W32_SYSTEM*/
  if (infostr && !*infostr)
    infostr = NULL;
  else if (infostr)
    infostr = xstrdup (infostr);

  if (opt.prefer_system_dirmngr && !force_pipe_server && !infostr)
    {
      infostr = xstrdup (dirmngr_socket_name ());
      try_default = 1;
    }

  rc = assuan_new (&ctx);
  if (rc)
    {
      log_error ("can't allocate assuan context: %s\n", gpg_strerror (rc));
      return rc;
    }

  if (!infostr)
    {
      const char *pgmname;
      const char *argv[3];
      int no_close_list[3];
      int i;

      if (!opt.dirmngr_program || !*opt.dirmngr_program)
        opt.dirmngr_program = gnupg_module_name (GNUPG_MODULE_NAME_DIRMNGR);
      if ( !(pgmname = strrchr (opt.dirmngr_program, '/')))
        pgmname = opt.dirmngr_program;
      else
        pgmname++;

      if (opt.verbose)
        log_info (_("no running dirmngr - starting `%s'\n"),
                  opt.dirmngr_program);

      if (fflush (NULL))
        {
          gpg_error_t tmperr = gpg_error (gpg_err_code_from_errno (errno));
          log_error ("error flushing pending output: %s\n", strerror (errno));
          return tmperr;
        }

      argv[0] = pgmname;
      argv[1] = "--server";
      argv[2] = NULL;

      i=0;
      if (log_get_fd () != -1)
        no_close_list[i++] = assuan_fd_from_posix_fd (log_get_fd ());
      no_close_list[i++] = assuan_fd_from_posix_fd (fileno (stderr));
      no_close_list[i] = -1;

      /* connect to the agent and perform initial handshaking */
      rc = assuan_pipe_connect (ctx, opt.dirmngr_program, argv,
                                no_close_list, NULL, NULL, 0);
    }
  else
    {
      int prot;
      int pid;

      if (!try_default)
        {
          if ( !(p = strchr (infostr, PATHSEP_C)) || p == infostr)
            {
              log_error (_("malformed DIRMNGR_INFO environment variable\n"));
              xfree (infostr);
              force_pipe_server = 1;
              return start_dirmngr_ext (ctrl, ctx_r);
            }
          *p++ = 0;
          pid = atoi (p);
          while (*p && *p != PATHSEP_C)
            p++;
          prot = *p? atoi (p+1) : 0;
          if (prot != 1)
            {
              log_error (_("dirmngr protocol version %d is not supported\n"),
                         prot);
              xfree (infostr);
              force_pipe_server = 1;
              return start_dirmngr_ext (ctrl, ctx_r);
            }
        }
      else
        pid = -1;

      rc = assuan_socket_connect (ctx, infostr, pid, 0);
#ifdef HAVE_W32_SYSTEM
      if (rc)
        log_debug ("connecting dirmngr at `%s' failed\n", infostr);
#endif

      xfree (infostr);
#ifndef HAVE_W32_SYSTEM
      if (gpg_err_code (rc) == GPG_ERR_ASS_CONNECT_FAILED)
        {
          log_info (_("can't connect to the dirmngr - trying fall back\n"));
          force_pipe_server = 1;
          return start_dirmngr_ext (ctrl, ctx_r);
        }
#endif /*!HAVE_W32_SYSTEM*/
    }

  prepare_dirmngr (ctrl, ctx, rc);

  if (rc)
    {
      assuan_release (ctx);
      log_error ("can't connect to the dirmngr: %s\n", gpg_strerror (rc));
      return gpg_error (GPG_ERR_NO_DIRMNGR);
    }
  *ctx_r = ctx;

  if (DBG_ASSUAN)
    log_debug ("connection to dirmngr established\n");
  return 0;
}


static int
start_dirmngr (ctrl_t ctrl)
{
  gpg_error_t err;

  assert (! dirmngr_ctx_locked);
  dirmngr_ctx_locked = 1;

  err = start_dirmngr_ext (ctrl, &dirmngr_ctx);
  /* We do not check ERR but the existance of a context because the
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
  int rc;
  const unsigned char *der;
  size_t derlen;
  int issuer_mode = 0;
  ksba_sexp_t ski = NULL;

  if (!strncmp (line, "SENDCERT", 8) && (line[8] == ' ' || !line[8]))
    {
      line += 8;
    }
  else if (!strncmp (line, "SENDCERT_SKI", 12) && (line[12]==' ' || !line[12]))
    {
      size_t n;

      /* Send a certificate where a sourceKeyIdentifier is included. */
      line += 12;
      while (*line == ' ')
        line++;
      ski = make_simple_sexp_from_hexstr (line, &n);
      line += n;
      while (*line == ' ')
        line++;
    }
  else if (!strncmp (line, "SENDISSUERCERT", 14)
           && (line[14] == ' ' || !line[14]))
    {
      line += 14;
      issuer_mode = 1;
    }
  else if (!strncmp (line, "ISTRUSTED", 9) && (line[9]==' ' || !line[9]))
    {
      /* The server is asking us whether the certificate is a trusted
         root certificate.  */
      const char *s;
      size_t n;
      char fpr[41];
      struct rootca_flags_s rootca_flags;

      line += 9;
      while (*line == ' ')
        line++;

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
      log_error ("unsupported inquiry `%s'\n", line);
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


      err = gpgsm_find_cert (line, ski, &cert);
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


/* Take a 20 byte hexencoded string and put it into the the provided
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
  n /= 2;
  for (s=hexstr, n=0; *s; s += 2, n++)
    fpr[n] = xtoi_2 (s);
  return 1; /* okay */
}


static gpg_error_t
isvalid_status_cb (void *opaque, const char *line)
{
  struct isvalid_status_parm_s *parm = opaque;

  if (!strncmp (line, "PROGRESS", 8) && (line[8]==' ' || !line[8]))
    {
      if (parm->ctrl)
        {
          for (line += 8; *line == ' '; line++)
            ;
          if (gpgsm_status (parm->ctrl, STATUS_PROGRESS, line))
            return gpg_error (GPG_ERR_ASS_CANCELED);
        }
    }
  else if (!strncmp (line, "ONLY_VALID_IF_CERT_VALID", 24)
      && (line[24]==' ' || !line[24]))
    {
      parm->seen++;
      if (!line[24] || !unhexify_fpr (line+25, parm->fpr))
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
     1 = Do an OCSP check.
     2 = Do an OCSP check using only the default responder.
 */
int
gpgsm_dirmngr_isvalid (ctrl_t ctrl,
                       ksba_cert_t cert, ksba_cert_t issuer_cert, int use_ocsp)
{
  static int did_options;
  int rc;
  char *certid;
  char line[ASSUAN_LINELENGTH];
  struct inq_certificate_parm_s parm;
  struct isvalid_status_parm_s stparm;

  rc = start_dirmngr (ctrl);
  if (rc)
    return rc;

  if (use_ocsp)
    {
      certid = gpgsm_get_fingerprint_hexstring (cert, GCRY_MD_SHA1);
    }
  else
    {
      certid = gpgsm_get_certid (cert);
      if (!certid)
        {
          log_error ("error getting the certificate ID\n");
	  release_dirmngr (ctrl);
          return gpg_error (GPG_ERR_GENERAL);
        }
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

  /* FIXME: If --disable-crl-checks has been set, we should pass an
     option to dirmngr, so that no fallback CRL check is done after an
     ocsp check.  It is not a problem right now as dirmngr does not
     fallback to CRL checking.  */

  /* It is sufficient to send the options only once because we have
     one connection per process only. */
  if (!did_options)
    {
      if (opt.force_crl_refresh)
        assuan_transact (dirmngr_ctx, "OPTION force-crl-refresh=1",
                         NULL, NULL, NULL, NULL, NULL, NULL);
      did_options = 1;
    }
  snprintf (line, DIM(line)-1, "ISVALID%s %s",
            use_ocsp == 2? " --only-ocsp --force-default-responder":"",
            certid);
  line[DIM(line)-1] = 0;
  xfree (certid);

  rc = assuan_transact (dirmngr_ctx, line, NULL, NULL,
                        inq_certificate, &parm,
                        isvalid_status_cb, &stparm);
  if (opt.verbose > 1)
    log_info ("response of dirmngr: %s\n", rc? gpg_strerror (rc): "okay");
  rc = rc;

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

              kh = keydb_new (0);
              if (!kh)
                rc = gpg_error (GPG_ERR_ENOMEM);
              if (!rc)
                rc = keydb_search_fpr (kh, stparm.fpr);
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
                  rc = gpgsm_validate_chain (ctrl, rspcert, "", NULL, 0, NULL,
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

  if (!strncmp (line, "PROGRESS", 8) && (line[8]==' ' || !line[8]))
    {
      if (parm->ctrl)
        {
          for (line += 8; *line == ' '; line++)
            ;
          if (gpgsm_status (parm->ctrl, STATUS_PROGRESS, line))
            return gpg_error (GPG_ERR_ASS_CANCELED);
        }
    }
  else if (!strncmp (line, "TRUNCATED", 9) && (line[9]==' ' || !line[9]))
    {
      if (parm->ctrl)
        {
          for (line +=9; *line == ' '; line++)
            ;
          gpgsm_status (parm->ctrl, STATUS_TRUNCATED, line);
        }
    }
  return 0;
}


/* Run the Directory Manager's lookup command using the pattern
   compiled from the strings given in NAMES.  The caller must provide
   the callback CB which will be passed cert by cert.  Note that CTRL
   is optional.  With CACHE_ONLY the dirmngr will search only its own
   key cache. */
int
gpgsm_dirmngr_lookup (ctrl_t ctrl, strlist_t names, int cache_only,
                      void (*cb)(void*, ksba_cert_t), void *cb_value)
{
  int rc;
  char *pattern;
  char line[ASSUAN_LINELENGTH];
  struct lookup_parm_s parm;
  size_t len;
  assuan_context_t ctx;

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

  pattern = pattern_from_strlist (names);
  if (!pattern)
    {
      if (ctx == dirmngr_ctx)
	release_dirmngr (ctrl);
      else
	release_dirmngr2 (ctrl);

      return out_of_core ();
    }
  snprintf (line, DIM(line)-1, "LOOKUP%s %s",
            cache_only? " --cache-only":"", pattern);
  line[DIM(line)-1] = 0;
  xfree (pattern);

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
  size_t buflen;
  ksba_cert_t cert;

  *r_cert = NULL;

  bin2hex (fpr, 20, hexfpr);
  snprintf (line, DIM(line)-1, "LOOKUP --single --cache-only 0x%s", hexfpr);

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
  int rc = 0;

  if ( !strncmp (line, "SENDCERT", 8) && (line[8] == ' ' || !line[8]) )
    { /* send the given certificate */
      int err;
      ksba_cert_t cert;
      const unsigned char *der;
      size_t derlen;

      line += 8;
      if (!*line)
        return gpg_error (GPG_ERR_ASS_PARAMETER);

      err = gpgsm_find_cert (line, NULL, &cert);
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
  else if ( !strncmp (line, "PRINTINFO", 9) && (line[9] == ' ' || !line[9]) )
    { /* Simply show the message given in the argument. */
      line += 9;
      log_info ("dirmngr: %s\n", line);
    }
  else
    {
      log_error ("unsupported inquiry `%s'\n", line);
      rc = gpg_error (GPG_ERR_ASS_UNKNOWN_INQUIRE);
    }

  return rc;
}

static gpg_error_t
run_command_status_cb (void *opaque, const char *line)
{
  ctrl_t ctrl = opaque;

  if (opt.verbose)
    {
      log_info ("dirmngr status: %s\n", line);
    }
  if (!strncmp (line, "PROGRESS", 8) && (line[8]==' ' || !line[8]))
    {
      if (ctrl)
        {
          for (line += 8; *line == ' '; line++)
            ;
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

  rc = start_dirmngr (ctrl);
  if (rc)
    return rc;

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
