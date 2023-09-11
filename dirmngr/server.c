/* server.c - LDAP and Keyserver access server
 * Copyright (C) 2002 Klarälvdalens Datakonsult AB
 * Copyright (C) 2003, 2004, 2005, 2007, 2008, 2009, 2011, 2015 g10 Code GmbH
 * Copyright (C) 2014, 2015, 2016 Werner Koch
 * Copyright (C) 2016 Bundesamt für Sicherheit in der Informationstechnik
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
 *
 * SPDX-License-Identifier: GPL-3.0+
 */

#include <config.h>
#include <stdio.h>
#include <stdlib.h>
#include <stddef.h>
#include <string.h>
#include <assert.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <errno.h>
#ifdef HAVE_W32_SYSTEM
# ifndef WINVER
#  define WINVER 0x0500  /* Same as in common/sysutils.c */
# endif
# include <winsock2.h>
# include <sddl.h>
#endif

#include "dirmngr.h"
#include <assuan.h>

#include "crlcache.h"
#include "crlfetch.h"
#if USE_LDAP
# include "ldapserver.h"
#endif
#include "ocsp.h"
#include "certcache.h"
#include "validate.h"
#include "misc.h"
#if USE_LDAP
# include "ldap-wrapper.h"
#endif
#include "ks-action.h"
#include "ks-engine.h"
#if USE_LDAP
# include "ldap-parse-uri.h"
#endif
#include "dns-stuff.h"
#include "../common/mbox-util.h"
#include "../common/zb32.h"
#include "../common/server-help.h"

/* To avoid DoS attacks we limit the size of a certificate to
   something reasonable.  The DoS was actually only an issue back when
   Dirmngr was a system service and not a user service. */
#define MAX_CERT_LENGTH (16*1024)

/* The limit for the CERTLIST inquiry.  We allow for up to 20
 * certificates but also take PEM encoding into account.  */
#define MAX_CERTLIST_LENGTH ((MAX_CERT_LENGTH * 20 * 4)/3)

/* The same goes for OpenPGP keyblocks, but here we need to allow for
   much longer blocks; a 200k keyblock is not too unusual for keys
   with a lot of signatures (e.g. 0x5b0358a2).  9C31503C6D866396 even
   has 770 KiB as of 2015-08-23.  To avoid adding a runtime option we
   now use 20MiB which should really be enough.  Well, a key with
   several pictures could be larger (the parser as a 18MiB limit for
   attribute packets) but it won't be nice to the keyservers to send
   them such large blobs.  */
#define MAX_KEYBLOCK_LENGTH (20*1024*1024)


#define PARM_ERROR(t) assuan_set_error (ctx, \
                                        gpg_error (GPG_ERR_ASS_PARAMETER), (t))
#define set_error(e,t) (ctx ? assuan_set_error (ctx, gpg_error (e), (t)) \
                        /**/: gpg_error (e))



/* Control structure per connection. */
struct server_local_s
{
  /* Data used to associate an Assuan context with local server data */
  assuan_context_t assuan_ctx;

  /* The session id (a counter).  */
  unsigned int session_id;

  /* Per-session LDAP servers.  */
  ldap_server_t ldapservers;

  /* Per-session list of keyservers.  */
  uri_item_t keyservers;

  /* If this flag is set to true this dirmngr process will be
     terminated after the end of this session.  */
  int stopme;

  /* State variable private to is_tor_running.  */
  int tor_state;

  /* If the first both flags are set the assuan logging of data lines
   * is suppressed.  The count variable is used to show the number of
   * non-logged bytes.  */
  size_t inhibit_data_logging_count;
  unsigned int inhibit_data_logging : 1;
  unsigned int inhibit_data_logging_now : 1;
};


/* Cookie definition for assuan data line output.  */
static gpgrt_ssize_t data_line_cookie_write (void *cookie,
                                             const void *buffer, size_t size);
static int data_line_cookie_close (void *cookie);
static es_cookie_io_functions_t data_line_cookie_functions =
  {
    NULL,
    data_line_cookie_write,
    NULL,
    data_line_cookie_close
  };


/* Local prototypes */
static const char *task_check_wkd_support (ctrl_t ctrl, const char *domain);




/* Accessor for the local ldapservers variable. */
ldap_server_t
get_ldapservers_from_ctrl (ctrl_t ctrl)
{
  if (ctrl && ctrl->server_local)
    return ctrl->server_local->ldapservers;
  else
    return NULL;
}

/* Release an uri_item_t list.  */
void
release_uri_item_list (uri_item_t list)
{
  while (list)
    {
      uri_item_t tmp = list->next;
      http_release_parsed_uri (list->parsed_uri);
      xfree (list);
      list = tmp;
    }
}

/* Release all configured keyserver info from CTRL.  */
void
release_ctrl_keyservers (ctrl_t ctrl)
{
  if (! ctrl->server_local)
    return;

  release_uri_item_list (ctrl->server_local->keyservers);
  ctrl->server_local->keyservers = NULL;
}



/* Helper to print a message while leaving a command.  */
static gpg_error_t
leave_cmd (assuan_context_t ctx, gpg_error_t err)
{
  if (err)
    {
      const char *name = assuan_get_command_name (ctx);
      if (!name)
        name = "?";
      if (gpg_err_source (err) == GPG_ERR_SOURCE_DEFAULT)
        log_error ("command '%s' failed: %s\n", name,
                   gpg_strerror (err));
      else
        log_error ("command '%s' failed: %s <%s>\n", name,
                   gpg_strerror (err), gpg_strsource (err));
    }
  return err;
}


/* This is a wrapper around assuan_send_data which makes debugging the
   output in verbose mode easier.  */
static gpg_error_t
data_line_write (assuan_context_t ctx, const void *buffer_arg, size_t size)
{
  ctrl_t ctrl = assuan_get_pointer (ctx);
  const char *buffer = buffer_arg;
  gpg_error_t err;

  /* If we do not want logging, enable it here.  */
  if (ctrl && ctrl->server_local && ctrl->server_local->inhibit_data_logging)
    ctrl->server_local->inhibit_data_logging_now = 1;

  if (opt.verbose && buffer && size)
    {
      /* Ease reading of output by sending a physical line at each LF.  */
      const char *p;
      size_t n, nbytes;

      nbytes = size;
      do
        {
          p = memchr (buffer, '\n', nbytes);
          n = p ? (p - buffer) + 1 : nbytes;
          err = assuan_send_data (ctx, buffer, n);
          if (err)
            {
              gpg_err_set_errno (EIO);
              goto leave;
            }
          buffer += n;
          nbytes -= n;
          if (nbytes && (err=assuan_send_data (ctx, NULL, 0))) /* Flush line. */
            {
              gpg_err_set_errno (EIO);
              goto leave;
            }
        }
      while (nbytes);
    }
  else
    {
      err = assuan_send_data (ctx, buffer, size);
      if (err)
        {
          gpg_err_set_errno (EIO);  /* For use by data_line_cookie_write.  */
          goto leave;
        }
    }

 leave:
  if (ctrl && ctrl->server_local && ctrl->server_local->inhibit_data_logging)
    {
      ctrl->server_local->inhibit_data_logging_now = 0;
      ctrl->server_local->inhibit_data_logging_count += size;
    }

  return err;
}


/* A write handler used by es_fopencookie to write assuan data
   lines.  */
static gpgrt_ssize_t
data_line_cookie_write (void *cookie, const void *buffer, size_t size)
{
  assuan_context_t ctx = cookie;

  if (data_line_write (ctx, buffer, size))
    return -1;
  return (gpgrt_ssize_t)size;
}


static int
data_line_cookie_close (void *cookie)
{
  assuan_context_t ctx = cookie;

  if (DBG_IPC)
    {
      ctrl_t ctrl = assuan_get_pointer (ctx);

      if (ctrl && ctrl->server_local
          && ctrl->server_local->inhibit_data_logging
          && ctrl->server_local->inhibit_data_logging_count)
        log_debug ("(%zu bytes sent via D lines not shown)\n",
                   ctrl->server_local->inhibit_data_logging_count);
    }
  if (assuan_send_data (ctx, NULL, 0))
    {
      gpg_err_set_errno (EIO);
      return -1;
    }

  return 0;
}


/* Copy the % and + escaped string S into the buffer D and replace the
   escape sequences.  Note, that it is sufficient to allocate the
   target string D as long as the source string S, i.e.: strlen(s)+1.
   Note further that if S contains an escaped binary Nul the resulting
   string D will contain the 0 as well as all other characters but it
   will be impossible to know whether this is the original EOS or a
   copied Nul. */
static void
strcpy_escaped_plus (char *d, const unsigned char *s)
{
  while (*s)
    {
      if (*s == '%' && s[1] && s[2])
        {
          s++;
          *d++ = xtoi_2 ( s);
          s += 2;
        }
      else if (*s == '+')
        *d++ = ' ', s++;
      else
        *d++ = *s++;
    }
  *d = 0;
}


/* This function returns true if a Tor server is running.  The status
 * is cached for the current connection.  */
static int
is_tor_running (ctrl_t ctrl)
{
  /* Check whether we can connect to the proxy.  */

  if (!ctrl || !ctrl->server_local)
    return 0; /* Ooops.  */

  if (!ctrl->server_local->tor_state)
    {
      assuan_fd_t sock;

      sock = assuan_sock_connect_byname (NULL, 0, 0, NULL, ASSUAN_SOCK_TOR);
      if (sock == ASSUAN_INVALID_FD)
        ctrl->server_local->tor_state = -1; /* Not running.  */
      else
        {
          assuan_sock_close (sock);
          ctrl->server_local->tor_state = 1; /* Running.  */
        }
    }
  return (ctrl->server_local->tor_state > 0);
}


/* Return an error if the assuan context does not belong to the owner
   of the process or to root.  On error FAILTEXT is set as Assuan
   error string.  */
static gpg_error_t
check_owner_permission (assuan_context_t ctx, const char *failtext)
{
#ifdef HAVE_W32_SYSTEM
  /* Under Windows the dirmngr is always run under the control of the
     user.  */
  (void)ctx;
  (void)failtext;
#else
  gpg_err_code_t ec;
  assuan_peercred_t cred;

  ec = gpg_err_code (assuan_get_peercred (ctx, &cred));
  if (!ec && cred->uid && cred->uid != getuid ())
    ec = GPG_ERR_EPERM;
  if (ec)
    return set_error (ec, failtext);
#endif
  return 0;
}



/* Common code for get_cert_local and get_issuer_cert_local. */
static ksba_cert_t
do_get_cert_local (ctrl_t ctrl, const char *name, const char *command)
{
  unsigned char *value;
  size_t valuelen;
  int rc;
  char *buf;
  ksba_cert_t cert;

  buf = name? strconcat (command, " ", name, NULL) : xtrystrdup (command);
  if (!buf)
    rc = gpg_error_from_syserror ();
  else
    {
      rc = assuan_inquire (ctrl->server_local->assuan_ctx, buf,
                           &value, &valuelen, MAX_CERT_LENGTH);
      xfree (buf);
    }
  if (rc)
    {
      log_error (_("assuan_inquire(%s) failed: %s\n"),
                 command, gpg_strerror (rc));
      return NULL;
    }

  if (!valuelen)
    {
      xfree (value);
      return NULL;
    }

  rc = ksba_cert_new (&cert);
  if (!rc)
    {
      rc = ksba_cert_init_from_mem (cert, value, valuelen);
      if (rc)
        {
          ksba_cert_release (cert);
          cert = NULL;
        }
    }
  xfree (value);
  return cert;
}



/* Ask back to return a certificate for NAME, given as a regular gpgsm
 * certificate identifier (e.g. fingerprint or one of the other
 * methods).  Alternatively, NULL may be used for NAME to return the
 * current target certificate.  Either return the certificate in a
 * KSBA object or NULL if it is not available.  */
ksba_cert_t
get_cert_local (ctrl_t ctrl, const char *name)
{
  if (!ctrl || !ctrl->server_local || !ctrl->server_local->assuan_ctx)
    {
      if (opt.debug)
        log_debug ("get_cert_local called w/o context\n");
      return NULL;
    }
  return do_get_cert_local (ctrl, name, "SENDCERT");

}


/* Ask back to return the issuing certificate for NAME, given as a
 * regular gpgsm certificate identifier (e.g. fingerprint or one
 * of the other methods).  Alternatively, NULL may be used for NAME to
 * return the current target certificate. Either return the certificate
 * in a KSBA object or NULL if it is not available.  */
ksba_cert_t
get_issuing_cert_local (ctrl_t ctrl, const char *name)
{
  if (!ctrl || !ctrl->server_local || !ctrl->server_local->assuan_ctx)
    {
      if (opt.debug)
        log_debug ("get_issuing_cert_local called w/o context\n");
      return NULL;
    }
  return do_get_cert_local (ctrl, name, "SENDISSUERCERT");
}


/* Ask back to return a certificate with subject NAME and a
 * subjectKeyIdentifier of KEYID. */
ksba_cert_t
get_cert_local_ski (ctrl_t ctrl, const char *name, ksba_sexp_t keyid)
{
  unsigned char *value;
  size_t valuelen;
  int rc;
  char *buf;
  ksba_cert_t cert;
  char *hexkeyid;

  if (!ctrl || !ctrl->server_local || !ctrl->server_local->assuan_ctx)
    {
      if (opt.debug)
        log_debug ("get_cert_local_ski called w/o context\n");
      return NULL;
    }
  if (!name || !keyid)
    {
      log_debug ("get_cert_local_ski called with insufficient arguments\n");
      return NULL;
    }

  hexkeyid = serial_hex (keyid);
  if (!hexkeyid)
    {
      log_debug ("serial_hex() failed\n");
      return NULL;
    }

  buf = strconcat ("SENDCERT_SKI ", hexkeyid, " /", name, NULL);
  if (!buf)
    {
      log_error ("can't allocate enough memory: %s\n", strerror (errno));
      xfree (hexkeyid);
      return NULL;
    }
  xfree (hexkeyid);

  rc = assuan_inquire (ctrl->server_local->assuan_ctx, buf,
                       &value, &valuelen, MAX_CERT_LENGTH);
  xfree (buf);
  if (rc)
    {
      log_error (_("assuan_inquire(%s) failed: %s\n"), "SENDCERT_SKI",
                 gpg_strerror (rc));
      return NULL;
    }

  if (!valuelen)
    {
      xfree (value);
      return NULL;
    }

  rc = ksba_cert_new (&cert);
  if (!rc)
    {
      rc = ksba_cert_init_from_mem (cert, value, valuelen);
      if (rc)
        {
          ksba_cert_release (cert);
          cert = NULL;
        }
    }
  xfree (value);
  return cert;
}


/* Ask the client via an inquiry to check the istrusted status of the
   certificate specified by the hexified fingerprint HEXFPR.  Returns
   0 if the certificate is trusted by the client or an error code.  */
gpg_error_t
get_istrusted_from_client (ctrl_t ctrl, const char *hexfpr)
{
  unsigned char *value;
  size_t valuelen;
  int rc;
  char request[100];

  if (!ctrl || !ctrl->server_local || !ctrl->server_local->assuan_ctx
      || !hexfpr)
    return gpg_error (GPG_ERR_INV_ARG);

  snprintf (request, sizeof request, "ISTRUSTED %s", hexfpr);
  rc = assuan_inquire (ctrl->server_local->assuan_ctx, request,
                       &value, &valuelen, 100);
  if (rc)
    {
      log_error (_("assuan_inquire(%s) failed: %s\n"),
                 request, gpg_strerror (rc));
      return rc;
    }
  /* The expected data is: "1" or "1 cruft" (not a C-string).  */
  if (valuelen && *value == '1' && (valuelen == 1 || spacep (value+1)))
    rc = 0;
  else
    rc = gpg_error (GPG_ERR_NOT_TRUSTED);
  xfree (value);
  return rc;
}




/* Ask the client to return the certificate associated with the
   current command. This is sometimes needed because the client usually
   sends us just the cert ID, assuming that the request can be
   satisfied from the cache, where the cert ID is used as key. */
static int
inquire_cert_and_load_crl (assuan_context_t ctx)
{
  ctrl_t ctrl = assuan_get_pointer (ctx);
  gpg_error_t err;
  unsigned char *value = NULL;
  size_t valuelen;
  ksba_cert_t cert = NULL;

  err = assuan_inquire( ctx, "SENDCERT", &value, &valuelen, 0);
  if (err)
    return err;

/*   { */
/*     FILE *fp = fopen ("foo.der", "r"); */
/*     value = xmalloc (2000); */
/*     valuelen = fread (value, 1, 2000, fp); */
/*     fclose (fp); */
/*   } */

  if (!valuelen) /* No data returned; return a comprehensible error. */
    return gpg_error (GPG_ERR_MISSING_CERT);

  err = ksba_cert_new (&cert);
  if (err)
    goto leave;
  err = ksba_cert_init_from_mem (cert, value, valuelen);
  if(err)
    goto leave;
  xfree (value); value = NULL;

  err = crl_cache_reload_crl (ctrl, cert);

 leave:
  ksba_cert_release (cert);
  xfree (value);
  return err;
}


/* Handle OPTION commands. */
static gpg_error_t
option_handler (assuan_context_t ctx, const char *key, const char *value)
{
  ctrl_t ctrl = assuan_get_pointer (ctx);
  gpg_error_t err = 0;

  if (!strcmp (key, "force-crl-refresh"))
    {
      int i = *value? atoi (value) : 0;
      ctrl->force_crl_refresh = i;
    }
  else if (!strcmp (key, "audit-events"))
    {
      int i = *value? atoi (value) : 0;
      ctrl->audit_events = i;
    }
  else if (!strcmp (key, "http-proxy"))
    {
      xfree (ctrl->http_proxy);
      if (!*value || !strcmp (value, "none"))
        ctrl->http_proxy = NULL;
      else if (!(ctrl->http_proxy = xtrystrdup (value)))
        err = gpg_error_from_syserror ();
    }
  else if (!strcmp (key, "honor-keyserver-url-used"))
    {
      /* Return an error if we are running in Tor mode.  */
      if (dirmngr_use_tor ())
        err = gpg_error (GPG_ERR_FORBIDDEN);
    }
  else if (!strcmp (key, "http-crl"))
    {
      int i = *value? atoi (value) : 0;
      ctrl->http_no_crl = !i;
    }
  else
    err = gpg_error (GPG_ERR_UNKNOWN_OPTION);

  return err;
}



static const char hlp_dns_cert[] =
  "DNS_CERT <subtype> <name>\n"
  "DNS_CERT --pka <user_id>\n"
  "DNS_CERT --dane <user_id>\n"
  "\n"
  "Return the CERT record for <name>.  <subtype> is one of\n"
  "  *     Return the first record of any supported subtype\n"
  "  PGP   Return the first record of subtype PGP (3)\n"
  "  IPGP  Return the first record of subtype IPGP (6)\n"
  "If the content of a certificate is available (PGP) it is returned\n"
  "by data lines.  Fingerprints and URLs are returned via status lines.\n"
  "In --pka mode the fingerprint and if available an URL is returned.\n"
  "In --dane mode the key is returned from RR type 61";
static gpg_error_t
cmd_dns_cert (assuan_context_t ctx, char *line)
{
  /* ctrl_t ctrl = assuan_get_pointer (ctx); */
  gpg_error_t err = 0;
  int pka_mode, dane_mode;
  char *mbox = NULL;
  char *namebuf = NULL;
  char *encodedhash = NULL;
  const char *name;
  int certtype;
  char *p;
  void *key = NULL;
  size_t keylen;
  unsigned char *fpr = NULL;
  size_t fprlen;
  char *url = NULL;

  pka_mode = has_option (line, "--pka");
  dane_mode = has_option (line, "--dane");
  line = skip_options (line);

  if (pka_mode && dane_mode)
    {
      err = PARM_ERROR ("either --pka or --dane may be given");
      goto leave;
    }

  if (pka_mode || dane_mode)
    ; /* No need to parse here - we do this later.  */
  else
    {
      p = strchr (line, ' ');
      if (!p)
        {
          err = PARM_ERROR ("missing arguments");
          goto leave;
        }
      *p++ = 0;
      if (!strcmp (line, "*"))
        certtype = DNS_CERTTYPE_ANY;
      else if (!strcmp (line, "IPGP"))
        certtype = DNS_CERTTYPE_IPGP;
      else if (!strcmp (line, "PGP"))
        certtype = DNS_CERTTYPE_PGP;
      else
        {
          err = PARM_ERROR ("unknown subtype");
          goto leave;
        }
      while (spacep (p))
        p++;
      line = p;
      if (!*line)
        {
          err = PARM_ERROR ("name missing");
          goto leave;
        }
    }

  if (pka_mode || dane_mode)
    {
      char *domain;     /* Points to mbox.  */
      char hashbuf[32]; /* For SHA-1 and SHA-256. */

      /* We lowercase ascii characters but the DANE I-D does not allow
         this.  FIXME: Check after the release of the RFC whether to
         change this.  */
      mbox = mailbox_from_userid (line);
      if (!mbox || !(domain = strchr (mbox, '@')))
        {
          err = set_error (GPG_ERR_INV_USER_ID, "no mailbox in user id");
          goto leave;
        }
      *domain++ = 0;

      if (pka_mode)
        {
          gcry_md_hash_buffer (GCRY_MD_SHA1, hashbuf, mbox, strlen (mbox));
          encodedhash = zb32_encode (hashbuf, 8*20);
          if (!encodedhash)
            {
              err = gpg_error_from_syserror ();
              goto leave;
            }
          namebuf = strconcat (encodedhash, "._pka.", domain, NULL);
          if (!namebuf)
            {
              err = gpg_error_from_syserror ();
              goto leave;
            }
          name = namebuf;
          certtype = DNS_CERTTYPE_IPGP;
        }
      else
        {
          /* Note: The hash is truncated to 28 bytes and we lowercase
             the result only for aesthetic reasons.  */
          gcry_md_hash_buffer (GCRY_MD_SHA256, hashbuf, mbox, strlen (mbox));
          encodedhash = bin2hex (hashbuf, 28, NULL);
          if (!encodedhash)
            {
              err = gpg_error_from_syserror ();
              goto leave;
            }
          ascii_strlwr (encodedhash);
          namebuf = strconcat (encodedhash, "._openpgpkey.", domain, NULL);
          if (!namebuf)
            {
              err = gpg_error_from_syserror ();
              goto leave;
            }
          name = namebuf;
          certtype = DNS_CERTTYPE_RR61;
        }
    }
  else
    name = line;

  err = get_dns_cert (name, certtype, &key, &keylen, &fpr, &fprlen, &url);
  if (err)
    goto leave;

  if (key)
    {
      err = data_line_write (ctx, key, keylen);
      if (err)
        goto leave;
    }

  if (fpr)
    {
      char *tmpstr;

      tmpstr = bin2hex (fpr, fprlen, NULL);
      if (!tmpstr)
        err = gpg_error_from_syserror ();
      else
        {
          err = assuan_write_status (ctx, "FPR", tmpstr);
          xfree (tmpstr);
        }
      if (err)
        goto leave;
    }

  if (url)
    {
      err = assuan_write_status (ctx, "URL", url);
      if (err)
        goto leave;
    }


 leave:
  xfree (key);
  xfree (fpr);
  xfree (url);
  xfree (mbox);
  xfree (namebuf);
  xfree (encodedhash);
  return leave_cmd (ctx, err);
}



/* Core of cmd_wkd_get and task_check_wkd_support.  If CTX is NULL
 * this function will not write anything to the assuan output.  */
static gpg_error_t
proc_wkd_get (ctrl_t ctrl, assuan_context_t ctx, char *line)
{
  gpg_error_t err = 0;
  char *mbox = NULL;
  char *domainbuf = NULL;
  char *domain;     /* Points to mbox or domainbuf.  This is used to
                     * connect to the host.  */
  char *domain_orig;/* Points to mbox.  This is the used for the
                     * query; i.e. the domain part of the
                     * addrspec.  */
  char sha1buf[20];
  char *uri = NULL;
  char *encodedhash = NULL;
  int opt_submission_addr;
  int opt_policy_flags;
  int is_wkd_query;   /* True if this is a real WKD query.  */
  int no_log = 0;
  char portstr[20] = { 0 };
  int subdomain_mode = 0;

  opt_submission_addr = has_option (line, "--submission-address");
  opt_policy_flags = has_option (line, "--policy-flags");
  if (has_option (line, "--quick"))
    ctrl->timeout = opt.connect_quick_timeout;
  line = skip_options (line);
  is_wkd_query = !(opt_policy_flags || opt_submission_addr);

  mbox = mailbox_from_userid (line);
  if (!mbox || !(domain = strchr (mbox, '@')))
    {
      err = set_error (GPG_ERR_INV_USER_ID, "no mailbox in user id");
      goto leave;
    }
  *domain++ = 0;
  domain_orig = domain;


  /* Let's check whether we already know that the domain does not
   * support WKD.  */
  if (is_wkd_query)
    {
      if (domaininfo_is_wkd_not_supported (domain_orig))
        {
          err = gpg_error (GPG_ERR_NO_DATA);
          dirmngr_status_printf (ctrl, "NOTE", "wkd_cached_result %u", err);
          goto leave;
        }
    }


  /* First try the new "openpgp" subdomain.  We check that the domain
   * is valid because it is later used as an unescaped filename part
   * of the URI.  */
  if (is_valid_domain_name (domain_orig))
    {
      dns_addrinfo_t aibuf;

      domainbuf = strconcat ( "openpgpkey.", domain_orig, NULL);
      if (!domainbuf)
        {
          err = gpg_error_from_syserror ();
          goto leave;
        }

      /* FIXME: We should put a cache into dns-stuff because the same
       * query (with a different port and socket type, though) will be
       * done later by http function.  */
      err = resolve_dns_name (domainbuf, 0, 0, 0, &aibuf, NULL);
      if (err)
        {
          err = 0;
          xfree (domainbuf);
          domainbuf = NULL;
        }
      else /* Got a subdomain. */
        {
          free_dns_addrinfo (aibuf);
          subdomain_mode = 1;
          domain = domainbuf;
        }
    }

  /* Check for SRV records unless we have a subdomain. */
  if (!subdomain_mode)
    {
      struct srventry *srvs;
      unsigned int srvscount;
      size_t domainlen, targetlen;
      int i;

      err = get_dns_srv (domain, "openpgpkey", NULL, &srvs, &srvscount);
      if (err)
        {
          /* Ignore server failed becuase there are too many resolvers
           * which do not work as expected.  */
          if (gpg_err_code (err) == GPG_ERR_SERVER_FAILED)
            err = 0; /*(srvcount is guaranteed to be 0)*/
          else
            goto leave;
        }

      /* Check for rogue DNS names.  */
      for (i = 0; i < srvscount; i++)
        {
          if (!is_valid_domain_name (srvs[i].target))
            {
              err = gpg_error (GPG_ERR_DNS_ADDRESS);
              log_error ("rogue openpgpkey SRV record for '%s'\n", domain);
              xfree (srvs);
              goto leave;
            }
        }

      /* Find the first target which also ends in DOMAIN or is equal
       * to DOMAIN.  */
      domainlen = strlen (domain);
      for (i = 0; i < srvscount; i++)
        {
          if (DBG_DNS)
            log_debug ("srv: trying '%s:%hu'\n", srvs[i].target, srvs[i].port);
          targetlen = strlen (srvs[i].target);
          if ((targetlen > domainlen + 1
               && srvs[i].target[targetlen - domainlen - 1] == '.'
               && !ascii_strcasecmp (srvs[i].target + targetlen - domainlen,
                                     domain))
              || (targetlen == domainlen
                  && !ascii_strcasecmp (srvs[i].target, domain)))
            {
              /* found.  */
              domainbuf = xtrystrdup (srvs[i].target);
              if (!domainbuf)
                {
                  err = gpg_error_from_syserror ();
                  xfree (srvs);
                  goto leave;
                }
              domain = domainbuf;
              if (srvs[i].port)
                snprintf (portstr, sizeof portstr, ":%hu", srvs[i].port);
              break;
            }
        }
      xfree (srvs);
    }

  /* Prepare the hash of the local part.  */
  gcry_md_hash_buffer (GCRY_MD_SHA1, sha1buf, mbox, strlen (mbox));
  encodedhash = zb32_encode (sha1buf, 8*20);
  if (!encodedhash)
    {
      err = gpg_error_from_syserror ();
      goto leave;
    }

  if (opt_submission_addr)
    {
      uri = strconcat ("https://",
                       domain,
                       portstr,
                       "/.well-known/openpgpkey/",
                       subdomain_mode? domain_orig : "",
                       subdomain_mode? "/" : "",
                       "submission-address",
                       NULL);
    }
  else if (opt_policy_flags)
    {
      uri = strconcat ("https://",
                       domain,
                       portstr,
                       "/.well-known/openpgpkey/",
                       subdomain_mode? domain_orig : "",
                       subdomain_mode? "/" : "",
                       "policy",
                       NULL);
    }
  else
    {
      char *escapedmbox;

      escapedmbox = http_escape_string (mbox, "%;?&=+#");
      if (escapedmbox)
        {
          uri = strconcat ("https://",
                           domain,
                           portstr,
                           "/.well-known/openpgpkey/",
                           subdomain_mode? domain_orig : "",
                           subdomain_mode? "/" : "",
                           "hu/",
                           encodedhash,
                           "?l=",
                           escapedmbox,
                           NULL);
          xfree (escapedmbox);
          no_log = 1;
          if (uri)
            {
              err = dirmngr_status_printf (ctrl, "SOURCE", "https://%s%s",
                                           domain, portstr);
              if (err)
                goto leave;
            }
        }
    }
  if (!uri)
    {
      err = gpg_error_from_syserror ();
      goto leave;
    }

  /* Setup an output stream and perform the get.  */
  {
    estream_t outfp;

    outfp = ctx? es_fopencookie (ctx, "w", data_line_cookie_functions) : NULL;
    if (!outfp && ctx)
      err = set_error (GPG_ERR_ASS_GENERAL,
                       "error setting up a data stream");
    else
      {
        if (ctrl->server_local)
          {
            if (no_log)
              ctrl->server_local->inhibit_data_logging = 1;
            ctrl->server_local->inhibit_data_logging_now = 0;
            ctrl->server_local->inhibit_data_logging_count = 0;
          }
        err = ks_action_fetch (ctrl, uri, outfp);
        es_fclose (outfp);
        if (ctrl->server_local)
          ctrl->server_local->inhibit_data_logging = 0;

        /* Register the result under the domain name of MBOX. */
        switch (gpg_err_code (err))
          {
          case 0:
            domaininfo_set_wkd_supported (domain_orig);
            break;

          case GPG_ERR_NO_NAME:
            /* There is no such domain.  */
            domaininfo_set_no_name (domain_orig);
            break;

          case GPG_ERR_NO_DATA:
            if (is_wkd_query && ctrl->server_local)
              {
                /* Mark that and schedule a check.  */
                domaininfo_set_wkd_not_found (domain_orig);
                workqueue_add_task (task_check_wkd_support, domain_orig,
                                    ctrl->server_local->session_id, 1);
              }
            else if (opt_policy_flags) /* No policy file - no support.  */
              domaininfo_set_wkd_not_supported (domain_orig);
            break;

          default:
            /* Don't register other errors.  */
            break;
          }
      }
  }

 leave:
  xfree (uri);
  xfree (encodedhash);
  xfree (mbox);
  xfree (domainbuf);
  return err;
}


static const char hlp_wkd_get[] =
  "WKD_GET [--submission-address|--policy-flags] <user_id>\n"
  "\n"
  "Return the key or other info for <user_id>\n"
  "from the Web Key Directory.";
static gpg_error_t
cmd_wkd_get (assuan_context_t ctx, char *line)
{
  ctrl_t ctrl = assuan_get_pointer (ctx);
  gpg_error_t err;

  err = proc_wkd_get (ctrl, ctx, line);

  return leave_cmd (ctx, err);
}


/* A task to check whether DOMAIN supports WKD.  This is done by
 * checking whether the policy flags file can be read.  */
static const char *
task_check_wkd_support (ctrl_t ctrl, const char *domain)
{
  char *string;

  if (!ctrl || !domain)
    return "check_wkd_support";

  string = strconcat ("--policy-flags foo@", domain, NULL);
  if (!string)
    log_error ("%s: %s\n", __func__, gpg_strerror (gpg_error_from_syserror ()));
  else
    {
      proc_wkd_get (ctrl, NULL, string);
      xfree (string);
    }

  return NULL;
}



static const char hlp_ldapserver[] =
  "LDAPSERVER [--clear] <data>\n"
  "\n"
  "Add a new LDAP server to the list of configured LDAP servers.\n"
  "DATA is in the same format as expected in the configure file.\n"
  "An optional prefix \"ldap:\" is allowed.  With no args all\n"
  "configured ldapservers are listed.  Option --clear removes all\n"
  "servers configured in this session.";
static gpg_error_t
cmd_ldapserver (assuan_context_t ctx, char *line)
{
#if USE_LDAP
  ctrl_t ctrl = assuan_get_pointer (ctx);
  ldap_server_t server;
  ldap_server_t *last_next_p;
  int clear_flag;

  clear_flag = has_option (line, "--clear");
  line = skip_options (line);
  while (spacep (line))
    line++;

  if (clear_flag)
    {
#if USE_LDAP
      ldapserver_list_free (ctrl->server_local->ldapservers);
#endif /*USE_LDAP*/
      ctrl->server_local->ldapservers = NULL;
    }

  if (!*line && clear_flag)
    return leave_cmd (ctx, 0);

  if (!*line)
    {
      /* List all ldapservers.  */
      struct ldapserver_iter ldapserver_iter;
      char *tmpstr;
      char portstr[20];

      for (ldapserver_iter_begin (&ldapserver_iter, ctrl);
           !ldapserver_iter_end_p (&ldapserver_iter);
           ldapserver_iter_next (&ldapserver_iter))
        {
          server = ldapserver_iter.server;
          if (server->port)
            snprintf (portstr, sizeof portstr, "%d", server->port);
          else
            *portstr = 0;

          tmpstr = xtryasprintf ("ldap:%s:%s:%s:%s:%s:%s%s:",
                                 server->host? server->host : "",
                                 portstr,
                                 server->user? server->user : "",
                                 server->pass? "*****": "",
                                 server->base? server->base : "",
                                 server->starttls ? "starttls" :
                                 server->ldap_over_tls ? "ldaptls" : "none",
                                 server->ntds ? ",ntds" : "");
          if (!tmpstr)
            return leave_cmd (ctx, gpg_error_from_syserror ());
          dirmngr_status (ctrl, "LDAPSERVER", tmpstr, NULL);
          xfree (tmpstr);
        }
      return leave_cmd (ctx, 0);
    }

  /* Skip an "ldap:" prefix unless it is a valid ldap url.  */
  if (!strncmp (line, "ldap:", 5) && !(line[5] == '/' && line[6] == '/'))
    line += 5;

  server = ldapserver_parse_one (line, NULL, 0);
  if (! server)
    return leave_cmd (ctx, gpg_error (GPG_ERR_INV_ARG));

  last_next_p = &ctrl->server_local->ldapservers;
  while (*last_next_p)
    last_next_p = &(*last_next_p)->next;
  *last_next_p = server;
  return leave_cmd (ctx, 0);
#else
  (void)line;
  return leave_cmd (ctx, gpg_error (GPG_ERR_NOT_IMPLEMENTED));
#endif
}


static const char hlp_isvalid[] =
  "ISVALID [--only-ocsp] [--force-default-responder]"
  " <certificate_id> [<certificate_fpr>]\n"
  "\n"
  "This command checks whether the certificate identified by the\n"
  "certificate_id is valid.  This is done by consulting CRLs or\n"
  "whatever has been configured.  Note, that the returned error codes\n"
  "are from gpg-error.h.  The command may callback using the inquire\n"
  "function.  See the manual for details.\n"
  "\n"
  "The CERTIFICATE_ID is a hex encoded string consisting of two parts,\n"
  "delimited by a single dot.  The first part is the SHA-1 hash of the\n"
  "issuer name and the second part the serial number.\n"
  "\n"
  "If an OCSP check is desired CERTIFICATE_FPR with the hex encoded\n"
  "fingerprint of the certificate is required.  In this case an OCSP\n"
  "request is done before consulting the CRL.\n"
  "\n"
  "If the option --only-ocsp is given, no fallback to a CRL check will\n"
  "be used.\n"
  "\n"
  "If the option --force-default-responder is given, only the default\n"
  "OCSP responder will be used and any other methods of obtaining an\n"
  "OCSP responder URL won't be used.";
static gpg_error_t
cmd_isvalid (assuan_context_t ctx, char *line)
{
  ctrl_t ctrl = assuan_get_pointer (ctx);
  char *issuerhash, *serialno, *fpr;
  gpg_error_t err;
  int did_inquire = 0;
  int ocsp_mode = 0;
  int only_ocsp;
  int force_default_responder;

  only_ocsp = has_option (line, "--only-ocsp");
  force_default_responder = has_option (line, "--force-default-responder");
  line = skip_options (line);

  /* We need to work on a copy of the line because that same Assuan
   * context may be used for an inquiry.  That is because Assuan
   * reuses its line buffer.  */
  issuerhash = xstrdup (line);

  serialno = strchr (issuerhash, '.');
  if (!serialno)
    {
      xfree (issuerhash);
      return leave_cmd (ctx, PARM_ERROR (_("serialno missing in cert ID")));
    }
  *serialno++ = 0;
  if (strlen (issuerhash) != 40)
    {
      xfree (issuerhash);
      return leave_cmd (ctx, PARM_ERROR ("cert ID is too short"));
    }

  fpr = strchr (serialno, ' ');
  while (fpr && spacep (fpr))
    fpr++;
  if (fpr && *fpr)
    {
      char *endp = strchr (fpr, ' ');
      if (endp)
        *endp = 0;
      if (strlen (fpr) != 40)
        {
          xfree (issuerhash);
          return leave_cmd (ctx, PARM_ERROR ("fingerprint too short"));
        }
      ocsp_mode = 1;
    }


 again:
  if (ocsp_mode)
    {
      /* Note, that we currently ignore the supplied fingerprint FPR;
       * instead ocsp_isvalid does an inquire to ask for the cert.
       * The fingerprint may eventually be used to lookup the
       * certificate in a local cache.  */
      if (!opt.allow_ocsp)
        err = gpg_error (GPG_ERR_NOT_SUPPORTED);
      else
        err = ocsp_isvalid (ctrl, NULL, NULL, force_default_responder);

      if (gpg_err_code (err) == GPG_ERR_CONFIGURATION
          && gpg_err_source (err) == GPG_ERR_SOURCE_DIRMNGR)
        {
          /* No default responder configured - fallback to CRL.  */
          if (!only_ocsp)
            log_info ("falling back to CRL check\n");
          ocsp_mode = 0;
          goto again;
        }
    }
  else if (only_ocsp)
    err = gpg_error (GPG_ERR_NO_CRL_KNOWN);
  else
    {
      switch (crl_cache_isvalid (ctrl,
                                 issuerhash, serialno,
                                 ctrl->force_crl_refresh))
        {
        case CRL_CACHE_VALID:
          err = 0;
          break;
        case CRL_CACHE_INVALID:
          err = gpg_error (GPG_ERR_CERT_REVOKED);
          break;
        case CRL_CACHE_DONTKNOW:
          if (did_inquire)
            err = gpg_error (GPG_ERR_NO_CRL_KNOWN);
          else if (!(err = inquire_cert_and_load_crl (ctx)))
            {
              did_inquire = 1;
              goto again;
            }
          break;
        case CRL_CACHE_CANTUSE:
          err = gpg_error (GPG_ERR_NO_CRL_KNOWN);
          break;
        default:
          log_fatal ("crl_cache_isvalid returned invalid code\n");
        }
    }

  xfree (issuerhash);
  return leave_cmd (ctx, err);
}


/* If the line contains a SHA-1 fingerprint as the first argument,
   return the FPR vuffer on success.  The function checks that the
   fingerprint consists of valid characters and prints and error
   message if it does not and returns NULL.  Fingerprints are
   considered optional and thus no explicit error is returned. NULL is
   also returned if there is no fingerprint at all available.
   FPR must be a caller provided buffer of at least 20 bytes.

   Note that colons within the fingerprint are allowed to separate 2
   hex digits; this allows for easier cutting and pasting using the
   usual fingerprint rendering.
*/
static unsigned char *
get_fingerprint_from_line (const char *line, unsigned char *fpr)
{
  const char *s;
  int i;

  for (s=line, i=0; *s && *s != ' '; s++ )
    {
      if ( hexdigitp (s) && hexdigitp (s+1) )
        {
          if ( i >= 20 )
            return NULL;  /* Fingerprint too long.  */
          fpr[i++] = xtoi_2 (s);
          s++;
        }
      else if ( *s != ':' )
        return NULL; /* Invalid.  */
    }
  if ( i != 20 )
    return NULL; /* Fingerprint to short.  */
  return fpr;
}



static const char hlp_checkcrl[] =
  "CHECKCRL [<fingerprint>]\n"
  "\n"
  "Check whether the certificate with FINGERPRINT (SHA-1 hash of the\n"
  "entire X.509 certificate blob) is valid or not by consulting the\n"
  "CRL responsible for this certificate.  If the fingerprint has not\n"
  "been given or the certificate is not known, the function \n"
  "inquires the certificate using an\n"
  "\n"
  "  INQUIRE TARGETCERT\n"
  "\n"
  "and the caller is expected to return the certificate for the\n"
  "request (which should match FINGERPRINT) as a binary blob.\n"
  "Processing then takes place without further interaction; in\n"
  "particular dirmngr tries to locate other required certificate by\n"
  "its own mechanism which includes a local certificate store as well\n"
  "as a list of trusted root certificates.\n"
  "\n"
  "The return value is the usual gpg-error code or 0 for ducesss;\n"
  "i.e. the certificate validity has been confirmed by a valid CRL.";
static gpg_error_t
cmd_checkcrl (assuan_context_t ctx, char *line)
{
  ctrl_t ctrl = assuan_get_pointer (ctx);
  gpg_error_t err;
  unsigned char fprbuffer[20], *fpr;
  ksba_cert_t cert;

  fpr = get_fingerprint_from_line (line, fprbuffer);
  cert = fpr? get_cert_byfpr (fpr) : NULL;

  if (!cert)
    {
      /* We do not have this certificate yet or the fingerprint has
         not been given.  Inquire it from the client.  */
      unsigned char *value = NULL;
      size_t valuelen;

      err = assuan_inquire (ctrl->server_local->assuan_ctx, "TARGETCERT",
                           &value, &valuelen, MAX_CERT_LENGTH);
      if (err)
        {
          log_error (_("assuan_inquire failed: %s\n"), gpg_strerror (err));
          goto leave;
        }

      if (!valuelen) /* No data returned; return a comprehensible error. */
        err = gpg_error (GPG_ERR_MISSING_CERT);
      else
        {
          err = ksba_cert_new (&cert);
          if (!err)
            err = ksba_cert_init_from_mem (cert, value, valuelen);
        }
      xfree (value);
      if(err)
        goto leave;
    }

  assert (cert);

  err = crl_cache_cert_isvalid (ctrl, cert, ctrl->force_crl_refresh);
  if (gpg_err_code (err) == GPG_ERR_NO_CRL_KNOWN)
    {
      err = crl_cache_reload_crl (ctrl, cert);
      if (!err)
        err = crl_cache_cert_isvalid (ctrl, cert, 0);
    }

 leave:
  ksba_cert_release (cert);
  return leave_cmd (ctx, err);
}


static const char hlp_checkocsp[] =
  "CHECKOCSP [--force-default-responder] [<fingerprint>]\n"
  "\n"
  "Check whether the certificate with FINGERPRINT (SHA-1 hash of the\n"
  "entire X.509 certificate blob) is valid or not by asking an OCSP\n"
  "responder responsible for this certificate.  The optional\n"
  "fingerprint may be used for a quick check in case an OCSP check has\n"
  "been done for this certificate recently (we always cache OCSP\n"
  "responses for a couple of minutes). If the fingerprint has not been\n"
  "given or there is no cached result, the function inquires the\n"
  "certificate using an\n"
  "\n"
  "   INQUIRE TARGETCERT\n"
  "\n"
  "and the caller is expected to return the certificate for the\n"
  "request (which should match FINGERPRINT) as a binary blob.\n"
  "Processing then takes place without further interaction; in\n"
  "particular dirmngr tries to locate other required certificates by\n"
  "its own mechanism which includes a local certificate store as well\n"
  "as a list of trusted root certificates.\n"
  "\n"
  "If the option --force-default-responder is given, only the default\n"
  "OCSP responder will be used and any other methods of obtaining an\n"
  "OCSP responder URL won't be used.\n"
  "\n"
  "The return value is the usual gpg-error code or 0 for ducesss;\n"
  "i.e. the certificate validity has been confirmed by a valid CRL.";
static gpg_error_t
cmd_checkocsp (assuan_context_t ctx, char *line)
{
  ctrl_t ctrl = assuan_get_pointer (ctx);
  gpg_error_t err;
  unsigned char fprbuffer[20], *fpr;
  ksba_cert_t cert;
  int force_default_responder;

  force_default_responder = has_option (line, "--force-default-responder");
  line = skip_options (line);

  fpr = get_fingerprint_from_line (line, fprbuffer);
  cert = fpr? get_cert_byfpr (fpr) : NULL;

  if (!cert)
    {
      /* We do not have this certificate yet or the fingerprint has
         not been given.  Inquire it from the client.  */
      unsigned char *value = NULL;
      size_t valuelen;

      err = assuan_inquire (ctrl->server_local->assuan_ctx, "TARGETCERT",
                           &value, &valuelen, MAX_CERT_LENGTH);
      if (err)
        {
          log_error (_("assuan_inquire failed: %s\n"), gpg_strerror (err));
          goto leave;
        }

      if (!valuelen) /* No data returned; return a comprehensible error. */
        err = gpg_error (GPG_ERR_MISSING_CERT);
      else
        {
          err = ksba_cert_new (&cert);
          if (!err)
            err = ksba_cert_init_from_mem (cert, value, valuelen);
        }
      xfree (value);
      if(err)
        goto leave;
    }

  assert (cert);

  if (!opt.allow_ocsp)
    err = gpg_error (GPG_ERR_NOT_SUPPORTED);
  else
    err = ocsp_isvalid (ctrl, cert, NULL, force_default_responder);

 leave:
  ksba_cert_release (cert);
  return leave_cmd (ctx, err);
}



static int
lookup_cert_by_url (assuan_context_t ctx, const char *url)
{
  ctrl_t ctrl = assuan_get_pointer (ctx);
  gpg_error_t err = 0;
  unsigned char *value = NULL;
  size_t valuelen;

  /* Fetch single certificate given it's URL.  */
  err = fetch_cert_by_url (ctrl, url, &value, &valuelen);
  if (err)
    {
      log_error (_("fetch_cert_by_url failed: %s\n"), gpg_strerror (err));
      goto leave;
    }

  /* Send the data, flush the buffer and then send an END. */
  err = assuan_send_data (ctx, value, valuelen);
  if (!err)
    err = assuan_send_data (ctx, NULL, 0);
  if (!err)
    err = assuan_write_line (ctx, "END");
  if (err)
    {
      log_error (_("error sending data: %s\n"), gpg_strerror (err));
      goto leave;
    }

 leave:

  return err;
}


/* Send the certificate, flush the buffer and then send an END. */
static gpg_error_t
return_one_cert (void *opaque, ksba_cert_t cert)
{
  assuan_context_t ctx = opaque;
  gpg_error_t err;
  const unsigned char *der;
  size_t derlen;

  der = ksba_cert_get_image (cert, &derlen);
  if (!der)
    err = gpg_error (GPG_ERR_INV_CERT_OBJ);
  else
    {
      err = assuan_send_data (ctx, der, derlen);
      if (!err)
        err = assuan_send_data (ctx, NULL, 0);
      if (!err)
        err = assuan_write_line (ctx, "END");
    }
  if (err)
    log_error (_("error sending data: %s\n"), gpg_strerror (err));
  return err;
}


/* Lookup certificates from the internal cache or using the ldap
   servers. */
static int
lookup_cert_by_pattern (assuan_context_t ctx, char *line,
                        int single, int cache_only)
{
  gpg_error_t err = 0;
  char *p;
  strlist_t sl, list = NULL;
  int truncated = 0, truncation_forced = 0;
  int count = 0;
  int local_count = 0;
#if USE_LDAP
  ctrl_t ctrl = assuan_get_pointer (ctx);
  unsigned char *value = NULL;
  size_t valuelen;
  struct ldapserver_iter ldapserver_iter;
  cert_fetch_context_t fetch_context;
#endif /*USE_LDAP*/
  int any_no_data = 0;

  /* Break the line down into an STRLIST */
  for (p=line; *p; line = p)
    {
      while (*p && *p != ' ')
        p++;
      if (*p)
        *p++ = 0;

      if (*line)
        {
          sl = xtrymalloc (sizeof *sl + strlen (line));
          if (!sl)
            {
              err = gpg_error_from_errno (errno);
              goto leave;
            }
          memset (sl, 0, sizeof *sl);
          strcpy_escaped_plus (sl->d, line);
          sl->next = list;
          list = sl;
        }
    }

  /* First look through the internal cache.  The certificates returned
     here are not counted towards the truncation limit.  */
  if (single && !cache_only)
    ; /* Do not read from the local cache in this case.  */
  else
    {
      for (sl=list; sl; sl = sl->next)
        {
          err = get_certs_bypattern (sl->d, return_one_cert, ctx);
          if (!err)
            local_count++;
          if (!err && single)
            goto ready;

          if (gpg_err_code (err) == GPG_ERR_NO_DATA
              || gpg_err_code (err) == GPG_ERR_NOT_FOUND)
            {
              err = 0;
              if (cache_only)
                any_no_data = 1;
            }
          else if (gpg_err_code (err) == GPG_ERR_INV_NAME && !cache_only)
            {
              /* No real fault because the internal pattern lookup
                 can't yet cope with all types of pattern.  */
              err = 0;
            }
          if (err)
            goto ready;
        }
    }

  /* Loop over all configured servers unless we want only the
     certificates from the cache.  */
#if USE_LDAP
  for (ldapserver_iter_begin (&ldapserver_iter, ctrl);
       !cache_only && !ldapserver_iter_end_p (&ldapserver_iter)
	 && ldapserver_iter.server->host && !truncation_forced;
       ldapserver_iter_next (&ldapserver_iter))
    {
      ldap_server_t ldapserver = ldapserver_iter.server;

      if (DBG_LOOKUP)
        log_debug ("cmd_lookup: trying %s:%d base=%s\n",
                   ldapserver->host, ldapserver->port,
                   ldapserver->base?ldapserver->base : "[default]");

      /* Fetch certificates matching pattern */
      err = start_cert_fetch (ctrl, &fetch_context, list, ldapserver);
      if ( gpg_err_code (err) == GPG_ERR_NO_DATA )
        {
          if (DBG_LOOKUP)
            log_debug ("cmd_lookup: no data\n");
          err = 0;
          any_no_data = 1;
          continue;
        }
      if (err)
        {
          log_error (_("start_cert_fetch failed: %s\n"), gpg_strerror (err));
          goto leave;
        }

      /* Fetch the certificates for this query. */
      while (!truncation_forced)
        {
          xfree (value); value = NULL;
          err = fetch_next_cert (fetch_context, &value, &valuelen);
          if (gpg_err_code (err) == GPG_ERR_NO_DATA )
            {
              err = 0;
              any_no_data = 1;
              break; /* Ready. */
            }
          if (gpg_err_code (err) == GPG_ERR_TRUNCATED)
            {
              truncated = 1;
              err = 0;
              break;  /* Ready.  */
            }
          if (gpg_err_code (err) == GPG_ERR_EOF)
            {
              err = 0;
              break; /* Ready. */
            }
          if (!err && !value)
            {
              err = gpg_error (GPG_ERR_BUG);
              goto leave;
            }
          if (err)
            {
              log_error (_("fetch_next_cert failed: %s\n"),
                         gpg_strerror (err));
              end_cert_fetch (fetch_context);
              goto leave;
            }

          if (DBG_LOOKUP)
            log_debug ("cmd_lookup: returning one cert%s\n",
                       truncated? " (truncated)":"");

          /* Send the data, flush the buffer and then send an END line
             as a certificate delimiter. */
          err = assuan_send_data (ctx, value, valuelen);
          if (!err)
            err = assuan_send_data (ctx, NULL, 0);
          if (!err)
            err = assuan_write_line (ctx, "END");
          if (err)
            {
              log_error (_("error sending data: %s\n"), gpg_strerror (err));
              end_cert_fetch (fetch_context);
              goto leave;
            }

          if (++count >= opt.max_replies )
            {
              truncation_forced = 1;
              log_info (_("max_replies %d exceeded\n"), opt.max_replies );
            }
          if (single)
            break;
        }

      end_cert_fetch (fetch_context);
    }
#endif /*USE_LDAP*/

 ready:
  if (truncated || truncation_forced)
    {
      char str[50];

      sprintf (str, "%d", count);
      assuan_write_status (ctx, "TRUNCATED", str);
    }

  if (!err && !count && !local_count && any_no_data)
    err = gpg_error (GPG_ERR_NO_DATA);

 leave:
  free_strlist (list);
  return err;
}


static const char hlp_lookup[] =
  "LOOKUP [--url] [--single] [--cache-only] <pattern>\n"
  "\n"
  "Lookup certificates matching PATTERN. With --url the pattern is\n"
  "expected to be one URL.\n"
  "\n"
  "If --url is not given:  To allow for multiple patterns (which are ORed)\n"
  "quoting is required: Spaces are translated to \"+\" or \"%20\";\n"
  "obviously this requires that the usual escape quoting rules are applied.\n"
  "\n"
  "If --url is given no special escaping is required because URLs are\n"
  "already escaped this way.\n"
  "\n"
  "If --single is given the first and only the first match will be\n"
  "returned.  If --cache-only is _not_ given, no local query will be\n"
  "done.\n"
  "\n"
  "If --cache-only is given no external lookup is done so that only\n"
  "certificates from the cache may get returned.";
static gpg_error_t
cmd_lookup (assuan_context_t ctx, char *line)
{
  gpg_error_t err;
  int lookup_url, single, cache_only;

  lookup_url = has_leading_option (line, "--url");
  single = has_leading_option (line, "--single");
  cache_only = has_leading_option (line, "--cache-only");
  line = skip_options (line);

  if (lookup_url && cache_only)
    err = gpg_error (GPG_ERR_NOT_FOUND);
  else if (lookup_url && single)
    err = gpg_error (GPG_ERR_NOT_IMPLEMENTED);
  else if (lookup_url)
    err = lookup_cert_by_url (ctx, line);
  else
    err = lookup_cert_by_pattern (ctx, line, single, cache_only);

  return leave_cmd (ctx, err);
}


static const char hlp_loadcrl[] =
  "LOADCRL [--url] <filename|url>\n"
  "\n"
  "Load the CRL in the file with name FILENAME into our cache.  Note\n"
  "that FILENAME should be given with an absolute path because\n"
  "Dirmngrs cwd is not known.  With --url the CRL is directly loaded\n"
  "from the given URL.\n"
  "\n"
  "This command is usually used by gpgsm using the invocation \"gpgsm\n"
  "--call-dirmngr loadcrl <filename>\".  A direct invocation of Dirmngr\n"
  "is not useful because gpgsm might need to callback gpgsm to ask for\n"
  "the CA's certificate.";
static gpg_error_t
cmd_loadcrl (assuan_context_t ctx, char *line)
{
  ctrl_t ctrl = assuan_get_pointer (ctx);
  gpg_error_t err = 0;
  int use_url = has_leading_option (line, "--url");

  line = skip_options (line);

  if (use_url)
    {
      ksba_reader_t reader;

      err = crl_fetch (ctrl, line, &reader);
      if (err)
        log_error (_("fetching CRL from '%s' failed: %s\n"),
                   line, gpg_strerror (err));
      else
        {
          err = crl_cache_insert (ctrl, line, reader);
          if (err)
            log_error (_("processing CRL from '%s' failed: %s\n"),
                       line, gpg_strerror (err));
          crl_close_reader (reader);
        }
    }
  else
    {
      char *buf;

      buf = xtrymalloc (strlen (line)+1);
      if (!buf)
        err = gpg_error_from_syserror ();
      else
        {
          strcpy_escaped_plus (buf, line);
          err = crl_cache_load (ctrl, buf);
          xfree (buf);
        }
    }

  return leave_cmd (ctx, err);
}


static const char hlp_listcrls[] =
  "LISTCRLS\n"
  "\n"
  "List the content of all CRLs in a readable format.  This command is\n"
  "usually used by gpgsm using the invocation \"gpgsm --call-dirmngr\n"
  "listcrls\".  It may also be used directly using \"dirmngr\n"
  "--list-crls\".";
static gpg_error_t
cmd_listcrls (assuan_context_t ctx, char *line)
{
  gpg_error_t err;
  estream_t fp;

  (void)line;

  fp = es_fopencookie (ctx, "w", data_line_cookie_functions);
  if (!fp)
    err = set_error (GPG_ERR_ASS_GENERAL, "error setting up a data stream");
  else
    {
      err = crl_cache_list (fp);
      es_fclose (fp);
    }
  return leave_cmd (ctx, err);
}


static const char hlp_cachecert[] =
  "CACHECERT\n"
  "\n"
  "Put a certificate into the internal cache.  This command might be\n"
  "useful if a client knows in advance certificates required for a\n"
  "test and wants to make sure they get added to the internal cache.\n"
  "It is also helpful for debugging.  To get the actual certificate,\n"
  "this command immediately inquires it using\n"
  "\n"
  "  INQUIRE TARGETCERT\n"
  "\n"
  "and the caller is expected to return the certificate for the\n"
  "request as a binary blob.";
static gpg_error_t
cmd_cachecert (assuan_context_t ctx, char *line)
{
  ctrl_t ctrl = assuan_get_pointer (ctx);
  gpg_error_t err;
  ksba_cert_t cert = NULL;
  unsigned char *value = NULL;
  size_t valuelen;

  (void)line;

  err = assuan_inquire (ctrl->server_local->assuan_ctx, "TARGETCERT",
                       &value, &valuelen, MAX_CERT_LENGTH);
  if (err)
    {
      log_error (_("assuan_inquire failed: %s\n"), gpg_strerror (err));
      goto leave;
    }

  if (!valuelen) /* No data returned; return a comprehensible error. */
    err = gpg_error (GPG_ERR_MISSING_CERT);
  else
    {
      err = ksba_cert_new (&cert);
      if (!err)
        err = ksba_cert_init_from_mem (cert, value, valuelen);
    }
  xfree (value);
  if(err)
    goto leave;

  err = cache_cert (cert);

 leave:
  ksba_cert_release (cert);
  return leave_cmd (ctx, err);
}


static const char hlp_validate[] =
  "VALIDATE [--systrust] [--tls] [--no-crl]\n"
  "\n"
  "Validate a certificate using the certificate validation function\n"
  "used internally by dirmngr.  This command is only useful for\n"
  "debugging.  To get the actual certificate, this command immediately\n"
  "inquires it using\n"
  "\n"
  "  INQUIRE TARGETCERT\n"
  "\n"
  "and the caller is expected to return the certificate for the\n"
  "request as a binary blob.  The option --tls modifies this by asking\n"
  "for list of certificates with\n"
  "\n"
  "  INQUIRE CERTLIST\n"
  "\n"
  "Here the first certificate is the target certificate, the remaining\n"
  "certificates are suggested intermediary certificates.  All certificates\n"
  "need to be PEM encoded.\n"
  "\n"
  "The option --systrust changes the behaviour to include the system\n"
  "provided root certificates as trust anchors.  The option --no-crl\n"
  "skips CRL checks";
static gpg_error_t
cmd_validate (assuan_context_t ctx, char *line)
{
  ctrl_t ctrl = assuan_get_pointer (ctx);
  gpg_error_t err;
  ksba_cert_t cert = NULL;
  certlist_t certlist = NULL;
  unsigned char *value = NULL;
  size_t valuelen;
  int systrust_mode, tls_mode, no_crl;

  systrust_mode = has_option (line, "--systrust");
  tls_mode = has_option (line, "--tls");
  no_crl = has_option (line, "--no-crl");
  line = skip_options (line);

  if (tls_mode)
    err = assuan_inquire (ctrl->server_local->assuan_ctx, "CERTLIST",
                          &value, &valuelen, MAX_CERTLIST_LENGTH);
  else
    err = assuan_inquire (ctrl->server_local->assuan_ctx, "TARGETCERT",
                          &value, &valuelen, MAX_CERT_LENGTH);
  if (err)
    {
      log_error (_("assuan_inquire failed: %s\n"), gpg_strerror (err));
      goto leave;
    }

  if (!valuelen) /* No data returned; return a comprehensible error. */
    err = gpg_error (GPG_ERR_MISSING_CERT);
  else if (tls_mode)
    {
      estream_t fp;

      fp = es_fopenmem_init (0, "rb", value, valuelen);
      if (!fp)
        err = gpg_error_from_syserror ();
      else
        {
          err = read_certlist_from_stream (&certlist, fp);
          es_fclose (fp);
          if (!err && !certlist)
            err = gpg_error (GPG_ERR_MISSING_CERT);
          if (!err)
            {
              /* Extract the first certificate from the list.  */
              cert = certlist->cert;
              ksba_cert_ref (cert);
            }
        }
    }
  else
    {
      err = ksba_cert_new (&cert);
      if (!err)
        err = ksba_cert_init_from_mem (cert, value, valuelen);
    }
  xfree (value);
  if(err)
    goto leave;

  if (!tls_mode)
    {
      /* If we have this certificate already in our cache, use the
       * cached version for validation because this will take care of
       * any cached results.  We don't need to do this in tls mode
       * because this has already been done for certificate in a
       * certlist_t. */
      unsigned char fpr[20];
      ksba_cert_t tmpcert;

      cert_compute_fpr (cert, fpr);
      tmpcert = get_cert_byfpr (fpr);
      if (tmpcert)
        {
          ksba_cert_release (cert);
          cert = tmpcert;
        }
    }

  /* Quick hack to make verification work by inserting the supplied
   * certs into the cache.  */
  if (tls_mode && certlist)
    {
      certlist_t cl;

      for (cl = certlist->next; cl; cl = cl->next)
        cache_cert (cl->cert);
    }

  err = validate_cert_chain (ctrl, cert, NULL,
                             (VALIDATE_FLAG_TRUST_CONFIG
                              | (tls_mode ? VALIDATE_FLAG_TLS : 0)
                              | (systrust_mode ? VALIDATE_FLAG_TRUST_SYSTEM : 0)
                              | (no_crl ? VALIDATE_FLAG_NOCRLCHECK : 0)),
                             NULL);

 leave:
  ksba_cert_release (cert);
  release_certlist (certlist);
  return leave_cmd (ctx, err);
}



/* Parse an keyserver URI and store it in a new uri item which is
   returned at R_ITEM.  On error return an error code.  */
static gpg_error_t
make_keyserver_item (const char *uri, uri_item_t *r_item)
{
  /* We used to have DNS CNAME redirection from the URLs below to
   * sks-keyserver. pools.  The idea was to allow for a quick way to
   * switch to a different set of pools.  The problem with that
   * approach is that TLS needs to verify the hostname and - because
   * DNS is not secured - it can only check the user supplied hostname
   * and not a hostname from a CNAME RR.  Thus the final server all
   * need to have certificates with the actual pool name as well as
   * for keys.gnupg.net - that would render the advantage of
   * keys.gnupg.net useless and so we better give up on this.  Because
   * the keys.gnupg.net URL are still in widespread use we do a static
   * mapping here.
   */
  if (!strcmp (uri, "hkps://keys.gnupg.net")
      || !strcmp (uri, "keys.gnupg.net"))
    uri = "hkps://keyserver.ubuntu.com";
  else if (!strcmp (uri, "https://keys.gnupg.net"))
    uri = "hkps://keyserver.ubuntu.com";
  else if (!strcmp (uri, "hkp://keys.gnupg.net"))
    uri = "hkp://pgp.surf.nl";
  else if (!strcmp (uri, "http://keys.gnupg.net"))
    uri = "hkp://pgp.surf.nl:80";
  else if (!strcmp (uri, "hkps://http-keys.gnupg.net")
           || !strcmp (uri, "http-keys.gnupg.net"))
    uri = "hkps://keyserver.ubuntu.com";
  else if (!strcmp (uri, "https://http-keys.gnupg.net"))
    uri = "hkps://keyserver.ubuntu.com";
  else if (!strcmp (uri, "hkp://http-keys.gnupg.net"))
    uri = "hkp://pgp.surf.nl";
  else if (!strcmp (uri, "http://http-keys.gnupg.net"))
    uri = "hkp://pgp.surf.nl:80";

  return ks_action_parse_uri (uri, r_item);
}


/* If no keyserver is stored in CTRL but a global keyserver has been
   set, put that global keyserver into CTRL.  We need use this
   function to help migrate from the old gpg based keyserver
   configuration to the new dirmngr based configuration.  */
static gpg_error_t
ensure_keyserver (ctrl_t ctrl)
{
  gpg_error_t err;
  uri_item_t item;
  uri_item_t onion_items = NULL;
  uri_item_t plain_items = NULL;
  uri_item_t ui;
  strlist_t sl;
  int none_seen = 1;

  if (ctrl->server_local->keyservers)
    return 0; /* Already set for this session.  */
  if (!opt.keyserver)
    {
      /* No global option set.  Fall back to default:  */
      return make_keyserver_item (DIRMNGR_DEFAULT_KEYSERVER,
                                  &ctrl->server_local->keyservers);
    }

  for (sl = opt.keyserver; sl; sl = sl->next)
    {
      /* Frontends like Kleopatra may prefix option values without a
       * scheme with "hkps://".  Thus we need to check that too.
       * Nobody will be mad enough to call a machine "none".  */
      if (!strcmp (sl->d, "none") || !strcmp (sl->d, "hkp://none")
          || !strcmp (sl->d, "hkps://none"))
        {
          none_seen = 1;
          continue;
        }
      err = make_keyserver_item (sl->d, &item);
      if (err)
        goto leave;
      if (item->parsed_uri->onion)
        {
          item->next = onion_items;
          onion_items = item;
        }
      else
        {
          item->next = plain_items;
          plain_items = item;
        }
    }

  if (none_seen && !plain_items && !onion_items)
    {
      err = gpg_error (GPG_ERR_NO_KEYSERVER);
      goto leave;
    }

  /* Decide which to use.  Note that the session has no keyservers
     yet set. */
  if (onion_items && !onion_items->next && plain_items && !plain_items->next)
    {
      /* If there is just one onion and one plain keyserver given, we take
         only one depending on whether Tor is running or not.  */
      if (!dirmngr_never_use_tor_p () && is_tor_running (ctrl))
        {
          ctrl->server_local->keyservers = onion_items;
          onion_items = NULL;
        }
      else
        {
          ctrl->server_local->keyservers = plain_items;
          plain_items = NULL;
        }
    }
  else if (dirmngr_never_use_tor_p () || !is_tor_running (ctrl))
    {
      /* Tor is not running.  It does not make sense to add Onion
         addresses.  */
      ctrl->server_local->keyservers = plain_items;
      plain_items = NULL;
    }
  else
    {
      /* In all other cases add all keyservers.  */
      ctrl->server_local->keyservers = onion_items;
      onion_items = NULL;
      for (ui = ctrl->server_local->keyservers; ui && ui->next; ui = ui->next)
        ;
      if (ui)
        ui->next = plain_items;
      else
        ctrl->server_local->keyservers = plain_items;
      plain_items = NULL;
    }

 leave:
  release_uri_item_list (onion_items);
  release_uri_item_list (plain_items);

  return err;
}


static const char hlp_keyserver[] =
  "KEYSERVER [<options>] [<uri>|<host>]\n"
  "Options are:\n"
  "  --help\n"
  "  --clear      Remove all configured keyservers\n"
  "  --resolve    Resolve HKP host names and rotate\n"
  "  --hosttable  Print table of known hosts and pools\n"
  "  --dead       Mark <host> as dead\n"
  "  --alive      Mark <host> as alive\n"
  "\n"
  "If called without arguments list all configured keyserver URLs.\n"
  "If called with an URI add this as keyserver.  Note that keyservers\n"
  "are configured on a per-session base.  A default keyserver may already be\n"
  "present, thus the \"--clear\" option must be used to get full control.\n"
  "If \"--clear\" and an URI are used together the clear command is\n"
  "obviously executed first.  A RESET command does not change the list\n"
  "of configured keyservers.";
static gpg_error_t
cmd_keyserver (assuan_context_t ctx, char *line)
{
  ctrl_t ctrl = assuan_get_pointer (ctx);
  gpg_error_t err = 0;
  int clear_flag, add_flag, help_flag, host_flag, resolve_flag;
  int dead_flag, alive_flag;
  uri_item_t item = NULL;

  clear_flag = has_option (line, "--clear");
  help_flag = has_option (line, "--help");
  resolve_flag = has_option (line, "--resolve");
  host_flag = has_option (line, "--hosttable");
  dead_flag = has_option (line, "--dead");
  alive_flag = has_option (line, "--alive");
  line = skip_options (line);
  add_flag = !!*line;

  if (help_flag)
    {
      err = ks_action_help (ctrl, line);
      goto leave;
    }

  if (resolve_flag)
    {
      err = ensure_keyserver (ctrl);
      if (err)
        {
          assuan_set_error (ctx, err,
                            "Bad keyserver configuration in dirmngr.conf");
          goto leave;
        }
      err = ks_action_resolve (ctrl, ctrl->server_local->keyservers);
      if (err)
        goto leave;
    }

  if (alive_flag && dead_flag)
    {
      err = set_error (GPG_ERR_ASS_PARAMETER, "no support for zombies");
      goto leave;
    }
  if (dead_flag)
    {
      err = check_owner_permission (ctx, "no permission to use --dead");
      if (err)
        goto leave;
    }
  if (alive_flag || dead_flag)
    {
      if (!*line)
        {
          err = set_error (GPG_ERR_ASS_PARAMETER, "name of host missing");
          goto leave;
        }

      err = ks_hkp_mark_host (ctrl, line, alive_flag);
      if (err)
        goto leave;
    }

  if (host_flag)
    {
      err = ks_hkp_print_hosttable (ctrl);
      if (err)
        goto leave;
    }
  if (resolve_flag || host_flag || alive_flag || dead_flag)
    goto leave;

  if (add_flag)
    {
      if (!strcmp (line, "none") || !strcmp (line, "hkp://none")
          || !strcmp (line, "hkps://none"))
        err = 0;
      else
        err = make_keyserver_item (line, &item);
      if (err)
        goto leave;
    }
  if (clear_flag)
    release_ctrl_keyservers (ctrl);
  if (add_flag && item)
    {
      item->next = ctrl->server_local->keyservers;
      ctrl->server_local->keyservers = item;
    }

  if (!add_flag && !clear_flag && !help_flag)
    {
      /* List configured keyservers.  However, we first add a global
         keyserver. */
      uri_item_t u;

      err = ensure_keyserver (ctrl);
      if (err)
        {
          assuan_set_error (ctx, err,
                            "Bad keyserver configuration in dirmngr.conf");
          goto leave;
        }

      for (u=ctrl->server_local->keyservers; u; u = u->next)
        dirmngr_status (ctrl, "KEYSERVER", u->uri, NULL);
    }
  err = 0;

 leave:
  return leave_cmd (ctx, err);
}



static const char hlp_ks_search[] =
  "KS_SEARCH {<pattern>}\n"
  "\n"
  "Search the configured OpenPGP keyservers (see command KEYSERVER)\n"
  "for keys matching PATTERN";
static gpg_error_t
cmd_ks_search (assuan_context_t ctx, char *line)
{
  ctrl_t ctrl = assuan_get_pointer (ctx);
  gpg_error_t err;
  strlist_t list, sl;
  char *p;
  estream_t outfp;

  if (has_option (line, "--quick"))
    ctrl->timeout = opt.connect_quick_timeout;
  line = skip_options (line);

  /* Break the line down into an strlist.  Each pattern is
     percent-plus escaped. */
  list = NULL;
  for (p=line; *p; line = p)
    {
      while (*p && *p != ' ')
        p++;
      if (*p)
        *p++ = 0;
      if (*line)
        {
          sl = xtrymalloc (sizeof *sl + strlen (line));
          if (!sl)
            {
              err = gpg_error_from_syserror ();
              goto leave;
            }
          sl->flags = 0;
          strcpy_escaped_plus (sl->d, line);
          sl->next = list;
          list = sl;
        }
    }

  err = ensure_keyserver (ctrl);
  if (err)
    goto leave;

  /* Setup an output stream and perform the search.  */
  outfp = es_fopencookie (ctx, "w", data_line_cookie_functions);
  if (!outfp)
    err = set_error (GPG_ERR_ASS_GENERAL, "error setting up a data stream");
  else
    {
      err = ks_action_search (ctrl, ctrl->server_local->keyservers,
			      list, outfp);
      es_fclose (outfp);
    }

 leave:
  free_strlist (list);
  return leave_cmd (ctx, err);
}



static const char hlp_ks_get[] =
  "KS_GET [--quick] [--newer=TIME] [--ldap] [--first|--next] {<pattern>}\n"
  "\n"
  "Get the keys matching PATTERN from the configured OpenPGP keyservers\n"
  "(see command KEYSERVER).  Each pattern should be a keyid, a fingerprint,\n"
  "or an exact name indicated by the '=' prefix.  Option --quick uses a\n"
  "shorter timeout; --ldap will use only ldap servers.  With --first only\n"
  "the first item is returned; --next is used to return the next item\n"
  "Option --newer works only with certain LDAP servers.";
static gpg_error_t
cmd_ks_get (assuan_context_t ctx, char *line)
{
  ctrl_t ctrl = assuan_get_pointer (ctx);
  gpg_error_t err;
  strlist_t list = NULL;
  strlist_t sl;
  const char *s;
  char *p;
  estream_t outfp;
  unsigned int flags = 0;
  gnupg_isotime_t opt_newer;

  *opt_newer = 0;

  if (has_option (line, "--quick"))
    ctrl->timeout = opt.connect_quick_timeout;
  if (has_option (line, "--ldap"))
    flags |= KS_GET_FLAG_ONLY_LDAP;
  if (has_option (line, "--first"))
    flags |= KS_GET_FLAG_FIRST;
  if (has_option (line, "--next"))
    flags |= KS_GET_FLAG_NEXT;
  if ((s = option_value (line, "--newer"))
      && !string2isotime (opt_newer, s))
    {
      err = set_error (GPG_ERR_SYNTAX, "invalid time format");
      goto leave;
    }
  line = skip_options (line);

  /* Break the line into a strlist.  Each pattern is by
     definition percent-plus escaped.  However we only support keyids
     and fingerprints and thus the client has no need to apply the
     escaping.  */
  for (p=line; *p; line = p)
    {
      while (*p && *p != ' ')
        p++;
      if (*p)
        *p++ = 0;
      if (*line)
        {
          sl = xtrymalloc (sizeof *sl + strlen (line));
          if (!sl)
            {
              err = gpg_error_from_syserror ();
              goto leave;
            }
          sl->flags = 0;
          strcpy_escaped_plus (sl->d, line);
          sl->next = list;
          list = sl;
        }
    }

  if ((flags & KS_GET_FLAG_FIRST) && !(flags & KS_GET_FLAG_ONLY_LDAP))
    {
      err = PARM_ERROR ("--first is only supported with --ldap");
      goto leave;
    }

  if (list && list->next && (flags & KS_GET_FLAG_FIRST))
    {
      /* ks_action_get loops over the pattern and we can't easily keep
       * this state.  */
      err = PARM_ERROR ("Only one pattern allowed with --first");
      goto leave;
    }

  if (!list && (flags & KS_GET_FLAG_FIRST))
    {
      /* Need to add a dummy pattern if no pattern is given.  */
      if (!add_to_strlist_try (&list, ""))
        {
          err = gpg_error_from_syserror ();
          goto leave;
        }
    }


  if ((flags & KS_GET_FLAG_NEXT))
    {
      if (list || (flags & ~KS_GET_FLAG_NEXT))
        {
          err = PARM_ERROR ("No pattern or other options allowed with --next");
          goto leave;
        }
      /* Add a dummy pattern.  */
      if (!add_to_strlist_try (&list, ""))
        {
          err = gpg_error_from_syserror ();
          goto leave;
        }
    }


  err = ensure_keyserver (ctrl);
  if (err)
    goto leave;

  /* Setup an output stream and perform the get.  */
  outfp = es_fopencookie (ctx, "w", data_line_cookie_functions);
  if (!outfp)
    err = set_error (GPG_ERR_ASS_GENERAL, "error setting up a data stream");
  else
    {
      ctrl->server_local->inhibit_data_logging = 1;
      ctrl->server_local->inhibit_data_logging_now = 0;
      ctrl->server_local->inhibit_data_logging_count = 0;
      err = ks_action_get (ctrl, ctrl->server_local->keyservers,
                           list, flags, opt_newer, outfp);
      es_fclose (outfp);
      ctrl->server_local->inhibit_data_logging = 0;
    }

 leave:
  free_strlist (list);
  return leave_cmd (ctx, err);
}


static const char hlp_ks_fetch[] =
  "KS_FETCH <URL>\n"
  "\n"
  "Get the key(s) from URL.";
static gpg_error_t
cmd_ks_fetch (assuan_context_t ctx, char *line)
{
  ctrl_t ctrl = assuan_get_pointer (ctx);
  gpg_error_t err;
  estream_t outfp;

  if (has_option (line, "--quick"))
    ctrl->timeout = opt.connect_quick_timeout;
  line = skip_options (line);

  err = ensure_keyserver (ctrl);  /* FIXME: Why do we needs this here?  */
  if (err)
    goto leave;

  /* Setup an output stream and perform the get.  */
  outfp = es_fopencookie (ctx, "w", data_line_cookie_functions);
  if (!outfp)
    err = set_error (GPG_ERR_ASS_GENERAL, "error setting up a data stream");
  else
    {
      ctrl->server_local->inhibit_data_logging = 1;
      ctrl->server_local->inhibit_data_logging_now = 0;
      ctrl->server_local->inhibit_data_logging_count = 0;
      err = ks_action_fetch (ctrl, line, outfp);
      es_fclose (outfp);
      ctrl->server_local->inhibit_data_logging = 0;
    }

 leave:
  return leave_cmd (ctx, err);
}



static const char hlp_ks_put[] =
  "KS_PUT\n"
  "\n"
  "Send a key to the configured OpenPGP keyservers.  The actual key material\n"
  "is then requested by Dirmngr using\n"
  "\n"
  "  INQUIRE KEYBLOCK\n"
  "\n"
  "The client shall respond with a binary version of the keyblock (e.g.,\n"
  "the output of `gpg --export KEYID').  For LDAP\n"
  "keyservers Dirmngr may ask for meta information of the provided keyblock\n"
  "using:\n"
  "\n"
  "  INQUIRE KEYBLOCK_INFO\n"
  "\n"
  "The client shall respond with a colon delimited info lines (the output\n"
  "of 'gpg --list-keys --with-colons KEYID').\n";
static gpg_error_t
cmd_ks_put (assuan_context_t ctx, char *line)
{
  ctrl_t ctrl = assuan_get_pointer (ctx);
  gpg_error_t err;
  unsigned char *value = NULL;
  size_t valuelen;
  unsigned char *info = NULL;
  size_t infolen;

  /* No options for now.  */
  line = skip_options (line);

  err = ensure_keyserver (ctrl);
  if (err)
    goto leave;

  /* Ask for the key material.  */
  err = assuan_inquire (ctx, "KEYBLOCK",
                        &value, &valuelen, MAX_KEYBLOCK_LENGTH);
  if (err)
    {
      log_error (_("assuan_inquire failed: %s\n"), gpg_strerror (err));
      goto leave;
    }

  if (!valuelen) /* No data returned; return a comprehensible error. */
    {
      err = gpg_error (GPG_ERR_MISSING_CERT);
      goto leave;
    }

  /* Ask for the key meta data.  */
  err = assuan_inquire (ctx, "KEYBLOCK_INFO",
                        &info, &infolen, MAX_KEYBLOCK_LENGTH);
  if (err)
    {
      log_error (_("assuan_inquire failed: %s\n"), gpg_strerror (err));
      goto leave;
    }

  /* Send the key.  */
  err = ks_action_put (ctrl, ctrl->server_local->keyservers,
		       value, valuelen, info, infolen);

 leave:
  xfree (info);
  xfree (value);
  return leave_cmd (ctx, err);
}



static const char hlp_ad_query[] =
  "AD_QUERY [--first|--next] [--] <filter> \n"
  "\n"
  "Query properties from a Windows Active Directory.\n"
  "Options:\n"
  "\n"
  "  --rootdse        - Query the root using serverless binding,\n"
  "  --subst          - Substitute variables in the filter\n"
  "  --attr=<attribs> - Comma delimited list of attributes\n"
  "                     to return.\n"
  "  --help           - List supported variables\n"
  "\n"
  "Extended filter syntax is allowed:\n"
  "   ^[<base>][&<scope>]&[<filter>]\n"
  "Usual escaping rules apply.  An ampersand in <base> must\n"
  "doubled.  <scope> may be \"base\", \"one\", or \"sub\"."
  ;
static gpg_error_t
cmd_ad_query (assuan_context_t ctx, char *line)
{
  ctrl_t ctrl = assuan_get_pointer (ctx);
  gpg_error_t err;
  unsigned int flags = 0;
  const char *filter;
  estream_t outfp = NULL;
  char *p;
  char **opt_attr = NULL;
  const char *s;
  gnupg_isotime_t opt_newer;
  int opt_help = 0;

  *opt_newer = 0;

  /* No options for now.  */
  if (has_option (line, "--first"))
    flags |= KS_GET_FLAG_FIRST;
  if (has_option (line, "--next"))
    flags |= KS_GET_FLAG_NEXT;
  if (has_option (line, "--rootdse"))
    flags |= KS_GET_FLAG_ROOTDSE;
  if (has_option (line, "--subst"))
    flags |= KS_GET_FLAG_SUBST;
  if (has_option (line, "--help"))
    opt_help = 1;
  if ((s = option_value (line, "--newer"))
      && !string2isotime (opt_newer, s))
    {
      err = set_error (GPG_ERR_SYNTAX, "invalid time format");
      goto leave;
    }
  err = get_option_value (line, "--attr", &p);
  if (err)
    goto leave;
  if (p)
    {
      opt_attr = strtokenize (p, ",");
      if (!opt_attr)
        {
          err = gpg_error_from_syserror ();
          xfree (p);
          goto leave;
        }
      xfree (p);
    }
  line = skip_options (line);
  filter = line;

  if (opt_help)
    {
#if USE_LDAP
      ks_ldap_help_variables (ctrl);
#endif
      err = 0;
      goto leave;
    }

  if ((flags & KS_GET_FLAG_NEXT))
    {
      if (*filter || (flags & ~KS_GET_FLAG_NEXT))
        {
          err = PARM_ERROR ("No filter or other options allowed with --next");
          goto leave;
        }
    }

  /* Setup an output stream and perform the get.  */
  outfp = es_fopencookie (ctx, "w", data_line_cookie_functions);
  if (!outfp)
    {
      err = set_error (GPG_ERR_ASS_GENERAL, "error setting up a data stream");
      goto leave;
    }

  ctrl->server_local->inhibit_data_logging = 1;
  ctrl->server_local->inhibit_data_logging_now = 0;
  ctrl->server_local->inhibit_data_logging_count = 0;

  err = ks_action_query (ctrl,
                         (flags & KS_GET_FLAG_ROOTDSE)? NULL : "ldap:///",
                         flags, filter, opt_attr, opt_newer, outfp);

 leave:
  es_fclose (outfp);
  xfree (opt_attr);
  ctrl->server_local->inhibit_data_logging = 0;
  return leave_cmd (ctx, err);
}



static const char hlp_loadswdb[] =
  "LOADSWDB [--force]\n"
  "\n"
  "Load and verify the swdb.lst from the Net.";
static gpg_error_t
cmd_loadswdb (assuan_context_t ctx, char *line)
{
  ctrl_t ctrl = assuan_get_pointer (ctx);
  gpg_error_t err;

  err = dirmngr_load_swdb (ctrl, has_option (line, "--force"));

  return leave_cmd (ctx, err);
}



static const char hlp_getinfo[] =
  "GETINFO <what>\n"
  "\n"
  "Multi purpose command to return certain information.  \n"
  "Supported values of WHAT are:\n"
  "\n"
  "version     - Return the version of the program.\n"
  "pid         - Return the process id of the server.\n"
  "tor         - Return OK if running in Tor mode\n"
  "dnsinfo     - Return info about the DNS resolver\n"
  "socket_name - Return the name of the socket.\n"
  "session_id  - Return the current session_id.\n"
  "workqueue   - Inspect the work queue\n"
  "getenv NAME - Return value of envvar NAME\n";
static gpg_error_t
cmd_getinfo (assuan_context_t ctx, char *line)
{
  ctrl_t ctrl = assuan_get_pointer (ctx);
  gpg_error_t err;
  char numbuf[50];

  if (!strcmp (line, "version"))
    {
      const char *s = VERSION;
      err = assuan_send_data (ctx, s, strlen (s));
    }
  else if (!strcmp (line, "pid"))
    {
      snprintf (numbuf, sizeof numbuf, "%lu", (unsigned long)getpid ());
      err = assuan_send_data (ctx, numbuf, strlen (numbuf));
    }
  else if (!strcmp (line, "socket_name"))
    {
      const char *s = dirmngr_get_current_socket_name ();
      err = assuan_send_data (ctx, s, strlen (s));
    }
  else if (!strcmp (line, "session_id"))
    {
      snprintf (numbuf, sizeof numbuf, "%u", ctrl->server_local->session_id);
      err = assuan_send_data (ctx, numbuf, strlen (numbuf));
    }
  else if (!strcmp (line, "tor"))
    {
      int use_tor;

      use_tor = dirmngr_use_tor ();
      if (use_tor)
        {
          if (!is_tor_running (ctrl))
            err = assuan_write_status (ctx, "NO_TOR", "Tor not running");
          else
            err = 0;
          if (!err)
            assuan_set_okay_line (ctx, use_tor == 1 ? "- Tor mode is enabled"
                                  /**/              : "- Tor mode is enforced");
        }
      else
        err = set_error (GPG_ERR_FALSE, "Tor mode is NOT enabled");
    }
  else if (!strcmp (line, "dnsinfo"))
    {
      if (standard_resolver_p ())
        assuan_set_okay_line
          (ctx, "- Forced use of System resolver (w/o Tor support)");
      else
        {
#ifdef USE_LIBDNS
          assuan_set_okay_line (ctx, (recursive_resolver_p ()
                                      ? "- Libdns recursive resolver"
                                      : "- Libdns stub resolver"));
#else
          assuan_set_okay_line (ctx, "- System resolver (w/o Tor support)");
#endif
        }
      err = 0;
    }
  else if (!strcmp (line, "workqueue"))
    {
      workqueue_dump_queue (ctrl);
      err = 0;
    }
  else if (!strncmp (line, "getenv", 6)
           && (line[6] == ' ' || line[6] == '\t' || !line[6]))
    {
      line += 6;
      while (*line == ' ' || *line == '\t')
        line++;
      if (!*line)
        err = gpg_error (GPG_ERR_MISSING_VALUE);
      else
        {
          const char *s = getenv (line);
          if (!s)
            {
              err = set_error (GPG_ERR_NOT_FOUND, "No such envvar");
              goto leave;
            }
          err = assuan_send_data (ctx, s, strlen (s));
        }
    }
#ifdef HAVE_W32_SYSTEM
  else if (!strcmp (line, "sid"))
    {
      PSID mysid;
      char *sidstr;

      mysid = w32_get_user_sid ();
      if (!mysid)
        {
          err = set_error (GPG_ERR_NOT_FOUND, "Error getting my SID");
          goto leave;
        }

      if (!ConvertSidToStringSid (mysid, &sidstr))
        {
          err = set_error (GPG_ERR_BUG, "Error converting SID to a string");
          goto leave;
        }
      err = assuan_send_data (ctx, sidstr, strlen (sidstr));
      LocalFree (sidstr);
    }
#endif /*HAVE_W32_SYSTEM*/
  else
    err = set_error (GPG_ERR_ASS_PARAMETER, "unknown value for WHAT");

 leave:
  return leave_cmd (ctx, err);
}



static const char hlp_killdirmngr[] =
  "KILLDIRMNGR\n"
  "\n"
  "This command allows a user - given sufficient permissions -\n"
  "to kill this dirmngr process.\n";
static gpg_error_t
cmd_killdirmngr (assuan_context_t ctx, char *line)
{
  ctrl_t ctrl = assuan_get_pointer (ctx);

  (void)line;

  ctrl->server_local->stopme = 1;
  assuan_set_flag (ctx, ASSUAN_FORCE_CLOSE, 1);
  return 0;
}


static const char hlp_reloaddirmngr[] =
  "RELOADDIRMNGR\n"
  "\n"
  "This command is an alternative to SIGHUP\n"
  "to reload the configuration.";
static gpg_error_t
cmd_reloaddirmngr (assuan_context_t ctx, char *line)
{
  (void)ctx;
  (void)line;

  dirmngr_sighup_action ();
  return 0;
}


static const char hlp_flushcrls[] =
  "FLUSHCRLS\n"
  "\n"
  "Remove all cached CRLs from memory and\n"
  "the file system.";
static gpg_error_t
cmd_flushcrls (assuan_context_t ctx, char *line)
{
  (void)line;

  return leave_cmd (ctx, crl_cache_flush () ? GPG_ERR_GENERAL : 0);
}



/* Tell the assuan library about our commands. */
static int
register_commands (assuan_context_t ctx)
{
  static struct {
    const char *name;
    assuan_handler_t handler;
    const char * const help;
  } table[] = {
    { "DNS_CERT",   cmd_dns_cert,   hlp_dns_cert },
    { "WKD_GET",    cmd_wkd_get,    hlp_wkd_get },
    { "LDAPSERVER", cmd_ldapserver, hlp_ldapserver },
    { "ISVALID",    cmd_isvalid,    hlp_isvalid },
    { "CHECKCRL",   cmd_checkcrl,   hlp_checkcrl },
    { "CHECKOCSP",  cmd_checkocsp,  hlp_checkocsp },
    { "LOOKUP",     cmd_lookup,     hlp_lookup },
    { "LOADCRL",    cmd_loadcrl,    hlp_loadcrl },
    { "LISTCRLS",   cmd_listcrls,   hlp_listcrls },
    { "CACHECERT",  cmd_cachecert,  hlp_cachecert },
    { "VALIDATE",   cmd_validate,   hlp_validate },
    { "KEYSERVER",  cmd_keyserver,  hlp_keyserver },
    { "KS_SEARCH",  cmd_ks_search,  hlp_ks_search },
    { "KS_GET",     cmd_ks_get,     hlp_ks_get },
    { "KS_FETCH",   cmd_ks_fetch,   hlp_ks_fetch },
    { "KS_PUT",     cmd_ks_put,     hlp_ks_put },
    { "AD_QUERY",   cmd_ad_query,   hlp_ad_query },
    { "GETINFO",    cmd_getinfo,    hlp_getinfo },
    { "LOADSWDB",   cmd_loadswdb,   hlp_loadswdb },
    { "KILLDIRMNGR",cmd_killdirmngr,hlp_killdirmngr },
    { "RELOADDIRMNGR",cmd_reloaddirmngr,hlp_reloaddirmngr },
    { "FLUSHCRLS",  cmd_flushcrls,  hlp_flushcrls },
    { NULL, NULL }
  };
  int i, j, rc;

  for (i=j=0; table[i].name; i++)
    {
      rc = assuan_register_command (ctx, table[i].name, table[i].handler,
                                    table[i].help);
      if (rc)
        return rc;
    }
  return 0;
}


/* Note that we do not reset the list of configured keyservers.  */
static gpg_error_t
reset_notify (assuan_context_t ctx, char *line)
{
  ctrl_t ctrl = assuan_get_pointer (ctx);
  (void)line;

#if USE_LDAP
  ldapserver_list_free (ctrl->server_local->ldapservers);
#endif /*USE_LDAP*/
  ctrl->server_local->ldapservers = NULL;
  return 0;
}


/* This function is called by our assuan log handler to test whether a
 * log message shall really be printed.  The function must return
 * false to inhibit the logging of MSG.  CAT gives the requested log
 * category.  MSG might be NULL. */
int
dirmngr_assuan_log_monitor (assuan_context_t ctx, unsigned int cat,
                            const char *msg)
{
  ctrl_t ctrl = assuan_get_pointer (ctx);

  (void)cat;
  (void)msg;

  if (!ctrl || !ctrl->server_local)
    return 1; /* Can't decide - allow logging.  */

  if (!ctrl->server_local->inhibit_data_logging)
    return 1; /* Not requested - allow logging.  */

  /* Disallow logging if *_now is true.  */
  return !ctrl->server_local->inhibit_data_logging_now;
}


/* Startup the server and run the main command loop.  With FD = -1,
 * use stdin/stdout.  SESSION_ID is either 0 or a unique number
 * identifying a session.  */
void
start_command_handler (assuan_fd_t fd, unsigned int session_id)
{
  static const char hello[] = "Dirmngr " VERSION " at your service";
  static char *hello_line;
  int rc;
  assuan_context_t ctx;
  ctrl_t ctrl;

  ctrl = xtrycalloc (1, sizeof *ctrl);
  if (ctrl)
    ctrl->server_local = xtrycalloc (1, sizeof *ctrl->server_local);
  if (!ctrl || !ctrl->server_local)
    {
      log_error (_("can't allocate control structure: %s\n"),
                 strerror (errno));
      xfree (ctrl);
      return;
    }

  dirmngr_init_default_ctrl (ctrl);

  rc = assuan_new (&ctx);
  if (rc)
    {
      log_error (_("failed to allocate assuan context: %s\n"),
		 gpg_strerror (rc));
      dirmngr_exit (2);
    }

  if (fd == ASSUAN_INVALID_FD)
    {
      assuan_fd_t filedes[2];

      filedes[0] = assuan_fdopen (0);
      filedes[1] = assuan_fdopen (1);
      rc = assuan_init_pipe_server (ctx, filedes);
    }
  else
    {
      rc = assuan_init_socket_server (ctx, fd, ASSUAN_SOCKET_SERVER_ACCEPTED);
    }

  if (rc)
    {
      assuan_release (ctx);
      log_error (_("failed to initialize the server: %s\n"),
                 gpg_strerror(rc));
      dirmngr_exit (2);
    }

  rc = register_commands (ctx);
  if (rc)
    {
      log_error (_("failed to the register commands with Assuan: %s\n"),
                 gpg_strerror(rc));
      dirmngr_exit (2);
    }


  if (!hello_line)
    {
      hello_line = xtryasprintf
        ("Home: %s\n"
         "Config: %s\n"
         "%s",
         gnupg_homedir (),
         opt.config_filename? opt.config_filename : "[none]",
         hello);
    }

  ctrl->server_local->assuan_ctx = ctx;
  assuan_set_pointer (ctx, ctrl);

  assuan_set_hello_line (ctx, hello_line);
  assuan_register_option_handler (ctx, option_handler);
  assuan_register_reset_notify (ctx, reset_notify);

  ctrl->server_local->session_id = session_id;

  for (;;)
    {
      rc = assuan_accept (ctx);
      if (rc == -1)
        break;
      if (rc)
        {
          log_info (_("Assuan accept problem: %s\n"), gpg_strerror (rc));
          break;
        }

#ifndef HAVE_W32_SYSTEM
      if (opt.verbose)
        {
	  assuan_peercred_t peercred;

          if (!assuan_get_peercred (ctx, &peercred))
            log_info ("connection from process %ld (%ld:%ld)\n",
                      (long)peercred->pid, (long)peercred->uid,
		      (long)peercred->gid);
        }
#endif

      rc = assuan_process (ctx);
      if (rc)
        {
          log_info (_("Assuan processing failed: %s\n"), gpg_strerror (rc));
          continue;
        }
    }


#if USE_LDAP
  ldap_wrapper_connection_cleanup (ctrl);

  ldapserver_list_free (ctrl->server_local->ldapservers);
#endif /*USE_LDAP*/
  ctrl->server_local->ldapservers = NULL;

  release_ctrl_keyservers (ctrl);

  ctrl->server_local->assuan_ctx = NULL;
  assuan_release (ctx);

  if (ctrl->server_local->stopme)
    dirmngr_exit (0);

  if (ctrl->refcount)
    log_error ("oops: connection control structure still referenced (%d)\n",
               ctrl->refcount);
  else
    {
#if USE_LDAP
      ks_ldap_free_state (ctrl->ks_get_state);
      ctrl->ks_get_state = NULL;
#endif
      release_ctrl_ocsp_certs (ctrl);
      xfree (ctrl->server_local);
      dirmngr_deinit_default_ctrl (ctrl);
      xfree (ctrl);
    }
}


/* Send a status line back to the client.  KEYWORD is the status
   keyword, the optional string arguments are blank separated added to
   the line, the last argument must be a NULL. */
gpg_error_t
dirmngr_status (ctrl_t ctrl, const char *keyword, ...)
{
  gpg_error_t err = 0;
  va_list arg_ptr;
  assuan_context_t ctx;

  va_start (arg_ptr, keyword);

  if (ctrl->server_local && (ctx = ctrl->server_local->assuan_ctx))
    {
      err = vprint_assuan_status_strings (ctx, keyword, arg_ptr);
    }

  va_end (arg_ptr);
  return err;
}


/* Print a help status line.  The function splits text at LFs.  */
gpg_error_t
dirmngr_status_help (ctrl_t ctrl, const char *text)
{
  gpg_error_t err = 0;
  assuan_context_t ctx;

  if (ctrl->server_local && (ctx = ctrl->server_local->assuan_ctx))
    {
      char buf[950], *p;
      size_t n;

      do
        {
          p = buf;
          n = 0;
          for ( ; *text && *text != '\n' && n < DIM (buf)-2; n++)
            *p++ = *text++;
          if (*text == '\n')
            text++;
          *p = 0;
          err = assuan_write_status (ctx, "#", buf);
        }
      while (!err && *text);
    }

  return err;
}


/* Print a help status line using a printf like format.  The function
 * splits text at LFs.  */
gpg_error_t
dirmngr_status_helpf (ctrl_t ctrl, const char *format, ...)
{
  va_list arg_ptr;
  gpg_error_t err;
  char *buf;

  va_start (arg_ptr, format);
  buf = es_vbsprintf (format, arg_ptr);
  err = buf? 0 : gpg_error_from_syserror ();
  va_end (arg_ptr);
  if (!err)
    err = dirmngr_status_help (ctrl, buf);
  es_free (buf);
  return err;
}


/* This function is similar to print_assuan_status but takes a CTRL
 * arg instead of an assuan context as first argument.  */
gpg_error_t
dirmngr_status_printf (ctrl_t ctrl, const char *keyword,
                       const char *format, ...)
{
  gpg_error_t err;
  va_list arg_ptr;
  assuan_context_t ctx;

  if (!ctrl->server_local || !(ctx = ctrl->server_local->assuan_ctx))
    return 0;

  va_start (arg_ptr, format);
  err = vprint_assuan_status (ctx, keyword, format, arg_ptr);
  va_end (arg_ptr);
  return err;
}


/* Send a tick progress indicator back.  Fixme: This is only done for
   the currently active channel.  */
gpg_error_t
dirmngr_tick (ctrl_t ctrl)
{
  static time_t next_tick = 0;
  gpg_error_t err = 0;
  time_t now = time (NULL);

  if (!next_tick)
    {
      next_tick = now + 1;
    }
  else if ( now > next_tick )
    {
      if (ctrl)
        {
          err = dirmngr_status (ctrl, "PROGRESS", "tick", "? 0 0", NULL);
          if (err)
            {
              /* Take this as in indication for a cancel request.  */
              err = gpg_error (GPG_ERR_CANCELED);
            }
          now = time (NULL);
        }

      next_tick = now + 1;
    }
  return err;
}
