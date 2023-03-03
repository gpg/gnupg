/* ldap.c - LDAP access
 * Copyright (C) 2002 Klarälvdalens Datakonsult AB
 * Copyright (C) 2003, 2004, 2005, 2007, 2008, 2010, 2021 g10 Code GmbH
 *
 * This file is part of GnuPG.
 *
 * GnuPG is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 *
 * DirMngr is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, see <https://www.gnu.org/licenses/>.
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

#include <config.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <fcntl.h>
#include <time.h>
#include <npth.h>

#include "dirmngr.h"
#include "../common/exechelp.h"
#include "crlfetch.h"
#include "ldapserver.h"
#include "misc.h"
#include "ldap-wrapper.h"
#include "ldap-url.h"
#include "../common/host2net.h"


#define UNENCODED_URL_CHARS "abcdefghijklmnopqrstuvwxyz"   \
                            "ABCDEFGHIJKLMNOPQRSTUVWXYZ"   \
                            "01234567890"                  \
                            "$-_.+!*'(),"
#define USERCERTIFICATE "userCertificate"
#define CACERTIFICATE   "caCertificate"
#define X509CACERT      "x509caCert"
#define USERSMIMECERTIFICATE "userSMIMECertificate"


/* Definition for the context of the cert fetch functions. */
struct cert_fetch_context_s
{
  ksba_reader_t reader;  /* The reader used (shallow copy). */
  unsigned char *tmpbuf; /* Helper buffer.  */
  size_t tmpbufsize;     /* Allocated size of tmpbuf.  */
  int truncated;         /* Flag to indicate a truncated output.  */
};




/* Add HOST and PORT to our list of LDAP servers.  Fixme: We should
   better use an extra list of servers. */
static void
add_server_to_servers (const char *host, int port)
{
  ldap_server_t server;
  ldap_server_t last = NULL;
  const char *s;

  if (!port)
    port = 389;

  for (server=opt.ldapservers; server; server = server->next)
    {
      if (!strcmp (server->host, host) && server->port == port)
	  return; /* already in list... */
      last = server;
    }

  /* We assume that the host names are all supplied by our
     configuration files and thus are sane.  To keep this assumption
     we must reject all invalid host names. */
  for (s=host; *s; s++)
    if (!strchr ("abcdefghijklmnopqrstuvwxyz"
                 "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
                 "01234567890.-", *s))
      {
        log_error (_("invalid char 0x%02x in host name - not added\n"), *s);
        return;
      }

  log_info (_("adding '%s:%d' to the ldap server list\n"), host, port);
  server = xtrycalloc (1, sizeof *s);
  if (!server)
    log_error (_("malloc failed: %s\n"), strerror (errno));
  else
    {
      server->host = xstrdup (host);
      server->port = port;
      if (last)
        last->next = server;
      else
        opt.ldapservers = server;
    }
}




/* Perform an LDAP query.  Returns an gpg error code or 0 on success.
   The function returns a new reader object at READER. */
static gpg_error_t
run_ldap_wrapper (ctrl_t ctrl,
                  int ignore_timeout,
                  int multi_mode,
                  int tls_mode,
                  int ntds,
                  int areconly,
                  const char *proxy,
                  const char *host, int port,
                  const char *user, const char *pass,
                  const char *base, const char *filter, const char *attr,
                  ksba_reader_t *reader)
{
  const char *argv[51];
  int argc;
  char portbuf[30], timeoutbuf[30];


  *reader = NULL;

  argc = 0;
  if (pass && *pass)  /* Note, that the password must be the first item.  */
    {
      argv[argc++] = "--pass";
      argv[argc++] = pass;
    }

  if (DBG_LOOKUP)
    argv[argc++] = "-vv";
  else if (DBG_EXTPROG)
    argv[argc++] = "-v";

  argv[argc++] = "--log-with-pid";
  if (multi_mode)
    argv[argc++] = "--multi";

  if (tls_mode == 1)
    argv[argc++] = "--starttls";
  else if (tls_mode)
    argv[argc++] = "--ldaptls";

  if (ntds)
    argv[argc++] = "--ntds";

  if (areconly)
    argv[argc++] = "--areconly";

  if (opt.ldaptimeout)
    {
      snprintf (timeoutbuf, sizeof timeoutbuf, "%u", opt.ldaptimeout);
      argv[argc++] = "--timeout";
      argv[argc++] = timeoutbuf;
      if (ignore_timeout)
        argv[argc++] = "--only-search-timeout";
    }
  if (proxy)
    {
      argv[argc++] = "--proxy";
      argv[argc++] = proxy;
    }
  if (host && *host)
    {
      argv[argc++] = "--host";
      argv[argc++] = host;
    }
  if (port)
    {
      sprintf (portbuf, "%d", port);
      argv[argc++] = "--port";
      argv[argc++] = portbuf;
    }
  if (user && *user)
    {
      argv[argc++] = "--user";
      argv[argc++] = user;
    }
  if (base && *base)
    {
      argv[argc++] = "--base";
      argv[argc++] = base;
    }
  if (attr)
    {
      argv[argc++] = "--attr";
      argv[argc++] = attr;
    }

  if (filter)
    argv[argc++] = filter;
  argv[argc] = NULL;

  return ldap_wrapper (ctrl, reader, argv);
}




/* Perform a LDAP query using a given URL. On success a new ksba
   reader is returned.  If HOST or PORT are not 0, they are used to
   override the values from the URL. */
gpg_error_t
url_fetch_ldap (ctrl_t ctrl, const char *url, ksba_reader_t *reader)
{
  gpg_error_t err;
  LDAPURLDesc *ludp = NULL;
  int tls_mode;

  if (!ldap_is_ldap_url (url))
    {
      log_error (_("'%s' is not an LDAP URL\n"), url);
      return gpg_error (GPG_ERR_INV_URI);
    }

  if (ldap_url_parse (url, &ludp))
    {
      log_error (_("'%s' is an invalid LDAP URL\n"), url);
      return gpg_error (GPG_ERR_INV_URI);
    }

  if (ludp->lud_filter && ludp->lud_filter[0] != '(')
    {
      if (!strcmp (ludp->lud_filter, "objectClass=cRLDistributionPoint"))
        {
          /* Hack for broken DPs in DGN certs.  */
          log_info ("fixing broken LDAP URL\n");
          free (ludp->lud_filter);
          ludp->lud_filter
            = strdup ("(objectClass=cRLDistributionPoint)");
          if (!ludp->lud_filter)
            {
              err = gpg_error_from_syserror ();
              goto leave;
            }
        }
      else
        {
          log_error (_("'%s' is an invalid LDAP URL\n"), url);
          err = gpg_error (GPG_ERR_BAD_URI);
          goto leave;
        }
    }

  if (ludp->lud_scheme && !strcmp (ludp->lud_scheme, "ldaps"))
    tls_mode = 2; /* LDAP-over-TLS here becuase we get it from certs. */
  else
    tls_mode = 0;

  err = run_ldap_wrapper (ctrl,
                          1, /* Ignore explicit timeout because CRLs
                                might be very large. */
                          0, /* No Multi-mode.  */
                          tls_mode,
                          0, /* No AD authentication.  */
                          0, /* No areconly.  */
                          opt.ldap_proxy,
                          ludp->lud_host, ludp->lud_port,
                          NULL, NULL,  /* user, password */
                          ludp->lud_dn,    /* Base DN */
                          ludp->lud_filter,
                          ludp->lud_attrs? ludp->lud_attrs[0] : NULL,
                          reader);

  /* FIXME: This option might be used for DoS attacks.  Because it
     will enlarge the list of servers to consult without a limit and
     all LDAP queries w/o a host are will then try each host in
     turn. */
  if (!err && opt.add_new_ldapservers && !opt.ldap_proxy)
    {
      if (ludp->lud_host)
        add_server_to_servers (ludp->lud_host, ludp->lud_port);
    }

  /* If the lookup failed and we are not only using the proxy, we try
     again using our default list of servers.  */
  if (err && !(opt.ldap_proxy && opt.only_ldap_proxy))
    {
      struct ldapserver_iter iter;

      if (DBG_LOOKUP)
        log_debug ("no hostname in URL or query failed; "
                   "trying all default hostnames\n");

      for (ldapserver_iter_begin (&iter, ctrl);
	   err && ! ldapserver_iter_end_p (&iter);
	   ldapserver_iter_next (&iter))
        {
	  ldap_server_t server = iter.server;

          if (server->starttls)
            tls_mode = 1;
          else if (server->ldap_over_tls)
            tls_mode = 2;
          else
            tls_mode = 0;

          err = run_ldap_wrapper (ctrl,
                                  0,
                                  0, /* No Multi-mode */
                                  tls_mode,
                                  server->ntds,
                                  server->areconly,
                                  NULL,
                                  server->host, server->port,
                                  server->user, server->pass,
                                  server->base,
                                  ludp->lud_filter,
                                  ludp->lud_attrs? ludp->lud_attrs[0] : NULL,
                                  reader);
          if (!err)
            break;
        }
    }

 leave:
  ldap_free_urldesc (ludp);
  return err;
}



/* Perform an LDAP query on all configured servers.  On error the
   error code of the last try is returned.  */
gpg_error_t
attr_fetch_ldap (ctrl_t ctrl,
                 const char *dn, const char *attr, ksba_reader_t *reader)
{
  gpg_error_t err = gpg_error (GPG_ERR_CONFIGURATION);
  struct ldapserver_iter iter;

  *reader = NULL;

  /* FIXME; we might want to look at the Base DN to try matching
     servers first. */
  for (ldapserver_iter_begin (&iter, ctrl); ! ldapserver_iter_end_p (&iter);
       ldapserver_iter_next (&iter))
    {
      ldap_server_t server = iter.server;
      int tls_mode;

      if (server->starttls)
        tls_mode = 1;
      else if (server->ldap_over_tls)
        tls_mode = 2;
      else
        tls_mode = 0;

      err = run_ldap_wrapper (ctrl,
                              0,
                              0,
                              tls_mode,
                              server->ntds,
                              server->areconly,
                              opt.ldap_proxy,
                              server->host, server->port,
                              server->user, server->pass,
                              dn,
                              "(objectClass=*)",
                              attr,
                              reader);
      if (!err)
        break; /* Probably found a result. Ready. */
    }
  return err;
}



/* Return true if VALUE needs escaping.  */
static int
rfc2254_need_escape (const char *value)
{
  /* NUL needs to be escaped as well but we can represent that in
   * VALUE, so no need for it.  */
  return !!strpbrk (value, "*()\\");
}

/* Escape VALUE using RFC-2254 rules.  Returns NULL on error. */
static char *
rfc2254_escape (const char *value)
{
  const char *s;
  char *buffer, *p;
  size_t length = 0;

  for (s=value; *s; s++)
    switch (*s)
      {
      case '*':
      case '(':
      case ')':
      case '\\': length += 3; break;
      default:   length++; break;
      }

  buffer = xtrymalloc (length+1);
  if (!buffer)
    return NULL;
  p = buffer;
  for (s=value; *s; s++)
    switch (*s)
      {
      case '*':  p = stpcpy (p, "\\2a"); break;
      case '(':  p = stpcpy (p, "\\28"); break;
      case ')':  p = stpcpy (p, "\\29"); break;
      case '\\': p = stpcpy (p, "\\5c"); break;
      default:   *p++ = *s; break;
      }
  *p = 0;
  return buffer;
}


/* Return true if VALUE needs escaping.  */
static int
extfilt_need_escape (const char *value)
{
  /* NUL needs to be escaped as well but we can represent that in
   * VALUE, so no need for it.  */
  return !!strchr (value, '&');
}

/* Escape VALUE using our extended filter rules from dirmngr_ldap.c.
 * Returns NULL on error. */
static char *
extfilt_escape (const char *value)
{
  const char *s;
  char *buffer, *p;
  size_t length = 0;

  for (s=value; *s; s++)
    {
      length++;
      if (*s == '&')
        length++;
    }

  buffer = xtrymalloc (length+1);
  if (!buffer)
    return NULL;
  p = buffer;
  for (s=value; *s; s++)
    {
      *p++ = *s;
      if (*s == '&')
        *p++ = '&';
    }
  *p = 0;
  return buffer;
}


/* Parse PATTERN and return a new filter expression for an LDAP query.
 * The extended filter syntax as known by dirmngr_ldap.c is used.
 * Caller must release the returned value.  R_RESULT is set to NULL on
 * error.
 *
 * Supported patterns:
 *
 *  | Ok  | gpg style user id type                               |
 *  |-----+------------------------------------------------------|
 *  | no  | KeyID                                                |
 *  | no  | Fingerprint                                          |
 *  | no  | OpenPGP userid                                       |
 *  | yes | Email address  Indicated by a left angle bracket.    |
 *  | no  | Exact word match in user id or subj. name            |
 *  | yes | Subj. DN  indicated by a leading slash               |
 *  | no  | Issuer DN                                            |
 *  | no  | Serial number + subj. DN                             |
 *  | yes | Substring match indicated by a leading '*; (default) |
 */
static gpg_error_t
make_one_filter (const char *pattern, char **r_result)
{
  gpg_error_t err = 0;
  char *pattern_buffer = NULL;
  char *result = NULL;
  size_t n;

  *r_result = NULL;

  switch (*pattern)
    {
    case '<':			/* Email. */
      {
        pattern++;
        if (rfc2254_need_escape (pattern)
            && !(pattern = pattern_buffer = rfc2254_escape (pattern)))
          {
            err = gpg_error_from_syserror ();
            goto leave;
          }
        result = strconcat ("(mail=", pattern, ")", NULL);
        if (!result)
          {
            err = gpg_error_from_syserror ();
            goto leave;
          }
        n = strlen (result);
        if (result[n-2] == '>') /* Strip trailing '>' */
          {
            result[n-2] = ')';
            result[n-1] = 0;
          }
	break;
      }
    case '/':			/* Subject DN. */
      pattern++;
      if (*pattern)
        {
          /* We need just the BaseDN.  This assumes that the Subject
           * is correcly stored in the DT.  This is however not always
           * the case and the actual DN is different from the
           * subject.  In this case we won't find anything.  */
          if (extfilt_need_escape (pattern)
              && !(pattern = pattern_buffer = extfilt_escape (pattern)))
            {
              err = gpg_error_from_syserror ();
              goto leave;
            }
          result = strconcat ("^", pattern, "&base&", NULL);
          if (!result)
            {
              err = gpg_error_from_syserror ();
              goto leave;
            }
        }
      break;
    case '#':			/* Issuer DN - Not yet working. */
      pattern++;
      if (*pattern == '/')  /* Just issuer DN. */
        {
          pattern++;
          if (extfilt_need_escape (pattern)
              && !(pattern = pattern_buffer = extfilt_escape (pattern)))
            {
              err = gpg_error_from_syserror ();
              goto leave;
            }
          result = strconcat ("^", pattern, "&base&", NULL);
          if (!result)
            {
              err = gpg_error_from_syserror ();
              goto leave;
            }
	}
      else  /* Serial number + issuer DN */
	{

        }
      break;
    case '*':
      pattern++;
      /* fall through */
    default:			/* Take as substring match. */
      if (*pattern)
        {
          if (rfc2254_need_escape (pattern)
              && !(pattern = pattern_buffer = rfc2254_escape (pattern)))
            {
              err = gpg_error_from_syserror ();
              goto leave;
            }
          result = strconcat ("(|(sn=*", pattern,
                              "*)(|(cn=*", pattern,
                              "*)(mail=*", pattern,
                              "*)))", NULL);
          if (!result)
            {
              err = gpg_error_from_syserror ();
              goto leave;
            }
        }
      break;
    }

  if (!result)
    err = gpg_error (GPG_ERR_INV_USER_ID);

 leave:
  xfree (pattern_buffer);
  if (err)
    xfree (result);
  else
    *r_result = result;
  return err;
}



/* Prepare an LDAP query to return the cACertificate attribute for DN.
 * All configured default servers are queried until one responds.
 * This function returns an error code or 0 and stored a newly
 * allocated contect object at CONTEXT on success. */
gpg_error_t
start_cacert_fetch_ldap (ctrl_t ctrl, cert_fetch_context_t *r_context,
                         const char *dn)
{
  gpg_error_t err;
  struct ldapserver_iter iter;

  *r_context = xtrycalloc (1, sizeof **r_context);
  if (!*r_context)
    return gpg_error_from_errno (errno);

  /* FIXME; we might want to look at the Base DN to try matching
     servers first. */
  err = gpg_error (GPG_ERR_CONFIGURATION);

  for (ldapserver_iter_begin (&iter, ctrl); ! ldapserver_iter_end_p (&iter);
       ldapserver_iter_next (&iter))
    {
      ldap_server_t server = iter.server;

      err = run_ldap_wrapper (ctrl,
                              0,
                              1,  /* --multi (record format) */
                              0, /* No TLS */
                              0, /* No AD authentication.  */
                              server->areconly,
                              opt.ldap_proxy,
                              server->host, server->port,
                              server->user, server->pass,
                              dn, "objectClass=*", "cACertificate",
                              &(*r_context)->reader);
      if (!err)
        break; /* Probably found a result. */
    }

  if (err)
    {
      xfree (*r_context);
      *r_context = NULL;
    }
  return err;
}


/* Prepare an LDAP query to return certificates matching PATTERNS
 * using the SERVER.  This function returns an error code or 0 and
 * stores a newly allocated object at R_CONTEXT on success. */
gpg_error_t
start_cert_fetch_ldap (ctrl_t ctrl, cert_fetch_context_t *r_context,
                       strlist_t patterns, const ldap_server_t server)
{
  gpg_error_t err;
  char *proxy = NULL;
  char *host = NULL;
  int port;
  char *user = NULL;
  char *pass = NULL;
  char *base = NULL;
  char *argv[50];
  int argc = 0;
  int argc_malloced = 0;
  char portbuf[30], timeoutbuf[30];
  int starttls, ldaptls, ntds;

  *r_context = NULL;

  if (opt.ldap_proxy && !(proxy = xtrystrdup (opt.ldap_proxy)))
    {
      err = gpg_error_from_syserror ();
      goto leave;
    }

  if (server)
    {
      if (server->host && !(host = xtrystrdup (server->host)))
        {
          err = gpg_error_from_syserror ();
          goto leave;
        }
      port = server->port;
      if (server->user && !(user = xtrystrdup (server->user)))
        {
          err = gpg_error_from_syserror ();
          goto leave;
        }
      if (server->pass && !(pass = xtrystrdup (server->pass)))
        {
          err = gpg_error_from_syserror ();
          goto leave;
        }
      if (server->base && !(base = xtrystrdup (server->base)))
        {
          err = gpg_error_from_syserror ();
          goto leave;
        }

      starttls = server->starttls;
      ldaptls  =  server->ldap_over_tls;
      ntds     = server->ntds;
    }
  else /* Use a default server. */
    {
      err = gpg_error (GPG_ERR_NOT_IMPLEMENTED);
      goto leave;
    }


  if (pass && *pass) /* Note: Must be the first item. */
    {
      argv[argc++] = "--pass";
      argv[argc++] = pass;
    }

  if (DBG_LOOKUP)
    argv[argc++] = "-vv";
  else if (DBG_EXTPROG)
    argv[argc++] = "-v";

  argv[argc++] = "--log-with-pid";
  argv[argc++] = "--multi";

  if (starttls)
    argv[argc++] = "--starttls";
  else if (ldaptls)
    argv[argc++] = "--ldaptls";

  if (ntds)
    argv[argc++] = "--ntds";

  if (opt.ldaptimeout)
    {
      snprintf (timeoutbuf, sizeof timeoutbuf, "%u", opt.ldaptimeout);
      argv[argc++] = "--timeout";
      argv[argc++] = timeoutbuf;
    }
  if (proxy && *proxy)
    {
      argv[argc++] = "--proxy";
      argv[argc++] = proxy;
    }
  if (host && *host)
    {
      argv[argc++] = "--host";
      argv[argc++] = host;
    }
  if (port)
    {
      snprintf (portbuf, sizeof portbuf, "%d", port);
      argv[argc++] = "--port";
      argv[argc++] = portbuf;
    }
  if (user && *user)
    {
      argv[argc++] = "--user";
      argv[argc++] = user;
    }
  if (base && *base)
    {
      argv[argc++] = "--base";
      argv[argc++] = base;
    }


  /* All entries in argv from this index on are malloc'ed.  */
  argc_malloced = argc;

  for (; patterns; patterns = patterns->next)
    {
      if (argc >= DIM (argv) - 1)
        {
          /* Too many patterns.  It does not make sense to allow an
             arbitrary number of patters because the length of the
             command line is limited anyway.  */
          err = gpg_error (GPG_ERR_RESOURCE_LIMIT);
          goto leave;
        }
      if (*patterns->d)
        {
          err = make_one_filter (patterns->d, &argv[argc]);
          if (err)
            goto leave;
          argc++;
        }
    }
  argv[argc] = NULL;

  *r_context = xtrycalloc (1, sizeof **r_context);
  if (!*r_context)
    {
      err = gpg_error_from_syserror ();
      goto leave;
    }

  err = ldap_wrapper (ctrl, &(*r_context)->reader, (const char**)argv);
  if (err)
    {
      xfree (*r_context);
      *r_context = NULL;
    }

 leave:
  for (; argc_malloced < argc; argc_malloced++)
    xfree (argv[argc_malloced]);
  xfree (proxy);
  xfree (host);
  xfree (base);
  xfree (user);
  xfree (pass);
  return err;
}


/* Read a fixed amount of data from READER into BUFFER.  */
static gpg_error_t
read_buffer (ksba_reader_t reader, unsigned char *buffer, size_t count)
{
  gpg_error_t err;
  size_t nread;

  while (count)
    {
      err = ksba_reader_read (reader, buffer, count, &nread);
      if (err)
        return err;
      buffer += nread;
      count -= nread;
    }
  return 0;
}


/* Fetch the next certificate. Return 0 on success, GPG_ERR_EOF if no
   (more) certificates are available or any other error
   code. GPG_ERR_TRUNCATED may be returned to indicate that the result
   has been truncated. */
gpg_error_t
fetch_next_cert_ldap (cert_fetch_context_t context,
                      unsigned char **value, size_t *valuelen)
{
  gpg_error_t err;
  unsigned char hdr[5];
  char *p, *pend;
  unsigned long n;
  int okay = 0;
  /* int is_cms = 0; */

  *value = NULL;
  *valuelen = 0;

  err = 0;
  while (!err)
    {
      err = read_buffer (context->reader, hdr, 5);
      if (err)
        break;
      n = buf32_to_ulong (hdr+1);
      if (*hdr == 'V' && okay)
        {
#if 0  /* That code to extra a cert from a CMS object is not yet ready.  */
          if (is_cms)
            {
              /* The certificate needs to be parsed from CMS data. */
              ksba_cms_t cms;
              ksba_stop_reason_t stopreason;
              int i;

              err = ksba_cms_new (&cms);
              if (err)
                goto leave;
              err = ksba_cms_set_reader_writer (cms, context->reader, NULL);
              if (err)
                {
                  log_error ("ksba_cms_set_reader_writer failed: %s\n",
                             gpg_strerror (err));
                  goto leave;
                }

              do
                {
                  err = ksba_cms_parse (cms, &stopreason);
                  if (err)
                    {
                      log_error ("ksba_cms_parse failed: %s\n",
                                 gpg_strerror (err));
                      goto leave;
                    }

                  if (stopreason == KSBA_SR_BEGIN_DATA)
                    log_error ("userSMIMECertificate is not "
                               "a certs-only message\n");
                }
              while (stopreason != KSBA_SR_READY);

              for (i=0; (cert=ksba_cms_get_cert (cms, i)); i++)
                {
                  check_and_store (ctrl, stats, cert, 0);
                  ksba_cert_release (cert);
                  cert = NULL;
                }
              if (!i)
                log_error ("no certificate found\n");
              else
                any = 1;
            }
          else
#endif /* End unfinished code to extract from a CMS object.  */
            {
              *value = xtrymalloc (n);
              if (!*value)
                return gpg_error_from_errno (errno);
              *valuelen = n;
              err = read_buffer (context->reader, *value, n);
              break; /* Ready or error.  */
            }
        }
      else if (!n && *hdr == 'A')
        okay = 0;
      else if (n)
        {
          if (n > context->tmpbufsize)
            {
              xfree (context->tmpbuf);
              context->tmpbufsize = 0;
              context->tmpbuf = xtrymalloc (n+1);
              if (!context->tmpbuf)
                return gpg_error_from_errno (errno);
              context->tmpbufsize = n;
            }
          err = read_buffer (context->reader, context->tmpbuf, n);
          if (err)
            break;
          if (*hdr == 'A')
            {
              p = context->tmpbuf;
              p[n] = 0; /*(we allocated one extra byte for this.)*/
              /* fixme: is_cms = 0; */
              if ( (pend = strchr (p, ';')) )
                *pend = 0; /* Strip off the extension. */
              if (!ascii_strcasecmp (p, USERCERTIFICATE))
                {
                  if (DBG_LOOKUP)
                    log_debug ("fetch_next_cert_ldap: got attribute '%s'\n",
                               USERCERTIFICATE);
                  okay = 1;
                }
              else if (!ascii_strcasecmp (p, CACERTIFICATE))
                {
                  if (DBG_LOOKUP)
                    log_debug ("fetch_next_cert_ldap: got attribute '%s'\n",
                               CACERTIFICATE);
                  okay = 1;
                }
              else if (!ascii_strcasecmp (p, X509CACERT))
                {
                  if (DBG_LOOKUP)
                    log_debug ("fetch_next_cert_ldap: got attribute '%s'\n",
                               CACERTIFICATE);
                  okay = 1;
                }
/*               else if (!ascii_strcasecmp (p, USERSMIMECERTIFICATE)) */
/*                 { */
/*                   if (DBG_LOOKUP) */
/*                     log_debug ("fetch_next_cert_ldap: got attribute '%s'\n", */
/*                                USERSMIMECERTIFICATE); */
/*                   okay = 1; */
/*                   is_cms = 1; */
/*                 } */
              else
                {
                  if (DBG_LOOKUP)
                    log_debug ("fetch_next_cert_ldap: got attribute '%s'"
                               " -  ignored\n", p);
                  okay = 0;
                }
            }
          else if (*hdr == 'E')
            {
              p = context->tmpbuf;
              p[n] = 0; /*(we allocated one extra byte for this.)*/
              if (!strcmp (p, "truncated"))
                {
                  context->truncated = 1;
                  log_info (_("ldap_search hit the size limit of"
                              " the server\n"));
                }
            }
        }
    }

  if (err)
    {
      xfree (*value);
      *value = NULL;
      *valuelen = 0;
      if (gpg_err_code (err) == GPG_ERR_EOF && context->truncated)
        {
          context->truncated = 0; /* So that the next call would return EOF. */
          err = gpg_error (GPG_ERR_TRUNCATED);
        }
    }

  return err;
}


void
end_cert_fetch_ldap (cert_fetch_context_t context)
{
  if (context)
    {
      ksba_reader_t reader = context->reader;

      xfree (context->tmpbuf);
      xfree (context);
      ldap_wrapper_release_context (reader);
      ksba_reader_release (reader);
    }
}
