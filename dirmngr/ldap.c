/* ldap.c - LDAP access
 * Copyright (C) 2002 Klarälvdalens Datakonsult AB
 * Copyright (C) 2003, 2004, 2005, 2007, 2008, 2010 g10 Code GmbH
 *
 * This file is part of DirMngr.
 *
 * DirMngr is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * DirMngr is distributed in the hope that it will be useful,
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
#include <fcntl.h>
#include <time.h>
#include <npth.h>

#include "dirmngr.h"
#include "../common/exechelp.h"
#include "crlfetch.h"
#include "ldapserver.h"
#include "misc.h"
#include "ldap-wrapper.h"
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
                  const char *proxy,
                  const char *host, int port,
                  const char *user, const char *pass,
                  const char *dn, const char *filter, const char *attr,
                  const char *url,
                  ksba_reader_t *reader)
{
  const char *argv[40];
  int argc;
  char portbuf[30], timeoutbuf[30];


  *reader = NULL;

  argc = 0;
  if (pass)  /* Note, that the password must be the first item.  */
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
  if (opt.ldaptimeout)
    {
      sprintf (timeoutbuf, "%u", opt.ldaptimeout);
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
  if (host)
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
  if (user)
    {
      argv[argc++] = "--user";
      argv[argc++] = user;
    }
  if (dn)
    {
      argv[argc++] = "--dn";
      argv[argc++] = dn;
    }
  if (filter)
    {
      argv[argc++] = "--filter";
      argv[argc++] = filter;
    }
  if (attr)
    {
      argv[argc++] = "--attr";
      argv[argc++] = attr;
    }
  argv[argc++] = url? url : "ldap://";
  argv[argc] = NULL;

  return ldap_wrapper (ctrl, reader, argv);
}




/* Perform a LDAP query using a given URL. On success a new ksba
   reader is returned.  If HOST or PORT are not 0, they are used to
   override the values from the URL. */
gpg_error_t
url_fetch_ldap (ctrl_t ctrl, const char *url, const char *host, int port,
                ksba_reader_t *reader)
{
  gpg_error_t err;

  err = run_ldap_wrapper (ctrl,
                          1, /* Ignore explicit timeout because CRLs
                                might be very large. */
                          0,
                          opt.ldap_proxy,
                          host, port,
                          NULL, NULL,
                          NULL, NULL, NULL, url,
                          reader);

  /* FIXME: This option might be used for DoS attacks.  Because it
     will enlarge the list of servers to consult without a limit and
     all LDAP queries w/o a host are will then try each host in
     turn. */
  if (!err && opt.add_new_ldapservers && !opt.ldap_proxy)
    {
      if (host)
        add_server_to_servers (host, port);
      else if (url)
        {
          char *tmp = host_and_port_from_url (url, &port);
          if (tmp)
            {
              add_server_to_servers (tmp, port);
              xfree (tmp);
            }
        }
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

          err = run_ldap_wrapper (ctrl,
                                  0,
                                  0,
                                  NULL,
                                  server->host, server->port,
                                  NULL, NULL,
                                  NULL, NULL, NULL, url,
                                  reader);
          if (!err)
            break;
        }
    }

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

  /* FIXME; we might want to look at the Base SN to try matching
     servers first. */
  for (ldapserver_iter_begin (&iter, ctrl); ! ldapserver_iter_end_p (&iter);
       ldapserver_iter_next (&iter))
    {
      ldap_server_t server = iter.server;

      err = run_ldap_wrapper (ctrl,
                              0,
                              0,
                              opt.ldap_proxy,
                              server->host, server->port,
                              server->user, server->pass,
                              dn, "objectClass=*", attr, NULL,
                              reader);
      if (!err)
        break; /* Probably found a result. Ready. */
    }
  return err;
}


/* Parse PATTERN and return a new strlist to be used for the actual
   LDAP query.  Bit 0 of the flags field is set if that pattern is
   actually a base specification.  Caller must release the returned
   strlist.  NULL is returned on error.

 * Possible patterns:
 *
 *   KeyID
 *   Fingerprint
 *   OpenPGP userid
 * x Email address  Indicated by a left angle bracket.
 *   Exact word match in user id or subj. name
 * x Subj. DN  indicated bu a leading slash
 *   Issuer DN
 *   Serial number + subj. DN
 * x Substring match indicated by a leading '*; is also the default.
 */

strlist_t
parse_one_pattern (const char *pattern)
{
  strlist_t result = NULL;
  char *p;

  switch (*pattern)
    {
    case '<':			/* Email. */
      {
        pattern++;
	result = xmalloc (sizeof *result + 5 + strlen (pattern));
        result->next = NULL;
        result->flags = 0;
	p = stpcpy (stpcpy (result->d, "mail="), pattern);
	if (p[-1] == '>')
	  *--p = 0;
        if (!*result->d) /* Error. */
          {
            xfree (result);
            result = NULL;
          }
	break;
      }
    case '/':			/* Subject DN. */
      pattern++;
      if (*pattern)
        {
          result = xmalloc (sizeof *result + strlen (pattern));
          result->next = NULL;
          result->flags = 1; /* Base spec. */
          strcpy (result->d, pattern);
        }
      break;
    case '#':			/* Issuer DN. */
      pattern++;
      if (*pattern == '/')  /* Just issuer DN. */
        {
          pattern++;
	}
      else  /* Serial number + issuer DN */
	{
        }
      break;
    case '*':
      pattern++;
      /* fall through */
    default:			/* Take as substring match. */
      {
	const char format[] = "(|(sn=*%s*)(|(cn=*%s*)(mail=*%s*)))";

        if (*pattern)
          {
            result = xmalloc (sizeof *result
                              + strlen (format) + 3 * strlen (pattern));
            result->next = NULL;
            result->flags = 0;
            sprintf (result->d, format, pattern, pattern, pattern);
          }
      }
      break;
    }

  return result;
}

/* Take the string STRING and escape it according to the URL rules.
   Retun a newly allocated string. */
static char *
escape4url (const char *string)
{
  const char *s;
  char *buf, *p;
  size_t n;

  if (!string)
    string = "";

  for (s=string,n=0; *s; s++)
    if (strchr (UNENCODED_URL_CHARS, *s))
      n++;
    else
      n += 3;

  buf = malloc (n+1);
  if (!buf)
    return NULL;

  for (s=string,p=buf; *s; s++)
    if (strchr (UNENCODED_URL_CHARS, *s))
      *p++ = *s;
    else
      {
        sprintf (p, "%%%02X", *(const unsigned char *)s);
        p += 3;
      }
  *p = 0;

  return buf;
}



/* Create a LDAP URL from DN and FILTER and return it in URL.  We don't
   need the host and port because this will be specified using the
   override options. */
static gpg_error_t
make_url (char **url, const char *dn, const char *filter)
{
  gpg_error_t err;
  char *u_dn, *u_filter;
  char const attrs[] = (USERCERTIFICATE ","
/*                         USERSMIMECERTIFICATE "," */
                        CACERTIFICATE ","
                        X509CACERT );

  *url = NULL;

  u_dn = escape4url (dn);
  if (!u_dn)
      return gpg_error_from_errno (errno);

  u_filter = escape4url (filter);
  if (!u_filter)
    {
      err = gpg_error_from_errno (errno);
      xfree (u_dn);
      return err;
    }

  *url = strconcat ("ldap:///", u_dn, "?", attrs, "?sub?", u_filter, NULL);
  if (!*url)
    err = gpg_error_from_syserror ();
  else
    err = 0;

  xfree (u_dn);
  xfree (u_filter);
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

  /* FIXME; we might want to look at the Base SN to try matching
     servers first. */
  err = gpg_error (GPG_ERR_CONFIGURATION);

  for (ldapserver_iter_begin (&iter, ctrl); ! ldapserver_iter_end_p (&iter);
       ldapserver_iter_next (&iter))
    {
      ldap_server_t server = iter.server;

      err = run_ldap_wrapper (ctrl,
                              0,
                              1,  /* --multi (record format) */
                              opt.ldap_proxy,
                              server->host, server->port,
                              server->user, server->pass,
                              dn, "objectClass=*", "cACertificate", NULL,
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
  const char *base;
  char *argv[50];
  int argc = 0;
  int argc_malloced = 0;
  char portbuf[30], timeoutbuf[30];


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
      base = server->base;

    }
  else /* Use a default server. */
    return gpg_error (GPG_ERR_NOT_IMPLEMENTED);


  if (!base)
    base = "";

  if (pass) /* Note: Must be the first item. */
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
  if (opt.ldaptimeout)
    {
      snprintf (timeoutbuf, sizeof timeoutbuf, "%u", opt.ldaptimeout);
      argv[argc++] = "--timeout";
      argv[argc++] = timeoutbuf;
    }
  if (opt.ldap_proxy)
    {
      argv[argc++] = "--proxy";
      argv[argc++] = proxy;
    }
  if (host)
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
  if (user)
    {
      argv[argc++] = "--user";
      argv[argc++] = user;
    }

  /* All entries in argv from this index on are malloc'ed.  */
  argc_malloced = argc;

  for (; patterns; patterns = patterns->next)
    {
      strlist_t sl;
      char *url;

      if (argc >= DIM (argv) - 1)
        {
          /* Too many patterns.  It does not make sense to allow an
             arbitrary number of patters because the length of the
             command line is limited anyway.  */
          /* fixme: cleanup. */
          return gpg_error (GPG_ERR_RESOURCE_LIMIT);
        }
      sl = parse_one_pattern (patterns->d);
      if (!sl)
        {
          log_error (_("start_cert_fetch: invalid pattern '%s'\n"),
                     patterns->d);
          err = gpg_error (GPG_ERR_INV_USER_ID);
          goto leave;
        }
      if ((sl->flags & 1))
        err = make_url (&url, sl->d, "objectClass=*");
      else
        err = make_url (&url, base, sl->d);
      free_strlist (sl);
      if (err)
        goto leave;
      argv[argc++] = url;
    }
  argv[argc] = NULL;

  *r_context = xtrycalloc (1, sizeof **r_context);
  if (!*r_context)
    {
      err = gpg_error_from_errno (errno);
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
