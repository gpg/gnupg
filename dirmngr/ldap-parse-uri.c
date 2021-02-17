/* ldap-parse-uri.c - Parse an LDAP URI.
 * Copyright (C) 2015  g10 Code GmbH
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

#include <gpg-error.h>

#ifdef HAVE_W32_SYSTEM
# include "ldap-url.h"
#else
# include <ldap.h>
#endif

#include "../common/util.h"
#include "http.h"

/* Returns 1 if the string is an LDAP URL.  */
int
ldap_uri_p (const char *url)
{
  parsed_uri_t puri;
  int result;

  if (http_parse_uri (&puri, url, 1))
    result = 0;
  else
    result = !!puri->is_ldap;

  http_release_parsed_uri (puri);

  return result;
}


/* Parse a URI and put the result into *purip.  On success the
   caller must use http_release_parsed_uri() to releases the resources.

   uri->path is the base DN (or NULL for the default).
   uri->auth is the bindname (or NULL for none).
   The uri->query variable "password" is the password.

   Note: any specified scope, any attributes, any filter and any
   unknown extensions are simply ignored.  */
gpg_error_t
ldap_parse_uri (parsed_uri_t *purip, const char *uri)
{
  gpg_err_code_t err = 0;
  parsed_uri_t puri = NULL;

  int result;
  LDAPURLDesc *lud = NULL;

  char *scheme = NULL;
  char *host = NULL;
  char *dn = NULL;
  char *bindname = NULL;
  char *password = NULL;
  char *gpg_ntds = NULL;

  char **s;

  char *buffer;
  int len;

  result = ldap_url_parse (uri, &lud);
  if (result != 0)
    {
      log_error ("Unable to parse LDAP uri '%s'\n", uri);
      err = GPG_ERR_GENERAL;
      goto out;
    }

  scheme = lud->lud_scheme;
  host = lud->lud_host;
  dn = lud->lud_dn;

  for (s = lud->lud_exts; s && *s; s ++)
    {
      if (strncmp (*s, "bindname=", 9) == 0)
	{
	  if (bindname)
	    log_error ("bindname given multiple times in URL '%s', ignoring.\n",
		       uri);
	  else
	    bindname = *s + 9;
	}
      else if (strncmp (*s, "password=", 9) == 0)
	{
	  if (password)
	    log_error ("password given multiple times in URL '%s', ignoring.\n",
		       uri);
	  else
	    password = *s + 9;
	}
      else if (!ascii_strncasecmp (*s, "gpgNtds=", 8)
              || !strncmp (*s, "1.3.6.1.4.1.11591.2.5.1=", 24))
	{
	  if (gpg_ntds)
	    log_error ("gpgNtds given multiple times in URL '%s', ignoring.\n",
		       uri);
	  else
	    gpg_ntds = *s + (**s == 'g'? 8 : 24);
	}
      else
	log_error ("Unhandled extension (%s) in URL '%s', ignoring.",
		   *s, uri);
    }

  len = 0;

#define add(s) do { if (s) len += strlen (s) + 1; } while (0)

  add (scheme);
  add (host);
  add (dn);
  add (bindname);
  add (password);

  puri = xtrycalloc (1, sizeof *puri + len);
  if (! puri)
    {
      err = gpg_err_code_from_syserror ();
      goto out;
    }

  buffer = puri->buffer;

#define copy(to, s)				\
  do						\
    {						\
      if (s)					\
	{					\
	  to = buffer;				\
	  buffer = stpcpy (buffer, s) + 1;	\
	}					\
    }						\
  while (0)

  copy (puri->scheme, scheme);
  /* Make sure the scheme is lower case.  */
  ascii_strlwr (puri->scheme);

  copy (puri->host, host);
  copy (puri->path, dn);
  copy (puri->auth, bindname);

  if (password)
    {
      puri->query = calloc (sizeof (*puri->query), 1);
      if (!puri->query)
        {
          err = gpg_err_code_from_syserror ();
          goto out;
        }
      puri->query->name = "password";
      copy (puri->query->value, password);
      puri->query->valuelen = strlen (password) + 1;
    }

  puri->use_tls = !strcmp (puri->scheme, "ldaps");
  puri->port = lud->lud_port;

  /* On Windows detect whether this is ldap:// or ldaps:// to indicate
   * that authentication via AD and the current user is requested.
   * This is shortform of adding "gpgNtDs=1" as extension parameter to
   * the URL.  */
  puri->ad_current = 0;
  if (gpg_ntds && atoi (gpg_ntds) == 1)
    puri->ad_current = 1;
#ifdef HAVE_W32_SYSTEM
  else if ((!puri->host || !*puri->host)
      && (!puri->path || !*puri->path)
      && (!puri->auth || !*puri->auth)
      && !password
      )
    puri->ad_current = 1;
#endif

 out:
  if (lud)
    ldap_free_urldesc (lud);

  if (err)
    {
      if (puri)
	http_release_parsed_uri (puri);
    }
  else
    *purip = puri;

  return gpg_err_make (default_errsource, err);
}

/* The following characters need to be escaped to be part of an LDAP
   filter: *, (, ), \, NUL and /.  Note: we don't handle NUL, since a
   NUL can't be part of a C string.

   This function always allocates a new string on success.  It is the
   caller's responsibility to free it.
*/
char *
ldap_escape_filter (const char *filter)
{
  int l = strcspn (filter, "*()\\/");
  if (l == strlen (filter))
    /* Nothing to escape.  */
    return xstrdup (filter);

  {
    /* In the worst case we need to escape every letter.  */
    char *escaped = xmalloc (1 + 3 * strlen (filter));

    /* Indices into filter and escaped.  */
    int filter_i = 0;
    int escaped_i = 0;

    for (filter_i = 0; filter_i < strlen (filter); filter_i ++)
      {
	switch (filter[filter_i])
	  {
	  case '*':
	  case '(':
	  case ')':
	  case '\\':
	  case '/':
	    snprintf (&escaped[escaped_i], 4, "%%%02x",
                     ((const unsigned char *)filter)[filter_i]);
	    escaped_i += 3;
	    break;

	  default:
	    escaped[escaped_i ++] = filter[filter_i];
	    break;
	  }
      }
    /* NUL terminate it.  */
    escaped[escaped_i] = 0;

    /* We could shrink escaped to be just escaped_i bytes, but the
       result will probably be freed very quickly anyways.  */
    return escaped;
  }
}
