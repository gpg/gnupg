/* ks-engine-ldap.c - talk to a LDAP keyserver
 * Copyright (C) 2001, 2002, 2004, 2005, 2006
 *               2007  Free Software Foundation, Inc.
 * Copyright (C) 2015, 2020  g10 Code GmbH
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
#include <string.h>
#include <time.h>
#include <unistd.h>
#ifdef HAVE_GETOPT_H
# include <getopt.h>
#endif
#include <stdlib.h>
#include <errno.h>
#include <assert.h>

#ifdef _WIN32
# include <winsock2.h>
# include <winldap.h>
#else
# ifdef NEED_LBER_H
#  include <lber.h>
# endif
/* For OpenLDAP, to enable the API that we're using. */
# define LDAP_DEPRECATED 1
# include <ldap.h>
#endif
#include <npth.h>

#include "dirmngr.h"
#include "misc.h"
#include "../common/userids.h"
#include "../common/mbox-util.h"
#include "ks-engine.h"
#include "ldap-parse-uri.h"


/* Flags with infos from the connected server.  */
#define SERVERINFO_REALLDAP 1 /* This is not the PGP keyserver.      */
#define SERVERINFO_PGPKEYV2 2 /* Needs "pgpeyV2" instead of "pgpKey" */
#define SERVERINFO_SCHEMAV2 4 /* Version 2 of the Schema.            */
#define SERVERINFO_NTDS     8 /* Server is an Active Directory.      */



#ifndef HAVE_TIMEGM
time_t timegm(struct tm *tm);
#endif

/* Convert an LDAP error to a GPG error.  */
static int
ldap_err_to_gpg_err (int code)
{
  gpg_err_code_t ec;

  switch (code)
    {
#ifdef LDAP_X_CONNECTING
    case LDAP_X_CONNECTING: ec = GPG_ERR_LDAP_X_CONNECTING; break;
#endif

    case LDAP_REFERRAL_LIMIT_EXCEEDED: ec = GPG_ERR_LDAP_REFERRAL_LIMIT; break;
    case LDAP_CLIENT_LOOP: ec = GPG_ERR_LDAP_CLIENT_LOOP; break;
    case LDAP_NO_RESULTS_RETURNED: ec = GPG_ERR_LDAP_NO_RESULTS; break;
    case LDAP_CONTROL_NOT_FOUND: ec = GPG_ERR_LDAP_CONTROL_NOT_FOUND; break;
    case LDAP_NOT_SUPPORTED: ec = GPG_ERR_LDAP_NOT_SUPPORTED; break;
    case LDAP_CONNECT_ERROR: ec = GPG_ERR_LDAP_CONNECT; break;
    case LDAP_NO_MEMORY: ec = GPG_ERR_LDAP_NO_MEMORY; break;
    case LDAP_PARAM_ERROR: ec = GPG_ERR_LDAP_PARAM; break;
    case LDAP_USER_CANCELLED: ec = GPG_ERR_LDAP_USER_CANCELLED; break;
    case LDAP_FILTER_ERROR: ec = GPG_ERR_LDAP_FILTER; break;
    case LDAP_AUTH_UNKNOWN: ec = GPG_ERR_LDAP_AUTH_UNKNOWN; break;
    case LDAP_TIMEOUT: ec = GPG_ERR_LDAP_TIMEOUT; break;
    case LDAP_DECODING_ERROR: ec = GPG_ERR_LDAP_DECODING; break;
    case LDAP_ENCODING_ERROR: ec = GPG_ERR_LDAP_ENCODING; break;
    case LDAP_LOCAL_ERROR: ec = GPG_ERR_LDAP_LOCAL; break;
    case LDAP_SERVER_DOWN: ec = GPG_ERR_LDAP_SERVER_DOWN; break;

    case LDAP_SUCCESS: ec = GPG_ERR_LDAP_SUCCESS; break;

    case LDAP_OPERATIONS_ERROR: ec = GPG_ERR_LDAP_OPERATIONS; break;
    case LDAP_PROTOCOL_ERROR: ec = GPG_ERR_LDAP_PROTOCOL; break;
    case LDAP_TIMELIMIT_EXCEEDED: ec = GPG_ERR_LDAP_TIMELIMIT; break;
    case LDAP_SIZELIMIT_EXCEEDED: ec = GPG_ERR_LDAP_SIZELIMIT; break;
    case LDAP_COMPARE_FALSE: ec = GPG_ERR_LDAP_COMPARE_FALSE; break;
    case LDAP_COMPARE_TRUE: ec = GPG_ERR_LDAP_COMPARE_TRUE; break;
    case LDAP_AUTH_METHOD_NOT_SUPPORTED: ec=GPG_ERR_LDAP_UNSUPPORTED_AUTH;break;
    case LDAP_STRONG_AUTH_REQUIRED: ec = GPG_ERR_LDAP_STRONG_AUTH_RQRD; break;
    case LDAP_PARTIAL_RESULTS: ec = GPG_ERR_LDAP_PARTIAL_RESULTS; break;
    case LDAP_REFERRAL: ec = GPG_ERR_LDAP_REFERRAL; break;

#ifdef LDAP_ADMINLIMIT_EXCEEDED
    case LDAP_ADMINLIMIT_EXCEEDED: ec = GPG_ERR_LDAP_ADMINLIMIT; break;
#endif

#ifdef LDAP_UNAVAILABLE_CRITICAL_EXTENSION
    case LDAP_UNAVAILABLE_CRITICAL_EXTENSION:
                               ec = GPG_ERR_LDAP_UNAVAIL_CRIT_EXTN; break;
#endif

    case LDAP_CONFIDENTIALITY_REQUIRED: ec = GPG_ERR_LDAP_CONFIDENT_RQRD; break;
    case LDAP_SASL_BIND_IN_PROGRESS: ec = GPG_ERR_LDAP_SASL_BIND_INPROG; break;
    case LDAP_NO_SUCH_ATTRIBUTE: ec = GPG_ERR_LDAP_NO_SUCH_ATTRIBUTE; break;
    case LDAP_UNDEFINED_TYPE: ec = GPG_ERR_LDAP_UNDEFINED_TYPE; break;
    case LDAP_INAPPROPRIATE_MATCHING: ec = GPG_ERR_LDAP_BAD_MATCHING; break;
    case LDAP_CONSTRAINT_VIOLATION: ec = GPG_ERR_LDAP_CONST_VIOLATION; break;

#ifdef LDAP_TYPE_OR_VALUE_EXISTS
    case LDAP_TYPE_OR_VALUE_EXISTS: ec = GPG_ERR_LDAP_TYPE_VALUE_EXISTS; break;
#endif

    case LDAP_INVALID_SYNTAX: ec = GPG_ERR_LDAP_INV_SYNTAX; break;
    case LDAP_NO_SUCH_OBJECT: ec = GPG_ERR_LDAP_NO_SUCH_OBJ; break;
    case LDAP_ALIAS_PROBLEM: ec = GPG_ERR_LDAP_ALIAS_PROBLEM; break;
    case LDAP_INVALID_DN_SYNTAX: ec = GPG_ERR_LDAP_INV_DN_SYNTAX; break;
    case LDAP_IS_LEAF: ec = GPG_ERR_LDAP_IS_LEAF; break;
    case LDAP_ALIAS_DEREF_PROBLEM: ec = GPG_ERR_LDAP_ALIAS_DEREF; break;

#ifdef LDAP_X_PROXY_AUTHZ_FAILURE
    case LDAP_X_PROXY_AUTHZ_FAILURE: ec = GPG_ERR_LDAP_X_PROXY_AUTH_FAIL; break;
#endif

    case LDAP_INAPPROPRIATE_AUTH: ec = GPG_ERR_LDAP_BAD_AUTH; break;
    case LDAP_INVALID_CREDENTIALS: ec = GPG_ERR_LDAP_INV_CREDENTIALS; break;

#ifdef LDAP_INSUFFICIENT_ACCESS
    case LDAP_INSUFFICIENT_ACCESS: ec = GPG_ERR_LDAP_INSUFFICIENT_ACC; break;
#endif

    case LDAP_BUSY: ec = GPG_ERR_LDAP_BUSY; break;
    case LDAP_UNAVAILABLE: ec = GPG_ERR_LDAP_UNAVAILABLE; break;
    case LDAP_UNWILLING_TO_PERFORM: ec = GPG_ERR_LDAP_UNWILL_TO_PERFORM; break;
    case LDAP_LOOP_DETECT: ec = GPG_ERR_LDAP_LOOP_DETECT; break;
    case LDAP_NAMING_VIOLATION: ec = GPG_ERR_LDAP_NAMING_VIOLATION; break;
    case LDAP_OBJECT_CLASS_VIOLATION: ec = GPG_ERR_LDAP_OBJ_CLS_VIOLATION; break;
    case LDAP_NOT_ALLOWED_ON_NONLEAF: ec=GPG_ERR_LDAP_NOT_ALLOW_NONLEAF;break;
    case LDAP_NOT_ALLOWED_ON_RDN: ec = GPG_ERR_LDAP_NOT_ALLOW_ON_RDN; break;
    case LDAP_ALREADY_EXISTS: ec = GPG_ERR_LDAP_ALREADY_EXISTS; break;
    case LDAP_NO_OBJECT_CLASS_MODS: ec = GPG_ERR_LDAP_NO_OBJ_CLASS_MODS; break;
    case LDAP_RESULTS_TOO_LARGE: ec = GPG_ERR_LDAP_RESULTS_TOO_LARGE; break;
    case LDAP_AFFECTS_MULTIPLE_DSAS: ec = GPG_ERR_LDAP_AFFECTS_MULT_DSAS; break;

#ifdef LDAP_VLV_ERROR
    case LDAP_VLV_ERROR: ec = GPG_ERR_LDAP_VLV; break;
#endif

    case LDAP_OTHER: ec = GPG_ERR_LDAP_OTHER; break;

#ifdef LDAP_CUP_RESOURCES_EXHAUSTED
    case LDAP_CUP_RESOURCES_EXHAUSTED: ec=GPG_ERR_LDAP_CUP_RESOURCE_LIMIT;break;
    case LDAP_CUP_SECURITY_VIOLATION: ec=GPG_ERR_LDAP_CUP_SEC_VIOLATION; break;
    case LDAP_CUP_INVALID_DATA: ec = GPG_ERR_LDAP_CUP_INV_DATA; break;
    case LDAP_CUP_UNSUPPORTED_SCHEME: ec = GPG_ERR_LDAP_CUP_UNSUP_SCHEME; break;
    case LDAP_CUP_RELOAD_REQUIRED: ec = GPG_ERR_LDAP_CUP_RELOAD; break;
#endif

#ifdef LDAP_CANCELLED
    case LDAP_CANCELLED: ec = GPG_ERR_LDAP_CANCELLED; break;
#endif

#ifdef LDAP_NO_SUCH_OPERATION
    case LDAP_NO_SUCH_OPERATION: ec = GPG_ERR_LDAP_NO_SUCH_OPERATION; break;
#endif

#ifdef LDAP_TOO_LATE
    case LDAP_TOO_LATE: ec = GPG_ERR_LDAP_TOO_LATE; break;
#endif

#ifdef LDAP_CANNOT_CANCEL
    case LDAP_CANNOT_CANCEL: ec = GPG_ERR_LDAP_CANNOT_CANCEL; break;
#endif

#ifdef LDAP_ASSERTION_FAILED
    case LDAP_ASSERTION_FAILED: ec = GPG_ERR_LDAP_ASSERTION_FAILED; break;
#endif

#ifdef LDAP_PROXIED_AUTHORIZATION_DENIED
    case LDAP_PROXIED_AUTHORIZATION_DENIED:
                                      ec = GPG_ERR_LDAP_PROX_AUTH_DENIED; break;
#endif

    default:
#if defined(LDAP_E_ERROR) && defined(LDAP_X_ERROR)
      if (LDAP_E_ERROR (code))
        ec = GPG_ERR_LDAP_E_GENERAL;
      else if (LDAP_X_ERROR (code))
        ec = GPG_ERR_LDAP_X_GENERAL;
      else
#endif
        ec = GPG_ERR_LDAP_GENERAL;
      break;
    }

  return ec;
}

/* Retrieve an LDAP error and return it's GPG equivalent.  */
static int
ldap_to_gpg_err (LDAP *ld)
{
#if defined(HAVE_LDAP_GET_OPTION) && defined(LDAP_OPT_ERROR_NUMBER)
  int err;

  if (ldap_get_option (ld, LDAP_OPT_ERROR_NUMBER, &err) == 0)
    return ldap_err_to_gpg_err (err);
  else
    return GPG_ERR_GENERAL;
#elif defined(HAVE_LDAP_LD_ERRNO)
  return ldap_err_to_gpg_err (ld->ld_errno);
#else
  /* We should never get here since the LDAP library should always
     have either ldap_get_option or ld_errno, but just in case... */
  return GPG_ERR_INTERNAL;
#endif
}

static time_t
ldap2epochtime (const char *timestr)
{
  struct tm pgptime;
  time_t answer;

  memset (&pgptime, 0, sizeof(pgptime));

  /* YYYYMMDDHHmmssZ */

  sscanf (timestr, "%4d%2d%2d%2d%2d%2d",
	  &pgptime.tm_year,
	  &pgptime.tm_mon,
	  &pgptime.tm_mday,
	  &pgptime.tm_hour,
	  &pgptime.tm_min,
	  &pgptime.tm_sec);

  pgptime.tm_year -= 1900;
  pgptime.tm_isdst = -1;
  pgptime.tm_mon--;

  /* mktime() takes the timezone into account, so we use timegm() */

  answer = timegm (&pgptime);

  return answer;
}

/* Caller must free the result.  */
static char *
tm2ldaptime (struct tm *tm)
{
  struct tm tmp = *tm;
  char buf[16];

  /* YYYYMMDDHHmmssZ */

  tmp.tm_year += 1900;
  tmp.tm_mon ++;

  snprintf (buf, sizeof buf, "%04d%02d%02d%02d%02d%02dZ",
	   tmp.tm_year,
	   tmp.tm_mon,
	   tmp.tm_mday,
	   tmp.tm_hour,
	   tmp.tm_min,
	   tmp.tm_sec);

  return xstrdup (buf);
}

#if 0
/* Caller must free */
static char *
epoch2ldaptime (time_t stamp)
{
  struct tm tm;
  if (gmtime_r (&stamp, &tm))
    return tm2ldaptime (&tm);
  else
    return xstrdup ("INVALID TIME");
}
#endif

/* Print a help output for the schemata supported by this module. */
gpg_error_t
ks_ldap_help (ctrl_t ctrl, parsed_uri_t uri)
{
  const char data[] =
    "Handler for LDAP URLs:\n"
    "  ldap://host:port/[BASEDN]???[bindname=BINDNAME,password=PASSWORD]\n"
    "\n"
    "Note: basedn, bindname and password need to be percent escaped. In\n"
    "particular, spaces need to be replaced with %20 and commas with %2c.\n"
    "bindname will typically be of the form:\n"
    "\n"
    "  uid=user%2cou=PGP%20Users%2cdc=EXAMPLE%2cdc=ORG\n"
    "\n"
    "The ldaps:// and ldapi:// schemes are also supported.  If ldaps is used\n"
    "then the server's certificate will be checked.  If it is not valid, any\n"
    "operation will be aborted.\n"
    "\n"
    "Supported methods: search, get, put\n";
  gpg_error_t err;

  if(!uri)
    err = ks_print_help (ctrl, "  ldap");
  else if (strcmp (uri->scheme, "ldap") == 0
      || strcmp (uri->scheme, "ldaps") == 0
      || strcmp (uri->scheme, "ldapi") == 0)
    err = ks_print_help (ctrl, data);
  else
    err = 0;

  return err;
}

/* Convert a keyspec to a filter.  Return an error if the keyspec is
   bad or is not supported.  The filter is escaped and returned in
   *filter.  It is the caller's responsibility to free *filter.
   *filter is only set if this function returns success (i.e., 0).  */
static gpg_error_t
keyspec_to_ldap_filter (const char *keyspec, char **filter, int only_exact,
                        unsigned int serverinfo)
{
  /* Remove search type indicator and adjust PATTERN accordingly.
     Note: don't include a preceding 0x when searching by keyid.  */

  /* XXX: Should we include disabled / revoke options?  */
  KEYDB_SEARCH_DESC desc;
  char *f = NULL;
  char *freeme = NULL;
  char *p;

  gpg_error_t err = classify_user_id (keyspec, &desc, 1);
  if (err)
    return err;

  switch (desc.mode)
    {
    case KEYDB_SEARCH_MODE_EXACT:
      f = xasprintf ("(pgpUserID=%s)",
		     (freeme = ldap_escape_filter (desc.u.name)));
      break;

    case KEYDB_SEARCH_MODE_SUBSTR:
      if (! only_exact)
	f = xasprintf ("(pgpUserID=*%s*)",
		       (freeme = ldap_escape_filter (desc.u.name)));
      break;

    case KEYDB_SEARCH_MODE_MAIL:
      freeme = ldap_escape_filter (desc.u.name);
      if (!freeme)
        break;
      if (*freeme == '<' && freeme[1] && freeme[2])
        {
          /* Strip angle brackets.  Note that it is does not
           * matter whether we work on the plan or LDAP escaped
           * version of the mailbox.  */
          p = freeme + 1;
          if (p[strlen(p)-1] == '>')
            p[strlen(p)-1] = 0;
        }
      else
        p = freeme;
      if ((serverinfo & SERVERINFO_SCHEMAV2))
        f = xasprintf ("(gpgMailbox=%s)", p);
      else if (!only_exact)
        f = xasprintf ("(pgpUserID=*<%s>*)", p);
      break;

    case KEYDB_SEARCH_MODE_MAILSUB:
      if (! only_exact)
	f = xasprintf ("(pgpUserID=*<*%s*>*)",
		       (freeme = ldap_escape_filter (desc.u.name)));
      break;

    case KEYDB_SEARCH_MODE_MAILEND:
      if (! only_exact)
	f = xasprintf ("(pgpUserID=*<*%s>*)",
		       (freeme = ldap_escape_filter (desc.u.name)));
      break;

    case KEYDB_SEARCH_MODE_SHORT_KID:
      f = xasprintf ("(pgpKeyID=%08lX)", (ulong) desc.u.kid[1]);
      break;
    case KEYDB_SEARCH_MODE_LONG_KID:
      f = xasprintf ("(pgpCertID=%08lX%08lX)",
		     (ulong) desc.u.kid[0], (ulong) desc.u.kid[1]);
      break;

    case KEYDB_SEARCH_MODE_FPR16:
    case KEYDB_SEARCH_MODE_FPR20:
    case KEYDB_SEARCH_MODE_FPR:
      if ((serverinfo & SERVERINFO_SCHEMAV2))
        {
          freeme = bin2hex (desc.u.fpr, 20, NULL);
          if (!freeme)
            return gpg_error_from_syserror ();
          f = xasprintf ("(|(gpgFingerprint=%s)(gpgSubFingerprint=%s))",
                         freeme, freeme);
          /* FIXME: For an exact search and in case of a match on
           * gpgSubFingerprint we need to check that there is only one
           * matching value.  */
        }
      break;

    case KEYDB_SEARCH_MODE_ISSUER:
    case KEYDB_SEARCH_MODE_ISSUER_SN:
    case KEYDB_SEARCH_MODE_SN:
    case KEYDB_SEARCH_MODE_SUBJECT:
    case KEYDB_SEARCH_MODE_KEYGRIP:
    case KEYDB_SEARCH_MODE_WORDS:
    case KEYDB_SEARCH_MODE_FIRST:
    case KEYDB_SEARCH_MODE_NEXT:
    default:
      break;
    }

  xfree (freeme);

  if (! f)
    {
      log_error ("Unsupported search mode.\n");
      return gpg_error (GPG_ERR_NOT_SUPPORTED);
    }

  *filter = f;

  return 0;
}



/* Connect to an LDAP server and interrogate it.

     - uri describes the server to connect to and various options
       including whether to use TLS and the username and password (see
       ldap_parse_uri for a description of the various fields).

   This function returns:

     - The ldap connection handle in *LDAP_CONNP.

     - The base DN for the PGP key space by querying the
       pgpBaseKeySpaceDN attribute (This is normally
       'ou=PGP Keys,dc=EXAMPLE,dc=ORG').

     - The attribute to lookup to find the pgp key.  This is either
       'pgpKey' or 'pgpKeyV2'.

     - Whether this is a real ldap server.  (It's unclear what this
       exactly means.)

   The values are returned in the passed variables.  If you pass NULL,
   then the value won't be returned.  It is the caller's
   responsibility to release *LDAP_CONNP with ldap_unbind and xfree
   *BASEDNP.

   If this function successfully interrogated the server, it returns
   0.  If there was an LDAP error, it returns the LDAP error code.  If
   an error occurred, *basednp, etc., are undefined (and don't need to
   be freed.)

   R_SERVERINFO receives information about the server.

   If no LDAP error occurred, you still need to check that *basednp is
   valid.  If it is NULL, then the server does not appear to be an
   OpenPGP Keyserver.  */
static int
my_ldap_connect (parsed_uri_t uri, LDAP **ldap_connp,
                 char **basednp, unsigned int *r_serverinfo)
{
  int err = 0;
  LDAP *ldap_conn = NULL;
  char *user = uri->auth;
  struct uri_tuple_s *password_param;
  char *password;
  char *basedn = NULL;

  *r_serverinfo = 0;

  password_param = uri_query_lookup (uri, "password");
  password = password_param ? password_param->value : NULL;

  if (opt.debug)
    log_debug ("my_ldap_connect(%s:%d/%s????%s%s%s%s%s%s)\n",
               uri->host, uri->port,
               uri->path ? uri->path : "",
               uri->auth ? "bindname=" : "",
               uri->auth ? uri->auth : "",
               uri->auth && password ? "," : "",
               password ? "password=" : "",
               password ? ">not shown<": "",
               uri->ad_current? " auth=>current_user<":"");

  /* If the uri specifies a secure connection and we don't support
     TLS, then fail; don't silently revert to an insecure
     connection.  */
  if (uri->use_tls)
    {
#ifndef HAVE_LDAP_START_TLS_S
      log_error ("Can't use LDAP to connect to the server: no TLS support.");
      err = GPG_ERR_LDAP_NOT_SUPPORTED;
      goto out;
#endif
    }

  if (uri->ad_current)
    ldap_conn = ldap_init (NULL, uri->port);
  else
    ldap_conn = ldap_init (uri->host, uri->port);
  if (!ldap_conn)
    {
      err = gpg_err_code_from_syserror ();
      if (uri->ad_current)
        log_error ("error initializing LDAP for current user\n");
      else
        log_error ("error initializing LDAP for (%s://%s:%d)\n",
                   uri->scheme, uri->host, uri->port);
      goto out;
    }

#ifdef HAVE_LDAP_SET_OPTION
  {
    int ver = LDAP_VERSION3;

    err = ldap_set_option (ldap_conn, LDAP_OPT_PROTOCOL_VERSION, &ver);
    if (err != LDAP_SUCCESS)
      {
	log_error ("ks-ldap: unable to go to LDAP 3: %s\n",
		   ldap_err2string (err));
	goto out;
      }
  }
#endif

  /* XXX: It would be nice to have an option to provide the server's
     certificate.  */
#if 0
#if defined(LDAP_OPT_X_TLS_CACERTFILE) && defined(HAVE_LDAP_SET_OPTION)
  err = ldap_set_option (NULL, LDAP_OPT_X_TLS_CACERTFILE, ca_cert_file);
  if (err)
    {
      log_error ("unable to set ca-cert-file to '%s': %s\n",
		 ca_cert_file, ldap_err2string (err));
      goto out;
    }
#endif /* LDAP_OPT_X_TLS_CACERTFILE && HAVE_LDAP_SET_OPTION */
#endif

#ifdef HAVE_LDAP_START_TLS_S
  if (uri->use_tls)
    {
      /* XXX: We need an option to determine whether to abort if the
	 certificate is bad or not.  Right now we conservatively
	 default to checking the certificate and aborting.  */
#ifndef HAVE_W32_SYSTEM
      int check_cert = LDAP_OPT_X_TLS_HARD; /* LDAP_OPT_X_TLS_NEVER */

      err = ldap_set_option (ldap_conn,
			     LDAP_OPT_X_TLS_REQUIRE_CERT, &check_cert);
      if (err)
	{
	  log_error ("error setting TLS option on LDAP connection\n");
	  goto out;
	}
#else
      /* On Windows, the certificates are checked by default.  If the
	 option to disable checking mentioned above is ever
	 implemented, the way to do that on Windows is to install a
	 callback routine using ldap_set_option (..,
	 LDAP_OPT_SERVER_CERTIFICATE, ..); */
#endif

      npth_unprotect ();
      err = ldap_start_tls_s (ldap_conn,
#ifdef HAVE_W32_SYSTEM
			      /* ServerReturnValue, result */
			      NULL, NULL,
#endif
			      /* ServerControls, ClientControls */
			      NULL, NULL);
      npth_protect ();
      if (err)
	{
	  log_error ("error connecting to LDAP server with TLS\n");
	  goto out;
	}
    }
#endif

  if (uri->ad_current)
    {
      if (opt.debug)
        log_debug ("LDAP bind to current user via AD\n");
#ifdef HAVE_W32_SYSTEM
      npth_unprotect ();
      err = ldap_bind_s (ldap_conn, NULL, NULL, LDAP_AUTH_NEGOTIATE);
      npth_protect ();
#else
      err = gpg_error (GPG_ERR_NOT_SUPPORTED);
#endif
      if (err != LDAP_SUCCESS)
	{
	  log_error ("error binding to LDAP via AD: %s\n",
                     ldap_err2string (err));
	  goto out;
	}
    }
  else if (uri->auth)
    {
      if (opt.debug)
        log_debug ("LDAP bind to %s, password %s\n",
                   user, password ? ">not shown<" : ">none<");

      npth_unprotect ();
      err = ldap_simple_bind_s (ldap_conn, user, password);
      npth_protect ();
      if (err != LDAP_SUCCESS)
	{
	  log_error ("error binding to LDAP: %s\n", ldap_err2string (err));
	  goto out;
	}
    }
  else
    {
      /* By default we don't bind as there is usually no need to.  */
    }

  if (uri->path && *uri->path)
    {
      /* User specified base DN.  */
      basedn = xstrdup (uri->path);

      /* If the user specifies a base DN, then we know the server is a
       * real LDAP server.  */
      *r_serverinfo |= SERVERINFO_REALLDAP;
    }
  else
    { /* Look for namingContexts.  */
      LDAPMessage *res = NULL;
      char *attr[] = { "namingContexts", NULL };

      npth_unprotect ();
      err = ldap_search_s (ldap_conn, "", LDAP_SCOPE_BASE,
			   "(objectClass=*)", attr, 0, &res);
      npth_protect ();

      if (err == LDAP_SUCCESS)
	{
	  char **context;

          npth_unprotect ();
          context = ldap_get_values (ldap_conn, res, "namingContexts");
          npth_protect ();
	  if (context)
	    {
              /* We found some, so try each namingContext as the
               * search base and look for pgpBaseKeySpaceDN.  Because
               * we found this, we know we're talking to a regular-ish
               * LDAP server and not an LDAP keyserver.  */
	      int i;
	      char *attr2[] =
		{ "pgpBaseKeySpaceDN", "pgpVersion", "pgpSoftware", NULL };

              *r_serverinfo |= SERVERINFO_REALLDAP;

	      for (i = 0; context[i] && ! basedn; i++)
		{
		  char **vals;
		  LDAPMessage *si_res;
                  int is_gnupg = 0;

                  {
                    char *object = xasprintf ("cn=pgpServerInfo,%s",
                                              context[i]);
                    npth_unprotect ();
                    err = ldap_search_s (ldap_conn, object, LDAP_SCOPE_BASE,
                                         "(objectClass=*)", attr2, 0, &si_res);
                    npth_protect ();
                    xfree (object);
                  }

		  if (err == LDAP_SUCCESS)
		    {
		      vals = ldap_get_values (ldap_conn, si_res,
					      "pgpBaseKeySpaceDN");
		      if (vals)
			{
			  basedn = xtrystrdup (vals[0]);
			  ldap_value_free (vals);
			}

		      vals = ldap_get_values (ldap_conn, si_res,
					      "pgpSoftware");
		      if (vals)
			{
                          if (opt.debug)
                            log_debug ("Server: \t%s\n", vals[0]);
                          if (!ascii_strcasecmp (vals[0], "GnuPG"))
                            is_gnupg = 1;
			  ldap_value_free (vals);
			}

		      vals = ldap_get_values (ldap_conn, si_res,
					      "pgpVersion");
		      if (vals)
			{
                          if (opt.debug)
                            log_debug ("Version:\t%s\n", vals[0]);
                          if (is_gnupg)
                            {
                              char *fields[2];
                              int nfields;
                              nfields = split_fields (vals[0],
                                                      fields, DIM(fields));
                              if (nfields > 0 && atoi(fields[0]) > 1)
                                *r_serverinfo |= SERVERINFO_SCHEMAV2;
                              if (nfields > 1
                                  && !ascii_strcasecmp (fields[1], "ntds"))
                                *r_serverinfo |= SERVERINFO_NTDS;
                            }
			  ldap_value_free (vals);
			}
		    }

		  /* From man ldap_search_s: "res parameter of
		     ldap_search_ext_s() and ldap_search_s() should be
		     freed with ldap_msgfree() regardless of return
		     value of these functions.  */
		  ldap_msgfree (si_res);
		}

	      ldap_value_free (context);
	    }
	}
      else
	{
	  /* We don't have an answer yet, which means the server might
	     be a PGP.com keyserver. */
	  char **vals;
	  LDAPMessage *si_res = NULL;

	  char *attr2[] = { "pgpBaseKeySpaceDN", "version", "software", NULL };

          npth_unprotect ();
	  err = ldap_search_s (ldap_conn, "cn=pgpServerInfo", LDAP_SCOPE_BASE,
			       "(objectClass=*)", attr2, 0, &si_res);
          npth_protect ();
	  if (err == LDAP_SUCCESS)
	    {
	      /* For the PGP LDAP keyserver, this is always
	       * "OU=ACTIVE,O=PGP KEYSPACE,C=US", but it might not be
               * in the future. */

	      vals = ldap_get_values (ldap_conn, si_res, "baseKeySpaceDN");
	      if (vals)
		{
		  basedn = xtrystrdup (vals[0]);
		  ldap_value_free (vals);
		}

	      vals = ldap_get_values (ldap_conn, si_res, "software");
	      if (vals)
		{
                  if (opt.debug)
                    log_debug ("ks-ldap: PGP Server: \t%s\n", vals[0]);
		  ldap_value_free (vals);
		}

	      vals = ldap_get_values (ldap_conn, si_res, "version");
	      if (vals)
		{
                  if (opt.debug)
                    log_debug ("ks-ldap: PGP Server Version:\t%s\n", vals[0]);

		  /* If the version is high enough, use the new
		     pgpKeyV2 attribute.  This design is iffy at best,
		     but it matches how PGP does it.  I figure the NAI
		     folks assumed that there would never be an LDAP
		     keyserver vendor with a different numbering
		     scheme. */
		  if (atoi (vals[0]) > 1)
                    *r_serverinfo |= SERVERINFO_PGPKEYV2;

		  ldap_value_free (vals);
		}
	    }

	  ldap_msgfree (si_res);
	}

      /* From man ldap_search_s: "res parameter of ldap_search_ext_s()
	 and ldap_search_s() should be freed with ldap_msgfree()
	 regardless of return value of these functions.  */
      ldap_msgfree (res);
    }

 out:
  if (!err && opt.debug)
    {
      log_debug ("ldap_conn: %p\n", ldap_conn);
      log_debug ("server_type: %s\n", ((*r_serverinfo & SERVERINFO_REALLDAP)
                                       ? "LDAP" : "PGP.com keyserver") );
      log_debug ("basedn: %s\n", basedn);
      log_debug ("pgpkeyattr: %s\n",
                 (*r_serverinfo & SERVERINFO_PGPKEYV2)? "pgpKeyV2":"pgpKey");
    }

  if (err)
    xfree (basedn);
  else
    {
      if (basednp)
	*basednp = basedn;
      else
	xfree (basedn);
    }

  if (err)
    {
      if (ldap_conn)
	ldap_unbind (ldap_conn);
    }
  else
    *ldap_connp = ldap_conn;

  return err;
}

/* Extract keys from an LDAP reply and write them out to the output
   stream OUTPUT in a format GnuPG can import (either the OpenPGP
   binary format or armored format).  */
static void
extract_keys (estream_t output,
	      LDAP *ldap_conn, const char *certid, LDAPMessage *message)
{
  char **vals;

  es_fprintf (output, "INFO %s BEGIN\n", certid);
  es_fprintf (output, "pub:%s:", certid);

  /* Note: ldap_get_values returns a NULL terminated array of
     strings.  */
  vals = ldap_get_values (ldap_conn, message, "pgpkeytype");
  if (vals && vals[0])
    {
      if (strcmp (vals[0], "RSA") == 0)
	es_fprintf  (output, "1");
      else if (strcmp (vals[0],"DSS/DH") == 0)
	es_fprintf (output, "17");
      ldap_value_free (vals);
    }

  es_fprintf (output, ":");

  vals = ldap_get_values (ldap_conn, message, "pgpkeysize");
  if (vals && vals[0])
    {
      int v = atoi (vals[0]);
      if (v > 0)
	es_fprintf (output, "%d", v);
      ldap_value_free (vals);
    }

  es_fprintf (output, ":");

  vals = ldap_get_values (ldap_conn, message, "pgpkeycreatetime");
  if (vals && vals[0])
    {
      if (strlen (vals[0]) == 15)
	es_fprintf (output, "%u", (unsigned int) ldap2epochtime (vals[0]));
      ldap_value_free (vals);
    }

  es_fprintf (output, ":");

  vals = ldap_get_values (ldap_conn, message, "pgpkeyexpiretime");
  if (vals && vals[0])
    {
      if (strlen (vals[0]) == 15)
	es_fprintf (output, "%u", (unsigned int) ldap2epochtime (vals[0]));
      ldap_value_free (vals);
    }

  es_fprintf (output, ":");

  vals = ldap_get_values (ldap_conn, message, "pgprevoked");
  if (vals && vals[0])
    {
      if (atoi (vals[0]) == 1)
	es_fprintf (output, "r");
      ldap_value_free (vals);
    }

  es_fprintf (output, "\n");

  vals = ldap_get_values (ldap_conn, message, "pgpuserid");
  if (vals && vals[0])
    {
      int i;
      for (i = 0; vals[i]; i++)
	es_fprintf (output, "uid:%s\n", vals[i]);
      ldap_value_free (vals);
    }

  es_fprintf (output, "INFO %s END\n", certid);
}

/* Get the key described key the KEYSPEC string from the keyserver
   identified by URI.  On success R_FP has an open stream to read the
   data.  */
gpg_error_t
ks_ldap_get (ctrl_t ctrl, parsed_uri_t uri, const char *keyspec,
	     estream_t *r_fp)
{
  gpg_error_t err = 0;
  int ldap_err;
  unsigned int serverinfo;
  char *filter = NULL;
  LDAP *ldap_conn = NULL;
  char *basedn = NULL;
  estream_t fp = NULL;
  LDAPMessage *message = NULL;

  (void) ctrl;

  if (dirmngr_use_tor ())
    {
      /* For now we do not support LDAP over Tor.  */
      log_error (_("LDAP access not possible due to Tor mode\n"));
      return gpg_error (GPG_ERR_NOT_SUPPORTED);
    }

  /* Make sure we are talking to an OpenPGP LDAP server.  */
  ldap_err = my_ldap_connect (uri, &ldap_conn, &basedn, &serverinfo);
  if (ldap_err || !basedn)
    {
      if (ldap_err)
	err = ldap_err_to_gpg_err (ldap_err);
      else
	err = gpg_error (GPG_ERR_GENERAL);
      goto out;
    }

  /* Now that we have information about the server we can construct a
   * query best suited for the capabilities of the server.  */
  err = keyspec_to_ldap_filter (keyspec, &filter, 1, serverinfo);
  if (err)
    goto out;

  if (opt.debug)
    log_debug ("ks-ldap: using filter: %s\n", filter);

  {
    /* The ordering is significant.  Specifically, "pgpcertid" needs
       to be the second item in the list, since everything after it
       may be discarded we aren't in verbose mode. */
    char *attrs[] =
      {
	"dummy",
	"pgpcertid", "pgpuserid", "pgpkeyid", "pgprevoked", "pgpdisabled",
	"pgpkeycreatetime", "modifytimestamp", "pgpkeysize", "pgpkeytype",
	NULL
      };
    /* 1 if we want just attribute types; 0 if we want both attribute
     * types and values.  */
    int attrsonly = 0;
    int count;

    /* Replace "dummy".  */
    attrs[0] = (serverinfo & SERVERINFO_PGPKEYV2)? "pgpKeyV2" : "pgpKey";

    npth_unprotect ();
    ldap_err = ldap_search_s (ldap_conn, basedn, LDAP_SCOPE_SUBTREE,
			      filter, attrs, attrsonly, &message);
    npth_protect ();
    if (ldap_err)
      {
	err = ldap_err_to_gpg_err (ldap_err);

	log_error ("ks-ldap: LDAP search error: %s\n",
		   ldap_err2string (ldap_err));
	goto out;
      }

    count = ldap_count_entries (ldap_conn, message);
    if (count < 1)
      {
	log_info ("ks-ldap: key %s not found on keyserver\n", keyspec);

	if (count == -1)
	  err = ldap_to_gpg_err (ldap_conn);
	else
	  err = gpg_error (GPG_ERR_NO_DATA);

	goto out;
      }

    {
      /* There may be more than one unique result for a given keyID,
	 so we should fetch them all (test this by fetching short key
	 id 0xDEADBEEF). */

      /* The set of entries that we've seen.  */
      strlist_t seen = NULL;
      LDAPMessage *each;

      for (npth_unprotect (),
             each = ldap_first_entry (ldap_conn, message),
             npth_protect ();
	   each;
           npth_unprotect (),
             each = ldap_next_entry (ldap_conn, each),
             npth_protect ())
	{
	  char **vals;
	  char **certid;

	  /* Use the long keyid to remove duplicates.  The LDAP
	     server returns the same keyid more than once if there
	     are multiple user IDs on the key.  Note that this does
	     NOT mean that a keyid that exists multiple times on the
	     keyserver will not be fetched.  It means that each KEY,
	     no matter how many user IDs share its keyid, will be
	     fetched only once.  If a keyid that belongs to more
	     than one key is fetched, the server quite properly
	     responds with all matching keys. -ds */

	  certid = ldap_get_values (ldap_conn, each, "pgpcertid");
	  if (certid && certid[0])
	    {
	      if (! strlist_find (seen, certid[0]))
		{
		  /* It's not a duplicate, add it */

		  add_to_strlist (&seen, certid[0]);

		  if (! fp)
		    fp = es_fopenmem(0, "rw");

		  extract_keys (fp, ldap_conn, certid[0], each);

		  vals = ldap_get_values (ldap_conn, each, attrs[0]);
		  if (! vals)
		    {
		      err = ldap_to_gpg_err (ldap_conn);
		      log_error("ks-ldap: unable to retrieve key %s "
				"from keyserver\n", certid[0]);
		      goto out;
		    }
		  else
		    {
		      /* We should strip the new lines.  */
		      es_fprintf (fp, "KEY 0x%s BEGIN\n", certid[0]);
		      es_fputs (vals[0], fp);
		      es_fprintf (fp, "\nKEY 0x%s END\n", certid[0]);

		      ldap_value_free (vals);
		    }
		}
	    }

	  ldap_value_free (certid);
	}

      free_strlist (seen);

      if (! fp)
	err = gpg_error (GPG_ERR_NO_DATA);
    }
  }

 out:
  if (message)
    ldap_msgfree (message);

  if (err)
    {
      if (fp)
	es_fclose (fp);
    }
  else
    {
      if (fp)
	es_fseek (fp, 0, SEEK_SET);

      *r_fp = fp;
    }

  xfree (basedn);

  if (ldap_conn)
    ldap_unbind (ldap_conn);

  xfree (filter);

  return err;
}


/* Search the keyserver identified by URI for keys matching PATTERN.
   On success R_FP has an open stream to read the data.  */
gpg_error_t
ks_ldap_search (ctrl_t ctrl, parsed_uri_t uri, const char *pattern,
		estream_t *r_fp)
{
  gpg_error_t err;
  int ldap_err;
  unsigned int serverinfo;
  char *filter = NULL;
  LDAP *ldap_conn = NULL;
  char *basedn = NULL;
  estream_t fp = NULL;

  (void) ctrl;

  if (dirmngr_use_tor ())
    {
      /* For now we do not support LDAP over Tor.  */
      log_error (_("LDAP access not possible due to Tor mode\n"));
      return gpg_error (GPG_ERR_NOT_SUPPORTED);
    }

  /* Make sure we are talking to an OpenPGP LDAP server.  */
  ldap_err = my_ldap_connect (uri, &ldap_conn, &basedn, &serverinfo);
  if (ldap_err || !basedn)
    {
      if (ldap_err)
	err = ldap_err_to_gpg_err (ldap_err);
      else
	err = GPG_ERR_GENERAL;
      goto out;
    }

  /* Now that we have information about the server we can construct a
   * query best suited for the capabilities of the server.  */
  err = keyspec_to_ldap_filter (pattern, &filter, 0, serverinfo);
  if (err)
    {
      log_error ("Bad search pattern: '%s'\n", pattern);
      goto out;
    }

  /* Even if we have no results, we want to return a stream.  */
  fp = es_fopenmem(0, "rw");
  if (!fp)
    {
      err = gpg_error_from_syserror ();
      goto out;
    }

  {
    char **vals;
    LDAPMessage *res, *each;
    int count = 0;
    strlist_t dupelist = NULL;

    /* The maximum size of the search, including the optional stuff
       and the trailing \0 */
    char *attrs[] =
      {
	"pgpcertid", "pgpuserid", "pgprevoked", "pgpdisabled",
	"pgpkeycreatetime", "pgpkeyexpiretime", "modifytimestamp",
	"pgpkeysize", "pgpkeytype", NULL
      };

    if (opt.debug)
      log_debug ("SEARCH '%s' => '%s' BEGIN\n", pattern, filter);

    npth_unprotect ();
    ldap_err = ldap_search_s (ldap_conn, basedn,
			      LDAP_SCOPE_SUBTREE, filter, attrs, 0, &res);
    npth_protect ();

    xfree (filter);
    filter = NULL;

    if (ldap_err != LDAP_SUCCESS && ldap_err != LDAP_SIZELIMIT_EXCEEDED)
      {
	err = ldap_err_to_gpg_err (ldap_err);

	log_error ("SEARCH %s FAILED %d\n", pattern, err);
	log_error ("ks-ldap: LDAP search error: %s\n",
		   ldap_err2string (err));
	goto out;
    }

    /* The LDAP server doesn't return a real count of unique keys, so we
       can't use ldap_count_entries here. */
    for (npth_unprotect (),
           each = ldap_first_entry (ldap_conn, res),
           npth_protect ();
	 each;
         npth_unprotect (),
           each = ldap_next_entry (ldap_conn, each),
           npth_protect ())
      {
	char **certid = ldap_get_values (ldap_conn, each, "pgpcertid");
	if (certid && certid[0] && ! strlist_find (dupelist, certid[0]))
	  {
	    add_to_strlist (&dupelist, certid[0]);
	    count++;
	  }
      }

    if (ldap_err == LDAP_SIZELIMIT_EXCEEDED)
      {
	if (count == 1)
	  log_error ("ks-ldap: search results exceeded server limit."
		     "  First 1 result shown.\n");
	else
	  log_error ("ks-ldap: search results exceeded server limit."
		     "  First %d results shown.\n", count);
      }

    free_strlist (dupelist);
    dupelist = NULL;

    if (count < 1)
      es_fputs ("info:1:0\n", fp);
    else
      {
	es_fprintf (fp, "info:1:%d\n", count);

	for (each = ldap_first_entry (ldap_conn, res);
	     each;
	     each = ldap_next_entry (ldap_conn, each))
	  {
	    char **certid;
	    LDAPMessage *uids;

	    certid = ldap_get_values (ldap_conn, each, "pgpcertid");
	    if (! certid || ! certid[0])
	      continue;

	    /* Have we seen this certid before? */
	    if (! strlist_find (dupelist, certid[0]))
	      {
		add_to_strlist (&dupelist, certid[0]);

		es_fprintf (fp, "pub:%s:",certid[0]);

		vals = ldap_get_values (ldap_conn, each, "pgpkeytype");
		if (vals)
		  {
		    /* The LDAP server doesn't exactly handle this
		       well. */
		    if (strcasecmp (vals[0], "RSA") == 0)
		      es_fputs ("1", fp);
		    else if (strcasecmp (vals[0], "DSS/DH") == 0)
		      es_fputs ("17", fp);
		    ldap_value_free (vals);
		  }

		es_fputc (':', fp);

		vals = ldap_get_values (ldap_conn, each, "pgpkeysize");
		if (vals)
		  {
		    /* Not sure why, but some keys are listed with a
		       key size of 0.  Treat that like an unknown. */
		    if (atoi (vals[0]) > 0)
		      es_fprintf (fp, "%d", atoi (vals[0]));
		    ldap_value_free (vals);
		  }

		es_fputc (':', fp);

		/* YYYYMMDDHHmmssZ */

		vals = ldap_get_values (ldap_conn, each, "pgpkeycreatetime");
		if(vals && strlen (vals[0]) == 15)
		  {
		    es_fprintf (fp, "%u",
				(unsigned int) ldap2epochtime(vals[0]));
		    ldap_value_free (vals);
		  }

		es_fputc (':', fp);

		vals = ldap_get_values (ldap_conn, each, "pgpkeyexpiretime");
		if (vals && strlen (vals[0]) == 15)
		  {
		    es_fprintf (fp, "%u",
				(unsigned int) ldap2epochtime (vals[0]));
		    ldap_value_free (vals);
		  }

		es_fputc (':', fp);

		vals = ldap_get_values (ldap_conn, each, "pgprevoked");
		if (vals)
		  {
		    if (atoi (vals[0]) == 1)
		      es_fprintf (fp, "r");
		    ldap_value_free (vals);
		  }

		vals = ldap_get_values (ldap_conn, each, "pgpdisabled");
		if (vals)
		  {
		    if (atoi (vals[0]) ==1)
		      es_fprintf (fp, "d");
		    ldap_value_free (vals);
		  }

#if 0
		/* This is not yet specified in the keyserver
		   protocol, but may be someday. */
		es_fputc (':', fp);

		vals = ldap_get_values (ldap_conn, each, "modifytimestamp");
		if(vals && strlen (vals[0]) == 15)
		  {
		    es_fprintf (fp, "%u",
				(unsigned int) ldap2epochtime (vals[0]));
		    ldap_value_free (vals);
		  }
#endif

		es_fprintf (fp, "\n");

		/* Now print all the uids that have this certid */
		for (uids = ldap_first_entry (ldap_conn, res);
		     uids;
		     uids = ldap_next_entry (ldap_conn, uids))
		  {
		    vals = ldap_get_values (ldap_conn, uids, "pgpcertid");
		    if (! vals)
		      continue;

		    if (strcasecmp (certid[0], vals[0]) == 0)
		      {
			char **uidvals;

			es_fprintf (fp, "uid:");

			uidvals = ldap_get_values (ldap_conn,
						   uids, "pgpuserid");
			if (uidvals)
			  {
			    /* Need to escape any colons */
			    char *quoted = percent_escape (uidvals[0], NULL);
			    es_fputs (quoted, fp);
			    xfree (quoted);
			    ldap_value_free (uidvals);
			  }

			es_fprintf (fp, "\n");
		      }

		    ldap_value_free(vals);
		  }
	      }

	      ldap_value_free (certid);
	  }
      }

    ldap_msgfree (res);
    free_strlist (dupelist);
  }

  if (opt.debug)
    log_debug ("SEARCH %s END\n", pattern);

 out:
  if (err)
    {
      if (fp)
	es_fclose (fp);
    }
  else
    {
      /* Return the read stream.  */
      if (fp)
	es_fseek (fp, 0, SEEK_SET);

      *r_fp = fp;
    }

  xfree (basedn);

  if (ldap_conn)
    ldap_unbind (ldap_conn);

  xfree (filter);

  return err;
}



/* A modlist describes a set of changes to an LDAP entry.  (An entry
   consists of 1 or more attributes.  Attributes are <name, value>
   pairs.  Note: an attribute may be multi-valued in which case
   multiple values are associated with a single name.)

   A modlist is a NULL terminated array of struct LDAPMod's.

   Thus, if we have:

     LDAPMod **modlist;

   Then:

     modlist[i]

   Is the ith modification.

   Each LDAPMod describes a change to a single attribute.  Further,
   there is one modification for each attribute that we want to
   change.  The attribute's new value is stored in LDAPMod.mod_values.
   If the attribute is multi-valued, we still only use a single
   LDAPMod structure: mod_values is a NULL-terminated array of
   strings.  To delete an attribute from an entry, we set mod_values
   to NULL.

   Thus, if:

     modlist[i]->mod_values == NULL

   then we remove the attribute.

   (Using LDAP_MOD_DELETE doesn't work here as we don't know if the
   attribute in question exists or not.)

   Note: this function does NOT copy or free ATTR.  It does copy
   VALUE.  */
static void
modlist_add (LDAPMod ***modlistp, char *attr, const char *value)
{
  LDAPMod **modlist = *modlistp;

  LDAPMod **m;
  int nummods = 0;

  /* Search modlist for the attribute we're playing with.  If modlist
     is NULL, then the list is empty.  Recall: modlist is a NULL
     terminated array.  */
  for (m = modlist; m && *m; m++, nummods ++)
    {
      /* The attribute is already on the list.  */
      char **ptr;
      int numvalues = 0;

      if (strcasecmp ((*m)->mod_type, attr) != 0)
	continue;

      /* We have this attribute already, so when the REPLACE happens,
	 the server attributes will be replaced anyway. */
      if (! value)
	return;

      /* Attributes can be multi-valued.  See if the value is already
	 present.  mod_values is a NULL terminated array of pointers.
	 Note: mod_values can be NULL.  */
      for (ptr = (*m)->mod_values; ptr && *ptr; ptr++)
	{
	  if (strcmp (*ptr, value) == 0)
	    /* Duplicate value, we're done.  */
	    return;
	  numvalues ++;
	}

      /* Append the value.  */
      ptr = xrealloc ((*m)->mod_values, sizeof (char *) * (numvalues + 2));

      (*m)->mod_values = ptr;
      ptr[numvalues] = xstrdup (value);

      ptr[numvalues + 1] = NULL;

      return;
    }

  /* We didn't find the attr, so make one and add it to the end */

  /* Like attribute values, the list of attributes is NULL terminated
     array of pointers.  */
  modlist = xrealloc (modlist, sizeof (LDAPMod *) * (nummods + 2));

  *modlistp = modlist;
  modlist[nummods] = xmalloc (sizeof (LDAPMod));

  modlist[nummods]->mod_op = LDAP_MOD_REPLACE;
  modlist[nummods]->mod_type = attr;
  if (value)
    {
      modlist[nummods]->mod_values = xmalloc (sizeof(char *) * 2);

      modlist[nummods]->mod_values[0] = xstrdup (value);
      modlist[nummods]->mod_values[1] = NULL;
    }
  else
    modlist[nummods]->mod_values = NULL;

  modlist[nummods + 1] = NULL;

  return;
}

/* Look up the value of an attribute in the specified modlist.  If the
   attribute is not on the mod list, returns NULL.  The result is a
   NULL-terminated array of strings.  Don't change it.  */
static char **
modlist_lookup (LDAPMod **modlist, const char *attr)
{
  LDAPMod **m;
  for (m = modlist; m && *m; m++)
    {
      if (strcasecmp ((*m)->mod_type, attr) != 0)
	continue;

      return (*m)->mod_values;
    }

  return NULL;
}

/* Dump a modlist to a file.  This is useful for debugging.  */
static estream_t modlist_dump (LDAPMod **modlist, estream_t output)
  GPGRT_ATTR_USED;

static estream_t
modlist_dump (LDAPMod **modlist, estream_t output)
{
  LDAPMod **m;

  int opened = 0;

  if (! output)
    {
      output = es_fopenmem (0, "rw");
      if (!output)
        return NULL;
      opened = 1;
    }

  for (m = modlist; m && *m; m++)
    {
      es_fprintf (output, "  %s:", (*m)->mod_type);

      if (! (*m)->mod_values)
	es_fprintf(output, " delete.\n");
      else
	{
	  char **ptr;
	  int i;

	  int multi = 0;
	  if ((*m)->mod_values[0] && (*m)->mod_values[1])
	    /* Have at least 2.  */
	    multi = 1;

	  if (multi)
	    es_fprintf (output, "\n");

	  for ((ptr = (*m)->mod_values), (i = 1); ptr && *ptr; ptr++, i ++)
	    {
	      /* Assuming terminals are about 80 characters wide,
		 display at most about 10 lines of debugging
		 output.  If we do trim the buffer, append '...' to
		 the end.  */
	      const int max_len = 10 * 70;
	      size_t value_len = strlen (*ptr);
	      int elide = value_len > max_len;

	      if (multi)
		es_fprintf (output, "    %d. ", i);
	      es_fprintf (output, "`%.*s", max_len, *ptr);
	      if (elide)
		es_fprintf (output, "...' (%zd bytes elided)",
			    value_len - max_len);
	      else
		es_fprintf (output, "'");
	      es_fprintf (output, "\n");
	    }
	}
    }

  if (opened)
    es_fseek (output, 0, SEEK_SET);

  return output;
}

/* Free all of the memory allocated by the mod list.  This assumes
   that the attribute names don't have to be freed, but the attributes
   values do.  (Which is what modlist_add does.)  */
static void
modlist_free (LDAPMod **modlist)
{
  LDAPMod **ml;

  if (! modlist)
    return;

  /* Unwind and free the whole modlist structure */

  /* The modlist is a NULL terminated array of pointers.  */
  for (ml = modlist; *ml; ml++)
    {
      LDAPMod *mod = *ml;
      char **ptr;

      /* The list of values is a NULL termianted array of pointers.
	 If the list is NULL, there are no values.  */

      if (mod->mod_values)
	{
	  for (ptr = mod->mod_values; *ptr; ptr++)
	    xfree (*ptr);

	  xfree (mod->mod_values);
	}

      xfree (mod);
    }
  xfree (modlist);
}

/* Append two onto the end of one.  Two is not freed, but its pointers
   are now part of one.  Make sure you don't free them both!

   As long as you don't add anything to ONE, TWO is still valid.
   After that all bets are off.  */
static void
modlists_join (LDAPMod ***one, LDAPMod **two)
{
  int i, one_count = 0, two_count = 0;
  LDAPMod **grow;

  if (!*two)
    /* two is empty.  Nothing to do.  */
    return;

  if (!*one)
    /* one is empty.  Just set it equal to *two.  */
    {
      *one = two;
      return;
    }

  for (grow = *one; *grow; grow++)
    one_count ++;

  for (grow = two; *grow; grow++)
    two_count ++;

  grow = xrealloc (*one, sizeof(LDAPMod *) * (one_count + two_count + 1));

  for (i = 0; i < two_count; i++)
    grow[one_count + i] = two[i];

  grow[one_count + i] = NULL;

  *one = grow;
}

/* Given a string, unescape C escapes.  In particular, \xXX.  This
   modifies the string in place.  */
static void
uncescape (char *str)
{
  size_t r = 0;
  size_t w = 0;

  char *first = strchr (str, '\\');
  if (! first)
    /* No backslashes => no escaping.  We're done.  */
    return;

  /* Start at the first '\\'.  */
  r = w = (uintptr_t) first - (uintptr_t) str;

  while (str[r])
    {
      /* XXX: What to do about bad escapes?
         XXX: hextobyte already checks the string thus the hexdigitp
         could be removed. */
      if (str[r] == '\\' && str[r + 1] == 'x'
          && str[r+2] && str[r+3]
	  && hexdigitp (str + r + 2)
	  && hexdigitp (str + r + 3))
	{
	  int x = hextobyte (&str[r + 2]);
	  assert (0 <= x && x <= 0xff);

	  str[w] = x;

	  /* We consumed 4 characters and wrote 1.  */
	  r += 4;
	  w ++;
	}
      else
	str[w ++] = str[r ++];
    }

  str[w] = '\0';
}

/* Given one line from an info block (`gpg --list-{keys,sigs}
   --with-colons KEYID'), pull it apart and fill in the modlist with
   the relevant (for the LDAP schema) attributes.  EXTRACT_STATE
   should initally be set to 0 by the caller.  SCHEMAV2 is set if the
   server supports the version 2 schema.  */
static void
extract_attributes (LDAPMod ***modlist, int *extract_state,
                    char *line, int schemav2)
{
  int field_count;
  char **fields;
  char *keyid;
  int is_pub, is_sub, is_uid, is_sig;

  /* Remove trailing whitespace */
  trim_trailing_spaces (line);

  fields = strsplit (line, ':', '\0', &field_count);
  if (field_count == 1)
    /* We only have a single field.  There is definitely nothing to
       do.  */
    goto out;

  if (field_count < 7)
    goto out;

  is_pub = !ascii_strcasecmp ("pub", fields[0]);
  is_sub = !ascii_strcasecmp ("sub", fields[0]);
  is_uid = !ascii_strcasecmp ("uid", fields[0]);
  is_sig = !ascii_strcasecmp ("sig", fields[0]);
  if (!ascii_strcasecmp ("fpr", fields[0]))
    {
      /* Special treatment for a fingerprint.  */
      if (!(*extract_state & 1))
        goto out;  /* Stray fingerprint line - ignore.  */
      *extract_state &= ~1;
      if (field_count >= 10 && schemav2)
        {
          if ((*extract_state & 2))
            modlist_add (modlist, "gpgFingerprint", fields[9]);
          else
            modlist_add (modlist, "gpgSubFingerprint", fields[9]);
        }
      goto out;
    }

  *extract_state &= ~(1|2);
  if (is_pub)
    *extract_state |= (1|2);
  else if (is_sub)
    *extract_state |= 1;

  if (!is_pub && !is_sub && !is_uid && !is_sig)
    goto out; /* Not a relevant line.  */

  keyid = fields[4];

  if (is_uid && strlen (keyid) == 0)
    ; /* The uid record type can have an empty keyid.  */
  else if (strlen (keyid) == 16
	   && strspn (keyid, "0123456789aAbBcCdDeEfF") == 16)
    ; /* Otherwise, we expect exactly 16 hex characters.  */
  else
    {
      log_error ("malformed record!\n");
      goto out;
    }

  if (is_pub)
    {
      int disabled = 0;
      int revoked = 0;
      char *flags;
      for (flags = fields[1]; *flags; flags ++)
	switch (*flags)
	  {
	  case 'r':
	  case 'R':
	    revoked = 1;
	    break;

	  case 'd':
	  case 'D':
	    disabled = 1;
	    break;
	  }

      /* Note: we always create the pgpDisabled and pgpRevoked
	attributes, regardless of whether the key is disabled/revoked
	or not.  This is because a very common search is like
	"(&(pgpUserID=*isabella*)(pgpDisabled=0))"  */

      if (is_pub)
	{
	  modlist_add (modlist,"pgpDisabled", disabled ? "1" : "0");
	  modlist_add (modlist,"pgpRevoked", revoked ? "1" : "0");
	}
    }

  if (is_pub || is_sub)
    {
      char padded[6];
      int val;

      val = atoi (fields[2]);
      if (val < 99999 && val > 0)
        {
          /* We zero pad this on the left to make PGP happy. */
          snprintf (padded, sizeof padded, "%05u", val);
          modlist_add (modlist, "pgpKeySize", padded);
        }
    }

  if (is_pub)
    {
      char *algo = fields[3];
      int val = atoi (algo);
      switch (val)
	{
	case 1:
	  algo = "RSA";
	  break;

	case 17:
	  algo = "DSS/DH";
	  break;

	default:
	  algo = NULL;
	  break;
	}

      if (algo)
        modlist_add (modlist, "pgpKeyType", algo);
    }

  if (is_pub || is_sub || is_sig)
    {
      if (is_pub)
	{
	  modlist_add (modlist, "pgpCertID", keyid);    /* Long keyid(!) */
	  modlist_add (modlist, "pgpKeyID", &keyid[8]); /* Short keyid   */
	}

      if (is_sub)
        modlist_add (modlist, "pgpSubKeyID", keyid);    /* Long keyid(!)  */
    }

  if (is_pub)
    {
      char *create_time = fields[5];

      if (strlen (create_time) == 0)
	create_time = NULL;
      else
	{
	  char *create_time_orig = create_time;
	  struct tm tm;
	  time_t t;
	  char *end;

	  memset (&tm, 0, sizeof (tm));

	  /* parse_timestamp handles both seconds fromt he epoch and
	     ISO 8601 format.  We also need to handle YYYY-MM-DD
	     format (as generated by gpg1 --with-colons --list-key).
	     Check that first and then if it fails, then try
	     parse_timestamp.  */

	  if (!isodate_human_to_tm (create_time, &tm))
	    create_time = tm2ldaptime (&tm);
	  else if ((t = parse_timestamp (create_time, &end)) != (time_t) -1
		   && *end == '\0')
	    {

	      if (!gnupg_gmtime (&t, &tm))
		create_time = NULL;
	      else
		create_time = tm2ldaptime (&tm);
	    }
	  else
	    create_time = NULL;

	  if (! create_time)
	    /* Failed to parse string.  */
	    log_error ("Failed to parse creation time ('%s')",
		       create_time_orig);
	}

      if (create_time)
	{
	  modlist_add (modlist, "pgpKeyCreateTime", create_time);
	  xfree (create_time);
	}
    }

  if (is_pub)
    {
      char *expire_time = fields[6];

      if (strlen (expire_time) == 0)
	expire_time = NULL;
      else
	{
	  char *expire_time_orig = expire_time;
	  struct tm tm;
	  time_t t;
	  char *end;

	  memset (&tm, 0, sizeof (tm));

	  /* parse_timestamp handles both seconds fromt he epoch and
	     ISO 8601 format.  We also need to handle YYYY-MM-DD
	     format (as generated by gpg1 --with-colons --list-key).
	     Check that first and then if it fails, then try
	     parse_timestamp.  */

	  if (!isodate_human_to_tm (expire_time, &tm))
	    expire_time = tm2ldaptime (&tm);
	  else if ((t = parse_timestamp (expire_time, &end)) != (time_t) -1
		   && *end == '\0')
	    {
	      if (!gnupg_gmtime (&t, &tm))
		expire_time = NULL;
	      else
		expire_time = tm2ldaptime (&tm);
	    }
	  else
	    expire_time = NULL;

	  if (! expire_time)
	    /* Failed to parse string.  */
	    log_error ("Failed to parse creation time ('%s')",
		       expire_time_orig);
	}

      if (expire_time)
	{
	  modlist_add (modlist, "pgpKeyExpireTime", expire_time);
	  xfree (expire_time);
	}
    }

  if (is_uid && field_count >= 10)
    {
      char *uid = fields[9];
      char *mbox;

      uncescape (uid);
      modlist_add (modlist, "pgpUserID", uid);
      if (schemav2 && (mbox = mailbox_from_userid (uid)))
        {
          modlist_add (modlist, "gpgMailbox", mbox);
          xfree (mbox);
        }
    }

 out:
  xfree (fields);
}

/* Send the key in {KEY,KEYLEN} with the metadata {INFO,INFOLEN} to
   the keyserver identified by URI.  See server.c:cmd_ks_put for the
   format of the data and metadata.  */
gpg_error_t
ks_ldap_put (ctrl_t ctrl, parsed_uri_t uri,
	     void *data, size_t datalen,
	     void *info, size_t infolen)
{
  gpg_error_t err = 0;
  int ldap_err;
  unsigned int serverinfo;
  LDAP *ldap_conn = NULL;
  char *basedn = NULL;
  LDAPMod **modlist = NULL;
  LDAPMod **addlist = NULL;
  char *data_armored = NULL;
  int extract_state;

  /* The last byte of the info block.  */
  const char *infoend = (const char *) info + infolen - 1;

  /* Enable this code to dump the modlist to /tmp/modlist.txt.  */
#if 0
# warning Disable debug code before checking in.
  const int dump_modlist = 1;
#else
  const int dump_modlist = 0;
#endif
  estream_t dump = NULL;

  /* Elide a warning.  */
  (void) ctrl;

  if (dirmngr_use_tor ())
    {
      /* For now we do not support LDAP over Tor.  */
      log_error (_("LDAP access not possible due to Tor mode\n"));
      return gpg_error (GPG_ERR_NOT_SUPPORTED);
    }

  ldap_err = my_ldap_connect (uri, &ldap_conn, &basedn, &serverinfo);
  if (ldap_err || !basedn)
    {
      if (ldap_err)
	err = ldap_err_to_gpg_err (ldap_err);
      else
	err = GPG_ERR_GENERAL;
      goto out;
    }

  if (!(serverinfo & SERVERINFO_REALLDAP))
    {
      /* We appear to have a PGP.com Keyserver, which can unpack the
       * key on its own (not just a dump LDAP server).  This will
       * rarely be the case these days.  */
      LDAPMod mod;
      LDAPMod *attrs[2];
      char *key[2];
      char *dn;

      key[0] = data;
      key[1] = NULL;
      memset (&mod, 0, sizeof (mod));
      mod.mod_op = LDAP_MOD_ADD;
      mod.mod_type = (serverinfo & SERVERINFO_PGPKEYV2)? "pgpKeyV2":"pgpKey";
      mod.mod_values = key;
      attrs[0] = &mod;
      attrs[1] = NULL;

      dn = xtryasprintf ("pgpCertid=virtual,%s", basedn);
      if (!dn)
        {
          err = gpg_error_from_syserror ();
          goto out;
        }
      ldap_err = ldap_add_s (ldap_conn, dn, attrs);
      xfree (dn);

      if (ldap_err != LDAP_SUCCESS)
	{
	  err = ldap_err_to_gpg_err (err);
	  goto out;
	}

      goto out;
    }

  modlist = xtrymalloc (sizeof (LDAPMod *));
  if (!modlist)
    {
      err = gpg_error_from_syserror ();
      goto out;
    }
  *modlist = NULL;

  if (dump_modlist)
    {
      dump = es_fopen("/tmp/modlist.txt", "w");
      if (! dump)
	log_error ("Failed to open /tmp/modlist.txt: %s\n",
		   strerror (errno));

      if (dump)
	{
	  es_fprintf(dump, "data (%zd bytes)\n", datalen);
	  es_fprintf(dump, "info (%zd bytes): '\n", infolen);
	  es_fwrite(info, infolen, 1, dump);
	  es_fprintf(dump, "'\n");
	}
    }

  /* Start by nulling out all attributes.  We try and do a modify
     operation first, so this ensures that we don't leave old
     attributes lying around. */
  modlist_add (&modlist, "pgpDisabled", NULL);
  modlist_add (&modlist, "pgpKeyID", NULL);
  modlist_add (&modlist, "pgpKeyType", NULL);
  modlist_add (&modlist, "pgpUserID", NULL);
  modlist_add (&modlist, "pgpKeyCreateTime", NULL);
  modlist_add (&modlist, "pgpRevoked", NULL);
  modlist_add (&modlist, "pgpSubKeyID", NULL);
  modlist_add (&modlist, "pgpKeySize", NULL);
  modlist_add (&modlist, "pgpKeyExpireTime", NULL);
  modlist_add (&modlist, "pgpCertID", NULL);
  if ((serverinfo & SERVERINFO_SCHEMAV2))
    {
      modlist_add (&modlist, "gpgFingerprint", NULL);
      modlist_add (&modlist, "gpgSubFingerprint", NULL);
      modlist_add (&modlist, "gpgMailbox", NULL);
    }

  /* Assemble the INFO stuff into LDAP attributes */
  extract_state = 0;
  while (infolen > 0)
    {
      char *temp = NULL;

      char *newline = memchr (info, '\n', infolen);
      if (! newline)
	/* The last line is not \n terminated!  Make a copy so we can
	   add a NUL terminator.  */
	{
	  temp = xmalloc (infolen + 1);
	  memcpy (temp, info, infolen);
	  info = temp;
	  newline = (char *) info + infolen;
	}

      *newline = '\0';

      extract_attributes (&addlist, &extract_state, info,
                          (serverinfo & SERVERINFO_SCHEMAV2));

      infolen = infolen - ((uintptr_t) newline - (uintptr_t) info + 1);
      info = newline + 1;

      /* Sanity check.  */
      if (! temp)
	log_assert ((char *) info + infolen - 1 == infoend);
      else
	{
	  log_assert (infolen == -1);
	  xfree (temp);
	}
    }

  modlist_add (&addlist, "objectClass", "pgpKeyInfo");

  err = armor_data (&data_armored, data, datalen);
  if (err)
    goto out;

  modlist_add (&addlist,
               (serverinfo & SERVERINFO_PGPKEYV2)? "pgpKeyV2":"pgpKey",
               data_armored);

  /* Now append addlist onto modlist.  */
  modlists_join (&modlist, addlist);

  if (dump)
    {
      estream_t input = modlist_dump (modlist, NULL);
      if (input)
        {
          copy_stream (input, dump);
          es_fclose (input);
        }
    }

  /* Going on the assumption that modify operations are more frequent
     than adds, we try a modify first.  If it's not there, we just
     turn around and send an add command for the same key.  Otherwise,
     the modify brings the server copy into compliance with our copy.
     Note that unlike the LDAP keyserver (and really, any other
     keyserver) this does NOT merge signatures, but replaces the whole
     key.  This should make some people very happy. */
  {
    char **attrval;
    char *dn;

    if ((serverinfo & SERVERINFO_NTDS))
      {
        /* The modern way using a CN RDN with the fingerprint.  This
         * has the advantage that we won't have duplicate 64 bit
         * keyids in the store.  In particular NTDS requires the
         * DN to be unique.  */
        attrval = modlist_lookup (addlist, "gpgFingerprint");
        /* We should have exactly one value.  */
        if (!attrval || !(attrval[0] && !attrval[1]))
          {
            log_error ("ks-ldap: bad gpgFingerprint provided\n");
            err = GPG_ERR_GENERAL;
            goto out;
          }
        dn = xtryasprintf ("CN=%s,%s", attrval[0], basedn);
      }
    else  /* The old style way.  */
      {
        attrval = modlist_lookup (addlist, "pgpCertID");
        /* We should have exactly one value.  */
        if (!attrval || !(attrval[0] && !attrval[1]))
          {
            log_error ("ks-ldap: bad pgpCertID provided\n");
            err = GPG_ERR_GENERAL;
            goto out;
          }
        dn = xtryasprintf ("pgpCertID=%s,%s", attrval[0], basedn);
      }
    if (!dn)
      {
        err = gpg_error_from_syserror ();
        goto out;
      }
    if (opt.debug)
      log_debug ("ks-ldap: using DN: %s\n", dn);

    npth_unprotect ();
    err = ldap_modify_s (ldap_conn, dn, modlist);
    if (err == LDAP_NO_SUCH_OBJECT)
      err = ldap_add_s (ldap_conn, dn, addlist);
    npth_protect ();

    xfree (dn);

    if (err != LDAP_SUCCESS)
      {
	log_error ("ks-ldap: error adding key to keyserver: %s\n",
		   ldap_err2string (err));
	err = ldap_err_to_gpg_err (err);
      }
  }

 out:
  if (dump)
    es_fclose (dump);

  if (ldap_conn)
    ldap_unbind (ldap_conn);

  xfree (basedn);

  modlist_free (modlist);
  xfree (addlist);

  xfree (data_armored);

  return err;
}
