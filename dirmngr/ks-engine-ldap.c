/* ks-engine-ldap.c - talk to a LDAP keyserver
 * Copyright (C) 2001, 2002, 2004, 2005, 2006
 *               2007  Free Software Foundation, Inc.
 * Copyright (C) 2015, 2020, 2023  g10 Code GmbH
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
#include <stdlib.h>
#include <npth.h>
#ifdef HAVE_W32_SYSTEM
# ifndef WINVER
#  define WINVER 0x0500  /* Same as in common/sysutils.c */
# endif
# include <winsock2.h>
# include <sddl.h>
#endif


#include "dirmngr.h"
#include "misc.h"
#include "../common/userids.h"
#include "../common/mbox-util.h"
#include "ks-action.h"
#include "ks-engine.h"
#include "ldap-misc.h"
#include "ldap-parse-uri.h"
#include "ldapserver.h"


/* Flags with infos from the connected server.  */
#define SERVERINFO_REALLDAP 1 /* This is not the PGP keyserver.      */
#define SERVERINFO_PGPKEYV2 2 /* Needs "pgpKeyV2" instead of "pgpKey"*/
#define SERVERINFO_SCHEMAV2 4 /* Version 2 of the Schema.            */
#define SERVERINFO_NTDS     8 /* Server is an Active Directory.      */
#define SERVERINFO_GENERIC 16 /* Connected in genric mode.           */


/* The page size requested from the server.  */
#define PAGE_SIZE  100


#ifndef HAVE_TIMEGM
time_t timegm(struct tm *tm);
#endif


/* Object to keep state pertaining to this module.  */
struct ks_engine_ldap_local_s
{
  LDAP *ldap_conn;
  LDAPMessage *message;
  LDAPMessage *msg_iter;  /* Iterator for message.  */
  unsigned int serverinfo;
  int scope;
  char *basedn;
  char *keyspec;
  char *filter;
  struct berval *pagecookie;
  unsigned int pageno;  /* Current page number (starting at 1). */
  unsigned int total;   /* Total number of attributes read.     */
  int more_pages;       /* More pages announced by server.      */
};

/*-- prototypes --*/
static char *map_rid_to_dn (ctrl_t ctrl, const char *rid);
static char *basedn_from_rootdse (ctrl_t ctrl, parsed_uri_t uri);



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


static void
my_ldap_value_free (char **vals)
{
  if (vals)
    ldap_value_free (vals);
}


/* Print a description of supported variables.  */
void
ks_ldap_help_variables (ctrl_t ctrl)
{
  const char data[] =
    "Supported variables in LDAP filter expressions:\n"
    "\n"
    "domain           - The defaultNamingContext.\n"
    "domain_admins    - Group of domain admins.\n"
    "domain_users     - Group with all user accounts.\n"
    "domain_guests    - Group with the builtin gues account.\n"
    "domain_computers - Group with all clients and servers.\n"
    "cert_publishers  - Group with all cert issuing computers.\n"
    "protected_users  - Group of users with extra protection.\n"
    "key_admins       - Group for delegated access to msdsKeyCredentialLink.\n"
    "enterprise_key_admins     - Similar to key_admins.\n"
    "domain_domain_controllers - Group with all domain controllers.\n"
    "sid_domain       - SubAuthority numbers.\n";

  ks_print_help (ctrl, data);
}


/* Helper function for substitute_vars.  */
static const char *
getval_for_filter (void *cookie, const char *name)
{
  ctrl_t ctrl = cookie;
  const char *result = NULL;

  if (!strcmp (name, "sid_domain"))
    {
#ifdef HAVE_W32_SYSTEM
      PSID mysid;
      static char *sidstr;
      char *s, *s0;
      int i;

      if (!sidstr)
        {
          mysid = w32_get_user_sid ();
          if (!mysid)
            {
              gpg_err_set_errno (ENOENT);
              goto leave;
            }

          if (!ConvertSidToStringSid (mysid, &sidstr))
            {
              gpg_err_set_errno (EINVAL);
              goto leave;
            }
          /* Example for SIDSTR:
           * S-1-5-21-3636969917-2569447256-918939550-1127 */
          for (s0=NULL,s=sidstr,i=0; (s=strchr (s, '-')); i++)
            {
              s++;
              if (i == 3)
                s0 = s;
              else if (i==6)
                {
                  s[-1] = 0;
                  break;
                }
            }
          if (!s0)
            {
              log_error ("oops: invalid SID received from OS");
              gpg_err_set_errno (EINVAL);
              LocalFree (sidstr);
              goto leave;
            }
          sidstr = s0;  /* (We never release SIDSTR thus no memmove.)  */
        }
      result = sidstr;
#else
      gpg_err_set_errno (ENOSYS);
      goto leave;
#endif
    }
  else if (!strcmp (name, "domain"))
    result = basedn_from_rootdse (ctrl, NULL);
  else if (!strcmp (name, "domain_admins"))
    result = map_rid_to_dn (ctrl, "512");
  else if (!strcmp (name, "domain_users"))
    result = map_rid_to_dn (ctrl, "513");
  else if (!strcmp (name, "domain_guests"))
    result = map_rid_to_dn (ctrl, "514");
  else if (!strcmp (name, "domain_computers"))
    result = map_rid_to_dn (ctrl, "515");
  else if (!strcmp (name, "domain_domain_controllers"))
    result = map_rid_to_dn (ctrl, "516");
  else if (!strcmp (name, "cert_publishers"))
    result = map_rid_to_dn (ctrl, "517");
  else if (!strcmp (name, "protected_users"))
    result = map_rid_to_dn (ctrl, "525");
  else if (!strcmp (name, "key_admins"))
    result = map_rid_to_dn (ctrl, "526");
  else if (!strcmp (name, "enterprise_key_admins"))
    result = map_rid_to_dn (ctrl, "527");
  else
    result = "";  /* Unknown variables are empty.  */

 leave:
  return result;
}



/* Print a help output for the schemata supported by this module. */
gpg_error_t
ks_ldap_help (ctrl_t ctrl, parsed_uri_t uri)
{
  const char data[] =
    "Handler for LDAP URLs:\n"
    "  ldap://HOST:PORT/[BASEDN]????[bindname=BINDNAME,password=PASSWORD]\n"
    "\n"
    "Note: basedn, bindname and password need to be percent escaped. In\n"
    "particular, spaces need to be replaced with %20 and commas with %2c.\n"
    "Thus bindname will typically be of the form:\n"
    "\n"
    "  uid=user%2cou=PGP%20Users%2cdc=EXAMPLE%2cdc=ORG\n"
    "\n"
    "The ldaps:// and ldapi:// schemes are also supported.  If ldaps is used\n"
    "then the server's certificate will be checked.  If it is not valid, any\n"
    "operation will be aborted.  Note that ldaps means LDAP with STARTTLS\n"
    "\n"
    "As an alternative to an URL a string in this form may be used:\n"
    "\n"
    "  HOST:PORT:BINDNAME:PASSWORD:BASEDN:FLAGS:\n"
    "\n"
    "The use of the percent sign or a colon in one of the string values is\n"
    "currently not supported.\n"
    "\n"
    "Supported methods: search, get, put\n";
  gpg_error_t err;

  if(!uri)
    err = ks_print_help (ctrl, "  ldap");
  else if (uri->is_ldap || uri->opaque)
    err = ks_print_help (ctrl, data);
  else
    err = 0;

  return err;
}



/* Create a new empty state object.  Returns NULL on error */
static struct ks_engine_ldap_local_s *
ks_ldap_new_state (void)
{
  struct ks_engine_ldap_local_s *state;

  state = xtrycalloc (1, sizeof(struct ks_engine_ldap_local_s));
  if (state)
    state->scope = LDAP_SCOPE_SUBTREE;
  return state;
}


/* Clear the state object STATE.  Returns the STATE object.  */
static struct ks_engine_ldap_local_s *
ks_ldap_clear_state (struct ks_engine_ldap_local_s *state)
{
  if (state->ldap_conn)
    {
      ldap_unbind (state->ldap_conn);
      state->ldap_conn = NULL;
    }
  if (state->message)
    {
      ldap_msgfree (state->message);
      state->message = NULL;
    }
  if (state->pagecookie)
    {
      ber_bvfree (state->pagecookie);
      state->pagecookie = NULL;
    }
  state->serverinfo = 0;
  xfree (state->basedn);
  state->scope = LDAP_SCOPE_SUBTREE;
  state->basedn = NULL;
  xfree (state->keyspec);
  state->keyspec = NULL;
  xfree (state->filter);
  state->filter = NULL;
  state->pageno = 0;
  state->total = 0;
  state->more_pages = 0;
  return state;
}


/* Release a state object.  */
void
ks_ldap_free_state (struct ks_engine_ldap_local_s *state)
{
  if (!state)
    return;
  ks_ldap_clear_state (state);
  xfree (state);
}


/* Helper for ks_ldap_get and ks_ldap_query.  On return first_mode and
 * next_mode are set accordingly.  */
static gpg_error_t
ks_ldap_prepare_my_state (ctrl_t ctrl, unsigned int ks_get_flags,
                          int *first_mode, int *next_mode)
{
  *first_mode = *next_mode = 0;

  if ((ks_get_flags & KS_GET_FLAG_FIRST))
    {
      if (ctrl->ks_get_state)
        ks_ldap_clear_state (ctrl->ks_get_state);
      else if (!(ctrl->ks_get_state = ks_ldap_new_state ()))
        return gpg_error_from_syserror ();
      *first_mode = 1;
    }

  if ((ks_get_flags & KS_GET_FLAG_NEXT))
    {
      if (!ctrl->ks_get_state || !ctrl->ks_get_state->ldap_conn
          || !ctrl->ks_get_state->message)
        {
          log_error ("ks-ldap: --next requested but no state\n");
          return gpg_error (GPG_ERR_INV_STATE);
        }
      *next_mode = 1;
    }

  /* Do not keep an old state around if not needed.  */
  if (!(*first_mode || *next_mode))
    {
      ks_ldap_free_state (ctrl->ks_get_state);
      ctrl->ks_get_state = NULL;
    }

  return 0;
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
        f = xasprintf ("(&(gpgMailbox=%s)(!(|(pgpRevoked=1)(pgpDisabled=1))))",
                       p);
      else if (!only_exact)
        f = xasprintf ("(pgpUserID=*<%s>*)", p);
      break;

    case KEYDB_SEARCH_MODE_MAILSUB:
      if ((serverinfo & SERVERINFO_SCHEMAV2))
	f = xasprintf("(&(gpgMailbox=*%s*)(!(|(pgpRevoked=1)(pgpDisabled=1))))",
                      (freeme = ldap_escape_filter (desc.u.name)));
      else if (!only_exact)
	f = xasprintf ("(pgpUserID=*<*%s*>*)",
		       (freeme = ldap_escape_filter (desc.u.name)));
      break;

    case KEYDB_SEARCH_MODE_MAILEND:
      if ((serverinfo & SERVERINFO_SCHEMAV2))
	f = xasprintf("(&(gpgMailbox=*%s)(!(|(pgpRevoked=1)(pgpDisabled=1))))",
                      (freeme = ldap_escape_filter (desc.u.name)));
      else if (!only_exact)
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

    case KEYDB_SEARCH_MODE_FPR:
      if ((serverinfo & SERVERINFO_SCHEMAV2))
        {
          freeme = bin2hex (desc.u.fpr, desc.fprlen, NULL);
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



/* Helper for my_ldap_connect.  */
static char *
interrogate_ldap_dn (LDAP *ldap_conn, const char *basedn_search,
                     unsigned int *r_serverinfo)
{
  int lerr;
  char **vals;
  LDAPMessage *si_res;
  int is_gnupg = 0;
  char *basedn = NULL;
  char *attr2[] = { "pgpBaseKeySpaceDN", "pgpVersion", "pgpSoftware", NULL };
  char *object;


  object = xasprintf ("cn=pgpServerInfo,%s", basedn_search);

  npth_unprotect ();
  lerr = ldap_search_s (ldap_conn, object, LDAP_SCOPE_BASE,
                        "(objectClass=*)", attr2, 0, &si_res);
  npth_protect ();
  xfree (object);

  if (lerr == LDAP_SUCCESS)
    {
      vals = ldap_get_values (ldap_conn, si_res, "pgpBaseKeySpaceDN");
      if (vals && vals[0])
        basedn = xtrystrdup (vals[0]);
      my_ldap_value_free (vals);

      vals = ldap_get_values (ldap_conn, si_res, "pgpSoftware");
      if (vals && vals[0])
        {
          if (opt.debug)
            log_debug ("Server: \t%s\n", vals[0]);
          if (!ascii_strcasecmp (vals[0], "GnuPG"))
            is_gnupg = 1;
        }
      my_ldap_value_free (vals);

      vals = ldap_get_values (ldap_conn, si_res, "pgpVersion");
      if (vals && vals[0])
        {
          if (opt.debug)
            log_debug ("Version:\t%s\n", vals[0]);
          if (is_gnupg)
            {
              const char *fields[2];
              int nfields;
              nfields = split_fields (vals[0], fields, DIM(fields));
              if (nfields > 0 && atoi(fields[0]) > 1)
                *r_serverinfo |= SERVERINFO_SCHEMAV2;
              if (nfields > 1
                  && !ascii_strcasecmp (fields[1], "ntds"))
                *r_serverinfo |= SERVERINFO_NTDS;
            }
        }
      my_ldap_value_free (vals);
    }

  /* From man ldap_search_s: "res parameter of
     ldap_search_ext_s() and ldap_search_s() should be
     freed with ldap_msgfree() regardless of return
     value of these functions.  */
  ldap_msgfree (si_res);
  return basedn;
}



/* Connect to an LDAP server and interrogate it.
 *
 * URI describes the server to connect to and various options
 * including whether to use TLS and the username and password (see
 * ldap_parse_uri for a description of the various fields).  Be
 * default a PGP keyserver is assumed; if GENERIC is true a generic
 * ldap connection is instead established.
 *
 * Returns: The ldap connection handle in *LDAP_CONNP, R_BASEDN is set
 * to the base DN for the PGP key space, several flags will be stored
 * at SERVERINFO, If you pass NULL, then the value won't be returned.
 * It is the caller's responsibility to release *LDAP_CONNP with
 * ldap_unbind and to xfree *BASEDNP.  On error these variables are
 * cleared.
 *
 * Note: On success, you still need to check that *BASEDNP is valid.
 * If it is NULL, then the server does not appear to be an OpenPGP
 * keyserver.  */
static gpg_error_t
my_ldap_connect (parsed_uri_t uri, unsigned int generic, LDAP **ldap_connp,
                 char **r_basedn, char **r_host, int *r_use_tls,
                 unsigned int *r_serverinfo)
{
  gpg_error_t err = 0;
  int lerr;
  ldap_server_t server = NULL;
  LDAP *ldap_conn = NULL;
  char *basedn = NULL;
  char *host = NULL;   /* Host to use.  */
  int port;            /* Port to use.  */
  int use_tls;         /* 1 = starttls, 2 = ldap-over-tls  */
  int use_ntds;        /* Use Active Directory authentication.  */
  int use_areconly;    /* Lookup only via A record (Windows).  */
  const char *bindname;
  const char *password;
  const char *basedn_arg;
#ifndef HAVE_W32_SYSTEM
  char *tmpstr;
#endif

  if (r_basedn)
    *r_basedn = NULL;
  if (r_host)
    *r_host = NULL;
  if (r_use_tls)
    *r_use_tls = 0;
  *r_serverinfo = 0;

  if (uri->opaque)
    {
      server = ldapserver_parse_one (uri->path, NULL, 0);
      if (!server)
        return gpg_error (GPG_ERR_LDAP_OTHER);
      host = server->host;
      port = server->port;
      bindname = server->user;
      password = bindname? server->pass : NULL;
      basedn_arg = server->base;
      use_tls = server->starttls? 1 : server->ldap_over_tls? 2 : 0;
      use_ntds = server->ntds;
      use_areconly = server->areconly;
    }
  else
    {
      host = uri->host;
      port = uri->port;
      bindname = uri->auth;
      password = bindname? uri_query_value (uri, "password") : NULL;
      basedn_arg = uri->path;
      use_tls = uri->use_tls ? 1 : 0;
      use_ntds = uri->ad_current;
      use_areconly = 0;
    }

  if (!port)
    port = use_tls == 2? 636 : 389;

  if (host)
    {
      host = xtrystrdup (host);
      if (!host)
        {
          err = gpg_error_from_syserror ();
          goto out;
        }
    }

  if (opt.verbose)
    log_info ("ldap connect to '%s:%d:%s:%s:%s:%s%s%s'%s\n",
              host, port,
              basedn_arg ? basedn_arg : "",
              bindname ? bindname : "",
              password ? "*****" : "",
              use_tls == 1? "starttls" : use_tls == 2? "ldaptls" : "plain",
              use_ntds ? ",ntds":"",
              use_areconly? ",areconly":"",
              generic? " (generic)":"");

  /* If the uri specifies a secure connection and we don't support
     TLS, then fail; don't silently revert to an insecure
     connection.  */
  if (use_tls)
    {
#ifndef HAVE_LDAP_START_TLS_S
      log_error ("ks-ldap: can't connect to the server: no TLS support.");
      err = GPG_ERR_LDAP_NOT_SUPPORTED;
      goto out;
#endif
    }


#ifdef HAVE_W32_SYSTEM
  /* Note that host==NULL uses the default domain controller.  */
  npth_unprotect ();
  ldap_conn = ldap_sslinit (host, port, (use_tls == 2));
  npth_protect ();
  if (!ldap_conn)
    {
      lerr = LdapGetLastError ();
      err = ldap_err_to_gpg_err (lerr);
      log_error ("error initializing LDAP '%s:%d': %s\n",
                 host, port, ldap_err2string (lerr));
      goto out;
    }
  if (use_areconly)
    {
      lerr = ldap_set_option (ldap_conn, LDAP_OPT_AREC_EXCLUSIVE, LDAP_OPT_ON);
      if (lerr != LDAP_SUCCESS)
        {
          log_error ("ks-ldap: unable to set LDAP_OPT_AREC_EXLUSIVE: %s\n",
                     ldap_err2string (lerr));
          err = ldap_err_to_gpg_err (lerr);
          goto out;
        }
    }

#else /* Unix */
  tmpstr = xtryasprintf ("%s://%s:%d",
                         use_tls == 2? "ldaps" : "ldap",
                         host, port);
  if (!tmpstr)
    {
      err = gpg_error_from_syserror ();
      goto out;
    }
  npth_unprotect ();
  lerr = ldap_initialize (&ldap_conn, tmpstr);
  npth_protect ();
  if (lerr != LDAP_SUCCESS || !ldap_conn)
    {
      err = ldap_err_to_gpg_err (lerr);
      log_error ("error initializing LDAP '%s': %s\n",
                 tmpstr, ldap_err2string (lerr));
      xfree (tmpstr);
      goto out;
    }
  xfree (tmpstr);
#endif /* Unix */

#ifdef HAVE_LDAP_SET_OPTION
  {
    int ver = LDAP_VERSION3;

    lerr = ldap_set_option (ldap_conn, LDAP_OPT_PROTOCOL_VERSION, &ver);
    if (lerr != LDAP_SUCCESS)
      {
	log_error ("ks-ldap: unable to go to LDAP 3: %s\n",
		   ldap_err2string (lerr));
	err = ldap_err_to_gpg_err (lerr);
	goto out;
      }
  }
  if (opt.ldaptimeout)
    {
      int ver = opt.ldaptimeout;

      /* fixme: also use LDAP_OPT_SEND_TIMEOUT?  */

      lerr = ldap_set_option (ldap_conn, LDAP_OPT_TIMELIMIT, &ver);
      if (lerr != LDAP_SUCCESS)
        {
          log_error ("ks-ldap: unable to set LDAP timelimit to %us: %s\n",
                     opt.ldaptimeout, ldap_err2string (lerr));
          err = ldap_err_to_gpg_err (lerr);
          goto out;
        }
      if (opt.verbose)
        log_info ("ldap timeout set to %us\n", opt.ldaptimeout);
    }
#endif


#ifdef HAVE_LDAP_START_TLS_S
  if (use_tls == 1)
    {
#ifndef HAVE_W32_SYSTEM
      int check_cert = LDAP_OPT_X_TLS_HARD; /* LDAP_OPT_X_TLS_NEVER */

      lerr = ldap_set_option (ldap_conn,
                              LDAP_OPT_X_TLS_REQUIRE_CERT, &check_cert);
      if (lerr)
	{
	  log_error ("ldap: error setting an TLS option: %s\n",
                     ldap_err2string (lerr));
          err = ldap_err_to_gpg_err (lerr);
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
      lerr = ldap_start_tls_s (ldap_conn,
#ifdef HAVE_W32_SYSTEM
			      /* ServerReturnValue, result */
			      NULL, NULL,
#endif
			      /* ServerControls, ClientControls */
			      NULL, NULL);
      npth_protect ();
      if (lerr)
	{
	  log_error ("ldap: error switching to STARTTLS mode: %s\n",
                     ldap_err2string (lerr));
          err = ldap_err_to_gpg_err (lerr);
	  goto out;
	}
    }
#endif

  if (use_ntds)
    {
#ifdef HAVE_W32_SYSTEM
      npth_unprotect ();
      lerr = ldap_bind_s (ldap_conn, NULL, NULL, LDAP_AUTH_NEGOTIATE);
      npth_protect ();
      if (lerr != LDAP_SUCCESS)
	{
	  log_error ("error binding to LDAP via AD: %s\n",
                     ldap_err2string (lerr));
          err = ldap_err_to_gpg_err (lerr);
	  goto out;
	}
#else
      log_error ("ldap: no Active Directory support but 'ntds' requested\n");
      err = gpg_error (GPG_ERR_NOT_SUPPORTED);
      goto out;
#endif
    }
  else if (bindname)
    {
      npth_unprotect ();
      lerr = ldap_simple_bind_s (ldap_conn, bindname, password);
      npth_protect ();
      if (lerr != LDAP_SUCCESS)
	{
	  log_error ("error binding to LDAP: %s\n", ldap_err2string (lerr));
          err = ldap_err_to_gpg_err (lerr);
	  goto out;
	}
    }
  else
    {
      /* By default we don't bind as there is usually no need to.  */
    }

  if (generic)
    {
      /* Generic use of this function for arbitrary LDAP servers.  */
      *r_serverinfo |= SERVERINFO_GENERIC;
      if (basedn_arg && *basedn_arg)
        {
          basedn = xtrystrdup (basedn_arg);
          if (!basedn)
            {
              err = gpg_error_from_syserror ();
              goto out;
            }
        }
    }
  else if (basedn_arg && *basedn_arg)
    {
      /* User specified base DN.  In this case we know the server is a
       * real LDAP server.  */
      const char *user_basedn = basedn_arg;

      *r_serverinfo |= SERVERINFO_REALLDAP;

      /* First try with provided basedn, else retry up one level.
       * Retry assumes that provided entry is for keyspace,
       * matching old behavior */
      basedn = interrogate_ldap_dn (ldap_conn, user_basedn, r_serverinfo);
      if (!basedn)
        {
          const char *basedn_parent = strchr (user_basedn, ',');
          if (basedn_parent && *basedn_parent)
            basedn = interrogate_ldap_dn (ldap_conn, basedn_parent + 1,
                                          r_serverinfo);
        }
    }
  else
    { /* Look for namingContexts.  */
      LDAPMessage *res = NULL;
      char *attr[] = { "namingContexts", NULL };

      npth_unprotect ();
      lerr = ldap_search_s (ldap_conn, "", LDAP_SCOPE_BASE,
			   "(objectClass=*)", attr, 0, &res);
      npth_protect ();

      if (lerr == LDAP_SUCCESS)
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

              *r_serverinfo |= SERVERINFO_REALLDAP;

	      for (i = 0; context[i] && !basedn; i++)
                basedn = interrogate_ldap_dn (ldap_conn, context[i],
                                              r_serverinfo);

	      ldap_value_free (context);
	    }
	}
      else /* ldap_search failed.  */
	{
	  /* We don't have an answer yet, which means the server might
	     be a PGP.com keyserver. */
	  char **vals;
	  LDAPMessage *si_res = NULL;

	  char *attr2[] = { "pgpBaseKeySpaceDN", "version", "software", NULL };

          npth_unprotect ();
	  lerr = ldap_search_s (ldap_conn, "cn=pgpServerInfo", LDAP_SCOPE_BASE,
			       "(objectClass=*)", attr2, 0, &si_res);
          npth_protect ();
	  if (lerr == LDAP_SUCCESS)
	    {
	      /* For the PGP LDAP keyserver, this is always
	       * "OU=ACTIVE,O=PGP KEYSPACE,C=US", but it might not be
               * in the future. */

	      vals = ldap_get_values (ldap_conn, si_res, "baseKeySpaceDN");
	      if (vals && vals[0])
		{
		  basedn = xtrystrdup (vals[0]);
		}
              my_ldap_value_free (vals);

	      vals = ldap_get_values (ldap_conn, si_res, "software");
	      if (vals && vals[0])
		{
                  if (opt.debug)
                    log_debug ("ks-ldap: PGP Server: \t%s\n", vals[0]);
		}
              my_ldap_value_free (vals);

	      vals = ldap_get_values (ldap_conn, si_res, "version");
	      if (vals && vals[0])
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

		}
              my_ldap_value_free (vals);
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
      log_debug ("server_type: %s\n",
                 ((*r_serverinfo & SERVERINFO_GENERIC)
                  ? "Generic" :
                  (*r_serverinfo & SERVERINFO_REALLDAP)
                  ? "LDAP" : "PGP.com keyserver") );
      log_debug ("basedn: %s\n", basedn);
      if (!(*r_serverinfo & SERVERINFO_GENERIC))
        log_debug ("pgpkeyattr: %s\n",
                   (*r_serverinfo & SERVERINFO_PGPKEYV2)? "pgpKeyV2":"pgpKey");
    }

  ldapserver_list_free (server);

  if (err)
    {
      xfree (basedn);
      if (ldap_conn)
	ldap_unbind (ldap_conn);
    }
  else
    {
      if (r_basedn)
	*r_basedn = basedn;
      else
	xfree (basedn);
      if (r_host)
        *r_host = host;
      else
        xfree (host);

      *ldap_connp = ldap_conn;
    }

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

  /* Note: ldap_get_values returns a NULL terminated array of
     strings.  */

  vals = ldap_get_values (ldap_conn, message, "gpgfingerprint");
  if (vals && vals[0] && vals[0][0])
    es_fprintf (output, "pub:%s:", vals[0]);
  else
    es_fprintf (output, "pub:%s:", certid);
  my_ldap_value_free (vals);

  vals = ldap_get_values (ldap_conn, message, "pgpkeytype");
  if (vals && vals[0])
    {
      if (strcmp (vals[0], "RSA") == 0)
	es_fprintf  (output, "1");
      else if (strcmp (vals[0],"DSS/DH") == 0)
	es_fprintf (output, "17");
    }
  my_ldap_value_free (vals);

  es_fprintf (output, ":");

  vals = ldap_get_values (ldap_conn, message, "pgpkeysize");
  if (vals && vals[0])
    {
      int v = atoi (vals[0]);
      if (v > 0)
	es_fprintf (output, "%d", v);
    }
  my_ldap_value_free (vals);

  es_fprintf (output, ":");

  vals = ldap_get_values (ldap_conn, message, "pgpkeycreatetime");
  if (vals && vals[0])
    {
      if (strlen (vals[0]) == 15)
	es_fprintf (output, "%u", (unsigned int) ldap2epochtime (vals[0]));
    }
  my_ldap_value_free (vals);

  es_fprintf (output, ":");

  vals = ldap_get_values (ldap_conn, message, "pgpkeyexpiretime");
  if (vals && vals[0])
    {
      if (strlen (vals[0]) == 15)
	es_fprintf (output, "%u", (unsigned int) ldap2epochtime (vals[0]));
    }
  my_ldap_value_free (vals);

  es_fprintf (output, ":");

  vals = ldap_get_values (ldap_conn, message, "pgprevoked");
  if (vals && vals[0])
    {
      if (atoi (vals[0]) == 1)
	es_fprintf (output, "r");
    }
  my_ldap_value_free (vals);

  es_fprintf (output, "\n");

  vals = ldap_get_values (ldap_conn, message, "pgpuserid");
  if (vals && vals[0])
    {
      int i;
      for (i = 0; vals[i]; i++)
	es_fprintf (output, "uid:%s\n", vals[i]);
    }
  my_ldap_value_free (vals);

  vals = ldap_get_values (ldap_conn, message, "modifyTimestamp");
  if (vals && vals[0])
    {
      gnupg_isotime_t atime;
      if (!rfc4517toisotime (atime, vals[0]))
        es_fprintf (output, "chg:%s:\n", atime);
    }
  my_ldap_value_free (vals);

  es_fprintf (output, "INFO %s END\n", certid);
}


/* For now we do not support LDAP over Tor.  */
static gpg_error_t
no_ldap_due_to_tor (ctrl_t ctrl)
{
  gpg_error_t err = gpg_error (GPG_ERR_NOT_SUPPORTED);
  const char *msg = _("LDAP access not possible due to Tor mode");

  log_error ("%s", msg);
  dirmngr_status_printf (ctrl, "NOTE", "no_ldap_due_to_tor %u %s", err, msg);
  return gpg_error (GPG_ERR_NOT_SUPPORTED);
}


/* Helper for ks_ldap_get.  Returns 0 if a key was fetched and printed
 * to FP.  The error code GPG_ERR_NO_DATA is returned if no key was
 * printed.  Note that FP is updated by this function. */
static gpg_error_t
return_one_keyblock (LDAP *ldap_conn, LDAPMessage *msg, unsigned int serverinfo,
                     estream_t *fp, strlist_t *seenp)
{
  gpg_error_t err;
  char **vals;
  char **certid;

  /* Use the long keyid to remove duplicates.  The LDAP server returns
   * the same keyid more than once if there are multiple user IDs on
   * the key.  Note that this does NOT mean that a keyid that exists
   * multiple times on the keyserver will not be fetched.  It means
   * that each KEY, no matter how many user IDs share its keyid, will
   * be fetched only once.  If a keyid that belongs to more than one
   * key is fetched, the server quite properly responds with all
   * matching keys. -ds
   *
   * Note that in --first/--next mode we don't do any duplicate
   * detection.
   */

  certid = ldap_get_values (ldap_conn, msg, "pgpcertid");
  if (certid && certid[0])
    {
      if (!seenp || !strlist_find (*seenp, certid[0]))
        {
          /* It's not a duplicate, add it */
          if (seenp)
            add_to_strlist (seenp, certid[0]);

          if (!*fp)
            {
              *fp = es_fopenmem(0, "rw");
              if (!*fp)
                {
                  err = gpg_error_from_syserror ();
                  goto leave;
                }
            }

          extract_keys (*fp, ldap_conn, certid[0], msg);

          vals = ldap_get_values (ldap_conn, msg,
                                  (serverinfo & SERVERINFO_PGPKEYV2)?
                                  "pgpKeyV2" : "pgpKey");
          if (!vals)
            {
              err = ldap_to_gpg_err (ldap_conn);
              log_error("ks-ldap: unable to retrieve key %s "
                        "from keyserver\n", certid[0]);
            }
          else
            {
              /* We should strip the new lines.  */
              es_fprintf (*fp, "KEY 0x%s BEGIN\n", certid[0]);
              es_fputs (vals[0], *fp);
              es_fprintf (*fp, "\nKEY 0x%s END\n", certid[0]);

              ldap_value_free (vals);
              err = 0;
            }
        }
      else /* Duplicate.  */
        err = gpg_error (GPG_ERR_NO_DATA);
    }
  else
    err = gpg_error (GPG_ERR_NO_DATA);

 leave:
  my_ldap_value_free (certid);
  return err;
}


/* Helper for ks_ldap_query.  Returns 0 if an attr was fetched and
 * printed to FP.  The error code GPG_ERR_NO_DATA is returned if no
 * data was printed.  Note that FP is updated by this function. */
static gpg_error_t
return_all_attributes (LDAP *ld, LDAPMessage *msg, estream_t *fp)
{
  gpg_error_t err = 0;
  BerElement *berctx = NULL;
  char *attr = NULL;
  const char *attrprefix;
  struct berval **values = NULL;
  int idx;
  int any = 0;
  const char *s;
  const char *val;
  size_t len;
  char *mydn;

  mydn = ldap_get_dn (ld, msg);
  if (!*fp)
    {
      *fp = es_fopenmem(0, "rw");
      if (!*fp)
        {
          err = gpg_error_from_syserror ();
          goto leave;
        }
    }

  /* Always print the DN - note that by using only unbkown attributes
   * it is pissible to list just the DNs with out addiional
   * linefeeds.  */
  es_fprintf (*fp, "Dn: %s\n", mydn? mydn : "[oops DN missing]");

  for (npth_unprotect (), attr = ldap_first_attribute (ld, msg, &berctx),
         npth_protect ();
       attr;
       npth_unprotect (), attr = ldap_next_attribute (ld, msg, berctx),
         npth_protect ())
    {
      npth_unprotect ();
      values = ldap_get_values_len (ld, msg, attr);
      npth_protect ();

      if (!values)
        {
          if (opt.verbose)
            log_info ("attribute '%s' not found\n", attr);
          ldap_memfree (attr);
          attr = NULL;
          continue;
        }

      any = 1;

      if (opt.verbose > 1)
        {
          log_info ("found attribute '%s'\n", attr);
          for (idx=0; values[idx]; idx++)
            log_info ("         length[%d]=%d\n",
                      idx, (int)values[0]->bv_len);
        }

      if (!ascii_strcasecmp (attr, "Dn"))
        attrprefix = "X-";
      else if (*attr == '#')
        attrprefix = "X-hash-";
      else if (*attr == ' ')
        attrprefix = "X-blank-";
      else
        attrprefix = "";
      /* FIXME: We should remap all invalid chars in ATTR.   */

      for (idx=0; values[idx]; idx++)
        {
          es_fprintf (*fp, "%s%s: ", attrprefix, attr);
          val = values[idx]->bv_val;
          len = values[idx]->bv_len;
          while (len && (s = memchr (val, '\n', len)))
            {
              s++; /* We als want to print the LF.  */
              if (es_fwrite (val, s - val, 1, *fp) != 1)
                goto fwrite_failed;
              len -= (s-val);
              val = s;
              if (len && es_fwrite (" ", 1, 1, *fp) != 1)
                goto fwrite_failed;
            }
          if (len && es_fwrite (val, len, 1, *fp) != 1)
            goto fwrite_failed;
          if (es_fwrite ("\n", 1, 1, *fp) != 1)  /* Final LF.  */
            goto fwrite_failed;
        }

      ldap_value_free_len (values);
      values = NULL;
      ldap_memfree (attr);
      attr = NULL;
    }

  /* One final linefeed to prettify the output.  */
  if (any && es_fwrite ("\n", 1, 1, *fp) != 1)
    goto fwrite_failed;


 leave:
  if (values)
    ldap_value_free_len (values);
  ldap_memfree (attr);
  if (mydn)
    ldap_memfree (mydn);
  ber_free (berctx, 0);
  return err;

 fwrite_failed:
  err = gpg_error_from_syserror ();
  log_error ("error writing to stdout: %s\n", gpg_strerror (err));
  goto leave;
}


/* Helper for ks_ldap_get and ks_ldap_query.  Note that KEYSPEC is
 * only used for diagnostics. */
static gpg_error_t
search_and_parse (ctrl_t ctrl, const char *keyspec,
                  LDAP *ldap_conn, char *basedn, int scope, char *filter,
                  char **attrs, LDAPMessage **r_message)
{
  gpg_error_t err = 0;
  int l_err, l_reserr;
  LDAPControl *srvctrls[2] = { NULL, NULL };
  int count;
  unsigned int totalcount = 0;
  LDAPControl *pagectrl = NULL;
  LDAPControl **resctrls = NULL;

  /* first/next mode is used to retrieve many entries; thus we should
   * use paged results.  We assume first/next mode if we have a state.
   * We make the paged mode non-critical so that we get at least as
   * many entries the server delivers anyway.  */
  if (ctrl->ks_get_state)
    {
      l_err = ldap_create_page_control (ldap_conn, PAGE_SIZE,
                                        ctrl->ks_get_state->pagecookie, 0,
                                        &pagectrl);
      if (err)
        {
          err = ldap_err_to_gpg_err (l_err);
          log_error ("ks-ldap: create_page_control failed: %s\n",
                     ldap_err2string (l_err));
          goto leave;
        }

      ctrl->ks_get_state->more_pages = 0;
      srvctrls[0] = pagectrl;
    }

  npth_unprotect ();
  l_err = ldap_search_ext_s (ldap_conn, basedn, scope,
                             filter, attrs, 0,
                             srvctrls[0]? srvctrls : NULL, NULL, NULL, 0,
                             r_message);
  npth_protect ();
  if (l_err)
    {
      err = ldap_err_to_gpg_err (l_err);
      log_error ("ks-ldap: LDAP search error: %s\n", ldap_err2string (l_err));
      goto leave;
    }

  if (ctrl->ks_get_state)
    {
      l_err = ldap_parse_result (ldap_conn, *r_message, &l_reserr,
                                 NULL, NULL, NULL, &resctrls, 0);
      if (l_err)
        {
          err = ldap_err_to_gpg_err (l_err);
          log_error ("ks-ldap: LDAP parse result error: %s\n",
                     ldap_err2string (l_err));
          goto leave;
        }
      /* Get the current cookie.  */
      if (ctrl->ks_get_state->pagecookie)
        {
          ber_bvfree (ctrl->ks_get_state->pagecookie);
          ctrl->ks_get_state->pagecookie = NULL;
        }
      l_err = ldap_parse_page_control (ldap_conn, resctrls,
                                       &totalcount,
                                       &ctrl->ks_get_state->pagecookie);
      if (l_err)
        {
          err = ldap_err_to_gpg_err (l_err);
          log_error ("ks-ldap: LDAP parse page control error: %s\n",
                     ldap_err2string (l_err));
          goto leave;
        }

      ctrl->ks_get_state->pageno++;

      /* Decide whether there will be more pages.  */
      ctrl->ks_get_state->more_pages =
        (ctrl->ks_get_state->pagecookie
         && ctrl->ks_get_state->pagecookie->bv_val
         && *ctrl->ks_get_state->pagecookie->bv_val);

      srvctrls[0] = NULL;
    }

  count = ldap_count_entries (ldap_conn, *r_message);
  if (ctrl->ks_get_state)
    {
      if (count >= 0)
        ctrl->ks_get_state->total += count;
      if (opt.verbose)
        log_info ("ks-ldap: received result page %u%s (%d/%u/%u)\n",
                  ctrl->ks_get_state->pageno,
                  ctrl->ks_get_state->more_pages? "":" (last)",
                  count, ctrl->ks_get_state->total, totalcount);
    }
  if (count < 1)
    {
      if (!ctrl->ks_get_state || ctrl->ks_get_state->pageno == 1)
        log_info ("ks-ldap: '%s' not found on LDAP server\n", keyspec);

      if (count == -1)
        err = ldap_to_gpg_err (ldap_conn);
      else
        err = gpg_error (GPG_ERR_NO_DATA);

      goto leave;
    }


 leave:
  if (resctrls)
    ldap_controls_free (resctrls);
  if (pagectrl)
    ldap_control_free (pagectrl);
  return err;
}


/* Fetch all entries from the RootDSE and return them as a name value
 * object.  */
static nvc_t
fetch_rootdse (ctrl_t ctrl, parsed_uri_t uri)
{
  gpg_error_t err;
  estream_t infp = NULL;
  uri_item_t puri;  /* The broken down URI (only one item used).  */
  nvc_t nvc = NULL;

  /* FIXME: We need the unparsed URI here - use uri_item_t instead
   * of fix the parser to fill in original */
  err = ks_action_parse_uri (uri && uri->original? uri->original : "ldap://",
                             &puri);
  if (err)
    return NULL;

  /* Reset authentication for a serverless.  */
  puri->parsed_uri->ad_current = 0;
  puri->parsed_uri->auth = NULL;

  if (!strcmp (puri->parsed_uri->scheme, "ldap")
      || !strcmp (puri->parsed_uri->scheme, "ldaps")
      || !strcmp (puri->parsed_uri->scheme, "ldapi")
      || puri->parsed_uri->opaque)
    {
      err = ks_ldap_query (ctrl, puri->parsed_uri, KS_GET_FLAG_ROOTDSE,
                           "^&base&(objectclass=*)", NULL, NULL, &infp);
      if (err)
        log_error ("ldap: reading the rootDES failed: %s\n",
                   gpg_strerror (err));
      else if ((err = nvc_parse (&nvc, NULL, infp)))
        log_error ("parsing the rootDES failed: %s\n", gpg_strerror (err));
    }

  es_fclose (infp);
  release_uri_item_list (puri);
  if (err)
    {
      nvc_release (nvc);
      nvc = NULL;
    }
  return nvc;
}


/* Return the DN for the given RID.  This is used with the Active
 * Directory.  */
static char *
map_rid_to_dn (ctrl_t ctrl, const char *rid)
{
  gpg_error_t err;
  char *result = NULL;
  estream_t infp = NULL;
  uri_item_t puri;  /* The broken down URI.  */
  nvc_t nvc = NULL;
  char *filter = NULL;
  const char *s;
  char *attr[2] = {"dn", NULL};

  err = ks_action_parse_uri ("ldap:///", &puri);
  if (err)
    return NULL;

  filter = strconcat ("(objectSid=S-1-5-21-$sid_domain-", rid, ")", NULL);
  if (!filter)
    goto leave;

  err = ks_ldap_query (ctrl, puri->parsed_uri, KS_GET_FLAG_SUBST,
                       filter, attr, NULL, &infp);
  if (err)
    {
      log_error ("ldap: AD query '%s' failed: %s\n", filter,gpg_strerror (err));
      goto leave;
    }
  if ((err = nvc_parse (&nvc, NULL, infp)))
    {
      log_error ("ldap: parsing the result failed: %s\n",gpg_strerror (err));
      goto leave;
    }
  if (!(s = nvc_get_string (nvc, "Dn:")))
    {
      err = gpg_error (GPG_ERR_NOT_FOUND);
      log_error ("ldap: mapping rid '%s'failed: %s\n", rid, gpg_strerror (err));
      goto leave;
    }
  result = xtrystrdup (s);
  if (!result)
    {
      err = gpg_error_from_syserror ();
      log_error ("ldap: strdup failed: %s\n", gpg_strerror (err));
      goto leave;
    }

 leave:
  es_fclose (infp);
  release_uri_item_list (puri);
  xfree (filter);
  nvc_release (nvc);
  return result;
}


/* Return the baseDN for URI which might have already been cached for
 * this session.  */
static char *
basedn_from_rootdse (ctrl_t ctrl, parsed_uri_t uri)
{
  const char *s;

  if (!ctrl->rootdse && !ctrl->rootdse_tried)
    {
      ctrl->rootdse = fetch_rootdse (ctrl, uri);
      ctrl->rootdse_tried = 1;
      if (ctrl->rootdse)
        {
          log_debug ("Dump of all rootDSE attributes:\n");
          nvc_write (ctrl->rootdse, log_get_stream ());
          log_debug ("End of dump\n");
        }
    }
  s = nvc_get_string (ctrl->rootdse, "defaultNamingContext:");
  return s? xtrystrdup (s): NULL;
}




/* Get the key described key the KEYSPEC string from the keyserver
 * identified by URI.  On success R_FP has an open stream to read the
 * data.  KS_GET_FLAGS conveys flags from the client.  */
gpg_error_t
ks_ldap_get (ctrl_t ctrl, parsed_uri_t uri, const char *keyspec,
	     unsigned int ks_get_flags, gnupg_isotime_t newer, estream_t *r_fp)
{
  gpg_error_t err;
  unsigned int serverinfo;
  char *host = NULL;
  int use_tls;
  char *filter = NULL;
  LDAP *ldap_conn = NULL;
  char *basedn = NULL;
  int scope = LDAP_SCOPE_SUBTREE;
  estream_t fp = NULL;
  LDAPMessage *message = NULL;
  LDAPMessage *msg;
  int anykey = 0;
  int first_mode = 0;
  int next_mode = 0;
  int get_first;
  strlist_t seen = NULL; /* The set of entries that we've seen.  */
  /* The ordering is significant.  Specifically, "pgpcertid" needs to
   * be the second item in the list, since everything after it may be
   * discarded if we aren't in verbose mode.  */
  char *attrs[] =
    {
     "dummy", /* (to be be replaced.)  */
     "pgpcertid", "pgpuserid", "pgpkeyid", "pgprevoked", "pgpdisabled",
     "pgpkeycreatetime", "modifyTimestamp", "pgpkeysize", "pgpkeytype",
     "gpgfingerprint",
     NULL
    };

  if (dirmngr_use_tor ())
    {
      return no_ldap_due_to_tor (ctrl);
    }

  err = ks_ldap_prepare_my_state (ctrl, ks_get_flags, &first_mode, &next_mode);
  if (err)
    return err;

  if (next_mode)
    {
    next_again:
      if (!ctrl->ks_get_state->msg_iter && ctrl->ks_get_state->more_pages)
        {
          /* Get the next page of results.  */
          if (ctrl->ks_get_state->message)
            {
              ldap_msgfree (ctrl->ks_get_state->message);
              ctrl->ks_get_state->message = NULL;
            }
          attrs[0] = ((ctrl->ks_get_state->serverinfo & SERVERINFO_PGPKEYV2)?
                      "pgpKeyV2" : "pgpKey");
          err = search_and_parse (ctrl, ctrl->ks_get_state->keyspec,
                                  ctrl->ks_get_state->ldap_conn,
                                  ctrl->ks_get_state->basedn,
                                  ctrl->ks_get_state->scope,
                                  ctrl->ks_get_state->filter,
                                  attrs,
                                  &ctrl->ks_get_state->message);
          if (err)
            goto leave;
          ctrl->ks_get_state->msg_iter = ctrl->ks_get_state->message;
          get_first = 1;
        }
      else
        get_first = 0;

      while (ctrl->ks_get_state->msg_iter)
        {
          npth_unprotect ();
          ctrl->ks_get_state->msg_iter
            = get_first? ldap_first_entry (ctrl->ks_get_state->ldap_conn,
                                           ctrl->ks_get_state->msg_iter)
              /*    */ : ldap_next_entry (ctrl->ks_get_state->ldap_conn,
                                          ctrl->ks_get_state->msg_iter);
          npth_protect ();
          get_first = 0;
          if (ctrl->ks_get_state->msg_iter)
            {
              err = return_one_keyblock (ctrl->ks_get_state->ldap_conn,
                                         ctrl->ks_get_state->msg_iter,
                                         ctrl->ks_get_state->serverinfo,
                                         &fp, NULL);
              if (!err)
                break;  /* Found.  */
              else if (gpg_err_code (err) == GPG_ERR_NO_DATA)
                err = 0;  /* Skip empty attributes. */
              else
                goto leave;
            }
        }

      if (!ctrl->ks_get_state->msg_iter || !fp)
        {
          ctrl->ks_get_state->msg_iter = NULL;
          if (ctrl->ks_get_state->more_pages)
            goto next_again;
          err = gpg_error (GPG_ERR_NO_DATA);
        }

    }
  else /* Not in --next mode.  */
    {
      /* Make sure we are talking to an OpenPGP LDAP server.  */
      err = my_ldap_connect (uri, 0, &ldap_conn,
                             &basedn, &host, &use_tls, &serverinfo);
      if (err || !basedn)
        {
          if (!err)
            err = gpg_error (GPG_ERR_GENERAL);
          goto leave;
        }

      /* Now that we have information about the server we can construct a
       * query best suited for the capabilities of the server.  */
      if (first_mode && !*keyspec)
        {
          filter = xtrystrdup("(!(|(pgpRevoked=1)(pgpDisabled=1)))");
          err = filter? 0 : gpg_error_from_syserror ();
        }
      else
        err = keyspec_to_ldap_filter (keyspec, &filter, 1, serverinfo);
      if (err)
        goto leave;

      if (*newer)
        {
          char *tstr, *fstr;

          tstr = isotime2rfc4517 (newer);
          if (!tstr)
            {
              err = gpg_error_from_syserror ();
              goto leave;
            }
          fstr = strconcat ("(&", filter,
                            "(modifyTimestamp>=", tstr, "))", NULL);
          xfree (tstr);
          if (!fstr)
            {
              err = gpg_error_from_syserror ();
              goto leave;
            }
          xfree (filter);
          filter = fstr;
        }

      if (opt.debug)
        log_debug ("ks-ldap: using filter: %s\n", filter);

      /* Replace "dummy".  */
      attrs[0] = (serverinfo & SERVERINFO_PGPKEYV2)? "pgpKeyV2" : "pgpKey";

      err = search_and_parse (ctrl, keyspec, ldap_conn, basedn, scope,
                              filter, attrs, &message);
      if (err)
        goto leave;


      for (npth_unprotect (),
             msg = ldap_first_entry (ldap_conn, message),
             npth_protect ();
	   msg;
           npth_unprotect (),
             msg = ldap_next_entry (ldap_conn, msg),
             npth_protect ())
	{
          err = return_one_keyblock (ldap_conn, msg, serverinfo,
                                     &fp, first_mode? NULL : &seen);
          if (!err)
            {
              anykey = 1;
              if (first_mode)
                break;
            }
          else if (gpg_err_code (err) == GPG_ERR_NO_DATA)
            err = 0;  /* Skip empty/duplicate attributes. */
          else
            goto leave;
	}

      if (ctrl->ks_get_state) /* Save the iterator.  */
        ctrl->ks_get_state->msg_iter = msg;

      if (!fp) /* Nothing was found.  */
	err = gpg_error (GPG_ERR_NO_DATA);

      if (!err && anykey)
        err = dirmngr_status_printf (ctrl, "SOURCE", "%s://%s",
                                     use_tls? "ldaps" : "ldap",
                                     host? host:"");
    }


 leave:
  /* Store our state if needed.  */
  if (!err && (ks_get_flags & KS_GET_FLAG_FIRST))
    {
      log_assert (!ctrl->ks_get_state->ldap_conn);
      ctrl->ks_get_state->ldap_conn = ldap_conn;
      ldap_conn = NULL;
      log_assert (!ctrl->ks_get_state->message);
      ctrl->ks_get_state->message = message;
      message = NULL;
      ctrl->ks_get_state->serverinfo = serverinfo;
      ctrl->ks_get_state->scope = scope;
      ctrl->ks_get_state->basedn = basedn;
      basedn = NULL;
      ctrl->ks_get_state->keyspec = keyspec? xtrystrdup (keyspec) : NULL;
      ctrl->ks_get_state->filter = filter;
      filter = NULL;
    }
  if ((ks_get_flags & KS_GET_FLAG_NEXT))
    {
      /* Keep the state in --next mode even with errors.  */
      ldap_conn = NULL;
      message = NULL;
    }

  if (message)
    ldap_msgfree (message);

  if (err)
    es_fclose (fp);
  else
    {
      if (fp)
	es_fseek (fp, 0, SEEK_SET);
      *r_fp = fp;
    }

  free_strlist (seen);
  xfree (basedn);
  xfree (host);

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
      return no_ldap_due_to_tor (ctrl);
    }

  /* Make sure we are talking to an OpenPGP LDAP server.  */
  err = my_ldap_connect (uri, 0, &ldap_conn, &basedn, NULL, NULL, &serverinfo);
  if (err || !basedn)
    {
      if (!err)
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
	"pgpkeycreatetime", "pgpkeyexpiretime", "modifyTimestamp",
	"pgpkeysize", "pgpkeytype", "gpgfingerprint",
        NULL
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
        my_ldap_value_free (certid);
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
	    if (!certid || !certid[0])
              {
                my_ldap_value_free (certid);
                continue;
              }

	    /* Have we seen this certid before? */
	    if (! strlist_find (dupelist, certid[0]))
	      {
		add_to_strlist (&dupelist, certid[0]);

                vals = ldap_get_values (ldap_conn, each, "gpgfingerprint");
                if (vals && vals[0] && vals[0][0])
                  es_fprintf (fp, "pub:%s:", vals[0]);
                else
                  es_fprintf (fp, "pub:%s:", certid[0]);
                my_ldap_value_free (vals);

		vals = ldap_get_values (ldap_conn, each, "pgpkeytype");
		if (vals && vals[0])
		  {
		    /* The LDAP server doesn't exactly handle this
		       well. */
		    if (strcasecmp (vals[0], "RSA") == 0)
		      es_fputs ("1", fp);
		    else if (strcasecmp (vals[0], "DSS/DH") == 0)
		      es_fputs ("17", fp);
		  }
		my_ldap_value_free (vals);

		es_fputc (':', fp);

		vals = ldap_get_values (ldap_conn, each, "pgpkeysize");
		if (vals && vals[0])
		  {
		    /* Not sure why, but some keys are listed with a
		       key size of 0.  Treat that like an unknown. */
		    if (atoi (vals[0]) > 0)
		      es_fprintf (fp, "%d", atoi (vals[0]));
		  }
                my_ldap_value_free (vals);

		es_fputc (':', fp);

		/* YYYYMMDDHHmmssZ */

		vals = ldap_get_values (ldap_conn, each, "pgpkeycreatetime");
		if(vals && vals[0] && strlen (vals[0]) == 15)
		  {
		    es_fprintf (fp, "%u",
				(unsigned int) ldap2epochtime(vals[0]));
		  }
                my_ldap_value_free (vals);

		es_fputc (':', fp);

		vals = ldap_get_values (ldap_conn, each, "pgpkeyexpiretime");
		if (vals && vals[0] && strlen (vals[0]) == 15)
		  {
		    es_fprintf (fp, "%u",
				(unsigned int) ldap2epochtime (vals[0]));
		  }
                my_ldap_value_free (vals);

		es_fputc (':', fp);

		vals = ldap_get_values (ldap_conn, each, "pgprevoked");
		if (vals && vals[0])
		  {
		    if (atoi (vals[0]) == 1)
		      es_fprintf (fp, "r");
		  }
                my_ldap_value_free (vals);

		vals = ldap_get_values (ldap_conn, each, "pgpdisabled");
		if (vals && vals[0])
		  {
		    if (atoi (vals[0]) ==1)
		      es_fprintf (fp, "d");
		  }
                my_ldap_value_free (vals);

		es_fputc (':', fp);

		vals = ldap_get_values (ldap_conn, each, "modifyTimestamp");
		if(vals && vals[0])
		  {
                    gnupg_isotime_t atime;
                    if (rfc4517toisotime (atime, vals[0]))
                      *atime = 0;
                    es_fprintf (fp, "%s", atime);
		  }
                my_ldap_value_free (vals);

		es_fprintf (fp, "\n");

		/* Now print all the uids that have this certid */
		for (uids = ldap_first_entry (ldap_conn, res);
		     uids;
		     uids = ldap_next_entry (ldap_conn, uids))
		  {
		    vals = ldap_get_values (ldap_conn, uids, "pgpcertid");
                    if (!vals || !vals[0])
                      {
                        my_ldap_value_free (vals);
                        continue;
                      }

		    if (!ascii_strcasecmp (certid[0], vals[0]))
		      {
			char **uidvals;

			es_fprintf (fp, "uid:");

			uidvals = ldap_get_values (ldap_conn,
						   uids, "pgpuserid");
			if (uidvals)
			  {
			    /* Need to percent escape any colons */
                            char *quoted = try_percent_escape (uidvals[0],
                                                               NULL);
                            if (quoted)
                              es_fputs (quoted, fp);
			    xfree (quoted);
			  }
                        my_ldap_value_free (uidvals);

			es_fprintf (fp, "\n");
		      }

		    ldap_value_free(vals);
		  }
	      }

            my_ldap_value_free (certid);
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
	  log_assert (0 <= x && x <= 0xff);

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
      if (schemav2 && (mbox = mailbox_from_userid (uid, 0)))
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
      return no_ldap_due_to_tor (ctrl);
    }

  err = my_ldap_connect (uri, 0, &ldap_conn, &basedn, NULL, NULL, &serverinfo);
  if (err || !basedn)
    {
      if (!err)
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
	log_error ("failed to open /tmp/modlist.txt: %s\n",
		   gpg_strerror (gpg_error_from_syserror ()));

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



/* Get the data described by FILTER_ARG from URI.  On success R_FP has
 * an open stream to read the data.  KS_GET_FLAGS conveys flags from
 * the client.  ATTRS is a NULL terminated list of attributes to
 * return or NULL for all. */
gpg_error_t
ks_ldap_query (ctrl_t ctrl, parsed_uri_t uri, unsigned int ks_get_flags,
               const char *filter_arg, char **attrs,
               gnupg_isotime_t newer, estream_t *r_fp)
{
  gpg_error_t err;
  unsigned int serverinfo;
  char *host = NULL;
  int use_tls;
  LDAP *ldap_conn = NULL;
  char *basedn = NULL;
  estream_t fp = NULL;
  char *filter_arg_buffer = NULL;
  char *filter = NULL;
  int scope = LDAP_SCOPE_SUBTREE;
  LDAPMessage *message = NULL;
  LDAPMessage *msg;
  int anydata = 0;
  int first_mode = 0;
  int next_mode = 0;
  int get_first;

  if (dirmngr_use_tor ())
    return no_ldap_due_to_tor (ctrl);

  if ((!filter_arg || !*filter_arg) && (ks_get_flags & KS_GET_FLAG_ROOTDSE))
    filter_arg = "^&base&(objectclass=*)";

  if ((ks_get_flags & KS_GET_FLAG_SUBST)
      && filter_arg && strchr (filter_arg, '$'))
    {
      filter_arg_buffer = substitute_vars (filter_arg, getval_for_filter, ctrl);
      if (!filter_arg_buffer)
        {
          err = gpg_error_from_syserror ();
          log_error ("substituting filter variables failed: %s\n",
                     gpg_strerror (err));
          goto leave;
        }
      filter_arg = filter_arg_buffer;
    }

  err = ks_ldap_prepare_my_state (ctrl, ks_get_flags, &first_mode, &next_mode);
  if (err)
    goto leave;

  if (!next_mode) /* (In --next mode the filter is ignored.)  */
    {
      if (!filter_arg || !*filter_arg)
        {
          err = gpg_error (GPG_ERR_LDAP_FILTER);
          goto leave;
        }
      err = ldap_parse_extfilter (filter_arg, 0, &basedn, &scope, &filter);
      if (err)
        goto leave;
      if (newer && *newer)
        {
          char *tstr, *fstr;

          tstr = isotime2rfc4517 (newer);
          if (!tstr)
            {
              err = gpg_error_from_syserror ();
              goto leave;
            }
          if (filter && *filter)
            fstr = strconcat ("(&", filter,
                              "(modifyTimestamp>=", tstr, "))", NULL);
          else
            fstr = strconcat ("(modifyTimestamp>=", tstr, ")", NULL);
          xfree (tstr);
          if (!fstr)
            {
              err = gpg_error_from_syserror ();
              goto leave;
            }
          xfree (filter);
          filter = fstr;
        }
    }


  if (next_mode)
    {
    next_again:
      if (!ctrl->ks_get_state->msg_iter && ctrl->ks_get_state->more_pages)
        {
          /* Get the next page of results.  */
          if (ctrl->ks_get_state->message)
            {
              ldap_msgfree (ctrl->ks_get_state->message);
              ctrl->ks_get_state->message = NULL;
            }
          err = search_and_parse (ctrl, ctrl->ks_get_state->keyspec,
                                  ctrl->ks_get_state->ldap_conn,
                                  ctrl->ks_get_state->basedn,
                                  ctrl->ks_get_state->scope,
                                  ctrl->ks_get_state->filter,
                                  attrs,
                                  &ctrl->ks_get_state->message);
          if (err)
            goto leave;
          ctrl->ks_get_state->msg_iter = ctrl->ks_get_state->message;
          get_first = 1;
        }
      else
        get_first = 0;

      while (ctrl->ks_get_state->msg_iter)
        {
          npth_unprotect ();
          ctrl->ks_get_state->msg_iter
            = get_first? ldap_first_entry (ctrl->ks_get_state->ldap_conn,
                                           ctrl->ks_get_state->msg_iter)
              /*    */ : ldap_next_entry (ctrl->ks_get_state->ldap_conn,
                                          ctrl->ks_get_state->msg_iter);
          npth_protect ();
          get_first = 0;
          if (ctrl->ks_get_state->msg_iter)
            {
              err = return_all_attributes (ctrl->ks_get_state->ldap_conn,
                                           ctrl->ks_get_state->msg_iter,
                                           &fp);
              if (!err)
                break;  /* Found.  */
              else if (gpg_err_code (err) == GPG_ERR_NO_DATA)
                err = 0;  /* Skip empty attributes. */
              else
                goto leave;
            }
        }

      if (!ctrl->ks_get_state->msg_iter || !fp)
        {
          ctrl->ks_get_state->msg_iter = NULL;
          if (ctrl->ks_get_state->more_pages)
            goto next_again;
          err = gpg_error (GPG_ERR_NO_DATA);
        }

    }
  else /* Not in --next mode.  */
    {
      /* Connect to the LDAP server in generic mode. */
      char *tmpbasedn;

      err = my_ldap_connect (uri, 1 /*generic*/, &ldap_conn,
                             &tmpbasedn, &host, &use_tls, &serverinfo);
      if (err)
        goto leave;
      if (basedn)
        xfree (tmpbasedn); /* Extended syntax overrides.  */
      else if (tmpbasedn)
        basedn = tmpbasedn;
      else if (!(ks_get_flags & KS_GET_FLAG_ROOTDSE))
        {
          /* No BaseDN known - get one.  */
          basedn = basedn_from_rootdse (ctrl, uri);
        }

      if (opt.debug)
        {
          log_debug ("ks-ldap: using basedn: %s\n", basedn);
          log_debug ("ks-ldap: using filter: %s\n", filter);
        }

      err = search_and_parse (ctrl, filter, ldap_conn, basedn, scope, filter,
                              attrs, &message);
      if (err)
        goto leave;


      for (npth_unprotect (),
             msg = ldap_first_entry (ldap_conn, message),
             npth_protect ();
	   msg;
           npth_unprotect (),
             msg = ldap_next_entry (ldap_conn, msg),
             npth_protect ())
	{
          err = return_all_attributes (ldap_conn, msg, &fp);
          if (!err)
            {
              anydata = 1;
              if (first_mode)
                break;
            }
          else if (gpg_err_code (err) == GPG_ERR_NO_DATA)
            err = 0;  /* Skip empty/duplicate attributes. */
          else
            goto leave;
	}

      if (ctrl->ks_get_state) /* Save the iterator.  */
        ctrl->ks_get_state->msg_iter = msg;

      if (!fp) /* Nothing was found.  */
	err = gpg_error (GPG_ERR_NO_DATA);

      if (!err && anydata)
        err = dirmngr_status_printf (ctrl, "SOURCE", "%s://%s",
                                     use_tls? "ldaps" : "ldap",
                                     host? host:"");
    }


 leave:
  /* Store our state if needed.  */
  if (!err && (ks_get_flags & KS_GET_FLAG_FIRST))
    {
      log_assert (!ctrl->ks_get_state->ldap_conn);
      ctrl->ks_get_state->ldap_conn = ldap_conn;
      ldap_conn = NULL;
      log_assert (!ctrl->ks_get_state->message);
      ctrl->ks_get_state->message = message;
      message = NULL;
      ctrl->ks_get_state->serverinfo = serverinfo;
      ctrl->ks_get_state->scope = scope;
      ctrl->ks_get_state->basedn = basedn;
      basedn = NULL;
      ctrl->ks_get_state->keyspec = filter? xtrystrdup (filter) : NULL;
      ctrl->ks_get_state->filter = filter;
      filter = NULL;
    }
  if ((ks_get_flags & KS_GET_FLAG_NEXT))
    {
      /* Keep the state in --next mode even with errors.  */
      ldap_conn = NULL;
      message = NULL;
    }

  if (message)
    ldap_msgfree (message);

  if (err)
    es_fclose (fp);
  else
    {
      if (fp)
	es_fseek (fp, 0, SEEK_SET);
      *r_fp = fp;
    }

  xfree (basedn);
  xfree (host);

  if (ldap_conn)
    ldap_unbind (ldap_conn);

  xfree (filter);
  xfree (filter_arg_buffer);

  return err;
}
