/* dirmngr-ldap.c  -  The LDAP helper for dirmngr.
 * Copyright (C) 2004, 2021 g10 Code GmbH
 * Copyright (C) 2010 Free Software Foundation, Inc.
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
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

#include <config.h>


#include <stdio.h>
#include <stdlib.h>
#include <stddef.h>
#include <stdarg.h>
#include <string.h>
#ifdef HAVE_SIGNAL_H
# include <signal.h>
#endif
#include <errno.h>
#include <sys/time.h>
#include <unistd.h>

#ifdef HAVE_W32_SYSTEM
# include <winsock2.h>
# include <winldap.h>
# include <winber.h>
# include <fcntl.h>
# include "ldap-url.h"
#else
  /* For OpenLDAP, to enable the API that we're using. */
# define LDAP_DEPRECATED 1
# include <ldap.h>
#endif


#include <gpg-error.h>
#include "../common/logging.h"
#include "../common/stringhelp.h"
#include "../common/mischelp.h"
#include "../common/strlist.h"
#include "../common/util.h"
#include "../common/init.h"
#include "ldap-misc.h"


/* There is no need for the npth_unprotect and leave functions here;
 * thus we redefine them to nops.  We keep them in the code just for
 * the case we ever want to reuse parts of the code in npth programs. */
static void npth_unprotect (void) { }
static void npth_protect (void) { }


#ifdef HAVE_W32_SYSTEM
 typedef LDAP_TIMEVAL  my_ldap_timeval_t;
#else
 typedef struct timeval my_ldap_timeval_t;
#endif

#define DEFAULT_LDAP_TIMEOUT 15 /* Arbitrary long timeout. */


/* Constants for the options.  */
enum
  {
    oQuiet	  = 'q',
    oVerbose	  = 'v',

    oTimeout      = 500,
    oMulti,
    oProxy,
    oHost,
    oPort,
    oUser,
    oPass,
    oEnvPass,
    oBase,
    oAttr,
    oStartTLS,
    oLdapTLS,
    oNtds,
    oARecOnly,
    oOnlySearchTimeout,
    oLogWithPID
  };


/* The list of options as used by the argparse.c code.  */
static gpgrt_opt_t opts[] = {
  { oVerbose,  "verbose",   0, "verbose" },
  { oQuiet,    "quiet",     0, "be somewhat more quiet" },
  { oTimeout,  "timeout",   1, "|N|set LDAP timeout to N seconds"},
  { oMulti,    "multi",     0, "return all values in"
                               " a record oriented format"},
  { oProxy,    "proxy",     2,
                "|NAME|ignore host part and connect through NAME"},
  { oStartTLS, "starttls",  0, "use STARTLS for the connection"},
  { oLdapTLS,  "ldaptls",   0, "use a TLS for the connection"},
  { oNtds,     "ntds",      0, "authenticate using AD"},
  { oARecOnly, "areconly",  0, "do only an A record lookup"},
  { oHost,     "host",      2, "|NAME|connect to host NAME"},
  { oPort,     "port",      1, "|N|connect to port N"},
  { oUser,     "user",      2, "|NAME|use NAME for authentication"},
  { oPass,     "pass",      2, "|PASS|use password PASS"
                               " for authentication"},
  { oEnvPass,  "env-pass",  0, "take password from $DIRMNGR_LDAP_PASS"},
  { oBase,     "base",      2, "|DN|Start query at DN"},
  { oAttr,     "attr",      2, "|STRING|return the attribute STRING"},
  { oOnlySearchTimeout, "only-search-timeout", 0, "@"},
  { oLogWithPID,"log-with-pid", 0, "@"},
  ARGPARSE_end ()
};


/* A structure with module options.  */
static struct
{
  int quiet;
  int verbose;
  my_ldap_timeval_t timeout;/* Timeout for the LDAP search functions.  */
  unsigned int alarm_timeout; /* And for the alarm based timeout.  */
  int multi;
  int starttls;
  int ldaptls;
  int ntds;
  int areconly;

  estream_t outstream;    /* Send output to this stream.  */

  /* Note that we can't use const for the strings because ldap_* are
     not defined that way.  */
  char *proxy; /* Host and Port override.  */
  char *user;  /* Authentication user.  */
  char *pass;  /* Authentication password.  */
  char *host;  /* Override host.  */
  int  port;   /* Override port.  */
  char *base;  /* Override DN.  */
  char *attr;  /* Override attribute.  */
} opt;


/* Prototypes.  */
#ifndef HAVE_W32_SYSTEM
static void catch_alarm (int dummy);
#endif
static gpg_error_t connect_ldap (LDAP **r_ld);
static gpg_error_t process_filter (LDAP *ld, const char *string);



/* Function called by argparse.c to display information.  */
static const char *
my_strusage (int level)
{
  const char *p;

  switch (level)
    {
    case  9: p = "GPL-3.0-or-later"; break;
    case 11: p = "dirmngr_ldap (@GNUPG@)";
      break;
    case 13: p = VERSION; break;
    case 14: p = GNUPG_DEF_COPYRIGHT_LINE; break;
    case 17: p = PRINTABLE_OS_NAME; break;
    case 19: p = "Please report bugs to <@EMAIL@>.\n"; break;
    case 49: p = PACKAGE_BUGREPORT; break;
    case 1:
    case 40: p =
               "Usage: dirmngr_ldap [options] filters (-h for help)\n";
      break;
    case 41: p =
           ("Syntax: dirmngr_ldap [options] filters\n"
            "Internal LDAP helper for Dirmngr\n"
            "Interface and options may change without notice\n");
      break;

    default: p = NULL;
    }
  return p;
}


int
main (int argc, char **argv)
{
  gpgrt_argparse_t pargs;
  int any_err = 0;
  char *p;
  int only_search_timeout = 0;
  char *malloced_buffer1 = NULL;
  LDAP *ld;

  early_system_init ();

  gpgrt_set_strusage (my_strusage);
  log_set_prefix ("dirmngr_ldap", GPGRT_LOG_WITH_PREFIX);

  init_common_subsystems (&argc, &argv);

  es_set_binary (es_stdout);
  opt.outstream = es_stdout;

  /* LDAP defaults */
  opt.timeout.tv_sec = DEFAULT_LDAP_TIMEOUT;
  opt.timeout.tv_usec = 0;
  opt.alarm_timeout = 0;

  /* Parse the command line.  */
  pargs.argc = &argc;
  pargs.argv = &argv;
  pargs.flags= ARGPARSE_FLAG_KEEP;
  while (gpgrt_argparse (NULL, &pargs, opts))
    {
      switch (pargs.r_opt)
        {
        case oVerbose: opt.verbose++; break;
        case oQuiet: opt.quiet++; break;
	case oTimeout:
	  opt.timeout.tv_sec = pargs.r.ret_int;
	  opt.timeout.tv_usec = 0;
          opt.alarm_timeout = pargs.r.ret_int;
	  break;
        case oOnlySearchTimeout: only_search_timeout = 1; break;
        case oStartTLS: opt.starttls = 1; opt.ldaptls = 0; break;
        case oLdapTLS:  opt.starttls = 0; opt.ldaptls = 1; break;
        case oNtds:     opt.ntds = 1; break;
        case oARecOnly: opt.areconly = 1; break;
        case oMulti: opt.multi = 1; break;
        case oUser: opt.user = pargs.r.ret_str; break;
        case oPass: opt.pass = pargs.r.ret_str; break;
        case oEnvPass:
          opt.pass = getenv ("DIRMNGR_LDAP_PASS");
          break;
        case oProxy: opt.proxy = pargs.r.ret_str; break;
        case oHost: opt.host = pargs.r.ret_str; break;
        case oPort: opt.port = pargs.r.ret_int; break;
        case oBase: opt.base = pargs.r.ret_str; break;
        case oAttr: opt.attr = pargs.r.ret_str; break;
        case oLogWithPID:
          {
            unsigned int oldflags;
            log_get_prefix (&oldflags);
            log_set_prefix (NULL, oldflags | GPGRT_LOG_WITH_PID);
          }
          break;

        default :
          pargs.err = ARGPARSE_PRINT_ERROR;
          break;
	}
    }
  gpgrt_argparse (NULL, &pargs, NULL);

  if (only_search_timeout)
    opt.alarm_timeout = 0;

  if (opt.proxy)
    {
      malloced_buffer1 = xtrystrdup (opt.proxy);
      if (!malloced_buffer1)
        {
          log_error ("error copying string: %s\n", strerror (errno));
          return 1;
        }
      opt.host = malloced_buffer1;
      p = strchr (opt.host, ':');
      if (p)
        {
          *p++ = 0;
          opt.port = atoi (p);
        }
      if (!opt.port)
        opt.port = 389;  /* make sure ports gets overridden.  */
    }

  if (opt.port < 0 || opt.port > 65535)
    log_error ("invalid port number %d\n", opt.port);

  if (!opt.port)
    opt.port = opt.ldaptls? 636 : 389;

#ifndef HAVE_W32_SYSTEM
  if (!opt.host)
    opt.host = "localhost";
#endif


  if (log_get_errorcount (0))
    exit (2);

  if (opt.alarm_timeout)
    {
#ifndef HAVE_W32_SYSTEM
# if defined(HAVE_SIGACTION) && defined(HAVE_STRUCT_SIGACTION)
      struct sigaction act;

      act.sa_handler = catch_alarm;
      sigemptyset (&act.sa_mask);
      act.sa_flags = 0;
      if (sigaction (SIGALRM,&act,NULL))
# else
      if (signal (SIGALRM, catch_alarm) == SIG_ERR)
# endif
          log_fatal ("unable to register timeout handler\n");
#endif
    }

  if (connect_ldap (&ld))
    any_err = 1;
  else
    {
      if (!argc)
        {
          if (process_filter (ld, "(objectClass=*)"))
            any_err = 1;
        }
      else
        {
          for (; argc; argc--, argv++)
            if (process_filter (ld, *argv))
              any_err = 1;
        }
      ldap_unbind (ld);
    }

  xfree (malloced_buffer1);
  return any_err;
}

#ifndef HAVE_W32_SYSTEM
static void
catch_alarm (int dummy)
{
  (void)dummy;
  _exit (10);
}
#endif


#ifdef HAVE_W32_SYSTEM
static DWORD CALLBACK
alarm_thread (void *arg)
{
  HANDLE timer = arg;

  WaitForSingleObject (timer, INFINITE);
  _exit (10);

  return 0;
}
#endif


static void
set_timeout (void)
{
  if (opt.alarm_timeout)
    {
#ifdef HAVE_W32_SYSTEM
      static HANDLE timer;
      LARGE_INTEGER due_time;

      /* A negative value is a relative time.  */
      due_time.QuadPart = (unsigned long long)-10000000 * opt.alarm_timeout;

      if (!timer)
        {
          SECURITY_ATTRIBUTES sec_attr;
          DWORD tid;

          memset (&sec_attr, 0, sizeof sec_attr);
          sec_attr.nLength = sizeof sec_attr;
          sec_attr.bInheritHandle = FALSE;

          /* Create a manual resettable timer.  */
          timer = CreateWaitableTimer (NULL, TRUE, NULL);
          /* Initially set the timer.  */
          SetWaitableTimer (timer, &due_time, 0, NULL, NULL, 0);

          if (CreateThread (&sec_attr, 0, alarm_thread, timer, 0, &tid))
            log_error ("failed to create alarm thread\n");
        }
      else /* Retrigger the timer.  */
        SetWaitableTimer (timer, &due_time, 0, NULL, NULL, 0);
#else
      alarm (opt.alarm_timeout);
#endif
    }
}



/* Connect to the ldap server.  On success the connection handle is
 * stored at R_LD. */
static gpg_error_t
connect_ldap (LDAP **r_ld)
{
  gpg_error_t err = 0;
  int lerr;
  LDAP *ld = NULL;
#ifndef HAVE_W32_SYSTEM
  char *tmpstr;
#endif

  *r_ld = NULL;

  if (opt.starttls || opt.ldaptls)
    {
#ifndef HAVE_LDAP_START_TLS_S
      log_error ("ldap: can't connect to the server: no TLS support.");
      err = GPG_ERR_LDAP_NOT_SUPPORTED;
      goto leave;
#endif
    }


  set_timeout ();
#ifdef HAVE_W32_SYSTEM
  npth_unprotect ();
  ld = ldap_sslinit (opt.host, opt.port, opt.ldaptls);
  npth_protect ();
  if (!ld)
    {
      lerr = LdapGetLastError ();
      err = ldap_err_to_gpg_err (lerr);
      log_error ("error initializing LDAP '%s:%d': %s\n",
                 opt.host, opt.port, ldap_err2string (lerr));
      goto leave;
    }
  if (opt.areconly)
    {
      lerr = ldap_set_option (ld, LDAP_OPT_AREC_EXCLUSIVE, LDAP_OPT_ON);
      if (lerr != LDAP_SUCCESS)
        {
          log_error ("ldap: unable to set AREC_EXLUSIVE: %s\n",
                     ldap_err2string (lerr));
          err = ldap_err_to_gpg_err (lerr);
          goto leave;
        }
    }
#else /* Unix */
  tmpstr = xtryasprintf ("%s://%s:%d",
                         opt.ldaptls? "ldaps" : "ldap",
                         opt.host, opt.port);
  if (!tmpstr)
    {
      err = gpg_error_from_syserror ();
      goto leave;
    }
  npth_unprotect ();
  lerr = ldap_initialize (&ld, tmpstr);
  npth_protect ();
  if (lerr || !ld)
    {
      err = ldap_err_to_gpg_err (lerr);
      log_error ("error initializing LDAP '%s': %s\n",
                 tmpstr, ldap_err2string (lerr));
      xfree (tmpstr);
      goto leave;
    }
  xfree (tmpstr);
#endif /* Unix */

  if (opt.verbose)
    log_info ("LDAP connected to '%s:%d'%s\n",
              opt.host, opt.port,
              opt.starttls? " using STARTTLS" :
              opt.ldaptls?  " using LDAP-over-TLS" : "");


#ifdef HAVE_LDAP_SET_OPTION
  {
    int ver = LDAP_VERSION3;

    lerr = ldap_set_option (ld, LDAP_OPT_PROTOCOL_VERSION, &ver);
    if (lerr != LDAP_SUCCESS)
      {
	log_error ("unable to go to LDAP 3: %s\n", ldap_err2string (lerr));
	err = ldap_err_to_gpg_err (lerr);
	goto leave;
      }
  }
#endif


#ifdef HAVE_LDAP_START_TLS_S
  if (opt.starttls)
    {
#ifndef HAVE_W32_SYSTEM
      int check_cert = LDAP_OPT_X_TLS_HARD; /* LDAP_OPT_X_TLS_NEVER */

      lerr = ldap_set_option (ld, LDAP_OPT_X_TLS_REQUIRE_CERT, &check_cert);
      if (lerr)
	{
	  log_error ("ldap: error setting an TLS option: %s\n",
                     ldap_err2string (lerr));
          err = ldap_err_to_gpg_err (lerr);
	  goto leave;
	}
#else
      /* On Windows, the certificates are checked by default.  If the
	 option to disable checking mentioned above is ever
	 implemented, the way to do that on Windows is to install a
	 callback routine using ldap_set_option (..,
	 LDAP_OPT_SERVER_CERTIFICATE, ..); */
#endif

      npth_unprotect ();
      lerr = ldap_start_tls_s (ld,
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
	  goto leave;
	}
    }
#endif

  if (opt.ntds)
    {
      if (opt.verbose)
        log_info ("binding to current user via AD\n");
#ifdef HAVE_W32_SYSTEM
      npth_unprotect ();
      lerr = ldap_bind_s (ld, NULL, NULL, LDAP_AUTH_NEGOTIATE);
      npth_protect ();
      if (lerr != LDAP_SUCCESS)
	{
	  log_error ("error binding to LDAP via AD: %s\n",
                     ldap_err2string (lerr));
          err = ldap_err_to_gpg_err (lerr);
	  goto leave;
	}
#else /* Unix */
      err = gpg_error (GPG_ERR_NOT_SUPPORTED);
      goto leave;
#endif /* Unix */
    }
  else if (opt.user)
    {
      if (opt.verbose)
        log_info ("LDAP bind to '%s', password '%s'\n",
                   opt.user, opt.pass ? ">not_shown<" : ">none<");

      npth_unprotect ();
      lerr = ldap_simple_bind_s (ld, opt.user, opt.pass);
      npth_protect ();
      if (lerr != LDAP_SUCCESS)
	{
	  log_error ("error binding to LDAP: %s\n", ldap_err2string (lerr));
          err = ldap_err_to_gpg_err (lerr);
	  goto leave;
	}
    }
  else
    {
      /* By default we don't bind as there is usually no need to.  */
    }

 leave:
  if (err)
    {
      if (ld)
        ldap_unbind (ld);
    }
  else
    *r_ld = ld;
  return err;
}


/* Helper for fetch_ldap().  */
static int
print_ldap_entries (LDAP *ld, LDAPMessage *msg, char *want_attr)
{
  LDAPMessage *item;
  int any = 0;

  for (npth_unprotect (), item = ldap_first_entry (ld, msg), npth_protect ();
       item;
       npth_unprotect (), item = ldap_next_entry (ld, item), npth_protect ())
    {
      BerElement *berctx;
      char *attr;

      if (opt.verbose > 1)
        log_info ("scanning result for attribute '%s'\n",
                  want_attr? want_attr : "[all]");

      if (opt.multi)
        { /*  Write item marker. */
          if (es_fwrite ("I\0\0\0\0", 5, 1, opt.outstream) != 1)
            {
              log_error ("error writing to stdout: %s\n",
                         strerror (errno));
              return -1;
            }
        }


      for (npth_unprotect (), attr = ldap_first_attribute (ld, item, &berctx),
             npth_protect ();
           attr;
           npth_unprotect (), attr = ldap_next_attribute (ld, item, berctx),
             npth_protect ())
        {
          struct berval **values;
          int idx;

          if (opt.verbose > 1)
            log_info ("          available attribute '%s'\n", attr);

          set_timeout ();

          /* I case we want only one attribute we do a case
             insensitive compare without the optional extension
             (i.e. ";binary").  Case insensitive is not really correct
             but the best we can do.  */
          if (want_attr)
            {
              char *cp1, *cp2;
              int cmpres;

              cp1 = strchr (want_attr, ';');
              if (cp1)
                *cp1 = 0;
              cp2 = strchr (attr, ';');
              if (cp2)
                *cp2 = 0;
              cmpres = ascii_strcasecmp (want_attr, attr);
              if (cp1)
                *cp1 = ';';
              if (cp2)
                *cp2 = ';';
              if (cmpres)
                {
                  ldap_memfree (attr);
                  continue; /* Not found:  Try next attribute.  */
                }
            }

          npth_unprotect ();
          values = ldap_get_values_len (ld, item, attr);
          npth_protect ();

          if (!values)
            {
              if (opt.verbose)
                log_info ("attribute '%s' not found\n", attr);
              ldap_memfree (attr);
              continue;
            }

          if (opt.verbose)
            {
              log_info ("found attribute '%s'\n", attr);
              if (opt.verbose > 1)
                for (idx=0; values[idx]; idx++)
                  log_info ("         length[%d]=%d\n",
                            idx, (int)values[0]->bv_len);

            }

          if (opt.multi)
            { /*  Write attribute marker. */
              unsigned char tmp[5];
              size_t n = strlen (attr);

              tmp[0] = 'A';
              tmp[1] = (n >> 24);
              tmp[2] = (n >> 16);
              tmp[3] = (n >> 8);
              tmp[4] = (n);
              if (es_fwrite (tmp, 5, 1, opt.outstream) != 1
                  || es_fwrite (attr, n, 1, opt.outstream) != 1)
                {
                  log_error ("error writing to stdout: %s\n",
                             strerror (errno));
                  ldap_value_free_len (values);
                  ldap_memfree (attr);
                  ber_free (berctx, 0);
                  return -1;
                }
            }

          for (idx=0; values[idx]; idx++)
            {
              if (opt.multi)
                { /* Write value marker.  */
                  unsigned char tmp[5];
                  size_t n = values[0]->bv_len;

                  tmp[0] = 'V';
                  tmp[1] = (n >> 24);
                  tmp[2] = (n >> 16);
                  tmp[3] = (n >> 8);
                  tmp[4] = (n);

                  if (es_fwrite (tmp, 5, 1, opt.outstream) != 1)
                    {
                      log_error ("error writing to stdout: %s\n",
                                 strerror (errno));
                      ldap_value_free_len (values);
                      ldap_memfree (attr);
                      ber_free (berctx, 0);
                      return -1;
                    }
                }

	      if (es_fwrite (values[0]->bv_val, values[0]->bv_len,
                             1, opt.outstream) != 1)
                {
                  log_error ("error writing to stdout: %s\n",
                             strerror (errno));
                  ldap_value_free_len (values);
                  ldap_memfree (attr);
                  ber_free (berctx, 0);
                  return -1;
                }

              any = 1;
              if (!opt.multi)
                break; /* Print only the first value.  */
            }
          ldap_value_free_len (values);
          ldap_memfree (attr);
          if (want_attr || !opt.multi)
            break; /* We only want to return the first attribute.  */
        }
      ber_free (berctx, 0);
    }

  if (opt.verbose > 1 && any)
    log_info ("result has been printed\n");

  return any?0:-1;
}



/* Fetch data from the server at LD using FILTER.  */
static int
fetch_ldap (LDAP *ld, const char *base, int scope, const char *filter)
{
  gpg_error_t err;
  int lerr;
  LDAPMessage *msg;
  char *attrs[2];

  if (filter && !*filter)
    filter = NULL;

  if (opt.verbose)
    {
      log_info ("fetching using");
      if (base)
        log_printf (" base '%s'", base);
      if (filter)
        log_printf (" filter '%s'", filter);
      log_printf ("\n");
    }

  attrs[0] = opt.attr;
  attrs[1] = NULL;

  set_timeout ();
  npth_unprotect ();
  lerr = ldap_search_st (ld, base, scope, filter,
                         attrs,
                         0,
                         &opt.timeout, &msg);
  npth_protect ();
  if (lerr == LDAP_SIZELIMIT_EXCEEDED && opt.multi)
    {
      if (es_fwrite ("E\0\0\0\x09truncated", 14, 1, opt.outstream) != 1)
        {
          log_error ("error writing to stdout: %s\n", strerror (errno));
          return -1;
        }
    }
  else if (lerr)
    {
      log_error ("searching '%s' failed: %s\n",
                 filter, ldap_err2string (lerr));
      if (lerr != LDAP_NO_SUCH_OBJECT)
        {
          /* FIXME: Need deinit (ld)?  */
          /* Hmmm: Do we need to released MSG in case of an error? */
          return -1;
        }
    }

  err = print_ldap_entries (ld, msg, opt.multi? NULL:opt.attr);

  ldap_msgfree (msg);
  return err;
}




/* Main processing.  Take the filter and run the LDAP query. The
 * result is printed to stdout, errors are logged to the log stream.
 * To allow searching with a different base it is possible to extend
 * the filter.  For example:
 *
 *   ^CN=foo, OU=My Users&(objectClasses=*)
 *
 * Uses "CN=foo, OU=My Users" as base DN and "(objectClasses=*)" as
 * filter.  If the base prefix includes an ampersand, it needs to be
 * doubled.  The usual escaping rules for DNs (for the base) and
 * filters apply.  If no scope is given (see ldap_parse_extfilter for
 * the syntax) subtree scope is used.
 */
static gpg_error_t
process_filter (LDAP *ld, const char *string)
{
  gpg_error_t err;
  char *base, *filter;
  int scope = -1;

  err = ldap_parse_extfilter (string, 0, &base, &scope, &filter);
  if (!err)
    err = fetch_ldap (ld,
                      base? base : opt.base,
                      scope == -1? LDAP_SCOPE_SUBTREE : scope,
                      filter);

  xfree (base);
  xfree (filter);
  return err;
}
