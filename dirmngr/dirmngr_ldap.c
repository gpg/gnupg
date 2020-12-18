/* dirmngr-ldap.c  -  The LDAP helper for dirmngr.
 * Copyright (C) 2004 g10 Code GmbH
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
#ifndef USE_LDAPWRAPPER
# include <npth.h>
#endif

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
#include "../common/argparse.h"
#include "../common/stringhelp.h"
#include "../common/mischelp.h"
#include "../common/strlist.h"

#include "../common/i18n.h"
#include "../common/util.h"
#include "../common/init.h"

/* With the ldap wrapper, there is no need for the npth_unprotect and leave
   functions; thus we redefine them to nops.  If we are not using the
   ldap wrapper process we need to include the prototype for our
   module's main function.  */
#ifdef USE_LDAPWRAPPER
static void npth_unprotect (void) { }
static void npth_protect (void) { }
#else
# include "./ldap-wrapper.h"
#endif

#ifdef HAVE_W32CE_SYSTEM
# include "w32-ldap-help.h"
# define my_ldap_init(a,b)                      \
  _dirmngr_ldap_init ((a), (b))
# define my_ldap_simple_bind_s(a,b,c)           \
  _dirmngr_ldap_simple_bind_s ((a),(b),(c))
# define my_ldap_search_st(a,b,c,d,e,f,g,h)     \
  _dirmngr_ldap_search_st ((a), (b), (c), (d), (e), (f), (g), (h))
# define my_ldap_first_attribute(a,b,c)         \
  _dirmngr_ldap_first_attribute ((a),(b),(c))
# define my_ldap_next_attribute(a,b,c)          \
  _dirmngr_ldap_next_attribute ((a),(b),(c))
# define my_ldap_get_values_len(a,b,c)          \
  _dirmngr_ldap_get_values_len ((a),(b),(c))
# define my_ldap_free_attr(a)                   \
  xfree ((a))
#else
# define my_ldap_init(a,b)              ldap_init ((a), (b))
# define my_ldap_simple_bind_s(a,b,c)   ldap_simple_bind_s ((a), (b), (c))
# define my_ldap_search_st(a,b,c,d,e,f,g,h)     \
  ldap_search_st ((a), (b), (c), (d), (e), (f), (g), (h))
# define my_ldap_first_attribute(a,b,c) ldap_first_attribute ((a),(b),(c))
# define my_ldap_next_attribute(a,b,c)  ldap_next_attribute ((a),(b),(c))
# define my_ldap_get_values_len(a,b,c)  ldap_get_values_len ((a),(b),(c))
# define my_ldap_free_attr(a)           ldap_memfree ((a))
#endif

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
    oDN,
    oFilter,
    oAttr,

    oOnlySearchTimeout,
    oLogWithPID
  };


/* The list of options as used by the argparse.c code.  */
static ARGPARSE_OPTS opts[] = {
  { oVerbose,  "verbose",   0, N_("verbose") },
  { oQuiet,    "quiet",     0, N_("be somewhat more quiet") },
  { oTimeout,  "timeout",   1, N_("|N|set LDAP timeout to N seconds")},
  { oMulti,    "multi",     0, N_("return all values in"
                                  " a record oriented format")},
  { oProxy,    "proxy",     2,
    N_("|NAME|ignore host part and connect through NAME")},
  { oHost,     "host",      2, N_("|NAME|connect to host NAME")},
  { oPort,     "port",      1, N_("|N|connect to port N")},
  { oUser,     "user",      2, N_("|NAME|use user NAME for authentication")},
  { oPass,     "pass",      2, N_("|PASS|use password PASS"
                                  " for authentication")},
  { oEnvPass,  "env-pass",  0, N_("take password from $DIRMNGR_LDAP_PASS")},
  { oDN,       "dn",        2, N_("|STRING|query DN STRING")},
  { oFilter,   "filter",    2, N_("|STRING|use STRING as filter expression")},
  { oAttr,     "attr",      2, N_("|STRING|return the attribute STRING")},
  { oOnlySearchTimeout, "only-search-timeout", 0, "@"},
  { oLogWithPID,"log-with-pid", 0, "@"},
  ARGPARSE_end ()
};


/* A structure with module options.  This is not a static variable
   because if we are not build as a standalone binary, each thread
   using this module needs to handle its own values.  */
struct my_opt_s
{
  int quiet;
  int verbose;
  my_ldap_timeval_t timeout;/* Timeout for the LDAP search functions.  */
  unsigned int alarm_timeout; /* And for the alarm based timeout.  */
  int multi;

  estream_t outstream;    /* Send output to this stream.  */

  /* Note that we can't use const for the strings because ldap_* are
     not defined that way.  */
  char *proxy; /* Host and Port override.  */
  char *user;  /* Authentication user.  */
  char *pass;  /* Authentication password.  */
  char *host;  /* Override host.  */
  int port;    /* Override port.  */
  char *dn;    /* Override DN.  */
  char *filter;/* Override filter.  */
  char *attr;  /* Override attribute.  */
};
typedef struct my_opt_s *my_opt_t;


/* Prototypes.  */
#ifndef HAVE_W32_SYSTEM
static void catch_alarm (int dummy);
#endif
static int process_url (my_opt_t myopt, const char *url);



/* Function called by argparse.c to display information.  */
#ifdef USE_LDAPWRAPPER
static const char *
my_strusage (int level)
{
  const char *p;

  switch(level)
    {
    case  9: p = "GPL-3.0-or-later"; break;
    case 11: p = "dirmngr_ldap (@GNUPG@)";
      break;
    case 13: p = VERSION; break;
    case 14: p = GNUPG_DEF_COPYRIGHT_LINE; break;
    case 17: p = PRINTABLE_OS_NAME; break;
    case 19: p = _("Please report bugs to <@EMAIL@>.\n"); break;
    case 49: p = PACKAGE_BUGREPORT; break;
    case 1:
    case 40: p =
               _("Usage: dirmngr_ldap [options] [URL] (-h for help)\n");
      break;
    case 41: p =
          _("Syntax: dirmngr_ldap [options] [URL]\n"
            "Internal LDAP helper for Dirmngr\n"
            "Interface and options may change without notice\n");
      break;

    default: p = NULL;
    }
  return p;
}
#endif /*!USE_LDAPWRAPPER*/


int
#ifdef USE_LDAPWRAPPER
main (int argc, char **argv)
#else
ldap_wrapper_main (char **argv, estream_t outstream)
#endif
{
#ifndef USE_LDAPWRAPPER
  int argc;
#endif
  ARGPARSE_ARGS pargs;
  int any_err = 0;
  char *p;
  int only_search_timeout = 0;
  struct my_opt_s my_opt_buffer;
  my_opt_t myopt = &my_opt_buffer;
  char *malloced_buffer1 = NULL;

  memset (&my_opt_buffer, 0, sizeof my_opt_buffer);

  early_system_init ();

#ifdef USE_LDAPWRAPPER
  set_strusage (my_strusage);
  log_set_prefix ("dirmngr_ldap", GPGRT_LOG_WITH_PREFIX);

  /* Setup I18N and common subsystems. */
  i18n_init();

  init_common_subsystems (&argc, &argv);

  es_set_binary (es_stdout);
  myopt->outstream = es_stdout;
#else /*!USE_LDAPWRAPPER*/
  myopt->outstream = outstream;
  for (argc=0; argv[argc]; argc++)
    ;
#endif /*!USE_LDAPWRAPPER*/

  /* LDAP defaults */
  myopt->timeout.tv_sec = DEFAULT_LDAP_TIMEOUT;
  myopt->timeout.tv_usec = 0;
  myopt->alarm_timeout = 0;

  /* Parse the command line.  */
  pargs.argc = &argc;
  pargs.argv = &argv;
  pargs.flags= ARGPARSE_FLAG_KEEP;
  while (gnupg_argparse (NULL, &pargs, opts))
    {
      switch (pargs.r_opt)
        {
        case oVerbose: myopt->verbose++; break;
        case oQuiet: myopt->quiet++; break;
	case oTimeout:
	  myopt->timeout.tv_sec = pargs.r.ret_int;
	  myopt->timeout.tv_usec = 0;
          myopt->alarm_timeout = pargs.r.ret_int;
	  break;
        case oOnlySearchTimeout: only_search_timeout = 1; break;
        case oMulti: myopt->multi = 1; break;
        case oUser: myopt->user = pargs.r.ret_str; break;
        case oPass: myopt->pass = pargs.r.ret_str; break;
        case oEnvPass:
          myopt->pass = getenv ("DIRMNGR_LDAP_PASS");
          break;
        case oProxy: myopt->proxy = pargs.r.ret_str; break;
        case oHost: myopt->host = pargs.r.ret_str; break;
        case oPort: myopt->port = pargs.r.ret_int; break;
        case oDN:   myopt->dn = pargs.r.ret_str; break;
        case oFilter: myopt->filter = pargs.r.ret_str; break;
        case oAttr: myopt->attr = pargs.r.ret_str; break;
        case oLogWithPID:
          {
            unsigned int oldflags;
            log_get_prefix (&oldflags);
            log_set_prefix (NULL, oldflags | GPGRT_LOG_WITH_PID);
          }
          break;

        default :
#ifdef USE_LDAPWRAPPER
          pargs.err = ARGPARSE_PRINT_ERROR;
#else
          pargs.err = ARGPARSE_PRINT_WARNING;  /* No exit() please.  */
#endif
          break;
	}
    }
  gnupg_argparse (NULL, &pargs, NULL);  /* Release internal state.  */

  if (only_search_timeout)
    myopt->alarm_timeout = 0;

  if (myopt->proxy)
    {
      malloced_buffer1 = xtrystrdup (myopt->proxy);
      if (!malloced_buffer1)
        {
          log_error ("error copying string: %s\n", strerror (errno));
          return 1;
        }
      myopt->host = malloced_buffer1;
      p = strchr (myopt->host, ':');
      if (p)
        {
          *p++ = 0;
          myopt->port = atoi (p);
        }
      if (!myopt->port)
        myopt->port = 389;  /* make sure ports gets overridden.  */
    }

  if (myopt->port < 0 || myopt->port > 65535)
    log_error (_("invalid port number %d\n"), myopt->port);

#ifdef USE_LDAPWRAPPER
  if (log_get_errorcount (0))
    exit (2);
  if (argc < 1)
    usage (1);
#else
  /* All passed arguments should be fine in this case.  */
  log_assert (argc);
#endif

#ifdef USE_LDAPWRAPPER
  if (myopt->alarm_timeout)
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
#endif /*USE_LDAPWRAPPER*/

  for (; argc; argc--, argv++)
    if (process_url (myopt, *argv))
      any_err = 1;

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
set_timeout (my_opt_t myopt)
{
  if (myopt->alarm_timeout)
    {
#ifdef HAVE_W32_SYSTEM
      static HANDLE timer;
      LARGE_INTEGER due_time;

      /* A negative value is a relative time.  */
      due_time.QuadPart = (unsigned long long)-10000000 * myopt->alarm_timeout;

      if (!timer)
        {
          SECURITY_ATTRIBUTES sec_attr;
          DWORD tid;

          memset (&sec_attr, 0, sizeof sec_attr);
          sec_attr.nLength = sizeof sec_attr;
          sec_attr.bInheritHandle = FALSE;

          /* Create a manual resetable timer.  */
          timer = CreateWaitableTimer (NULL, TRUE, NULL);
          /* Intially set the timer.  */
          SetWaitableTimer (timer, &due_time, 0, NULL, NULL, 0);

          if (CreateThread (&sec_attr, 0, alarm_thread, timer, 0, &tid))
            log_error ("failed to create alarm thread\n");
        }
      else /* Retrigger the timer.  */
        SetWaitableTimer (timer, &due_time, 0, NULL, NULL, 0);
#else
      alarm (myopt->alarm_timeout);
#endif
    }
}


/* Helper for fetch_ldap().  */
static int
print_ldap_entries (my_opt_t myopt, LDAP *ld, LDAPMessage *msg, char *want_attr)
{
  LDAPMessage *item;
  int any = 0;

  for (npth_unprotect (), item = ldap_first_entry (ld, msg), npth_protect ();
       item;
       npth_unprotect (), item = ldap_next_entry (ld, item), npth_protect ())
    {
      BerElement *berctx;
      char *attr;

      if (myopt->verbose > 1)
        log_info (_("scanning result for attribute '%s'\n"),
                  want_attr? want_attr : "[all]");

      if (myopt->multi)
        { /*  Write item marker. */
          if (es_fwrite ("I\0\0\0\0", 5, 1, myopt->outstream) != 1)
            {
              log_error (_("error writing to stdout: %s\n"),
                         strerror (errno));
              return -1;
            }
        }


      for (npth_unprotect (), attr = my_ldap_first_attribute (ld, item, &berctx),
             npth_protect ();
           attr;
           npth_unprotect (), attr = my_ldap_next_attribute (ld, item, berctx),
             npth_protect ())
        {
          struct berval **values;
          int idx;

          if (myopt->verbose > 1)
            log_info (_("          available attribute '%s'\n"), attr);

          set_timeout (myopt);

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
                  my_ldap_free_attr (attr);
                  continue; /* Not found:  Try next attribute.  */
                }
            }

          npth_unprotect ();
          values = my_ldap_get_values_len (ld, item, attr);
          npth_protect ();

          if (!values)
            {
              if (myopt->verbose)
                log_info (_("attribute '%s' not found\n"), attr);
              my_ldap_free_attr (attr);
              continue;
            }

          if (myopt->verbose)
            {
              log_info (_("found attribute '%s'\n"), attr);
              if (myopt->verbose > 1)
                for (idx=0; values[idx]; idx++)
                  log_info ("         length[%d]=%d\n",
                            idx, (int)values[0]->bv_len);

            }

          if (myopt->multi)
            { /*  Write attribute marker. */
              unsigned char tmp[5];
              size_t n = strlen (attr);

              tmp[0] = 'A';
              tmp[1] = (n >> 24);
              tmp[2] = (n >> 16);
              tmp[3] = (n >> 8);
              tmp[4] = (n);
              if (es_fwrite (tmp, 5, 1, myopt->outstream) != 1
                  || es_fwrite (attr, n, 1, myopt->outstream) != 1)
                {
                  log_error (_("error writing to stdout: %s\n"),
                             strerror (errno));
                  ldap_value_free_len (values);
                  my_ldap_free_attr (attr);
                  ber_free (berctx, 0);
                  return -1;
                }
            }

          for (idx=0; values[idx]; idx++)
            {
              if (myopt->multi)
                { /* Write value marker.  */
                  unsigned char tmp[5];
                  size_t n = values[0]->bv_len;

                  tmp[0] = 'V';
                  tmp[1] = (n >> 24);
                  tmp[2] = (n >> 16);
                  tmp[3] = (n >> 8);
                  tmp[4] = (n);

                  if (es_fwrite (tmp, 5, 1, myopt->outstream) != 1)
                    {
                      log_error (_("error writing to stdout: %s\n"),
                                 strerror (errno));
                      ldap_value_free_len (values);
                      my_ldap_free_attr (attr);
                      ber_free (berctx, 0);
                      return -1;
                    }
                }

	      if (es_fwrite (values[0]->bv_val, values[0]->bv_len,
                             1, myopt->outstream) != 1)
                {
                  log_error (_("error writing to stdout: %s\n"),
                             strerror (errno));
                  ldap_value_free_len (values);
                  my_ldap_free_attr (attr);
                  ber_free (berctx, 0);
                  return -1;
                }

              any = 1;
              if (!myopt->multi)
                break; /* Print only the first value.  */
            }
          ldap_value_free_len (values);
          my_ldap_free_attr (attr);
          if (want_attr || !myopt->multi)
            break; /* We only want to return the first attribute.  */
        }
      ber_free (berctx, 0);
    }

  if (myopt->verbose > 1 && any)
    log_info ("result has been printed\n");

  return any?0:-1;
}



/* Helper for the URL based LDAP query. */
static int
fetch_ldap (my_opt_t myopt, const char *url, const LDAPURLDesc *ludp)
{
  LDAP *ld;
  LDAPMessage *msg;
  int rc = 0;
  char *host, *dn, *filter, *attrs[2], *attr;
  int port;
  int ret;

  host     = myopt->host?   myopt->host   : ludp->lud_host;
  port     = myopt->port?   myopt->port   : ludp->lud_port;
  dn       = myopt->dn?     myopt->dn     : ludp->lud_dn;
  filter   = myopt->filter? myopt->filter : ludp->lud_filter;
  attrs[0] = myopt->attr?   myopt->attr   : ludp->lud_attrs? ludp->lud_attrs[0]:NULL;
  attrs[1] = NULL;
  attr = attrs[0];

  if (!port)
    port = (ludp->lud_scheme && !strcmp (ludp->lud_scheme, "ldaps"))? 636:389;

  if (myopt->verbose)
    {
      log_info (_("processing url '%s'\n"), url);
      if (myopt->user)
        log_info (_("          user '%s'\n"), myopt->user);
      if (myopt->pass)
        log_info (_("          pass '%s'\n"), *myopt->pass?"*****":"");
      if (host)
        log_info (_("          host '%s'\n"), host);
      log_info (_("          port %d\n"), port);
      if (dn)
        log_info (_("            DN '%s'\n"), dn);
      if (filter)
        log_info (_("        filter '%s'\n"), filter);
      if (myopt->multi && !myopt->attr && ludp->lud_attrs)
        {
          int i;
          for (i=0; ludp->lud_attrs[i]; i++)
            log_info (_("          attr '%s'\n"), ludp->lud_attrs[i]);
        }
      else if (attr)
        log_info (_("          attr '%s'\n"), attr);
    }


  if (!host || !*host)
    {
      log_error (_("no host name in '%s'\n"), url);
      return -1;
    }
  if (!myopt->multi && !attr)
    {
      log_error (_("no attribute given for query '%s'\n"), url);
      return -1;
    }

  if (!myopt->multi && !myopt->attr
      && ludp->lud_attrs && ludp->lud_attrs[0] && ludp->lud_attrs[1])
    log_info (_("WARNING: using first attribute only\n"));


  set_timeout (myopt);
  npth_unprotect ();
  ld = my_ldap_init (host, port);
  npth_protect ();
  if (!ld)
    {
      log_error (_("LDAP init to '%s:%d' failed: %s\n"),
                 host, port, strerror (errno));
      return -1;
    }
  npth_unprotect ();
  /* Fixme:  Can we use MYOPT->user or is it shared with other theeads?.  */
  ret = my_ldap_simple_bind_s (ld, myopt->user, myopt->pass);
  npth_protect ();
#ifdef LDAP_VERSION3
  if (ret == LDAP_PROTOCOL_ERROR)
    {
      /* Protocol error could mean that the server only supports v3. */
      int version = LDAP_VERSION3;
      if (myopt->verbose)
        log_info ("protocol error; retrying bind with v3 protocol\n");
      npth_unprotect ();
      ldap_set_option (ld, LDAP_OPT_PROTOCOL_VERSION, &version);
      ret = my_ldap_simple_bind_s (ld, myopt->user, myopt->pass);
      npth_protect ();
    }
#endif
  if (ret)
    {
      log_error (_("binding to '%s:%d' failed: %s\n"),
                 host, port, ldap_err2string (ret));
      ldap_unbind (ld);
      return -1;
    }

  set_timeout (myopt);
  npth_unprotect ();
  rc = my_ldap_search_st (ld, dn, ludp->lud_scope, filter,
                          myopt->multi && !myopt->attr && ludp->lud_attrs?
                          ludp->lud_attrs:attrs,
                          0,
                          &myopt->timeout, &msg);
  npth_protect ();
  if (rc == LDAP_SIZELIMIT_EXCEEDED && myopt->multi)
    {
      if (es_fwrite ("E\0\0\0\x09truncated", 14, 1, myopt->outstream) != 1)
        {
          log_error (_("error writing to stdout: %s\n"), strerror (errno));
          return -1;
        }
    }
  else if (rc)
    {
#ifdef HAVE_W32CE_SYSTEM
      log_error ("searching '%s' failed: %d\n", url, rc);
#else
      log_error (_("searching '%s' failed: %s\n"),
                 url, ldap_err2string (rc));
#endif
      if (rc != LDAP_NO_SUCH_OBJECT)
        {
          /* FIXME: Need deinit (ld)?  */
          /* Hmmm: Do we need to released MSG in case of an error? */
          return -1;
        }
    }

  rc = print_ldap_entries (myopt, ld, msg, myopt->multi? NULL:attr);

  ldap_msgfree (msg);
  ldap_unbind (ld);
  return rc;
}




/* Main processing.  Take the URL and run the LDAP query. The result
   is printed to stdout, errors are logged to the log stream. */
static int
process_url (my_opt_t myopt, const char *url)
{
  int rc;
  LDAPURLDesc *ludp = NULL;


  if (!ldap_is_ldap_url (url))
    {
      log_error (_("'%s' is not an LDAP URL\n"), url);
      return -1;
    }

  if (ldap_url_parse (url, &ludp))
    {
      log_error (_("'%s' is an invalid LDAP URL\n"), url);
      return -1;
    }

  rc = fetch_ldap (myopt, url, ludp);

  ldap_free_urldesc (ludp);
  return rc;
}
