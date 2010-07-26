/* dirmngr-ldap.c  -  The LDAP helper for dirmngr.
 *	Copyright (C) 2004 g10 Code GmbH
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
#include <stddef.h>
#include <stdarg.h>
#include <string.h>
#ifdef HAVE_SIGNAL_H
# include <signal.h>
#endif
#include <errno.h>
#include <assert.h>
#include <sys/time.h>
#include <unistd.h>

#ifdef HAVE_W32_SYSTEM
#include <winsock2.h>
#include <winldap.h>
#include <fcntl.h>
#include "ldap-url.h"
#else
/* For OpenLDAP, to enable the API that we're using. */
#define LDAP_DEPRECATED 1
#include <ldap.h>
#endif


#define JNLIB_NEED_LOG_LOGV
#include "../common/logging.h"
#include "../common/argparse.h"
#include "../common/stringhelp.h"
#include "../common/mischelp.h"
#include "../common/strlist.h"

#include "i18n.h"
#include "util.h"

/* If we are not using the ldap wrapper process we need to include the
   prototype for our module's main function.  */
#ifndef USE_LDAPWRAPPER
#include "./ldap-wrapper.h"
#endif

#define DEFAULT_LDAP_TIMEOUT 100 /* Arbitrary long timeout. */


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
  { 0, NULL, 0, NULL }
};


/* A structure with module options.  This is not a static variable
   because if we are not build as a standalone binary, each thread
   using this module needs to handle its own values.  */
struct my_opt_s
{
  int quiet;
  int verbose;
  struct timeval timeout; /* Timeout for the LDAP search functions.  */
  unsigned int alarm_timeout; /* And for the alarm based timeout.  */
  int multi;

  estream_t outstream;    /* Send output to thsi stream.  */

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
typedef struct my_opt_s my_opt_t;


/* Prototypes.  */
static void catch_alarm (int dummy);
static int process_url (my_opt_t myopt, const char *url);



/* Function called by argparse.c to display information.  */
static const char *
my_strusage (int level)
{
  const char *p;
    
  switch(level)
    {
    case 11: p = "dirmngr_ldap (GnuPG)";
      break;
    case 13: p = VERSION; break;
    case 17: p = PRINTABLE_OS_NAME; break;
    case 19: p = _("Please report bugs to <@EMAIL@>.\n"); break;
    case 49: p = PACKAGE_BUGREPORT; break;
    case 1:
    case 40: p =
               _("Usage: dirmngr_ldap [options] [URL] (-h for help)\n");
      break;
    case 41: p =
          _("Syntax: dirmngr_ldap [options] [URL]\n"
            "Internal LDAP helper for Dirmngr.\n"
            "Interface and options may change without notice.\n");
      break;

    default: p = NULL;
    }
  return p;
}


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
  
  memset (&my_opt_buffer, 0, sizeof my_opt_buffer);

#ifdef USE_LDAPWRAPPER
  set_strusage (my_strusage);
  log_set_prefix ("dirmngr_ldap", JNLIB_LOG_WITH_PREFIX); 
  
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
  pargs.flags= 1;  /* Do not remove the args. */
  while (arg_parse (&pargs, opts) )
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
            log_set_prefix (NULL, oldflags | JNLIB_LOG_WITH_PID);
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

  if (only_search_timeout)
    myopt->alarm_timeout = 0;

  if (myopt->proxy)
    {
      myopt->host = xstrdup (myopt->proxy);
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
  assert (argc);
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


  /* FIXME: Do we need to release stuff?  */
  return any_err;
}


static void
catch_alarm (int dummy)
{
  (void)dummy;
  _exit (10);
}


static void
set_timeout (my_opt_t myopt)
{
#ifndef HAVE_W32_SYSTEM
  /* FIXME for W32.  */
  if (myopt->alarm_timeout)
    alarm (myopt->alarm_timeout);
#endif
}


/* Helper for fetch_ldap().  */
static int
print_ldap_entries (my_opt_t myopt, LDAP *ld, LDAPMessage *msg, char *want_attr)
{
  LDAPMessage *item;
  int any = 0;

  for (item = ldap_first_entry (ld, msg); item;
       item = ldap_next_entry (ld, item))
    {
      BerElement *berctx;
      char *attr;

      if (myopt->verbose > 1)
        log_info (_("scanning result for attribute `%s'\n"),
                  want_attr? want_attr : "[all]");

      if (myopt->multi)
        { /*  Write item marker. */
          if (es_fwrite ("I\0\0\0\0", 5, 1, myopt->oustream) != 1)
            {
              log_error (_("error writing to stdout: %s\n"),
                         strerror (errno));
              return -1;
            }
        }

          
      for (attr = ldap_first_attribute (ld, item, &berctx); attr;
           attr = ldap_next_attribute (ld, item, berctx))
        {
          struct berval **values;
          int idx;

          if (myopt->verbose > 1)
            log_info (_("          available attribute `%s'\n"), attr);
          
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
                  ldap_memfree (attr);
                  continue; /* Not found:  Try next attribute.  */
                }
            }

          values = ldap_get_values_len (ld, item, attr);
  
          if (!values)
            {
              if (myopt->verbose)
                log_info (_("attribute `%s' not found\n"), attr);
              ldap_memfree (attr);
              continue;
            }

          if (myopt->verbose)
            {
              log_info (_("found attribute `%s'\n"), attr);
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
              if (es_fwrite (tmp, 5, 1, myopt->oustream) != 1 
                  || es_fwrite (attr, n, 1, myopt->oustream) != 1)
                {
                  log_error (_("error writing to stdout: %s\n"),
                             strerror (errno));
                  ldap_value_free_len (values);
                  ldap_memfree (attr);
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

                  if (es_fwrite (tmp, 5, 1, myopt->oustream) != 1)
                    {
                      log_error (_("error writing to stdout: %s\n"),
                                 strerror (errno));
                      ldap_value_free_len (values);
                      ldap_memfree (attr);
                      ber_free (berctx, 0);
                      return -1;
                    }
                }
#if 1
	      /* Note: this does not work for STDOUT on a Windows
		 console, where it fails with "Not enough space" for
		 CRLs which are 52 KB or larger.  */
#warning still true - implement in estream
	      if (es_fwrite (values[0]->bv_val, values[0]->bv_len,
                             1, myopt->oustream) != 1)
                {
                  log_error (_("error writing to stdout: %s\n"),
                             strerror (errno));
                  ldap_value_free_len (values);
                  ldap_memfree (attr);
                  ber_free (berctx, 0);
                  return -1;
                }
#else
	      /* On Windows console STDOUT, we have to break up the
		 writes into small parts.  */
	      {
		int n = 0;
		while (n < values[0]->bv_len)
		  {
		    int cnt = values[0]->bv_len - n;
		    /* The actual limit is (52 * 1024 - 1) on Windows XP SP2.  */
#define MAX_CNT (32*1024)
		    if (cnt > MAX_CNT)
		      cnt = MAX_CNT;
		    
		    if (es_fwrite (((char *) values[0]->bv_val) + n, cnt, 1,
                                   myopt->oustream) != 1)
		      {
			log_error (_("error writing to stdout: %s\n"),
				   strerror (errno));
			ldap_value_free_len (values);
			ldap_memfree (attr);
			ber_free (berctx, 0);
			return -1;
		      }
		    n += cnt;
		  }
	      }
#endif
              any = 1;
              if (!myopt->multi)
                break; /* Print only the first value.  */
            }
          ldap_value_free_len (values);
          ldap_memfree (attr);
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
      log_info (_("processing url `%s'\n"), url);
      if (myopt->user)
        log_info (_("          user `%s'\n"), myopt->user);
      if (myopt->pass)
        log_info (_("          pass `%s'\n"), *myopt->pass?"*****":"");
      if (host)
        log_info (_("          host `%s'\n"), host);
      log_info (_("          port %d\n"), port);
      if (dn)
        log_info (_("            DN `%s'\n"), dn);
      if (filter)
        log_info (_("        filter `%s'\n"), filter);
      if (myopt->multi && !myopt->attr && ludp->lud_attrs)
        {
          int i;
          for (i=0; ludp->lud_attrs[i]; i++)
            log_info (_("          attr `%s'\n"), ludp->lud_attrs[i]);
        }
      else if (attr)
        log_info (_("          attr `%s'\n"), attr);
    }


  if (!host || !*host)
    {
      log_error (_("no host name in `%s'\n"), url);
      return -1;
    }
  if (!myopt->multi && !attr)
    {
      log_error (_("no attribute given for query `%s'\n"), url);
      return -1;
    }

  if (!myopt->multi && !myopt->attr
      && ludp->lud_attrs && ludp->lud_attrs[0] && ludp->lud_attrs[1])
    log_info (_("WARNING: using first attribute only\n"));


  set_timeout (myopt);
  ld = ldap_init (host, port);
  if (!ld)
    {
      log_error (_("LDAP init to `%s:%d' failed: %s\n"), 
                 host, port, strerror (errno));
      return -1;
    }
  if (ldap_simple_bind_s (ld, myopt->user, myopt->pass))
    {
      log_error (_("binding to `%s:%d' failed: %s\n"), 
                 host, port, strerror (errno));
      /* FIXME: Need deinit (ld)?  */
      return -1;
    }

  set_timeout (myopt);
  rc = ldap_search_st (ld, dn, ludp->lud_scope, filter,
                       myopt->multi && !myopt->attr && ludp->lud_attrs?
                       ludp->lud_attrs:attrs,
                       0,
                       &myopt->timeout, &msg);
  if (rc == LDAP_SIZELIMIT_EXCEEDED && myopt->multi)
    {
      if (es_fwrite ("E\0\0\0\x09truncated", 14, 1, myopt->oustream) != 1)
        {
          log_error (_("error writing to stdout: %s\n"), strerror (errno));
          return -1;
        }
    }
  else if (rc)
    {
      log_error (_("searching `%s' failed: %s\n"), 
                 url, ldap_err2string (rc));
      if (rc != LDAP_NO_SUCH_OBJECT)
        {
          /* FIXME: Need deinit (ld)?  */
          /* Hmmm: Do we need to released MSG in case of an error? */
          return -1;
        }
    }

  rc = print_ldap_entries (myopt, ld, msg, myopt->multi? NULL:attr);

  ldap_msgfree (msg);
  /* FIXME: Need deinit (ld)?  */
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
      log_error (_("`%s' is not an LDAP URL\n"), url);
      return -1;
    }

  if (ldap_url_parse (url, &ludp))
    {
      log_error (_("`%s' is an invalid LDAP URL\n"), url);
      return -1;
    }

  rc = fetch_ldap (myopt, url, ludp);

  ldap_free_urldesc (ludp);
  return rc;
}

