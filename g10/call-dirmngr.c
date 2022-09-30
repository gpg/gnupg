/* call-dirmngr.c - GPG operations to the Dirmngr.
 * Copyright (C) 2011 Free Software Foundation, Inc.
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
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <time.h>
#ifdef HAVE_LOCALE_H
# include <locale.h>
#endif

#include "gpg.h"
#include <assuan.h>
#include "../common/util.h"
#include "../common/membuf.h"
#include "options.h"
#include "../common/i18n.h"
#include "../common/asshelp.h"
#include "../common/status.h"
#include "keyserver-internal.h"
#include "call-dirmngr.h"


/* Keys retrieved from the web key directory should be small.  There
 * is only one UID and we can expect that the number of subkeys is
 * reasonable.  So we set a generous limit of 256 KiB.  */
#define MAX_WKD_RESULT_LENGTH   (256 * 1024)


/* Parameter structure used to gather status info.  Note that it is
 * also used for WKD requests.  */
struct ks_status_parm_s
{
  const char *keyword; /* Look for this keyword or NULL for "SOURCE". */
  char *source;
};


/* Parameter structure used with the KS_SEARCH command.  */
struct ks_search_parm_s
{
  gpg_error_t lasterr;  /* Last error code.  */
  membuf_t saveddata;   /* Buffer to build complete lines.  */
  char *helpbuf;        /* NULL or malloced buffer.  */
  size_t helpbufsize;   /* Allocated size of HELPBUF.  */
  gpg_error_t (*data_cb)(void*, int, char*);  /* Callback.  */
  void *data_cb_value;  /* First argument for DATA_CB.  */
  struct ks_status_parm_s *stparm; /* Link to the status parameter.  */
};


/* Parameter structure used with the KS_GET command.  */
struct ks_get_parm_s
{
  estream_t memfp;
};


/* Parameter structure used with the KS_PUT command.  */
struct ks_put_parm_s
{
  assuan_context_t ctx;
  kbnode_t keyblock;  /* The optional keyblock.  */
  const void *data;   /* The key in OpenPGP binary format.  */
  size_t datalen;     /* The length of DATA.  */
};


/* Parameter structure used with the DNS_CERT command.  */
struct dns_cert_parm_s
{
  estream_t memfp;
  unsigned char *fpr;
  size_t fprlen;
  char *url;
};


/* Data used to associate an session with dirmngr contexts.  We can't
   use a simple one to one mapping because we sometimes need two
   connections to the dirmngr; for example while doing a listing and
   being in a data callback we may want to retrieve a key.  The local
   dirmngr data takes care of this.  At the end of the session the
   function dirmngr_deinit_session_data is called by gpg.c to cleanup
   these resources.  Note that gpg.h defines a typedef dirmngr_local_t
   for this structure. */
struct dirmngr_local_s
{
  /* Link to other contexts which are used simultaneously.  */
  struct dirmngr_local_s *next;

  /* The active Assuan context. */
  assuan_context_t ctx;

  /* Flag set when the keyserver names have been send.  */
  int set_keyservers_done;

  /* Flag set to true while an operation is running on CTX.  */
  int is_active;
};



/* Deinitialize all session data of dirmngr pertaining to CTRL.  */
void
gpg_dirmngr_deinit_session_data (ctrl_t ctrl)
{
  dirmngr_local_t dml;

  while ((dml = ctrl->dirmngr_local))
    {
      ctrl->dirmngr_local = dml->next;
      if (dml->is_active)
        log_error ("oops: trying to cleanup an active dirmngr context\n");
      else
        assuan_release (dml->ctx);
      xfree (dml);
    }
}


/* Print a warning if the server's version number is less than our
   version number.  Returns an error code on a connection problem.  */
static gpg_error_t
warn_version_mismatch (assuan_context_t ctx, const char *servername)
{
  return warn_server_version_mismatch (ctx, servername, 0,
                                       write_status_strings2, NULL,
                                       !opt.quiet);
}


/* Try to connect to the Dirmngr via a socket or spawn it if possible.
   Handle the server's initial greeting and set global options.  */
static gpg_error_t
create_context (ctrl_t ctrl, assuan_context_t *r_ctx)
{
  gpg_error_t err;
  assuan_context_t ctx;

  *r_ctx = NULL;

  if (opt.disable_dirmngr)
    return gpg_error (GPG_ERR_NO_DIRMNGR);

  err = start_new_dirmngr (&ctx,
                           GPG_ERR_SOURCE_DEFAULT,
                           opt.dirmngr_program,
                           opt.autostart, opt.verbose, DBG_IPC,
                           NULL /*gpg_status2*/, ctrl);
  if (!opt.autostart && gpg_err_code (err) == GPG_ERR_NO_DIRMNGR)
    {
      static int shown;

      if (!shown)
        {
          shown = 1;
          log_info (_("no dirmngr running in this session\n"));
        }
    }
  else if (!err && !(err = warn_version_mismatch (ctx, DIRMNGR_NAME)))
    {
      char *line;

      /* Tell the dirmngr that we want to collect audit event. */
      /* err = assuan_transact (agent_ctx, "OPTION audit-events=1", */
      /*                        NULL, NULL, NULL, NULL, NULL, NULL); */
      if (opt.keyserver_options.http_proxy)
        {
          line = xtryasprintf ("OPTION http-proxy=%s",
                               opt.keyserver_options.http_proxy);
          if (!line)
            err = gpg_error_from_syserror ();
          else
            {
              err = assuan_transact (ctx, line, NULL, NULL, NULL,
                                     NULL, NULL, NULL);
              xfree (line);
            }
        }

      if (err)
        ;
      else if ((opt.keyserver_options.options & KEYSERVER_HONOR_KEYSERVER_URL))
        {
          /* Tell the dirmngr that this possibly privacy invading
             option is in use.  If Dirmngr is running in Tor mode, it
             will return an error.  */
          err = assuan_transact (ctx, "OPTION honor-keyserver-url-used",
                                 NULL, NULL, NULL, NULL, NULL, NULL);
          if (gpg_err_code (err) == GPG_ERR_FORBIDDEN)
            log_error (_("keyserver option \"honor-keyserver-url\""
                         " may not be used in Tor mode\n"));
          else if (gpg_err_code (err) == GPG_ERR_UNKNOWN_OPTION)
            err = 0; /* Old dirmngr versions do not support this option.  */
        }
    }

  if (err)
    assuan_release (ctx);
  else
    {
      /* audit_log_ok (ctrl->audit, AUDIT_DIRMNGR_READY, err); */
      *r_ctx = ctx;
    }

  return err;
}


/* Get a context for accessing dirmngr.  If no context is available a
   new one is created and - if required - dirmngr started.  On success
   an assuan context is stored at R_CTX.  This context may only be
   released by means of close_context.  Note that NULL is stored at
   R_CTX on error.  */
static gpg_error_t
open_context (ctrl_t ctrl, assuan_context_t *r_ctx)
{
  gpg_error_t err;
  dirmngr_local_t dml;

  *r_ctx = NULL;
  for (;;)
    {
      for (dml = ctrl->dirmngr_local; dml && dml->is_active; dml = dml->next)
        ;
      if (dml)
        {
          /* Found an inactive local session - return that.  */
          log_assert (!dml->is_active);

          /* But first do the per session init if not yet done.  */
          if (!dml->set_keyservers_done)
            {
              keyserver_spec_t ksi;

              /* Set all configured keyservers.  We clear existing
                 keyservers so that any keyserver configured in GPG
                 overrides keyservers possibly still configured in Dirmngr
                 for the session (Note that the keyserver list of a
                 session in Dirmngr survives a RESET. */
              for (ksi = opt.keyserver; ksi; ksi = ksi->next)
                {
                  char *line;

                  line = xtryasprintf
                    ("KEYSERVER%s %s",
                     ksi == opt.keyserver? " --clear":"", ksi->uri);
                  if (!line)
                    err = gpg_error_from_syserror ();
                  else
                    {
                      err = assuan_transact (dml->ctx, line, NULL, NULL, NULL,
                                             NULL, NULL, NULL);
                      xfree (line);
                    }

                  if (err)
                    return err;
                }

              dml->set_keyservers_done = 1;
            }

          dml->is_active = 1;

          *r_ctx = dml->ctx;
          return 0;
        }

      dml = xtrycalloc (1, sizeof *dml);
      if (!dml)
        return gpg_error_from_syserror ();
      err = create_context (ctrl, &dml->ctx);
      if (err)
        {
          xfree (dml);
          return err;
        }

      /* To be on the nPth thread safe site we need to add it to a
         list; this is far easier than to have a lock for this
         function.  It should not happen anyway but the code is free
         because we need it for the is_active check above.  */
      dml->next = ctrl->dirmngr_local;
      ctrl->dirmngr_local = dml;
    }
}


/* Close the assuan context CTX or return it to a pool of unused
   contexts.  If CTX is NULL, the function does nothing.  */
static void
close_context (ctrl_t ctrl, assuan_context_t ctx)
{
  dirmngr_local_t dml;

  if (!ctx)
    return;

  for (dml = ctrl->dirmngr_local; dml; dml = dml->next)
    {
      if (dml->ctx == ctx)
        {
          if (!dml->is_active)
            log_fatal ("closing inactive dirmngr context %p\n", ctx);
          dml->is_active = 0;
          return;
        }
    }
  log_fatal ("closing unknown dirmngr ctx %p\n", ctx);
}


/* Clear the set_keyservers_done flag on context CTX.  */
static void
clear_context_flags (ctrl_t ctrl, assuan_context_t ctx)
{
  dirmngr_local_t dml;

  if (!ctx)
    return;

  for (dml = ctrl->dirmngr_local; dml; dml = dml->next)
    {
      if (dml->ctx == ctx)
        {
          if (!dml->is_active)
            log_fatal ("clear_context_flags on inactive dirmngr ctx %p\n", ctx);
          dml->set_keyservers_done = 0;
          return;
        }
    }
  log_fatal ("clear_context_flags on unknown dirmngr ctx %p\n", ctx);
}



/* Status callback for ks_list, ks_get, ks_search, and wkd_get  */
static gpg_error_t
ks_status_cb (void *opaque, const char *line)
{
  struct ks_status_parm_s *parm = opaque;
  gpg_error_t err = 0;
  const char *s, *s2;
  const char *warn = NULL;
  int is_note = 0;
  char *p;

  if ((s = has_leading_keyword (line, parm->keyword? parm->keyword : "SOURCE")))
    {
      /* Note that the arg for "S SOURCE" is the URL of a keyserver.  */
      if (!parm->source)
        {
          parm->source = xtrystrdup (s);
          if (!parm->source)
            err = gpg_error_from_syserror ();
          else
            {
              p = strchr (parm->source, ':');
              if (p && p[1] == '/' && p[2] == '/')
                {
                  /* This is a real URL like "ldap://foo:389/bla,bla"
                   * Strip off the local part.  */
                  if ((p = strchr (p+3, '/')))
                    *p = 0;
                }
              else
                {
                  /* This is an LDAP config entry like
                   * "foo:389:user:pass:base:flags"
                   * we strip off everything beyound the port.  */
                  if ((p = strchr (p+1, ':')))
                    {
                      if (p[-1] == ':')
                        p[-1] = 0;  /* No port given.  */
                      else
                        *p = 0;
                    }
                }
            }
        }
    }
  else if ((s = has_leading_keyword (line, "WARNING"))
           || (is_note = !!(s = has_leading_keyword (line, "NOTE"))))
    {
      if ((s2 = has_leading_keyword (s, "wkd_cached_result")))
        {
          if (opt.verbose)
            warn = _("WKD uses a cached result");
        }
      else if ((s2 = has_leading_keyword (s, "tor_not_running")))
        warn = _("Tor is not running");
      else if ((s2 = has_leading_keyword (s, "tor_config_problem")))
        warn = _("Tor is not properly configured");
      else if ((s2 = has_leading_keyword (s, "dns_config_problem")))
        warn = _("DNS is not properly configured");
      else if ((s2 = has_leading_keyword (s, "http_redirect")))
        warn = _("unacceptable HTTP redirect from server");
      else if ((s2 = has_leading_keyword (s, "http_redirect_cleanup")))
        warn = _("unacceptable HTTP redirect from server was cleaned up");
      else if ((s2 = has_leading_keyword (s, "tls_cert_error")))
        warn = _("server uses an invalid certificate");
      else
        warn = NULL;

      if (warn)
        {
          if (is_note)
            log_info (_("Note: %s\n"), warn);
          else
            log_info (_("WARNING: %s\n"), warn);
          if (s2)
            {
              while (*s2 && !spacep (s2))
                s2++;
              while (*s2 && spacep (s2))
                s2++;
              if (*s2)
                print_further_info ("%s", s2);
            }
        }
    }

  return err;
}



/* Run the "KEYSERVER" command to return the name of the used
   keyserver at R_KEYSERVER.  */
gpg_error_t
gpg_dirmngr_ks_list (ctrl_t ctrl, char **r_keyserver)
{
  gpg_error_t err;
  assuan_context_t ctx;
  struct ks_status_parm_s stparm;

  memset (&stparm, 0, sizeof stparm);
  stparm.keyword = "KEYSERVER";
  if (r_keyserver)
    *r_keyserver = NULL;

  err = open_context (ctrl, &ctx);
  if (err)
    return err;

  err = assuan_transact (ctx, "KEYSERVER", NULL, NULL,
                         NULL, NULL, ks_status_cb, &stparm);
  if (err)
    goto leave;
  if (!stparm.source)
    {
      err = gpg_error (GPG_ERR_NO_KEYSERVER);
      goto leave;
    }

  if (r_keyserver)
    *r_keyserver = stparm.source;
  else
    xfree (stparm.source);
  stparm.source = NULL;

 leave:
  xfree (stparm.source);
  close_context (ctrl, ctx);
  return err;
}



/* Data callback for the KS_SEARCH command. */
static gpg_error_t
ks_search_data_cb (void *opaque, const void *data, size_t datalen)
{
  gpg_error_t err = 0;
  struct ks_search_parm_s *parm = opaque;
  const char *line, *s;
  size_t rawlen, linelen;
  char fixedbuf[256];

  if (parm->lasterr)
    return 0;

  if (parm->stparm->source)
    {
      err = parm->data_cb (parm->data_cb_value, 1, parm->stparm->source);
      if (err)
        {
          parm->lasterr = err;
          return err;
        }
      /* Clear it so that we won't get back here unless the server
         accidentally sends a second source status line.  Note that
         will not see all accidentally sent source lines because it
         depends on whether data lines have been send in between.  */
      xfree (parm->stparm->source);
      parm->stparm->source = NULL;
    }

  if (!data)
    return 0;  /* Ignore END commands.  */

  put_membuf (&parm->saveddata, data, datalen);

 again:
  line = peek_membuf (&parm->saveddata, &rawlen);
  if (!line)
    {
      parm->lasterr = gpg_error_from_syserror ();
      return parm->lasterr; /* Tell the server about our problem.  */
    }
  if ((s = memchr (line, '\n', rawlen)))
    {
      linelen = s - line;  /* That is the length excluding the LF.  */
      if (linelen + 1 < sizeof fixedbuf)
        {
          /* We can use the static buffer.  */
          memcpy (fixedbuf, line, linelen);
          fixedbuf[linelen] = 0;
          if (linelen && fixedbuf[linelen-1] == '\r')
            fixedbuf[linelen-1] = 0;
          err = parm->data_cb (parm->data_cb_value, 0, fixedbuf);
        }
      else
        {
          if (linelen + 1 >= parm->helpbufsize)
            {
              xfree (parm->helpbuf);
              parm->helpbufsize = linelen + 1 + 1024;
              parm->helpbuf = xtrymalloc (parm->helpbufsize);
              if (!parm->helpbuf)
                {
                  parm->lasterr = gpg_error_from_syserror ();
                  return parm->lasterr;
                }
            }
          memcpy (parm->helpbuf, line, linelen);
          parm->helpbuf[linelen] = 0;
          if (linelen && parm->helpbuf[linelen-1] == '\r')
            parm->helpbuf[linelen-1] = 0;
          err = parm->data_cb (parm->data_cb_value, 0, parm->helpbuf);
        }
      if (err)
        parm->lasterr = err;
      else
        {
          clear_membuf (&parm->saveddata, linelen+1);
          goto again;  /* There might be another complete line.  */
        }
    }

  return err;
}


/* Run the KS_SEARCH command using the search string SEARCHSTR.  All
   data lines are passed to the CB function.  That function is called
   with CB_VALUE as its first argument, a 0 as second argument, and
   the decoded data line as third argument.  The callback function may
   modify the data line and it is guaranteed that this data line is a
   complete line with a terminating 0 character but without the
   linefeed.  NULL is passed to the callback to indicate EOF.  */
gpg_error_t
gpg_dirmngr_ks_search (ctrl_t ctrl, const char *searchstr,
                       gpg_error_t (*cb)(void*, int, char *), void *cb_value)
{
  gpg_error_t err;
  assuan_context_t ctx;
  struct ks_status_parm_s stparm;
  struct ks_search_parm_s parm;
  char line[ASSUAN_LINELENGTH];

  err = open_context (ctrl, &ctx);
  if (err)
    return err;

  {
    char *escsearchstr = percent_plus_escape (searchstr);
    if (!escsearchstr)
      {
        err = gpg_error_from_syserror ();
        close_context (ctrl, ctx);
        return err;
      }
    snprintf (line, sizeof line, "KS_SEARCH -- %s", escsearchstr);
    xfree (escsearchstr);
  }

  memset (&stparm, 0, sizeof stparm);
  memset (&parm, 0, sizeof parm);
  init_membuf (&parm.saveddata, 1024);
  parm.data_cb = cb;
  parm.data_cb_value = cb_value;
  parm.stparm = &stparm;

  err = assuan_transact (ctx, line, ks_search_data_cb, &parm,
                        NULL, NULL, ks_status_cb, &stparm);
  if (!err)
    err = cb (cb_value, 0, NULL);  /* Send EOF.  */
  else if (parm.stparm->source)
    {
      /* Error but we received a SOURCE status.  Tell via callback but
       * ignore errors.  */
      parm.data_cb (parm.data_cb_value, 1, parm.stparm->source);
    }

  xfree (get_membuf (&parm.saveddata, NULL));
  xfree (parm.helpbuf);
  xfree (stparm.source);

  close_context (ctrl, ctx);
  return err;
}



/* Data callback for the KS_GET and KS_FETCH commands. */
static gpg_error_t
ks_get_data_cb (void *opaque, const void *data, size_t datalen)
{
  gpg_error_t err = 0;
  struct ks_get_parm_s *parm = opaque;
  size_t nwritten;

  if (!data)
    return 0;  /* Ignore END commands.  */

  if (es_write (parm->memfp, data, datalen, &nwritten))
    err = gpg_error_from_syserror ();

  return err;
}


/* Run the KS_GET command using the patterns in the array PATTERN.  On
   success an estream object is returned to retrieve the keys.  On
   error an error code is returned and NULL stored at R_FP.

   The pattern may only use search specification which a keyserver can
   use to retrieve keys.  Because we know the format of the pattern we
   don't need to escape the patterns before sending them to the
   server.

   Bit values for FLAGS are:
   - KEYSERVER_IMPORT_FLAG_QUICK :: dirmngr shall use a shorter timeout.
   - KEYSERVER_IMPORT_FLAG_LDAP  :: dirmngr shall only use LDAP or NTDS.

   If R_SOURCE is not NULL the source of the data is stored as a
   malloced string there.  If a source is not known NULL is stored.
   Note that this may even be returned after an error.

   If there are too many patterns the function returns an error.  That
   could be fixed by issuing several search commands or by
   implementing a different interface.  However with long keyids we
   are able to ask for (1000-10-1)/(2+8+1) = 90 keys at once.  */
gpg_error_t
gpg_dirmngr_ks_get (ctrl_t ctrl, char **pattern,
                    keyserver_spec_t override_keyserver,
                    unsigned int flags,
                    estream_t *r_fp, char **r_source)
{
  gpg_error_t err;
  assuan_context_t ctx;
  struct ks_status_parm_s stparm;
  struct ks_get_parm_s parm;
  char *line = NULL;
  size_t linelen;
  membuf_t mb;
  int idx;

  memset (&stparm, 0, sizeof stparm);
  memset (&parm, 0, sizeof parm);

  *r_fp = NULL;
  if (r_source)
    *r_source = NULL;

  err = open_context (ctrl, &ctx);
  if (err)
    return err;

  /* If we have an override keyserver we first indicate that the next
     user of the context needs to again setup the global keyservers and
     then we send the override keyserver.  */
  if (override_keyserver)
    {
      clear_context_flags (ctrl, ctx);
      line = xtryasprintf ("KEYSERVER --clear %s", override_keyserver->uri);
      if (!line)
        {
          err = gpg_error_from_syserror ();
          goto leave;
        }
      err = assuan_transact (ctx, line, NULL, NULL, NULL,
                             NULL, NULL, NULL);
      if (err)
        goto leave;

      xfree (line);
      line = NULL;
    }

  /* Lump all patterns into one string.  */
  init_membuf (&mb, 1024);
  put_membuf_str (&mb, "KS_GET");
  if ((flags & KEYSERVER_IMPORT_FLAG_QUICK))
    put_membuf_str (&mb, " --quick");
  if ((flags & KEYSERVER_IMPORT_FLAG_LDAP))
    put_membuf_str (&mb, " --ldap");
  put_membuf_str (&mb, " --");
  for (idx=0; pattern[idx]; idx++)
    {
      put_membuf (&mb, " ", 1); /* Append Delimiter.  */
      put_membuf_str (&mb, pattern[idx]);
    }
  put_membuf (&mb, "", 1); /* Append Nul.  */
  line = get_membuf (&mb, &linelen);
  if (!line)
    {
      err = gpg_error_from_syserror ();
      goto leave;
    }
  if (linelen + 2 >= ASSUAN_LINELENGTH)
    {
      err = gpg_error (GPG_ERR_TOO_MANY);
      goto leave;
    }

  parm.memfp = es_fopenmem (0, "rwb");
  if (!parm.memfp)
    {
      err = gpg_error_from_syserror ();
      goto leave;
    }
  err = assuan_transact (ctx, line, ks_get_data_cb, &parm,
                         NULL, NULL, ks_status_cb, &stparm);
  if (err)
    goto leave;

  es_rewind (parm.memfp);
  *r_fp = parm.memfp;
  parm.memfp = NULL;


 leave:
  if (r_source && stparm.source)
    {
      *r_source = stparm.source;
      stparm.source = NULL;
    }
  es_fclose (parm.memfp);
  xfree (stparm.source);
  xfree (line);
  close_context (ctrl, ctx);
  return err;
}


/* Run the KS_FETCH and pass URL as argument.  On success an estream
   object is returned to retrieve the keys.  On error an error code is
   returned and NULL stored at R_FP.

   The url is expected to point to a small set of keys; in many cases
   only to one key.  However, schemes like finger may return several
   keys.  Note that the configured keyservers are ignored by the
   KS_FETCH command.  */
gpg_error_t
gpg_dirmngr_ks_fetch (ctrl_t ctrl, const char *url, estream_t *r_fp)
{
  gpg_error_t err;
  assuan_context_t ctx;
  struct ks_get_parm_s parm;
  char *line = NULL;

  memset (&parm, 0, sizeof parm);

  *r_fp = NULL;

  err = open_context (ctrl, &ctx);
  if (err)
    return err;

  line = strconcat ("KS_FETCH -- ", url, NULL);
  if (!line)
    {
      err = gpg_error_from_syserror ();
      goto leave;
    }
  if (strlen (line) + 2 >= ASSUAN_LINELENGTH)
    {
      err = gpg_error (GPG_ERR_TOO_LARGE);
      goto leave;
    }

  parm.memfp = es_fopenmem (0, "rwb");
  if (!parm.memfp)
    {
      err = gpg_error_from_syserror ();
      goto leave;
    }
  err = assuan_transact (ctx, line, ks_get_data_cb, &parm,
                         NULL, NULL, NULL, NULL);
  if (err)
    goto leave;

  es_rewind (parm.memfp);
  *r_fp = parm.memfp;
  parm.memfp = NULL;

 leave:
  es_fclose (parm.memfp);
  xfree (line);
  close_context (ctrl, ctx);
  return err;
}



static void
record_output (estream_t output,
	       pkttype_t type,
	       const char *validity,
	       int pub_key_length,  /* The public key length or -1.  */
	       int pub_key_algo,    /* The public key algo or -1.    */
	       const u32 *keyid,    /* 2 ulongs or NULL.             */
	       u32 creation_date,   /* The creation date or 0.       */
	       u32 expiration_date, /* The expiration date or 0.     */
	       const char *userid)  /* The userid or NULL.           */
{
  const char *type_str = NULL;

  switch (type)
    {
    case PKT_PUBLIC_KEY:
      type_str = "pub";
      break;
    case PKT_PUBLIC_SUBKEY:
      type_str = "sub";
      break;
    case PKT_USER_ID:
      type_str = "uid";
      break;
    case PKT_SIGNATURE:
      type_str = "sig";
      break;
    default:
      log_assert (! "Unhandled type.");
    }
  es_fprintf (output, "%s:%s:",
              type_str,
	      validity ? validity : "");

  if (pub_key_length > 0)
    es_fprintf (output, "%d", pub_key_length);
  es_fputc (':', output);

  if (pub_key_algo != -1)
    es_fprintf (output, "%d", pub_key_algo);
  es_fputc (':', output);

  if (keyid)
    es_fprintf (output, "%08lX%08lX", (ulong) keyid[0], (ulong) keyid[1]);

  es_fprintf (output, ":%s:", colon_strtime (creation_date));
  es_fprintf (output, "%s:::", colon_strtime (expiration_date));

  if (userid)
    es_write_sanitized (output, userid, strlen (userid), ":", NULL);
  else
    es_fputc (':', output);
  es_fputs (":::::::::\n", output);

}


/* Handle the KS_PUT inquiries. */
static gpg_error_t
ks_put_inq_cb (void *opaque, const char *line)
{
  struct ks_put_parm_s *parm = opaque;
  gpg_error_t err = 0;

  if (has_leading_keyword (line, "KEYBLOCK"))
    {
      if (parm->data)
        err = assuan_send_data (parm->ctx, parm->data, parm->datalen);
    }
  else if (has_leading_keyword (line, "KEYBLOCK_INFO"))
    {
      kbnode_t node;
      estream_t fp;
      char hexfpr[2*MAX_FINGERPRINT_LEN+1];

      /* Parse the keyblock and send info lines back to the server.  */
      fp = es_fopenmem (0, "rw,samethread");
      if (!fp)
        err = gpg_error_from_syserror ();

      /* Note: the output format for the INFO block follows the colon
	 format as described in doc/DETAILS.  We don't actually reuse
	 the functionality from g10/keylist.c to produce the output,
	 because we don't need all of it and some of it is quite
	 expensive to generate.

	 The fields are (the starred fields are the ones we need):

	   * Field 1 - Type of record
           * Field 2 - Validity
           * Field 3 - Key length
           * Field 4 - Public key algorithm
           * Field 5 - KeyID
           * Field 6 - Creation date
           * Field 7 - Expiration date
             Field 8 - Certificate S/N, UID hash, trust signature info
             Field 9 -  Ownertrust
	   * Field 10 - User-ID
             Field 11 - Signature class
             Field 12 - Key capabilities
             Field 13 - Issuer certificate fingerprint or other info
             Field 14 - Flag field
             Field 15 - S/N of a token
             Field 16 - Hash algorithm
             Field 17 - Curve name
       */
      for (node = parm->keyblock; !err && node; node=node->next)
        {
          switch (node->pkt->pkttype)
            {
            case PKT_PUBLIC_KEY:
            case PKT_PUBLIC_SUBKEY:
              {
                PKT_public_key *pk = node->pkt->pkt.public_key;

		char validity[3];
		int i;

		i = 0;
		if (pk->flags.revoked)
		  validity[i ++] = 'r';
		if (pk->has_expired)
		  validity[i ++] = 'e';
		validity[i] = '\0';

                keyid_from_pk (pk, NULL);

		record_output (fp, node->pkt->pkttype, validity,
			       nbits_from_pk (pk), pk->pubkey_algo,
			       pk->keyid, pk->timestamp, pk->expiredate,
			       NULL);
                es_fprintf (fp, "fpr:::::::::%s:\n",
                            hexfingerprint (pk, hexfpr, sizeof hexfpr));
              }
              break;

            case PKT_USER_ID:
              {
                PKT_user_id *uid = node->pkt->pkt.user_id;

                if (!uid->attrib_data)
                  {
		    char validity[3];
		    int i;

		    i = 0;
		    if (uid->flags.revoked)
		      validity[i ++] = 'r';
		    if (uid->flags.expired)
		      validity[i ++] = 'e';
		    validity[i] = '\0';

		    record_output (fp, node->pkt->pkttype, validity,
				   -1, -1, NULL,
				   uid->created, uid->expiredate,
				   uid->name);
                  }
              }
              break;

            default:
              continue;
            }
          /* Given that the last operation was an es_fprintf we should
             get the correct ERRNO if ferror indicates an error.  */
          if (es_ferror (fp))
            err = gpg_error_from_syserror ();
        }

      /* Without an error and if we have an keyblock at all, send the
         data back.  */
      if (!err && parm->keyblock)
        {
          int rc;
          char buffer[512];
          size_t nread;

          es_rewind (fp);
          while (!(rc=es_read (fp, buffer, sizeof buffer, &nread)) && nread)
            {
              err = assuan_send_data (parm->ctx, buffer, nread);
              if (err)
                break;
            }
          if (!err && rc)
            err = gpg_error_from_syserror ();
        }
      es_fclose (fp);
    }
  else
    return gpg_error (GPG_ERR_ASS_UNKNOWN_INQUIRE);

  return err;
}


/* Send a key to the configured server.  {DATA,DATLEN} contains the
   key in OpenPGP binary transport format.  If KEYBLOCK is not NULL it
   has the internal representation of that key; this is for example
   used to convey meta data to LDAP keyservers.  */
gpg_error_t
gpg_dirmngr_ks_put (ctrl_t ctrl, void *data, size_t datalen, kbnode_t keyblock)
{
  gpg_error_t err;
  assuan_context_t ctx;
  struct ks_put_parm_s parm;

  memset (&parm, 0, sizeof parm);

  /* We are going to parse the keyblock, thus we better make sure the
     all information is readily available.  */
  if (keyblock)
    merge_keys_and_selfsig (ctrl, keyblock);

  err = open_context (ctrl, &ctx);
  if (err)
    return err;

  parm.ctx = ctx;
  parm.keyblock = keyblock;
  parm.data = data;
  parm.datalen = datalen;

  err = assuan_transact (ctx, "KS_PUT", NULL, NULL,
                         ks_put_inq_cb, &parm, NULL, NULL);

  close_context (ctrl, ctx);
  return err;
}



/* Data callback for the DNS_CERT and WKD_GET commands. */
static gpg_error_t
dns_cert_data_cb (void *opaque, const void *data, size_t datalen)
{
  struct dns_cert_parm_s *parm = opaque;
  gpg_error_t err = 0;
  size_t nwritten;

  if (!data)
    return 0;  /* Ignore END commands.  */
  if (!parm->memfp)
    return 0;  /* Data is not required.  */

  if (es_write (parm->memfp, data, datalen, &nwritten))
    err = gpg_error_from_syserror ();

  return err;
}


/* Status callback for the DNS_CERT command.  */
static gpg_error_t
dns_cert_status_cb (void *opaque, const char *line)
{
  struct dns_cert_parm_s *parm = opaque;
  gpg_error_t err = 0;
  const char *s;
  size_t nbytes;

  if ((s = has_leading_keyword (line, "FPR")))
    {
      char *buf;

      if (!(buf = xtrystrdup (s)))
        err = gpg_error_from_syserror ();
      else if (parm->fpr)
        err = gpg_error (GPG_ERR_DUP_KEY);
      else if (!hex2str (buf, buf, strlen (buf)+1, &nbytes))
        err = gpg_error_from_syserror ();
      else if (nbytes < 20)
        err = gpg_error (GPG_ERR_TOO_SHORT);
      else
        {
          parm->fpr = xtrymalloc (nbytes);
          if (!parm->fpr)
            err = gpg_error_from_syserror ();
          else
            memcpy (parm->fpr, buf, (parm->fprlen = nbytes));
        }
      xfree (buf);
    }
  else if ((s = has_leading_keyword (line, "URL")) && *s)
    {
      if (parm->url)
        err = gpg_error (GPG_ERR_DUP_KEY);
      else if (!(parm->url = xtrystrdup (s)))
        err = gpg_error_from_syserror ();
    }

  return err;
}

/* Ask the dirmngr for a DNS CERT record.  Depending on the found
   subtypes different return values are set:

   - For a PGP subtype a new estream with that key will be returned at
     R_KEY and the other return parameters are set to NULL/0.

   - For an IPGP subtype the fingerprint is stored as a malloced block
     at (R_FPR,R_FPRLEN).  If an URL is available it is stored as a
     malloced string at R_URL; NULL is stored if there is no URL.

   If CERTTYPE is DNS_CERTTYPE_ANY this function returns the first
   CERT record found with a supported type; it is expected that only
   one CERT record is used.  If CERTTYPE is one of the supported
   certtypes, only records with this certtype are considered and the
   first one found is returned.  All R_* args are optional.

   If CERTTYPE is NULL the DANE method is used to fetch the key.
 */
gpg_error_t
gpg_dirmngr_dns_cert (ctrl_t ctrl, const char *name, const char *certtype,
                      estream_t *r_key,
                      unsigned char **r_fpr, size_t *r_fprlen,
                      char **r_url)
{
  gpg_error_t err;
  assuan_context_t ctx;
  struct dns_cert_parm_s parm;
  char *line = NULL;

  memset (&parm, 0, sizeof parm);
  if (r_key)
    *r_key = NULL;
  if (r_fpr)
    *r_fpr = NULL;
  if (r_fprlen)
    *r_fprlen = 0;
  if (r_url)
    *r_url = NULL;

  err = open_context (ctrl, &ctx);
  if (err)
    return err;

  line = es_bsprintf ("DNS_CERT %s %s", certtype? certtype : "--dane", name);
  if (!line)
    {
      err = gpg_error_from_syserror ();
      goto leave;
    }
  if (strlen (line) + 2 >= ASSUAN_LINELENGTH)
    {
      err = gpg_error (GPG_ERR_TOO_LARGE);
      goto leave;
    }

  parm.memfp = es_fopenmem (0, "rwb");
  if (!parm.memfp)
    {
      err = gpg_error_from_syserror ();
      goto leave;
    }
  err = assuan_transact (ctx, line, dns_cert_data_cb, &parm,
                         NULL, NULL, dns_cert_status_cb, &parm);
  if (err)
    goto leave;

  if (r_key)
    {
      es_rewind (parm.memfp);
      *r_key = parm.memfp;
      parm.memfp = NULL;
    }

  if (r_fpr && parm.fpr)
    {
      *r_fpr = parm.fpr;
      parm.fpr = NULL;
    }
  if (r_fprlen)
    *r_fprlen = parm.fprlen;

  if (r_url && parm.url)
    {
      *r_url = parm.url;
      parm.url = NULL;
    }

 leave:
  xfree (parm.fpr);
  xfree (parm.url);
  es_fclose (parm.memfp);
  xfree (line);
  close_context (ctrl, ctx);
  return err;
}



/* Ask the dirmngr to retrieve a key via the Web Key Directory
 * protocol.  If QUICK is set the dirmngr is advised to use a shorter
 * timeout.  On success a new estream with the key stored at R_KEY and the
 * url of the lookup (if any) stored at R_URL.  Note that
 */
gpg_error_t
gpg_dirmngr_wkd_get (ctrl_t ctrl, const char *name, int quick,
                     estream_t *r_key, char **r_url)
{
  gpg_error_t err;
  assuan_context_t ctx;
  struct ks_status_parm_s stparm = { NULL };
  struct dns_cert_parm_s parm = { NULL };
  char *line = NULL;

  if (r_key)
    *r_key = NULL;

  if (r_url)
    *r_url = NULL;

  err = open_context (ctrl, &ctx);
  if (err)
    return err;

  line = es_bsprintf ("WKD_GET%s -- %s", quick?" --quick":"", name);
  if (!line)
    {
      err = gpg_error_from_syserror ();
      goto leave;
    }
  if (strlen (line) + 2 >= ASSUAN_LINELENGTH)
    {
      err = gpg_error (GPG_ERR_TOO_LARGE);
      goto leave;
    }

  parm.memfp = es_fopenmem (MAX_WKD_RESULT_LENGTH, "rwb");
  if (!parm.memfp)
    {
      err = gpg_error_from_syserror ();
      goto leave;
    }
  err = assuan_transact (ctx, line, dns_cert_data_cb, &parm,
                         NULL, NULL, ks_status_cb, &stparm);
  if (gpg_err_code (err) == GPG_ERR_ENOSPC)
    err = gpg_error (GPG_ERR_TOO_LARGE);
  if (err)
    goto leave;

  if (r_key)
    {
      es_rewind (parm.memfp);
      *r_key = parm.memfp;
      parm.memfp = NULL;
    }

  if (r_url)
    {
      *r_url = stparm.source;
      stparm.source = NULL;
    }

 leave:
  xfree (stparm.source);
  xfree (parm.fpr);
  xfree (parm.url);
  es_fclose (parm.memfp);
  xfree (line);
  close_context (ctrl, ctx);
  return err;
}
