/* get-passphrase.c - Ask for a passphrase via the agent
 * Copyright (C) 2009 Free Software Foundation, Inc.
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
 * along with this program; if not, see <http://www.gnu.org/licenses/>.
 */

#include <config.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <assuan.h>

#include "util.h"
#include "i18n.h"
#include "asshelp.h"
#include "membuf.h"
#include "sysutils.h"
#include "get-passphrase.h"

/* The context used by this process to ask for the passphrase.  */
static assuan_context_t agent_ctx;
static struct
{
  gpg_err_source_t errsource;
  int verbosity;
  const char *homedir;
  const char *agent_program;
  const char *lc_ctype;
  const char *lc_messages;
  session_env_t session_env;
  const char *pinentry_user_data;
} agentargs;


/* Set local variable to be used for a possible agent startup.  Note
   that the strings are just pointers and should not anymore be
   modified by the caller. */
void
gnupg_prepare_get_passphrase (gpg_err_source_t errsource,
                              int verbosity,
                              const char *homedir,
                              const char *agent_program,
                              const char *opt_lc_ctype,
                              const char *opt_lc_messages,
                              session_env_t session_env)
{
  agentargs.errsource          = errsource;
  agentargs.verbosity          = verbosity;
  agentargs.homedir            = homedir;
  agentargs.agent_program      = agent_program;
  agentargs.lc_ctype           = opt_lc_ctype;
  agentargs.lc_messages        = opt_lc_messages;
  agentargs.session_env        = session_env;
}


/* Try to connect to the agent via socket or fork it off and work by
   pipes.  Handle the server's initial greeting.  */
static gpg_error_t
start_agent (void)
{
  gpg_error_t err;

  /* Fixme: This code is not thread safe, thus we don't build it with
     pth.  We will need a context for each thread or serialize the
     access to the agent.  */
  if (agent_ctx)
    return 0; 

  err = start_new_gpg_agent (&agent_ctx,
                             agentargs.errsource,
                             agentargs.homedir,
                             agentargs.agent_program,
                             agentargs.lc_ctype,
                             agentargs.lc_messages,
                             agentargs.session_env,
                             agentargs.verbosity, 0, NULL, NULL);
  if (!err)
    {
      /* Tell the agent that we support Pinentry notifications.  No
         error checking so that it will work with older agents.  */
      assuan_transact (agent_ctx, "OPTION allow-pinentry-notify",
                       NULL, NULL, NULL, NULL, NULL, NULL);
    }

  return err;
}


/* This is the default inquiry callback.  It merely handles the
   Pinentry notification.  */
static gpg_error_t
default_inq_cb (void *opaque, const char *line)
{
  (void)opaque;

  if (!strncmp (line, "PINENTRY_LAUNCHED", 17) && (line[17]==' '||!line[17]))
    {
      gnupg_allow_set_foregound_window ((pid_t)strtoul (line+17, NULL, 10));
      /* We do not return errors to avoid breaking other code.  */
    }
  else
    log_debug ("ignoring gpg-agent inquiry `%s'\n", line);

  return 0;
}


static gpg_error_t
membuf_data_cb (void *opaque, const void *buffer, size_t length)
{
  membuf_t *data = opaque;

  if (buffer)
    put_membuf (data, buffer, length);
  return 0;
}
  

/* Ask for a passphrase via gpg-agent.  On success the caller needs to
   free the string stored at R_PASSPHRASE.  On error NULL will be
   stored at R_PASSPHRASE and an appropriate gpg error code is
   returned.  With REPEAT set to 1, gpg-agent will ask the user to
   repeat the just entered passphrase.  CACHE_ID is a gpg-agent style
   passphrase cache id or NULL.  ERR_MSG is a error message to be
   presented to the user (e.g. "bad passphrase - try again") or NULL.
   PROMPT is the prompt string to label the entry box, it may be NULL
   for a default one.  DESC_MSG is a longer description to be
   displayed above the entry box, if may be NULL for a default one.
   If USE_SECMEM is true, the returned passphrase is retruned in
   secure memory.  The length of all these strings is limited; they
   need to fit in their encoded form into a standard Assuan line (i.e
   less then about 950 characters).  All strings shall be UTF-8.  */
gpg_error_t
gnupg_get_passphrase (const char *cache_id,
                      const char *err_msg,
                      const char *prompt,
                      const char *desc_msg,
                      int repeat,
                      int check_quality,
                      int use_secmem,
                      char **r_passphrase)
{
  gpg_error_t err;
  char line[ASSUAN_LINELENGTH];
  const char *arg1 = NULL;
  char *arg2 = NULL;  
  char *arg3 = NULL; 
  char *arg4 = NULL;
  membuf_t data;

  *r_passphrase = NULL;

  err = start_agent ();
  if (err)
    return err;

  /* Check that the gpg-agent understands the repeat option.  */
  if (assuan_transact (agent_ctx, 
                       "GETINFO cmd_has_option GET_PASSPHRASE repeat",
                       NULL, NULL, NULL, NULL, NULL, NULL))
    return gpg_error (GPG_ERR_NOT_SUPPORTED);

  arg1 = cache_id && *cache_id? cache_id:NULL;
  if (err_msg && *err_msg)
    if (!(arg2 = percent_plus_escape (err_msg)))
      goto no_mem;
  if (prompt && *prompt)
    if (!(arg3 = percent_plus_escape (prompt)))
      goto no_mem;
  if (desc_msg && *desc_msg)
    if (!(arg4 = percent_plus_escape (desc_msg)))
      goto no_mem;

  snprintf (line, DIM(line)-1, 
            "GET_PASSPHRASE --data %s--repeat=%d -- %s %s %s %s", 
            check_quality? "--check ":"",
            repeat, 
            arg1? arg1:"X",
            arg2? arg2:"X",
            arg3? arg3:"X",
            arg4? arg4:"X");
  line[DIM(line)-1] = 0;
  xfree (arg2);
  xfree (arg3);
  xfree (arg4);

  if (use_secmem)
    init_membuf_secure (&data, 64);
  else
    init_membuf (&data, 64);
  err = assuan_transact (agent_ctx, line, 
                         membuf_data_cb, &data,
                         default_inq_cb, NULL, NULL, NULL);
  
  /* Older Pinentries return the old assuan error code for canceled
     which gets translated bt libassuan to GPG_ERR_ASS_CANCELED and
     not to the code for a user cancel.  Fix this here. */
  if (err && gpg_err_source (err)
      && gpg_err_code (err) == GPG_ERR_ASS_CANCELED)
    err = gpg_err_make (gpg_err_source (err), GPG_ERR_CANCELED);

  if (err)
    {
      void *p;
      size_t n;

      p = get_membuf (&data, &n);
      if (p)
        wipememory (p, n);
      xfree (p);
    }
  else 
    {
      put_membuf (&data, "", 1);
      *r_passphrase = get_membuf (&data, NULL);
      if (!*r_passphrase)
        err = gpg_error_from_syserror ();
    }
  return err;
 no_mem:
  err = gpg_error_from_syserror ();
  xfree (arg2);
  xfree (arg3);
  xfree (arg4);
  return err;
}


/* Flush the passphrase cache with Id CACHE_ID.  */
gpg_error_t
gnupg_clear_passphrase (const char *cache_id)
{
  gpg_error_t err;
  char line[ASSUAN_LINELENGTH];

  if (!cache_id || !*cache_id)
    return 0;

  err = start_agent ();
  if (err)
    return err;

  snprintf (line, DIM(line)-1, "CLEAR_PASSPHRASE %s", cache_id);
  line[DIM(line)-1] = 0;
  return assuan_transact (agent_ctx, line, NULL, NULL,
                          default_inq_cb, NULL, NULL, NULL);
}
