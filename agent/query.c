/* query.c - fork of the pinentry to query stuff from the user
 * Copyright (C) 2001, 2002, 2004 Free Software Foundation, Inc.
 *
 * This file is part of GnuPG.
 *
 * GnuPG is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * GnuPG is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA
 */

#include <config.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <assert.h>
#include <unistd.h>
#include <sys/stat.h>
#ifdef USE_GNU_PTH
# include <pth.h>
#endif

#include "agent.h"
#include "i18n.h"
#include <assuan.h>

#ifdef _POSIX_OPEN_MAX
#define MAX_OPEN_FDS _POSIX_OPEN_MAX
#else
#define MAX_OPEN_FDS 20
#endif


/* Because access to the pinentry must be serialized (it is and shall
   be a global mutual dialog) we should better timeout further
   requests after some time.  2 minutes seem to be a reasonable
   time. */
#define LOCK_TIMEOUT  (1*60)


static ASSUAN_CONTEXT entry_ctx = NULL;
#ifdef USE_GNU_PTH
static pth_mutex_t entry_lock;
#endif

/* data to be passed to our callbacks */
struct entry_parm_s {
  int lines;
  size_t size;
  char *buffer;
};




/* This function must be called once to initialize this module.  This
   has to be done before a second thread is spawned.  We can't do the
   static initialization because Pth emulation code might not be able
   to do a static init; in particualr, it is not possible for W32. */
void
initialize_module_query (void)
{
#ifdef USE_GNU_PTH
  static int initialized;

  if (!initialized)
    if (pth_mutex_init (&entry_lock))
      initialized = 1;
#endif /*USE_GNU_PTH*/
}




/* Unlock the pinentry so that another thread can start one and
   disconnect that pinentry - we do this after the unlock so that a
   stalled pinentry does not block other threads.  Fixme: We should
   have a timeout in Assuan for the disconnect operation. */
static int 
unlock_pinentry (int rc)
{
  ASSUAN_CONTEXT ctx = entry_ctx;

#ifdef USE_GNU_PTH
  if (!pth_mutex_release (&entry_lock))
    {
      log_error ("failed to release the entry lock\n");
      if (!rc)
        rc = gpg_error (GPG_ERR_INTERNAL);
    }
#endif
  entry_ctx = NULL;
  assuan_disconnect (ctx);
  return rc;
}


/* To make sure we leave no secrets in our image after forking of the
   pinentry, we use this callback. */
static void
atfork_cb (void *opaque, int where)
{
  if (!where)
    gcry_control (GCRYCTL_TERM_SECMEM);
}


/* Fork off the pin entry if this has not already been done.  Note,
   that this function must always be used to aquire the lock for the
   pinentry - we will serialize _all_ pinentry calls.
 */
static int
start_pinentry (CTRL ctrl)
{
  int rc;
  const char *pgmname;
  ASSUAN_CONTEXT ctx;
  const char *argv[5];
  int no_close_list[3];
  int i;

#ifdef USE_GNU_PTH
 {
   pth_event_t evt;

   evt = pth_event (PTH_EVENT_TIME, pth_timeout (LOCK_TIMEOUT, 0));
   if (!pth_mutex_acquire (&entry_lock, 0, evt))
    {
      if (pth_event_occurred (evt))
        rc = gpg_error (GPG_ERR_TIMEOUT);
      else
        rc = gpg_error (GPG_ERR_INTERNAL);
      pth_event_free (evt, PTH_FREE_THIS);
      log_error (_("failed to acquire the pinentry lock: %s\n"),
                 gpg_strerror (rc));
      return rc;
    }
   pth_event_free (evt, PTH_FREE_THIS);
 }
#endif

  if (entry_ctx)
    return 0; 

  if (opt.verbose)
    log_info ("starting a new PIN Entry\n");
      
  if (fflush (NULL))
    {
      gpg_error_t tmperr = gpg_error (gpg_err_code_from_errno (errno));
      log_error ("error flushing pending output: %s\n", strerror (errno));
      return unlock_pinentry (tmperr);
    }

  if (!opt.pinentry_program || !*opt.pinentry_program)
    opt.pinentry_program = GNUPG_DEFAULT_PINENTRY;
  if ( !(pgmname = strrchr (opt.pinentry_program, '/')))
    pgmname = opt.pinentry_program;
  else
    pgmname++;

  argv[0] = pgmname;
  if (ctrl->display && !opt.keep_display)
    {
      argv[1] = "--display";
      argv[2] = ctrl->display;
      argv[3] = NULL;
    }
  else
    argv[1] = NULL;
  
  i=0;
  if (!opt.running_detached)
    {
      if (log_get_fd () != -1)
        no_close_list[i++] = log_get_fd ();
      no_close_list[i++] = fileno (stderr);
    }
  no_close_list[i] = -1;

  /* Connect to the pinentry and perform initial handshaking */
  rc = assuan_pipe_connect2 (&ctx, opt.pinentry_program, (char**)argv,
                             no_close_list, atfork_cb, NULL);
  if (rc)
    {
      log_error ("can't connect to the PIN entry module: %s\n",
                 assuan_strerror (rc));
      return unlock_pinentry (gpg_error (GPG_ERR_NO_PIN_ENTRY));
    }
  entry_ctx = ctx;

  if (DBG_ASSUAN)
    log_debug ("connection to PIN entry established\n");

  rc = assuan_transact (entry_ctx, 
                        opt.no_grab? "OPTION no-grab":"OPTION grab",
                        NULL, NULL, NULL, NULL, NULL, NULL);
  if (rc)
    return unlock_pinentry (map_assuan_err (rc));
  if (ctrl->ttyname)
    {
      char *optstr;
      if (asprintf (&optstr, "OPTION ttyname=%s", ctrl->ttyname) < 0 )
	return unlock_pinentry (out_of_core ());
      rc = assuan_transact (entry_ctx, optstr, NULL, NULL, NULL, NULL, NULL,
			    NULL);
      free (optstr);
      if (rc)
	return unlock_pinentry (map_assuan_err (rc));
    }
  if (ctrl->ttytype)
    {
      char *optstr;
      if (asprintf (&optstr, "OPTION ttytype=%s", ctrl->ttytype) < 0 )
	return unlock_pinentry (out_of_core ());
      rc = assuan_transact (entry_ctx, optstr, NULL, NULL, NULL, NULL, NULL,
			    NULL);
      if (rc)
	return unlock_pinentry (map_assuan_err (rc));
    }
  if (ctrl->lc_ctype)
    {
      char *optstr;
      if (asprintf (&optstr, "OPTION lc-ctype=%s", ctrl->lc_ctype) < 0 )
	return unlock_pinentry (out_of_core ());
      rc = assuan_transact (entry_ctx, optstr, NULL, NULL, NULL, NULL, NULL,
			    NULL);
      if (rc)
	return unlock_pinentry (map_assuan_err (rc));
    }
  if (ctrl->lc_messages)
    {
      char *optstr;
      if (asprintf (&optstr, "OPTION lc-messages=%s", ctrl->lc_messages) < 0 )
	return unlock_pinentry (out_of_core ());
      rc = assuan_transact (entry_ctx, optstr, NULL, NULL, NULL, NULL, NULL,
			    NULL);
      if (rc)
	return unlock_pinentry (map_assuan_err (rc));
    }
  return 0;
}


static AssuanError
getpin_cb (void *opaque, const void *buffer, size_t length)
{
  struct entry_parm_s *parm = opaque;

  if (!buffer)
    return 0;

  /* we expect the pin to fit on one line */
  if (parm->lines || length >= parm->size)
    return ASSUAN_Too_Much_Data;

  /* fixme: we should make sure that the assuan buffer is allocated in
     secure memory or read the response byte by byte */
  memcpy (parm->buffer, buffer, length);
  parm->buffer[length] = 0;
  parm->lines++;
  return 0;
}


static int
all_digitsp( const char *s)
{
  for (; *s && *s >= '0' && *s <= '9'; s++)
    ;
  return !*s;
}  



/* Call the Entry and ask for the PIN.  We do check for a valid PIN
   number here and repeat it as long as we have invalid formed
   numbers. */
int
agent_askpin (ctrl_t ctrl,
              const char *desc_text, const char *prompt_text,
              const char *initial_errtext,
              struct pin_entry_info_s *pininfo)
{
  int rc;
  char line[ASSUAN_LINELENGTH];
  struct entry_parm_s parm;
  const char *errtext = NULL;
  int is_pin = 0;

  if (opt.batch)
    return 0; /* fixme: we should return BAD PIN */

  if (!pininfo || pininfo->max_length < 1)
    return gpg_error (GPG_ERR_INV_VALUE);
  if (!desc_text && pininfo->min_digits)
    desc_text = _("Please enter your PIN, so that the secret key "
                  "can be unlocked for this session");
  else if (!desc_text)
    desc_text = _("Please enter your passphrase, so that the secret key "
                  "can be unlocked for this session");

  if (prompt_text)
    is_pin = !!strstr (prompt_text, "PIN");
  else
    is_pin = desc_text && strstr (desc_text, "PIN");

  rc = start_pinentry (ctrl);
  if (rc)
    return rc;

  snprintf (line, DIM(line)-1, "SETDESC %s", desc_text);
  line[DIM(line)-1] = 0;
  rc = assuan_transact (entry_ctx, line, NULL, NULL, NULL, NULL, NULL, NULL);
  if (rc)
    return unlock_pinentry (map_assuan_err (rc));

  snprintf (line, DIM(line)-1, "SETPROMPT %s",
            prompt_text? prompt_text : is_pin? "PIN:" : "Passphrase:");
  line[DIM(line)-1] = 0;
  rc = assuan_transact (entry_ctx, line, NULL, NULL, NULL, NULL, NULL, NULL);
  if (rc)
    return unlock_pinentry (map_assuan_err (rc));


  if (initial_errtext)
    { 
      snprintf (line, DIM(line)-1, "SETERROR %s", initial_errtext);
      line[DIM(line)-1] = 0;
      rc = assuan_transact (entry_ctx, line,
                            NULL, NULL, NULL, NULL, NULL, NULL);
      if (rc)
        return unlock_pinentry (map_assuan_err (rc));
    }

  for (;pininfo->failed_tries < pininfo->max_tries; pininfo->failed_tries++)
    {
      memset (&parm, 0, sizeof parm);
      parm.size = pininfo->max_length;
      parm.buffer = pininfo->pin;

      if (errtext)
        { 
          /* fixme: should we show the try count? It must be translated */
          snprintf (line, DIM(line)-1, "SETERROR %s (try %d of %d)",
                    errtext, pininfo->failed_tries+1, pininfo->max_tries);
          line[DIM(line)-1] = 0;
          rc = assuan_transact (entry_ctx, line,
                                NULL, NULL, NULL, NULL, NULL, NULL);
          if (rc)
            return unlock_pinentry (map_assuan_err (rc));
          errtext = NULL;
        }
      
      rc = assuan_transact (entry_ctx, "GETPIN", getpin_cb, &parm,
                            NULL, NULL, NULL, NULL);
      if (rc == ASSUAN_Too_Much_Data)
        errtext = is_pin? _("PIN too long")
                        : _("Passphrase too long");
      else if (rc)
        return unlock_pinentry (map_assuan_err (rc));

      if (!errtext && pininfo->min_digits)
        {
          /* do some basic checks on the entered PIN. */
          if (!all_digitsp (pininfo->pin))
            errtext = _("Invalid characters in PIN");
          else if (pininfo->max_digits
                   && strlen (pininfo->pin) > pininfo->max_digits)
            errtext = _("PIN too long");
          else if (strlen (pininfo->pin) < pininfo->min_digits)
            errtext = _("PIN too short");
        }

      if (!errtext && pininfo->check_cb)
        {
          /* More checks by utilizing the optional callback. */
          pininfo->cb_errtext = NULL;
          rc = pininfo->check_cb (pininfo);
          if (rc == -1 && pininfo->cb_errtext)
            errtext = pininfo->cb_errtext;
          else if (gpg_err_code (rc) == GPG_ERR_BAD_PASSPHRASE
                   || gpg_err_code (rc) == GPG_ERR_BAD_PIN)
            errtext = (is_pin? _("Bad PIN")
                       : _("Bad Passphrase"));
          else if (rc)
            return unlock_pinentry (map_assuan_err (rc));
        }

      if (!errtext)
        return unlock_pinentry (0); /* okay, got a PIN or passphrase */
    }

  return unlock_pinentry (gpg_error (pininfo->min_digits? GPG_ERR_BAD_PIN
                          : GPG_ERR_BAD_PASSPHRASE));
}



/* Ask for the passphrase using the supplied arguments.  The
   passphrase is returned in RETPASS as an hex encoded string to be
   freed by the caller */
int 
agent_get_passphrase (CTRL ctrl,
                      char **retpass, const char *desc, const char *prompt,
                      const char *errtext)
{

  int rc;
  char line[ASSUAN_LINELENGTH];
  struct entry_parm_s parm;
  unsigned char *p, *hexstring;
  int i;

  *retpass = NULL;
  if (opt.batch)
    return gpg_error (GPG_ERR_BAD_PASSPHRASE); 

  rc = start_pinentry (ctrl);
  if (rc)
    return rc;

  if (!prompt)
    prompt = desc && strstr (desc, "PIN")? "PIN": _("Passphrase");


  if (desc)
    snprintf (line, DIM(line)-1, "SETDESC %s", desc);
  else
    snprintf (line, DIM(line)-1, "RESET");
  line[DIM(line)-1] = 0;
  rc = assuan_transact (entry_ctx, line, NULL, NULL, NULL, NULL, NULL, NULL);
  if (rc)
    return unlock_pinentry (map_assuan_err (rc));

  snprintf (line, DIM(line)-1, "SETPROMPT %s", prompt);
  line[DIM(line)-1] = 0;
  rc = assuan_transact (entry_ctx, line, NULL, NULL, NULL, NULL, NULL, NULL);
  if (rc)
    return unlock_pinentry (map_assuan_err (rc));

  if (errtext)
    {
      snprintf (line, DIM(line)-1, "SETERROR %s", errtext);
      line[DIM(line)-1] = 0;
      rc = assuan_transact (entry_ctx, line, NULL, NULL, NULL, NULL, NULL, NULL);
      if (rc)
        return unlock_pinentry (map_assuan_err (rc));
    }

  memset (&parm, 0, sizeof parm);
  parm.size = ASSUAN_LINELENGTH/2 - 5;
  parm.buffer = gcry_malloc_secure (parm.size+10);
  if (!parm.buffer)
    return unlock_pinentry (out_of_core ());

  assuan_begin_confidential (entry_ctx);
  rc = assuan_transact (entry_ctx, "GETPIN", getpin_cb, &parm, NULL, NULL, NULL, NULL);
  if (rc)
    {
      xfree (parm.buffer);
      return unlock_pinentry (map_assuan_err (rc));
    }
  
  hexstring = gcry_malloc_secure (strlen (parm.buffer)*2+1);
  if (!hexstring)
    {
      gpg_error_t tmperr = out_of_core ();
      xfree (parm.buffer);
      return unlock_pinentry (tmperr);
    }

  for (i=0, p=parm.buffer; *p; p++, i += 2)
    sprintf (hexstring+i, "%02X", *p);
  
  xfree (parm.buffer);
  *retpass = hexstring;
  return unlock_pinentry (0);
}



/* Pop up the PIN-entry, display the text and the prompt and ask the
   user to confirm this.  We return 0 for success, ie. the used
   confirmed it, GPG_ERR_NOT_CONFIRMED for what the text says or an
   other error. */
int 
agent_get_confirmation (CTRL ctrl,
                        const char *desc, const char *ok, const char *cancel)
{
  int rc;
  char line[ASSUAN_LINELENGTH];

  rc = start_pinentry (ctrl);
  if (rc)
    return rc;

  if (desc)
    snprintf (line, DIM(line)-1, "SETDESC %s", desc);
  else
    snprintf (line, DIM(line)-1, "RESET");
  line[DIM(line)-1] = 0;
  rc = assuan_transact (entry_ctx, line, NULL, NULL, NULL, NULL, NULL, NULL);
  if (rc)
    return unlock_pinentry (map_assuan_err (rc));

  if (ok)
    {
      snprintf (line, DIM(line)-1, "SETOK %s", ok);
      line[DIM(line)-1] = 0;
      rc = assuan_transact (entry_ctx, line, NULL, NULL, NULL, NULL, NULL, NULL);
      if (rc)
        return unlock_pinentry (map_assuan_err (rc));
    }
  if (cancel)
    {
      snprintf (line, DIM(line)-1, "SETCANCEL %s", cancel);
      line[DIM(line)-1] = 0;
      rc = assuan_transact (entry_ctx, line, NULL, NULL, NULL, NULL, NULL, NULL);
      if (rc)
        return unlock_pinentry (map_assuan_err (rc));
    }

  rc = assuan_transact (entry_ctx, "CONFIRM", NULL, NULL, NULL, NULL, NULL, NULL);
  return unlock_pinentry (map_assuan_err (rc));
}



