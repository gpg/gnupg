/* call-pinentry.c - Spawn the pinentry to query stuff from the user
 * Copyright (C) 2001, 2002, 2004, 2007, 2008,
 *               2010  Free Software Foundation, Inc.
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
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <assert.h>
#include <unistd.h>
#include <sys/stat.h>
#ifndef HAVE_W32_SYSTEM
# include <sys/wait.h>
# include <sys/types.h>
# include <signal.h>
#endif
#include <pth.h>

#include "agent.h"
#include <assuan.h>
#include "setenv.h"
#include "i18n.h"

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

/* The assuan context of the current pinentry. */
static assuan_context_t entry_ctx;

/* The control variable of the connection owning the current pinentry.
   This is only valid if ENTRY_CTX is not NULL.  Note, that we care
   only about the value of the pointer and that it should never be
   dereferenced.  */
static ctrl_t entry_owner;

/* A mutex used to serialize access to the pinentry. */
static pth_mutex_t entry_lock;

/* The thread ID of the popup working thread. */
static pth_t  popup_tid;

/* A flag used in communication between the popup working thread and
   its stop function. */
static int popup_finished;



/* Data to be passed to our callbacks, */
struct entry_parm_s
{
  int lines;
  size_t size;
  unsigned char *buffer;
};




/* This function must be called once to initialize this module.  This
   has to be done before a second thread is spawned.  We can't do the
   static initialization because Pth emulation code might not be able
   to do a static init; in particular, it is not possible for W32. */
void
initialize_module_call_pinentry (void)
{
  static int initialized;

  if (!initialized)
    {
      if (pth_mutex_init (&entry_lock))
        initialized = 1;
    }
}



static void
dump_mutex_state (pth_mutex_t *m)
{
#ifdef _W32_PTH_H
  (void)m;
  log_printf ("unknown under W32");
#else
  if (!(m->mx_state & PTH_MUTEX_INITIALIZED))
    log_printf ("not_initialized");
  else if (!(m->mx_state & PTH_MUTEX_LOCKED))
    log_printf ("not_locked");
  else
    log_printf ("locked tid=0x%lx count=%lu", (long)m->mx_owner, m->mx_count);
#endif
}


/* This function may be called to print infromation pertaining to the
   current state of this module to the log. */
void
agent_query_dump_state (void)
{
  log_info ("agent_query_dump_state: entry_lock=");
  dump_mutex_state (&entry_lock);
  log_printf ("\n");
  log_info ("agent_query_dump_state: entry_ctx=%p pid=%ld popup_tid=%p\n",
            entry_ctx, (long)assuan_get_pid (entry_ctx), popup_tid);
}

/* Called to make sure that a popup window owned by the current
   connection gets closed. */
void
agent_reset_query (ctrl_t ctrl)
{
  if (entry_ctx && popup_tid && entry_owner == ctrl)
    {
      agent_popup_message_stop (ctrl);
    }
}


/* Unlock the pinentry so that another thread can start one and
   disconnect that pinentry - we do this after the unlock so that a
   stalled pinentry does not block other threads.  Fixme: We should
   have a timeout in Assuan for the disconnect operation. */
static int 
unlock_pinentry (int rc)
{
  assuan_context_t ctx = entry_ctx;

  entry_ctx = NULL;
  if (!pth_mutex_release (&entry_lock))
    {
      log_error ("failed to release the entry lock\n");
      if (!rc)
        rc = gpg_error (GPG_ERR_INTERNAL);
    }
  assuan_release (ctx);
  return rc;
}


/* To make sure we leave no secrets in our image after forking of the
   pinentry, we use this callback. */
static void
atfork_cb (void *opaque, int where)
{
  ctrl_t ctrl = opaque;

  if (!where)
    {
      int iterator = 0;
      const char *name, *assname, *value;
      
      gcry_control (GCRYCTL_TERM_SECMEM);

      while ((name = session_env_list_stdenvnames (&iterator, &assname)))
        {
          /* For all new envvars (!ASSNAME) and the two medium old
             ones which do have an assuan name but are conveyed using
             environment variables, update the environment of the
             forked process.  */
          if (!assname 
              || !strcmp (name, "XAUTHORITY")
              || !strcmp (name, "PINENTRY_USER_DATA"))
            {
              value = session_env_getenv (ctrl->session_env, name);
              if (value)
                setenv (name, value, 1);
            }
        }
    }
}


static gpg_error_t
getinfo_pid_cb (void *opaque, const void *buffer, size_t length)
{
  unsigned long *pid = opaque;
  char pidbuf[50];

  /* There is only the pid in the server's response.  */
  if (length >= sizeof pidbuf)
    length = sizeof pidbuf -1;
  if (length)
    {
      strncpy (pidbuf, buffer, length);
      pidbuf[length] = 0;
      *pid = strtoul (pidbuf, NULL, 10);
    }
  return 0;
}

/* Fork off the pin entry if this has not already been done.  Note,
   that this function must always be used to aquire the lock for the
   pinentry - we will serialize _all_ pinentry calls.
 */
static int
start_pinentry (ctrl_t ctrl)
{
  int rc;
  const char *pgmname;
  assuan_context_t ctx;
  const char *argv[5];
  int no_close_list[3];
  int i;
  pth_event_t evt;
  const char *tmpstr;
  unsigned long pinentry_pid;
  const char *value;

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

  entry_owner = ctrl;

  if (entry_ctx)
    return 0; 

  if (opt.verbose)
    log_info ("starting a new PIN Entry\n");

#ifdef HAVE_W32_SYSTEM      
  fflush (stdout);
  fflush (stderr);
#endif
  if (fflush (NULL))
    {
#ifndef HAVE_W32_SYSTEM
      gpg_error_t tmperr = gpg_error (gpg_err_code_from_errno (errno));
#endif
      log_error ("error flushing pending output: %s\n", strerror (errno));
      /* At least Windows XP fails here with EBADF.  According to docs
         and Wine an fflush(NULL) is the same as _flushall.  However
         the Wime implementaion does not flush stdin,stdout and stderr
         - see above.  Lets try to ignore the error. */
#ifndef HAVE_W32_SYSTEM
      return unlock_pinentry (tmperr);
#endif
    }

  if (!opt.pinentry_program || !*opt.pinentry_program)
    opt.pinentry_program = gnupg_module_name (GNUPG_MODULE_NAME_PINENTRY);
    pgmname = opt.pinentry_program;
  if ( !(pgmname = strrchr (opt.pinentry_program, '/')))
    pgmname = opt.pinentry_program;
  else
    pgmname++;

  /* OS X needs the entire file name in argv[0], so that it can locate
     the resource bundle.  For other systems we stick to the usual
     convention of supplying only the name of the program.  */
#ifdef __APPLE__
  argv[0] = opt.pinentry_program;
#else /*!__APPLE__*/
  argv[0] = pgmname;
#endif /*__APPLE__*/

  if (!opt.keep_display
      && (value = session_env_getenv (ctrl->session_env, "DISPLAY")))
    {
      argv[1] = "--display";
      argv[2] = value;
      argv[3] = NULL;
    }
  else
    argv[1] = NULL;
  
  i=0;
  if (!opt.running_detached)
    {
      if (log_get_fd () != -1)
        no_close_list[i++] = assuan_fd_from_posix_fd (log_get_fd ());
      no_close_list[i++] = assuan_fd_from_posix_fd (fileno (stderr));
    }
  no_close_list[i] = -1;

  rc = assuan_new (&ctx);
  if (rc)
    {
      log_error ("can't allocate assuan context: %s\n", gpg_strerror (rc));
      return rc;
    }

  /* Connect to the pinentry and perform initial handshaking.  Note
     that atfork is used to change the environment for pinentry.  We
     start the server in detached mode to suppress the console window
     under Windows.  */
  rc = assuan_pipe_connect (ctx, opt.pinentry_program, argv,
			    no_close_list, atfork_cb, ctrl,
			    ASSUAN_PIPE_CONNECT_DETACHED);
  if (rc)
    {
      log_error ("can't connect to the PIN entry module: %s\n",
                 gpg_strerror (rc));
      assuan_release (ctx);
      return unlock_pinentry (gpg_error (GPG_ERR_NO_PIN_ENTRY));
    }
  entry_ctx = ctx;

  if (DBG_ASSUAN)
    log_debug ("connection to PIN entry established\n");

  rc = assuan_transact (entry_ctx, 
                        opt.no_grab? "OPTION no-grab":"OPTION grab",
                        NULL, NULL, NULL, NULL, NULL, NULL);
  if (rc)
    return unlock_pinentry (rc);

  value = session_env_getenv (ctrl->session_env, "GPG_TTY");
  if (value)
    {
      char *optstr;
      if (asprintf (&optstr, "OPTION ttyname=%s", value) < 0 )
	return unlock_pinentry (out_of_core ());
      rc = assuan_transact (entry_ctx, optstr, NULL, NULL, NULL, NULL, NULL,
			    NULL);
      xfree (optstr);
      if (rc)
	return unlock_pinentry (rc);
    }
  value = session_env_getenv (ctrl->session_env, "TERM");
  if (value)
    {
      char *optstr;
      if (asprintf (&optstr, "OPTION ttytype=%s", value) < 0 )
	return unlock_pinentry (out_of_core ());
      rc = assuan_transact (entry_ctx, optstr, NULL, NULL, NULL, NULL, NULL,
			    NULL);
      xfree (optstr);
      if (rc)
	return unlock_pinentry (rc);
    }
  if (ctrl->lc_ctype)
    {
      char *optstr;
      if (asprintf (&optstr, "OPTION lc-ctype=%s", ctrl->lc_ctype) < 0 )
	return unlock_pinentry (out_of_core ());
      rc = assuan_transact (entry_ctx, optstr, NULL, NULL, NULL, NULL, NULL,
			    NULL);
      xfree (optstr);
      if (rc)
	return unlock_pinentry (rc);
    }
  if (ctrl->lc_messages)
    {
      char *optstr;
      if (asprintf (&optstr, "OPTION lc-messages=%s", ctrl->lc_messages) < 0 )
	return unlock_pinentry (out_of_core ());
      rc = assuan_transact (entry_ctx, optstr, NULL, NULL, NULL, NULL, NULL,
			    NULL);
      xfree (optstr);
      if (rc)
	return unlock_pinentry (rc);
    }

  {
    /* Provide a few default strings for use by the pinentries.  This
       may help a pinentry to avoid implementing localization code.  */
    static struct { const char *key, *value; } tbl[] = {
      /* TRANSLATORS: These are labels for buttons etc used in
         Pinentries.  An underscore indicates that the next letter
         should be used as an accelerator.  Double the underscore for
         a literal one.  The actual to be translated text starts after
         the second vertical bar.  */
      { "ok",     N_("|pinentry-label|_OK") },
      { "cancel", N_("|pinentry-label|_Cancel") },
      { "prompt", N_("|pinentry-label|PIN:") },
      { NULL, NULL}
    };
    char *optstr;
    int idx;
    const char *s, *s2;

    for (idx=0; tbl[idx].key; idx++)
      {
        s = _(tbl[idx].value);
        if (*s == '|' && (s2=strchr (s+1,'|')))
          s = s2+1;
        if (asprintf (&optstr, "OPTION default-%s=%s", tbl[idx].key, s) < 0 )
          return unlock_pinentry (out_of_core ());
        assuan_transact (entry_ctx, optstr, NULL, NULL, NULL, NULL, NULL,
                         NULL);
        xfree (optstr);
      }
  }

  
  /* Tell the pinentry the name of a file it shall touch after having
     messed with the tty.  This is optional and only supported by
     newer pinentries and thus we do no error checking. */
  tmpstr = opt.pinentry_touch_file;
  if (tmpstr && !strcmp (tmpstr, "/dev/null"))
    tmpstr = NULL;
  else if (!tmpstr)
    tmpstr = get_agent_socket_name ();
  if (tmpstr)
    {
      char *optstr;
      
      if (asprintf (&optstr, "OPTION touch-file=%s", tmpstr ) < 0 )
        ;
      else
        {
          assuan_transact (entry_ctx, optstr, NULL, NULL, NULL, NULL, NULL,
                           NULL);
          xfree (optstr);
        }
    }


  /* Now ask the Pinentry for its PID.  If the Pinentry is new enough
     it will send the pid back and we will use an inquire to notify
     our client.  The client may answer the inquiry either with END or
     with CAN to cancel the pinentry. */
  rc = assuan_transact (entry_ctx, "GETINFO pid", 
                        getinfo_pid_cb, &pinentry_pid,
                        NULL, NULL, NULL, NULL);
  if (rc)
    {
      log_info ("You may want to update to a newer pinentry\n");
      rc = 0;
    }
  else if (!rc && (pid_t)pinentry_pid == (pid_t)(-1))
    log_error ("pinentry did not return a PID\n");
  else
    {
      rc = agent_inq_pinentry_launched (ctrl, pinentry_pid);
      if (gpg_err_code (rc) == GPG_ERR_CANCELED)
        return unlock_pinentry (gpg_error (GPG_ERR_CANCELED));
      rc = 0;
    }

  return 0;
}


/* Returns True is the pinentry is currently active. If WAITSECONDS is
   greater than zero the function will wait for this many seconds
   before returning.  */
int
pinentry_active_p (ctrl_t ctrl, int waitseconds)
{
  (void)ctrl;

  if (waitseconds > 0)
    {
      pth_event_t evt;
      int rc;

      evt = pth_event (PTH_EVENT_TIME, pth_timeout (waitseconds, 0));
      if (!pth_mutex_acquire (&entry_lock, 0, evt))
        {
          if (pth_event_occurred (evt))
            rc = gpg_error (GPG_ERR_TIMEOUT);
          else
            rc = gpg_error (GPG_ERR_INTERNAL);
          pth_event_free (evt, PTH_FREE_THIS);
          return rc;
        }
      pth_event_free (evt, PTH_FREE_THIS);
    }
  else
    {
      if (!pth_mutex_acquire (&entry_lock, 1, NULL))
        return gpg_error (GPG_ERR_LOCKED);
    }

  if (!pth_mutex_release (&entry_lock))
    log_error ("failed to release the entry lock at %d\n", __LINE__);
  return 0;
}


static gpg_error_t
getpin_cb (void *opaque, const void *buffer, size_t length)
{
  struct entry_parm_s *parm = opaque;

  if (!buffer)
    return 0;

  /* we expect the pin to fit on one line */
  if (parm->lines || length >= parm->size)
    return gpg_error (GPG_ERR_ASS_TOO_MUCH_DATA);

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


/* Return a new malloced string by unescaping the string S.  Escaping
   is percent escaping and '+'/space mapping.  A binary Nul will
   silently be replaced by a 0xFF.  Function returns NULL to indicate
   an out of memory status.  PArsing stops at the end of the string or
   a white space character. */
static char *
unescape_passphrase_string (const unsigned char *s)
{
  char *buffer, *d;

  buffer = d = xtrymalloc_secure (strlen ((const char*)s)+1);
  if (!buffer)
    return NULL;
  while (*s && !spacep (s))
    {
      if (*s == '%' && s[1] && s[2])
        { 
          s++;
          *d = xtoi_2 (s);
          if (!*d)
            *d = '\xff';
          d++;
          s += 2;
        }
      else if (*s == '+')
        {
          *d++ = ' ';
          s++;
        }
      else
        *d++ = *s++;
    }
  *d = 0; 
  return buffer;
}


/* Estimate the quality of the passphrase PW and return a value in the
   range 0..100.  */
static int
estimate_passphrase_quality (const char *pw)
{
  int goodlength = opt.min_passphrase_len + opt.min_passphrase_len/3;
  int length;
  const char *s;

  if (goodlength < 1)
    return 0;

  for (length = 0, s = pw; *s; s++)
    if (!spacep (s))
      length ++;

  if (length > goodlength)
    return 100;
  return ((length*10) / goodlength)*10;
}


/* Handle the QUALITY inquiry. */
static gpg_error_t
inq_quality (void *opaque, const char *line)
{
  assuan_context_t ctx = opaque;
  char *pin;
  int rc;
  int percent;
  char numbuf[20];

  if (!strncmp (line, "QUALITY", 7) && (line[7] == ' ' || !line[7]))
    {
      line += 7;
      while (*line == ' ')
        line++;
      
      pin = unescape_passphrase_string (line);
      if (!pin)
        rc = gpg_error_from_syserror ();
      else
        {
          percent = estimate_passphrase_quality (pin);
          if (check_passphrase_constraints (NULL, pin, 1))
            percent = -percent;
          snprintf (numbuf, sizeof numbuf, "%d", percent);
          rc = assuan_send_data (ctx, numbuf, strlen (numbuf));
          xfree (pin);
        }
    }
  else
    {
      log_error ("unsupported inquiry `%s' from pinentry\n", line);
      rc = gpg_error (GPG_ERR_ASS_UNKNOWN_INQUIRE);
    }

  return rc;
}


/* Helper for agent_askpin and agent_get_passphrase.  */
static int
setup_qualitybar (void)
{
  int rc;
  char line[ASSUAN_LINELENGTH];
  char *tmpstr, *tmpstr2;
  const char *tooltip;
  
  /* TRANSLATORS: This string is displayed by Pinentry as the label
     for the quality bar.  */
  tmpstr = try_percent_escape (_("Quality:"), "\t\r\n\f\v");
  snprintf (line, DIM(line)-1, "SETQUALITYBAR %s", tmpstr? tmpstr:"");
  line[DIM(line)-1] = 0;
  xfree (tmpstr);
  rc = assuan_transact (entry_ctx, line, NULL, NULL, NULL, NULL, NULL, NULL);
  if (rc == 103 /*(Old assuan error code)*/
      || gpg_err_code (rc) == GPG_ERR_ASS_UNKNOWN_CMD)
    ; /* Ignore Unknown Command from old Pinentry versions.  */
  else if (rc)
    return rc;
  
  tmpstr2 = gnupg_get_help_string ("pinentry.qualitybar.tooltip", 0);
  if (tmpstr2)
    tooltip = tmpstr2;
  else
    {
      /* TRANSLATORS: This string is a tooltip, shown by pinentry when
         hovering over the quality bar.  Please use an appropriate
         string to describe what this is about.  The length of the
         tooltip is limited to about 900 characters.  If you do not
         translate this entry, a default english text (see source)
         will be used. */
      tooltip =  _("pinentry.qualitybar.tooltip");
      if (!strcmp ("pinentry.qualitybar.tooltip", tooltip))
        tooltip = ("The quality of the text entered above.\n"
                   "Please ask your administrator for "
                   "details about the criteria.");
    }
  tmpstr = try_percent_escape (tooltip, "\t\r\n\f\v");
  xfree (tmpstr2);
  snprintf (line, DIM(line)-1, "SETQUALITYBAR_TT %s", tmpstr? tmpstr:"");
  line[DIM(line)-1] = 0;
  xfree (tmpstr);
  rc = assuan_transact (entry_ctx, line, NULL, NULL, NULL, NULL, NULL, NULL);
  if (rc == 103 /*(Old assuan error code)*/
          || gpg_err_code (rc) == GPG_ERR_ASS_UNKNOWN_CMD)
    ; /* Ignore Unknown Command from old pinentry versions.  */
  else if (rc)
    return rc;

  return 0;
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
  int saveflag;

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
    return unlock_pinentry (rc);

  snprintf (line, DIM(line)-1, "SETPROMPT %s",
            prompt_text? prompt_text : is_pin? "PIN:" : "Passphrase:");
  line[DIM(line)-1] = 0;
  rc = assuan_transact (entry_ctx, line, NULL, NULL, NULL, NULL, NULL, NULL);
  if (rc)
    return unlock_pinentry (rc);

  /* If a passphrase quality indicator has been requested and a
     minimum passphrase length has not been disabled, send the command
     to the pinentry.  */
  if (pininfo->with_qualitybar && opt.min_passphrase_len )
    {
      rc = setup_qualitybar ();
      if (rc)
        return unlock_pinentry (rc);
    }

  if (initial_errtext)
    { 
      snprintf (line, DIM(line)-1, "SETERROR %s", initial_errtext);
      line[DIM(line)-1] = 0;
      rc = assuan_transact (entry_ctx, line,
                            NULL, NULL, NULL, NULL, NULL, NULL);
      if (rc)
        return unlock_pinentry (rc);
    }

  for (;pininfo->failed_tries < pininfo->max_tries; pininfo->failed_tries++)
    {
      memset (&parm, 0, sizeof parm);
      parm.size = pininfo->max_length;
      *pininfo->pin = 0; /* Reset the PIN. */
      parm.buffer = (unsigned char*)pininfo->pin;

      if (errtext)
        { 
          /* TRANLATORS: The string is appended to an error message in
             the pinentry.  The %s is the actual error message, the
             two %d give the current and maximum number of tries. */
          snprintf (line, DIM(line)-1, _("SETERROR %s (try %d of %d)"),
                    errtext, pininfo->failed_tries+1, pininfo->max_tries);
          line[DIM(line)-1] = 0;
          rc = assuan_transact (entry_ctx, line,
                                NULL, NULL, NULL, NULL, NULL, NULL);
          if (rc)
            return unlock_pinentry (rc);
          errtext = NULL;
        }
      
      saveflag = assuan_get_flag (entry_ctx, ASSUAN_CONFIDENTIAL);
      assuan_begin_confidential (entry_ctx);
      rc = assuan_transact (entry_ctx, "GETPIN", getpin_cb, &parm,
                            inq_quality, entry_ctx, NULL, NULL);
      assuan_set_flag (entry_ctx, ASSUAN_CONFIDENTIAL, saveflag);
      /* Most pinentries out in the wild return the old Assuan error code
         for canceled which gets translated to an assuan Cancel error and
         not to the code for a user cancel.  Fix this here. */
      if (rc && gpg_err_source (rc)
          && gpg_err_code (rc) == GPG_ERR_ASS_CANCELED)
        rc = gpg_err_make (gpg_err_source (rc), GPG_ERR_CANCELED);

      if (gpg_err_code (rc) == GPG_ERR_ASS_TOO_MUCH_DATA)
        errtext = is_pin? _("PIN too long")
                        : _("Passphrase too long");
      else if (rc)
        return unlock_pinentry (rc);

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
            return unlock_pinentry (rc);
        }

      if (!errtext)
        return unlock_pinentry (0); /* okay, got a PIN or passphrase */
    }

  return unlock_pinentry (gpg_error (pininfo->min_digits? GPG_ERR_BAD_PIN
                          : GPG_ERR_BAD_PASSPHRASE));
}



/* Ask for the passphrase using the supplied arguments.  The returned
   passphrase needs to be freed by the caller. */
int 
agent_get_passphrase (ctrl_t ctrl,
                      char **retpass, const char *desc, const char *prompt,
                      const char *errtext, int with_qualitybar)
{

  int rc;
  char line[ASSUAN_LINELENGTH];
  struct entry_parm_s parm;
  int saveflag;

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
    return unlock_pinentry (rc);

  snprintf (line, DIM(line)-1, "SETPROMPT %s", prompt);
  line[DIM(line)-1] = 0;
  rc = assuan_transact (entry_ctx, line, NULL, NULL, NULL, NULL, NULL, NULL);
  if (rc)
    return unlock_pinentry (rc);

  if (with_qualitybar && opt.min_passphrase_len)
    {
      rc = setup_qualitybar ();
      if (rc)
        return unlock_pinentry (rc);
    }

  if (errtext)
    {
      snprintf (line, DIM(line)-1, "SETERROR %s", errtext);
      line[DIM(line)-1] = 0;
      rc = assuan_transact (entry_ctx, line, NULL, NULL, NULL, NULL, NULL, NULL);
      if (rc)
        return unlock_pinentry (rc);
    }

  memset (&parm, 0, sizeof parm);
  parm.size = ASSUAN_LINELENGTH/2 - 5;
  parm.buffer = gcry_malloc_secure (parm.size+10);
  if (!parm.buffer)
    return unlock_pinentry (out_of_core ());

  saveflag = assuan_get_flag (entry_ctx, ASSUAN_CONFIDENTIAL);
  assuan_begin_confidential (entry_ctx);
  rc = assuan_transact (entry_ctx, "GETPIN", getpin_cb, &parm,
                        inq_quality, entry_ctx, NULL, NULL);
  assuan_set_flag (entry_ctx, ASSUAN_CONFIDENTIAL, saveflag);
  /* Most pinentries out in the wild return the old Assuan error code
     for canceled which gets translated to an assuan Cancel error and
     not to the code for a user cancel.  Fix this here. */
  if (rc && gpg_err_source (rc) && gpg_err_code (rc) == GPG_ERR_ASS_CANCELED)
    rc = gpg_err_make (gpg_err_source (rc), GPG_ERR_CANCELED);
  if (rc)
    xfree (parm.buffer);
  else
    *retpass = parm.buffer;
  return unlock_pinentry (rc);
}



/* Pop up the PIN-entry, display the text and the prompt and ask the
   user to confirm this.  We return 0 for success, ie. the user
   confirmed it, GPG_ERR_NOT_CONFIRMED for what the text says or an
   other error.  If WITH_CANCEL it true an extra cancel button is
   displayed to allow the user to easily return a GPG_ERR_CANCELED.
   if the Pinentry does not support this, the user can still cancel by
   closing the Pinentry window.  */
int 
agent_get_confirmation (ctrl_t ctrl,
                        const char *desc, const char *ok, 
                        const char *notok, int with_cancel)
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
  /* Most pinentries out in the wild return the old Assuan error code
     for canceled which gets translated to an assuan Cancel error and
     not to the code for a user cancel.  Fix this here. */
  if (rc && gpg_err_source (rc) && gpg_err_code (rc) == GPG_ERR_ASS_CANCELED)
    rc = gpg_err_make (gpg_err_source (rc), GPG_ERR_CANCELED);

  if (rc)
    return unlock_pinentry (rc);

  if (ok)
    {
      snprintf (line, DIM(line)-1, "SETOK %s", ok);
      line[DIM(line)-1] = 0;
      rc = assuan_transact (entry_ctx,
                            line, NULL, NULL, NULL, NULL, NULL, NULL);
      if (rc)
        return unlock_pinentry (rc);
    }
  if (notok)
    {
      /* Try to use the newer NOTOK feature if a cancel button is
         requested.  If no cancel button is requested we keep on using
         the standard cancel.  */
      if (with_cancel)
        {
          snprintf (line, DIM(line)-1, "SETNOTOK %s", notok);
          line[DIM(line)-1] = 0;
          rc = assuan_transact (entry_ctx,
                                line, NULL, NULL, NULL, NULL, NULL, NULL);
        }
      else
        rc = GPG_ERR_ASS_UNKNOWN_CMD;

      if (gpg_err_code (rc) == GPG_ERR_ASS_UNKNOWN_CMD)
	{
	  snprintf (line, DIM(line)-1, "SETCANCEL %s", notok);
	  line[DIM(line)-1] = 0;
	  rc = assuan_transact (entry_ctx, line,
                                NULL, NULL, NULL, NULL, NULL, NULL);
	}
      if (rc)
        return unlock_pinentry (rc);
    }

  rc = assuan_transact (entry_ctx, "CONFIRM",
                        NULL, NULL, NULL, NULL, NULL, NULL);
  if (rc && gpg_err_source (rc) && gpg_err_code (rc) == GPG_ERR_ASS_CANCELED)
    rc = gpg_err_make (gpg_err_source (rc), GPG_ERR_CANCELED);

  return unlock_pinentry (rc);
}



/* Pop up the PINentry, display the text DESC and a button with the
   text OK_BTN (which may be NULL to use the default of "OK") and waut
   for the user to hit this button.  The return value is not
   relevant.  */
int 
agent_show_message (ctrl_t ctrl, const char *desc, const char *ok_btn)
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
  /* Most pinentries out in the wild return the old Assuan error code
     for canceled which gets translated to an assuan Cancel error and
     not to the code for a user cancel.  Fix this here. */
  if (rc && gpg_err_source (rc) && gpg_err_code (rc) == GPG_ERR_ASS_CANCELED)
    rc = gpg_err_make (gpg_err_source (rc), GPG_ERR_CANCELED);

  if (rc)
    return unlock_pinentry (rc);

  if (ok_btn)
    {
      snprintf (line, DIM(line)-1, "SETOK %s", ok_btn);
      line[DIM(line)-1] = 0;
      rc = assuan_transact (entry_ctx, line, NULL, NULL, NULL,
                            NULL, NULL, NULL);
      if (rc)
        return unlock_pinentry (rc);
    }
  
  rc = assuan_transact (entry_ctx, "CONFIRM --one-button", NULL, NULL, NULL,
                        NULL, NULL, NULL);
  if (rc && gpg_err_source (rc) && gpg_err_code (rc) == GPG_ERR_ASS_CANCELED)
    rc = gpg_err_make (gpg_err_source (rc), GPG_ERR_CANCELED);

  return unlock_pinentry (rc);
}


/* The thread running the popup message. */
static void *
popup_message_thread (void *arg)
{
  (void)arg;

  /* We use the --one-button hack instead of the MESSAGE command to
     allow the use of old Pinentries.  Those old Pinentries will then
     show an additional Cancel button but that is mostly a visual
     annoyance. */
  assuan_transact (entry_ctx, "CONFIRM --one-button", 
                   NULL, NULL, NULL, NULL, NULL, NULL);
  popup_finished = 1;
  return NULL;
}


/* Pop up a message window similar to the confirm one but keep it open
   until agent_popup_message_stop has been called.  It is crucial for
   the caller to make sure that the stop function gets called as soon
   as the message is not anymore required because the message is
   system modal and all other attempts to use the pinentry will fail
   (after a timeout). */
int 
agent_popup_message_start (ctrl_t ctrl, const char *desc, const char *ok_btn)
{
  int rc;
  char line[ASSUAN_LINELENGTH];
  pth_attr_t tattr;

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
    return unlock_pinentry (rc);

  if (ok_btn)
    {
      snprintf (line, DIM(line)-1, "SETOK %s", ok_btn);
      line[DIM(line)-1] = 0;
      rc = assuan_transact (entry_ctx, line, NULL,NULL,NULL,NULL,NULL,NULL);
      if (rc)
        return unlock_pinentry (rc);
    }

  tattr = pth_attr_new();
  pth_attr_set (tattr, PTH_ATTR_JOINABLE, 1);
  pth_attr_set (tattr, PTH_ATTR_STACK_SIZE, 256*1024);
  pth_attr_set (tattr, PTH_ATTR_NAME, "popup-message");

  popup_finished = 0;
  popup_tid = pth_spawn (tattr, popup_message_thread, NULL);
  if (!popup_tid)
    {
      rc = gpg_error_from_syserror ();
      log_error ("error spawning popup message handler: %s\n",
                 strerror (errno) );
      pth_attr_destroy (tattr);
      return unlock_pinentry (rc);
    }
  pth_attr_destroy (tattr);

  return 0;
}

/* Close a popup window. */
void
agent_popup_message_stop (ctrl_t ctrl)
{
  int rc;
  pid_t pid;

  (void)ctrl;

  if (!popup_tid || !entry_ctx)
    {
      log_debug ("agent_popup_message_stop called with no active popup\n");
      return; 
    }

  pid = assuan_get_pid (entry_ctx);
  if (pid == (pid_t)(-1))
    ; /* No pid available can't send a kill. */
  else if (popup_finished)
    ; /* Already finished and ready for joining. */
#ifdef HAVE_W32_SYSTEM
  /* Older versions of assuan set PID to 0 on Windows to indicate an
     invalid value.  */
  else if (pid != (pid_t) INVALID_HANDLE_VALUE
	   && pid != 0)
    {
      HANDLE process = (HANDLE) pid;
      
      /* Arbitrary error code.  */
      TerminateProcess (process, 1);
    }
#else
  else if (pid && ((rc=waitpid (pid, NULL, WNOHANG))==-1 || (rc == pid)) )
    { /* The daemon already died.  No need to send a kill.  However
         because we already waited for the process, we need to tell
         assuan that it should not wait again (done by
         unlock_pinentry). */
      if (rc == pid)
        assuan_set_flag (entry_ctx, ASSUAN_NO_WAITPID, 1);
    }
  else if (pid > 0)
    kill (pid, SIGKILL);  /* Need to use SIGKILL due to bad
                             interaction of SIGINT with Pth. */
#endif

  /* Now wait for the thread to terminate. */
  rc = pth_join (popup_tid, NULL);
  if (!rc)
    log_debug ("agent_popup_message_stop: pth_join failed: %s\n",
               strerror (errno));
  popup_tid = NULL;
  entry_owner = NULL;

  /* Now we can close the connection. */
  unlock_pinentry (0);
}


