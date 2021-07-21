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
 * along with this program; if not, see <https://www.gnu.org/licenses/>.
 */

#include <config.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <unistd.h>
#include <sys/stat.h>
#ifndef HAVE_W32_SYSTEM
# include <sys/wait.h>
# include <sys/types.h>
# include <signal.h>
# include <sys/utsname.h>
#endif
#include <npth.h>

#include "agent.h"
#include <assuan.h>
#include "../common/sysutils.h"
#include "../common/i18n.h"
#include "../common/zb32.h"

#ifdef _POSIX_OPEN_MAX
#define MAX_OPEN_FDS _POSIX_OPEN_MAX
#else
#define MAX_OPEN_FDS 20
#endif


/* Because access to the pinentry must be serialized (it is and shall
   be a global mutually exclusive dialog) we better timeout pending
   requests after some time.  1 minute seem to be a reasonable
   time. */
#define LOCK_TIMEOUT  (1*60)

/* Define the number of bits to use for a generated pin.  The
 * passphrase will be rendered as zbase32 which results for 150 bits
 * in a string of 30 characters.  That fits nicely into the 5
 * character blocking which pinentry can do.  128 bits would actually
 * be sufficient but can't be formatted nicely.  Please do not change
 * this value because pattern check files may let such passwords
 * always pass. */
#define DEFAULT_GENPIN_BITS 150

/* The assuan context of the current pinentry. */
static assuan_context_t entry_ctx;

/* A list of features of the current pinentry.  */
static struct
{
  /* The Pinentry support RS+US tabbing.  This means that a RS (0x1e)
   * starts a new tabbing block in which a US (0x1f) followed by a
   * colon marks a colon.  A pinentry can use this to pretty print
   * name value pairs.  */
  unsigned int tabbing:1;
} entry_features;


/* A mutex used to serialize access to the pinentry. */
static npth_mutex_t entry_lock;

/* The thread ID of the popup working thread. */
static npth_t  popup_tid;

/* A flag used in communication between the popup working thread and
   its stop function. */
static int popup_finished;



/* Data to be passed to our callbacks, */
struct entry_parm_s
{
  int lines;
  size_t size;
  unsigned char *buffer;
  int status;
  unsigned int constraints_flags;
};




/* This function must be called once to initialize this module.  This
   has to be done before a second thread is spawned.  We can't do the
   static initialization because Pth emulation code might not be able
   to do a static init; in particular, it is not possible for W32. */
void
initialize_module_call_pinentry (void)
{
  static int initialized;
  int err;

  if (!initialized)
    {
      err = npth_mutex_init (&entry_lock, NULL);
      if (err)
	log_fatal ("error initializing mutex: %s\n", strerror (err));

      initialized = 1;
    }
}



/* This function may be called to print information pertaining to the
   current state of this module to the log. */
void
agent_query_dump_state (void)
{
  log_info ("agent_query_dump_state: entry_ctx=%p pid=%ld popup_tid=%p\n",
            entry_ctx, (long)assuan_get_pid (entry_ctx), (void*)popup_tid);
}

/* Called to make sure that a popup window owned by the current
   connection gets closed. */
void
agent_reset_query (ctrl_t ctrl)
{
  if (entry_ctx && popup_tid && ctrl->pinentry_active)
    {
      agent_popup_message_stop (ctrl);
    }
}


/* Unlock the pinentry so that another thread can start one and
   disconnect that pinentry - we do this after the unlock so that a
   stalled pinentry does not block other threads.  Fixme: We should
   have a timeout in Assuan for the disconnect operation. */
static gpg_error_t
unlock_pinentry (ctrl_t ctrl, gpg_error_t rc)
{
  assuan_context_t ctx = entry_ctx;
  int err;

  if (rc)
    {
      if (DBG_IPC)
        log_debug ("error calling pinentry: %s <%s>\n",
                   gpg_strerror (rc), gpg_strsource (rc));

      /* Change the source of the error to pinentry so that the final
         consumer of the error code knows that the problem is with
         pinentry.  For backward compatibility we do not do that for
         some common error codes.  */
      switch (gpg_err_code (rc))
        {
        case GPG_ERR_NO_PIN_ENTRY:
        case GPG_ERR_CANCELED:
        case GPG_ERR_FULLY_CANCELED:
        case GPG_ERR_ASS_UNKNOWN_INQUIRE:
        case GPG_ERR_ASS_TOO_MUCH_DATA:
        case GPG_ERR_NO_PASSPHRASE:
        case GPG_ERR_BAD_PASSPHRASE:
        case GPG_ERR_BAD_PIN:
          break;

        case GPG_ERR_CORRUPTED_PROTECTION:
          /* This comes from gpg-agent.  */
          break;

        default:
          rc = gpg_err_make (GPG_ERR_SOURCE_PINENTRY, gpg_err_code (rc));
          break;
        }
    }

  if (--ctrl->pinentry_active == 0)
    {
      entry_ctx = NULL;
      err = npth_mutex_unlock (&entry_lock);
      if (err)
        {
          log_error ("failed to release the entry lock: %s\n", strerror (err));
          if (!rc)
            rc = gpg_error_from_errno (err);
        }
      assuan_release (ctx);
    }
  return rc;
}


/* Helper for at_fork_cb which can also be called by the parent to
 * show which envvars will be set.  */
static void
atfork_core (ctrl_t ctrl, int debug_mode)
{
  int iterator = 0;
  const char *name, *assname, *value;

  while ((name = session_env_list_stdenvnames (&iterator, &assname)))
    {
      /* For all new envvars (!ASSNAME) and the two medium old ones
       * which do have an assuan name but are conveyed using
       * environment variables, update the environment of the forked
       * process.  We also pass DISPLAY despite that --display is also
       * used when exec-ing the pinentry.  The reason is that for
       * example the qt5ct tool does not have any arguments and thus
       * relies on the DISPLAY envvar.  The use case here is a global
       * envvar like "QT_QPA_PLATFORMTHEME=qt5ct" which for example is
       * useful when using the Qt pinentry under GNOME or XFCE.
       */
      if (!assname
          || (!opt.keep_display && !strcmp (name, "DISPLAY"))
          || !strcmp (name, "XAUTHORITY")
          || !strcmp (name, "PINENTRY_USER_DATA"))
        {
          value = session_env_getenv (ctrl->session_env, name);
          if (value)
            {
              if (debug_mode)
                log_debug ("pinentry: atfork used setenv(%s,%s)\n",name,value);
              else
                gnupg_setenv (name, value, 1);
            }
        }
    }
}


/* To make sure we leave no secrets in our image after forking of the
   pinentry, we use this callback. */
static void
atfork_cb (void *opaque, int where)
{
  ctrl_t ctrl = opaque;

  if (!where)
    {
      gcry_control (GCRYCTL_TERM_SECMEM);
      atfork_core (ctrl, 0);
    }
}


/* Status line callback for the FEATURES status.  */
static gpg_error_t
getinfo_features_cb (void *opaque, const char *line)
{
  const char *args;
  char **tokens;
  int i;

  (void)opaque;

  if ((args = has_leading_keyword (line, "FEATURES")))
    {
      tokens = strtokenize (args, " ");
      if (!tokens)
        return gpg_error_from_syserror ();
      for (i=0; tokens[i]; i++)
        if (!strcmp (tokens[i], "tabbing"))
          entry_features.tabbing = 1;
      xfree (tokens);
    }

  return 0;
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
   that this function must always be used to acquire the lock for the
   pinentry - we will serialize _all_ pinentry calls.
 */
static gpg_error_t
start_pinentry (ctrl_t ctrl)
{
  int rc = 0;
  const char *full_pgmname;
  const char *pgmname;
  assuan_context_t ctx;
  const char *argv[5];
  assuan_fd_t no_close_list[3];
  int i;
  const char *tmpstr;
  unsigned long pinentry_pid;
  const char *value;
  struct timespec abstime;
  char *flavor_version;
  int err;

  if (ctrl->pinentry_active)
    {
      /* It's trying to use pinentry recursively.  In this situation,
         the thread holds ENTRY_LOCK already.  */
      ctrl->pinentry_active++;
      return 0;
    }

  npth_clock_gettime (&abstime);
  abstime.tv_sec += LOCK_TIMEOUT;
  err = npth_mutex_timedlock (&entry_lock, &abstime);
  if (err)
    {
      if (err == ETIMEDOUT)
	rc = gpg_error (GPG_ERR_TIMEOUT);
      else
	rc = gpg_error_from_errno (rc);
      log_error (_("failed to acquire the pinentry lock: %s\n"),
                 gpg_strerror (rc));
      return rc;
    }

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
         the Wine implementation does not flush stdin,stdout and stderr
         - see above.  Let's try to ignore the error. */
#ifndef HAVE_W32_SYSTEM
      return unlock_pinentry (ctrl, tmperr);
#endif
    }

  full_pgmname = opt.pinentry_program;
  if (!full_pgmname || !*full_pgmname)
    full_pgmname = gnupg_module_name (GNUPG_MODULE_NAME_PINENTRY);
  if ( !(pgmname = strrchr (full_pgmname, '/')))
    pgmname = full_pgmname;
  else
    pgmname++;

  /* OS X needs the entire file name in argv[0], so that it can locate
     the resource bundle.  For other systems we stick to the usual
     convention of supplying only the name of the program.  */
#ifdef __APPLE__
  argv[0] = full_pgmname;
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
  no_close_list[i] = ASSUAN_INVALID_FD;

  rc = assuan_new (&ctx);
  if (rc)
    {
      log_error ("can't allocate assuan context: %s\n", gpg_strerror (rc));
      return rc;
    }

  ctrl->pinentry_active = 1;
  entry_ctx = ctx;

  /* We don't want to log the pinentry communication to make the logs
     easier to read.  We might want to add a new debug option to enable
     pinentry logging.  */
#ifdef ASSUAN_NO_LOGGING
  assuan_set_flag (ctx, ASSUAN_NO_LOGGING, !opt.debug_pinentry);
#endif

  /* Connect to the pinentry and perform initial handshaking.  Note
     that atfork is used to change the environment for pinentry.  We
     start the server in detached mode to suppress the console window
     under Windows.  */
  rc = assuan_pipe_connect (entry_ctx, full_pgmname, argv,
			    no_close_list, atfork_cb, ctrl,
			    ASSUAN_PIPE_CONNECT_DETACHED);
  if (rc)
    {
      log_error ("can't connect to the PIN entry module '%s': %s\n",
                 full_pgmname, gpg_strerror (rc));
      return unlock_pinentry (ctrl, gpg_error (GPG_ERR_NO_PIN_ENTRY));
    }

  if (DBG_IPC)
    log_debug ("connection to PIN entry established\n");

  if (opt.debug_pinentry)
    atfork_core (ctrl, 1); /* Just show the envvars set after the fork.  */

  value = session_env_getenv (ctrl->session_env, "PINENTRY_USER_DATA");
  if (value != NULL)
    {
      char *optstr;
      if (asprintf (&optstr, "OPTION pinentry-user-data=%s", value) < 0 )
        return unlock_pinentry (ctrl, out_of_core ());
      rc = assuan_transact (entry_ctx, optstr, NULL, NULL, NULL, NULL, NULL,
			    NULL);
      xfree (optstr);
      if (rc && gpg_err_code (rc) != GPG_ERR_UNKNOWN_OPTION)
        return unlock_pinentry (ctrl, rc);
    }

  rc = assuan_transact (entry_ctx,
                        opt.no_grab? "OPTION no-grab":"OPTION grab",
                        NULL, NULL, NULL, NULL, NULL, NULL);
  if (rc)
    return unlock_pinentry (ctrl, rc);

  value = session_env_getenv (ctrl->session_env, "GPG_TTY");
  if (value)
    {
      char *optstr;
      if (asprintf (&optstr, "OPTION ttyname=%s", value) < 0 )
        return unlock_pinentry (ctrl, out_of_core ());
      rc = assuan_transact (entry_ctx, optstr, NULL, NULL, NULL, NULL, NULL,
			    NULL);
      xfree (optstr);
      if (rc)
        return unlock_pinentry (ctrl, rc);
    }
  value = session_env_getenv (ctrl->session_env, "TERM");
  if (value && *value)
    {
      char *optstr;
      if (asprintf (&optstr, "OPTION ttytype=%s", value) < 0 )
        return unlock_pinentry (ctrl, out_of_core ());
      rc = assuan_transact (entry_ctx, optstr, NULL, NULL, NULL, NULL, NULL,
			    NULL);
      xfree (optstr);
      if (rc)
        return unlock_pinentry (ctrl, rc);
    }
  if (ctrl->lc_ctype)
    {
      char *optstr;
      if (asprintf (&optstr, "OPTION lc-ctype=%s", ctrl->lc_ctype) < 0 )
        return unlock_pinentry (ctrl, out_of_core ());
      rc = assuan_transact (entry_ctx, optstr, NULL, NULL, NULL, NULL, NULL,
			    NULL);
      xfree (optstr);
      if (rc)
        return unlock_pinentry (ctrl, rc);
    }
  if (ctrl->lc_messages)
    {
      char *optstr;
      if (asprintf (&optstr, "OPTION lc-messages=%s", ctrl->lc_messages) < 0 )
        return unlock_pinentry (ctrl, out_of_core ());
      rc = assuan_transact (entry_ctx, optstr, NULL, NULL, NULL, NULL, NULL,
			    NULL);
      xfree (optstr);
      if (rc)
        return unlock_pinentry (ctrl, rc);
    }


  if (opt.allow_external_cache)
    {
      /* Indicate to the pinentry that it may read from an external cache.

         It is essential that the pinentry respect this.  If the
         cached password is not up to date and retry == 1, then, using
         a version of GPG Agent that doesn't support this, won't issue
         another pin request and the user won't get a chance to
         correct the password.  */
      rc = assuan_transact (entry_ctx, "OPTION allow-external-password-cache",
                            NULL, NULL, NULL, NULL, NULL, NULL);
      if (rc && gpg_err_code (rc) != GPG_ERR_UNKNOWN_OPTION)
        return unlock_pinentry (ctrl, rc);
    }

  if (opt.allow_emacs_pinentry)
    {
      /* Indicate to the pinentry that it may read passphrase through
	 Emacs minibuffer, if possible.  */
      rc = assuan_transact (entry_ctx, "OPTION allow-emacs-prompt",
                            NULL, NULL, NULL, NULL, NULL, NULL);
      if (rc && gpg_err_code (rc) != GPG_ERR_UNKNOWN_OPTION)
        return unlock_pinentry (ctrl, rc);
    }


  {
    /* Provide a few default strings for use by the pinentries.  This
       may help a pinentry to avoid implementing localization code.  */
    static const struct { const char *key, *value; int what; } tbl[] = {
      /* TRANSLATORS: These are labels for buttons etc used in
         Pinentries.  An underscore indicates that the next letter
         should be used as an accelerator.  Double the underscore for
         a literal one.  The actual to be translated text starts after
         the second vertical bar.  Note that gpg-agent has been set to
         utf-8 so that the strings are in the expected encoding.  */
      { "ok",     N_("|pinentry-label|_OK") },
      { "cancel", N_("|pinentry-label|_Cancel") },
      { "yes",    N_("|pinentry-label|_Yes") },
      { "no",     N_("|pinentry-label|_No") },
      { "prompt", N_("|pinentry-label|PIN:") },
      { "pwmngr", N_("|pinentry-label|_Save in password manager"), 1 },
      { "cf-visi",N_("Do you really want to make your "
                     "passphrase visible on the screen?") },
      { "tt-visi",N_("|pinentry-tt|Make passphrase visible") },
      { "tt-hide",N_("|pinentry-tt|Hide passphrase") },
      { "capshint", N_("Caps Lock is on") },
      { NULL, NULL}
    };
    char *optstr;
    int idx;
    const char *s, *s2;

    for (idx=0; tbl[idx].key; idx++)
      {
        if (!opt.allow_external_cache && tbl[idx].what == 1)
          continue;  /* No need for it.  */
        s = L_(tbl[idx].value);
        if (*s == '|' && (s2=strchr (s+1,'|')))
          s = s2+1;
        if (asprintf (&optstr, "OPTION default-%s=%s", tbl[idx].key, s) < 0 )
          return unlock_pinentry (ctrl, out_of_core ());
        assuan_transact (entry_ctx, optstr, NULL, NULL, NULL, NULL, NULL,
                         NULL);
        xfree (optstr);
      }
  }

  /* Tell the pinentry that we would prefer that the given character
     is used as the invisible character by the entry widget.  */
  if (opt.pinentry_invisible_char)
    {
      char *optstr;
      if ((optstr = xtryasprintf ("OPTION invisible-char=%s",
                                  opt.pinentry_invisible_char)))
        {
          assuan_transact (entry_ctx, optstr, NULL, NULL, NULL, NULL, NULL,
                           NULL);
          /* We ignore errors because this is just a fancy thing and
             older pinentries do not support this feature.  */
          xfree (optstr);
        }
    }

  if (opt.pinentry_timeout)
    {
      char *optstr;
      if ((optstr = xtryasprintf ("SETTIMEOUT %lu", opt.pinentry_timeout)))
        {
          assuan_transact (entry_ctx, optstr, NULL, NULL, NULL, NULL, NULL,
                           NULL);
          /* We ignore errors because this is just a fancy thing.  */
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

  /* Tell Pinentry about our client.  */
  if (ctrl->client_pid)
    {
      char *optstr;
      const char *nodename = "";

#ifndef HAVE_W32_SYSTEM
      struct utsname utsbuf;
      if (!uname (&utsbuf))
        nodename = utsbuf.nodename;
#endif /*!HAVE_W32_SYSTEM*/

      if ((optstr = xtryasprintf ("OPTION owner=%lu %s",
                                  ctrl->client_pid, nodename)))
        {
          assuan_transact (entry_ctx, optstr, NULL, NULL, NULL, NULL, NULL,
                           NULL);
          /* We ignore errors because this is just a fancy thing and
             older pinentries do not support this feature.  */
          xfree (optstr);
        }
    }


  /* Ask the pinentry for its version and flavor and store that as a
   * string in MB.  This information is useful for helping users to
   * figure out Pinentry problems.  Note that "flavor" may also return
   * a status line with the features; we use a dedicated handler for
   * that.  */
  {
    membuf_t mb;

    init_membuf (&mb, 256);
    if (assuan_transact (entry_ctx, "GETINFO flavor",
                         put_membuf_cb, &mb,
                         NULL, NULL,
                         getinfo_features_cb, NULL))
      put_membuf_str (&mb, "unknown");
    put_membuf_str (&mb, " ");
    if (assuan_transact (entry_ctx, "GETINFO version",
                         put_membuf_cb, &mb, NULL, NULL, NULL, NULL))
      put_membuf_str (&mb, "unknown");
    put_membuf_str (&mb, " ");
    if (assuan_transact (entry_ctx, "GETINFO ttyinfo",
                         put_membuf_cb, &mb, NULL, NULL, NULL, NULL))
      put_membuf_str (&mb, "? ? ?");
    put_membuf (&mb, "", 1);
    flavor_version = get_membuf (&mb, NULL);
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
      rc = agent_inq_pinentry_launched (ctrl, pinentry_pid, flavor_version);
      if (gpg_err_code (rc) == GPG_ERR_CANCELED
          || gpg_err_code (rc) == GPG_ERR_FULLY_CANCELED)
        return unlock_pinentry (ctrl, gpg_err_make (GPG_ERR_SOURCE_DEFAULT,
                                                    gpg_err_code (rc)));
      rc = 0;
    }

  xfree (flavor_version);

  return rc;
}


/* Returns True if the pinentry is currently active. If WAITSECONDS is
   greater than zero the function will wait for this many seconds
   before returning.  */
int
pinentry_active_p (ctrl_t ctrl, int waitseconds)
{
  int err;
  (void)ctrl;

  if (waitseconds > 0)
    {
      struct timespec abstime;
      int rc;

      npth_clock_gettime (&abstime);
      abstime.tv_sec += waitseconds;
      err = npth_mutex_timedlock (&entry_lock, &abstime);
      if (err)
        {
          if (err == ETIMEDOUT)
            rc = gpg_error (GPG_ERR_TIMEOUT);
          else
            rc = gpg_error (GPG_ERR_INTERNAL);
          return rc;
        }
    }
  else
    {
      err = npth_mutex_trylock (&entry_lock);
      if (err)
        return gpg_error (GPG_ERR_LOCKED);
    }

  err = npth_mutex_unlock (&entry_lock);
  if (err)
    log_error ("failed to release the entry lock at %d: %s\n", __LINE__,
	       strerror (errno));
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
   an out of memory status.  Parsing stops at the end of the string or
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


/* Generate a random passphrase in zBase32 encoding (RFC-6189) to be
 * used by Pinentry to suggest a passphrase.  Note that we have the
 * same algorithm in gpg.c for --gen-random at level 30.  It is
 * important that we always output exactly 30 characters to match the
 * special exception we have in the pattern file for symmetric
 * encryption.  */
static char *
generate_pin (void)
{
  unsigned int nbits = DEFAULT_GENPIN_BITS;
  size_t nbytes = nbytes = (nbits + 7) / 8;
  void *rand;
  char *generated;

   rand = gcry_random_bytes_secure (nbytes, GCRY_STRONG_RANDOM);
  if (!rand)
    {
      log_error ("failed to generate random pin\n");
      return NULL;
    }

  generated = zb32_encode (rand, nbits);
  gcry_free (rand);
  return generated;
}


/* Handle inquiries. */
struct inq_cb_parm_s
{
  assuan_context_t ctx;
  unsigned int flags;  /* CHECK_CONSTRAINTS_... */
  int genpinhash_valid;
  char genpinhash[32]; /* Hash of the last generated pin.  */
};


/* Return true if PIN is indentical to the last generated pin.  */
static int
is_generated_pin (struct inq_cb_parm_s *parm, const char *pin)
{
  char hashbuf[32];

  if (!parm->genpinhash_valid)
    return 0;
  if (!*pin)
    return 0;
  /* Note that we compare the hash so that we do not need to save the
   * generated PIN longer than needed. */
  gcry_md_hash_buffer (GCRY_MD_SHA256, hashbuf, pin, strlen (pin));

  if (!memcmp (hashbuf, parm->genpinhash, 32))
    return 1; /* yes, it is the same.  */

  return 0;
}


static gpg_error_t
inq_cb (void *opaque, const char *line)
{
  struct inq_cb_parm_s *parm = opaque;
  gpg_error_t err;
  const char *s;
  char *pin;
  int percent;
  char numbuf[20];

  if ((s = has_leading_keyword (line, "QUALITY")))
    {
      pin = unescape_passphrase_string (s);
      if (!pin)
        err = gpg_error_from_syserror ();
      else
        {
          percent = estimate_passphrase_quality (pin);
          if (check_passphrase_constraints (NULL, pin, parm->flags, NULL))
            percent = -percent;
          snprintf (numbuf, sizeof numbuf, "%d", percent);
          err = assuan_send_data (parm->ctx, numbuf, strlen (numbuf));
          xfree (pin);
        }
    }
  else if ((s = has_leading_keyword (line, "CHECKPIN")))
    {
      char *errtext = NULL;
      size_t errtextlen;

      if (!opt.enforce_passphrase_constraints)
        {
          log_error ("unexpected inquiry 'CHECKPIN' without enforced "
                     "passphrase constraints\n");
          err = gpg_error (GPG_ERR_ASS_UNEXPECTED_CMD);
          goto leave;
        }

      pin = unescape_passphrase_string (s);
      if (!pin)
        err = gpg_error_from_syserror ();
      else
        {
          if (!is_generated_pin (parm, pin)
              && check_passphrase_constraints (NULL, pin,parm->flags, &errtext))
            {
              if (errtext)
                {
                  /* Unescape the percent-escaped errtext because
                     assuan_send_data escapes it again. */
                  errtextlen = percent_unescape_inplace (errtext, 0);
                  err = assuan_send_data (parm->ctx, errtext, errtextlen);
                }
              else
                {
                  log_error ("passphrase check failed without error text\n");
                  err = gpg_error (GPG_ERR_GENERAL);
                }
            }
          else
            {
              err = assuan_send_data (parm->ctx, NULL, 0);
            }
          xfree (errtext);
          xfree (pin);
        }
    }
  else if ((s = has_leading_keyword (line, "GENPIN")))
    {
      int wasconf;

      parm->genpinhash_valid = 0;
      pin = generate_pin ();
      if (!pin)
        {
          log_error ("failed to generate a passphrase\n");
          err = gpg_error (GPG_ERR_GENERAL);
          goto leave;
        }
      wasconf = assuan_get_flag (entry_ctx, ASSUAN_CONFIDENTIAL);
      assuan_begin_confidential (parm->ctx);
      err = assuan_send_data (parm->ctx, pin, strlen (pin));
      if (!wasconf)
        assuan_end_confidential (parm->ctx);
      gcry_md_hash_buffer (GCRY_MD_SHA256, parm->genpinhash, pin, strlen (pin));
      parm->genpinhash_valid = 1;
      xfree (pin);
    }
  else
    {
      log_error ("unsupported inquiry '%s' from pinentry\n", line);
      err = gpg_error (GPG_ERR_ASS_UNKNOWN_INQUIRE);
    }

 leave:
  return err;
}


/* Helper to setup pinentry for genpin action. */
static gpg_error_t
setup_genpin (ctrl_t ctrl)
{
  gpg_error_t err;
  char line[ASSUAN_LINELENGTH];
  char *tmpstr, *tmpstr2;
  const char *tooltip;

  (void)ctrl;

  /* TRANSLATORS: This string is displayed by Pinentry as the label
     for generating a passphrase.  */
  tmpstr = try_percent_escape (L_("Suggest"), "\t\r\n\f\v");
  snprintf (line, DIM(line), "SETGENPIN %s", tmpstr? tmpstr:"");
  xfree (tmpstr);
  err = assuan_transact (entry_ctx, line, NULL, NULL, NULL, NULL, NULL, NULL);
  if (gpg_err_code (err) == 103 /*(Old assuan error code)*/
      || gpg_err_code (err) == GPG_ERR_ASS_UNKNOWN_CMD)
    ; /* Ignore Unknown Command from old Pinentry versions.  */
  else if (err)
    return err;

  tmpstr2 = gnupg_get_help_string ("pinentry.genpin.tooltip", 0);
  if (tmpstr2)
    tooltip = tmpstr2;
  else
    {
      /* TRANSLATORS: This string is a tooltip, shown by pinentry when
         hovering over the generate button.  Please use an appropriate
         string to describe what this is about.  The length of the
         tooltip is limited to about 900 characters.  If you do not
         translate this entry, a default English text (see source)
         will be used.  The strcmp thingy is there to detect a
         non-translated string.  */
      tooltip = L_("pinentry.genpin.tooltip");
      if (!strcmp ("pinentry.genpin.tooltip", tooltip))
        tooltip = "Suggest a random passphrase.";
    }
  tmpstr = try_percent_escape (tooltip, "\t\r\n\f\v");
  xfree (tmpstr2);
  snprintf (line, DIM(line), "SETGENPIN_TT %s", tmpstr? tmpstr:"");
  xfree (tmpstr);
  err = assuan_transact (entry_ctx, line, NULL, NULL, NULL, NULL, NULL, NULL);
  if (gpg_err_code (err) == 103 /*(Old assuan error code)*/
          || gpg_err_code (err) == GPG_ERR_ASS_UNKNOWN_CMD)
    ; /* Ignore Unknown Command from old pinentry versions.  */
  else if (err)
    return err;

  return 0;
}


/* Helper to setup pinentry for formatted passphrase. */
static gpg_error_t
setup_formatted_passphrase (ctrl_t ctrl)
{
  static const struct { const char *key, *help_id, *value; } tbl[] = {
    /* TRANSLATORS: This is a text shown by pinentry if the option
        for formatted passphrase is enabled.  The length is
        limited to about 900 characters.  */
    { "hint",  "pinentry.formatted_passphrase.hint",
      N_("Note: The blanks are not part of the passphrase.") },
    { NULL, NULL }
  };

  gpg_error_t rc;
  char line[ASSUAN_LINELENGTH];
  int idx;
  char *tmpstr;
  const char *s;
  char *escapedstr;

  (void)ctrl;

  if (opt.pinentry_formatted_passphrase)
    {
      snprintf (line, DIM(line), "OPTION formatted-passphrase");
      rc = assuan_transact (entry_ctx, line, NULL, NULL, NULL, NULL, NULL,
                            NULL);
      if (rc && gpg_err_code (rc) != GPG_ERR_UNKNOWN_OPTION)
        return rc;

      for (idx=0; tbl[idx].key; idx++)
        {
          tmpstr = gnupg_get_help_string (tbl[idx].help_id, 0);
          if (tmpstr)
            s = tmpstr;
          else
            s = L_(tbl[idx].value);
          escapedstr = try_percent_escape (s, "\t\r\n\f\v");
          xfree (tmpstr);
          if (escapedstr && *escapedstr)
            {
              snprintf (line, DIM(line), "OPTION formatted-passphrase-%s=%s",
                        tbl[idx].key, escapedstr);
              rc = assuan_transact (entry_ctx, line,
                                    NULL, NULL, NULL, NULL, NULL, NULL);
            }
          else
            rc = 0;
          xfree (escapedstr);
          if (rc && gpg_err_code (rc) != GPG_ERR_UNKNOWN_OPTION)
            return rc;
        }
    }

  return 0;
}


/* Helper to setup pinentry for enforced passphrase constraints. */
static gpg_error_t
setup_enforced_constraints (ctrl_t ctrl)
{
  static const struct { const char *key, *help_id, *value; } tbl[] = {
    { "hint-short", "pinentry.constraints.hint.short", NULL },
    { "hint-long",  "pinentry.constraints.hint.long", NULL },
    /* TRANSLATORS: This is a text shown by pinentry as title of a dialog
       telling the user that the entered new passphrase does not satisfy
       the passphrase constraints.  Please keep it short. */
    { "error-title", NULL, N_("Passphrase Not Allowed") },
    { NULL, NULL }
  };

  gpg_error_t rc;
  char line[ASSUAN_LINELENGTH];
  int idx;
  char *tmpstr;
  const char *s;
  char *escapedstr;

  (void)ctrl;

  if (opt.enforce_passphrase_constraints)
    {
      snprintf (line, DIM(line), "OPTION constraints-enforce");
      rc = assuan_transact (entry_ctx, line, NULL, NULL, NULL, NULL, NULL,
                            NULL);
      if (rc && gpg_err_code (rc) != GPG_ERR_UNKNOWN_OPTION)
        return rc;

      for (idx=0; tbl[idx].key; idx++)
        {
          tmpstr = gnupg_get_help_string (tbl[idx].help_id, 0);
          if (tmpstr)
            s = tmpstr;
          else if (tbl[idx].value)
            s = L_(tbl[idx].value);
          else
            {
              log_error ("no help string found for %s\n", tbl[idx].help_id);
              continue;
            }
          escapedstr = try_percent_escape (s, "\t\r\n\f\v");
          xfree (tmpstr);
          if (escapedstr && *escapedstr)
            {
              snprintf (line, DIM(line), "OPTION constraints-%s=%s",
                        tbl[idx].key, escapedstr);
              rc = assuan_transact (entry_ctx, line,
                                    NULL, NULL, NULL, NULL, NULL, NULL);
            }
          else
            rc = 0;  /* Ignore an empty string (would give an IPC error).  */
          xfree (escapedstr);
          if (rc && gpg_err_code (rc) != GPG_ERR_UNKNOWN_OPTION)
            return rc;
        }
    }

  return 0;
}


/* Helper for agent_askpin and agent_get_passphrase.  */
static gpg_error_t
setup_qualitybar (ctrl_t ctrl)
{
  int rc;
  char line[ASSUAN_LINELENGTH];
  char *tmpstr, *tmpstr2;
  const char *tooltip;

  (void)ctrl;

  /* TRANSLATORS: This string is displayed by Pinentry as the label
     for the quality bar.  */
  tmpstr = try_percent_escape (L_("Quality:"), "\t\r\n\f\v");
  snprintf (line, DIM(line), "SETQUALITYBAR %s", tmpstr? tmpstr:"");
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
      tooltip =  L_("pinentry.qualitybar.tooltip");
      if (!strcmp ("pinentry.qualitybar.tooltip", tooltip))
        tooltip = ("The quality of the text entered above.\n"
                   "Please ask your administrator for "
                   "details about the criteria.");
    }
  tmpstr = try_percent_escape (tooltip, "\t\r\n\f\v");
  xfree (tmpstr2);
  snprintf (line, DIM(line), "SETQUALITYBAR_TT %s", tmpstr? tmpstr:"");
  xfree (tmpstr);
  rc = assuan_transact (entry_ctx, line, NULL, NULL, NULL, NULL, NULL, NULL);
  if (rc == 103 /*(Old assuan error code)*/
          || gpg_err_code (rc) == GPG_ERR_ASS_UNKNOWN_CMD)
    ; /* Ignore Unknown Command from old pinentry versions.  */
  else if (rc)
    return rc;

  return 0;
}

/* Check the button_info line for a close action.  Also check for the
   PIN_REPEATED flag.  */
static gpg_error_t
pinentry_status_cb (void *opaque, const char *line)
{
  unsigned int *flag = opaque;
  const char *args;

  if ((args = has_leading_keyword (line, "BUTTON_INFO")))
    {
      if (!strcmp (args, "close"))
        *flag |= PINENTRY_STATUS_CLOSE_BUTTON;
    }
  else if (has_leading_keyword (line, "PIN_REPEATED"))
    {
      *flag |= PINENTRY_STATUS_PIN_REPEATED;
    }
  else if (has_leading_keyword (line, "PASSWORD_FROM_CACHE"))
    {
      *flag |= PINENTRY_STATUS_PASSWORD_FROM_CACHE;
    }

  return 0;
}


/* Build a SETDESC command line.  This is a dedicated function so that
 * it can remove control characters which are not supported by the
 * current Pinentry.  */
static void
build_cmd_setdesc (char *line, size_t linelen, const char *desc)
{
  char *src, *dst;

  snprintf (line, linelen, "SETDESC %s", desc);
  if (!entry_features.tabbing)
    {
      /* Remove RS and US.  */
      for (src=dst=line; *src; src++)
        if (!strchr ("\x1e\x1f", *src))
          *dst++ = *src;
      *dst = 0;
    }
}


/* Ask pinentry to get a pin by "GETPIN" command, spawning a thread
 * detecting the socket's EOF.   */
static gpg_error_t
do_getpin (ctrl_t ctrl, struct entry_parm_s *parm)
{
  gpg_error_t rc;
  int wasconf;
  struct inq_cb_parm_s inq_cb_parm;

  (void)ctrl;

  inq_cb_parm.ctx = entry_ctx;
  inq_cb_parm.flags = parm->constraints_flags;
  inq_cb_parm.genpinhash_valid = 0;

  wasconf = assuan_get_flag (entry_ctx, ASSUAN_CONFIDENTIAL);
  assuan_begin_confidential (entry_ctx);
  rc = assuan_transact (entry_ctx, "GETPIN", getpin_cb, parm,
                        inq_cb, &inq_cb_parm,
                        pinentry_status_cb, &parm->status);
  if (!wasconf)
    assuan_end_confidential (entry_ctx);

  if (!rc && parm->buffer && is_generated_pin (&inq_cb_parm, parm->buffer))
    parm->status |= PINENTRY_STATUS_PASSWORD_GENERATED;
  else
    parm->status &= ~PINENTRY_STATUS_PASSWORD_GENERATED;

  /* Most pinentries out in the wild return the old Assuan error code
     for canceled which gets translated to an assuan Cancel error and
     not to the code for a user cancel.  Fix this here. */
  if (rc && gpg_err_source (rc) && gpg_err_code (rc) == GPG_ERR_ASS_CANCELED)
    rc = gpg_err_make (gpg_err_source (rc), GPG_ERR_CANCELED);
  /* Change error code in case the window close button was clicked
     to cancel the operation.  */
  if ((parm->status & PINENTRY_STATUS_CLOSE_BUTTON)
      && gpg_err_code (rc) == GPG_ERR_CANCELED)
    rc = gpg_err_make (gpg_err_source (rc), GPG_ERR_FULLY_CANCELED);

  return rc;
}



/* Call the Entry and ask for the PIN.  We do check for a valid PIN
   number here and repeat it as long as we have invalid formed
   numbers.  KEYINFO and CACHE_MODE are used to tell pinentry something
   about the key. */
gpg_error_t
agent_askpin (ctrl_t ctrl,
              const char *desc_text, const char *prompt_text,
              const char *initial_errtext,
              struct pin_entry_info_s *pininfo,
              const char *keyinfo, cache_mode_t cache_mode)
{
  gpg_error_t rc;
  char line[ASSUAN_LINELENGTH];
  struct entry_parm_s parm;
  const char *errtext = NULL;
  int is_pin = 0;
  int is_generated;

  if (opt.batch)
    return 0; /* fixme: we should return BAD PIN */

  if (ctrl->pinentry_mode != PINENTRY_MODE_ASK)
    {
      if (ctrl->pinentry_mode == PINENTRY_MODE_CANCEL)
        return gpg_error (GPG_ERR_CANCELED);
      if (ctrl->pinentry_mode == PINENTRY_MODE_LOOPBACK)
        {
	  unsigned char *passphrase;
	  size_t size;

	  *pininfo->pin = 0; /* Reset the PIN. */
	  rc = pinentry_loopback (ctrl, "PASSPHRASE", &passphrase, &size,
                                  pininfo->max_length - 1);
	  if (rc)
	    return rc;

	  memcpy(&pininfo->pin, passphrase, size);
	  xfree(passphrase);
	  pininfo->pin[size] = 0;
	  if (pininfo->check_cb)
	    {
	      /* More checks by utilizing the optional callback. */
	      pininfo->cb_errtext = NULL;
	      rc = pininfo->check_cb (pininfo);
	    }
	  return rc;
	}
      return gpg_error(GPG_ERR_NO_PIN_ENTRY);
    }

  if (!pininfo || pininfo->max_length < 1)
    return gpg_error (GPG_ERR_INV_VALUE);
  if (!desc_text && pininfo->min_digits)
    desc_text = L_("Please enter your PIN, so that the secret key "
                   "can be unlocked for this session");
  else if (!desc_text)
    desc_text = L_("Please enter your passphrase, so that the secret key "
                   "can be unlocked for this session");

  if (prompt_text)
    is_pin = !!strstr (prompt_text, "PIN");
  else
    is_pin = desc_text && strstr (desc_text, "PIN");

  rc = start_pinentry (ctrl);
  if (rc)
    return rc;

  /* If we have a KEYINFO string and are normal, user, or ssh cache
     mode, we tell that the Pinentry so it may use it for own caching
     purposes.  Most pinentries won't have this implemented and thus
     we do not error out in this case.  */
  if (keyinfo && (cache_mode == CACHE_MODE_NORMAL
                  || cache_mode == CACHE_MODE_USER
                  || cache_mode == CACHE_MODE_SSH))
    snprintf (line, DIM(line), "SETKEYINFO %c/%s",
	      cache_mode == CACHE_MODE_USER? 'u' :
	      cache_mode == CACHE_MODE_SSH? 's' : 'n',
	      keyinfo);
  else
    snprintf (line, DIM(line), "SETKEYINFO --clear");

  rc = assuan_transact (entry_ctx, line,
			NULL, NULL, NULL, NULL, NULL, NULL);
  if (rc && gpg_err_code (rc) != GPG_ERR_ASS_UNKNOWN_CMD)
    return unlock_pinentry (ctrl, rc);

  build_cmd_setdesc (line, DIM(line), desc_text);
  rc = assuan_transact (entry_ctx, line, NULL, NULL, NULL, NULL, NULL, NULL);
  if (rc)
    return unlock_pinentry (ctrl, rc);

  snprintf (line, DIM(line), "SETPROMPT %s",
            prompt_text? prompt_text : is_pin? L_("PIN:") : L_("Passphrase:"));
  rc = assuan_transact (entry_ctx, line, NULL, NULL, NULL, NULL, NULL, NULL);
  if (rc)
    return unlock_pinentry (ctrl, rc);

  /* If a passphrase quality indicator has been requested and a
     minimum passphrase length has not been disabled, send the command
     to the pinentry.  */
  if (pininfo->with_qualitybar && opt.min_passphrase_len )
    {
      rc = setup_qualitybar (ctrl);
      if (rc)
        return unlock_pinentry (ctrl, rc);
    }

  if (initial_errtext)
    {
      snprintf (line, DIM(line), "SETERROR %s", initial_errtext);
      rc = assuan_transact (entry_ctx, line,
                            NULL, NULL, NULL, NULL, NULL, NULL);
      if (rc)
        return unlock_pinentry (ctrl, rc);
    }

  if (pininfo->with_repeat)
    {
      snprintf (line, DIM(line), "SETREPEATERROR %s",
                L_("does not match - try again"));
      rc = assuan_transact (entry_ctx, line,
                            NULL, NULL, NULL, NULL, NULL, NULL);
      if (rc)
        pininfo->with_repeat = 0; /* Pinentry does not support it.  */
    }
  pininfo->repeat_okay = 0;
  pininfo->status = 0;

  for (;pininfo->failed_tries < pininfo->max_tries; pininfo->failed_tries++)
    {
      memset (&parm, 0, sizeof parm);
      parm.size = pininfo->max_length;
      *pininfo->pin = 0; /* Reset the PIN. */
      parm.buffer = (unsigned char*)pininfo->pin;
      parm.constraints_flags = pininfo->constraints_flags;

      if (errtext)
        {
          /* TRANSLATORS: The string is appended to an error message in
             the pinentry.  The %s is the actual error message, the
             two %d give the current and maximum number of tries.
             Do not translate the "SETERROR" keyword. */
          snprintf (line, DIM(line), L_("SETERROR %s (try %d of %d)"),
                    errtext, pininfo->failed_tries+1, pininfo->max_tries);
          rc = assuan_transact (entry_ctx, line,
                                NULL, NULL, NULL, NULL, NULL, NULL);
          if (rc)
            return unlock_pinentry (ctrl, rc);
          errtext = NULL;
        }

      if (pininfo->with_repeat)
        {
          snprintf (line, DIM(line), "SETREPEAT %s", L_("Repeat:"));
          rc = assuan_transact (entry_ctx, line,
                                NULL, NULL, NULL, NULL, NULL, NULL);
          if (rc)
            return unlock_pinentry (ctrl, rc);
        }

      rc = do_getpin (ctrl, &parm);
      pininfo->status = parm.status;
      is_generated = !!(parm.status & PINENTRY_STATUS_PASSWORD_GENERATED);

      if (gpg_err_code (rc) == GPG_ERR_ASS_TOO_MUCH_DATA)
        errtext = is_pin? L_("PIN too long")
                        : L_("Passphrase too long");
      else if (rc)
        return unlock_pinentry (ctrl, rc);

      if (!errtext && pininfo->min_digits && !is_generated)
        {
          /* do some basic checks on the entered PIN. */
          if (!all_digitsp (pininfo->pin))
            errtext = L_("Invalid characters in PIN");
          else if (pininfo->max_digits
                   && strlen (pininfo->pin) > pininfo->max_digits)
            errtext = L_("PIN too long");
          else if (strlen (pininfo->pin) < pininfo->min_digits)
            errtext = L_("PIN too short");
        }

      if (!errtext && pininfo->check_cb && !is_generated)
        {
          /* More checks by utilizing the optional callback. */
          pininfo->cb_errtext = NULL;
          rc = pininfo->check_cb (pininfo);
          /* When pinentry cache causes an error, return now.  */
          if (rc
              && (pininfo->status & PINENTRY_STATUS_PASSWORD_FROM_CACHE))
            return unlock_pinentry (ctrl, rc);

          if (gpg_err_code (rc) == GPG_ERR_BAD_PASSPHRASE)
            {
              if (pininfo->cb_errtext)
                errtext = pininfo->cb_errtext;
              else if (gpg_err_code (rc) == GPG_ERR_BAD_PASSPHRASE
                       || gpg_err_code (rc) == GPG_ERR_BAD_PIN)
                errtext = (is_pin? L_("Bad PIN") : L_("Bad Passphrase"));
            }
          else if (rc)
            return unlock_pinentry (ctrl, rc);
        }

      if (!errtext)
        {
          if (pininfo->with_repeat
              && (pininfo->status & PINENTRY_STATUS_PIN_REPEATED))
            pininfo->repeat_okay = 1;
          return unlock_pinentry (ctrl, 0); /* okay, got a PIN or passphrase */
        }

      if ((pininfo->status & PINENTRY_STATUS_PASSWORD_FROM_CACHE))
        {
          /* The password was read from the cache.  Don't count this
             against the retry count.  */
          pininfo->failed_tries --;
        }
    }

  return unlock_pinentry (ctrl, gpg_error (pininfo->min_digits? GPG_ERR_BAD_PIN
                          : GPG_ERR_BAD_PASSPHRASE));
}



/* Ask for the passphrase using the supplied arguments.  The returned
   passphrase needs to be freed by the caller.  PININFO is optional
   and can be used to have constraints checinkg while the pinentry
   dialog is open (like what we do in agent_askpin).  This is very
   similar to agent_akpin and we should eventually merge the two
   functions. */
int
agent_get_passphrase (ctrl_t ctrl,
                      char **retpass, const char *desc, const char *prompt,
                      const char *errtext, int with_qualitybar,
		      const char *keyinfo, cache_mode_t cache_mode,
                      struct pin_entry_info_s *pininfo)
{
  int rc;
  int is_pin;
  int is_generated;
  char line[ASSUAN_LINELENGTH];
  struct entry_parm_s parm;

  *retpass = NULL;
  if (opt.batch)
    return gpg_error (GPG_ERR_BAD_PASSPHRASE);

  if (ctrl->pinentry_mode != PINENTRY_MODE_ASK)
    {
      unsigned char *passphrase;
      size_t size;

      if (ctrl->pinentry_mode == PINENTRY_MODE_CANCEL)
        return gpg_error (GPG_ERR_CANCELED);

      if (ctrl->pinentry_mode == PINENTRY_MODE_LOOPBACK && pininfo)
        {
	  *pininfo->pin = 0; /* Reset the PIN. */
	  rc = pinentry_loopback (ctrl, "PASSPHRASE",
                                  &passphrase, &size,
                                  pininfo->max_length - 1);
          if (rc)
            return rc;

	  memcpy (&pininfo->pin, passphrase, size);
          wipememory (passphrase, size);
	  xfree (passphrase);
	  pininfo->pin[size] = 0;
	  if (pininfo->check_cb)
	    {
	      /* More checks by utilizing the optional callback. */
	      pininfo->cb_errtext = NULL;
	      rc = pininfo->check_cb (pininfo);
	    }
	  return rc;

        }
      else if (ctrl->pinentry_mode == PINENTRY_MODE_LOOPBACK)
        {
          /* Legacy variant w/o PININFO.  */
	  return pinentry_loopback (ctrl, "PASSPHRASE",
				    (unsigned char **)retpass, &size,
                                    MAX_PASSPHRASE_LEN);
        }

      return gpg_error (GPG_ERR_NO_PIN_ENTRY);
    }

  rc = start_pinentry (ctrl);
  if (rc)
    return rc;

  /* Set IS_PIN and if needed a default prompt.  */
  if (prompt)
    is_pin = !!strstr (prompt, "PIN");
  else
    {
      is_pin = desc && strstr (desc, "PIN");
      prompt = is_pin? L_("PIN:"): L_("Passphrase:");
    }

  /* If we have a KEYINFO string and are normal, user, or ssh cache
     mode, we tell that the Pinentry so it may use it for own caching
     purposes.  Most pinentries won't have this implemented and thus
     we do not error out in this case.  */
  if (keyinfo && (cache_mode == CACHE_MODE_NORMAL
                  || cache_mode == CACHE_MODE_USER
                  || cache_mode == CACHE_MODE_SSH))
    snprintf (line, DIM(line), "SETKEYINFO %c/%s",
	      cache_mode == CACHE_MODE_USER? 'u' :
	      cache_mode == CACHE_MODE_SSH? 's' : 'n',
	      keyinfo);
  else
    snprintf (line, DIM(line), "SETKEYINFO --clear");

  rc = assuan_transact (entry_ctx, line,
			NULL, NULL, NULL, NULL, NULL, NULL);
  if (rc && gpg_err_code (rc) != GPG_ERR_ASS_UNKNOWN_CMD)
    return unlock_pinentry (ctrl, rc);

  if (desc)
    build_cmd_setdesc (line, DIM(line), desc);
  else
    snprintf (line, DIM(line), "RESET");
  rc = assuan_transact (entry_ctx, line, NULL, NULL, NULL, NULL, NULL, NULL);
  if (rc)
    return unlock_pinentry (ctrl, rc);

  snprintf (line, DIM(line), "SETPROMPT %s", prompt);
  rc = assuan_transact (entry_ctx, line, NULL, NULL, NULL, NULL, NULL, NULL);
  if (rc)
    return unlock_pinentry (ctrl, rc);

  if ((with_qualitybar || (pininfo && pininfo->with_qualitybar))
       && opt.min_passphrase_len)
    {
      rc = setup_qualitybar (ctrl);
      if (rc)
        return unlock_pinentry (ctrl, rc);
    }

  if (errtext)
    {
      snprintf (line, DIM(line), "SETERROR %s", errtext);
      rc = assuan_transact (entry_ctx, line,
                            NULL, NULL, NULL, NULL, NULL, NULL);
      if (rc)
        return unlock_pinentry (ctrl, rc);
    }

  rc = setup_formatted_passphrase (ctrl);
  if (rc)
    return unlock_pinentry (ctrl, rc);

  if (!pininfo)
    {
      /* Legacy method without PININFO.  */
      memset (&parm, 0, sizeof parm);
      parm.size = ASSUAN_LINELENGTH/2 - 5;
      parm.buffer = gcry_malloc_secure (parm.size+10);
      if (!parm.buffer)
        return unlock_pinentry (ctrl, out_of_core ());

      rc = do_getpin (ctrl, &parm);
      if (rc)
        xfree (parm.buffer);
      else
        *retpass = parm.buffer;
      return unlock_pinentry (ctrl, rc);
    }

  /* We got PININFO.  */

  if (pininfo->with_repeat)
    {
      snprintf (line, DIM(line), "SETREPEATERROR %s",
                L_("does not match - try again"));
      rc = assuan_transact (entry_ctx, line,
                            NULL, NULL, NULL, NULL, NULL, NULL);
      if (rc)
        pininfo->with_repeat = 0; /* Pinentry does not support it.  */

      (void)setup_genpin (ctrl);

      rc = setup_enforced_constraints (ctrl);
      if (rc)
        return unlock_pinentry (ctrl, rc);
    }
  pininfo->repeat_okay = 0;
  pininfo->status = 0;

  for (;pininfo->failed_tries < pininfo->max_tries; pininfo->failed_tries++)
    {
      memset (&parm, 0, sizeof parm);
      parm.constraints_flags = pininfo->constraints_flags;
      parm.size = pininfo->max_length;
      parm.buffer = (unsigned char*)pininfo->pin;
      *pininfo->pin = 0; /* Reset the PIN. */

      if (errtext)
        {
          /* TRANSLATORS: The string is appended to an error message in
             the pinentry.  The %s is the actual error message, the
             two %d give the current and maximum number of tries. */
          snprintf (line, DIM(line), L_("SETERROR %s (try %d of %d)"),
                    errtext, pininfo->failed_tries+1, pininfo->max_tries);
          rc = assuan_transact (entry_ctx, line,
                                NULL, NULL, NULL, NULL, NULL, NULL);
          if (rc)
            return unlock_pinentry (ctrl, rc);
          errtext = NULL;
        }

      if (pininfo->with_repeat)
        {
          snprintf (line, DIM(line), "SETREPEAT %s", L_("Repeat:"));
          rc = assuan_transact (entry_ctx, line,
                                NULL, NULL, NULL, NULL, NULL, NULL);
          if (rc)
            return unlock_pinentry (ctrl, rc);
        }

      rc = do_getpin (ctrl, &parm);
      pininfo->status = parm.status;
      is_generated = !!(parm.status & PINENTRY_STATUS_PASSWORD_GENERATED);

      if (gpg_err_code (rc) == GPG_ERR_ASS_TOO_MUCH_DATA)
        errtext = is_pin? L_("PIN too long")
                        : L_("Passphrase too long");
      else if (rc)
        return unlock_pinentry (ctrl, rc);

      if (!errtext && pininfo->min_digits && !is_generated)
        {
          /* do some basic checks on the entered PIN. */
          if (!all_digitsp (pininfo->pin))
            errtext = L_("Invalid characters in PIN");
          else if (pininfo->max_digits
                   && strlen (pininfo->pin) > pininfo->max_digits)
            errtext = L_("PIN too long");
          else if (strlen (pininfo->pin) < pininfo->min_digits)
            errtext = L_("PIN too short");
        }

      if (!errtext && pininfo->check_cb && !is_generated)
        {
          /* More checks by utilizing the optional callback. */
          pininfo->cb_errtext = NULL;
          rc = pininfo->check_cb (pininfo);
          /* When pinentry cache causes an error, return now.  */
          if (rc && (pininfo->status & PINENTRY_STATUS_PASSWORD_FROM_CACHE))
            return unlock_pinentry (ctrl, rc);

          if (gpg_err_code (rc) == GPG_ERR_BAD_PASSPHRASE)
            {
              if (pininfo->cb_errtext)
                errtext = pininfo->cb_errtext;
              else if (gpg_err_code (rc) == GPG_ERR_BAD_PASSPHRASE
                       || gpg_err_code (rc) == GPG_ERR_BAD_PIN)
                errtext = (is_pin? L_("Bad PIN") : L_("Bad Passphrase"));
            }
          else if (rc)
            return unlock_pinentry (ctrl, rc);
        }

      if (!errtext)
        {
          if (pininfo->with_repeat
              && (pininfo->status & PINENTRY_STATUS_PIN_REPEATED))
            pininfo->repeat_okay = 1;
          return unlock_pinentry (ctrl, 0); /* okay, got a PIN or passphrase */
        }

      if ((pininfo->status & PINENTRY_STATUS_PASSWORD_FROM_CACHE))
        {
          /* The password was read from the Pinentry's own cache.
             Don't count this against the retry count.  */
          pininfo->failed_tries--;
        }
    }

  return unlock_pinentry (ctrl, gpg_error (pininfo->min_digits? GPG_ERR_BAD_PIN
                          : GPG_ERR_BAD_PASSPHRASE));
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

  if (ctrl->pinentry_mode != PINENTRY_MODE_ASK)
    {
      if (ctrl->pinentry_mode == PINENTRY_MODE_CANCEL)
        return gpg_error (GPG_ERR_CANCELED);

      return gpg_error (GPG_ERR_NO_PIN_ENTRY);
    }

  rc = start_pinentry (ctrl);
  if (rc)
    return rc;

  if (desc)
    build_cmd_setdesc (line, DIM(line), desc);
  else
    snprintf (line, DIM(line), "RESET");
  rc = assuan_transact (entry_ctx, line, NULL, NULL, NULL, NULL, NULL, NULL);
  /* Most pinentries out in the wild return the old Assuan error code
     for canceled which gets translated to an assuan Cancel error and
     not to the code for a user cancel.  Fix this here. */
  if (rc && gpg_err_source (rc) && gpg_err_code (rc) == GPG_ERR_ASS_CANCELED)
    rc = gpg_err_make (gpg_err_source (rc), GPG_ERR_CANCELED);

  if (rc)
    return unlock_pinentry (ctrl, rc);

  if (ok)
    {
      snprintf (line, DIM(line), "SETOK %s", ok);
      rc = assuan_transact (entry_ctx,
                            line, NULL, NULL, NULL, NULL, NULL, NULL);
      if (rc)
        return unlock_pinentry (ctrl, rc);
    }
  if (notok)
    {
      /* Try to use the newer NOTOK feature if a cancel button is
         requested.  If no cancel button is requested we keep on using
         the standard cancel.  */
      if (with_cancel)
        {
          snprintf (line, DIM(line), "SETNOTOK %s", notok);
          rc = assuan_transact (entry_ctx,
                                line, NULL, NULL, NULL, NULL, NULL, NULL);
        }
      else
        rc = GPG_ERR_ASS_UNKNOWN_CMD;

      if (gpg_err_code (rc) == GPG_ERR_ASS_UNKNOWN_CMD)
	{
	  snprintf (line, DIM(line), "SETCANCEL %s", notok);
	  rc = assuan_transact (entry_ctx, line,
                                NULL, NULL, NULL, NULL, NULL, NULL);
	}
      if (rc)
        return unlock_pinentry (ctrl, rc);
    }

  rc = assuan_transact (entry_ctx, "CONFIRM",
                        NULL, NULL, NULL, NULL, NULL, NULL);
  if (rc && gpg_err_source (rc) && gpg_err_code (rc) == GPG_ERR_ASS_CANCELED)
    rc = gpg_err_make (gpg_err_source (rc), GPG_ERR_CANCELED);

  return unlock_pinentry (ctrl, rc);
}



/* Pop up the PINentry, display the text DESC and a button with the
   text OK_BTN (which may be NULL to use the default of "OK") and wait
   for the user to hit this button.  The return value is not
   relevant.  */
int
agent_show_message (ctrl_t ctrl, const char *desc, const char *ok_btn)
{
  int rc;
  char line[ASSUAN_LINELENGTH];

  if (ctrl->pinentry_mode != PINENTRY_MODE_ASK)
    return gpg_error (GPG_ERR_CANCELED);

  rc = start_pinentry (ctrl);
  if (rc)
    return rc;

  if (desc)
    build_cmd_setdesc (line, DIM(line), desc);
  else
    snprintf (line, DIM(line), "RESET");
  rc = assuan_transact (entry_ctx, line, NULL, NULL, NULL, NULL, NULL, NULL);
  /* Most pinentries out in the wild return the old Assuan error code
     for canceled which gets translated to an assuan Cancel error and
     not to the code for a user cancel.  Fix this here. */
  if (rc && gpg_err_source (rc) && gpg_err_code (rc) == GPG_ERR_ASS_CANCELED)
    rc = gpg_err_make (gpg_err_source (rc), GPG_ERR_CANCELED);

  if (rc)
    return unlock_pinentry (ctrl, rc);

  if (ok_btn)
    {
      snprintf (line, DIM(line), "SETOK %s", ok_btn);
      rc = assuan_transact (entry_ctx, line, NULL, NULL, NULL,
                            NULL, NULL, NULL);
      if (rc)
        return unlock_pinentry (ctrl, rc);
    }

  rc = assuan_transact (entry_ctx, "CONFIRM --one-button", NULL, NULL, NULL,
                        NULL, NULL, NULL);
  if (rc && gpg_err_source (rc) && gpg_err_code (rc) == GPG_ERR_ASS_CANCELED)
    rc = gpg_err_make (gpg_err_source (rc), GPG_ERR_CANCELED);

  return unlock_pinentry (ctrl, rc);
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
  npth_attr_t tattr;
  int err;

  if (ctrl->pinentry_mode != PINENTRY_MODE_ASK)
    return gpg_error (GPG_ERR_CANCELED);

  rc = start_pinentry (ctrl);
  if (rc)
    return rc;

  if (desc)
    build_cmd_setdesc (line, DIM(line), desc);
  else
    snprintf (line, DIM(line), "RESET");
  rc = assuan_transact (entry_ctx, line, NULL, NULL, NULL, NULL, NULL, NULL);
  if (rc)
    return unlock_pinentry (ctrl, rc);

  if (ok_btn)
    {
      snprintf (line, DIM(line), "SETOK %s", ok_btn);
      rc = assuan_transact (entry_ctx, line, NULL,NULL,NULL,NULL,NULL,NULL);
      if (rc)
        return unlock_pinentry (ctrl, rc);
    }

  err = npth_attr_init (&tattr);
  if (err)
    return unlock_pinentry (ctrl, gpg_error_from_errno (err));
  npth_attr_setdetachstate (&tattr, NPTH_CREATE_JOINABLE);

  popup_finished = 0;
  err = npth_create (&popup_tid, &tattr, popup_message_thread, NULL);
  npth_attr_destroy (&tattr);
  if (err)
    {
      rc = gpg_error_from_errno (err);
      log_error ("error spawning popup message handler: %s\n",
                 strerror (err) );
      return unlock_pinentry (ctrl, rc);
    }
  npth_setname_np (popup_tid, "popup-message");

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
    kill (pid, SIGINT);
#endif

  /* Now wait for the thread to terminate. */
  rc = npth_join (popup_tid, NULL);
  if (rc)
    log_debug ("agent_popup_message_stop: pth_join failed: %s\n",
               strerror (rc));
  /* Thread IDs are opaque, but we try our best here by resetting it
     to the same content that a static global variable has.  */
  memset (&popup_tid, '\0', sizeof (popup_tid));

  /* Now we can close the connection. */
  unlock_pinentry (ctrl, 0);
}

int
agent_clear_passphrase (ctrl_t ctrl,
			const char *keyinfo, cache_mode_t cache_mode)
{
  int rc;
  char line[ASSUAN_LINELENGTH];

  if (! (keyinfo && (cache_mode == CACHE_MODE_NORMAL
		     || cache_mode == CACHE_MODE_USER
		     || cache_mode == CACHE_MODE_SSH)))
    return gpg_error (GPG_ERR_NOT_SUPPORTED);

  rc = start_pinentry (ctrl);
  if (rc)
    return rc;

  snprintf (line, DIM(line), "CLEARPASSPHRASE %c/%s",
	    cache_mode == CACHE_MODE_USER? 'u' :
	    cache_mode == CACHE_MODE_SSH? 's' : 'n',
	    keyinfo);
  rc = assuan_transact (entry_ctx, line,
			NULL, NULL, NULL, NULL, NULL, NULL);

  return unlock_pinentry (ctrl, rc);
}
