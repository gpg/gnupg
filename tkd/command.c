/* command.c - TKdaemon command handler
 * Copyright (C) 2001, 2002, 2003, 2004, 2005,
 *               2007, 2008, 2009, 2011  Free Software Foundation, Inc.
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
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <unistd.h>
#include <signal.h>
#ifdef USE_NPTH
# include <npth.h>
#endif

#include "tkdaemon.h"
#include "../common/asshelp.h"
#include "../common/server-help.h"
#include "../common/ssh-utils.h"

/* Maximum length allowed as a PIN; used for INQUIRE NEEDPIN.  That
 * length needs to small compared to the maximum Assuan line length.  */
#define MAXLEN_PIN 100

#define set_error(e,t) assuan_set_error (ctx, gpg_error (e), (t))


/* Data used to associate an Assuan context with local server data.
   This object describes the local properties of one session.  */
struct server_local_s
{
  /* We keep a list of all active sessions with the anchor at
     SESSION_LIST (see below).  This field is used for linking. */
  struct server_local_s *next_session;

  /* This object is usually assigned to a CTRL object (which is
     globally visible).  While enumerating all sessions we sometimes
     need to access data of the CTRL object; thus we keep a
     backpointer here. */
  ctrl_t ctrl_backlink;

  /* The Assuan context used by this session/server. */
  assuan_context_t assuan_ctx;

#ifdef HAVE_W32_SYSTEM
  void *event_signal;           /* Or NULL if not used. */
#else
  int event_signal;             /* Or 0 if not used. */
#endif

  /* If set to true we will be terminate ourself at the end of the
     this session.  */
  unsigned int stopme:1;
};


struct token_ctx_s
{
};

/* To keep track of all running sessions, we link all active server
   contexts and the anchor in this variable.  */
static struct server_local_s *session_list;

gpg_error_t
initialize_module_command (void)
{
  return 0;
}

static void
finalize (ctrl_t ctrl)
{
  (void)ctrl;
}

static gpg_error_t
option_handler (assuan_context_t ctx, const char *key, const char *value)
{
  ctrl_t ctrl = assuan_get_pointer (ctx);

  if (!strcmp (key, "event-signal"))
    {
      /* A value of 0 is allowed to reset the event signal. */
#ifdef HAVE_W32_SYSTEM
      if (!*value)
        return gpg_error (GPG_ERR_ASS_PARAMETER);
#ifdef _WIN64
      ctrl->server_local->event_signal = (void *)strtoull (value, NULL, 16);
#else
      ctrl->server_local->event_signal = (void *)strtoul (value, NULL, 16);
#endif
#else
      int i = *value? atoi (value) : -1;
      if (i < 0)
        return gpg_error (GPG_ERR_ASS_PARAMETER);
      ctrl->server_local->event_signal = i;
#endif
    }

 return 0;
}

#if 0
static gpg_error_t
pin_cb (void *opaque, const char *info, char **retstr)
{
  assuan_context_t ctx = opaque;
  char *command;
  int rc;
  unsigned char *value;
  size_t valuelen;

  if (!retstr)
    {
      /* We prompt for pinpad entry.  To make sure that the popup has
         been show we use an inquire and not just a status message.
         We ignore any value returned.  */
      if (info)
        {
          log_debug ("prompting for pinpad entry '%s'\n", info);
          rc = gpgrt_asprintf (&command, "POPUPPINPADPROMPT %s", info);
          if (rc < 0)
            return gpg_error (gpg_err_code_from_errno (errno));
          rc = assuan_inquire (ctx, command, &value, &valuelen, MAXLEN_PIN);
          xfree (command);
        }
      else
        {
          log_debug ("dismiss pinpad entry prompt\n");
          rc = assuan_inquire (ctx, "DISMISSPINPADPROMPT",
                               &value, &valuelen, MAXLEN_PIN);
        }
      if (!rc)
        xfree (value);
      return rc;
    }

  *retstr = NULL;
  log_debug ("asking for PIN '%s'\n", info);

  rc = gpgrt_asprintf (&command, "NEEDPIN %s", info);
  if (rc < 0)
    return gpg_error (gpg_err_code_from_errno (errno));

  /* Fixme: Write an inquire function which returns the result in
     secure memory and check all further handling of the PIN. */
  assuan_begin_confidential (ctx);
  rc = assuan_inquire (ctx, command, &value, &valuelen, MAXLEN_PIN);
  assuan_end_confidential (ctx);
  xfree (command);
  if (rc)
    return rc;

  if (!valuelen || value[valuelen-1])
    {
      /* We require that the returned value is an UTF-8 string */
      xfree (value);
      return gpg_error (GPG_ERR_INV_RESPONSE);
    }
  *retstr = (char*)value;
  return 0;
}
#endif

static const char hlp_getinfo[] =
  "GETINFO <what>\n"
  "\n"
  "Multi purpose command to return certain information.  \n"
  "Supported values of WHAT are:\n"
  "\n"
  "  version     - Return the version of the program.\n"
  "  pid         - Return the process id of the server.\n"
  "  socket_name - Return the name of the socket.\n"
  "  connections - Return number of active connections.";
static gpg_error_t
cmd_getinfo (assuan_context_t ctx, char *line)
{
  int rc = 0;
  const char *s;

  if (!strcmp (line, "version"))
    {
      s = VERSION;
      rc = assuan_send_data (ctx, s, strlen (s));
    }
  else if (!strcmp (line, "pid"))
    {
      char numbuf[50];

      snprintf (numbuf, sizeof numbuf, "%lu", (unsigned long)getpid ());
      rc = assuan_send_data (ctx, numbuf, strlen (numbuf));
    }
  else if (!strcmp (line, "socket_name"))
    {
      s = tkd_get_socket_name ();
      if (s)
        rc = assuan_send_data (ctx, s, strlen (s));
      else
        rc = gpg_error (GPG_ERR_NO_DATA);
    }
  else if (!strcmp (line, "connections"))
    {
      char numbuf[20];

      snprintf (numbuf, sizeof numbuf, "%d", get_active_connection_count ());
      rc = assuan_send_data (ctx, numbuf, strlen (numbuf));
    }
  else
    rc = set_error (GPG_ERR_ASS_PARAMETER, "unknown value for WHAT");
  return rc;
}


static const char hlp_restart[] =
  "RESTART\n"
  "\n"
  "Restart the current connection.\n"
  "\n"
  "This is used by gpg-agent to reuse a primary pipe connection.";
/*
 * TKDeamon does not have a context for a connection (for now).
 * So, this command does nothing.
 */
static gpg_error_t
cmd_restart (assuan_context_t ctx, char *line)
{
  (void)line;
  (void)ctx;
  return 0;
}


/* SLOTLIST command
 * A command to (re)scan for available keys, something like SERIALNO
 * command of scdaemon.
 */
static const char hlp_slotlist[] =
  "SLOTLIST\n"
  "\n"
  "Return the status of each token using a status response.  This\n"
  "function should be used to check for the presence of tokens.";
static gpg_error_t
cmd_slotlist (assuan_context_t ctx, char *line)
{
  ctrl_t ctrl = assuan_get_pointer (ctx);
  gpg_error_t err;

  line = skip_options (line);
  (void)line;

  err = tkd_init (ctrl, ctx, 1);
  return err;
}

static const char hlp_readkey[] =
  "READKEY [--info[-only]] <keygrip>\n"
  "\n"
  "Return the public key for the given KEYGRIP, as a standard\n"
  "S-expression.";
static gpg_error_t
cmd_readkey (assuan_context_t ctx, char *line)
{
  ctrl_t ctrl = assuan_get_pointer (ctx);
  gpg_error_t err;
  const char *keygrip;

  line = xtrystrdup (line); /* Need a copy of the line. */
  if (!line)
    return gpg_error_from_syserror ();

  keygrip = skip_options (line);
  if (strlen (keygrip) != 40)
    err = gpg_error (GPG_ERR_INV_ID);

  err = tkd_readkey (ctrl, ctx, keygrip);

  xfree (line);
  return err;
}

static const char hlp_pksign[] =
  "PKSIGN [--hash=[sha{256,384,512}|none]] <keygrip>\n"
  "\n"
  "The --hash option is optional; the default is none.";
static gpg_error_t
cmd_pksign (assuan_context_t ctx, char *line)
{
  ctrl_t ctrl = assuan_get_pointer (ctx);
  gpg_error_t err;
  int hash_algo;
  const char *keygrip;
  unsigned char *outdata;
  size_t outdatalen;

  if (has_option (line, "--hash=sha256"))
    hash_algo = GCRY_MD_SHA256;
  else if (has_option (line, "--hash=sha384"))
    hash_algo = GCRY_MD_SHA384;
  else if (has_option (line, "--hash=sha512"))
    hash_algo = GCRY_MD_SHA512;
  else if (has_option (line, "--hash=none"))
    hash_algo = 0;
  else if (!strstr (line, "--"))
    hash_algo = 0;
  else
    return set_error (GPG_ERR_ASS_PARAMETER, "invalid hash algorithm");

  line = xtrystrdup (line); /* Need a copy of the line. */
  if (!line)
    return gpg_error_from_syserror ();

  keygrip = skip_options (line);

  if (strlen (keygrip) != 40)
    err = gpg_error (GPG_ERR_INV_ID);

  err = tkd_sign (ctrl, ctx, keygrip, hash_algo, &outdata, &outdatalen);
  if (err)
    {
      log_error ("tkd_sign failed: %s\n", gpg_strerror (err));
    }
  else
    {
      err = assuan_send_data (ctx, outdata, outdatalen);
      xfree (outdata);
    }

  xfree (line);
  return err;
}

static const char hlp_killtkd[] =
  "KILLTKD\n"
  "\n"
  "Commit suicide.";
static gpg_error_t
cmd_killtkd (assuan_context_t ctx, char *line)
{
  ctrl_t ctrl = assuan_get_pointer (ctx);

  (void)line;

  ctrl->server_local->stopme = 1;
  assuan_set_flag (ctx, ASSUAN_FORCE_CLOSE, 1);
  return 0;
}


static const char hlp_keyinfo[] =
  "KEYINFO [--list[=auth|encr|sign]] [--data] <keygrip>\n"
  "\n"
  "Return information about the key specified by the KEYGRIP.  If the\n"
  "key is not available GPG_ERR_NOT_FOUND is returned.  If the option\n"
  "--list is given the keygrip is ignored and information about all\n"
  "available keys are returned.  Capability may limit the listing.\n"
  "Unless --data is given, the\n"
  "information is returned as a status line using the format:\n"
  "\n"
  "  KEYINFO <keygrip> T <serialno> <idstr> <usage>\n"
  "\n"
  "KEYGRIP is the keygrip.\n"
  "\n"
  "SERIALNO is an ASCII string with the serial number of the\n"
  "         smartcard.  If the serial number is not known a single\n"
  "         dash '-' is used instead.\n"
  "\n"
  "IDSTR is a string used to distinguish keys on a smartcard.  If it\n"
  "      is not known a dash is used instead.\n"
  "\n"
  "USAGE is a string of capabilities of the key, 's' for sign, \n"
  "'e' for encryption, 'a' for auth, and 'c' for cert.  If it is not\n"
  "known a dash is used instead.\n"
  "\n"
  "More information may be added in the future.";
static gpg_error_t
cmd_keyinfo (assuan_context_t ctx, char *line)
{
  gpg_error_t err;
  int cap;
  int opt_data;
  const char *keygrip = NULL;
  ctrl_t ctrl = assuan_get_pointer (ctx);

  opt_data = has_option (line, "--data");

  line = xtrystrdup (line); /* Need a copy of the line. */
  if (!line)
    return gpg_error_from_syserror ();

  cap = 0;
  if (has_option (line, "--list"))
    cap = 0;
  else if (has_option (line, "--list=sign"))
    cap = GCRY_PK_USAGE_SIGN;
  else if (has_option (line, "--list=encr"))
    cap = GCRY_PK_USAGE_ENCR;
  else if (has_option (line, "--list=auth"))
    cap = GCRY_PK_USAGE_AUTH;
  else
    keygrip = skip_options (line);

  err = tkd_keyinfo (ctrl, ctx, keygrip, opt_data, cap);

  xfree (line);
  return err;
}


/* Send a keyinfo string as used by the KEYGRIP_ACTION_SEND_DATA.  If
 * DATA is true the string is emitted as a data line, else as a status
 * line.  */
void
send_keyinfo (ctrl_t ctrl, int data, const char *keygrip_str,
              const char *serialno, const char *idstr, const char *usage)
{
  char *string;
  assuan_context_t ctx = ctrl->server_local->assuan_ctx;

  string = xtryasprintf ("%s T %s %s %s%s", keygrip_str,
                         serialno? serialno : "-",
                         idstr? idstr : "-",
                         usage? usage : "-",
                         data? "\n" : "");

  if (!string)
    return;

  if (!data)
    assuan_write_status (ctx, "KEYINFO", string);
  else
    assuan_send_data (ctx, string, strlen (string));

  xfree (string);
  return;
}

/* Tell the assuan library about our commands */
static int
register_commands (assuan_context_t ctx)
{
  static struct {
    const char *name;
    assuan_handler_t handler;
    const char * const help;
  } table[] = {
    { "INPUT",        NULL },
    { "OUTPUT",       NULL },
    { "SLOTLIST",     cmd_slotlist, hlp_slotlist },
    { "READKEY",      cmd_readkey,  hlp_readkey },
    { "PKSIGN",       cmd_pksign,   hlp_pksign },
    { "KILLTKD",      cmd_killtkd,  hlp_killtkd },
    { "KEYINFO",      cmd_keyinfo,  hlp_keyinfo },
    { "GETINFO",      cmd_getinfo,  hlp_getinfo },
    { "RESTART",      cmd_restart,  hlp_restart },
    { NULL }
  };
  int i, rc;

  for (i=0; table[i].name; i++)
    {
      rc = assuan_register_command (ctx, table[i].name, table[i].handler,
                                    table[i].help);
      if (rc)
        return rc;
    }
  assuan_set_hello_line (ctx, "GNU Privacy Guard's token daemon ready");

  assuan_register_option_handler (ctx, option_handler);
  return 0;
}


/* Startup the server.  If FD is given as -1 this is simple pipe
   server, otherwise it is a regular server.  Returns true if there
   are no more active asessions.  */
int
tkd_command_handler (ctrl_t ctrl, gnupg_fd_t fd)
{
  int rc;
  assuan_context_t ctx = NULL;
  int stopme;

  rc = assuan_new (&ctx);
  if (rc)
    {
      log_error ("failed to allocate assuan context: %s\n",
                 gpg_strerror (rc));
      tkd_exit (2);
    }

  if (fd == GNUPG_INVALID_FD)
    {
      assuan_fd_t filedes[2];

      filedes[0] = assuan_fdopen (0);
      filedes[1] = assuan_fdopen (1);
      rc = assuan_init_pipe_server (ctx, filedes);
    }
  else
    {
      rc = assuan_init_socket_server (ctx, fd,
                                      ASSUAN_SOCKET_SERVER_ACCEPTED);
    }
  if (rc)
    {
      log_error ("failed to initialize the server: %s\n",
                 gpg_strerror(rc));
      tkd_exit (2);
    }
  rc = register_commands (ctx);
  if (rc)
    {
      log_error ("failed to register commands with Assuan: %s\n",
                 gpg_strerror(rc));
      tkd_exit (2);
    }
  assuan_set_pointer (ctx, ctrl);

  /* Allocate and initialize the server object.  Put it into the list
     of active sessions. */
  ctrl->server_local = xcalloc (1, sizeof *ctrl->server_local);
  ctrl->server_local->next_session = session_list;
  session_list = ctrl->server_local;
  ctrl->server_local->ctrl_backlink = ctrl;
  ctrl->server_local->assuan_ctx = ctx;

  /* Command processing loop. */
  for (;;)
    {
      rc = assuan_accept (ctx);
      if (rc == -1)
        {
          break;
        }
      else if (rc)
        {
          log_info ("Assuan accept problem: %s\n", gpg_strerror (rc));
          break;
        }

      rc = assuan_process (ctx);
      if (rc)
        {
          log_info ("Assuan processing failed: %s\n", gpg_strerror (rc));
          continue;
        }
    }

  /* Cleanup.  */
  finalize (ctrl);

  /* Release the server object.  */
  if (session_list == ctrl->server_local)
    session_list = ctrl->server_local->next_session;
  else
    {
      struct server_local_s *sl;

      for (sl=session_list; sl->next_session; sl = sl->next_session)
        if (sl->next_session == ctrl->server_local)
          break;
      if (!sl->next_session)
          BUG ();
      sl->next_session = ctrl->server_local->next_session;
    }
  stopme = ctrl->server_local->stopme;
  xfree (ctrl->server_local);
  ctrl->server_local = NULL;

  /* Release the Assuan context.  */
  assuan_release (ctx);

  if (stopme)
    tkd_exit (0);

  /* If there are no more sessions return true.  */
  return !session_list;
}


/* Send a line with status information via assuan and escape all given
   buffers. The variable elements are pairs of (char *, size_t),
   terminated with a (NULL, 0). */
void
send_status_info (ctrl_t ctrl, const char *keyword, ...)
{
  va_list arg_ptr;
  const unsigned char *value;
  size_t valuelen;
  char buf[950], *p;
  size_t n;
  assuan_context_t ctx = ctrl->server_local->assuan_ctx;

  va_start (arg_ptr, keyword);

  p = buf;
  n = 0;
  while ( (value = va_arg (arg_ptr, const unsigned char *))
           && n < DIM (buf)-2 )
    {
      valuelen = va_arg (arg_ptr, size_t);
      if (!valuelen)
        continue; /* empty buffer */
      if (n)
        {
          *p++ = ' ';
          n++;
        }
      for ( ; valuelen && n < DIM (buf)-2; n++, valuelen--, value++)
        {
          if (*value == '+' || *value == '\"' || *value == '%'
              || *value < ' ')
            {
              sprintf (p, "%%%02X", *value);
              p += 3;
              n += 2;
            }
          else if (*value == ' ')
            *p++ = '+';
          else
            *p++ = *value;
        }
    }
  *p = 0;
  assuan_write_status (ctx, keyword, buf);

  va_end (arg_ptr);
}


/* Send a ready formatted status line via assuan.  */
gpg_error_t
send_status_direct (ctrl_t ctrl, const char *keyword, const char *args)
{
  assuan_context_t ctx = ctrl->server_local->assuan_ctx;

  if (strchr (args, '\n'))
    {
      log_error ("error: LF detected in status line - not sending\n");
      return gpg_error (GPG_ERR_INTERNAL);
    }
  return assuan_write_status (ctx, keyword, args);
}


/* This status functions expects a printf style format string.  No
 * filtering of the data is done instead the printf formatted data is
 * send using assuan_send_status. */
gpg_error_t
send_status_printf (ctrl_t ctrl, const char *keyword, const char *format, ...)
{
  gpg_error_t err;
  va_list arg_ptr;
  assuan_context_t ctx;

  if (!ctrl || !ctrl->server_local || !(ctx = ctrl->server_local->assuan_ctx))
    return 0;

  va_start (arg_ptr, format);
  err = vprint_assuan_status (ctx, keyword, format, arg_ptr);
  va_end (arg_ptr);
  return err;
}
