/* command.c - TPM2daemon command handler
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

#include "tpm2daemon.h"
#include "tpm2.h"
#include <assuan.h>
#include <ksba.h>
#include "../common/asshelp.h"
#include "../common/server-help.h"

/* Maximum length allowed as a PIN; used for INQUIRE NEEDPIN */
#define MAXLEN_PIN 100

/* Maximum allowed size of key data as used in inquiries. */
#define MAXLEN_KEYDATA 4096

/* Maximum allowed total data size for SETDATA.  */
#define MAXLEN_SETDATA 4096

/* Maximum allowed size of certificate data as used in inquiries. */
#define MAXLEN_CERTDATA 16384


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
  unsigned long event_signal;   /* Or 0 if not used. */
#else
  int event_signal;             /* Or 0 if not used. */
#endif

  /* True if the card has been removed and a reset is required to
     continue operation. */
  int card_removed;

  /* If set to true we will be terminate ourself at the end of the
     this session.  */
  int stopme;

};


/* To keep track of all running sessions, we link all active server
   contexts and the anchor in this variable.  */
static struct server_local_s *session_list;


static gpg_error_t
reset_notify (assuan_context_t ctx, char *line)
{
  (void) ctx;
  (void) line;

  return 0;
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
      ctrl->server_local->event_signal = strtoul (value, NULL, 16);
#else
      int i = *value? atoi (value) : -1;
      if (i < 0)
        return gpg_error (GPG_ERR_ASS_PARAMETER);
      ctrl->server_local->event_signal = i;
#endif
    }

 return 0;
}


static gpg_error_t
pin_cb (ctrl_t ctrl, const char *info, char **retstr)
{
  assuan_context_t ctx = ctrl->ctx;
  char *command;
  int rc;
  unsigned char *value;
  size_t valuelen;

  *retstr = NULL;
  log_debug ("asking for PIN '%s'\n", info);

  rc = gpgrt_asprintf (&command, "NEEDPIN %s", info);
  if (rc < 0)
    return gpg_error (gpg_err_code_from_errno (errno));

  /* Fixme: Write an inquire function which returns the result in
     secure memory and check all further handling of the PIN. */
  rc = assuan_inquire (ctx, command, &value, &valuelen, MAXLEN_PIN);
  xfree (command);
  if (rc)
    return rc;

  if (!valuelen)
    {
      /* We require that the returned value is an UTF-8 string */
      xfree (value);
      return gpg_error (GPG_ERR_INV_RESPONSE);
    }
  *retstr = (char*)value;
  return 0;
}

static const char hlp_import[] =
  "IMPORT\n"
  "\n"
  "This command is used to convert a public and secret key to tpm format.\n"
  "keydata is communicated via an inquire KEYDATA command\n"
  "The keydata is expected to be the usual canonical encoded\n"
  "S-expression.  The return will be a TPM format S-expression\n"
  "\n"
  "A PIN will be requested.";
static gpg_error_t
cmd_import (assuan_context_t ctx, char *line)
{
  ctrl_t ctrl = assuan_get_pointer (ctx);
  int rc;
  unsigned char *keydata;
  size_t keydatalen;
  TSS_CONTEXT *tssc;
  gcry_sexp_t s_key;
  unsigned char *shadow_info = NULL;
  size_t shadow_len;

  line = skip_options (line);

  if (*line)
    return set_error (GPG_ERR_ASS_PARAMETER, "additional parameters given");

  /* Now get the actual keydata. */
  assuan_begin_confidential (ctx);
  rc = assuan_inquire (ctx, "KEYDATA", &keydata, &keydatalen, MAXLEN_KEYDATA);
  assuan_end_confidential (ctx);
  if (rc)
    return rc;

  if ((rc = tpm2_start (&tssc)))
    goto out;
  gcry_sexp_new (&s_key, keydata, keydatalen, 0);
  rc = tpm2_import_key (ctrl, tssc, pin_cb, &shadow_info, &shadow_len,
			s_key, opt.parent);
  gcry_sexp_release (s_key);
  tpm2_end (tssc);
  if (rc)
    goto out;

  rc = assuan_send_data (ctx, shadow_info, shadow_len);

 out:
  xfree (shadow_info);
  xfree (keydata);

  return rc;
}

static const char hlp_pksign[] =
  "PKSIGN\n"
  "\n"
  "Get the TPM to produce a signature.  KEYDATA will request the TPM\n"
  "form S-expression (returned by IMPORT) and EXTRA will be the hash\n"
  "to sign.  The TPM currently deduces hash type from length.\n"
  "\n"
  "A PIN will be requested.";
static gpg_error_t
cmd_pksign (assuan_context_t ctx, char *line)
{
  ctrl_t ctrl = assuan_get_pointer (ctx);
  int rc;
  unsigned char *shadow_info;
  size_t len;
  TSS_CONTEXT *tssc;
  TPM_HANDLE key;
  TPMI_ALG_PUBLIC type;
  unsigned char *digest;
  size_t digestlen;
  unsigned char *sig;
  size_t siglen;

  line = skip_options (line);

  if (*line)
    return set_error (GPG_ERR_ASS_PARAMETER, "additional parameters given");

  /* Now get the actual keydata. */
  rc = assuan_inquire (ctx, "KEYDATA", &shadow_info, &len, MAXLEN_KEYDATA);
  if (rc)
    return rc;

  rc = assuan_inquire (ctx, "EXTRA", &digest, &digestlen, MAXLEN_KEYDATA);
  if (rc)
    goto out_freeshadow;

  rc = tpm2_start (&tssc);
  if (rc)
    goto out;

  rc = tpm2_load_key (tssc, shadow_info, &key, &type);
  if (rc)
    goto end_out;

  rc = tpm2_sign (ctrl, tssc, key, pin_cb, type, digest, digestlen,
		 &sig, &siglen);

  tpm2_flush_handle (tssc, key);

 end_out:
  tpm2_end (tssc);

  if (rc)
    goto out;

  rc = assuan_send_data (ctx, sig, siglen);
  xfree (sig);

 out:
  xfree (digest);
 out_freeshadow:
  xfree (shadow_info);

  return rc;
}

static const char hlp_pkdecrypt[] =
  "PKDECRYPT\n"
  "Get the TPM to recover a symmetric key.  KEYDATA will request the TPM\n"
  "form S-expression (returned by IMPORT) and EXTRA will be the input\n"
  "to derive or decrypt.  The return will be the symmetric key\n"
  "\n"
  "\n"
  "A PIN will be requested.";
static gpg_error_t
cmd_pkdecrypt (assuan_context_t ctx, char *line)
{
  ctrl_t ctrl = assuan_get_pointer (ctx);
  int rc;
  unsigned char *shadow_info;
  size_t len;
  TSS_CONTEXT *tssc;
  TPM_HANDLE key;
  TPMI_ALG_PUBLIC type;
  unsigned char *crypto;
  size_t cryptolen;
  char *buf;
  size_t buflen;

  line = skip_options (line);

  if (*line)
    return set_error (GPG_ERR_ASS_PARAMETER, "additional parameters given");

  /* Now get the actual keydata. */
  rc = assuan_inquire (ctx, "KEYDATA", &shadow_info, &len, MAXLEN_KEYDATA);
  if (rc)
    return rc;

  rc = assuan_inquire (ctx, "EXTRA", &crypto, &cryptolen, MAXLEN_KEYDATA);
  if (rc)
    goto out_freeshadow;

  rc = tpm2_start (&tssc);
  if (rc)
    goto out;

  rc = tpm2_load_key (tssc, shadow_info, &key, &type);
  if (rc)
    goto end_out;

  if (type == TPM_ALG_RSA)
    rc = tpm2_rsa_decrypt (ctrl, tssc, key, pin_cb, crypto,
			   cryptolen, &buf, &buflen);
  else if (type == TPM_ALG_ECC)
    rc = tpm2_ecc_decrypt (ctrl, tssc, key, pin_cb, crypto,
			   cryptolen, &buf, &buflen);

  tpm2_flush_handle (tssc, key);

 end_out:
  tpm2_end (tssc);

  if (rc)
    goto out;

  rc = assuan_send_data (ctx, buf, buflen);
  xfree (buf);

 out:
  xfree (crypto);
 out_freeshadow:
  xfree (shadow_info);

  return rc;
}

static const char hlp_killtpm2d[] =
  "KILLTPM2D\n"
  "\n"
  "Commit suicide.";
static gpg_error_t
cmd_killtpm2d (assuan_context_t ctx, char *line)
{
  ctrl_t ctrl = assuan_get_pointer (ctx);

  (void)line;

  ctrl->server_local->stopme = 1;
  assuan_set_flag (ctx, ASSUAN_FORCE_CLOSE, 1);
  return 0;
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
    { "IMPORT",       cmd_import,     hlp_import },
    { "PKSIGN",       cmd_pksign,     hlp_pksign },
    { "PKDECRYPT",    cmd_pkdecrypt,  hlp_pkdecrypt },
    { "KILLTPM2D",    cmd_killtpm2d,  hlp_killtpm2d },
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
  assuan_set_hello_line (ctx, "GNU Privacy Guard's TPM2 server ready");

  assuan_register_reset_notify (ctx, reset_notify);
  assuan_register_option_handler (ctx, option_handler);
  return 0;
}


/* Startup the server.  If FD is given as -1 this is simple pipe
   server, otherwise it is a regular server.  Returns true if there
   are no more active asessions.  */
int
tpm2d_command_handler (ctrl_t ctrl, gnupg_fd_t fd)
{
  int rc;
  assuan_context_t ctx = NULL;
  int stopme;

  rc = assuan_new (&ctx);
  if (rc)
    {
      log_error ("failed to allocate assuan context: %s\n",
                 gpg_strerror (rc));
      tpm2d_exit (2);
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
                 gpg_strerror (rc));
      tpm2d_exit (2);
    }
  rc = register_commands (ctx);
  if (rc)
    {
      log_error ("failed to register commands with Assuan: %s\n",
                 gpg_strerror (rc));
      tpm2d_exit (2);
    }
  assuan_set_pointer (ctx, ctrl);
  ctrl->ctx = ctx;

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
    tpm2d_exit (0);

  /* If there are no more sessions return true.  */
  return !session_list;
}
