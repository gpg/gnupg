/* command.c - gpg-agent command handler
 * Copyright (C) 2001, 2002, 2003, 2004 Free Software Foundation, Inc.
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

/* FIXME: we should not use the default assuan buffering but setup
   some buffering in secure mempory to protect session keys etc. */

#include <config.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <unistd.h>

#include <assuan.h>

#include "agent.h"

/* maximum allowed size of the inquired ciphertext */
#define MAXLEN_CIPHERTEXT 4096
/* maximum allowed size of the key parameters */
#define MAXLEN_KEYPARAM 1024

#define set_error(e,t) assuan_set_error (ctx, ASSUAN_ ## e, (t))


#if MAX_DIGEST_LEN < 20
#error MAX_DIGEST_LEN shorter than keygrip
#endif

/* Data used to associate an Assuan context with local server data */
struct server_local_s {
  ASSUAN_CONTEXT assuan_ctx;
  int message_fd;
  int use_cache_for_signing;
  char *keydesc;  /* Allocated description fro the next key
                     operation. */
};





static void
reset_notify (ASSUAN_CONTEXT ctx)
{
  ctrl_t ctrl = assuan_get_pointer (ctx);

  memset (ctrl->keygrip, 0, 20);
  ctrl->have_keygrip = 0;
  ctrl->digest.valuelen = 0;

  xfree (ctrl->server_local->keydesc);
  ctrl->server_local->keydesc = NULL;
}


/* Check whether the option NAME appears in LINE */
static int
has_option (const char *line, const char *name)
{
  const char *s;
  int n = strlen (name);

  s = strstr (line, name);
  return (s && (s == line || spacep (s-1)) && (!s[n] || spacep (s+n)));
}

/* Replace all '+' by a blank. */
static void
plus_to_blank (char *s)
{
  for (; *s; s++)
    {
      if (*s == '+')
        *s = ' ';
    }
}


/* Parse a hex string.  Return an Assuan error code or 0 on success and the
   length of the parsed string in LEN. */
static int
parse_hexstring (ASSUAN_CONTEXT ctx, const char *string, size_t *len)
{
  const char *p;
  size_t n;

  /* parse the hash value */
  for (p=string, n=0; hexdigitp (p); p++, n++)
    ;
  if (*p)
    return set_error (Parameter_Error, "invalid hexstring");
  if ((n&1))
    return set_error (Parameter_Error, "odd number of digits");
  *len = n;
  return 0;
}

/* Parse the keygrip in STRING into the provided buffer BUF.  BUF must
   provide space for 20 bytes. BUF is not changed if the fucntions
   returns an error. */
static int
parse_keygrip (ASSUAN_CONTEXT ctx, const char *string, unsigned char *buf)
{
  int rc;
  size_t n;
  const unsigned char *p;

  rc = parse_hexstring (ctx, string, &n);
  if (rc)
    return rc;
  n /= 2;
  if (n != 20)
    return set_error (Parameter_Error, "invalid length of keygrip");

  for (p=string, n=0; n < 20; p += 2, n++)
    buf[n] = xtoi_2 (p);

  return 0;
}




/* ISTRUSTED <hexstring_with_fingerprint>

   Return OK when we have an entry with this fingerprint in our
   trustlist */
static int
cmd_istrusted (ASSUAN_CONTEXT ctx, char *line)
{
  int rc, n, i;
  char *p;
  char fpr[41];

  /* parse the fingerprint value */
  for (p=line,n=0; hexdigitp (p); p++, n++)
    ;
  if (*p || !(n == 40 || n == 32))
    return set_error (Parameter_Error, "invalid fingerprint");
  i = 0;
  if (n==32)
    {
      strcpy (fpr, "00000000");
      i += 8;
    }
  for (p=line; i < 40; p++, i++)
    fpr[i] = *p >= 'a'? (*p & 0xdf): *p;
  fpr[i] = 0;
  rc = agent_istrusted (fpr);
  if (!rc)
    return 0;
  else if (rc == -1)
    return ASSUAN_Not_Trusted;
  else
    {
      log_error ("command is_trusted failed: %s\n", gpg_strerror (rc));
      return map_to_assuan_status (rc);
    }
}

/* LISTTRUSTED 

   List all entries from the trustlist */
static int
cmd_listtrusted (ASSUAN_CONTEXT ctx, char *line)
{
  int rc = agent_listtrusted (ctx);
  if (rc)
    log_error ("command listtrusted failed: %s\n", gpg_strerror (rc));
  return map_to_assuan_status (rc);
}


/* MARKTRUSTED <hexstring_with_fingerprint> <flag> <display_name>

   Store a new key in into the trustlist*/
static int
cmd_marktrusted (ASSUAN_CONTEXT ctx, char *line)
{
  ctrl_t ctrl = assuan_get_pointer (ctx);
  int rc, n, i;
  char *p;
  char fpr[41];
  int flag;

  /* parse the fingerprint value */
  for (p=line,n=0; hexdigitp (p); p++, n++)
    ;
  if (!spacep (p) || !(n == 40 || n == 32))
    return set_error (Parameter_Error, "invalid fingerprint");
  i = 0;
  if (n==32)
    {
      strcpy (fpr, "00000000");
      i += 8;
    }
  for (p=line; i < 40; p++, i++)
    fpr[i] = *p >= 'a'? (*p & 0xdf): *p;
  fpr[i] = 0;
  
  while (spacep (p))
    p++;
  flag = *p++;
  if ( (flag != 'S' && flag != 'P') || !spacep (p) )
    return set_error (Parameter_Error, "invalid flag - must be P or S");
  while (spacep (p))
    p++;

  rc = agent_marktrusted (ctrl, p, fpr, flag);
  if (rc)
    log_error ("command marktrusted failed: %s\n", gpg_strerror (rc));
  return map_to_assuan_status (rc);
}




/* HAVEKEY <hexstring_with_keygrip>
  
   Return success when the secret key is available */
static int
cmd_havekey (ASSUAN_CONTEXT ctx, char *line)
{
  int rc;
  unsigned char buf[20];

  rc = parse_keygrip (ctx, line, buf);
  if (rc)
    return rc;

  if (agent_key_available (buf))
    return ASSUAN_No_Secret_Key;

  return 0;
}


/* SIGKEY <hexstring_with_keygrip>
   SETKEY <hexstring_with_keygrip>
  
   Set the  key used for a sign or decrypt operation */
static int
cmd_sigkey (ASSUAN_CONTEXT ctx, char *line)
{
  int rc;
  ctrl_t ctrl = assuan_get_pointer (ctx);

  rc = parse_keygrip (ctx, line, ctrl->keygrip);
  if (rc)
    return rc;
  ctrl->have_keygrip = 1;
  return 0;
}


/* SETKEYDESC plus_percent_escaped_string:

   Set a description to be used for the next PKSIGN or PKDECRYPT
   operation if this operation requires the entry of a passphrase.  If
   this command is not used a default text will be used.  Note, that
   this description implictly selects the label used for the entry
   box; if the string contains the string PIN (which in general will
   not be translated), "PIN" is used, other wiese the translation of
   'passphrase" is used.  The description string should not contain
   blanks unless they are percent or '+' escaped.

   The descrition is only valid for the next PKSIGN or PKDECRYPT
   operation.
*/
static int
cmd_setkeydesc (assuan_context_t ctx, char *line)
{
  ctrl_t ctrl = assuan_get_pointer (ctx);
  char *desc, *p;

  for (p=line; *p == ' '; p++)
    ;
  desc = p;
  p = strchr (desc, ' ');
  if (p)
    *p = 0; /* We ignore any garbage; we might late use it for other args. */

  if (!desc || !*desc)
    return set_error (Parameter_Error, "no description given");

  /* Note, that we only need to replace the + characters and should
     leave the other escaping in place because the escaped string is
     send verbatim to the pinentry which does the unescaping (but not
     the + replacing) */
  plus_to_blank (desc);

  xfree (ctrl->server_local->keydesc);
  ctrl->server_local->keydesc = xtrystrdup (desc);
  if (!ctrl->server_local->keydesc)
    return map_to_assuan_status (gpg_error_from_errno (errno));
  return 0;
}


/* SETHASH <algonumber> <hexstring> 

  The client can use this command to tell the server about the data
  (which usually is a hash) to be signed. */
static int
cmd_sethash (ASSUAN_CONTEXT ctx, char *line)
{
  int rc;
  size_t n;
  char *p;
  ctrl_t ctrl = assuan_get_pointer (ctx);
  unsigned char *buf;
  char *endp;
  int algo;

  /* parse the algo number and check it */
  algo = (int)strtoul (line, &endp, 10);
  for (line = endp; *line == ' ' || *line == '\t'; line++)
    ;
  if (!algo || gcry_md_test_algo (algo))
    return set_error (Unsupported_Algorithm, NULL);
  ctrl->digest.algo = algo;

  /* parse the hash value */
  rc = parse_hexstring (ctx, line, &n);
  if (rc)
    return rc;
  n /= 2;
  if (n != 16 && n != 20 && n != 24 && n != 32)
    return set_error (Parameter_Error, "unsupported length of hash");
  if (n > MAX_DIGEST_LEN)
    return set_error (Parameter_Error, "hash value to long");

  buf = ctrl->digest.value;
  ctrl->digest.valuelen = n;
  for (p=line, n=0; n < ctrl->digest.valuelen; p += 2, n++)
    buf[n] = xtoi_2 (p);
  for (; n < ctrl->digest.valuelen; n++)
    buf[n] = 0;
  return 0;
}


/* PKSIGN <options>

   Perform the actual sign operation. Neither input nor output are
   sensitive to eavesdropping */
static int
cmd_pksign (ASSUAN_CONTEXT ctx, char *line)
{
  int rc;
  int ignore_cache = 0;
  ctrl_t ctrl = assuan_get_pointer (ctx);

  if (opt.ignore_cache_for_signing)
    ignore_cache = 1;
  else if (!ctrl->server_local->use_cache_for_signing)
    ignore_cache = 1;

  rc = agent_pksign (ctrl, ctrl->server_local->keydesc,
                     assuan_get_data_fp (ctx), ignore_cache);
  if (rc)
    log_error ("command pksign failed: %s\n", gpg_strerror (rc));
  xfree (ctrl->server_local->keydesc);
  ctrl->server_local->keydesc = NULL;
  return map_to_assuan_status (rc);
}

/* PKDECRYPT <options>

   Perform the actual decrypt operation.  Input is not 
   sensitive to eavesdropping */
static int
cmd_pkdecrypt (ASSUAN_CONTEXT ctx, char *line)
{
  int rc;
  ctrl_t ctrl = assuan_get_pointer (ctx);
  unsigned char *value;
  size_t valuelen;

  /* First inquire the data to decrypt */
  rc = assuan_inquire (ctx, "CIPHERTEXT",
                       &value, &valuelen, MAXLEN_CIPHERTEXT);
  if (rc)
    return rc;

  rc = agent_pkdecrypt (ctrl, ctrl->server_local->keydesc,
                        value, valuelen, assuan_get_data_fp (ctx));
  xfree (value);
  if (rc)
    log_error ("command pkdecrypt failed: %s\n", gpg_strerror (rc));
  xfree (ctrl->server_local->keydesc);
  ctrl->server_local->keydesc = NULL;
  return map_to_assuan_status (rc);
}


/* GENKEY

   Generate a new key, store the secret part and return the public
   part.  Here is an example transaction:

   C: GENKEY
   S: INQUIRE KEYPARM
   C: D (genkey (rsa (nbits  1024)))
   C: END
   S: D (public-key
   S: D   (rsa (n 326487324683264) (e 10001)))
   S  OK key created
*/

static int
cmd_genkey (ASSUAN_CONTEXT ctx, char *line)
{
  ctrl_t ctrl = assuan_get_pointer (ctx);
  int rc;
  unsigned char *value;
  size_t valuelen;

  /* First inquire the parameters */
  rc = assuan_inquire (ctx, "KEYPARAM", &value, &valuelen, MAXLEN_KEYPARAM);
  if (rc)
    return rc;

  rc = agent_genkey (ctrl, value, valuelen, assuan_get_data_fp (ctx));
  xfree (value);
  if (rc)
    log_error ("command genkey failed: %s\n", gpg_strerror (rc));
  return map_to_assuan_status (rc);
}


/* GET_PASSPHRASE <cache_id> [<error_message> <prompt> <description>]

   This function is usually used to ask for a passphrase to be used
   for conventional encryption, but may also be used by programs which
   need specal handling of passphrases.  This command uses a syntax
   which helps clients to use the agent with minimum effort.  The
   agent either returns with an error or with a OK followed by the hex
   encoded passphrase.  Note that the length of the strings is
   implicitly limited by the maximum length of a command.
*/

static int
cmd_get_passphrase (ASSUAN_CONTEXT ctx, char *line)
{
  ctrl_t ctrl = assuan_get_pointer (ctx);
  int rc;
  const char *pw;
  char *response;
  char *cacheid = NULL, *desc = NULL, *prompt = NULL, *errtext = NULL;
  char *p;
  void *cache_marker;

  /* parse the stuff */
  for (p=line; *p == ' '; p++)
    ;
  cacheid = p;
  p = strchr (cacheid, ' ');
  if (p)
    {
      *p++ = 0;
      while (*p == ' ')
        p++;
      errtext = p;
      p = strchr (errtext, ' ');
      if (p)
        {
          *p++ = 0;
          while (*p == ' ')
            p++;
          prompt = p;
          p = strchr (prompt, ' ');
          if (p)
            {
              *p++ = 0;
              while (*p == ' ')
                p++;
              desc = p;
              p = strchr (desc, ' ');
              if (p)
                *p = 0; /* ignore garbage */
            }
        }
    }
  if (!cacheid || !*cacheid || strlen (cacheid) > 50)
    return set_error (Parameter_Error, "invalid length of cacheID");
  if (!desc)
    return set_error (Parameter_Error, "no description given");

  if (!strcmp (cacheid, "X"))
    cacheid = NULL;
  if (!strcmp (errtext, "X"))
    errtext = NULL;
  if (!strcmp (prompt, "X"))
    prompt = NULL;
  if (!strcmp (desc, "X"))
    desc = NULL;

  /* Note: we store the hexified versions in the cache. */
  pw = cacheid ? agent_get_cache (cacheid, &cache_marker) : NULL;
  if (pw)
    {
      assuan_begin_confidential (ctx);
      rc = assuan_set_okay_line (ctx, pw);
      agent_unlock_cache_entry (&cache_marker);
    }
  else
    {
      /* Note, that we only need to replace the + characters and
         should leave the other escaping in place because the escaped
         string is send verbatim to the pinentry which does the
         unescaping (but not the + replacing) */
      if (errtext)
        plus_to_blank (errtext);
      if (prompt)
        plus_to_blank (prompt);
      if (desc)
        plus_to_blank (desc);

      rc = agent_get_passphrase (ctrl, &response, desc, prompt, errtext);
      if (!rc)
        {
          if (cacheid)
            agent_put_cache (cacheid, response, 0);
          assuan_begin_confidential (ctx);
          rc = assuan_set_okay_line (ctx, response);
          xfree (response);
        }
    }

  if (rc)
    log_error ("command get_passphrase failed: %s\n", gpg_strerror (rc));
  return map_to_assuan_status (rc);
}


/* CLEAR_PASSPHRASE <cache_id>

   may be used to invalidate the cache entry for a passphrase.  The
   function returns with OK even when there is no cached passphrase.
*/

static int
cmd_clear_passphrase (ASSUAN_CONTEXT ctx, char *line)
{
  char *cacheid = NULL;
  char *p;

  /* parse the stuff */
  for (p=line; *p == ' '; p++)
    ;
  cacheid = p;
  p = strchr (cacheid, ' ');
  if (p)
    *p = 0; /* ignore garbage */
  if (!cacheid || !*cacheid || strlen (cacheid) > 50)
    return set_error (Parameter_Error, "invalid length of cacheID");

  agent_put_cache (cacheid, NULL, 0);
  return 0;
}


/* GET_CONFIRMATION <description>

   This command may be used to ask for a simple confirmation.
   DESCRIPTION is displayed along with a Okay and Cancel button.  This
   command uses a syntax which helps clients to use the agent with
   minimum effort.  The agent either returns with an error or with a
   OK.  Note, that the length of DESCRIPTION is implicitly limited by
   the maximum length of a command. DESCRIPTION should not contain
   any spaces, those must be encoded either percent escaped or simply
   as '+'.
*/

static int
cmd_get_confirmation (ASSUAN_CONTEXT ctx, char *line)
{
  ctrl_t ctrl = assuan_get_pointer (ctx);
  int rc;
  char *desc = NULL;
  char *p;

  /* parse the stuff */
  for (p=line; *p == ' '; p++)
    ;
  desc = p;
  p = strchr (desc, ' ');
  if (p)
    *p = 0; /* We ignore any garbage -may be later used for other args. */

  if (!desc || !*desc)
    return set_error (Parameter_Error, "no description given");

  if (!strcmp (desc, "X"))
    desc = NULL;

  /* Note, that we only need to replace the + characters and should
     leave the other escaping in place because the escaped string is
     send verbatim to the pinentry which does the unescaping (but not
     the + replacing) */
  if (desc)
    plus_to_blank (desc);

  rc = agent_get_confirmation (ctrl, desc, NULL, NULL);
  if (rc)
    log_error ("command get_confirmation failed: %s\n", gpg_strerror (rc));
  return map_to_assuan_status (rc);
}



/* LEARN [--send]

   Learn something about the currently inserted smartcard.  With
   --send the new certificates are send back.  */
static int
cmd_learn (ASSUAN_CONTEXT ctx, char *line)
{
  ctrl_t ctrl = assuan_get_pointer (ctx);
  int rc;

  rc = agent_handle_learn (ctrl, has_option (line, "--send")? ctx : NULL);
  if (rc)
    log_error ("command learn failed: %s\n", gpg_strerror (rc));
  return map_to_assuan_status (rc);
}



/* PASSWD <hexstring_with_keygrip>
  
   Change the passphrase/PID for the key identified by keygrip in LINE. */
static int
cmd_passwd (ASSUAN_CONTEXT ctx, char *line)
{
  ctrl_t ctrl = assuan_get_pointer (ctx);
  int rc;
  unsigned char grip[20];
  gcry_sexp_t s_skey = NULL;
  unsigned char *shadow_info = NULL;

  rc = parse_keygrip (ctx, line, grip);
  if (rc)
    return rc; /* we can't jump to leave because this is already an
                  Assuan error code. */

  rc = agent_key_from_file (ctrl, ctrl->server_local->keydesc,
                            grip, &shadow_info, 1, &s_skey);
  if (rc)
    ;
  else if (!s_skey)
    {
      log_error ("changing a smartcard PIN is not yet supported\n");
      rc = gpg_error (GPG_ERR_NOT_IMPLEMENTED);
    }
  else
    rc = agent_protect_and_store (ctrl, s_skey);

  xfree (ctrl->server_local->keydesc);
  ctrl->server_local->keydesc = NULL;
  gcry_sexp_release (s_skey);
  xfree (shadow_info);
  if (rc)
    log_error ("command passwd failed: %s\n", gpg_strerror (rc));
  return map_to_assuan_status (rc);
}


/* SCD <commands to pass to the scdaemon>
  
   This is a general quote command to redirect everything to the
   SCDAEMON. */
static int
cmd_scd (ASSUAN_CONTEXT ctx, char *line)
{
  ctrl_t ctrl = assuan_get_pointer (ctx);
  int rc;

  rc = divert_generic_cmd (ctrl, line, ctx);

  return map_to_assuan_status (rc);
}



static int
option_handler (ASSUAN_CONTEXT ctx, const char *key, const char *value)
{
  ctrl_t ctrl = assuan_get_pointer (ctx);

  if (!strcmp (key, "display"))
    {
      if (ctrl->display)
        free (ctrl->display);
      ctrl->display = strdup (value);
      if (!ctrl->display)
        return ASSUAN_Out_Of_Core;
    }
  else if (!strcmp (key, "ttyname"))
    {
      if (!opt.keep_tty)
        {
          if (ctrl->ttyname)
            free (ctrl->ttyname);
          ctrl->ttyname = strdup (value);
          if (!ctrl->ttyname)
            return ASSUAN_Out_Of_Core;
        }
    }
  else if (!strcmp (key, "ttytype"))
    {
      if (!opt.keep_tty)
        {
          if (ctrl->ttytype)
            free (ctrl->ttytype);
          ctrl->ttytype = strdup (value);
          if (!ctrl->ttytype)
            return ASSUAN_Out_Of_Core;
        }
    }
  else if (!strcmp (key, "lc-ctype"))
    {
      if (ctrl->lc_ctype)
        free (ctrl->lc_ctype);
      ctrl->lc_ctype = strdup (value);
      if (!ctrl->lc_ctype)
        return ASSUAN_Out_Of_Core;
    }
  else if (!strcmp (key, "lc-messages"))
    {
      if (ctrl->lc_messages)
        free (ctrl->lc_messages);
      ctrl->lc_messages = strdup (value);
      if (!ctrl->lc_messages)
        return ASSUAN_Out_Of_Core;
    }
  else if (!strcmp (key, "use-cache-for-signing"))
    ctrl->server_local->use_cache_for_signing = *value? atoi (value) : 0;
  else
    return ASSUAN_Invalid_Option;

  return 0;
}


/* Tell the assuan library about our commands */
static int
register_commands (ASSUAN_CONTEXT ctx)
{
  static struct {
    const char *name;
    int (*handler)(ASSUAN_CONTEXT, char *line);
  } table[] = {
    { "ISTRUSTED",      cmd_istrusted },
    { "HAVEKEY",        cmd_havekey },
    { "SIGKEY",         cmd_sigkey },
    { "SETKEY",         cmd_sigkey },
    { "SETKEYDESC",     cmd_setkeydesc },
    { "SETHASH",        cmd_sethash },
    { "PKSIGN",         cmd_pksign },
    { "PKDECRYPT",      cmd_pkdecrypt },
    { "GENKEY",         cmd_genkey },
    { "GET_PASSPHRASE", cmd_get_passphrase },
    { "CLEAR_PASSPHRASE", cmd_clear_passphrase },
    { "GET_CONFIRMATION", cmd_get_confirmation },
    { "LISTTRUSTED",    cmd_listtrusted },
    { "MARKTRUSTED",    cmd_marktrusted },
    { "LEARN",          cmd_learn },
    { "PASSWD",         cmd_passwd },
    { "INPUT",          NULL }, 
    { "OUTPUT",         NULL }, 
    { "SCD",            cmd_scd },
    { NULL }
  };
  int i, rc;

  for (i=0; table[i].name; i++)
    {
      rc = assuan_register_command (ctx, table[i].name, table[i].handler);
      if (rc)
        return rc;
    } 
  assuan_register_reset_notify (ctx, reset_notify);
  assuan_register_option_handler (ctx, option_handler);
  return 0;
}


/* Startup the server.  If LISTEN_FD and FD is given as -1, this is a simple
   piper server, otherwise it is a regular server */
void
start_command_handler (int listen_fd, int fd)
{
  int rc;
  ASSUAN_CONTEXT ctx;
  struct server_control_s ctrl;

  memset (&ctrl, 0, sizeof ctrl);
  agent_init_default_ctrl (&ctrl);
  
  if (listen_fd == -1 && fd == -1)
    {
      int filedes[2];

      filedes[0] = 0;
      filedes[1] = 1;
      rc = assuan_init_pipe_server (&ctx, filedes);
    }
  else if (listen_fd != -1)
    {
      rc = assuan_init_socket_server (&ctx, listen_fd);
    }
  else 
    {
      rc = assuan_init_connected_socket_server (&ctx, fd);
      ctrl.connection_fd = fd;
    }
  if (rc)
    {
      log_error ("failed to initialize the server: %s\n",
                 assuan_strerror(rc));
      agent_exit (2);
    }
  rc = register_commands (ctx);
  if (rc)
    {
      log_error ("failed to register commands with Assuan: %s\n",
                 assuan_strerror(rc));
      agent_exit (2);
    }

  assuan_set_pointer (ctx, &ctrl);
  ctrl.server_local = xcalloc (1, sizeof *ctrl.server_local);
  ctrl.server_local->assuan_ctx = ctx;
  ctrl.server_local->message_fd = -1;
  ctrl.server_local->use_cache_for_signing = 1;
  ctrl.digest.raw_value = 0;

  if (DBG_ASSUAN)
    assuan_set_log_stream (ctx, log_get_stream ());

  for (;;)
    {
      rc = assuan_accept (ctx);
      if (rc == -1)
        {
          break;
        }
      else if (rc)
        {
          log_info ("Assuan accept problem: %s\n", assuan_strerror (rc));
          break;
        }
      
      rc = assuan_process (ctx);
      if (rc)
        {
          log_info ("Assuan processing failed: %s\n", assuan_strerror (rc));
          continue;
        }
    }

  /* Reset the SCD if needed. */
  agent_reset_scd (&ctrl);

  assuan_deinit_server (ctx);
  if (ctrl.display)
    free (ctrl.display);
  if (ctrl.ttyname)
    free (ctrl.ttyname);
  if (ctrl.ttytype)
    free (ctrl.ttytype);
  if (ctrl.lc_ctype)
    free (ctrl.lc_ctype);
  if (ctrl.lc_messages)
    free (ctrl.lc_messages);
}

