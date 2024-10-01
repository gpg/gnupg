/* command.c - gpg-agent command handler
 * Copyright (C) 2001-2011 Free Software Foundation, Inc.
 * Copyright (C) 2001-2013 Werner Koch
 * Copyright (C) 2015 g10 Code GmbH.
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

/* FIXME: we should not use the default assuan buffering but setup
   some buffering in secure mempory to protect session keys etc. */

#include <config.h>

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <unistd.h>
#include <assert.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <dirent.h>

#include "agent.h"
#include <assuan.h>
#include "../common/i18n.h"
#include "cvt-openpgp.h"
#include "../common/ssh-utils.h"
#include "../common/asshelp.h"
#include "../common/server-help.h"


/* Maximum allowed size of the inquired ciphertext.  */
#define MAXLEN_CIPHERTEXT 4096
/* Maximum allowed size of the key parameters.  */
#define MAXLEN_KEYPARAM 1024
/* Maximum allowed size of key data as used in inquiries (bytes). */
#define MAXLEN_KEYDATA 8192
/* The size of the import/export KEK key (in bytes).  */
#define KEYWRAP_KEYSIZE (128/8)

/* A shortcut to call assuan_set_error using an gpg_err_code_t and a
   text string.  */
#define set_error(e,t) assuan_set_error (ctx, gpg_error (e), (t))

/* Check that the maximum digest length we support has at least the
   length of the keygrip.  */
#if MAX_DIGEST_LEN < 20
#error MAX_DIGEST_LEN shorter than keygrip
#endif

/* Data used to associate an Assuan context with local server data.
   This is this modules local part of the server_control_s struct.  */
struct server_local_s
{
  /* Our Assuan context.  */
  assuan_context_t assuan_ctx;

  /* If this flag is true, the passphrase cache is used for signing
     operations.  It defaults to true but may be set on a per
     connection base.  The global option opt.ignore_cache_for_signing
     takes precedence over this flag.  */
  unsigned int use_cache_for_signing : 1;

  /* Flag to suppress I/O logging during a command.  */
  unsigned int pause_io_logging : 1;

  /* Flag indicating that the connection is from ourselves.  */
  unsigned int connect_from_self : 1;

  /* Helper flag for io_monitor to allow suppressing of our own
   * greeting in some cases.  See io_monitor for details.  */
  unsigned int greeting_seen : 1;

  /* If this flag is set to true the agent will be terminated after
     the end of the current session.  */
  unsigned int stopme : 1;

  /* Flag indicating whether pinentry notifications shall be done. */
  unsigned int allow_pinentry_notify : 1;

  /* An allocated description for the next key operation.  This is
     used if a pinnetry needs to be popped up.  */
  char *keydesc;

  /* Malloced KEK (Key-Encryption-Key) for the import_key command.  */
  void *import_key;

  /* Malloced KEK for the export_key command.  */
  void *export_key;

  /* Client is aware of the error code GPG_ERR_FULLY_CANCELED.  */
  int allow_fully_canceled;

  /* Last CACHE_NONCE sent as status (malloced).  */
  char *last_cache_nonce;

  /* Last PASSWD_NONCE sent as status (malloced). */
  char *last_passwd_nonce;
};


/* An entry for the getval/putval commands. */
struct putval_item_s
{
  struct putval_item_s *next;
  size_t off;  /* Offset to the value into DATA.  */
  size_t len;  /* Length of the value.  */
  char d[1];   /* Key | Nul | value.  */
};


/* A list of key value pairs fpr the getval/putval commands.  */
static struct putval_item_s *putval_list;



/* To help polling clients, we keep track of the number of certain
   events.  This structure keeps those counters.  The counters are
   integers and there should be no problem if they are overflowing as
   callers need to check only whether a counter changed.  The actual
   values are not meaningful. */
struct
{
  /* Incremented if any of the other counters below changed. */
  unsigned int any;

  /* Incremented if a key is added or removed from the internal privat
     key database. */
  unsigned int key;

  /* Incremented if a change of the card readers stati has been
     detected. */
  unsigned int card;

} eventcounter;



/*  Local prototypes.  */
static int command_has_option (const char *cmd, const char *cmdopt);




/* Release the memory buffer MB but first wipe out the used memory. */
static void
clear_outbuf (membuf_t *mb)
{
  void *p;
  size_t n;

  p = get_membuf (mb, &n);
  if (p)
    {
      wipememory (p, n);
      xfree (p);
    }
}


/* Write the content of memory buffer MB as assuan data to CTX and
   wipe the buffer out afterwards. */
static gpg_error_t
write_and_clear_outbuf (assuan_context_t ctx, membuf_t *mb)
{
  gpg_error_t ae;
  void *p;
  size_t n;

  p = get_membuf (mb, &n);
  if (!p)
    return out_of_core ();
  ae = assuan_send_data (ctx, p, n);
  memset (p, 0, n);
  xfree (p);
  return ae;
}


/* Clear the nonces used to enable the passphrase cache for certain
   multi-command command sequences.  */
static void
clear_nonce_cache (ctrl_t ctrl)
{
  if (ctrl->server_local->last_cache_nonce)
    {
      agent_put_cache (ctrl, ctrl->server_local->last_cache_nonce,
                       CACHE_MODE_NONCE, NULL, 0);
      xfree (ctrl->server_local->last_cache_nonce);
      ctrl->server_local->last_cache_nonce = NULL;
    }
  if (ctrl->server_local->last_passwd_nonce)
    {
      agent_put_cache (ctrl, ctrl->server_local->last_passwd_nonce,
                       CACHE_MODE_NONCE, NULL, 0);
      xfree (ctrl->server_local->last_passwd_nonce);
      ctrl->server_local->last_passwd_nonce = NULL;
    }
}


/* This function is called by Libassuan whenever the client sends a
   reset.  It has been registered similar to the other Assuan
   commands.  */
static gpg_error_t
reset_notify (assuan_context_t ctx, char *line)
{
  ctrl_t ctrl = assuan_get_pointer (ctx);

  (void) line;

  memset (ctrl->keygrip, 0, 20);
  ctrl->have_keygrip = 0;
  ctrl->digest.valuelen = 0;

  xfree (ctrl->server_local->keydesc);
  ctrl->server_local->keydesc = NULL;

  clear_nonce_cache (ctrl);

  return 0;
}


/* Replace all '+' by a blank in the string S. */
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
parse_hexstring (assuan_context_t ctx, const char *string, size_t *len)
{
  const char *p;
  size_t n;

  /* parse the hash value */
  for (p=string, n=0; hexdigitp (p); p++, n++)
    ;
  if (*p != ' ' && *p != '\t' && *p)
    return set_error (GPG_ERR_ASS_PARAMETER, "invalid hexstring");
  if ((n&1))
    return set_error (GPG_ERR_ASS_PARAMETER, "odd number of digits");
  *len = n;
  return 0;
}


/* Parse the keygrip in STRING into the provided buffer BUF.  BUF must
   provide space for 20 bytes.  BUF is not changed if the function
   returns an error. */
static int
parse_keygrip (assuan_context_t ctx, const char *string, unsigned char *buf)
{
  int rc;
  size_t n = 0;

  rc = parse_hexstring (ctx, string, &n);
  if (rc)
    return rc;
  n /= 2;
  if (n != 20)
    return set_error (GPG_ERR_ASS_PARAMETER, "invalid length of keygrip");

  if (hex2bin (string, buf, 20) < 0)
    return set_error (GPG_ERR_BUG, "hex2bin");

  return 0;
}


/* Write an Assuan status line.  KEYWORD is the first item on the
 * status line.  The following arguments are all separated by a space
 * in the output.  The last argument must be a NULL.  Linefeeds and
 * carriage returns characters (which are not allowed in an Assuan
 * status line) are silently quoted in C-style.  */
gpg_error_t
agent_write_status (ctrl_t ctrl, const char *keyword, ...)
{
  gpg_error_t err;
  va_list arg_ptr;
  assuan_context_t ctx = ctrl->server_local->assuan_ctx;

  va_start (arg_ptr, keyword);
  err = vprint_assuan_status_strings (ctx, keyword, arg_ptr);
  va_end (arg_ptr);
  return err;
}


/* This function is similar to print_assuan_status but takes a CTRL
   arg instead of an assuan context as first argument.  */
gpg_error_t
agent_print_status (ctrl_t ctrl, const char *keyword, const char *format, ...)
{
  gpg_error_t err;
  va_list arg_ptr;
  assuan_context_t ctx = ctrl->server_local->assuan_ctx;

  va_start (arg_ptr, format);
  err = vprint_assuan_status (ctx, keyword, format, arg_ptr);
  va_end (arg_ptr);
  return err;
}


/* Helper to notify the client about a launched Pinentry.  Because
   that might disturb some older clients, this is only done if enabled
   via an option.  Returns an gpg error code. */
gpg_error_t
agent_inq_pinentry_launched (ctrl_t ctrl, unsigned long pid, const char *extra)
{
  char line[256];

  if (!ctrl || !ctrl->server_local
      || !ctrl->server_local->allow_pinentry_notify)
    return 0;
  snprintf (line, DIM(line), "PINENTRY_LAUNCHED %lu%s%s",
            pid, extra?" ":"", extra? extra:"");
  return assuan_inquire (ctrl->server_local->assuan_ctx, line, NULL, NULL, 0);
}


/* An agent progress callback for Libgcrypt.  This has been registered
 * to be called via the progress dispatcher mechanism from
 * gpg-agent.c  */
static void
progress_cb (ctrl_t ctrl, const char *what, int printchar,
             int current, int total)
{
  if (!ctrl || !ctrl->server_local || !ctrl->server_local->assuan_ctx)
    ;
  else if (printchar == '\n' && what && !strcmp (what, "primegen"))
    agent_print_status (ctrl, "PROGRESS", "%.20s X 100 100", what);
  else
    agent_print_status (ctrl, "PROGRESS", "%.20s %c %d %d",
                        what, printchar=='\n'?'X':printchar, current, total);
}


/* Helper to print a message while leaving a command.  Note that this
 * function does not call assuan_set_error; the caller may do this
 * prior to calling us.  */
static gpg_error_t
leave_cmd (assuan_context_t ctx, gpg_error_t err)
{
  if (err)
    {
      const char *name = assuan_get_command_name (ctx);
      if (!name)
        name = "?";

      /* Not all users of gpg-agent know about the fully canceled
         error code; map it back if needed.  */
      if (gpg_err_code (err) == GPG_ERR_FULLY_CANCELED)
        {
          ctrl_t ctrl = assuan_get_pointer (ctx);

          if (!ctrl->server_local->allow_fully_canceled)
            err = gpg_err_make (gpg_err_source (err), GPG_ERR_CANCELED);
        }

      /* Most code from common/ does not know the error source, thus
         we fix this here.  */
      if (gpg_err_source (err) == GPG_ERR_SOURCE_UNKNOWN)
        err = gpg_err_make (GPG_ERR_SOURCE_DEFAULT, gpg_err_code (err));

      if (gpg_err_source (err) == GPG_ERR_SOURCE_DEFAULT)
        log_error ("command '%s' failed: %s\n", name,
                   gpg_strerror (err));
      else
        log_error ("command '%s' failed: %s <%s>\n", name,
                   gpg_strerror (err), gpg_strsource (err));
    }
  return err;
}



static const char hlp_geteventcounter[] =
  "GETEVENTCOUNTER\n"
  "\n"
  "Return a status line named EVENTCOUNTER with the current values\n"
  "of all event counters.  The values are decimal numbers in the range\n"
  "0 to UINT_MAX and wrapping around to 0.  The actual values should\n"
  "not be relied upon, they shall only be used to detect a change.\n"
  "\n"
  "The currently defined counters are:\n"
  "\n"
  "ANY  - Incremented with any change of any of the other counters.\n"
  "KEY  - Incremented for added or removed private keys.\n"
  "CARD - Incremented for changes of the card readers stati.";
static gpg_error_t
cmd_geteventcounter (assuan_context_t ctx, char *line)
{
  ctrl_t ctrl = assuan_get_pointer (ctx);

  (void)line;

  if (ctrl->restricted)
    return leave_cmd (ctx, gpg_error (GPG_ERR_FORBIDDEN));

  return agent_print_status (ctrl, "EVENTCOUNTER", "%u %u %u",
                             eventcounter.any,
                             eventcounter.key,
                             eventcounter.card);
}


/* This function should be called once for all key removals or
   additions.  This function is assured not to do any context
   switches. */
void
bump_key_eventcounter (void)
{
  eventcounter.key++;
  eventcounter.any++;
}


/* This function should be called for all card reader status
   changes.  This function is assured not to do any context
   switches. */
void
bump_card_eventcounter (void)
{
  eventcounter.card++;
  eventcounter.any++;
}




static const char hlp_istrusted[] =
  "ISTRUSTED <hexstring_with_fingerprint>\n"
  "\n"
  "Return OK when we have an entry with this fingerprint in our\n"
  "trustlist";
static gpg_error_t
cmd_istrusted (assuan_context_t ctx, char *line)
{
  ctrl_t ctrl = assuan_get_pointer (ctx);
  int rc, n, i;
  char *p;
  char fpr[41];

  /* Parse the fingerprint value. */
  for (p=line,n=0; hexdigitp (p); p++, n++)
    ;
  if (*p || !(n == 40 || n == 32))
    return set_error (GPG_ERR_ASS_PARAMETER, "invalid fingerprint");
  i = 0;
  if (n==32)
    {
      strcpy (fpr, "00000000");
      i += 8;
    }
  for (p=line; i < 40; p++, i++)
    fpr[i] = *p >= 'a'? (*p & 0xdf): *p;
  fpr[i] = 0;
  rc = agent_istrusted (ctrl, fpr, NULL);
  if (!rc || gpg_err_code (rc) == GPG_ERR_NOT_TRUSTED)
    return rc;
  else if (rc == -1 || gpg_err_code (rc) == GPG_ERR_EOF )
    return gpg_error (GPG_ERR_NOT_TRUSTED);
  else
    return leave_cmd (ctx, rc);
}


static const char hlp_listtrusted[] =
  "LISTTRUSTED [--status]\n"
  "\n"
  "List all entries from the trustlist.  With --status the\n"
  "keys are listed using status line similar to ISTRUSTED";
static gpg_error_t
cmd_listtrusted (assuan_context_t ctx, char *line)
{
  ctrl_t ctrl = assuan_get_pointer (ctx);
  gpg_error_t err;
  int opt_status;

  opt_status = has_option (line, "--status");

  if (ctrl->restricted)
    return leave_cmd (ctx, gpg_error (GPG_ERR_FORBIDDEN));

  err = agent_listtrusted (ctrl, ctx, opt_status);
  return leave_cmd (ctx, err);
}


static const char hlp_martrusted[] =
  "MARKTRUSTED <hexstring_with_fingerprint> <flag> <display_name>\n"
  "\n"
  "Store a new key in into the trustlist.";
static gpg_error_t
cmd_marktrusted (assuan_context_t ctx, char *line)
{
  ctrl_t ctrl = assuan_get_pointer (ctx);
  int rc, n, i;
  char *p;
  char fpr[41];
  int flag;

  if (ctrl->restricted)
    return leave_cmd (ctx, gpg_error (GPG_ERR_FORBIDDEN));

  /* parse the fingerprint value */
  for (p=line,n=0; hexdigitp (p); p++, n++)
    ;
  if (!spacep (p) || !(n == 40 || n == 32))
    return set_error (GPG_ERR_ASS_PARAMETER, "invalid fingerprint");
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
    return set_error (GPG_ERR_ASS_PARAMETER, "invalid flag - must be P or S");
  while (spacep (p))
    p++;

  rc = agent_marktrusted (ctrl, p, fpr, flag);
  return leave_cmd (ctx, rc);
}




static const char hlp_havekey[] =
  "HAVEKEY <hexstrings_with_keygrips>\n"
  "\n"
  "Return success if at least one of the secret keys with the given\n"
  "keygrips is available.";
static gpg_error_t
cmd_havekey (assuan_context_t ctx, char *line)
{
  gpg_error_t err;
  unsigned char buf[20];

  do
    {
      err = parse_keygrip (ctx, line, buf);
      if (err)
        return err;

      if (!agent_key_available (buf))
        return 0; /* Found.  */

      while (*line && *line != ' ' && *line != '\t')
        line++;
      while (*line == ' ' || *line == '\t')
        line++;
    }
  while (*line);

  /* No leave_cmd() here because errors are expected and would clutter
     the log.  */
  return gpg_error (GPG_ERR_NO_SECKEY);
}


static const char hlp_sigkey[] =
  "SIGKEY <hexstring_with_keygrip>\n"
  "SETKEY <hexstring_with_keygrip>\n"
  "\n"
  "Set the  key used for a sign or decrypt operation.";
static gpg_error_t
cmd_sigkey (assuan_context_t ctx, char *line)
{
  int rc;
  ctrl_t ctrl = assuan_get_pointer (ctx);

  rc = parse_keygrip (ctx, line, ctrl->keygrip);
  if (rc)
    return rc;
  ctrl->have_keygrip = 1;
  return 0;
}


static const char hlp_setkeydesc[] =
  "SETKEYDESC plus_percent_escaped_string\n"
  "\n"
  "Set a description to be used for the next PKSIGN, PKDECRYPT, IMPORT_KEY\n"
  "or EXPORT_KEY operation if this operation requires a passphrase.  If\n"
  "this command is not used a default text will be used.  Note, that\n"
  "this description implictly selects the label used for the entry\n"
  "box; if the string contains the string PIN (which in general will\n"
  "not be translated), \"PIN\" is used, otherwise the translation of\n"
  "\"passphrase\" is used.  The description string should not contain\n"
  "blanks unless they are percent or '+' escaped.\n"
  "\n"
  "The description is only valid for the next PKSIGN, PKDECRYPT,\n"
  "IMPORT_KEY, EXPORT_KEY, or DELETE_KEY operation.";
static gpg_error_t
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

  if (!*desc)
    return set_error (GPG_ERR_ASS_PARAMETER, "no description given");

  /* Note, that we only need to replace the + characters and should
     leave the other escaping in place because the escaped string is
     send verbatim to the pinentry which does the unescaping (but not
     the + replacing) */
  plus_to_blank (desc);

  xfree (ctrl->server_local->keydesc);

  if (ctrl->restricted)
    {
      ctrl->server_local->keydesc = strconcat
        ((ctrl->restricted == 2
         ? _("Note: Request from the web browser.")
         : _("Note: Request from a remote site.")  ), "%0A%0A", desc, NULL);
    }
  else
    ctrl->server_local->keydesc = xtrystrdup (desc);
  if (!ctrl->server_local->keydesc)
    return out_of_core ();
  return 0;
}


static const char hlp_sethash[] =
  "SETHASH (--hash=<name>)|(<algonumber>) <hexstring>\n"
  "\n"
  "The client can use this command to tell the server about the data\n"
  "(which usually is a hash) to be signed.";
static gpg_error_t
cmd_sethash (assuan_context_t ctx, char *line)
{
  int rc;
  size_t n;
  char *p;
  ctrl_t ctrl = assuan_get_pointer (ctx);
  unsigned char *buf;
  char *endp;
  int algo;

  /* Parse the alternative hash options which may be used instead of
     the algo number.  */
  if (has_option_name (line, "--hash"))
    {
      if (has_option (line, "--hash=sha1"))
        algo = GCRY_MD_SHA1;
      else if (has_option (line, "--hash=sha224"))
        algo = GCRY_MD_SHA224;
      else if (has_option (line, "--hash=sha256"))
        algo = GCRY_MD_SHA256;
      else if (has_option (line, "--hash=sha384"))
        algo = GCRY_MD_SHA384;
      else if (has_option (line, "--hash=sha512"))
        algo = GCRY_MD_SHA512;
      else if (has_option (line, "--hash=rmd160"))
        algo = GCRY_MD_RMD160;
      else if (has_option (line, "--hash=md5"))
        algo = GCRY_MD_MD5;
      else if (has_option (line, "--hash=tls-md5sha1"))
        algo = MD_USER_TLS_MD5SHA1;
      else
        return set_error (GPG_ERR_ASS_PARAMETER, "invalid hash algorithm");
    }
  else
    algo = 0;

  line = skip_options (line);

  if (!algo)
    {
      /* No hash option has been given: require an algo number instead  */
      algo = (int)strtoul (line, &endp, 10);
      for (line = endp; *line == ' ' || *line == '\t'; line++)
        ;
      if (!algo || gcry_md_test_algo (algo))
        return set_error (GPG_ERR_UNSUPPORTED_ALGORITHM, NULL);
    }
  ctrl->digest.algo = algo;
  ctrl->digest.raw_value = 0;

  /* Parse the hash value. */
  n = 0;
  rc = parse_hexstring (ctx, line, &n);
  if (rc)
    return rc;
  n /= 2;
  if (algo == MD_USER_TLS_MD5SHA1 && n == 36)
    ;
  else if (n != 16 && n != 20 && n != 24
           && n != 28 && n != 32 && n != 48 && n != 64)
    return set_error (GPG_ERR_ASS_PARAMETER, "unsupported length of hash");

  if (n > MAX_DIGEST_LEN)
    return set_error (GPG_ERR_ASS_PARAMETER, "hash value to long");

  buf = ctrl->digest.value;
  ctrl->digest.valuelen = n;
  for (p=line, n=0; n < ctrl->digest.valuelen; p += 2, n++)
    buf[n] = xtoi_2 (p);
  for (; n < ctrl->digest.valuelen; n++)
    buf[n] = 0;
  return 0;
}


static const char hlp_pksign[] =
  "PKSIGN [<options>] [<cache_nonce>]\n"
  "\n"
  "Perform the actual sign operation.  Neither input nor output are\n"
  "sensitive to eavesdropping.";
static gpg_error_t
cmd_pksign (assuan_context_t ctx, char *line)
{
  gpg_error_t err;
  cache_mode_t cache_mode = CACHE_MODE_NORMAL;
  ctrl_t ctrl = assuan_get_pointer (ctx);
  membuf_t outbuf;
  char *cache_nonce = NULL;
  char *p;

  line = skip_options (line);

  for (p=line; *p && *p != ' ' && *p != '\t'; p++)
    ;
  *p = '\0';
  if (*line)
    cache_nonce = xtrystrdup (line);

  if (opt.ignore_cache_for_signing)
    cache_mode = CACHE_MODE_IGNORE;
  else if (!ctrl->server_local->use_cache_for_signing)
    cache_mode = CACHE_MODE_IGNORE;

  init_membuf (&outbuf, 512);

  err = agent_pksign (ctrl, cache_nonce, ctrl->server_local->keydesc,
                      &outbuf, cache_mode);
  if (err)
    clear_outbuf (&outbuf);
  else
    err = write_and_clear_outbuf (ctx, &outbuf);

  xfree (cache_nonce);
  xfree (ctrl->server_local->keydesc);
  ctrl->server_local->keydesc = NULL;
  return leave_cmd (ctx, err);
}


static const char hlp_pkdecrypt[] =
  "PKDECRYPT [<options>]\n"
  "\n"
  "Perform the actual decrypt operation.  Input is not\n"
  "sensitive to eavesdropping.";
static gpg_error_t
cmd_pkdecrypt (assuan_context_t ctx, char *line)
{
  int rc;
  ctrl_t ctrl = assuan_get_pointer (ctx);
  unsigned char *value;
  size_t valuelen;
  membuf_t outbuf;
  int padding;

  (void)line;

  /* First inquire the data to decrypt */
  rc = print_assuan_status (ctx, "INQUIRE_MAXLEN", "%u", MAXLEN_CIPHERTEXT);
  if (!rc)
    rc = assuan_inquire (ctx, "CIPHERTEXT",
			&value, &valuelen, MAXLEN_CIPHERTEXT);
  if (rc)
    return rc;

  init_membuf (&outbuf, 512);

  rc = agent_pkdecrypt (ctrl, ctrl->server_local->keydesc,
                        value, valuelen, &outbuf, &padding);
  xfree (value);
  if (rc)
    clear_outbuf (&outbuf);
  else
    {
      if (padding != -1)
        rc = print_assuan_status (ctx, "PADDING", "%d", padding);
      else
        rc = 0;
      if (!rc)
        rc = write_and_clear_outbuf (ctx, &outbuf);
    }
  xfree (ctrl->server_local->keydesc);
  ctrl->server_local->keydesc = NULL;
  return leave_cmd (ctx, rc);
}


static const char hlp_genkey[] =
  "GENKEY [--no-protection] [--preset] [--timestamp=<isodate>]\n"
  "       [--inq-passwd] [--passwd-nonce=<s>] [<cache_nonce>]\n"
  "\n"
  "Generate a new key, store the secret part and return the public\n"
  "part.  Here is an example transaction:\n"
  "\n"
  "  C: GENKEY\n"
  "  S: INQUIRE KEYPARAM\n"
  "  C: D (genkey (rsa (nbits  2048)))\n"
  "  C: END\n"
  "  S: D (public-key\n"
  "  S: D   (rsa (n 326487324683264) (e 10001)))\n"
  "  S: OK key created\n"
  "\n"
  "If the --preset option is used the passphrase for the generated\n"
  "key will be added to the cache.  If --inq-passwd is used an inquire\n"
  "with the keyword NEWPASSWD is used to request the passphrase for the\n"
  "new key.  If a --passwd-nonce is used, the corresponding cached\n"
  "passphrase is used to protect the new key.  If --timestamp is given\n"
  "its value is recorded as the key's creation time; the value is\n"
  "expected in ISO format (e.g. \"20030316T120000\").";
static gpg_error_t
cmd_genkey (assuan_context_t ctx, char *line)
{
  ctrl_t ctrl = assuan_get_pointer (ctx);
  int rc;
  int no_protection;
  unsigned char *value = NULL;
  size_t valuelen;
  unsigned char *newpasswd = NULL;
  membuf_t outbuf;
  char *cache_nonce = NULL;
  char *passwd_nonce = NULL;
  int opt_preset;
  int opt_inq_passwd;
  size_t n;
  char *p, *pend;
  const char *s;
  time_t opt_timestamp;
  int c;

  init_membuf (&outbuf, 512);

  if (ctrl->restricted)
    return leave_cmd (ctx, gpg_error (GPG_ERR_FORBIDDEN));

  no_protection = has_option (line, "--no-protection");
  opt_preset = has_option (line, "--preset");
  opt_inq_passwd = has_option (line, "--inq-passwd");
  passwd_nonce = option_value (line, "--passwd-nonce");
  if (passwd_nonce)
    {
      for (pend = passwd_nonce; *pend && !spacep (pend); pend++)
        ;
      c = *pend;
      *pend = '\0';
      passwd_nonce = xtrystrdup (passwd_nonce);
      *pend = c;
      if (!passwd_nonce)
        {
          rc = gpg_error_from_syserror ();
          goto leave;
        }
    }
  if ((s=has_option_name (line, "--timestamp")))
    {
      if (*s != '=')
        {
          rc = set_error (GPG_ERR_ASS_PARAMETER, "missing value for option");
          goto leave;
        }
      opt_timestamp = isotime2epoch (s+1);
      if (opt_timestamp < 1)
        {
          rc = set_error (GPG_ERR_ASS_PARAMETER, "invalid time value");
          goto leave;
        }
    }
  else
    opt_timestamp = 0;
  line = skip_options (line);

  for (p=line; *p && *p != ' ' && *p != '\t'; p++)
    ;
  *p = '\0';
  if (*line)
    cache_nonce = xtrystrdup (line);

  /* First inquire the parameters */
  rc = print_assuan_status (ctx, "INQUIRE_MAXLEN", "%u", MAXLEN_KEYPARAM);
  if (!rc)
    rc = assuan_inquire (ctx, "KEYPARAM", &value, &valuelen, MAXLEN_KEYPARAM);
  if (rc)
    return rc;

  /* If requested, ask for the password to be used for the key.  If
     this is not used the regular Pinentry mechanism is used.  */
  if (opt_inq_passwd && !no_protection)
    {
      /* (N is used as a dummy) */
      assuan_begin_confidential (ctx);
      rc = assuan_inquire (ctx, "NEWPASSWD", &newpasswd, &n, 256);
      assuan_end_confidential (ctx);
      if (rc)
        goto leave;
      if (!*newpasswd)
        {
          /* Empty password given - switch to no-protection mode.  */
          xfree (newpasswd);
          newpasswd = NULL;
          no_protection = 1;
        }

    }
  else if (passwd_nonce)
    newpasswd = agent_get_cache (ctrl, passwd_nonce, CACHE_MODE_NONCE);

  rc = agent_genkey (ctrl, cache_nonce, opt_timestamp,
                     (char*)value, valuelen, no_protection,
                     newpasswd, opt_preset, &outbuf);

 leave:
  if (newpasswd)
    {
      /* Assuan_inquire does not allow us to read into secure memory
         thus we need to wipe it ourself.  */
      wipememory (newpasswd, strlen (newpasswd));
      xfree (newpasswd);
    }
  xfree (value);
  if (rc)
    clear_outbuf (&outbuf);
  else
    rc = write_and_clear_outbuf (ctx, &outbuf);
  xfree (cache_nonce);
  xfree (passwd_nonce);
  return leave_cmd (ctx, rc);
}



static const char hlp_readkey[] =
  "READKEY [--no-data] <hexstring_with_keygrip>\n"
  "                    --card <keyid>\n"
  "\n"
  "Return the public key for the given keygrip or keyid.\n"
  "With --card, private key file with card information will be created.";
static gpg_error_t
cmd_readkey (assuan_context_t ctx, char *line)
{
  ctrl_t ctrl = assuan_get_pointer (ctx);
  int rc;
  unsigned char grip[20];
  gcry_sexp_t s_pkey = NULL;
  unsigned char *pkbuf = NULL;
  char *serialno = NULL;
  char *keyidbuf = NULL;
  size_t pkbuflen;
  int opt_card, opt_no_data;
  char *dispserialno = NULL;

  if (ctrl->restricted)
    return leave_cmd (ctx, gpg_error (GPG_ERR_FORBIDDEN));

  opt_no_data = has_option (line, "--no-data");
  opt_card = has_option (line, "--card");
  line = skip_options (line);

  if (opt_card)
    {
      const char *keyid = line;

      rc = agent_card_getattr (ctrl, "SERIALNO", &serialno);
      if (rc)
        {
          log_error (_("error getting serial number of card: %s\n"),
                     gpg_strerror (rc));
          goto leave;
        }

      /* Hack to create the shadow key for the standard keys.  */
      if ((!strcmp (keyid, "$SIGNKEYID") || !strcmp (keyid, "$ENCRKEYID")
           || !strcmp (keyid, "$AUTHKEYID"))
          && !agent_card_getattr (ctrl, keyid, &keyidbuf))
        keyid = keyidbuf;

      rc = agent_card_readkey (ctrl, keyid, &pkbuf);
      if (rc)
        goto leave;
      pkbuflen = gcry_sexp_canon_len (pkbuf, 0, NULL, NULL);
      rc = gcry_sexp_sscan (&s_pkey, NULL, (char*)pkbuf, pkbuflen);
      if (rc)
        goto leave;

      if (!gcry_pk_get_keygrip (s_pkey, grip))
        {
          rc = gcry_pk_testkey (s_pkey);
          if (rc == 0)
            rc = gpg_error (GPG_ERR_INTERNAL);

          goto leave;
        }

      agent_card_getattr (ctrl, "$DISPSERIALNO", &dispserialno);
      /* Shadow-key is or is not available in our key storage.  In
       * any case we need to check whether we need to update with
       * a new display-s/n or whatever.  */
      rc = agent_write_shadow_key (grip, serialno, keyid, pkbuf, 0, 0,
                                   dispserialno);
      if (rc)
        goto leave;

      rc = opt_no_data? 0 : assuan_send_data (ctx, pkbuf, pkbuflen);
    }
  else
    {
      rc = parse_keygrip (ctx, line, grip);
      if (rc)
        goto leave;

      rc = agent_public_key_from_file (ctrl, grip, &s_pkey);
      if (!rc)
        {
          pkbuflen = gcry_sexp_sprint (s_pkey, GCRYSEXP_FMT_CANON, NULL, 0);
          log_assert (pkbuflen);
          pkbuf = xtrymalloc (pkbuflen);
          if (!pkbuf)
            rc = gpg_error_from_syserror ();
          else
            {
              pkbuflen = gcry_sexp_sprint (s_pkey, GCRYSEXP_FMT_CANON,
                                           pkbuf, pkbuflen);
              rc = opt_no_data? 0 : assuan_send_data (ctx, pkbuf, pkbuflen);
            }
        }
    }

 leave:
  xfree (keyidbuf);
  xfree (serialno);
  xfree (pkbuf);
  xfree (dispserialno);
  gcry_sexp_release (s_pkey);
  return leave_cmd (ctx, rc);
}



static const char hlp_keyinfo[] =
  "KEYINFO [--[ssh-]list] [--data] [--ssh-fpr[=algo]] [--with-ssh] <keygrip>\n"
  "\n"
  "Return information about the key specified by the KEYGRIP.  If the\n"
  "key is not available GPG_ERR_NOT_FOUND is returned.  If the option\n"
  "--list is given the keygrip is ignored and information about all\n"
  "available keys are returned.  If --ssh-list is given information\n"
  "about all keys listed in the sshcontrol are returned.  With --with-ssh\n"
  "information from sshcontrol is always added to the info. Unless --data\n"
  "is given, the information is returned as a status line using the format:\n"
  "\n"
  "  KEYINFO <keygrip> <type> <serialno> <idstr> <cached> <protection> <fpr>\n"
  "\n"
  "KEYGRIP is the keygrip.\n"
  "\n"
  "TYPE is describes the type of the key:\n"
  "    'D' - Regular key stored on disk,\n"
  "    'T' - Key is stored on a smartcard (token),\n"
  "    'X' - Unknown type,\n"
  "    '-' - Key is missing.\n"
  "\n"
  "SERIALNO is an ASCII string with the serial number of the\n"
  "         smartcard.  If the serial number is not known a single\n"
  "         dash '-' is used instead.\n"
  "\n"
  "IDSTR is the IDSTR used to distinguish keys on a smartcard.  If it\n"
  "      is not known a dash is used instead.\n"
  "\n"
  "CACHED is 1 if the passphrase for the key was found in the key cache.\n"
  "       If not, a '-' is used instead.\n"
  "\n"
  "PROTECTION describes the key protection type:\n"
  "    'P' - The key is protected with a passphrase,\n"
  "    'C' - The key is not protected,\n"
  "    '-' - Unknown protection.\n"
  "\n"
  "FPR returns the formatted ssh-style fingerprint of the key.  It is only\n"
  "    printed if the option --ssh-fpr has been used.  If ALGO is not given\n"
  "    to that option the default ssh fingerprint algo is used.  Without the\n"
  "    option a '-' is printed.\n"
  "\n"
  "TTL is the TTL in seconds for that key or '-' if n/a.\n"
  "\n"
  "FLAGS is a word consisting of one-letter flags:\n"
  "      'D' - The key has been disabled,\n"
  "      'S' - The key is listed in sshcontrol (requires --with-ssh),\n"
  "      'c' - Use of the key needs to be confirmed,\n"
  "      '-' - No flags given.\n"
  "\n"
  "More information may be added in the future.";
static gpg_error_t
do_one_keyinfo (ctrl_t ctrl, const unsigned char *grip, assuan_context_t ctx,
                int data, int with_ssh_fpr, int in_ssh,
                int ttl, int disabled, int confirm)
{
  gpg_error_t err;
  char hexgrip[40+1];
  char *fpr = NULL;
  int keytype;
  unsigned char *shadow_info = NULL;
  char *serialno = NULL;
  char *idstr = NULL;
  const char *keytypestr;
  const char *cached;
  const char *protectionstr;
  char *pw;
  int missing_key = 0;
  char ttlbuf[20];
  char flagsbuf[5];

  err = agent_key_info_from_file (ctrl, grip, &keytype, &shadow_info);
  if (err)
    {
      if (in_ssh && gpg_err_code (err) == GPG_ERR_NOT_FOUND)
        missing_key = 1;
      else
        goto leave;
    }

  /* Reformat the grip so that we use uppercase as good style. */
  bin2hex (grip, 20, hexgrip);

  if (ttl > 0)
    snprintf (ttlbuf, sizeof ttlbuf, "%d", ttl);
  else
    strcpy (ttlbuf, "-");

  *flagsbuf = 0;
  if (disabled)
    strcat (flagsbuf, "D");
  if (in_ssh)
    strcat (flagsbuf, "S");
  if (confirm)
    strcat (flagsbuf, "c");
  if (!*flagsbuf)
    strcpy (flagsbuf, "-");


  if (missing_key)
    {
      protectionstr = "-"; keytypestr = "-";
    }
  else
    {
      switch (keytype)
        {
        case PRIVATE_KEY_CLEAR:
        case PRIVATE_KEY_OPENPGP_NONE:
          protectionstr = "C"; keytypestr = "D";
          break;
        case PRIVATE_KEY_PROTECTED: protectionstr = "P"; keytypestr = "D";
          break;
        case PRIVATE_KEY_SHADOWED: protectionstr = "-"; keytypestr = "T";
          break;
        default: protectionstr = "-"; keytypestr = "X";
          break;
        }
    }

  /* Compute the ssh fingerprint if requested.  */
  if (with_ssh_fpr)
    {
      gcry_sexp_t key;

      if (!agent_raw_key_from_file (ctrl, grip, &key))
        {
          ssh_get_fingerprint_string (key, with_ssh_fpr, &fpr);
          gcry_sexp_release (key);
        }
    }

  /* Here we have a little race by doing the cache check separately
     from the retrieval function.  Given that the cache flag is only a
     hint, it should not really matter.  */
  pw = agent_get_cache (ctrl, hexgrip, CACHE_MODE_NORMAL);
  cached = pw ? "1" : "-";
  xfree (pw);

  if (shadow_info)
    {
      err = parse_shadow_info (shadow_info, &serialno, &idstr, NULL);
      if (err)
        goto leave;
    }

  if (!data)
    err = agent_write_status (ctrl, "KEYINFO",
                              hexgrip,
                              keytypestr,
                              serialno? serialno : "-",
                              idstr? idstr : "-",
                              cached,
			      protectionstr,
                              fpr? fpr : "-",
                              ttlbuf,
                              flagsbuf,
                              NULL);
  else
    {
      char *string;

      string = xtryasprintf ("%s %s %s %s %s %s %s %s %s\n",
                             hexgrip, keytypestr,
                             serialno? serialno : "-",
                             idstr? idstr : "-", cached, protectionstr,
                             fpr? fpr : "-",
                             ttlbuf,
                             flagsbuf);
      if (!string)
        err = gpg_error_from_syserror ();
      else
        err = assuan_send_data (ctx, string, strlen(string));
      xfree (string);
    }

 leave:
  xfree (fpr);
  xfree (shadow_info);
  xfree (serialno);
  xfree (idstr);
  return err;
}


/* Entry into the command KEYINFO.  This function handles the
 * command option processing.  For details see hlp_keyinfo above.  */
static gpg_error_t
cmd_keyinfo (assuan_context_t ctx, char *line)
{
  ctrl_t ctrl = assuan_get_pointer (ctx);
  int err;
  unsigned char grip[20];
  gnupg_dir_t dir = NULL;
  int list_mode;
  int opt_data, opt_ssh_fpr, opt_with_ssh;
  ssh_control_file_t cf = NULL;
  char hexgrip[41];
  int disabled, ttl, confirm, is_ssh;

  if (has_option (line, "--ssh-list"))
    list_mode = 2;
  else
    list_mode = has_option (line, "--list");
  opt_data = has_option (line, "--data");

  if (has_option_name (line, "--ssh-fpr"))
    {
      if (has_option (line, "--ssh-fpr=md5"))
        opt_ssh_fpr = GCRY_MD_MD5;
      else if (has_option (line, "--ssh-fpr=sha1"))
        opt_ssh_fpr = GCRY_MD_SHA1;
      else if (has_option (line, "--ssh-fpr=sha256"))
        opt_ssh_fpr = GCRY_MD_SHA256;
      else
        opt_ssh_fpr = opt.ssh_fingerprint_digest;
    }
  else
    opt_ssh_fpr = 0;

  opt_with_ssh = has_option (line, "--with-ssh");
  line = skip_options (line);

  if (opt_with_ssh || list_mode == 2)
    cf = ssh_open_control_file ();

  if (list_mode == 2)
    {
      if (cf)
        {
          while (!ssh_read_control_file (cf, hexgrip,
                                         &disabled, &ttl, &confirm))
            {
              if (hex2bin (hexgrip, grip, 20) < 0 )
                continue; /* Bad hex string.  */
              err = do_one_keyinfo (ctrl, grip, ctx, opt_data, opt_ssh_fpr, 1,
                                    ttl, disabled, confirm);
              if (err)
                goto leave;
            }
        }
      err = 0;
    }
  else if (list_mode)
    {
      char *dirname;
      gnupg_dirent_t dir_entry;

      if (ctrl->restricted)
        return leave_cmd (ctx, gpg_error (GPG_ERR_FORBIDDEN));

      dirname = make_filename_try (gnupg_homedir (),
                                   GNUPG_PRIVATE_KEYS_DIR, NULL);
      if (!dirname)
        {
          err = gpg_error_from_syserror ();
          goto leave;
        }
      dir = gnupg_opendir (dirname);
      if (!dir)
        {
          err = gpg_error_from_syserror ();
          xfree (dirname);
          goto leave;
        }
      xfree (dirname);

      while ( (dir_entry = gnupg_readdir (dir)) )
        {
          if (strlen (dir_entry->d_name) != 44
              || strcmp (dir_entry->d_name + 40, ".key"))
            continue;
          strncpy (hexgrip, dir_entry->d_name, 40);
          hexgrip[40] = 0;

          if ( hex2bin (hexgrip, grip, 20) < 0 )
            continue; /* Bad hex string.  */

          disabled = ttl = confirm = is_ssh = 0;
          if (opt_with_ssh)
            {
              err = ssh_search_control_file (cf, hexgrip,
                                             &disabled, &ttl, &confirm);
              if (!err)
                is_ssh = 1;
              else if (gpg_err_code (err) != GPG_ERR_NOT_FOUND)
                goto leave;
            }

          err = do_one_keyinfo (ctrl, grip, ctx, opt_data, opt_ssh_fpr, is_ssh,
                                ttl, disabled, confirm);
          if (err)
            goto leave;
        }
      err = 0;
    }
  else
    {
      err = parse_keygrip (ctx, line, grip);
      if (err)
        goto leave;
      disabled = ttl = confirm = is_ssh = 0;
      if (opt_with_ssh)
        {
          err = ssh_search_control_file (cf, line,
                                         &disabled, &ttl, &confirm);
          if (!err)
            is_ssh = 1;
          else if (gpg_err_code (err) != GPG_ERR_NOT_FOUND)
            goto leave;
        }

      err = do_one_keyinfo (ctrl, grip, ctx, opt_data, opt_ssh_fpr, is_ssh,
                            ttl, disabled, confirm);
    }

 leave:
  ssh_close_control_file (cf);
  gnupg_closedir (dir);
  if (err && gpg_err_code (err) != GPG_ERR_NOT_FOUND)
    leave_cmd (ctx, err);
  return err;
}



/* Helper for cmd_get_passphrase.  */
static int
send_back_passphrase (assuan_context_t ctx, int via_data, const char *pw)
{
  size_t n;
  int rc;

  assuan_begin_confidential (ctx);
  n = strlen (pw);
  if (via_data)
    rc = assuan_send_data (ctx, pw, n);
  else
    {
      char *p = xtrymalloc_secure (n*2+1);
      if (!p)
        rc = gpg_error_from_syserror ();
      else
        {
          bin2hex (pw, n, p);
          rc = assuan_set_okay_line (ctx, p);
          xfree (p);
        }
    }
  return rc;
}


/* Callback function to compare the first entered PIN with the one
   currently being entered. */
static gpg_error_t
reenter_passphrase_cmp_cb (struct pin_entry_info_s *pi)
{
  const char *pin1 = pi->check_cb_arg;

  if (!strcmp (pin1, pi->pin))
    return 0; /* okay */
  return gpg_error (GPG_ERR_BAD_PASSPHRASE);
}


static const char hlp_get_passphrase[] =
  "GET_PASSPHRASE [--data] [--check] [--no-ask] [--repeat[=N]]\n"
  "               [--qualitybar] [--newsymkey] <cache_id>\n"
  "               [<error_message> <prompt> <description>]\n"
  "\n"
  "This function is usually used to ask for a passphrase to be used\n"
  "for conventional encryption, but may also be used by programs which\n"
  "need specal handling of passphrases.  This command uses a syntax\n"
  "which helps clients to use the agent with minimum effort.  The\n"
  "agent either returns with an error or with a OK followed by the hex\n"
  "encoded passphrase.  Note that the length of the strings is\n"
  "implicitly limited by the maximum length of a command.\n"
  "\n"
  "If the option \"--data\" is used the passphrase is returned by usual\n"
  "data lines and not on the okay line.\n"
  "\n"
  "If the option \"--check\" is used the passphrase constraints checks as\n"
  "implemented by gpg-agent are applied.  A check is not done if the\n"
  "passphrase has been found in the cache.\n"
  "\n"
  "If the option \"--no-ask\" is used and the passphrase is not in the\n"
  "cache the user will not be asked to enter a passphrase but the error\n"
  "code GPG_ERR_NO_DATA is returned.  \n"
  "\n"
  "If the option\"--newsymkey\" is used the agent asks for a new passphrase\n"
  "to be used in symmetric-only encryption.  This must not be empty.\n"
  "\n"
  "If the option \"--qualitybar\" is used a visual indication of the\n"
  "entered passphrase quality is shown.  (Unless no minimum passphrase\n"
  "length has been configured.)";
static gpg_error_t
cmd_get_passphrase (assuan_context_t ctx, char *line)
{
  ctrl_t ctrl = assuan_get_pointer (ctx);
  int rc;
  char *pw;
  char *response = NULL;
  char *response2 = NULL;
  char *cacheid = NULL;  /* May point into LINE.  */
  char *desc = NULL;     /* Ditto  */
  char *prompt = NULL;   /* Ditto  */
  char *errtext = NULL;  /* Ditto  */
  const char *desc2 = _("Please re-enter this passphrase");
  char *p;
  int opt_data, opt_check, opt_no_ask, opt_qualbar, opt_newsymkey;
  int opt_repeat = 0;
  char *entry_errtext = NULL;
  struct pin_entry_info_s *pi = NULL;
  struct pin_entry_info_s *pi2 = NULL;
  int is_generated;

  if (ctrl->restricted)
    return leave_cmd (ctx, gpg_error (GPG_ERR_FORBIDDEN));

  opt_data = has_option (line, "--data");
  opt_check = has_option (line, "--check");
  opt_no_ask = has_option (line, "--no-ask");
  if (has_option_name (line, "--repeat"))
    {
      p = option_value (line, "--repeat");
      if (p)
	opt_repeat = atoi (p);
      else
	opt_repeat = 1;
    }
  opt_qualbar = has_option (line, "--qualitybar");
  opt_newsymkey = has_option (line, "--newsymkey");
  line = skip_options (line);

  cacheid = line;
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
                *p = 0; /* Ignore trailing garbage. */
            }
        }
    }
  if (!*cacheid || strlen (cacheid) > 50)
    return set_error (GPG_ERR_ASS_PARAMETER, "invalid length of cacheID");
  if (!desc)
    return set_error (GPG_ERR_ASS_PARAMETER, "no description given");

  if (!strcmp (cacheid, "X"))
    cacheid = NULL;
  if (!strcmp (errtext, "X"))
    errtext = NULL;
  if (!strcmp (prompt, "X"))
    prompt = NULL;
  if (!strcmp (desc, "X"))
    desc = NULL;

  pw = cacheid ? agent_get_cache (ctrl, cacheid, CACHE_MODE_USER) : NULL;
  if (pw)
    {
      rc = send_back_passphrase (ctx, opt_data, pw);
      xfree (pw);
      goto leave;
    }
  else if (opt_no_ask)
    {
      rc = gpg_error (GPG_ERR_NO_DATA);
      goto leave;
    }

  /* Note, that we only need to replace the + characters and should
   * leave the other escaping in place because the escaped string is
   * send verbatim to the pinentry which does the unescaping (but not
   * the + replacing) */
  if (errtext)
    plus_to_blank (errtext);
  if (prompt)
    plus_to_blank (prompt);
  if (desc)
    plus_to_blank (desc);

  /* If opt_repeat is 2 or higher we can't use our pin_entry_info_s
   * based method but fallback to the old simple method.  It is
   * anyway questionable whether this extra repeat count makes any
   * real sense.  */
  if (opt_newsymkey && opt_repeat < 2)
    {
      /* We do not want to break any existing usage of this command
       * and thus we introduced the option --newsymkey to make this
       * command more useful to query the passphrase for symmetric
       * encryption.  */
      pi = gcry_calloc_secure (1, sizeof (*pi) + MAX_PASSPHRASE_LEN + 1);
      if (!pi)
        {
          rc = gpg_error_from_syserror ();
          goto leave;
        }
      pi2 = gcry_calloc_secure (1, sizeof (*pi2) + MAX_PASSPHRASE_LEN + 1);
      if (!pi2)
        {
          rc = gpg_error_from_syserror ();
          goto leave;
        }
      pi->max_length = MAX_PASSPHRASE_LEN + 1;
      pi->max_tries = 3;
      pi->with_qualitybar = opt_qualbar;
      pi->with_repeat = opt_repeat;
      pi->constraints_flags = (CHECK_CONSTRAINTS_NOT_EMPTY
                               | CHECK_CONSTRAINTS_NEW_SYMKEY);
      pi2->max_length = MAX_PASSPHRASE_LEN + 1;
      pi2->max_tries = 3;
      pi2->check_cb = reenter_passphrase_cmp_cb;
      pi2->check_cb_arg = pi->pin;

      for (;;) /* (degenerated for-loop) */
        {
          xfree (response);
          response = NULL;
          rc = agent_get_passphrase (ctrl, &response,
                                     desc,
                                     prompt,
                                     entry_errtext? entry_errtext:errtext,
                                     opt_qualbar, cacheid, CACHE_MODE_USER,
                                     pi);
          if (rc)
            goto leave;
          xfree (entry_errtext);
          entry_errtext = NULL;
          is_generated = !!(pi->status & PINENTRY_STATUS_PASSWORD_GENERATED);

          /* We don't allow an empty passpharse in this mode.  */
          if (!is_generated
              && check_passphrase_constraints (ctrl, pi->pin,
                                               pi->constraints_flags,
                                               &entry_errtext))
            {
              pi->failed_tries = 0;
              pi2->failed_tries = 0;
              continue;
            }
          if (*pi->pin && !pi->repeat_okay
              && ctrl->pinentry_mode != PINENTRY_MODE_LOOPBACK
              && opt_repeat)
            {
              /* The passphrase is empty and the pinentry did not
               * already run the repetition check, do it here.  This
               * is only called when using an old and simple pinentry.
               * It is neither called in loopback mode because the
               * caller does any passphrase repetition by herself nor if
               * no repetition was requested. */
              xfree (response);
              response = NULL;
              rc = agent_get_passphrase (ctrl, &response,
                                         L_("Please re-enter this passphrase"),
                                         prompt,
                                         entry_errtext? entry_errtext:errtext,
                                         opt_qualbar, cacheid, CACHE_MODE_USER,
                                         pi2);
              if (gpg_err_code (rc) == GPG_ERR_BAD_PASSPHRASE)
                { /* The re-entered passphrase one did not match and
                   * the user did not hit cancel. */
                  entry_errtext = xtrystrdup (L_("does not match - try again"));
                  if (!entry_errtext)
                    {
                      rc = gpg_error_from_syserror ();
                      goto leave;
                    }
                  continue;
                }
            }
          break;
        }
      if (!rc && *pi->pin)
        {
          /* Return the passphrase. */
          if (cacheid)
            agent_put_cache (ctrl, cacheid, CACHE_MODE_USER, pi->pin, 0);
          rc = send_back_passphrase (ctx, opt_data, pi->pin);
        }
    }
  else
    {
    next_try:
      xfree (response);
      response = NULL;
      rc = agent_get_passphrase (ctrl, &response, desc, prompt,
                                 entry_errtext? entry_errtext:errtext,
                                 opt_qualbar, cacheid, CACHE_MODE_USER, NULL);
      xfree (entry_errtext);
      entry_errtext = NULL;
      is_generated = 0;

      if (!rc)
        {
          int i;

          if (opt_check
              && !is_generated
	      && check_passphrase_constraints
              (ctrl, response,
               (opt_newsymkey? CHECK_CONSTRAINTS_NEW_SYMKEY:0),
               &entry_errtext))
            {
              goto next_try;
            }
          for (i = 0; i < opt_repeat; i++)
            {
              if (ctrl->pinentry_mode == PINENTRY_MODE_LOOPBACK)
                break;

              xfree (response2);
              response2 = NULL;
              rc = agent_get_passphrase (ctrl, &response2, desc2, prompt,
                                         errtext, 0,
					 cacheid, CACHE_MODE_USER, NULL);
              if (rc)
                break;
              if (strcmp (response2, response))
                {
                  entry_errtext = try_percent_escape
                    (_("does not match - try again"), NULL);
                  if (!entry_errtext)
                    {
                      rc = gpg_error_from_syserror ();
                      break;
                    }
                  goto next_try;
                }
            }
          if (!rc)
            {
              if (cacheid)
                agent_put_cache (ctrl, cacheid, CACHE_MODE_USER, response, 0);
              rc = send_back_passphrase (ctx, opt_data, response);
            }
        }
    }

 leave:
  xfree (response);
  xfree (response2);
  xfree (entry_errtext);
  xfree (pi2);
  xfree (pi);
  return leave_cmd (ctx, rc);
}


static const char hlp_clear_passphrase[] =
  "CLEAR_PASSPHRASE [--mode=normal] <cache_id>\n"
  "\n"
  "may be used to invalidate the cache entry for a passphrase.  The\n"
  "function returns with OK even when there is no cached passphrase.\n"
  "The --mode=normal option is used to clear an entry for a cacheid\n"
  "added by the agent.  The --mode=ssh option is used for a cacheid\n"
  "added for ssh.\n";
static gpg_error_t
cmd_clear_passphrase (assuan_context_t ctx, char *line)
{
  ctrl_t ctrl = assuan_get_pointer (ctx);
  char *cacheid = NULL;
  char *p;
  cache_mode_t cache_mode = CACHE_MODE_USER;

  if (ctrl->restricted)
    return leave_cmd (ctx, gpg_error (GPG_ERR_FORBIDDEN));

  if (has_option (line, "--mode=normal"))
    cache_mode = CACHE_MODE_NORMAL;
  else if (has_option (line, "--mode=ssh"))
    cache_mode = CACHE_MODE_SSH;

  line = skip_options (line);

  /* parse the stuff */
  for (p=line; *p == ' '; p++)
    ;
  cacheid = p;
  p = strchr (cacheid, ' ');
  if (p)
    *p = 0; /* ignore garbage */
  if (!*cacheid || strlen (cacheid) > 50)
    return set_error (GPG_ERR_ASS_PARAMETER, "invalid length of cacheID");

  agent_put_cache (ctrl, cacheid, cache_mode, NULL, 0);

  agent_clear_passphrase (ctrl, cacheid, cache_mode);

  return 0;
}


static const char hlp_get_confirmation[] =
  "GET_CONFIRMATION <description>\n"
  "\n"
  "This command may be used to ask for a simple confirmation.\n"
  "DESCRIPTION is displayed along with a Okay and Cancel button.  This\n"
  "command uses a syntax which helps clients to use the agent with\n"
  "minimum effort.  The agent either returns with an error or with a\n"
  "OK.  Note, that the length of DESCRIPTION is implicitly limited by\n"
  "the maximum length of a command. DESCRIPTION should not contain\n"
  "any spaces, those must be encoded either percent escaped or simply\n"
  "as '+'.";
static gpg_error_t
cmd_get_confirmation (assuan_context_t ctx, char *line)
{
  ctrl_t ctrl = assuan_get_pointer (ctx);
  int rc;
  char *desc = NULL;
  char *p;

  if (ctrl->restricted)
    return leave_cmd (ctx, gpg_error (GPG_ERR_FORBIDDEN));

  /* parse the stuff */
  for (p=line; *p == ' '; p++)
    ;
  desc = p;
  p = strchr (desc, ' ');
  if (p)
    *p = 0; /* We ignore any garbage -may be later used for other args. */

  if (!*desc)
    return set_error (GPG_ERR_ASS_PARAMETER, "no description given");

  if (!strcmp (desc, "X"))
    desc = NULL;

  /* Note, that we only need to replace the + characters and should
     leave the other escaping in place because the escaped string is
     send verbatim to the pinentry which does the unescaping (but not
     the + replacing) */
  if (desc)
    plus_to_blank (desc);

  rc = agent_get_confirmation (ctrl, desc, NULL, NULL, 0);
  return leave_cmd (ctx, rc);
}



static const char hlp_learn[] =
  "LEARN [--send] [--sendinfo] [--force]\n"
  "\n"
  "Learn something about the currently inserted smartcard.  With\n"
  "--sendinfo information about the card is returned; with --send\n"
  "the available certificates are returned as D lines; with --force\n"
  "private key storage will be updated by the result.";
static gpg_error_t
cmd_learn (assuan_context_t ctx, char *line)
{
  ctrl_t ctrl = assuan_get_pointer (ctx);
  gpg_error_t err;
  int send, sendinfo, force, reallyforce;

  send = has_option (line, "--send");
  sendinfo = send? 1 : has_option (line, "--sendinfo");
  force = has_option (line, "--force");
  reallyforce = has_option (line, "--reallyforce");

  if (ctrl->restricted)
    return leave_cmd (ctx, gpg_error (GPG_ERR_FORBIDDEN));

  err = agent_handle_learn (ctrl, send, sendinfo? ctx : NULL,
                            force, reallyforce);
  return leave_cmd (ctx, err);
}



static const char hlp_passwd[] =
  "PASSWD [--cache-nonce=<c>] [--passwd-nonce=<s>] [--preset]\n"
  "       [--verify] <hexkeygrip>\n"
  "\n"
  "Change the passphrase/PIN for the key identified by keygrip in LINE.  If\n"
  "--preset is used then the new passphrase will be added to the cache.\n"
  "If --verify is used the command asks for the passphrase and verifies\n"
  "that the passphrase valid.\n";
static gpg_error_t
cmd_passwd (assuan_context_t ctx, char *line)
{
  ctrl_t ctrl = assuan_get_pointer (ctx);
  gpg_error_t err;
  int c;
  char *cache_nonce = NULL;
  char *passwd_nonce = NULL;
  unsigned char grip[20];
  gcry_sexp_t s_skey = NULL;
  unsigned char *shadow_info = NULL;
  char *passphrase = NULL;
  char *pend;
  int opt_preset, opt_verify;

  if (ctrl->restricted)
    return leave_cmd (ctx, gpg_error (GPG_ERR_FORBIDDEN));

  opt_preset = has_option (line, "--preset");
  cache_nonce = option_value (line, "--cache-nonce");
  opt_verify = has_option (line, "--verify");
  if (cache_nonce)
    {
      for (pend = cache_nonce; *pend && !spacep (pend); pend++)
        ;
      c = *pend;
      *pend = '\0';
      cache_nonce = xtrystrdup (cache_nonce);
      *pend = c;
      if (!cache_nonce)
        {
          err = gpg_error_from_syserror ();
          goto leave;
        }
    }

  passwd_nonce = option_value (line, "--passwd-nonce");
  if (passwd_nonce)
    {
      for (pend = passwd_nonce; *pend && !spacep (pend); pend++)
        ;
      c = *pend;
      *pend = '\0';
      passwd_nonce = xtrystrdup (passwd_nonce);
      *pend = c;
      if (!passwd_nonce)
        {
          err = gpg_error_from_syserror ();
          goto leave;
        }
    }

  line = skip_options (line);

  err = parse_keygrip (ctx, line, grip);
  if (err)
    goto leave;

  ctrl->in_passwd++;
  err = agent_key_from_file (ctrl,
                             opt_verify? NULL : cache_nonce,
                             ctrl->server_local->keydesc,
                             grip, &shadow_info, CACHE_MODE_IGNORE, NULL,
                             &s_skey, &passphrase, NULL);
  if (err)
    ;
  else if (shadow_info)
    {
      log_error ("changing a smartcard PIN is not yet supported\n");
      err = gpg_error (GPG_ERR_NOT_IMPLEMENTED);
    }
  else if (opt_verify)
    {
      /* All done.  */
      if (passphrase)
        {
          if (!passwd_nonce)
            {
              char buf[12];
              gcry_create_nonce (buf, 12);
              passwd_nonce = bin2hex (buf, 12, NULL);
            }
          if (passwd_nonce
              && !agent_put_cache (ctrl, passwd_nonce, CACHE_MODE_NONCE,
                                   passphrase, CACHE_TTL_NONCE))
            {
              assuan_write_status (ctx, "PASSWD_NONCE", passwd_nonce);
              xfree (ctrl->server_local->last_passwd_nonce);
              ctrl->server_local->last_passwd_nonce = passwd_nonce;
              passwd_nonce = NULL;
            }
        }
    }
  else
    {
      char *newpass = NULL;

      if (passwd_nonce)
        newpass = agent_get_cache (ctrl, passwd_nonce, CACHE_MODE_NONCE);
      err = agent_protect_and_store (ctrl, s_skey, &newpass);
      if (!err && passphrase)
        {
          /* A passphrase existed on the old key and the change was
             successful.  Return a nonce for that old passphrase to
             let the caller try to unprotect the other subkeys with
             the same key.  */
          if (!cache_nonce)
            {
              char buf[12];
              gcry_create_nonce (buf, 12);
              cache_nonce = bin2hex (buf, 12, NULL);
            }
          if (cache_nonce
              && !agent_put_cache (ctrl, cache_nonce, CACHE_MODE_NONCE,
                                   passphrase, CACHE_TTL_NONCE))
            {
              assuan_write_status (ctx, "CACHE_NONCE", cache_nonce);
              xfree (ctrl->server_local->last_cache_nonce);
              ctrl->server_local->last_cache_nonce = cache_nonce;
              cache_nonce = NULL;
            }
          if (newpass)
            {
              /* If we have a new passphrase (which might be empty) we
                 store it under a passwd nonce so that the caller may
                 send that nonce again to use it for another key. */
              if (!passwd_nonce)
                {
                  char buf[12];
                  gcry_create_nonce (buf, 12);
                  passwd_nonce = bin2hex (buf, 12, NULL);
                }
              if (passwd_nonce
                  && !agent_put_cache (ctrl, passwd_nonce, CACHE_MODE_NONCE,
                                       newpass, CACHE_TTL_NONCE))
                {
                  assuan_write_status (ctx, "PASSWD_NONCE", passwd_nonce);
                  xfree (ctrl->server_local->last_passwd_nonce);
                  ctrl->server_local->last_passwd_nonce = passwd_nonce;
                  passwd_nonce = NULL;
                }
            }
        }
      if (!err && opt_preset)
        {
	  char hexgrip[40+1];
	  bin2hex(grip, 20, hexgrip);
	  err = agent_put_cache (ctrl, hexgrip, CACHE_MODE_ANY, newpass,
                                 ctrl->cache_ttl_opt_preset);
        }
      xfree (newpass);
    }
  ctrl->in_passwd--;

  xfree (ctrl->server_local->keydesc);
  ctrl->server_local->keydesc = NULL;

 leave:
  xfree (passphrase);
  gcry_sexp_release (s_skey);
  xfree (shadow_info);
  xfree (cache_nonce);
  xfree (passwd_nonce);
  return leave_cmd (ctx, err);
}


static const char hlp_preset_passphrase[] =
  "PRESET_PASSPHRASE [--inquire] <string_or_keygrip> <timeout> [<hexstring>]\n"
  "\n"
  "Set the cached passphrase/PIN for the key identified by the keygrip\n"
  "to passwd for the given time, where -1 means infinite and 0 means\n"
  "the default (currently only a timeout of -1 is allowed, which means\n"
  "to never expire it).  If passwd is not provided, ask for it via the\n"
  "pinentry module unless --inquire is passed in which case the passphrase\n"
  "is retrieved from the client via a server inquire.\n";
static gpg_error_t
cmd_preset_passphrase (assuan_context_t ctx, char *line)
{
  ctrl_t ctrl = assuan_get_pointer (ctx);
  int rc;
  char *grip_clear = NULL;
  unsigned char *passphrase = NULL;
  int ttl;
  size_t len;
  int opt_inquire;

  if (ctrl->restricted)
    return leave_cmd (ctx, gpg_error (GPG_ERR_FORBIDDEN));

  if (!opt.allow_preset_passphrase)
    return set_error (GPG_ERR_NOT_SUPPORTED, "no --allow-preset-passphrase");

  opt_inquire = has_option (line, "--inquire");
  line = skip_options (line);
  grip_clear = line;
  while (*line && (*line != ' ' && *line != '\t'))
    line++;
  if (!*line)
    return gpg_error (GPG_ERR_MISSING_VALUE);
  *line = '\0';
  line++;
  while (*line && (*line == ' ' || *line == '\t'))
    line++;

  /* Currently, only infinite timeouts are allowed.  */
  ttl = -1;
  if (line[0] != '-' || line[1] != '1')
    return gpg_error (GPG_ERR_NOT_IMPLEMENTED);
  line++;
  line++;
  while (!(*line != ' ' && *line != '\t'))
    line++;

  /* Syntax check the hexstring.  */
  len = 0;
  rc = parse_hexstring (ctx, line, &len);
  if (rc)
    return rc;
  line[len] = '\0';

  /* If there is a passphrase, use it.  Currently, a passphrase is
     required.  */
  if (*line)
    {
      if (opt_inquire)
        {
	  rc = set_error (GPG_ERR_ASS_PARAMETER,
                          "both --inquire and passphrase specified");
	  goto leave;
	}

      /* Do in-place conversion.  */
      passphrase = line;
      if (!hex2str (passphrase, passphrase, strlen (passphrase)+1, NULL))
        rc = set_error (GPG_ERR_ASS_PARAMETER, "invalid hexstring");
    }
  else if (opt_inquire)
    {
      /* Note that the passphrase will be truncated at any null byte and the
       * limit is 480 characters. */
      size_t maxlen = 480;

      rc = print_assuan_status (ctx, "INQUIRE_MAXLEN", "%zu", maxlen);
      if (!rc)
        {
          assuan_begin_confidential (ctx);
          rc = assuan_inquire (ctx, "PASSPHRASE", &passphrase, &len, maxlen);
          assuan_end_confidential (ctx);
        }
    }
  else
    rc = set_error (GPG_ERR_NOT_IMPLEMENTED, "passphrase is required");

  if (!rc)
    {
      rc = agent_put_cache (ctrl, grip_clear, CACHE_MODE_ANY, passphrase, ttl);
      if (opt_inquire)
        {
	  wipememory (passphrase, len);
          xfree (passphrase);
        }
    }

leave:
  return leave_cmd (ctx, rc);
}



static const char hlp_scd[] =
  "SCD <commands to pass to the scdaemon>\n"
  " \n"
  "This is a general quote command to redirect everything to the\n"
  "SCdaemon.";
static gpg_error_t
cmd_scd (assuan_context_t ctx, char *line)
{
  int rc;
#ifdef BUILD_WITH_SCDAEMON
  ctrl_t ctrl = assuan_get_pointer (ctx);
  if (ctrl->restricted)
    return leave_cmd (ctx, gpg_error (GPG_ERR_FORBIDDEN));

  rc = divert_generic_cmd (ctrl, line, ctx);
#else
  (void)ctx; (void)line;
  rc = gpg_error (GPG_ERR_NOT_SUPPORTED);
#endif
  return rc;
}



static const char hlp_keywrap_key[] =
  "KEYWRAP_KEY [--clear] <mode>\n"
  "\n"
  "Return a key to wrap another key.  For now the key is returned\n"
  "verbatim and thus makes not much sense because an eavesdropper on\n"
  "the gpg-agent connection will see the key as well as the wrapped key.\n"
  "However, this function may either be equipped with a public key\n"
  "mechanism or not used at all if the key is a pre-shared key.  In any\n"
  "case wrapping the import and export of keys is a requirement for\n"
  "certain cryptographic validations and thus useful.  The key persists\n"
  "until a RESET command but may be cleared using the option --clear.\n"
  "\n"
  "Supported modes are:\n"
  "  --import  - Return a key to import a key into gpg-agent\n"
  "  --export  - Return a key to export a key from gpg-agent";
static gpg_error_t
cmd_keywrap_key (assuan_context_t ctx, char *line)
{
  ctrl_t ctrl = assuan_get_pointer (ctx);
  gpg_error_t err = 0;
  int clearopt = has_option (line, "--clear");

  if (ctrl->restricted)
    return leave_cmd (ctx, gpg_error (GPG_ERR_FORBIDDEN));

  assuan_begin_confidential (ctx);
  if (has_option (line, "--import"))
    {
      xfree (ctrl->server_local->import_key);
      if (clearopt)
        ctrl->server_local->import_key = NULL;
      else if (!(ctrl->server_local->import_key =
                 gcry_random_bytes (KEYWRAP_KEYSIZE, GCRY_STRONG_RANDOM)))
        err = gpg_error_from_syserror ();
      else
        err = assuan_send_data (ctx, ctrl->server_local->import_key,
                                KEYWRAP_KEYSIZE);
    }
  else if (has_option (line, "--export"))
    {
      xfree (ctrl->server_local->export_key);
      if (clearopt)
        ctrl->server_local->export_key = NULL;
      else if (!(ctrl->server_local->export_key =
            gcry_random_bytes (KEYWRAP_KEYSIZE, GCRY_STRONG_RANDOM)))
        err = gpg_error_from_syserror ();
      else
        err = assuan_send_data (ctx, ctrl->server_local->export_key,
                                KEYWRAP_KEYSIZE);
    }
  else
    err = set_error (GPG_ERR_ASS_PARAMETER, "unknown value for MODE");
  assuan_end_confidential (ctx);

  return leave_cmd (ctx, err);
}



static const char hlp_import_key[] =
  "IMPORT_KEY [--unattended] [--force] [--timestamp=<isodate>]\n"
  "           [<cache_nonce>]\n"
  "\n"
  "Import a secret key into the key store.  The key is expected to be\n"
  "encrypted using the current session's key wrapping key (cf. command\n"
  "KEYWRAP_KEY) using the AESWRAP-128 algorithm.  This function takes\n"
  "no arguments but uses the inquiry \"KEYDATA\" to ask for the actual\n"
  "key data.  The unwrapped key must be a canonical S-expression.  The\n"
  "option --unattended tries to import the key as-is without any\n"
  "re-encryption.  An existing key can be overwritten with --force.\n"
  "If --timestamp is given its value is recorded as the key's creation\n"
  "time; the value is expected in ISO format (e.g. \"20030316T120000\").";
static gpg_error_t
cmd_import_key (assuan_context_t ctx, char *line)
{
  ctrl_t ctrl = assuan_get_pointer (ctx);
  gpg_error_t err;
  int opt_unattended;
  time_t opt_timestamp;
  int force;
  unsigned char *wrappedkey = NULL;
  size_t wrappedkeylen;
  gcry_cipher_hd_t cipherhd = NULL;
  unsigned char *key = NULL;
  size_t keylen, realkeylen;
  char *passphrase = NULL;
  unsigned char *finalkey = NULL;
  size_t finalkeylen;
  unsigned char grip[20];
  gcry_sexp_t openpgp_sexp = NULL;
  char *cache_nonce = NULL;
  char *p;
  const char *s;

  if (ctrl->restricted)
    return leave_cmd (ctx, gpg_error (GPG_ERR_FORBIDDEN));

  if (!ctrl->server_local->import_key)
    {
      err = gpg_error (GPG_ERR_MISSING_KEY);
      goto leave;
    }

  opt_unattended = has_option (line, "--unattended");
  force = has_option (line, "--force");
  if ((s=has_option_name (line, "--timestamp")))
    {
      if (*s != '=')
        {
          err = set_error (GPG_ERR_ASS_PARAMETER, "missing value for option");
          goto leave;
        }
      opt_timestamp = isotime2epoch (s+1);
      if (opt_timestamp < 1)
        {
          err = set_error (GPG_ERR_ASS_PARAMETER, "invalid time value");
          goto leave;
        }
    }
  else
    opt_timestamp = 0;
  line = skip_options (line);

  for (p=line; *p && *p != ' ' && *p != '\t'; p++)
    ;
  *p = '\0';
  if (*line)
    cache_nonce = xtrystrdup (line);

  assuan_begin_confidential (ctx);
  err = assuan_inquire (ctx, "KEYDATA",
                        &wrappedkey, &wrappedkeylen, MAXLEN_KEYDATA);
  assuan_end_confidential (ctx);
  if (err)
    goto leave;
  if (wrappedkeylen < 24)
    {
      err = gpg_error (GPG_ERR_INV_LENGTH);
      goto leave;
    }
  keylen = wrappedkeylen - 8;
  key = xtrymalloc_secure (keylen);
  if (!key)
    {
      err = gpg_error_from_syserror ();
      goto leave;
    }

  err = gcry_cipher_open (&cipherhd, GCRY_CIPHER_AES128,
                          GCRY_CIPHER_MODE_AESWRAP, 0);
  if (err)
    goto leave;
  err = gcry_cipher_setkey (cipherhd,
                            ctrl->server_local->import_key, KEYWRAP_KEYSIZE);
  if (err)
    goto leave;
  err = gcry_cipher_decrypt (cipherhd, key, keylen, wrappedkey, wrappedkeylen);
  if (err)
    goto leave;
  gcry_cipher_close (cipherhd);
  cipherhd = NULL;
  xfree (wrappedkey);
  wrappedkey = NULL;

  realkeylen = gcry_sexp_canon_len (key, keylen, NULL, &err);
  if (!realkeylen)
    goto leave; /* Invalid canonical encoded S-expression.  */

  err = keygrip_from_canon_sexp (key, realkeylen, grip);
  if (err)
    {
      /* This might be due to an unsupported S-expression format.
         Check whether this is openpgp-private-key and trigger that
         import code.  */
      if (!gcry_sexp_sscan (&openpgp_sexp, NULL, key, realkeylen))
        {
          const char *tag;
          size_t taglen;

          tag = gcry_sexp_nth_data (openpgp_sexp, 0, &taglen);
          if (tag && taglen == 19 && !memcmp (tag, "openpgp-private-key", 19))
            ;
          else
            {
              gcry_sexp_release (openpgp_sexp);
              openpgp_sexp = NULL;
            }
        }
      if (!openpgp_sexp)
        goto leave; /* Note that ERR is still set.  */
    }

  if (openpgp_sexp)
    {
      /* In most cases the key is encrypted and thus the conversion
         function from the OpenPGP format to our internal format will
         ask for a passphrase.  That passphrase will be returned and
         used to protect the key using the same code as for regular
         key import. */

      xfree (key);
      key = NULL;
      err = convert_from_openpgp (ctrl, openpgp_sexp, force, grip,
                                  ctrl->server_local->keydesc, cache_nonce,
                                  &key, opt_unattended? NULL : &passphrase);
      if (err)
        goto leave;
      realkeylen = gcry_sexp_canon_len (key, 0, NULL, &err);
      if (!realkeylen)
        goto leave; /* Invalid canonical encoded S-expression.  */
      if (passphrase)
        {
          assert (!opt_unattended);
          if (!cache_nonce)
            {
              char buf[12];
              gcry_create_nonce (buf, 12);
              cache_nonce = bin2hex (buf, 12, NULL);
            }
          if (cache_nonce
              && !agent_put_cache (ctrl, cache_nonce, CACHE_MODE_NONCE,
                                   passphrase, CACHE_TTL_NONCE))
            assuan_write_status (ctx, "CACHE_NONCE", cache_nonce);
        }
    }
  else if (opt_unattended)
    {
      err = set_error (GPG_ERR_ASS_PARAMETER,
                       "\"--unattended\" may only be used with OpenPGP keys");
      goto leave;
    }
  else
    {
      if (!force && !agent_key_available (grip))
        err = gpg_error (GPG_ERR_EEXIST);
      else
        {
          char *prompt = xtryasprintf
            (_("Please enter the passphrase to protect the "
               "imported object within the %s system."), GNUPG_NAME);
          if (!prompt)
            err = gpg_error_from_syserror ();
          else
            err = agent_ask_new_passphrase (ctrl, prompt, &passphrase);
          xfree (prompt);
        }
      if (err)
        goto leave;
    }

  if (passphrase)
    {
      err = agent_protect (key, passphrase, &finalkey, &finalkeylen,
                           ctrl->s2k_count);
      if (!err)
        err = agent_write_private_key (grip, finalkey, finalkeylen, force, 0,
                                       NULL, NULL, NULL, opt_timestamp);
    }
  else
    err = agent_write_private_key (grip, key, realkeylen, force, 0,
                                   NULL, NULL, NULL, opt_timestamp);

 leave:
  gcry_sexp_release (openpgp_sexp);
  xfree (finalkey);
  xfree (passphrase);
  xfree (key);
  gcry_cipher_close (cipherhd);
  xfree (wrappedkey);
  xfree (cache_nonce);
  xfree (ctrl->server_local->keydesc);
  ctrl->server_local->keydesc = NULL;
  return leave_cmd (ctx, err);
}



static const char hlp_export_key[] =
  "EXPORT_KEY [--cache-nonce=<nonce>] [--openpgp] <hexstring_with_keygrip>\n"
  "\n"
  "Export a secret key from the key store.  The key will be encrypted\n"
  "using the current session's key wrapping key (cf. command KEYWRAP_KEY)\n"
  "using the AESWRAP-128 algorithm.  The caller needs to retrieve that key\n"
  "prior to using this command.  The function takes the keygrip as argument.\n"
  "\n"
  "If --openpgp is used, the secret key material will be exported in RFC 4880\n"
  "compatible passphrase-protected form.  Without --openpgp, the secret key\n"
  "material will be exported in the clear (after prompting the user to unlock\n"
  "it, if needed).\n";
static gpg_error_t
cmd_export_key (assuan_context_t ctx, char *line)
{
  ctrl_t ctrl = assuan_get_pointer (ctx);
  gpg_error_t err;
  unsigned char grip[20];
  gcry_sexp_t s_skey = NULL;
  unsigned char *key = NULL;
  size_t keylen;
  gcry_cipher_hd_t cipherhd = NULL;
  unsigned char *wrappedkey = NULL;
  size_t wrappedkeylen;
  int openpgp;
  char *cache_nonce;
  char *passphrase = NULL;
  unsigned char *shadow_info = NULL;
  char *pend;
  int c;

  if (ctrl->restricted)
    return leave_cmd (ctx, gpg_error (GPG_ERR_FORBIDDEN));

  openpgp = has_option (line, "--openpgp");
  cache_nonce = option_value (line, "--cache-nonce");
  if (cache_nonce)
    {
      for (pend = cache_nonce; *pend && !spacep (pend); pend++)
        ;
      c = *pend;
      *pend = '\0';
      cache_nonce = xtrystrdup (cache_nonce);
      *pend = c;
      if (!cache_nonce)
        {
          err = gpg_error_from_syserror ();
          goto leave;
        }
    }
  line = skip_options (line);

  if (!ctrl->server_local->export_key)
    {
      err = set_error (GPG_ERR_MISSING_KEY, "did you run KEYWRAP_KEY ?");
      goto leave;
    }

  err = parse_keygrip (ctx, line, grip);
  if (err)
    goto leave;

  if (agent_key_available (grip))
    {
      err = gpg_error (GPG_ERR_NO_SECKEY);
      goto leave;
    }

  /* Get the key from the file.  With the openpgp flag we also ask for
     the passphrase so that we can use it to re-encrypt it.  */
  err = agent_key_from_file (ctrl, cache_nonce,
                             ctrl->server_local->keydesc, grip,
                             &shadow_info, CACHE_MODE_IGNORE, NULL, &s_skey,
                             openpgp ? &passphrase : NULL, NULL);
  if (err)
    goto leave;
  if (shadow_info)
    {
      /* Key is on a smartcard.  */
      err = gpg_error (GPG_ERR_UNUSABLE_SECKEY);
      goto leave;
    }

  if (openpgp)
    {
      /* The openpgp option changes the key format into the OpenPGP
         key transfer format.  The result is already a padded
         canonical S-expression.  */
      if (!passphrase)
        {
          err = agent_ask_new_passphrase
            (ctrl, _("This key (or subkey) is not protected with a passphrase."
                     "  Please enter a new passphrase to export it."),
             &passphrase);
          if (err)
            goto leave;
        }
      err = convert_to_openpgp (ctrl, s_skey, passphrase, &key, &keylen);
      if (!err && passphrase)
        {
          if (!cache_nonce)
            {
              char buf[12];
              gcry_create_nonce (buf, 12);
              cache_nonce = bin2hex (buf, 12, NULL);
            }
          if (cache_nonce
              && !agent_put_cache (ctrl, cache_nonce, CACHE_MODE_NONCE,
                                   passphrase, CACHE_TTL_NONCE))
            {
              assuan_write_status (ctx, "CACHE_NONCE", cache_nonce);
              xfree (ctrl->server_local->last_cache_nonce);
              ctrl->server_local->last_cache_nonce = cache_nonce;
              cache_nonce = NULL;
            }
        }
    }
  else
    {
      /* Convert into a canonical S-expression and wrap that.  */
      err = make_canon_sexp_pad (s_skey, 1, &key, &keylen);
    }
  if (err)
    goto leave;
  gcry_sexp_release (s_skey);
  s_skey = NULL;

  err = gcry_cipher_open (&cipherhd, GCRY_CIPHER_AES128,
                          GCRY_CIPHER_MODE_AESWRAP, 0);
  if (err)
    goto leave;
  err = gcry_cipher_setkey (cipherhd,
                            ctrl->server_local->export_key, KEYWRAP_KEYSIZE);
  if (err)
    goto leave;

  wrappedkeylen = keylen + 8;
  wrappedkey = xtrymalloc (wrappedkeylen);
  if (!wrappedkey)
    {
      err = gpg_error_from_syserror ();
      goto leave;
    }

  err = gcry_cipher_encrypt (cipherhd, wrappedkey, wrappedkeylen, key, keylen);
  if (err)
    goto leave;
  xfree (key);
  key = NULL;
  gcry_cipher_close (cipherhd);
  cipherhd = NULL;

  assuan_begin_confidential (ctx);
  err = assuan_send_data (ctx, wrappedkey, wrappedkeylen);
  assuan_end_confidential (ctx);


 leave:
  xfree (cache_nonce);
  xfree (passphrase);
  xfree (wrappedkey);
  gcry_cipher_close (cipherhd);
  xfree (key);
  gcry_sexp_release (s_skey);
  xfree (ctrl->server_local->keydesc);
  ctrl->server_local->keydesc = NULL;
  xfree (shadow_info);

  return leave_cmd (ctx, err);
}



static const char hlp_delete_key[] =
  "DELETE_KEY [--force|--stub-only] <hexstring_with_keygrip>\n"
  "\n"
  "Delete a secret key from the key store.  If --force is used\n"
  "and a loopback pinentry is allowed, the agent will not ask\n"
  "the user for confirmation.  If --stub-only is used the key will\n"
  "only be deleted if it is a reference to a token.";
static gpg_error_t
cmd_delete_key (assuan_context_t ctx, char *line)
{
  ctrl_t ctrl = assuan_get_pointer (ctx);
  gpg_error_t err;
  int force, stub_only;
  unsigned char grip[20];

  if (ctrl->restricted)
    return leave_cmd (ctx, gpg_error (GPG_ERR_FORBIDDEN));

  force = has_option (line, "--force");
  stub_only = has_option (line, "--stub-only");
  line = skip_options (line);

  /* If the use of a loopback pinentry has been disabled, we assume
   * that a silent deletion of keys shall also not be allowed.  */
  if (!opt.allow_loopback_pinentry)
    force = 0;

  err = parse_keygrip (ctx, line, grip);
  if (err)
    goto leave;

  err = agent_delete_key (ctrl, ctrl->server_local->keydesc, grip,
                          force, stub_only);
  if (err)
    goto leave;

 leave:
  xfree (ctrl->server_local->keydesc);
  ctrl->server_local->keydesc = NULL;

  return leave_cmd (ctx, err);
}



static const char hlp_keytocard[] =
  "KEYTOCARD [--force] <hexgrip> <serialno> <keyref> [<timestamp> [<ecdh>]]\n"
  "\n"
  "TIMESTAMP is required for OpenPGP and defaults to the Epoch.\n"
  "ECDH are the hexified ECDH parameters for OpenPGP.\n"
  "SERIALNO is used for checking; use \"-\" to disable the check.";
static gpg_error_t
cmd_keytocard (assuan_context_t ctx, char *line)
{
  ctrl_t ctrl = assuan_get_pointer (ctx);
  int force;
  gpg_error_t err = 0;
  char *argv[5];
  int argc;
  unsigned char grip[20];
  const char *serialno, *keyref;
  gcry_sexp_t s_skey = NULL;
  unsigned char *keydata;
  size_t keydatalen;
  unsigned char *shadow_info = NULL;
  uint64_t timestamp;
  char *ecdh_params = NULL;
  unsigned int ecdh_params_len;
  unsigned int extralen1, extralen2;

  if (ctrl->restricted)
    return leave_cmd (ctx, gpg_error (GPG_ERR_FORBIDDEN));

  force = has_option (line, "--force");
  line = skip_options (line);

  /* Need a copy of LINE, since it might inquire to the frontend which
     resulted original buffer overwritten.  */
  line = xtrystrdup (line);
  if (!line)
    return gpg_error_from_syserror ();

  argc = split_fields (line, argv, DIM (argv));
  if (argc < 3)
    {
      err = gpg_error (GPG_ERR_MISSING_VALUE);
      goto leave;
    }

  err = parse_keygrip (ctx, argv[0], grip);
  if (err)
    goto leave;

  if (agent_key_available (grip))
    {
      err =gpg_error (GPG_ERR_NO_SECKEY);
      goto leave;
    }

  /* Note that checking of the s/n is currently not implemented but we
   * want to provide a clean interface if we ever implement it.  */
  serialno = argv[1];
  if (!strcmp (serialno, "-"))
    serialno = NULL;

  keyref = argv[2];

  err = agent_key_from_file (ctrl, NULL, ctrl->server_local->keydesc, grip,
                             &shadow_info, CACHE_MODE_IGNORE, NULL,
                             &s_skey, NULL, &timestamp);
  if (err)
    goto leave;

  if (shadow_info)
    {
      /* Key is already on a smartcard - wer can't extract it.  */
      err = gpg_error (GPG_ERR_UNUSABLE_SECKEY);
      goto leave;
    }

  /* Default to the creation time as stored in the private key.  The
   * parameter is here so that gpg can make sure that the timestamp is
   * used.  It is also important for OpenPGP cards to allow computing
   * of the fingerprint.  Same goes for the ECDH params.  */
  if (argc > 3)
    {
      timestamp = isotime2epoch_u64 (argv[3]);
      if (argc > 4)
        {
          size_t n;

          err = parse_hexstring (ctx, argv[4], &n);
          if (err)
            goto leave;  /* Badly formatted ecdh params. */
          n /= 2;
          if (n < 4)
            {
              err = set_error (GPG_ERR_ASS_PARAMETER, "ecdh param too short");
              goto leave;
            }
          ecdh_params_len = n;
          ecdh_params = xtrymalloc (ecdh_params_len);
          if (!ecdh_params)
            {
              err = gpg_error_from_syserror ();
              goto leave;
            }
          if (hex2bin (argv[4], ecdh_params, ecdh_params_len) < 0)
            {
              err = set_error (GPG_ERR_BUG, "hex2bin");
              goto leave;
            }
        }
    }
  else if (timestamp == (uint64_t)(-1))
    timestamp = isotime2epoch_u64 ("19700101T000000");

  if (timestamp == (uint64_t)(-1))
    {
      err = gpg_error (GPG_ERR_INV_TIME);
      goto leave;
    }

  /* Note: We can't use make_canon_sexp because we need to allocate a
   * few extra bytes for our hack below.  The 20 for extralen2
   * accounts for the sexp length of ecdh_params.  */
  keydatalen = gcry_sexp_sprint (s_skey, GCRYSEXP_FMT_CANON, NULL, 0);
  extralen1 = 30;
  extralen2 = ecdh_params? (20+20+ecdh_params_len) : 0;
  keydata = xtrymalloc_secure (keydatalen + extralen1 + extralen2);
  if (keydata == NULL)
    {
      err = gpg_error_from_syserror ();
      goto leave;
    }
  gcry_sexp_sprint (s_skey, GCRYSEXP_FMT_CANON, keydata, keydatalen);
  gcry_sexp_release (s_skey);
  s_skey = NULL;

  keydatalen--;			/* Decrement for last '\0'.  */

  /* Hack to insert the timestamp "created-at" into the private key.  */
  snprintf (keydata+keydatalen-1, extralen1, "(10:created-at10:%010llu))",
            (unsigned long long)timestamp);
  keydatalen += 10 + 19 - 1;

  /* Hack to insert the timestamp "ecdh-params" into the private key.  */
  if (ecdh_params)
    {
      snprintf (keydata+keydatalen-1, extralen2, "(11:ecdh-params%u:",
                ecdh_params_len);
      keydatalen += strlen (keydata+keydatalen-1) -1;
      memcpy (keydata+keydatalen, ecdh_params, ecdh_params_len);
      keydatalen += ecdh_params_len;
      memcpy (keydata+keydatalen, "))", 3);
      keydatalen += 2;
    }

  err = divert_writekey (ctrl, force, serialno, keyref, keydata, keydatalen);
  xfree (keydata);

 leave:
  xfree (line);
  xfree (ecdh_params);
  gcry_sexp_release (s_skey);
  xfree (shadow_info);
  return leave_cmd (ctx, err);
}



static const char hlp_getval[] =
  "GETVAL <key>\n"
  "\n"
  "Return the value for KEY from the special environment as created by\n"
  "PUTVAL.";
static gpg_error_t
cmd_getval (assuan_context_t ctx, char *line)
{
  ctrl_t ctrl = assuan_get_pointer (ctx);
  int rc = 0;
  char *key = NULL;
  char *p;
  struct putval_item_s *vl;

  if (ctrl->restricted)
    return leave_cmd (ctx, gpg_error (GPG_ERR_FORBIDDEN));

  for (p=line; *p == ' '; p++)
    ;
  key = p;
  p = strchr (key, ' ');
  if (p)
    {
      *p++ = 0;
      for (; *p == ' '; p++)
        ;
      if (*p)
        return set_error (GPG_ERR_ASS_PARAMETER, "too many arguments");
    }
  if (!*key)
    return set_error (GPG_ERR_ASS_PARAMETER, "no key given");


  for (vl=putval_list; vl; vl = vl->next)
    if ( !strcmp (vl->d, key) )
      break;

  if (vl) /* Got an entry. */
    rc = assuan_send_data (ctx, vl->d+vl->off, vl->len);
  else
    return gpg_error (GPG_ERR_NO_DATA);

  return leave_cmd (ctx, rc);
}


static const char hlp_putval[] =
  "PUTVAL <key> [<percent_escaped_value>]\n"
  "\n"
  "The gpg-agent maintains a kind of environment which may be used to\n"
  "store key/value pairs in it, so that they can be retrieved later.\n"
  "This may be used by helper daemons to daemonize themself on\n"
  "invocation and register them with gpg-agent.  Callers of the\n"
  "daemon's service may now first try connect to get the information\n"
  "for that service from gpg-agent through the GETVAL command and then\n"
  "try to connect to that daemon.  Only if that fails they may start\n"
  "an own instance of the service daemon. \n"
  "\n"
  "KEY is an arbitrary symbol with the same syntax rules as keys\n"
  "for shell environment variables.  PERCENT_ESCAPED_VALUE is the\n"
  "corresponding value; they should be similar to the values of\n"
  "envronment variables but gpg-agent does not enforce any\n"
  "restrictions.  If that value is not given any value under that KEY\n"
  "is removed from this special environment.";
static gpg_error_t
cmd_putval (assuan_context_t ctx, char *line)
{
  ctrl_t ctrl = assuan_get_pointer (ctx);
  int rc = 0;
  char *key = NULL;
  char *value = NULL;
  size_t valuelen = 0;
  char *p;
  struct putval_item_s *vl, *vlprev;

  if (ctrl->restricted)
    return leave_cmd (ctx, gpg_error (GPG_ERR_FORBIDDEN));

  for (p=line; *p == ' '; p++)
    ;
  key = p;
  p = strchr (key, ' ');
  if (p)
    {
      *p++ = 0;
      for (; *p == ' '; p++)
        ;
      if (*p)
        {
          value = p;
          p = strchr (value, ' ');
          if (p)
            *p = 0;
          valuelen = percent_plus_unescape_inplace (value, 0);
        }
    }
  if (!*key)
    return set_error (GPG_ERR_ASS_PARAMETER, "no key given");


  for (vl=putval_list,vlprev=NULL; vl; vlprev=vl, vl = vl->next)
    if ( !strcmp (vl->d, key) )
      break;

  if (vl) /* Delete old entry. */
    {
      if (vlprev)
        vlprev->next = vl->next;
      else
        putval_list = vl->next;
      xfree (vl);
    }

  if (valuelen) /* Add entry. */
    {
      vl = xtrymalloc (sizeof *vl + strlen (key) + valuelen);
      if (!vl)
        rc = gpg_error_from_syserror ();
      else
        {
          vl->len = valuelen;
          vl->off = strlen (key) + 1;
          strcpy (vl->d, key);
          memcpy (vl->d + vl->off, value, valuelen);
          vl->next = putval_list;
          putval_list = vl;
        }
    }

  return leave_cmd (ctx, rc);
}




static const char hlp_updatestartuptty[] =
  "UPDATESTARTUPTTY\n"
  "\n"
  "Set startup TTY and X11 DISPLAY variables to the values of this\n"
  "session.  This command is useful to pull future pinentries to\n"
  "another screen.  It is only required because there is no way in the\n"
  "ssh-agent protocol to convey this information.";
static gpg_error_t
cmd_updatestartuptty (assuan_context_t ctx, char *line)
{
  ctrl_t ctrl = assuan_get_pointer (ctx);
  gpg_error_t err = 0;
  session_env_t se;
  char *lc_ctype = NULL;
  char *lc_messages = NULL;
  int iterator;
  const char *name;

  (void)line;

  if (ctrl->restricted)
    return leave_cmd (ctx, gpg_error (GPG_ERR_FORBIDDEN));

  se = session_env_new ();
  if (!se)
    err = gpg_error_from_syserror ();

  iterator = 0;
  while (!err && (name = session_env_list_stdenvnames (&iterator, NULL)))
    {
      const char *value = session_env_getenv (ctrl->session_env, name);
      if (value)
        err = session_env_setenv (se, name, value);
    }

  if (!err && ctrl->lc_ctype)
    if (!(lc_ctype = xtrystrdup (ctrl->lc_ctype)))
      err = gpg_error_from_syserror ();

  if (!err && ctrl->lc_messages)
    if (!(lc_messages = xtrystrdup (ctrl->lc_messages)))
      err = gpg_error_from_syserror ();

  if (err)
    {
      session_env_release (se);
      xfree (lc_ctype);
      xfree (lc_messages);
    }
  else
    {
      session_env_release (opt.startup_env);
      opt.startup_env = se;
      xfree (opt.startup_lc_ctype);
      opt.startup_lc_ctype = lc_ctype;
      xfree (opt.startup_lc_messages);
      opt.startup_lc_messages = lc_messages;
    }

  return err;
}



static const char hlp_killagent[] =
  "KILLAGENT\n"
  "\n"
  "Stop the agent.";
static gpg_error_t
cmd_killagent (assuan_context_t ctx, char *line)
{
  ctrl_t ctrl = assuan_get_pointer (ctx);

  (void)line;

  if (ctrl->restricted)
    return leave_cmd (ctx, gpg_error (GPG_ERR_FORBIDDEN));

  ctrl->server_local->stopme = 1;
  assuan_set_flag (ctx, ASSUAN_FORCE_CLOSE, 1);
  return 0;
}


static const char hlp_reloadagent[] =
  "RELOADAGENT\n"
  "\n"
  "This command is an alternative to SIGHUP\n"
  "to reload the configuration.";
static gpg_error_t
cmd_reloadagent (assuan_context_t ctx, char *line)
{
  ctrl_t ctrl = assuan_get_pointer (ctx);

  (void)line;

  if (ctrl->restricted)
    return leave_cmd (ctx, gpg_error (GPG_ERR_FORBIDDEN));

  agent_sighup_action ();
  return 0;
}



static const char hlp_getinfo[] =
  "GETINFO <what>\n"
  "\n"
  "Multipurpose function to return a variety of information.\n"
  "Supported values for WHAT are:\n"
  "\n"
  "  version         - Return the version of the program.\n"
  "  pid             - Return the process id of the server.\n"
  "  socket_name     - Return the name of the socket.\n"
  "  ssh_socket_name - Return the name of the ssh socket.\n"
  "  scd_running     - Return OK if the SCdaemon is already running.\n"
  "  s2k_time        - Return the time in milliseconds required for S2K.\n"
  "  s2k_count       - Return the standard S2K count.\n"
  "  s2k_count_cal   - Return the calibrated S2K count.\n"
  "  std_env_names   - List the names of the standard environment.\n"
  "  std_session_env - List the standard session environment.\n"
  "  std_startup_env - List the standard startup environment.\n"
  "  getenv NAME     - Return value of envvar NAME.\n"
  "  connections     - Return number of active connections.\n"
  "  jent_active     - Returns OK if Libgcrypt's JENT is active.\n"
  "  restricted      - Returns OK if the connection is in restricted mode.\n"
  "  cmd_has_option CMD OPT\n"
  "                  - Returns OK if command CMD has option OPT.\n";
static gpg_error_t
cmd_getinfo (assuan_context_t ctx, char *line)
{
  ctrl_t ctrl = assuan_get_pointer (ctx);
  int rc = 0;

  if (!strcmp (line, "version"))
    {
      const char *s = VERSION;
      rc = assuan_send_data (ctx, s, strlen (s));
    }
  else if (!strncmp (line, "cmd_has_option", 14)
           && (line[14] == ' ' || line[14] == '\t' || !line[14]))
    {
      char *cmd, *cmdopt;
      line += 14;
      while (*line == ' ' || *line == '\t')
        line++;
      if (!*line)
        rc = gpg_error (GPG_ERR_MISSING_VALUE);
      else
        {
          cmd = line;
          while (*line && (*line != ' ' && *line != '\t'))
            line++;
          if (!*line)
            rc = gpg_error (GPG_ERR_MISSING_VALUE);
          else
            {
              *line++ = 0;
              while (*line == ' ' || *line == '\t')
                line++;
              if (!*line)
                rc = gpg_error (GPG_ERR_MISSING_VALUE);
              else
                {
                  cmdopt = line;
                  if (!command_has_option (cmd, cmdopt))
                    rc = gpg_error (GPG_ERR_FALSE);
                }
            }
        }
    }
  else if (!strcmp (line, "s2k_count"))
    {
      char numbuf[50];

      snprintf (numbuf, sizeof numbuf, "%lu", get_standard_s2k_count ());
      rc = assuan_send_data (ctx, numbuf, strlen (numbuf));
    }
  else if (!strcmp (line, "restricted"))
    {
      rc = ctrl->restricted? 0 : gpg_error (GPG_ERR_FALSE);
    }
  else if (ctrl->restricted)
    {
      rc = gpg_error (GPG_ERR_FORBIDDEN);
    }
  /* All sub-commands below are not allowed in restricted mode.  */
  else if (!strcmp (line, "pid"))
    {
      char numbuf[50];

      snprintf (numbuf, sizeof numbuf, "%lu", (unsigned long)getpid ());
      rc = assuan_send_data (ctx, numbuf, strlen (numbuf));
    }
  else if (!strcmp (line, "socket_name"))
    {
      const char *s = get_agent_socket_name ();

      if (s)
        rc = assuan_send_data (ctx, s, strlen (s));
      else
        rc = gpg_error (GPG_ERR_NO_DATA);
    }
  else if (!strcmp (line, "ssh_socket_name"))
    {
      const char *s = get_agent_ssh_socket_name ();

      if (s)
        rc = assuan_send_data (ctx, s, strlen (s));
      else
        rc = gpg_error (GPG_ERR_NO_DATA);
    }
  else if (!strcmp (line, "scd_running"))
    {
      rc = agent_scd_check_running ()? 0 : gpg_error (GPG_ERR_FALSE);
    }
  else if (!strcmp (line, "std_env_names"))
    {
      int iterator;
      const char *name;

      iterator = 0;
      while ((name = session_env_list_stdenvnames (&iterator, NULL)))
        {
          rc = assuan_send_data (ctx, name, strlen (name)+1);
          if (!rc)
            rc = assuan_send_data (ctx, NULL, 0);
          if (rc)
            break;
        }
    }
  else if (!strcmp (line, "std_session_env")
           || !strcmp (line, "std_startup_env"))
    {
      int iterator;
      const char *name, *value;
      char *string;

      iterator = 0;
      while ((name = session_env_list_stdenvnames (&iterator, NULL)))
        {
          value = session_env_getenv_or_default
            (line[5] == 't'? opt.startup_env:ctrl->session_env, name, NULL);
          if (value)
            {
              string = xtryasprintf ("%s=%s", name, value);
              if (!string)
                rc = gpg_error_from_syserror ();
              else
                {
                  rc = assuan_send_data (ctx, string, strlen (string)+1);
                  if (!rc)
                    rc = assuan_send_data (ctx, NULL, 0);
                }
              if (rc)
                break;
            }
        }
    }
  else if (!strncmp (line, "getenv", 6)
           && (line[6] == ' ' || line[6] == '\t' || !line[6]))
    {
      line += 6;
      while (*line == ' ' || *line == '\t')
        line++;
      if (!*line)
        rc = gpg_error (GPG_ERR_MISSING_VALUE);
      else
        {
          const char *s = getenv (line);
          if (!s)
            rc = set_error (GPG_ERR_NOT_FOUND, "No such envvar");
          else
            rc = assuan_send_data (ctx, s, strlen (s));
        }
    }
  else if (!strcmp (line, "connections"))
    {
      char numbuf[20];

      snprintf (numbuf, sizeof numbuf, "%d",
                get_agent_active_connection_count ());
      rc = assuan_send_data (ctx, numbuf, strlen (numbuf));
    }
  else if (!strcmp (line, "jent_active"))
    {
      char *buf;
      char *fields[5];

      buf = gcry_get_config (0, "rng-type");
      if (buf
          && split_fields_colon (buf, fields, DIM (fields)) >= 5
          && atoi (fields[4]) > 0)
        rc = 0;
      else
        rc = gpg_error (GPG_ERR_FALSE);
      gcry_free (buf);
    }
  else if (!strcmp (line, "s2k_count_cal"))
    {
      char numbuf[50];

      snprintf (numbuf, sizeof numbuf, "%lu", get_calibrated_s2k_count ());
      rc = assuan_send_data (ctx, numbuf, strlen (numbuf));
    }
  else if (!strcmp (line, "s2k_time"))
    {
      char numbuf[50];

      snprintf (numbuf, sizeof numbuf, "%lu", get_standard_s2k_time ());
      rc = assuan_send_data (ctx, numbuf, strlen (numbuf));
    }
  else
    rc = set_error (GPG_ERR_ASS_PARAMETER, "unknown value for WHAT");
  return rc;
}



/* This function is called by Libassuan to parse the OPTION command.
   It has been registered similar to the other Assuan commands.  */
static gpg_error_t
option_handler (assuan_context_t ctx, const char *key, const char *value)
{
  ctrl_t ctrl = assuan_get_pointer (ctx);
  gpg_error_t err = 0;

  if (!strcmp (key, "agent-awareness"))
    {
      /* The value is a version string telling us of which agent
         version the caller is aware of.  */
      ctrl->server_local->allow_fully_canceled =
        gnupg_compare_version (value, "2.1.0");
    }
  else if (ctrl->restricted)
    {
      err = gpg_error (GPG_ERR_FORBIDDEN);
    }
  /* All options below are not allowed in restricted mode.  */
  else if (!strcmp (key, "putenv"))
    {
      /* Change the session's environment to be used for the
         Pinentry.  Valid values are:
          <NAME>            Delete envvar NAME
          <KEY>=            Set envvar NAME to the empty string
          <KEY>=<VALUE>     Set envvar NAME to VALUE
      */
      err = session_env_putenv (ctrl->session_env, value);
    }
  else if (!strcmp (key, "display"))
    {
      err = session_env_setenv (ctrl->session_env, "DISPLAY", value);
    }
  else if (!strcmp (key, "ttyname"))
    {
      if (!opt.keep_tty)
        err = session_env_setenv (ctrl->session_env, "GPG_TTY", value);
    }
  else if (!strcmp (key, "ttytype"))
    {
      if (!opt.keep_tty)
        err = session_env_setenv (ctrl->session_env, "TERM", value);
    }
  else if (!strcmp (key, "lc-ctype"))
    {
      if (ctrl->lc_ctype)
        xfree (ctrl->lc_ctype);
      ctrl->lc_ctype = xtrystrdup (value);
      if (!ctrl->lc_ctype)
        return out_of_core ();
    }
  else if (!strcmp (key, "lc-messages"))
    {
      if (ctrl->lc_messages)
        xfree (ctrl->lc_messages);
      ctrl->lc_messages = xtrystrdup (value);
      if (!ctrl->lc_messages)
        return out_of_core ();
    }
  else if (!strcmp (key, "xauthority"))
    {
      err = session_env_setenv (ctrl->session_env, "XAUTHORITY", value);
    }
  else if (!strcmp (key, "pinentry-user-data"))
    {
      err = session_env_setenv (ctrl->session_env, "PINENTRY_USER_DATA", value);
    }
  else if (!strcmp (key, "use-cache-for-signing"))
    ctrl->server_local->use_cache_for_signing = *value? !!atoi (value) : 0;
  else if (!strcmp (key, "allow-pinentry-notify"))
    ctrl->server_local->allow_pinentry_notify = 1;
  else if (!strcmp (key, "pinentry-mode"))
    {
      int tmp = parse_pinentry_mode (value);
      if (tmp == -1)
        err = gpg_error (GPG_ERR_INV_VALUE);
      else if (tmp == PINENTRY_MODE_LOOPBACK && !opt.allow_loopback_pinentry)
        err = gpg_error (GPG_ERR_NOT_SUPPORTED);
      else
        ctrl->pinentry_mode = tmp;
    }
  else if (!strcmp (key, "cache-ttl-opt-preset"))
    {
      ctrl->cache_ttl_opt_preset = *value? atoi (value) : 0;
    }
  else if (!strcmp (key, "s2k-count"))
    {
      ctrl->s2k_count = *value? strtoul(value, NULL, 10) : 0;
      if (ctrl->s2k_count && ctrl->s2k_count < 65536)
        {
	  ctrl->s2k_count = 0;
        }
    }
  else if (!strcmp (key, "pretend-request-origin"))
    {
      log_assert (!ctrl->restricted);
      switch (parse_request_origin (value))
        {
        case REQUEST_ORIGIN_LOCAL:   ctrl->restricted = 0; break;
        case REQUEST_ORIGIN_REMOTE:  ctrl->restricted = 1; break;
        case REQUEST_ORIGIN_BROWSER: ctrl->restricted = 2; break;
        default:
          err = gpg_error (GPG_ERR_INV_VALUE);
          /* Better pretend to be remote in case of a bad value.  */
          ctrl->restricted = 1;
          break;
        }
    }
  else
    err = gpg_error (GPG_ERR_UNKNOWN_OPTION);

  return err;
}




/* Called by libassuan after all commands. ERR is the error from the
   last assuan operation and not the one returned from the command. */
static void
post_cmd_notify (assuan_context_t ctx, gpg_error_t err)
{
  ctrl_t ctrl = assuan_get_pointer (ctx);

  (void)err;

  /* Switch off any I/O monitor controlled logging pausing. */
  ctrl->server_local->pause_io_logging = 0;
}


/* This function is called by libassuan for all I/O.  We use it here
   to disable logging for the GETEVENTCOUNTER commands.  This is so
   that the debug output won't get cluttered by this primitive
   command.  */
static unsigned int
io_monitor (assuan_context_t ctx, void *hook, int direction,
            const char *line, size_t linelen)
{
  ctrl_t ctrl = assuan_get_pointer (ctx);

  (void) hook;

  /* We want to suppress all Assuan log messages for connections from
   * self.  However, assuan_get_pid works only after
   * assuan_accept. Now, assuan_accept already logs a line ending with
   * the process id.  We use this hack here to get the peers pid so
   * that we can compare it to our pid.  We should add an assuan
   * function to return the pid for a file descriptor and use that to
   * detect connections to self.  */
  if (ctx && !ctrl->server_local->greeting_seen
      && direction == ASSUAN_IO_TO_PEER)
    {
      ctrl->server_local->greeting_seen = 1;
      if (linelen > 32
          && !strncmp (line, "OK Pleased to meet you, process ", 32)
          && strtoul (line+32, NULL, 10) == getpid ())
        return ASSUAN_IO_MONITOR_NOLOG;
    }


  /* Do not log self-connections.  This makes the log cleaner because
   * we won't see the check-our-own-socket calls.  */
  if (ctx && ctrl->server_local->connect_from_self)
    return ASSUAN_IO_MONITOR_NOLOG;

  /* Note that we only check for the uppercase name.  This allows the user to
     see the logging for debugging if using a non-upercase command
     name. */
  if (ctx && direction == ASSUAN_IO_FROM_PEER
      && linelen >= 15
      && !strncmp (line, "GETEVENTCOUNTER", 15)
      && (linelen == 15 || spacep (line+15)))
    {
      ctrl->server_local->pause_io_logging = 1;
    }

  return ctrl->server_local->pause_io_logging? ASSUAN_IO_MONITOR_NOLOG : 0;
}


/* Return true if the command CMD implements the option OPT.  */
static int
command_has_option (const char *cmd, const char *cmdopt)
{
  if (!strcmp (cmd, "GET_PASSPHRASE"))
    {
      if (!strcmp (cmdopt, "repeat"))
        return 1;
      if (!strcmp (cmdopt, "newsymkey"))
        return 1;
    }

  return 0;
}


/* Tell Libassuan about our commands.  Also register the other Assuan
   handlers. */
static int
register_commands (assuan_context_t ctx)
{
  static struct {
    const char *name;
    assuan_handler_t handler;
    const char * const help;
  } table[] = {
    { "GETEVENTCOUNTER",cmd_geteventcounter, hlp_geteventcounter },
    { "ISTRUSTED",      cmd_istrusted, hlp_istrusted },
    { "HAVEKEY",        cmd_havekey,   hlp_havekey },
    { "KEYINFO",        cmd_keyinfo,   hlp_keyinfo },
    { "SIGKEY",         cmd_sigkey,    hlp_sigkey },
    { "SETKEY",         cmd_sigkey,    hlp_sigkey },
    { "SETKEYDESC",     cmd_setkeydesc,hlp_setkeydesc },
    { "SETHASH",        cmd_sethash,   hlp_sethash },
    { "PKSIGN",         cmd_pksign,    hlp_pksign },
    { "PKDECRYPT",      cmd_pkdecrypt, hlp_pkdecrypt },
    { "GENKEY",         cmd_genkey,    hlp_genkey },
    { "READKEY",        cmd_readkey,   hlp_readkey },
    { "GET_PASSPHRASE", cmd_get_passphrase, hlp_get_passphrase },
    { "PRESET_PASSPHRASE", cmd_preset_passphrase, hlp_preset_passphrase },
    { "CLEAR_PASSPHRASE", cmd_clear_passphrase,   hlp_clear_passphrase },
    { "GET_CONFIRMATION", cmd_get_confirmation,   hlp_get_confirmation },
    { "LISTTRUSTED",    cmd_listtrusted, hlp_listtrusted },
    { "MARKTRUSTED",    cmd_marktrusted, hlp_martrusted },
    { "LEARN",          cmd_learn,     hlp_learn },
    { "PASSWD",         cmd_passwd,    hlp_passwd },
    { "INPUT",          NULL },
    { "OUTPUT",         NULL },
    { "SCD",            cmd_scd,       hlp_scd },
    { "KEYWRAP_KEY",    cmd_keywrap_key, hlp_keywrap_key },
    { "IMPORT_KEY",     cmd_import_key, hlp_import_key },
    { "EXPORT_KEY",     cmd_export_key, hlp_export_key },
    { "DELETE_KEY",     cmd_delete_key, hlp_delete_key },
    { "GETVAL",         cmd_getval,    hlp_getval },
    { "PUTVAL",         cmd_putval,    hlp_putval },
    { "UPDATESTARTUPTTY",  cmd_updatestartuptty, hlp_updatestartuptty },
    { "KILLAGENT",      cmd_killagent,  hlp_killagent },
    { "RELOADAGENT",    cmd_reloadagent,hlp_reloadagent },
    { "GETINFO",        cmd_getinfo,   hlp_getinfo },
    { "KEYTOCARD",      cmd_keytocard, hlp_keytocard },
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
  assuan_register_post_cmd_notify (ctx, post_cmd_notify);
  assuan_register_reset_notify (ctx, reset_notify);
  assuan_register_option_handler (ctx, option_handler);
  return 0;
}


/* Startup the server.  If LISTEN_FD and FD is given as -1, this is a
   simple piper server, otherwise it is a regular server.  CTRL is the
   control structure for this connection; it has only the basic
   initialization. */
void
start_command_handler (ctrl_t ctrl, gnupg_fd_t listen_fd, gnupg_fd_t fd)
{
  int rc;
  assuan_context_t ctx = NULL;

  if (ctrl->restricted)
    {
      if (agent_copy_startup_env (ctrl))
        return;
    }

  rc = assuan_new (&ctx);
  if (rc)
    {
      log_error ("failed to allocate assuan context: %s\n", gpg_strerror (rc));
      agent_exit (2);
    }

  if (listen_fd == GNUPG_INVALID_FD && fd == GNUPG_INVALID_FD)
    {
      assuan_fd_t filedes[2];

      filedes[0] = assuan_fdopen (0);
      filedes[1] = assuan_fdopen (1);
      rc = assuan_init_pipe_server (ctx, filedes);
    }
  else if (listen_fd != GNUPG_INVALID_FD)
    {
      rc = assuan_init_socket_server (ctx, listen_fd, 0);
      /* FIXME: Need to call assuan_sock_set_nonce for Windows.  But
	 this branch is currently not used.  */
    }
  else
    {
      rc = assuan_init_socket_server (ctx, fd, ASSUAN_SOCKET_SERVER_ACCEPTED);
    }
  if (rc)
    {
      log_error ("failed to initialize the server: %s\n",
                 gpg_strerror(rc));
      agent_exit (2);
    }
  rc = register_commands (ctx);
  if (rc)
    {
      log_error ("failed to register commands with Assuan: %s\n",
                 gpg_strerror(rc));
      agent_exit (2);
    }

  assuan_set_pointer (ctx, ctrl);
  ctrl->server_local = xcalloc (1, sizeof *ctrl->server_local);
  ctrl->server_local->assuan_ctx = ctx;
  ctrl->server_local->use_cache_for_signing = 1;

  ctrl->digest.raw_value = 0;

  assuan_set_io_monitor (ctx, io_monitor, NULL);
  agent_set_progress_cb (progress_cb, ctrl);

  for (;;)
    {
      pid_t client_pid;

      rc = assuan_accept (ctx);
      if (gpg_err_code (rc) == GPG_ERR_EOF || rc == -1)
        {
          break;
        }
      else if (rc)
        {
          log_info ("Assuan accept problem: %s\n", gpg_strerror (rc));
          break;
        }

      client_pid = assuan_get_pid (ctx);
      ctrl->server_local->connect_from_self = (client_pid == getpid ());
      if (client_pid != ASSUAN_INVALID_PID)
        ctrl->client_pid = (unsigned long)client_pid;
      else
        ctrl->client_pid = 0;

      rc = assuan_process (ctx);
      if (rc)
        {
          log_info ("Assuan processing failed: %s\n", gpg_strerror (rc));
          continue;
        }
    }

  /* Reset the nonce caches.  */
  clear_nonce_cache (ctrl);

  /* Reset the SCD if needed. */
  agent_reset_scd (ctrl);

  /* Reset the pinentry (in case of popup messages). */
  agent_reset_query (ctrl);

  /* Cleanup.  */
  assuan_release (ctx);
  xfree (ctrl->server_local->keydesc);
  xfree (ctrl->server_local->import_key);
  xfree (ctrl->server_local->export_key);
  if (ctrl->server_local->stopme)
    agent_exit (0);
  xfree (ctrl->server_local);
  ctrl->server_local = NULL;
}


/* Helper for the pinentry loopback mode.  It merely passes the
   parameters on to the client.  */
gpg_error_t
pinentry_loopback(ctrl_t ctrl, const char *keyword,
                  unsigned char **buffer, size_t *size,
                  size_t max_length)
{
  gpg_error_t rc;
  assuan_context_t ctx = ctrl->server_local->assuan_ctx;

  rc = print_assuan_status (ctx, "INQUIRE_MAXLEN", "%zu", max_length);
  if (rc)
    return rc;

  assuan_begin_confidential (ctx);
  rc = assuan_inquire (ctx, keyword, buffer, size, max_length);
  assuan_end_confidential (ctx);
  return rc;
}
