/* command.c - gpg-agent command handler
 * Copyright (C) 2001, 2002, 2003, 2004, 2005  Free Software Foundation, Inc.
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301,
 * USA.
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
struct server_local_s
{
  assuan_context_t assuan_ctx;
  int message_fd;
  int use_cache_for_signing;
  char *keydesc;  /* Allocated description for the next key
                     operation. */
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





/* Release the memory buffer MB but first wipe out the used memory. */
static void
clear_outbuf (membuf_t *mb)
{
  void *p;
  size_t n;

  p = get_membuf (mb, &n);
  if (p)
    {
      memset (p, 0, n);
      xfree (p);
    }
}


/* Write the content of memory buffer MB as assuan data to CTX and
   wipe the buffer out afterwards. */
static gpg_error_t
write_and_clear_outbuf (assuan_context_t ctx, membuf_t *mb)
{
  assuan_error_t ae;
  void *p;
  size_t n;

  p = get_membuf (mb, &n);
  if (!p)
    return gpg_error (GPG_ERR_ENOMEM);
  ae = assuan_send_data (ctx, p, n);
  memset (p, 0, n);
  xfree (p);
  return map_assuan_err (ae);
}


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


/* Do the percent and plus/space unescaping in place and return the
   length of the valid buffer. */
static size_t
percent_plus_unescape (char *string)
{
  unsigned char *p = string;
  size_t n = 0;

  while (*string)
    {
      if (*string == '%' && string[1] && string[2])
        { 
          string++;
          *p++ = xtoi_2 (string);
          n++;
          string+= 2;
        }
      else if (*string == '+')
        {
          *p++ = ' ';
          n++;
          string++;
        }
      else
        {
          *p++ = *string++;
          n++;
        }
    }

  return n;
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
  if (*p != ' ' && *p != '\t' && *p)
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

  for (p=(const unsigned char*)string, n=0; n < 20; p += 2, n++)
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


/* SETKEYDESC plus_percent_escaped_string

   Set a description to be used for the next PKSIGN or PKDECRYPT
   operation if this operation requires the entry of a passphrase.  If
   this command is not used a default text will be used.  Note, that
   this description implictly selects the label used for the entry
   box; if the string contains the string PIN (which in general will
   not be translated), "PIN" is used, otherwise the translation of
   "passphrase" is used.  The description string should not contain
   blanks unless they are percent or '+' escaped.

   The description is only valid for the next PKSIGN or PKDECRYPT
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
   sensitive to eavesdropping. */
static int
cmd_pksign (ASSUAN_CONTEXT ctx, char *line)
{
  int rc;
  cache_mode_t cache_mode = CACHE_MODE_NORMAL;
  ctrl_t ctrl = assuan_get_pointer (ctx);
  membuf_t outbuf;
  
  if (opt.ignore_cache_for_signing)
    cache_mode = CACHE_MODE_IGNORE;
  else if (!ctrl->server_local->use_cache_for_signing)
    cache_mode = CACHE_MODE_IGNORE;

  init_membuf (&outbuf, 512);

  rc = agent_pksign (ctrl, ctrl->server_local->keydesc,
                     &outbuf, cache_mode);
  if (rc)
    clear_outbuf (&outbuf);
  else
    rc = write_and_clear_outbuf (ctx, &outbuf);
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
  membuf_t outbuf;

  /* First inquire the data to decrypt */
  rc = assuan_inquire (ctx, "CIPHERTEXT",
                       &value, &valuelen, MAXLEN_CIPHERTEXT);
  if (rc)
    return rc;

  init_membuf (&outbuf, 512);

  rc = agent_pkdecrypt (ctrl, ctrl->server_local->keydesc,
                        value, valuelen, &outbuf);
  xfree (value);
  if (rc)
    clear_outbuf (&outbuf);
  else
    rc = write_and_clear_outbuf (ctx, &outbuf);
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
  membuf_t outbuf;

  /* First inquire the parameters */
  rc = assuan_inquire (ctx, "KEYPARAM", &value, &valuelen, MAXLEN_KEYPARAM);
  if (rc)
    return rc;

  init_membuf (&outbuf, 512);

  rc = agent_genkey (ctrl, (char*)value, valuelen, &outbuf);
  xfree (value);
  if (rc)
    clear_outbuf (&outbuf);
  else
    rc = write_and_clear_outbuf (ctx, &outbuf);
  if (rc)
    log_error ("command genkey failed: %s\n", gpg_strerror (rc));
  return map_to_assuan_status (rc);
}




/* READKEY <hexstring_with_keygrip>
  
   Return the public key for the given keygrip.  */
static int
cmd_readkey (assuan_context_t ctx, char *line)
{
  ctrl_t ctrl = assuan_get_pointer (ctx);
  int rc;
  unsigned char grip[20];
  gcry_sexp_t s_pkey = NULL;

  rc = parse_keygrip (ctx, line, grip);
  if (rc)
    return rc; /* Return immediately as this is already an Assuan error code.*/

  rc = agent_public_key_from_file (ctrl, grip, &s_pkey);
  if (!rc)
    {
      size_t len;
      unsigned char *buf;

      len = gcry_sexp_sprint (s_pkey, GCRYSEXP_FMT_CANON, NULL, 0);
      assert (len);
      buf = xtrymalloc (len);
      if (!buf)
        rc = gpg_error_from_errno (errno);
      else
        {
          len = gcry_sexp_sprint (s_pkey, GCRYSEXP_FMT_CANON, buf, len);
          assert (len);
          rc = assuan_send_data (ctx, buf, len);
          rc = map_assuan_err (rc);
          xfree (buf);
        }
      gcry_sexp_release (s_pkey);
    }

  if (rc)
    log_error ("command readkey failed: %s\n", gpg_strerror (rc));
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
  pw = cacheid ? agent_get_cache (cacheid, CACHE_MODE_NORMAL, &cache_marker)
               : NULL;
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
            agent_put_cache (cacheid, CACHE_MODE_USER, response, 0);
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

  agent_put_cache (cacheid, CACHE_MODE_USER, NULL, 0);
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
                            grip, &shadow_info, CACHE_MODE_IGNORE, &s_skey);
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

/* PRESET_PASSPHRASE <hexstring_with_keygrip> <timeout> <hexstring>
  
   Set the cached passphrase/PIN for the key identified by the keygrip
   to passwd for the given time, where -1 means infinite and 0 means
   the default (currently only a timeout of -1 is allowed, which means
   to never expire it).  If passwd is not provided, ask for it via the
   pinentry module.  */
static int
cmd_preset_passphrase (ASSUAN_CONTEXT ctx, char *line)
{
  int rc;
  unsigned char grip[20];
  char *grip_clear = NULL;
  char *passphrase = NULL;
  int ttl;
  size_t len;

  if (!opt.allow_preset_passphrase)
    return gpg_error (GPG_ERR_NOT_SUPPORTED);

  rc = parse_keygrip (ctx, line, grip);
  if (rc)
    return rc;

  /* FIXME: parse_keygrip should return a tail pointer.  */
  grip_clear = line;
  while (*line && (*line != ' ' && *line != '\t'))
    line++;
  if (!*line)
    return map_to_assuan_status (gpg_error (GPG_ERR_MISSING_VALUE));
  *line = '\0';
  line++;
  while (*line && (*line == ' ' || *line == '\t'))
    line++;
  
  /* Currently, only infinite timeouts are allowed.  */
  ttl = -1;
  if (line[0] != '-' || line[1] != '1')
    return map_to_assuan_status (gpg_error (GPG_ERR_NOT_IMPLEMENTED));
  line++;
  line++;
  while (!(*line != ' ' && *line != '\t'))
    line++;

  /* Syntax check the hexstring.  */
  rc = parse_hexstring (ctx, line, &len);
  if (rc)
    return rc;
  line[len] = '\0';

  /* If there is a passphrase, use it.  Currently, a passphrase is
     required.  */
  if (*line)
    passphrase = line;
  else
    return map_to_assuan_status (gpg_error (GPG_ERR_NOT_IMPLEMENTED));

  rc = agent_put_cache (grip_clear, CACHE_MODE_ANY, passphrase, ttl);

  if (rc)
    log_error ("command preset_passwd failed: %s\n", gpg_strerror (rc));

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



/* GETVAL <key>

   Return the value for KEY from the special environment as created by
   PUTVAL.
 */
static int
cmd_getval (assuan_context_t ctx, char *line)
{
  int rc = 0;
  char *key = NULL;
  char *p;
  struct putval_item_s *vl;

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
        return set_error (Parameter_Error, "too many arguments");
    }
  if (!key || !*key)
    return set_error (Parameter_Error, "no key given");


  for (vl=putval_list; vl; vl = vl->next)
    if ( !strcmp (vl->d, key) )
      break;

  if (vl) /* Got an entry. */
    {
      rc = assuan_send_data (ctx, vl->d+vl->off, vl->len);
      if (rc)
        rc = map_assuan_err (rc);
    }
  else
    return gpg_error (GPG_ERR_NO_DATA);

  if (rc)
    log_error ("command getval failed: %s\n", gpg_strerror (rc));
  return map_to_assuan_status (rc);
}


/* PUTVAL <key> [<percent_escaped_value>]

   The gpg-agent maintains a kind of environment which may be used to
   store key/value pairs in it, so that they can be retrieved later.
   This may be used by helper daemons to daemonize themself on
   invocation and register them with gpg-agent.  Callers of the
   daemon's service may now first try connect to get the information
   for that service from gpg-agent through the GETVAL command and then
   try to connect to that daemon.  Only if that fails they may start
   an own instance of the service daemon. 

   KEY is an an arbitrary symbol with the same syntax rules as keys
   for shell environment variables.  PERCENT_ESCAPED_VALUE is the
   corresponsing value; they should be similar to the values of
   envronment variables but gpg-agent does not enforce any
   restrictions.  If that value is not given any value under that KEY
   is removed from this special environment.
*/
static int
cmd_putval (assuan_context_t ctx, char *line)
{
  int rc = 0;
  char *key = NULL;
  char *value = NULL;
  size_t valuelen = 0;
  char *p;
  struct putval_item_s *vl, *vlprev;

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
          valuelen = percent_plus_unescape (value);
        }
    }
  if (!key || !*key)
    return set_error (Parameter_Error, "no key given");


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
        rc = gpg_error_from_errno (errno);
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

  if (rc)
    log_error ("command putval failed: %s\n", gpg_strerror (rc));
  return map_to_assuan_status (rc);
}




/* UPDATESTARTUPTTY 
  
  Set startup TTY and X DISPLAY variables to the values of this
  session.  This command is useful to pull future pinentries to
  another screen.  It is only required because there is no way in the
  ssh-agent protocol to convey this information.  */
static int
cmd_updatestartuptty (assuan_context_t ctx, char *line)
{
  ctrl_t ctrl = assuan_get_pointer (ctx);

  xfree (opt.startup_display); opt.startup_display = NULL;
  xfree (opt.startup_ttyname); opt.startup_ttyname = NULL;
  xfree (opt.startup_ttytype); opt.startup_ttytype = NULL;
  xfree (opt.startup_lc_ctype); opt.startup_lc_ctype = NULL;
  xfree (opt.startup_lc_messages); opt.startup_lc_messages = NULL;

  if (ctrl->display)
    opt.startup_display = xtrystrdup (ctrl->display);
  if (ctrl->ttyname)
    opt.startup_ttyname = xtrystrdup (ctrl->ttyname);
  if (ctrl->ttytype)
    opt.startup_ttytype = xtrystrdup (ctrl->ttytype);
  if (ctrl->lc_ctype) 
    opt.startup_lc_ctype = xtrystrdup (ctrl->lc_ctype);
  if (ctrl->lc_messages)
    opt.startup_lc_messages = xtrystrdup (ctrl->lc_messages);

  return 0;
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
    { "READKEY",        cmd_readkey },
    { "GET_PASSPHRASE", cmd_get_passphrase },
    { "PRESET_PASSPHRASE", cmd_preset_passphrase },
    { "CLEAR_PASSPHRASE", cmd_clear_passphrase },
    { "GET_CONFIRMATION", cmd_get_confirmation },
    { "LISTTRUSTED",    cmd_listtrusted },
    { "MARKTRUSTED",    cmd_marktrusted },
    { "LEARN",          cmd_learn },
    { "PASSWD",         cmd_passwd },
    { "INPUT",          NULL }, 
    { "OUTPUT",         NULL }, 
    { "SCD",            cmd_scd },
    { "GETVAL",         cmd_getval },
    { "PUTVAL",         cmd_putval },
    { "UPDATESTARTUPTTY",  cmd_updatestartuptty },
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

  /* Reset the pinentry (in case of popup messages). */
  agent_reset_query (&ctrl);

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
  xfree (ctrl.server_local);
}

