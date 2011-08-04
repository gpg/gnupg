/* command.c - gpg-agent command handler
 * Copyright (C) 2001, 2002, 2003, 2004, 2005,
 *               2006, 2008, 2009  Free Software Foundation, Inc.
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
#include "i18n.h"
#include "../common/ssh-utils.h"

/* maximum allowed size of the inquired ciphertext */
#define MAXLEN_CIPHERTEXT 4096
/* maximum allowed size of the key parameters */
#define MAXLEN_KEYPARAM 1024

#define set_error(e,t) assuan_set_error (ctx, gpg_error (e), (t))


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
  int pause_io_logging; /* Used to suppress I/O logging during a command */
  int stopme;    /* If set to true the agent will be terminated after
                    the end of this session.  */
  int allow_pinentry_notify; /* Set if pinentry notifications should
                                be done. */
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
      memset (p, 0, n);
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
  return 0;
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

/* Same as has_option but does only test for the name of the option
   and ignores an argument, i.e. with NAME being "--hash" it would
   return true for "--hash" as well as for "--hash=foo". */
static int
has_option_name (const char *line, const char *name)
{
  const char *s;
  int n = strlen (name);

  s = strstr (line, name);
  return (s && (s == line || spacep (s-1))
          && (!s[n] || spacep (s+n) || s[n] == '='));
}

/* Return a pointer to the argument of the option with NAME.  If such
   an option is not given, it returns NULL. */
static char *
option_value (const char *line, const char *name)
{
  char *s;
  int n = strlen (name);

  s = strstr (line, name);
  if (s && (s == line || spacep (s-1))
      && s[n] && (spacep (s+n) || s[n] == '='))
    {
      s += n + 1;
      s += strspn (s, " ");
      if (*s && !spacep(s))
        return s;
    }
  return NULL;
}


/* Skip over options.  It is assumed that leading spaces have been
   removed (this is the case for lines passed to a handler from
   assuan).  Blanks after the options are also removed. */
static char *
skip_options (char *line)
{
  while ( *line == '-' && line[1] == '-' )
    {
      while (*line && !spacep (line))
        line++;
      while (spacep (line))
        line++;
    }
  return line;
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
   provide space for 20 bytes. BUF is not changed if the function
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


/* Write an assuan status line. */
gpg_error_t
agent_write_status (ctrl_t ctrl, const char *keyword, ...)
{
  gpg_error_t err = 0;
  va_list arg_ptr;
  const char *text;
  assuan_context_t ctx = ctrl->server_local->assuan_ctx;
  char buf[950], *p;
  size_t n;

  va_start (arg_ptr, keyword);

  p = buf;
  n = 0;
  while ( (text = va_arg (arg_ptr, const char *)) )
    {
      if (n)
        {
          *p++ = ' ';
          n++;
        }
      for ( ; *text && n < DIM (buf)-3; n++, text++)
        {
          if (*text == '\n')
            {
              *p++ = '\\';
              *p++ = 'n';
            }
          else if (*text == '\r')
            {
              *p++ = '\\';
              *p++ = 'r';
            }
          else
            *p++ = *text;
        }
    }
  *p = 0;
  err = assuan_write_status (ctx, keyword, buf);

  va_end (arg_ptr);
  return err;
}


/* Helper to notify the client about a launched Pinentry.  Because
   that might disturb some older clients, this is only done if enabled
   via an option.  Returns an gpg error code. */
gpg_error_t
agent_inq_pinentry_launched (ctrl_t ctrl, unsigned long pid)
{
  char line[100];

  if (!ctrl || !ctrl->server_local
      || !ctrl->server_local->allow_pinentry_notify)
    return 0;
  snprintf (line, DIM(line)-1, "PINENTRY_LAUNCHED %lu", pid);
  return assuan_inquire (ctrl->server_local->assuan_ctx, line, NULL, NULL, 0);
}



static const char hlp_geteventcounter[] =
  "GETEVENTCOUNTER\n"
  "\n"
  "Return a a status line named EVENTCOUNTER with the current values\n"
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
  char any_counter[25];
  char key_counter[25];
  char card_counter[25];

  (void)line;

  snprintf (any_counter, sizeof any_counter, "%u", eventcounter.any);
  snprintf (key_counter, sizeof key_counter, "%u", eventcounter.key);
  snprintf (card_counter, sizeof card_counter, "%u", eventcounter.card);

  return agent_write_status (ctrl, "EVENTCOUNTER",
                             any_counter,
                             key_counter,
                             card_counter,
                             NULL);
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
    {
      log_error ("command is_trusted failed: %s\n", gpg_strerror (rc));
      return rc;
    }
}


static const char hlp_listtrusted[] =
  "LISTTRUSTED\n"
  "\n"
  "List all entries from the trustlist.";
static gpg_error_t
cmd_listtrusted (assuan_context_t ctx, char *line)
{
  int rc;

  (void)line;

  rc = agent_listtrusted (ctx);
  if (rc)
    log_error ("command listtrusted failed: %s\n", gpg_strerror (rc));
  return rc;
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
  if (rc)
    log_error ("command marktrusted failed: %s\n", gpg_strerror (rc));
  return rc;
}




static const char hlp_havekey[] =
  "HAVEKEY <hexstring_with_keygrip>\n"
  "\n"
  "Return success when the secret key is available.";
static gpg_error_t
cmd_havekey (assuan_context_t ctx, char *line)
{
  int rc;
  unsigned char buf[20];

  rc = parse_keygrip (ctx, line, buf);
  if (rc)
    return rc;

  if (agent_key_available (buf))
    return gpg_error (GPG_ERR_NO_SECKEY);

  return 0;
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
  "Set a description to be used for the next PKSIGN or PKDECRYPT\n"
  "operation if this operation requires the entry of a passphrase.  If\n"
  "this command is not used a default text will be used.  Note, that\n"
  "this description implictly selects the label used for the entry\n"
  "box; if the string contains the string PIN (which in general will\n"
  "not be translated), \"PIN\" is used, otherwise the translation of\n"
  "\"passphrase\" is used.  The description string should not contain\n"
  "blanks unless they are percent or '+' escaped.\n"
  "\n"
  "The description is only valid for the next PKSIGN or PKDECRYPT\n"
  "operation.";
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

  if (!desc || !*desc)
    return set_error (GPG_ERR_ASS_PARAMETER, "no description given");

  /* Note, that we only need to replace the + characters and should
     leave the other escaping in place because the escaped string is
     send verbatim to the pinentry which does the unescaping (but not
     the + replacing) */
  plus_to_blank (desc);

  xfree (ctrl->server_local->keydesc);
  ctrl->server_local->keydesc = xtrystrdup (desc);
  if (!ctrl->server_local->keydesc)
    return out_of_core ();
  return 0;
}


static const char hlp_sethash[] =
  "SETHASH --hash=<name>|<algonumber> <hexstring>\n"
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
  "PKSIGN [options]\n"
  "\n"
  "Perform the actual sign operation.  Neither input nor output are\n"
  "sensitive to eavesdropping.";
static gpg_error_t
cmd_pksign (assuan_context_t ctx, char *line)
{
  int rc;
  cache_mode_t cache_mode = CACHE_MODE_NORMAL;
  ctrl_t ctrl = assuan_get_pointer (ctx);
  membuf_t outbuf;

  (void)line;

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
  return rc;
}


static const char hlp_pkdecrypt[] =
  "PKDECRYPT <options>\n"
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

  (void)line;

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
  return rc;
}


static const char hlp_genkey[] =
  "GENKEY\n"
  "\n"
  "Generate a new key, store the secret part and return the public\n"
  "part.  Here is an example transaction:\n"
  "\n"
  "  C: GENKEY\n"
  "  S: INQUIRE KEYPARAM\n"
  "  C: D (genkey (rsa (nbits  1024)))\n"
  "  C: END\n"
  "  S: D (public-key\n"
  "  S: D   (rsa (n 326487324683264) (e 10001)))\n"
  "  S: OK key created\n"
  "\n";
static gpg_error_t
cmd_genkey (assuan_context_t ctx, char *line)
{
  ctrl_t ctrl = assuan_get_pointer (ctx);
  int rc;
  unsigned char *value;
  size_t valuelen;
  membuf_t outbuf;

  (void)line;

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
  return rc;
}




static const char hlp_readkey[] =
  "READKEY <hexstring_with_keygrip>\n"
  "\n"
  "Return the public key for the given keygrip.";
static gpg_error_t
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
        rc = gpg_error_from_syserror ();
      else
        {
          len = gcry_sexp_sprint (s_pkey, GCRYSEXP_FMT_CANON, buf, len);
          assert (len);
          rc = assuan_send_data (ctx, buf, len);
          xfree (buf);
        }
      gcry_sexp_release (s_pkey);
    }

  if (rc)
    log_error ("command readkey failed: %s\n", gpg_strerror (rc));
  return rc;
}



static const char hlp_keyinfo[] =
  "KEYINFO [--list] [--data] [--ssh-fpr] <keygrip>\n"
  "\n"
  "Return information about the key specified by the KEYGRIP.  If the\n"
  "key is not available GPG_ERR_NOT_FOUND is returned.  If the option\n"
  "--list is given the keygrip is ignored and information about all\n"
  "available keys are returned.  The information is returned as a\n"
  "status line unless --data was specified, with this format:\n"
  "\n"
  "  KEYINFO <keygrip> <type> <serialno> <idstr> - - <fpr>\n"
  "\n"
  "KEYGRIP is the keygrip.\n"
  "\n"
  "TYPE is describes the type of the key:\n"
  "    'D' - Regular key stored on disk,\n"
  "    'T' - Key is stored on a smartcard (token).\n"
  "    '-' - Unknown type.\n"
  "\n"
  "SERIALNO is an ASCII string with the serial number of the\n"
  "         smartcard.  If the serial number is not known a single\n"
  "         dash '-' is used instead.\n"
  "\n"
  "IDSTR is the IDSTR used to distinguish keys on a smartcard.  If it\n"
  "      is not known a dash is used instead.\n"
  "\n"
  "FPR returns the formatted ssh-style fingerprint of the key.  It is only\n"
  "    print if the option --ssh-fpr has been used. '-' is printed if the\n"
  "    fingerprint is not available.\n"
  "\n"
  "More information may be added in the future.";
static gpg_error_t
do_one_keyinfo (ctrl_t ctrl, const unsigned char *grip, assuan_context_t ctx,
                int data, int with_ssh_fpr)
{
  gpg_error_t err;
  char hexgrip[40+1];
  char *fpr = NULL;
  int keytype;
  unsigned char *shadow_info = NULL;
  char *serialno = NULL;
  char *idstr = NULL;
  const char *keytypestr;

  err = agent_key_info_from_file (ctrl, grip, &keytype, &shadow_info);
  if (err)
    goto leave;

  /* Reformat the grip so that we use uppercase as good style. */
  bin2hex (grip, 20, hexgrip);

  if (keytype == PRIVATE_KEY_CLEAR
      || keytype == PRIVATE_KEY_PROTECTED)
    keytypestr = "D";
  else if (keytype == PRIVATE_KEY_SHADOWED)
    keytypestr = "T";
  else
    keytypestr = "-";

  /* Compute the ssh fingerprint if requested.  */
  if (with_ssh_fpr)
    {
      gcry_sexp_t key;

      if (!agent_raw_key_from_file (ctrl, grip, &key))
        {
          ssh_get_fingerprint_string (key, &fpr);
          gcry_sexp_release (key);
        }
    }

  if (shadow_info)
    {
      err = parse_shadow_info (shadow_info, &serialno, &idstr);
      if (err)
        goto leave;
    }

  /* Note that we don't support the CACHED and PROTECTION values as
     gnupg 2.1 does.  We print '-' instead.  However we support the
     ssh fingerprint.  */
  if (!data)
    err = agent_write_status (ctrl, "KEYINFO",
                              hexgrip,
                              keytypestr,
                              serialno? serialno : "-",
                              idstr? idstr : "-",
                              "-",
			      "-",
                              fpr? fpr : "-",
                              NULL);
  else
    {
      char *string;

      string = xtryasprintf ("%s %s %s %s - - %s\n",
                             hexgrip, keytypestr,
                             serialno? serialno : "-",
                             idstr? idstr : "-",
                             fpr? fpr : "-");
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


static gpg_error_t
cmd_keyinfo (assuan_context_t ctx, char *line)
{
  ctrl_t ctrl = assuan_get_pointer (ctx);
  int err;
  unsigned char grip[20];
  DIR *dir = NULL;
  int list_mode;
  int opt_data, opt_ssh_fpr;

  list_mode = has_option (line, "--list");
  opt_data = has_option (line, "--data");
  opt_ssh_fpr = has_option (line, "--ssh-fpr");
  line = skip_options (line);

  if (list_mode)
    {
      char *dirname;
      struct dirent *dir_entry;
      char hexgrip[41];

      dirname = make_filename_try (opt.homedir, GNUPG_PRIVATE_KEYS_DIR, NULL);
      if (!dirname)
        {
          err = gpg_error_from_syserror ();
          goto leave;
        }
      dir = opendir (dirname);
      if (!dir)
        {
          err = gpg_error_from_syserror ();
          xfree (dirname);
          goto leave;
        }
      xfree (dirname);

      while ( (dir_entry = readdir (dir)) )
        {
          if (strlen (dir_entry->d_name) != 44
              || strcmp (dir_entry->d_name + 40, ".key"))
            continue;
          strncpy (hexgrip, dir_entry->d_name, 40);
          hexgrip[40] = 0;

          if ( hex2bin (hexgrip, grip, 20) < 0 )
            continue; /* Bad hex string.  */

          err = do_one_keyinfo (ctrl, grip, ctx, opt_data, opt_ssh_fpr);
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
      err = do_one_keyinfo (ctrl, grip, ctx, opt_data, opt_ssh_fpr);
    }

 leave:
  if (dir)
    closedir (dir);
  if (err && gpg_err_code (err) != GPG_ERR_NOT_FOUND)
    log_error ("command keyinfo failed: %s\n", gpg_strerror (err));
  return err;
}



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


static const char hlp_get_passphrase[] =
  "GET_PASSPHRASE [--data] [--check] [--no-ask] [--repeat[=N]]\n"
  "               [--qualitybar] <cache_id>\n"
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
  "If the option \"--qualitybar\" is used a visual indication of the\n"
  "entered passphrase quality is shown.  (Unless no minimum passphrase\n"
  "length has been configured.)";
static gpg_error_t
cmd_get_passphrase (assuan_context_t ctx, char *line)
{
  ctrl_t ctrl = assuan_get_pointer (ctx);
  int rc;
  const char *pw;
  char *response;
  char *cacheid = NULL, *desc = NULL, *prompt = NULL, *errtext = NULL;
  const char *desc2 = _("Please re-enter this passphrase");
  char *p;
  void *cache_marker;
  int opt_data, opt_check, opt_no_ask, opt_qualbar;
  int opt_repeat = 0;
  char *repeat_errtext = NULL;

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
  if (!cacheid || !*cacheid || strlen (cacheid) > 50)
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

  pw = cacheid ? agent_get_cache (cacheid, CACHE_MODE_NORMAL, &cache_marker)
               : NULL;
  if (pw)
    {
      rc = send_back_passphrase (ctx, opt_data, pw);
      agent_unlock_cache_entry (&cache_marker);
    }
  else if (opt_no_ask)
    rc = gpg_error (GPG_ERR_NO_DATA);
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

    next_try:
      rc = agent_get_passphrase (ctrl, &response, desc, prompt,
                                 repeat_errtext? repeat_errtext:errtext,
                                 opt_qualbar);
      xfree (repeat_errtext);
      repeat_errtext = NULL;
      if (!rc)
        {
          int i;

          if (opt_check && check_passphrase_constraints (ctrl, response, 0))
            {
              xfree (response);
              goto next_try;
            }
          for (i = 0; i < opt_repeat; i++)
            {
              char *response2;

              rc = agent_get_passphrase (ctrl, &response2, desc2, prompt,
                                         errtext, 0);
              if (rc)
                break;
              if (strcmp (response2, response))
                {
                  xfree (response2);
                  xfree (response);
                  repeat_errtext = try_percent_escape
                    (_("does not match - try again"), NULL);
                  if (!repeat_errtext)
                    {
                      rc = gpg_error_from_syserror ();
                      break;
                    }
                  goto next_try;
                }
              xfree (response2);
            }
          if (!rc)
            {
              if (cacheid)
                agent_put_cache (cacheid, CACHE_MODE_USER, response, 0);
              rc = send_back_passphrase (ctx, opt_data, response);
            }
          xfree (response);
        }
    }

  if (rc)
    log_error ("command get_passphrase failed: %s\n", gpg_strerror (rc));
  return rc;
}


static const char hlp_clear_passphrase[] =
  "CLEAR_PASSPHRASE <cache_id>\n"
  "\n"
  "may be used to invalidate the cache entry for a passphrase.  The\n"
  "function returns with OK even when there is no cached passphrase.";
static gpg_error_t
cmd_clear_passphrase (assuan_context_t ctx, char *line)
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
    return set_error (GPG_ERR_ASS_PARAMETER, "invalid length of cacheID");

  agent_put_cache (cacheid, CACHE_MODE_USER, NULL, 0);
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

  /* parse the stuff */
  for (p=line; *p == ' '; p++)
    ;
  desc = p;
  p = strchr (desc, ' ');
  if (p)
    *p = 0; /* We ignore any garbage -may be later used for other args. */

  if (!desc || !*desc)
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
  if (rc)
    log_error ("command get_confirmation failed: %s\n", gpg_strerror (rc));
  return rc;
}



static const char hlp_learn[] =
  "LEARN [--send]\n"
  "\n"
  "Learn something about the currently inserted smartcard.  With\n"
  "--send the new certificates are send back.";
static gpg_error_t
cmd_learn (assuan_context_t ctx, char *line)
{
  ctrl_t ctrl = assuan_get_pointer (ctx);
  int rc;

  rc = agent_handle_learn (ctrl, has_option (line, "--send")? ctx : NULL);
  if (rc)
    log_error ("command learn failed: %s\n", gpg_strerror (rc));
  return rc;
}



static const char hlp_passwd[] =
  "PASSWD <hexstring_with_keygrip>\n"
  "\n"
  "Change the passphrase/PIN for the key identified by keygrip in LINE.";
static gpg_error_t
cmd_passwd (assuan_context_t ctx, char *line)
{
  ctrl_t ctrl = assuan_get_pointer (ctx);
  int rc;
  unsigned char grip[20];
  gcry_sexp_t s_skey = NULL;
  unsigned char *shadow_info = NULL;

  rc = parse_keygrip (ctx, line, grip);
  if (rc)
    goto leave;

  ctrl->in_passwd++;
  rc = agent_key_from_file (ctrl, ctrl->server_local->keydesc,
                            grip, &shadow_info, CACHE_MODE_IGNORE, NULL,
                            &s_skey);
  if (rc)
    ;
  else if (!s_skey)
    {
      log_error ("changing a smartcard PIN is not yet supported\n");
      rc = gpg_error (GPG_ERR_NOT_IMPLEMENTED);
    }
  else
    rc = agent_protect_and_store (ctrl, s_skey);
  ctrl->in_passwd--;

  xfree (ctrl->server_local->keydesc);
  ctrl->server_local->keydesc = NULL;

 leave:
  gcry_sexp_release (s_skey);
  xfree (shadow_info);
  if (rc)
    log_error ("command passwd failed: %s\n", gpg_strerror (rc));
  return rc;
}


static const char hlp_preset_passphrase[] =
  "PRESET_PASSPHRASE <string_or_keygrip> <timeout> <hexstring>\n"
  "\n"
  "Set the cached passphrase/PIN for the key identified by the keygrip\n"
  "to passwd for the given time, where -1 means infinite and 0 means\n"
  "the default (currently only a timeout of -1 is allowed, which means\n"
  "to never expire it).  If passwd is not provided, ask for it via the\n"
  "pinentry module.";
static gpg_error_t
cmd_preset_passphrase (assuan_context_t ctx, char *line)
{
  int rc;
  char *grip_clear = NULL;
  char *passphrase = NULL;
  int ttl;
  size_t len;

  if (!opt.allow_preset_passphrase)
    return set_error (GPG_ERR_NOT_SUPPORTED, "no --allow-preset-passphrase");

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
      /* Do in-place conversion.  */
      passphrase = line;
      if (!hex2str (passphrase, passphrase, strlen (passphrase)+1, NULL))
        rc = set_error (GPG_ERR_ASS_PARAMETER, "invalid hexstring");
    }
  else
    rc = set_error (GPG_ERR_NOT_IMPLEMENTED, "passphrase is required");

  if (!rc)
    rc = agent_put_cache (grip_clear, CACHE_MODE_ANY, passphrase, ttl);

  if (rc)
    log_error ("command preset_passphrase failed: %s\n", gpg_strerror (rc));

  return rc;
}



static const char hlp_scd[] =
  "SCD <commands to pass to the scdaemon>\n"
  " \n"
  "This is a general quote command to redirect everything to the\n"
  "SCdaemon.";
static gpg_error_t
cmd_scd (assuan_context_t ctx, char *line)
{
  ctrl_t ctrl = assuan_get_pointer (ctx);
  int rc;

  rc = divert_generic_cmd (ctrl, line, ctx);

  return rc;
}



static const char hlp_getval[] =
  "GETVAL <key>\n"
  "\n"
  "Return the value for KEY from the special environment as created by\n"
  "PUTVAL.";
static gpg_error_t
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
        return set_error (GPG_ERR_ASS_PARAMETER, "too many arguments");
    }
  if (!key || !*key)
    return set_error (GPG_ERR_ASS_PARAMETER, "no key given");


  for (vl=putval_list; vl; vl = vl->next)
    if ( !strcmp (vl->d, key) )
      break;

  if (vl) /* Got an entry. */
    rc = assuan_send_data (ctx, vl->d+vl->off, vl->len);
  else
    return gpg_error (GPG_ERR_NO_DATA);

  if (rc)
    log_error ("command getval failed: %s\n", gpg_strerror (rc));
  return rc;
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
  "KEY is an an arbitrary symbol with the same syntax rules as keys\n"
  "for shell environment variables.  PERCENT_ESCAPED_VALUE is the\n"
  "corresponsing value; they should be similar to the values of\n"
  "envronment variables but gpg-agent does not enforce any\n"
  "restrictions.  If that value is not given any value under that KEY\n"
  "is removed from this special environment.";
static gpg_error_t
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
          valuelen = percent_plus_unescape_inplace (value, 0);
        }
    }
  if (!key || !*key)
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

  if (rc)
    log_error ("command putval failed: %s\n", gpg_strerror (rc));
  return rc;
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
  static const char *names[] =
    { "GPG_TTY", "DISPLAY", "TERM", "XAUTHORITY", "PINENTRY_USER_DATA", NULL };
  ctrl_t ctrl = assuan_get_pointer (ctx);
  gpg_error_t err = 0;
  session_env_t se;
  int idx;
  char *lc_ctype = NULL;
  char *lc_messages = NULL;

  (void)line;

  se = session_env_new ();
  if (!se)
    err = gpg_error_from_syserror ();

  for (idx=0; !err && names[idx]; idx++)
    {
      const char *value = session_env_getenv (ctrl->session_env, names[idx]);
      if (value)
        err = session_env_setenv (se, names[idx], value);
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
  "If the agent has been started using a standard socket\n"
  "we allow a client to stop the agent.";
static gpg_error_t
cmd_killagent (assuan_context_t ctx, char *line)
{
  ctrl_t ctrl = assuan_get_pointer (ctx);

  (void)line;

  if (!opt.use_standard_socket)
    return set_error (GPG_ERR_NOT_SUPPORTED, "no --use-standard-socket");

  ctrl->server_local->stopme = 1;
  return gpg_error (GPG_ERR_EOF);
}


static const char hlp_reloadagent[] =
  "RELOADAGENT\n"
  "\n"
  "This command is an alternative to SIGHUP\n"
  "to reload the configuration.";
static gpg_error_t
cmd_reloadagent (assuan_context_t ctx, char *line)
{
  (void)ctx;
  (void)line;

  agent_sighup_action ();
  return 0;
}



static const char hlp_getinfo[] =
  "GETINFO <what>\n"
  "\n"
  "Multipurpose function to return a variety of information.\n"
  "Supported values for WHAT are:\n"
  "\n"
  "  version     - Return the version of the program.\n"
  "  pid         - Return the process id of the server.\n"
  "  socket_name - Return the name of the socket.\n"
  "  ssh_socket_name - Return the name of the ssh socket.\n"
  "  scd_running - Return OK if the SCdaemon is already running.\n"
  "  std_session_env - List the standard session environment.\n"
  "  std_startup_env - List the standard startup environment.\n"
  "  cmd_has_option\n"
  "              - Returns OK if the command CMD implements the option OPT.";
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
      rc = agent_scd_check_running ()? 0 : gpg_error (GPG_ERR_GENERAL);
    }
  else if (!strcmp (line, "s2k_count"))
    {
      char numbuf[50];

      snprintf (numbuf, sizeof numbuf, "%lu", get_standard_s2k_count ());
      rc = assuan_send_data (ctx, numbuf, strlen (numbuf));
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
                    rc = gpg_error (GPG_ERR_GENERAL);
                }
            }
        }
    }
  else
    rc = set_error (GPG_ERR_ASS_PARAMETER, "unknown value for WHAT");
  return rc;
}



static gpg_error_t
option_handler (assuan_context_t ctx, const char *key, const char *value)
{
  ctrl_t ctrl = assuan_get_pointer (ctx);
  gpg_error_t err = 0;

  if (!strcmp (key, "putenv"))
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
    ctrl->server_local->use_cache_for_signing = *value? atoi (value) : 0;
  else if (!strcmp (key, "allow-pinentry-notify"))
    ctrl->server_local->allow_pinentry_notify = 1;
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

  /* Note that we only check for the uppercase name.  This allows to
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
    }

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
    { "GETVAL",         cmd_getval,    hlp_getval },
    { "PUTVAL",         cmd_putval,    hlp_putval },
    { "UPDATESTARTUPTTY",  cmd_updatestartuptty, hlp_updatestartuptty },
    { "KILLAGENT",      cmd_killagent,  hlp_killagent },
    { "RELOADAGENT",    cmd_reloadagent,hlp_reloadagent },
    { "GETINFO",        cmd_getinfo,   hlp_getinfo },
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
   intialization. */
void
start_command_handler (ctrl_t ctrl, gnupg_fd_t listen_fd, gnupg_fd_t fd)
{
  int rc;
  assuan_context_t ctx = NULL;

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
  ctrl->server_local->message_fd = -1;
  ctrl->server_local->use_cache_for_signing = 1;
  ctrl->digest.raw_value = 0;

  assuan_set_io_monitor (ctx, io_monitor, NULL);

  for (;;)
    {
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

      rc = assuan_process (ctx);
      if (rc)
        {
          log_info ("Assuan processing failed: %s\n", gpg_strerror (rc));
          continue;
        }
    }

  /* Reset the SCD if needed. */
  agent_reset_scd (ctrl);

  /* Reset the pinentry (in case of popup messages). */
  agent_reset_query (ctrl);

  /* Cleanup.  */
  assuan_release (ctx);
  if (ctrl->server_local->stopme)
    agent_exit (0);
  xfree (ctrl->server_local);
  ctrl->server_local = NULL;
}

