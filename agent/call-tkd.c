/* call-tkd.c - fork of the tkdaemon to do TK operations
 * Copyright (C) 2001, 2002, 2005, 2007, 2010,
 *               2011 Free Software Foundation, Inc.
 * Copyright (C) 2013 Werner Koch
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
#include <assert.h>
#include <unistd.h>

#include "agent.h"
#include <assuan.h>
#include "../common/strlist.h"
#include "../common/sexp-parse.h"
#include "../common/i18n.h"

static int
start_tkd (ctrl_t ctrl)
{
  return daemon_start (DAEMON_TKD, ctrl);
}

static int
unlock_tkd (ctrl_t ctrl, gpg_error_t err)
{
  return daemon_unlock (DAEMON_TKD, ctrl, err);
}

static assuan_context_t
daemon_ctx (ctrl_t ctrl)
{
  return daemon_type_ctx (DAEMON_TKD, ctrl);
}

struct inq_parm_s {
  assuan_context_t ctx;
  gpg_error_t (*getpin_cb)(ctrl_t, const char *, char **);
  ctrl_t ctrl;
  /* The next fields are used by inq_keydata.  */
  const unsigned char *keydata;
  size_t keydatalen;
  /* following only used by inq_extra */
  const unsigned char *extra;
  size_t extralen;
  char *pin;
};

static gpg_error_t
inq_needpin (void *opaque, const char *line)
{
  struct inq_parm_s *parm = opaque;
  char *pin = NULL;
  gpg_error_t rc;
  const char *s;

  if ((s = has_leading_keyword (line, "NEEDPIN")))
    {
      rc = parm->getpin_cb (parm->ctrl, s, &pin);
      if (!rc)
        rc = assuan_send_data (parm->ctx, pin, strlen(pin));
      parm->pin = pin;
    }
  else
    {
      log_error ("unsupported inquiry '%s'\n", line);
      rc = gpg_error (GPG_ERR_ASS_UNKNOWN_INQUIRE);
    }

  return rc;
}

static gpg_error_t
inq_extra (void *opaque, const char *line)
{
  struct inq_parm_s *parm = opaque;

  if (has_leading_keyword (line, "EXTRA"))
    return assuan_send_data (parm->ctx, parm->extra, parm->extralen);
  else
    return inq_needpin (opaque, line);
}

static gpg_error_t
pin_cb (ctrl_t ctrl, const char *prompt, char **passphrase)
{
  char hexgrip[2*KEYGRIP_LEN + 1];

  bin2hex (ctrl->keygrip, KEYGRIP_LEN, hexgrip);
  *passphrase = agent_get_cache (ctrl, hexgrip, CACHE_MODE_USER);
  if (*passphrase)
    return 0;
  return agent_get_passphrase (ctrl, passphrase,
                               _("Please enter your passphrase, so that the "
                                 "secret key can be unlocked for this session"),
                               prompt, NULL, 0,
                               hexgrip, CACHE_MODE_USER, NULL);
}

/* Read a key with KEYGRIP and return it in a malloced buffer pointed
 * to by R_BUF as a valid S-expression.  If R_BUFLEN is not NULL the
 * length is stored there. */
int
agent_tkd_readkey (ctrl_t ctrl, const char *keygrip,
                   unsigned char **r_buf, size_t *r_buflen)
{
  int rc;
  char line[ASSUAN_LINELENGTH];
  membuf_t data;
  size_t buflen;
  struct inq_parm_s inqparm;

  *r_buf = NULL;
  if (r_buflen)
    *r_buflen = 0;

  rc = start_tkd (ctrl);
  if (rc)
    return rc;

  init_membuf (&data, 1024);

  inqparm.ctx = daemon_ctx (ctrl);
  inqparm.getpin_cb = pin_cb;
  inqparm.ctrl = ctrl;
  inqparm.pin = NULL;

  snprintf (line, DIM(line), "READKEY %s", keygrip);
  rc = assuan_transact (daemon_ctx (ctrl), line,
                        put_membuf_cb, &data,
                        inq_needpin, &inqparm,
                        NULL, NULL);
  if (rc)
    {
      xfree (get_membuf (&data, &buflen));
      return unlock_tkd (ctrl, rc);
    }
  *r_buf = get_membuf (&data, &buflen);
  if (!*r_buf)
    return unlock_tkd (ctrl, gpg_error (GPG_ERR_ENOMEM));

  if (!gcry_sexp_canon_len (*r_buf, buflen, NULL, NULL))
    {
      xfree (*r_buf); *r_buf = NULL;
      return unlock_tkd (ctrl, gpg_error (GPG_ERR_INV_VALUE));
    }
  if (r_buflen)
    *r_buflen = buflen;

  return unlock_tkd (ctrl, 0);
}


/* Helper returning a command option to describe the used hash
   algorithm.  See scd/command.c:cmd_pksign.  */
static const char *
hash_algo_option (int algo)
{
  switch (algo)
    {
    case GCRY_MD_MD5   : return "--hash=md5";
    case GCRY_MD_RMD160: return "--hash=rmd160";
    case GCRY_MD_SHA1  : return "--hash=sha1";
    case GCRY_MD_SHA224: return "--hash=sha224";
    case GCRY_MD_SHA256: return "--hash=sha256";
    case GCRY_MD_SHA384: return "--hash=sha384";
    case GCRY_MD_SHA512: return "--hash=sha512";
    default:             return "";
    }
}


int
agent_tkd_pksign (ctrl_t ctrl, const unsigned char *digest, size_t digestlen,
                  unsigned char **r_sig, size_t *r_siglen)
{
  int rc;
  char line[ASSUAN_LINELENGTH];
  membuf_t data;
  struct inq_parm_s inqparm;
  char hexgrip[2*KEYGRIP_LEN + 1];

  rc = start_tkd (ctrl);
  if (rc)
    return rc;

  init_membuf (&data, 1024);

  inqparm.ctx = daemon_ctx (ctrl);
  inqparm.getpin_cb = pin_cb;
  inqparm.pin = NULL;
  inqparm.ctrl = ctrl;
  inqparm.extra = digest;
  inqparm.extralen = digestlen;

  bin2hex (ctrl->keygrip, KEYGRIP_LEN, hexgrip);
  snprintf (line, sizeof(line), "PKSIGN %s %s",
            hash_algo_option (ctrl->digest.algo), hexgrip);

  rc = assuan_transact (daemon_ctx (ctrl), line,
			put_membuf_cb, &data,
			inq_extra, &inqparm,
			NULL, NULL);
  if (!rc)
    {
      bin2hex (ctrl->keygrip, KEYGRIP_LEN, hexgrip);
      agent_put_cache (ctrl, hexgrip, CACHE_MODE_USER, inqparm.pin, 0);
    }

  xfree (inqparm.pin);

  if (rc)
    {
      size_t len;
      xfree (get_membuf (&data, &len));
      return unlock_tkd (ctrl, rc);
    }

  *r_sig = get_membuf (&data, r_siglen);

  return unlock_tkd (ctrl, 0);
}

/* This handler is a helper for pincache_put_cb but may also be called
 * directly for that status code with ARGS being the arguments after
 * the status keyword (and with white space removed).  */
static gpg_error_t
handle_pincache_put (const char *args)
{
  gpg_error_t err;
  const char *s, *key, *pin;
  char *keybuf = NULL;
  size_t keylen;

  key = s = args;
  while (*s && !spacep (s))
    s++;
  keylen = s - key;
  if (keylen < 3)
    {
      /* At least we need 2 slashes and slot number.  */
      log_error ("%s: ignoring invalid key\n", __func__);
      err = 0;
      goto leave;
    }

  keybuf = xtrymalloc (keylen+1);
  if (!keybuf)
    {
      err = gpg_error_from_syserror ();
      goto leave;
    }
  memcpy (keybuf, key, keylen);
  keybuf[keylen] = 0;
  key = keybuf;

  while (spacep (s))
    s++;
  pin = s;
  if (!*pin)
    {
      /* No value - flush the cache.  The cache module knows aboput
       * the structure of the key to flush only parts.  */
      log_debug ("%s: flushing cache '%s'\n", __func__, key);
      agent_put_cache (NULL, key, CACHE_MODE_PIN, NULL, -1);
      err = 0;
      goto leave;
    }

  log_debug ("%s: caching '%s'->'%s'\n", __func__, key, pin);
  agent_put_cache (NULL, key, CACHE_MODE_PIN, pin, -1);
  err = 0;

 leave:
  xfree (keybuf);
  return err;
}

static gpg_error_t
pass_status_thru (void *opaque, const char *line)
{
  gpg_error_t err = 0;
  assuan_context_t ctx = opaque;
  char keyword[200];
  int i;

  if (line[0] == '#' && (!line[1] || spacep (line+1)))
    {
      /* We are called in convey comments mode.  Now, if we see a
         comment marker as keyword we forward the line verbatim to the
         the caller.  This way the comment lines from scdaemon won't
         appear as status lines with keyword '#'.  */
      assuan_write_line (ctx, line);
    }
  else
    {
      for (i=0; *line && !spacep (line) && i < DIM(keyword)-1; line++, i++)
        keyword[i] = *line;
      keyword[i] = 0;

      /* Truncate any remaining keyword stuff.  */
      for (; *line && !spacep (line); line++)
        ;
      while (spacep (line))
        line++;

      /* We do not want to pass PINCACHE_PUT through.  */
      if (!strcmp (keyword, "PINCACHE_PUT"))
        err = handle_pincache_put (line);
      else
        assuan_write_status (ctx, keyword, line);
    }
  return err;
}

static gpg_error_t
pass_data_thru (void *opaque, const void *buffer, size_t length)
{
  assuan_context_t ctx = opaque;

  assuan_send_data (ctx, buffer, length);
  return 0;
}

int
agent_tkd_cmd (ctrl_t ctrl, const char *cmdline)
{
  int rc;
  struct inq_parm_s inqparm;
  int saveflag;

  rc = start_tkd (ctrl);
  if (rc)
    return rc;

  inqparm.ctx = daemon_ctx (ctrl);
  inqparm.getpin_cb = pin_cb;
  inqparm.pin = NULL;

  saveflag = assuan_get_flag (daemon_ctx (ctrl), ASSUAN_CONVEY_COMMENTS);
  assuan_set_flag (daemon_ctx (ctrl), ASSUAN_CONVEY_COMMENTS, 1);
  rc = assuan_transact (daemon_ctx (ctrl), cmdline,
                        pass_data_thru, daemon_ctx (ctrl),
                        inq_needpin, &inqparm,
                        pass_status_thru, daemon_ctx (ctrl));

  assuan_set_flag (daemon_ctx (ctrl), ASSUAN_CONVEY_COMMENTS, saveflag);

  return unlock_tkd (ctrl, rc);
}
