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
inq_keydata (void *opaque, const char *line)
{
  struct inq_parm_s *parm = opaque;

  if (has_leading_keyword (line, "KEYDATA"))
    return assuan_send_data (parm->ctx, parm->keydata, parm->keydatalen);
  else
    return inq_needpin (opaque, line);
}

static gpg_error_t
inq_extra (void *opaque, const char *line)
{
  struct inq_parm_s *parm = opaque;

  if (has_leading_keyword (line, "EXTRA"))
    return assuan_send_data (parm->ctx, parm->extra, parm->extralen);
  else
    return inq_keydata (opaque, line);
}

static gpg_error_t
pin_cb (ctrl_t ctrl, const char *prompt, char **passphrase)
{
  char hexgrip[2*KEYGRIP_LEN + 1];

  bin2hex (ctrl->keygrip, KEYGRIP_LEN, hexgrip);
  *passphrase = agent_get_cache (ctrl, hexgrip, CACHE_MODE_USER);
  if (*passphrase)
    return 0;
  return agent_get_passphrase(ctrl, passphrase,
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

  *r_buf = NULL;
  if (r_buflen)
    *r_buflen = 0;

  rc = start_tkd (ctrl);
  if (rc)
    return rc;

  init_membuf (&data, 1024);
  snprintf (line, DIM(line), "READKEY %s", keygrip);
  rc = assuan_transact (daemon_ctx (ctrl), line,
                        put_membuf_cb, &data,
                        NULL, NULL, NULL, NULL);
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


int
agent_tkd_pksign (ctrl_t ctrl, const char *keygrip,
                  const unsigned char *digest, size_t digestlen,
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
  inqparm.ctrl = ctrl;
  // inqparm.keydata = shadow_info;
  // inqparm.keydatalen = gcry_sexp_canon_len (shadow_info, 0, NULL, NULL);
  inqparm.extra = digest;
  inqparm.extralen = digestlen;
  inqparm.pin = NULL;

  snprintf (line, sizeof(line), "PKSIGN %s", keygrip);

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
