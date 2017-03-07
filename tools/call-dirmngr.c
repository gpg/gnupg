/* call-dirmngr.c - Interact with the Dirmngr.
 * Copyright (C) 2016 g10 Code GmbH
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
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <time.h>
#ifdef HAVE_LOCALE_H
# include <locale.h>
#endif

#include <assuan.h>
#include "../common/util.h"
#include "../common/i18n.h"
#include "../common/asshelp.h"
#include "../common/mbox-util.h"
#include "./call-dirmngr.h"

static struct
{
  int verbose;
  int debug_ipc;
  int autostart;
} opt;



void
set_dirmngr_options (int verbose, int debug_ipc, int autostart)
{
  opt.verbose = verbose;
  opt.debug_ipc = debug_ipc;
  opt.autostart = autostart;
}


/* Connect to the Dirmngr and return an assuan context.  */
static gpg_error_t
connect_dirmngr (assuan_context_t *r_ctx)
{
  gpg_error_t err;
  assuan_context_t ctx;

  *r_ctx = NULL;
  err = start_new_dirmngr (&ctx,
                           GPG_ERR_SOURCE_DEFAULT,
                           NULL,
                           opt.autostart, opt.verbose, opt.debug_ipc,
                           NULL, NULL);
  if (!opt.autostart && gpg_err_code (err) == GPG_ERR_NO_DIRMNGR)
    {
      static int shown;

      if (!shown)
        {
          shown = 1;
          log_info (_("no dirmngr running in this session\n"));
        }
    }

  if (err)
    assuan_release (ctx);
  else
    {
      *r_ctx = ctx;
    }

  return err;
}




/* Parameter structure used with the WKD_GET command.  */
struct wkd_get_parm_s
{
  estream_t memfp;
};


/* Data callback for the WKD_GET command. */
static gpg_error_t
wkd_get_data_cb (void *opaque, const void *data, size_t datalen)
{
  struct wkd_get_parm_s *parm = opaque;
  gpg_error_t err = 0;
  size_t nwritten;

  if (!data)
    return 0;  /* Ignore END commands.  */
  if (!parm->memfp)
    return 0;  /* Data is not required.  */

  if (es_write (parm->memfp, data, datalen, &nwritten))
    err = gpg_error_from_syserror ();

  return err;
}


/* Status callback for the WKD_GET command.  */
static gpg_error_t
wkd_get_status_cb (void *opaque, const char *line)
{
  struct wkd_get_parm_s *parm = opaque;
  gpg_error_t err = 0;

  (void)line;
  (void)parm;

  return err;
}


/* Ask the dirmngr for the submission address of a WKD server for the
 * mail address ADDRSPEC.  On success the submission address is stored
 * at R_ADDRSPEC.  */
gpg_error_t
wkd_get_submission_address (const char *addrspec, char **r_addrspec)
{
  gpg_error_t err;
  assuan_context_t ctx;
  struct wkd_get_parm_s parm;
  char *line = NULL;
  void *vp;
  char *buffer = NULL;
  char *p;

  memset (&parm, 0, sizeof parm);
  *r_addrspec = NULL;

  err = connect_dirmngr (&ctx);
  if (err)
    return err;

  line = es_bsprintf ("WKD_GET --submission-address -- %s", addrspec);
  if (!line)
    {
      err = gpg_error_from_syserror ();
      goto leave;
    }
  if (strlen (line) + 2 >= ASSUAN_LINELENGTH)
    {
      err = gpg_error (GPG_ERR_TOO_LARGE);
      goto leave;
    }

  parm.memfp = es_fopenmem (0, "rwb");
  if (!parm.memfp)
    {
      err = gpg_error_from_syserror ();
      goto leave;
    }
  err = assuan_transact (ctx, line, wkd_get_data_cb, &parm,
                         NULL, NULL, wkd_get_status_cb, &parm);
  if (err)
    goto leave;

  es_fputc (0, parm.memfp);
  if (es_fclose_snatch (parm.memfp, &vp, NULL))
    {
      err = gpg_error_from_syserror ();
      goto leave;
    }
  buffer = vp;
  parm.memfp = NULL;
  p = strchr (buffer, '\n');
  if (p)
    *p = 0;
  trim_spaces (buffer);
  if (!is_valid_mailbox (buffer))
    {
      err = gpg_error (GPG_ERR_INV_USER_ID);
      goto leave;
    }
  *r_addrspec = xtrystrdup (buffer);
  if (!*r_addrspec)
    err = gpg_error_from_syserror ();

 leave:
  es_free (buffer);
  es_fclose (parm.memfp);
  xfree (line);
  assuan_release (ctx);
  return err;
}


/* Ask the dirmngr for the policy flags and return them as an estream
 * memory stream.  If no policy flags are set, NULL is stored at
 * R_BUFFER.  */
gpg_error_t
wkd_get_policy_flags (const char *addrspec, estream_t *r_buffer)
{
  gpg_error_t err;
  assuan_context_t ctx;
  struct wkd_get_parm_s parm;
  char *line = NULL;
  char *buffer = NULL;

  memset (&parm, 0, sizeof parm);
  *r_buffer = NULL;

  err = connect_dirmngr (&ctx);
  if (err)
    return err;

  line = es_bsprintf ("WKD_GET --policy-flags -- %s", addrspec);
  if (!line)
    {
      err = gpg_error_from_syserror ();
      goto leave;
    }
  if (strlen (line) + 2 >= ASSUAN_LINELENGTH)
    {
      err = gpg_error (GPG_ERR_TOO_LARGE);
      goto leave;
    }

  parm.memfp = es_fopenmem (0, "rwb");
  if (!parm.memfp)
    {
      err = gpg_error_from_syserror ();
      goto leave;
    }
  err = assuan_transact (ctx, line, wkd_get_data_cb, &parm,
                         NULL, NULL, wkd_get_status_cb, &parm);
  if (err)
    goto leave;

  es_rewind (parm.memfp);
  *r_buffer = parm.memfp;
  parm.memfp = 0;

 leave:
  es_free (buffer);
  es_fclose (parm.memfp);
  xfree (line);
  assuan_release (ctx);
  return err;
}


/* Ask the dirmngr for the key for ADDRSPEC.  On success a stream with
 * the key is stored at R_KEY.  */
gpg_error_t
wkd_get_key (const char *addrspec, estream_t *r_key)
{
  gpg_error_t err;
  assuan_context_t ctx;
  struct wkd_get_parm_s parm;
  char *line = NULL;

  memset (&parm, 0, sizeof parm);
  *r_key = NULL;

  err = connect_dirmngr (&ctx);
  if (err)
    return err;

  line = es_bsprintf ("WKD_GET -- %s", addrspec);
  if (!line)
    {
      err = gpg_error_from_syserror ();
      goto leave;
    }
  if (strlen (line) + 2 >= ASSUAN_LINELENGTH)
    {
      err = gpg_error (GPG_ERR_TOO_LARGE);
      goto leave;
    }

  parm.memfp = es_fopenmem (0, "rwb");
  if (!parm.memfp)
    {
      err = gpg_error_from_syserror ();
      goto leave;
    }
  err = assuan_transact (ctx, line, wkd_get_data_cb, &parm,
                         NULL, NULL, wkd_get_status_cb, &parm);
  if (err)
    goto leave;

  es_rewind (parm.memfp);
  *r_key = parm.memfp;
  parm.memfp = NULL;

 leave:
  es_fclose (parm.memfp);
  xfree (line);
  assuan_release (ctx);
  return err;
}
