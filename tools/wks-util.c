/* wks-utils.c - Common helper fucntions for wks tools
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
 * along with this program; if not, see <http://www.gnu.org/licenses/>.
 */

#include <config.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "util.h"
#include "mime-maker.h"
#include "send-mail.h"
#include "gpg-wks.h"


/* Helper to write mail to the output(s).  */
gpg_error_t
wks_send_mime (mime_maker_t mime)
{
  gpg_error_t err;
  estream_t mail;

  /* Without any option we take a short path.  */
  if (!opt.use_sendmail && !opt.output)
    return mime_maker_make (mime, es_stdout);

  mail = es_fopenmem (0, "w+b");
  if (!mail)
    {
      err = gpg_error_from_syserror ();
      return err;
    }

  err = mime_maker_make (mime, mail);

  if (!err && opt.output)
    {
      es_rewind (mail);
      err = send_mail_to_file (mail, opt.output);
    }

  if (!err && opt.use_sendmail)
    {
      es_rewind (mail);
      err = send_mail (mail);
    }

  es_fclose (mail);
  return err;
}
