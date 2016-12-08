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
 * along with this program; if not, see <https://www.gnu.org/licenses/>.
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


/* Parse the policy flags by reading them from STREAM and storing them
 * into FLAGS.  If IGNORE_UNKNOWN is iset unknown keywords are
 * ignored.  */
gpg_error_t
wks_parse_policy (policy_flags_t flags, estream_t stream, int ignore_unknown)
{
  enum tokens {
    TOK_MAILBOX_ONLY,
    TOK_DANE_ONLY,
    TOK_AUTH_SUBMIT,
    TOK_MAX_PENDING
  };
  static struct {
    const char *name;
    enum tokens token;
  } keywords[] = {
    { "mailbox-only", TOK_MAILBOX_ONLY },
    { "dane-only",    TOK_DANE_ONLY    },
    { "auth-submit",  TOK_AUTH_SUBMIT  },
    { "max-pending",  TOK_MAX_PENDING  }
  };
  gpg_error_t err = 0;
  int lnr = 0;
  char line[1024];
  char *p, *keyword, *value;
  int i, n;

  memset (flags, 0, sizeof *flags);

  while (es_fgets (line, DIM(line)-1, stream) )
    {
      lnr++;
      n = strlen (line);
      if (!n || line[n-1] != '\n')
        {
          err = gpg_error (*line? GPG_ERR_LINE_TOO_LONG
                           : GPG_ERR_INCOMPLETE_LINE);
          break;
        }
      trim_trailing_spaces (line);
      /* Skip empty and comment lines. */
      for (p=line; spacep (p); p++)
        ;
      if (!*p || *p == '#')
        continue;

      if (*p == ':')
        {
          err = gpg_error (GPG_ERR_SYNTAX);
          break;
        }

      keyword = p;
      value = NULL;
      if ((p = strchr (p, ':')))
        {
          /* Colon found: Keyword with value.  */
          *p++ = 0;
          for (; spacep (p); p++)
            ;
          if (!*p)
            {
              err = gpg_error (GPG_ERR_MISSING_VALUE);
              break;
            }
          value = p;
        }

      for (i=0; i < DIM (keywords); i++)
        if (!ascii_strcasecmp (keywords[i].name, keyword))
          break;
      if (!(i < DIM (keywords)))
        {
          if (ignore_unknown)
            continue;
          err = gpg_error (GPG_ERR_INV_NAME);
          break;
	}

      switch (keywords[i].token)
        {
        case TOK_MAILBOX_ONLY: flags->mailbox_only = 1; break;
        case TOK_DANE_ONLY:    flags->dane_only = 1;    break;
        case TOK_AUTH_SUBMIT:  flags->auth_submit = 1;  break;
        case TOK_MAX_PENDING:
          if (!value)
            {
              err = gpg_error (GPG_ERR_SYNTAX);
              goto leave;
            }
          /* FIXME: Define whether these are seconds, hours, or days
           * and decide whether to allow other units.  */
          flags->max_pending = atoi (value);
          break;
        }
    }

  if (!err && !es_feof (stream))
    err = gpg_error_from_syserror ();

 leave:
  if (err)
    log_error ("error reading '%s', line %d: %s\n",
               es_fname_get (stream), lnr, gpg_strerror (err));

  return err;
}
