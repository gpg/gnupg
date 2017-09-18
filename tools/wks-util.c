/* wks-utils.c - Common helper functions for wks tools
 * Copyright (C) 2016 g10 Code GmbH
 * Copyright (C) 2016 Bundesamt für Sicherheit in der Informationstechnik
 *
 * This file is part of GnuPG.
 *
 * This file is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as
 * published by the Free Software Foundation; either version 2.1 of
 * the License, or (at your option) any later version.
 *
 * This file is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Lesser General Public License for more details.
 */

#include <config.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "../common/util.h"
#include "../common/status.h"
#include "../common/ccparray.h"
#include "../common/exectool.h"
#include "../common/mbox-util.h"
#include "mime-maker.h"
#include "send-mail.h"
#include "gpg-wks.h"

/* The stream to output the status information.  Output is disabled if
   this is NULL.  */
static estream_t statusfp;



/* Set the status FD.  */
void
wks_set_status_fd (int fd)
{
  static int last_fd = -1;

  if (fd != -1 && last_fd == fd)
    return;

  if (statusfp && statusfp != es_stdout && statusfp != es_stderr)
    es_fclose (statusfp);
  statusfp = NULL;
  if (fd == -1)
    return;

  if (fd == 1)
    statusfp = es_stdout;
  else if (fd == 2)
    statusfp = es_stderr;
  else
    statusfp = es_fdopen (fd, "w");
  if (!statusfp)
    {
      log_fatal ("can't open fd %d for status output: %s\n",
                 fd, gpg_strerror (gpg_error_from_syserror ()));
    }
  last_fd = fd;
}


/* Write a status line with code NO followed by the outout of the
 * printf style FORMAT.  The caller needs to make sure that LFs and
 * CRs are not printed.  */
void
wks_write_status (int no, const char *format, ...)
{
  va_list arg_ptr;

  if (!statusfp)
    return;  /* Not enabled.  */

  es_fputs ("[GNUPG:] ", statusfp);
  es_fputs (get_status_string (no), statusfp);
  if (format)
    {
      es_putc (' ', statusfp);
      va_start (arg_ptr, format);
      es_vfprintf (statusfp, format, arg_ptr);
      va_end (arg_ptr);
    }
  es_putc ('\n', statusfp);
}




/* Append UID to LIST and return the new item.  On success LIST is
 * updated.  On error ERRNO is set and NULL returned. */
static uidinfo_list_t
append_to_uidinfo_list (uidinfo_list_t *list, const char *uid, time_t created)
{
  uidinfo_list_t r, sl;

  sl = xtrymalloc (sizeof *sl + strlen (uid));
  if (!sl)
    return NULL;

  strcpy (sl->uid, uid);
  sl->created = created;
  sl->mbox = mailbox_from_userid (uid);
  sl->next = NULL;
  if (!*list)
    *list = sl;
  else
    {
      for (r = *list; r->next; r = r->next )
        ;
      r->next = sl;
    }
  return sl;
}


/* Free the list of uid infos at LIST.  */
void
free_uidinfo_list (uidinfo_list_t list)
{
  while (list)
    {
      uidinfo_list_t tmp = list->next;
      xfree (list->mbox);
      xfree (list);
      list = tmp;
    }
}



/* Helper for wks_list_key and wks_filter_uid.  */
static void
key_status_cb (void *opaque, const char *keyword, char *args)
{
  (void)opaque;

  if (DBG_CRYPTO)
    log_debug ("gpg status: %s %s\n", keyword, args);
}


/* Run gpg on KEY and store the primary fingerprint at R_FPR and the
 * list of mailboxes at R_MBOXES.  Returns 0 on success; on error NULL
 * is stored at R_FPR and R_MBOXES and an error code is returned.
 * R_FPR may be NULL if the fingerprint is not needed.  */
gpg_error_t
wks_list_key (estream_t key, char **r_fpr, uidinfo_list_t *r_mboxes)
{
  gpg_error_t err;
  ccparray_t ccp;
  const char **argv;
  estream_t listing;
  char *line = NULL;
  size_t length_of_line = 0;
  size_t  maxlen;
  ssize_t len;
  char **fields = NULL;
  int nfields;
  int lnr;
  char *fpr = NULL;
  uidinfo_list_t mboxes = NULL;

  if (r_fpr)
    *r_fpr = NULL;
  *r_mboxes = NULL;

  /* Open a memory stream.  */
  listing = es_fopenmem (0, "w+b");
  if (!listing)
    {
      err = gpg_error_from_syserror ();
      log_error ("error allocating memory buffer: %s\n", gpg_strerror (err));
      return err;
    }

  ccparray_init (&ccp, 0);

  ccparray_put (&ccp, "--no-options");
  if (!opt.verbose)
    ccparray_put (&ccp, "--quiet");
  else if (opt.verbose > 1)
    ccparray_put (&ccp, "--verbose");
  ccparray_put (&ccp, "--batch");
  ccparray_put (&ccp, "--status-fd=2");
  ccparray_put (&ccp, "--always-trust");
  ccparray_put (&ccp, "--with-colons");
  ccparray_put (&ccp, "--dry-run");
  ccparray_put (&ccp, "--import-options=import-minimal,import-show");
  ccparray_put (&ccp, "--import");

  ccparray_put (&ccp, NULL);
  argv = ccparray_get (&ccp, NULL);
  if (!argv)
    {
      err = gpg_error_from_syserror ();
      goto leave;
    }
  err = gnupg_exec_tool_stream (opt.gpg_program, argv, key,
                                NULL, listing,
                                key_status_cb, NULL);
  if (err)
    {
      log_error ("import failed: %s\n", gpg_strerror (err));
      goto leave;
    }

  es_rewind (listing);
  lnr = 0;
  maxlen = 2048; /* Set limit.  */
  while ((len = es_read_line (listing, &line, &length_of_line, &maxlen)) > 0)
    {
      lnr++;
      if (!maxlen)
        {
          log_error ("received line too long\n");
          err = gpg_error (GPG_ERR_LINE_TOO_LONG);
          goto leave;
        }
      /* Strip newline and carriage return, if present.  */
      while (len > 0
	     && (line[len - 1] == '\n' || line[len - 1] == '\r'))
	line[--len] = '\0';
      /* log_debug ("line '%s'\n", line); */

      xfree (fields);
      fields = strtokenize (line, ":");
      if (!fields)
        {
          err = gpg_error_from_syserror ();
          log_error ("strtokenize failed: %s\n", gpg_strerror (err));
          goto leave;
        }
      for (nfields = 0; fields[nfields]; nfields++)
        ;
      if (!nfields)
        {
          err = gpg_error (GPG_ERR_INV_ENGINE);
          goto leave;
        }
      if (!strcmp (fields[0], "sec"))
        {
          /* gpg may return "sec" as the first record - but we do not
           * accept secret keys.  */
          err = gpg_error (GPG_ERR_NO_PUBKEY);
          goto leave;
        }
      if (lnr == 1 && strcmp (fields[0], "pub"))
        {
          /* First record is not a public key.  */
          err = gpg_error (GPG_ERR_INV_ENGINE);
          goto leave;
        }
      if (lnr > 1 && !strcmp (fields[0], "pub"))
        {
          /* More than one public key.  */
          err = gpg_error (GPG_ERR_TOO_MANY);
          goto leave;
        }
      if (!strcmp (fields[0], "sub") || !strcmp (fields[0], "ssb"))
        break; /* We can stop parsing here.  */

      if (!strcmp (fields[0], "fpr") && nfields > 9 && !fpr)
        {
          fpr = xtrystrdup (fields[9]);
          if (!fpr)
            {
              err = gpg_error_from_syserror ();
              goto leave;
            }
        }
      else if (!strcmp (fields[0], "uid") && nfields > 9)
        {
          /* Fixme: Unescape fields[9] */
          if (!append_to_uidinfo_list (&mboxes, fields[9],
                                       parse_timestamp (fields[5], NULL)))
            {
              err = gpg_error_from_syserror ();
              goto leave;
            }
        }
    }
  if (len < 0 || es_ferror (listing))
    {
      err = gpg_error_from_syserror ();
      log_error ("error reading memory stream\n");
      goto leave;
    }

  if (!fpr)
    {
      err = gpg_error (GPG_ERR_NO_PUBKEY);
      goto leave;
    }

  if (r_fpr)
    {
      *r_fpr = fpr;
      fpr = NULL;
    }
  *r_mboxes = mboxes;
  mboxes = NULL;

 leave:
  xfree (fpr);
  free_uidinfo_list (mboxes);
  xfree (fields);
  es_free (line);
  xfree (argv);
  es_fclose (listing);
  return err;
}


/* Run gpg as a filter on KEY and write the output to a new stream
 * stored at R_NEWKEY.  The new key will containn only the user id
 * UID.  Returns 0 on success.  Only one key is expected in KEY. */
gpg_error_t
wks_filter_uid (estream_t *r_newkey, estream_t key, const char *uid)
{
  gpg_error_t err;
  ccparray_t ccp;
  const char **argv = NULL;
  estream_t newkey;
  char *filterexp = NULL;

  *r_newkey = NULL;

  /* Open a memory stream.  */
  newkey = es_fopenmem (0, "w+b");
  if (!newkey)
    {
      err = gpg_error_from_syserror ();
      log_error ("error allocating memory buffer: %s\n", gpg_strerror (err));
      return err;
    }

  /* Prefix the key with the MIME content type.  */
  es_fputs ("Content-Type: application/pgp-keys\n"
            "\n", newkey);

  filterexp = es_bsprintf ("keep-uid=uid=%s", uid);
  if (!filterexp)
    {
      err = gpg_error_from_syserror ();
      log_error ("error allocating memory buffer: %s\n", gpg_strerror (err));
      goto leave;
    }

  ccparray_init (&ccp, 0);

  ccparray_put (&ccp, "--no-options");
  if (!opt.verbose)
    ccparray_put (&ccp, "--quiet");
  else if (opt.verbose > 1)
    ccparray_put (&ccp, "--verbose");
  ccparray_put (&ccp, "--batch");
  ccparray_put (&ccp, "--status-fd=2");
  ccparray_put (&ccp, "--always-trust");
  ccparray_put (&ccp, "--armor");
  ccparray_put (&ccp, "--import-options=import-export");
  ccparray_put (&ccp, "--import-filter");
  ccparray_put (&ccp, filterexp);
  ccparray_put (&ccp, "--import");

  ccparray_put (&ccp, NULL);
  argv = ccparray_get (&ccp, NULL);
  if (!argv)
    {
      err = gpg_error_from_syserror ();
      goto leave;
    }
  err = gnupg_exec_tool_stream (opt.gpg_program, argv, key,
                                NULL, newkey,
                                key_status_cb, NULL);
  if (err)
    {
      log_error ("import/export failed: %s\n", gpg_strerror (err));
      goto leave;
    }

  es_rewind (newkey);
  *r_newkey = newkey;
  newkey = NULL;

 leave:
  xfree (filterexp);
  xfree (argv);
  es_fclose (newkey);
  return err;
}


/* Helper to write mail to the output(s).  */
gpg_error_t
wks_send_mime (mime_maker_t mime)
{
  gpg_error_t err;
  estream_t mail;

  /* Without any option we take a short path.  */
  if (!opt.use_sendmail && !opt.output)
    {
      es_set_binary (es_stdout);
      return mime_maker_make (mime, es_stdout);
    }


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
    TOK_MAX_PENDING,
    TOK_PROTOCOL_VERSION
  };
  static struct {
    const char *name;
    enum tokens token;
  } keywords[] = {
    { "mailbox-only", TOK_MAILBOX_ONLY },
    { "dane-only",    TOK_DANE_ONLY    },
    { "auth-submit",  TOK_AUTH_SUBMIT  },
    { "max-pending",  TOK_MAX_PENDING  },
    { "protocol-version", TOK_PROTOCOL_VERSION }
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
        case TOK_PROTOCOL_VERSION:
          if (!value)
            {
              err = gpg_error (GPG_ERR_SYNTAX);
              goto leave;
            }
          flags->protocol_version = atoi (value);
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
