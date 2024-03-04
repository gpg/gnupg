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
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>

#include "../common/util.h"
#include "../common/status.h"
#include "../common/ccparray.h"
#include "../common/exectool.h"
#include "../common/zb32.h"
#include "../common/userids.h"
#include "../common/mbox-util.h"
#include "../common/sysutils.h"
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


/* Write a status line with code NO followed by the output of the
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
 * updated.  C-style escaping is removed from UID.  On error ERRNO is
 * set and NULL returned. */
static uidinfo_list_t
append_to_uidinfo_list (uidinfo_list_t *list, const char *uid, time_t created,
                        int expired, int revoked)
{
  uidinfo_list_t r, sl;
  char *plainuid;

  plainuid = decode_c_string (uid);
  if (!plainuid)
    return NULL;

  sl = xtrymalloc (sizeof *sl + strlen (plainuid));
  if (!sl)
    {
      xfree (plainuid);
      return NULL;
    }

  strcpy (sl->uid, plainuid);
  sl->created = created;
  sl->flags = 0;
  sl->mbox = mailbox_from_userid (plainuid, 0);
  sl->expired = !!expired;
  sl->revoked = !!revoked;
  sl->next = NULL;
  if (!*list)
    *list = sl;
  else
    {
      for (r = *list; r->next; r = r->next )
        ;
      r->next = sl;
    }

  xfree (plainuid);
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


static void
debug_gpg_invocation (const char *func, const char **argv)
{
  int i;

  if (!(opt.debug & DBG_EXTPROG_VALUE))
    return;

  log_debug ("%s: exec '%s' with", func, opt.gpg_program);
  for (i=0; argv[i]; i++)
    log_printf (" '%s'", argv[i]);
  log_printf ("\n");
}



struct get_key_status_parm_s
{
  const char *fpr;
  int found;
  int count;
};


static void
get_key_status_cb (void *opaque, const char *keyword, char *args)
{
  struct get_key_status_parm_s *parm = opaque;

  if (DBG_CRYPTO)
    log_debug ("%s: %s\n", keyword, args);
  if (!strcmp (keyword, "EXPORTED"))
    {
      parm->count++;
      if (!ascii_strcasecmp (args, parm->fpr))
        parm->found = 1;
    }
}

/* Get a key by fingerprint from gpg's keyring and make sure that the
 * mail address ADDRSPEC is included in the key.  If EXACT is set the
 * returned user id must match Addrspec exactly and not just in the
 * addr-spec (mailbox) part.  The key is returned as a new memory
 * stream at R_KEY.  If BINARY is set the returned key is
 * non-armored.  */
gpg_error_t
wks_get_key (estream_t *r_key, const char *fingerprint, const char *addrspec,
             int exact, int binary)
{
  gpg_error_t err;
  ccparray_t ccp;
  const char **argv = NULL;
  estream_t key = NULL;
  struct get_key_status_parm_s parm;
  char *filterexp = NULL;

  memset (&parm, 0, sizeof parm);

  *r_key = NULL;

  key = es_fopenmem (0, "w+b");
  if (!key)
    {
      err = gpg_error_from_syserror ();
      log_error ("error allocating memory buffer: %s\n", gpg_strerror (err));
      goto leave;
    }

  /* Prefix the key with the MIME content type.  */
  if (!binary)
    es_fputs ("Content-Type: application/pgp-keys\n"
              "\n", key);

  filterexp = es_bsprintf ("keep-uid=%s= %s", exact? "uid":"mbox", addrspec);
  if (!filterexp)
    {
      err = gpg_error_from_syserror ();
      log_error ("error allocating memory buffer: %s\n", gpg_strerror (err));
      goto leave;
    }

  ccparray_init (&ccp, 0);

  ccparray_put (&ccp, "--no-options");
  if (opt.verbose < 2)
    ccparray_put (&ccp, "--quiet");
  else
    ccparray_put (&ccp, "--verbose");
  ccparray_put (&ccp, "--batch");
  ccparray_put (&ccp, "--status-fd=2");
  ccparray_put (&ccp, "--always-trust");
  if (!binary)
    ccparray_put (&ccp, "--armor");
  ccparray_put (&ccp, opt.realclean? "--export-options=export-realclean"
                /* */              : "--export-options=export-clean");
  ccparray_put (&ccp, "--export-filter");
  ccparray_put (&ccp, filterexp);
  ccparray_put (&ccp, "--export");
  ccparray_put (&ccp, "--");
  ccparray_put (&ccp, fingerprint);

  ccparray_put (&ccp, NULL);
  argv = ccparray_get (&ccp, NULL);
  if (!argv)
    {
      err = gpg_error_from_syserror ();
      goto leave;
    }
  parm.fpr = fingerprint;
  debug_gpg_invocation (__func__, argv);
  err = gnupg_exec_tool_stream (opt.gpg_program, argv, NULL,
                                NULL, key,
                                get_key_status_cb, &parm);
  if (!err && parm.count > 1)
    err = gpg_error (GPG_ERR_TOO_MANY);
  else if (!err && !parm.found)
    err = gpg_error (GPG_ERR_NOT_FOUND);
  if (err)
    {
      log_error ("export failed: %s\n", gpg_strerror (err));
      goto leave;
    }

  es_rewind (key);
  *r_key = key;
  key = NULL;

 leave:
  es_fclose (key);
  xfree (argv);
  xfree (filterexp);
  return err;
}



/* Helper for wks_list_key and wks_filter_uid.  */
static void
key_status_cb (void *opaque, const char *keyword, char *args)
{
  (void)opaque;

  if (DBG_CRYPTO)
    log_debug ("gpg status: %s %s\n", keyword, args);
}


/* Parse field 1 and set revoked and expired on return.  */
static void
set_expired_revoked (const char *string, int *expired, int *revoked)
{
  *expired = *revoked = 0;
  /* Look at letters and stop at the first digit.  */
  for ( ;*string && !digitp (string); string++)
    {
      if (*string == 'e')
        *expired = 1;
      else if (*string == 'r')
        *revoked = 1;
    }
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
  int expired, revoked;

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
  if (opt.verbose < 2)
    ccparray_put (&ccp, "--quiet");
  else
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
  debug_gpg_invocation (__func__, argv);
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
  expired = revoked = 0;
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
      fields = strtokenize_nt (line, ":");
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
      if (!strcmp (fields[0], "pub"))
        {
          if (lnr > 1)
            {
              /* More than one public key.  */
              err = gpg_error (GPG_ERR_TOO_MANY);
              goto leave;
            }
          if (nfields > 1)
            set_expired_revoked (fields[1], &expired, &revoked);
          else
            expired = revoked = 0;
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
          int uidexpired, uidrevoked;

          set_expired_revoked (fields[1], &uidexpired, &uidrevoked);
          if (!append_to_uidinfo_list (&mboxes, fields[9],
                                       parse_timestamp (fields[5], NULL),
                                       expired || uidexpired,
                                       revoked || uidrevoked))
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
 * stored at R_NEWKEY.  The new key will contain only the user id UID.
 * Returns 0 on success.  Only one key is expected in KEY.  If BINARY
 * is set the resulting key is returned as a binary (non-armored)
 * keyblock.  */
gpg_error_t
wks_filter_uid (estream_t *r_newkey, estream_t key, const char *uid,
                int binary)
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
  if (!binary)
    es_fputs ("Content-Type: application/pgp-keys\n"
              "\n", newkey);

  filterexp = es_bsprintf ("keep-uid=-t uid= %s", uid);
  if (!filterexp)
    {
      err = gpg_error_from_syserror ();
      log_error ("error allocating memory buffer: %s\n", gpg_strerror (err));
      goto leave;
    }

  ccparray_init (&ccp, 0);

  ccparray_put (&ccp, "--no-options");
  if (opt.verbose < 2)
    ccparray_put (&ccp, "--quiet");
  else
    ccparray_put (&ccp, "--verbose");
  ccparray_put (&ccp, "--batch");
  ccparray_put (&ccp, "--status-fd=2");
  ccparray_put (&ccp, "--always-trust");
  if (!binary)
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
  debug_gpg_invocation (__func__, argv);
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


/* Put the ascii-armor around KEY and return that as a new estream
 * object at R_NEWKEY.  Caller must make sure that KEY has been seeked
 * to the right position (usually by calling es_rewind).  The
 * resulting NEWKEY has already been rewound.  If PREFIX is not NULL,
 * its content is written to NEWKEY propr to the armor; this may be
 * used for MIME headers. */
gpg_error_t
wks_armor_key (estream_t *r_newkey, estream_t key, const char *prefix)
{
  gpg_error_t err;
  estream_t newkey;
  struct b64state b64state;
  char buffer[4096];
  size_t nread;

  *r_newkey = NULL;

  newkey = es_fopenmem (0, "w+b");
  if (!newkey)
    {
      err = gpg_error_from_syserror ();
      return err;
    }

  if (prefix)
    es_fputs (prefix, newkey);

  err = b64enc_start_es (&b64state, newkey, "PGP PUBLIC KEY BLOCK");
  if (err)
    goto leave;

  do
    {
      nread = es_fread (buffer, 1, sizeof buffer, key);
      if (!nread)
	break;
      err = b64enc_write (&b64state, buffer, nread);
      if (err)
        goto leave;
    }
  while (!es_feof (key) && !es_ferror (key));
  if (!es_feof (key) || es_ferror (key))
    {
      err = gpg_error_from_syserror ();
      goto leave;
    }

  err = b64enc_finish (&b64state);
  if (err)
    goto leave;

  es_rewind (newkey);
  *r_newkey = newkey;
  newkey = NULL;

 leave:
  es_fclose (newkey);
  return err;
}


/* Run gpg to export the revocation certificates for ADDRSPEC.  Add
 * them to KEY which is expected to be non-armored keyblock.  */
gpg_error_t
wks_find_add_revocs (estream_t key, const char *addrspec)
{
  gpg_error_t err;
  ccparray_t ccp;
  const char **argv = NULL;
  char *filterexp = NULL;

  filterexp = es_bsprintf ("select=mbox= %s", addrspec);
  if (!filterexp)
    {
      err = gpg_error_from_syserror ();
      log_error ("error allocating memory buffer: %s\n", gpg_strerror (err));
      goto leave;
    }

  ccparray_init (&ccp, 0);

  ccparray_put (&ccp, "--no-options");
  if (opt.verbose < 2)
    ccparray_put (&ccp, "--quiet");
  else
    ccparray_put (&ccp, "--verbose");
  ccparray_put (&ccp, "--batch");
  ccparray_put (&ccp, "--status-fd=2");
  ccparray_put (&ccp, "--export-options=export-revocs");
  ccparray_put (&ccp, "--export-filter");
  ccparray_put (&ccp, filterexp);
  ccparray_put (&ccp, "--export");
  ccparray_put (&ccp, addrspec);

  ccparray_put (&ccp, NULL);
  argv = ccparray_get (&ccp, NULL);
  if (!argv)
    {
      err = gpg_error_from_syserror ();
      goto leave;
    }
  debug_gpg_invocation (__func__, argv);
  err = gnupg_exec_tool_stream (opt.gpg_program, argv, NULL,
                                NULL, key,
                                key_status_cb, NULL);
  if (err)
    {
      log_error ("exporting revocs failed: %s\n", gpg_strerror (err));
      goto leave;
    }

 leave:
  xfree (filterexp);
  xfree (argv);
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
 * into FLAGS.  If IGNORE_UNKNOWN is set unknown keywords are
 * ignored.  */
gpg_error_t
wks_parse_policy (policy_flags_t flags, estream_t stream, int ignore_unknown)
{
  enum tokens {
    TOK_SUBMISSION_ADDRESS,
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
    { "submission-address", TOK_SUBMISSION_ADDRESS },
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
        case TOK_SUBMISSION_ADDRESS:
          if (!value || !*value)
            {
              err = gpg_error (GPG_ERR_SYNTAX);
              goto leave;
            }
          xfree (flags->submission_address);
          flags->submission_address = xtrystrdup (value);
          if (!flags->submission_address)
            {
              err = gpg_error_from_syserror ();
              goto leave;
            }
          break;
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


void
wks_free_policy (policy_flags_t policy)
{
  if (policy)
    {
      xfree (policy->submission_address);
      memset (policy, 0, sizeof *policy);
    }
}


/* Write the content of SRC to the new file FNAME.  If FNAME is NULL
 * SRC is written to stdout. */
gpg_error_t
wks_write_to_file (estream_t src, const char *fname)
{
  gpg_error_t err;
  estream_t dst;
  char buffer[4096];
  size_t nread, written;

  if (!fname)
    {
      dst = es_stdout;
      es_set_binary (es_stdout);
    }
  else
    {
      dst = es_fopen (fname, "wb");
      if (!dst)
        return gpg_error_from_syserror ();
    }

  do
    {
      nread = es_fread (buffer, 1, sizeof buffer, src);
      if (!nread)
	break;
      written = es_fwrite (buffer, 1, nread, dst);
      if (written != nread)
	break;
    }
  while (!es_feof (src) && !es_ferror (src) && !es_ferror (dst));
  if (!es_feof (src) || es_ferror (src) || es_ferror (dst))
    {
      err = gpg_error_from_syserror ();
      if (dst != es_stdout)
        {
          es_fclose (dst);
          gnupg_remove (fname);
        }
      return err;
    }

  if (dst != es_stdout && es_fclose (dst))
    {
      err = gpg_error_from_syserror ();
      log_error ("error closing '%s': %s\n", fname, gpg_strerror (err));
      return err;
    }

  return 0;
}


/* Return the filename and optionally the addrspec for USERID at
 * R_FNAME and R_ADDRSPEC.  R_ADDRSPEC might also be set on error.  If
 * HASH_ONLY is set only the has is returned at R_FNAME and no file is
 * created.  */
gpg_error_t
wks_fname_from_userid (const char *userid, int hash_only,
                       char **r_fname, char **r_addrspec)
{
  gpg_error_t err;
  char *addrspec = NULL;
  const char *domain;
  char *hash = NULL;
  const char *s;
  char shaxbuf[32]; /* Used for SHA-1 and SHA-256 */

  *r_fname = NULL;
  if (r_addrspec)
    *r_addrspec = NULL;

  addrspec = mailbox_from_userid (userid, 0);
  if (!addrspec)
    {
      if (opt.verbose || hash_only)
        log_info ("\"%s\" is not a proper mail address\n", userid);
      err = gpg_error (GPG_ERR_INV_USER_ID);
      goto leave;
    }

  domain = strchr (addrspec, '@');
  log_assert (domain);
  domain++;
  if (strchr (domain, '/') || strchr (domain, '\\'))
    {
      log_info ("invalid domain detected ('%s')\n", domain);
      err = gpg_error (GPG_ERR_NOT_FOUND);
      goto leave;
    }

  /* Hash user ID and create filename.  */
  s = strchr (addrspec, '@');
  log_assert (s);
  gcry_md_hash_buffer (GCRY_MD_SHA1, shaxbuf, addrspec, s - addrspec);
  hash = zb32_encode (shaxbuf, 8*20);
  if (!hash)
    {
      err = gpg_error_from_syserror ();
      goto leave;
    }

  if (hash_only)
    {
      *r_fname = hash;
      hash = NULL;
      err = 0;
    }
  else
    {
      *r_fname = make_filename_try (opt.directory, domain, "hu", hash, NULL);
      if (!*r_fname)
        err = gpg_error_from_syserror ();
      else
        err = 0;
    }

 leave:
  if (r_addrspec && addrspec)
    *r_addrspec = addrspec;
  else
    xfree (addrspec);
  xfree (hash);
  return err;
}


/* Compute the the full file name for the key with ADDRSPEC and return
 * it at R_FNAME.  */
gpg_error_t
wks_compute_hu_fname (char **r_fname, const char *addrspec)
{
  gpg_error_t err;
  char *hash;
  const char *domain;
  char sha1buf[20];
  char *fname;
  struct stat sb;

  *r_fname = NULL;

  domain = strchr (addrspec, '@');
  if (!domain || !domain[1] || domain == addrspec)
    return gpg_error (GPG_ERR_INV_ARG);
  domain++;
  if (strchr (domain, '/') || strchr (domain, '\\'))
    {
      log_info ("invalid domain detected ('%s')\n", domain);
      return gpg_error (GPG_ERR_NOT_FOUND);
    }

  gcry_md_hash_buffer (GCRY_MD_SHA1, sha1buf, addrspec, domain - addrspec - 1);
  hash = zb32_encode (sha1buf, 8*20);
  if (!hash)
    return gpg_error_from_syserror ();

  /* Try to create missing directories below opt.directory.  */
  fname = make_filename_try (opt.directory, domain, NULL);
  if (fname && gnupg_stat (fname, &sb)
      && gpg_err_code_from_syserror () == GPG_ERR_ENOENT)
    if (!gnupg_mkdir (fname, "-rwxr-xr-x") && opt.verbose)
      log_info ("directory '%s' created\n", fname);
  xfree (fname);
  fname = make_filename_try (opt.directory, domain, "hu", NULL);
  if (fname && gnupg_stat (fname, &sb)
      && gpg_err_code_from_syserror () == GPG_ERR_ENOENT)
    if (!gnupg_mkdir (fname, "-rwxr-xr-x") && opt.verbose)
      log_info ("directory '%s' created\n", fname);
  xfree (fname);

  /* Create the filename.  */
  fname = make_filename_try (opt.directory, domain, "hu", hash, NULL);
  err = fname? 0 : gpg_error_from_syserror ();

  if (err)
    xfree (fname);
  else
    *r_fname = fname; /* Okay.  */
  xfree (hash);
  return err;
}


/* Make sure that a policy file exists for addrspec.  Directories must
 * already exist.  */
static gpg_error_t
ensure_policy_file (const char *addrspec)
{
  gpg_err_code_t ec;
  gpg_error_t err;
  const char *domain;
  char *fname;
  estream_t fp;

  domain = strchr (addrspec, '@');
  if (!domain || !domain[1] || domain == addrspec)
    return gpg_error (GPG_ERR_INV_ARG);
  domain++;
  if (strchr (domain, '/') || strchr (domain, '\\'))
    {
      log_info ("invalid domain detected ('%s')\n", domain);
      return gpg_error (GPG_ERR_NOT_FOUND);
    }

  /* Create the filename.  */
  fname = make_filename_try (opt.directory, domain, "policy", NULL);
  err = fname? 0 : gpg_error_from_syserror ();
  if (err)
    goto leave;

  /* First a quick check whether it already exists.  */
  if (!(ec = gnupg_access (fname, F_OK)))
    {
      err = 0; /* File already exists.  */
      goto leave;
    }
  err = gpg_error (ec);
  if (gpg_err_code (err) == GPG_ERR_ENOENT)
    err = 0;
  else
    {
      log_error ("domain %s: problem with '%s': %s\n",
                 domain, fname, gpg_strerror (err));
      goto leave;
    }

  /* Now create the file.  */
  fp = es_fopen (fname, "wxb");
  if (!fp)
    {
      err = gpg_error_from_syserror ();
      if (gpg_err_code (err) == GPG_ERR_EEXIST)
        err = 0; /* Was created between the gnupg_access() and es_fopen().  */
      else
        log_error ("domain %s: error creating '%s': %s\n",
                   domain, fname, gpg_strerror (err));
      goto leave;
    }

  es_fprintf (fp, "# Policy flags for domain %s\n", domain);
  if (es_ferror (fp) || es_fclose (fp))
    {
      err = gpg_error_from_syserror ();
      log_error ("error writing '%s': %s\n", fname, gpg_strerror (err));
      goto leave;
    }

  if (opt.verbose)
    log_info ("policy file '%s' created\n", fname);

  /* Make sure the policy file world readable.  */
  if (gnupg_chmod (fname, "-rw-r--r--"))
    {
      err = gpg_error_from_syserror ();
      log_error ("can't set permissions of '%s': %s\n",
                 fname, gpg_strerror (err));
      goto leave;
    }

 leave:
  xfree (fname);
  return err;
}


/* Helper form wks_cmd_install_key.  */
static gpg_error_t
install_key_from_spec_file (const char *fname)
{
  gpg_error_t err;
  estream_t fp;
  char *line = NULL;
  size_t linelen = 0;
  size_t maxlen = 2048;
  const char *fields[2];
  unsigned int lnr = 0;

  if (!fname || !strcmp (fname, ""))
    fp = es_stdin;
  else
    fp = es_fopen (fname, "rb");
  if (!fp)
    {
      err = gpg_error_from_syserror ();
      log_error ("error reading '%s': %s\n", fname, gpg_strerror (err));
      goto leave;
    }

  while (es_read_line (fp, &line, &linelen, &maxlen) > 0)
    {
      if (!maxlen)
        {
          err = gpg_error (GPG_ERR_LINE_TOO_LONG);
          log_error ("error reading '%s': %s\n", fname, gpg_strerror (err));
          goto leave;
        }
      lnr++;
      trim_spaces (line);
      if (!*line ||  *line == '#')
        continue;
      if (split_fields (line, fields, DIM(fields)) < 2)
        {
          log_error ("error reading '%s': syntax error at line %u\n",
                     fname, lnr);
          continue;
        }
      err = wks_cmd_install_key (fields[0], fields[1]);
      if (err)
        goto leave;
    }
  if (es_ferror (fp))
    {
      err = gpg_error_from_syserror ();
      log_error ("error reading '%s': %s\n", fname, gpg_strerror (err));
      goto leave;
    }

 leave:
  if (fp != es_stdin)
    es_fclose (fp);
  es_free (line);
  return err;
}


/* The core of the code to install a key as a file.  */
gpg_error_t
wks_install_key_core (estream_t key, const char *addrspec)
{
  gpg_error_t err;
  char *huname = NULL;

  /* Hash user ID and create filename.  */
  err = wks_compute_hu_fname (&huname, addrspec);
  if (err)
    goto leave;

  /* Now that wks_compute_hu_fname has created missing directories we
   * can create a policy file if it does not exist.  */
  err = ensure_policy_file (addrspec);
  if (err)
    goto leave;

  /* Publish.  */
  err = wks_write_to_file (key, huname);
  if (err)
    {
      log_error ("copying key to '%s' failed: %s\n", huname,gpg_strerror (err));
      goto leave;
    }

  /* Make sure it is world readable.  */
  if (gnupg_chmod (huname, "-rw-r--r--"))
    log_error ("can't set permissions of '%s': %s\n",
               huname, gpg_strerror (gpg_err_code_from_syserror()));

 leave:
  xfree (huname);
  return err;
}


/* Install a single key into the WKD by reading FNAME and extracting
 * USERID.  If USERID is NULL FNAME is expected to be a list of fpr
 * mbox lines and for each line the respective key will be
 * installed.  */
gpg_error_t
wks_cmd_install_key (const char *fname, const char *userid)
{
  gpg_error_t err;
  KEYDB_SEARCH_DESC desc;
  estream_t fp = NULL;
  char *addrspec = NULL;
  char *fpr = NULL;
  uidinfo_list_t uidlist = NULL;
  uidinfo_list_t uid, thisuid;
  time_t thistime;
  int any;

  if (!userid)
    return install_key_from_spec_file (fname);

  addrspec = mailbox_from_userid (userid, 0);
  if (!addrspec)
    {
      log_error ("\"%s\" is not a proper mail address\n", userid);
      err = gpg_error (GPG_ERR_INV_USER_ID);
      goto leave;
    }

  if (!classify_user_id (fname, &desc, 1)
      && desc.mode == KEYDB_SEARCH_MODE_FPR)
    {
      /* FNAME looks like a fingerprint.  Get the key from the
       * standard keyring.  */
      err = wks_get_key (&fp, fname, addrspec, 0, 1);
      if (err)
        {
          log_error ("error getting key '%s' (uid='%s'): %s\n",
                     fname, addrspec, gpg_strerror (err));
          goto leave;
        }
    }
  else /* Take it from the file */
    {
      fp = es_fopen (fname, "rb");
      if (!fp)
        {
          err = gpg_error_from_syserror ();
          log_error ("error reading '%s': %s\n", fname, gpg_strerror (err));
          goto leave;
        }
    }

  /* List the key so that we can figure out the newest UID with the
   * requested addrspec.  */
  err = wks_list_key (fp, &fpr, &uidlist);
  if (err)
    {
      log_error ("error parsing key: %s\n", gpg_strerror (err));
      err = gpg_error (GPG_ERR_NO_PUBKEY);
      goto leave;
    }
  thistime = 0;
  thisuid = NULL;
  any = 0;
  for (uid = uidlist; uid; uid = uid->next)
    {
      if (!uid->mbox)
        continue; /* Should not happen anyway.  */
      if (ascii_strcasecmp (uid->mbox, addrspec))
        continue; /* Not the requested addrspec.  */
      if (uid->expired)
        {
          if (opt.verbose)
            log_info ("ignoring expired user id '%s'\n", uid->uid);
          continue;
        }
      any = 1;
      if (uid->created > thistime)
        {
          thistime = uid->created;
          thisuid = uid;
        }
    }
  if (!thisuid)
    thisuid = uidlist;  /* This is the case for a missing timestamp.  */
  if (!any)
    {
      log_error ("public key in '%s' has no mail address '%s'\n",
                 fname, addrspec);
      err = gpg_error (GPG_ERR_INV_USER_ID);
      goto leave;
    }

  if (opt.verbose)
    log_info ("using key with user id '%s'\n", thisuid->uid);

  {
    estream_t fp2;

    es_rewind (fp);
    err = wks_filter_uid (&fp2, fp, thisuid->uid, 1);
    if (err)
      {
        log_error ("error filtering key: %s\n", gpg_strerror (err));
        err = gpg_error (GPG_ERR_NO_PUBKEY);
        goto leave;
      }
    es_fclose (fp);
    fp = fp2;
  }

  if (opt.add_revocs)
    {
      if (es_fseek (fp, 0, SEEK_END))
        {
          err = gpg_error_from_syserror ();
          log_error ("error seeking stream: %s\n", gpg_strerror (err));
          goto leave;
        }
      err = wks_find_add_revocs (fp, addrspec);
      if (err)
        {
          log_error ("error finding revocations for '%s': %s\n",
                     addrspec, gpg_strerror (err));
          goto leave;
        }
      es_rewind (fp);
    }

  err = wks_install_key_core (fp, addrspec);
  if (!opt.quiet)
    log_info ("key %s published for '%s'\n", fpr, addrspec);


 leave:
  free_uidinfo_list (uidlist);
  xfree (fpr);
  xfree (addrspec);
  es_fclose (fp);
  return err;
}


/* Remove the key with mail address in USERID.  */
gpg_error_t
wks_cmd_remove_key (const char *userid)
{
  gpg_error_t err;
  char *addrspec = NULL;
  char *fname = NULL;

  err = wks_fname_from_userid (userid, 0, &fname, &addrspec);
  if (err)
    goto leave;

  if (gnupg_remove (fname))
    {
      err = gpg_error_from_syserror ();
      if (gpg_err_code (err) == GPG_ERR_ENOENT)
        {
          if (!opt.quiet)
            log_info ("key for '%s' is not installed\n", addrspec);
          log_inc_errorcount ();
          err = 0;
        }
      else
        log_error ("error removing '%s': %s\n", fname, gpg_strerror (err));
      goto leave;
    }

  if (opt.verbose)
    log_info ("key for '%s' removed\n", addrspec);
  err = 0;

 leave:
  xfree (fname);
  xfree (addrspec);
  return err;
}


/* Print the WKD hash for the user id to stdout.  */
gpg_error_t
wks_cmd_print_wkd_hash (const char *userid)
{
  gpg_error_t err;
  char *addrspec, *fname;

  err = wks_fname_from_userid (userid, 1, &fname, &addrspec);
  if (err)
    return err;

  es_printf ("%s %s\n", fname, addrspec);

  xfree (fname);
  xfree (addrspec);
  return err;
}


/* Print the WKD URL for the user id to stdout.  */
gpg_error_t
wks_cmd_print_wkd_url (const char *userid)
{
  gpg_error_t err;
  char *addrspec, *fname;
  char *domain;

  err = wks_fname_from_userid (userid, 1, &fname, &addrspec);
  if (err)
    return err;

  domain = strchr (addrspec, '@');
  if (domain)
    *domain++ = 0;

  es_printf ("https://openpgpkey.%s/.well-known/openpgpkey/%s/hu/%s?l=%s\n",
             domain, domain, fname, addrspec);

  xfree (fname);
  xfree (addrspec);
  return err;
}
