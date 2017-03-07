/* gpg-wks-client.c - A client for the Web Key Service protocols.
 * Copyright (C) 2016 Werner Koch
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

#include "../common/util.h"
#include "../common/status.h"
#include "../common/i18n.h"
#include "../common/sysutils.h"
#include "../common/init.h"
#include "../common/asshelp.h"
#include "../common/userids.h"
#include "../common/ccparray.h"
#include "../common/exectool.h"
#include "../common/mbox-util.h"
#include "../common/name-value.h"
#include "call-dirmngr.h"
#include "mime-maker.h"
#include "send-mail.h"
#include "gpg-wks.h"


/* Constants to identify the commands and options. */
enum cmd_and_opt_values
  {
    aNull = 0,

    oQuiet      = 'q',
    oVerbose	= 'v',
    oOutput     = 'o',

    oDebug      = 500,

    aSupported,
    aCheck,
    aCreate,
    aReceive,
    aRead,

    oGpgProgram,
    oSend,
    oFakeSubmissionAddr,
    oStatusFD,

    oDummy
  };


/* The list of commands and options. */
static ARGPARSE_OPTS opts[] = {
  ARGPARSE_group (300, ("@Commands:\n ")),

  ARGPARSE_c (aSupported, "supported",
              ("check whether provider supports WKS")),
  ARGPARSE_c (aCheck, "check",
              ("check whether a key is available")),
  ARGPARSE_c (aCreate,   "create",
              ("create a publication request")),
  ARGPARSE_c (aReceive,   "receive",
              ("receive a MIME confirmation request")),
  ARGPARSE_c (aRead,      "read",
              ("receive a plain text confirmation request")),

  ARGPARSE_group (301, ("@\nOptions:\n ")),

  ARGPARSE_s_n (oVerbose, "verbose", ("verbose")),
  ARGPARSE_s_n (oQuiet,	"quiet",  ("be somewhat more quiet")),
  ARGPARSE_s_s (oDebug, "debug", "@"),
  ARGPARSE_s_s (oGpgProgram, "gpg", "@"),
  ARGPARSE_s_n (oSend, "send", "send the mail using sendmail"),
  ARGPARSE_s_s (oOutput, "output", "|FILE|write the mail to FILE"),
  ARGPARSE_s_i (oStatusFD, "status-fd", N_("|FD|write status info to this FD")),

  ARGPARSE_s_s (oFakeSubmissionAddr, "fake-submission-addr", "@"),

  ARGPARSE_end ()
};


/* The list of supported debug flags.  */
static struct debug_flags_s debug_flags [] =
  {
    { DBG_MIME_VALUE   , "mime"    },
    { DBG_PARSER_VALUE , "parser"  },
    { DBG_CRYPTO_VALUE , "crypto"  },
    { DBG_MEMORY_VALUE , "memory"  },
    { DBG_MEMSTAT_VALUE, "memstat" },
    { DBG_IPC_VALUE    , "ipc"     },
    { DBG_EXTPROG_VALUE, "extprog" },
    { 0, NULL }
  };



/* Value of the option --fake-submission-addr.  */
const char *fake_submission_addr;


static void wrong_args (const char *text) GPGRT_ATTR_NORETURN;
static gpg_error_t command_supported (char *userid);
static gpg_error_t command_check (char *userid);
static gpg_error_t command_send (const char *fingerprint, char *userid);
static gpg_error_t encrypt_response (estream_t *r_output, estream_t input,
                                     const char *addrspec,
                                     const char *fingerprint);
static gpg_error_t read_confirmation_request (estream_t msg);
static gpg_error_t command_receive_cb (void *opaque,
                                       const char *mediatype, estream_t fp,
                                       unsigned int flags);



/* Print usage information and provide strings for help. */
static const char *
my_strusage( int level )
{
  const char *p;

  switch (level)
    {
    case 11: p = "gpg-wks-client (@GNUPG@)";
      break;
    case 13: p = VERSION; break;
    case 17: p = PRINTABLE_OS_NAME; break;
    case 19: p = ("Please report bugs to <@EMAIL@>.\n"); break;

    case 1:
    case 40:
      p = ("Usage: gpg-wks-client [command] [options] [args] (-h for help)");
      break;
    case 41:
      p = ("Syntax: gpg-wks-client [command] [options] [args]\n"
           "Client for the Web Key Service\n");
      break;

    default: p = NULL; break;
    }
  return p;
}


static void
wrong_args (const char *text)
{
  es_fprintf (es_stderr, _("usage: %s [options] %s\n"), strusage (11), text);
  exit (2);
}



/* Command line parsing.  */
static enum cmd_and_opt_values
parse_arguments (ARGPARSE_ARGS *pargs, ARGPARSE_OPTS *popts)
{
  enum cmd_and_opt_values cmd = 0;
  int no_more_options = 0;

  while (!no_more_options && optfile_parse (NULL, NULL, NULL, pargs, popts))
    {
      switch (pargs->r_opt)
        {
	case oQuiet:     opt.quiet = 1; break;
        case oVerbose:   opt.verbose++; break;
        case oDebug:
          if (parse_debug_flag (pargs->r.ret_str, &opt.debug, debug_flags))
            {
              pargs->r_opt = ARGPARSE_INVALID_ARG;
              pargs->err = ARGPARSE_PRINT_ERROR;
            }
          break;

        case oGpgProgram:
          opt.gpg_program = pargs->r.ret_str;
          break;
        case oSend:
          opt.use_sendmail = 1;
          break;
        case oOutput:
          opt.output = pargs->r.ret_str;
          break;
        case oFakeSubmissionAddr:
          fake_submission_addr = pargs->r.ret_str;
          break;
        case oStatusFD:
          wks_set_status_fd (translate_sys2libc_fd_int (pargs->r.ret_int, 1));
          break;

	case aSupported:
	case aCreate:
	case aReceive:
	case aRead:
        case aCheck:
          cmd = pargs->r_opt;
          break;

        default: pargs->err = 2; break;
	}
    }

  return cmd;
}



/* gpg-wks-client main. */
int
main (int argc, char **argv)
{
  gpg_error_t err;
  ARGPARSE_ARGS pargs;
  enum cmd_and_opt_values cmd;

  gnupg_reopen_std ("gpg-wks-client");
  set_strusage (my_strusage);
  log_set_prefix ("gpg-wks-client", GPGRT_LOG_WITH_PREFIX);

  /* Make sure that our subsystems are ready.  */
  i18n_init();
  init_common_subsystems (&argc, &argv);

  assuan_set_gpg_err_source (GPG_ERR_SOURCE_DEFAULT);
  setup_libassuan_logging (&opt.debug, NULL);

  /* Parse the command line. */
  pargs.argc  = &argc;
  pargs.argv  = &argv;
  pargs.flags = ARGPARSE_FLAG_KEEP;
  cmd = parse_arguments (&pargs, opts);

  if (log_get_errorcount (0))
    exit (2);

  /* Print a warning if an argument looks like an option.  */
  if (!opt.quiet && !(pargs.flags & ARGPARSE_FLAG_STOP_SEEN))
    {
      int i;

      for (i=0; i < argc; i++)
        if (argv[i][0] == '-' && argv[i][1] == '-')
          log_info (("NOTE: '%s' is not considered an option\n"), argv[i]);
    }

  /* Set defaults for non given options.  */
  if (!opt.gpg_program)
    opt.gpg_program = gnupg_module_name (GNUPG_MODULE_NAME_GPG);

  /* Tell call-dirmngr what options we want.  */
  set_dirmngr_options (opt.verbose, (opt.debug & DBG_IPC_VALUE), 1);

  /* Run the selected command.  */
  switch (cmd)
    {
    case aSupported:
      if (argc != 1)
        wrong_args ("--supported USER-ID");
      err = command_supported (argv[0]);
      if (err && gpg_err_code (err) != GPG_ERR_FALSE)
        log_error ("checking support failed: %s\n", gpg_strerror (err));
      break;

    case aCreate:
      if (argc != 2)
        wrong_args ("--create FINGERPRINT USER-ID");
      err = command_send (argv[0], argv[1]);
      if (err)
        log_error ("creating request failed: %s\n", gpg_strerror (err));
      break;

    case aReceive:
      if (argc)
        wrong_args ("--receive < MIME-DATA");
      err = wks_receive (es_stdin, command_receive_cb, NULL);
      if (err)
        log_error ("processing mail failed: %s\n", gpg_strerror (err));
      break;

    case aRead:
      if (argc)
        wrong_args ("--read < WKS-DATA");
      err = read_confirmation_request (es_stdin);
      if (err)
        log_error ("processing mail failed: %s\n", gpg_strerror (err));
      break;

    case aCheck:
      if (argc != 1)
        wrong_args ("--check USER-ID");
      err = command_check (argv[0]);
      break;

    default:
      usage (1);
      err = 0;
      break;
    }

  if (err)
    wks_write_status (STATUS_FAILURE, "- %u", err);
  else if (log_get_errorcount (0))
    wks_write_status (STATUS_FAILURE, "- %u", GPG_ERR_GENERAL);
  else
    wks_write_status (STATUS_SUCCESS, NULL);
  return log_get_errorcount (0)? 1:0;
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

  /*log_debug ("%s: %s\n", keyword, args);*/
  if (!strcmp (keyword, "EXPORTED"))
    {
      parm->count++;
      if (!ascii_strcasecmp (args, parm->fpr))
        parm->found = 1;
    }
}


/* Get a key by fingerprint from gpg's keyring and make sure that the
 * mail address ADDRSPEC is included in the key.  The key is returned
 * as a new memory stream at R_KEY.
 *
 * Fixme: After we have implemented import and export filters for gpg
 * this function shall only return a key with just this user id.  */
static gpg_error_t
get_key (estream_t *r_key, const char *fingerprint, const char *addrspec)
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
  es_fputs ("Content-Type: application/pgp-keys\n"
            "\n", key);

  filterexp = es_bsprintf ("keep-uid=mbox = %s", addrspec);
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
  ccparray_put (&ccp, "--export-options=export-minimal");
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



struct decrypt_stream_parm_s
{
  char *fpr;
  char *mainfpr;
  int  otrust;
};

static void
decrypt_stream_status_cb (void *opaque, const char *keyword, char *args)
{
  struct decrypt_stream_parm_s *decinfo = opaque;

  if (DBG_CRYPTO)
    log_debug ("gpg status: %s %s\n", keyword, args);
  if (!strcmp (keyword, "DECRYPTION_KEY") && !decinfo->fpr)
    {
      char *fields[3];

      if (split_fields (args, fields, DIM (fields)) >= 3)
        {
          decinfo->fpr = xstrdup (fields[0]);
          decinfo->mainfpr = xstrdup (fields[1]);
          decinfo->otrust = *fields[2];
        }
    }
}

/* Decrypt the INPUT stream to a new stream which is stored at success
 * at R_OUTPUT.  */
static gpg_error_t
decrypt_stream (estream_t *r_output, struct decrypt_stream_parm_s *decinfo,
                estream_t input)
{
  gpg_error_t err;
  ccparray_t ccp;
  const char **argv;
  estream_t output;

  *r_output = NULL;
  memset (decinfo, 0, sizeof *decinfo);

  output = es_fopenmem (0, "w+b");
  if (!output)
    {
      err = gpg_error_from_syserror ();
      log_error ("error allocating memory buffer: %s\n", gpg_strerror (err));
      return err;
    }

  ccparray_init (&ccp, 0);

  ccparray_put (&ccp, "--no-options");
  /* We limit the output to 64 KiB to avoid DoS using compression
   * tricks.  A regular client will anyway only send a minimal key;
   * that is one w/o key signatures and attribute packets.  */
  ccparray_put (&ccp, "--max-output=0x10000");
  if (!opt.verbose)
    ccparray_put (&ccp, "--quiet");
  else if (opt.verbose > 1)
    ccparray_put (&ccp, "--verbose");
  ccparray_put (&ccp, "--batch");
  ccparray_put (&ccp, "--status-fd=2");
  ccparray_put (&ccp, "--decrypt");
  ccparray_put (&ccp, "--");

  ccparray_put (&ccp, NULL);
  argv = ccparray_get (&ccp, NULL);
  if (!argv)
    {
      err = gpg_error_from_syserror ();
      goto leave;
    }
  err = gnupg_exec_tool_stream (opt.gpg_program, argv, input,
                                NULL, output,
                                decrypt_stream_status_cb, decinfo);
  if (!err && (!decinfo->fpr || !decinfo->mainfpr || !decinfo->otrust))
    err = gpg_error (GPG_ERR_INV_ENGINE);
  if (err)
    {
      log_error ("decryption failed: %s\n", gpg_strerror (err));
      goto leave;
    }
  else if (opt.verbose)
    log_info ("decryption succeeded\n");

  es_rewind (output);
  *r_output = output;
  output = NULL;

 leave:
  if (err)
    {
      xfree (decinfo->fpr);
      xfree (decinfo->mainfpr);
      memset (decinfo, 0, sizeof *decinfo);
    }
  es_fclose (output);
  xfree (argv);
  return err;
}




/* Check whether the  provider supports the WKS protocol.  */
static gpg_error_t
command_supported (char *userid)
{
  gpg_error_t err;
  char *addrspec = NULL;
  char *submission_to = NULL;

  addrspec = mailbox_from_userid (userid);
  if (!addrspec)
    {
      log_error (_("\"%s\" is not a proper mail address\n"), userid);
      err = gpg_error (GPG_ERR_INV_USER_ID);
      goto leave;
    }

  /* Get the submission address.  */
  err = wkd_get_submission_address (addrspec, &submission_to);
  if (err)
    {
      if (gpg_err_code (err) == GPG_ERR_NO_DATA
          || gpg_err_code (err) == GPG_ERR_UNKNOWN_HOST)
        {
          if (opt.verbose)
            log_info ("provider for '%s' does NOT support WKS (%s)\n",
                      addrspec, gpg_strerror (err));
          err = gpg_error (GPG_ERR_FALSE);
          log_inc_errorcount ();
        }
      goto leave;
    }
  if (opt.verbose)
    log_info ("provider for '%s' supports WKS\n", addrspec);

 leave:
  xfree (submission_to);
  xfree (addrspec);
  return err;
}



/* Check whether the key for USERID is available in the WKD.  */
static gpg_error_t
command_check (char *userid)
{
  gpg_error_t err;
  char *addrspec = NULL;
  estream_t key = NULL;
  char *fpr = NULL;
  strlist_t mboxes = NULL;
  strlist_t sl;
  int found = 0;

  addrspec = mailbox_from_userid (userid);
  if (!addrspec)
    {
      log_error (_("\"%s\" is not a proper mail address\n"), userid);
      err = gpg_error (GPG_ERR_INV_USER_ID);
      goto leave;
    }

  /* Get the submission address.  */
  err = wkd_get_key (addrspec, &key);
  switch (gpg_err_code (err))
    {
    case 0:
      if (opt.verbose)
        log_info ("public key for '%s' found via WKD\n", addrspec);
      /* Fixme: Check that the key contains the user id.  */
      break;

    case GPG_ERR_NO_DATA: /* No such key.  */
      if (opt.verbose)
        log_info ("public key for '%s' NOT found via WKD\n", addrspec);
      err = gpg_error (GPG_ERR_NO_PUBKEY);
      log_inc_errorcount ();
      break;

    case GPG_ERR_UNKNOWN_HOST:
      if (opt.verbose)
        log_info ("error looking up '%s' via WKD: %s\n",
                  addrspec, gpg_strerror (err));
      err = gpg_error (GPG_ERR_NOT_SUPPORTED);
      break;

    default:
      log_error ("error looking up '%s' via WKD: %s\n",
                 addrspec, gpg_strerror (err));
      break;
    }

  if (err)
    goto leave;

  /* Look closer at the key.  */
  err = wks_list_key (key, &fpr, &mboxes);
  if (err || !fpr)
    {
      log_error ("error parsing key: %s\n",
                 err? gpg_strerror (err) : "no fingerprint found");
      err = gpg_error (GPG_ERR_NO_PUBKEY);
      goto leave;
    }

  if (opt.verbose)
    log_info ("fingerprint: %s\n", fpr);

  for (sl = mboxes; sl; sl = sl->next)
    {
      if (!strcmp (sl->d, addrspec))
        found = 1;
      if (opt.verbose)
        log_info ("  addr-spec: %s\n", sl->d);
    }
  if (!found)
    {
      log_error ("public key for '%s' has no user id with the mail address\n",
                 addrspec);
      err = gpg_error (GPG_ERR_CERT_REVOKED);
    }

 leave:
  xfree (fpr);
  free_strlist (mboxes);
  es_fclose (key);
  xfree (addrspec);
  return err;
}



/* Locate the key by fingerprint and userid and send a publication
 * request.  */
static gpg_error_t
command_send (const char *fingerprint, char *userid)
{
  gpg_error_t err;
  KEYDB_SEARCH_DESC desc;
  char *addrspec = NULL;
  estream_t key = NULL;
  estream_t keyenc = NULL;
  char *submission_to = NULL;
  mime_maker_t mime = NULL;
  struct policy_flags_s policy;

  memset (&policy, 0, sizeof policy);

  if (classify_user_id (fingerprint, &desc, 1)
      || !(desc.mode == KEYDB_SEARCH_MODE_FPR
           || desc.mode == KEYDB_SEARCH_MODE_FPR20))
    {
      log_error (_("\"%s\" is not a fingerprint\n"), fingerprint);
      err = gpg_error (GPG_ERR_INV_NAME);
      goto leave;
    }
  addrspec = mailbox_from_userid (userid);
  if (!addrspec)
    {
      log_error (_("\"%s\" is not a proper mail address\n"), userid);
      err = gpg_error (GPG_ERR_INV_USER_ID);
      goto leave;
    }
  err = get_key (&key, fingerprint, addrspec);
  if (err)
    goto leave;

  /* Get the submission address.  */
  if (fake_submission_addr)
    {
      submission_to = xstrdup (fake_submission_addr);
      err = 0;
    }
  else
    err = wkd_get_submission_address (addrspec, &submission_to);
  if (err)
    {
      char *domain = strchr (addrspec, '@');
      if (domain)
        domain = domain + 1;
      log_error (_("looking up WKS submission address for %s: %s\n"),
                 domain ? domain : addrspec, gpg_strerror (err));
      if (gpg_err_code (err) == GPG_ERR_NO_DATA)
        log_error (_("this domain probably doesn't support WKS.\n"));
      goto leave;
    }
  log_info ("submitting request to '%s'\n", submission_to);

  /* Get the policy flags.  */
  if (!fake_submission_addr)
    {
      estream_t mbuf;

      err = wkd_get_policy_flags (addrspec, &mbuf);
      if (err && gpg_err_code (err) != GPG_ERR_NO_DATA)
        {
          log_error ("error reading policy flags for '%s': %s\n",
                     submission_to, gpg_strerror (err));
          goto leave;
        }
      if (mbuf)
        {
          err = wks_parse_policy (&policy, mbuf, 1);
          es_fclose (mbuf);
          if (err)
            goto leave;
        }
    }

  if (policy.auth_submit)
    log_info ("no confirmation required for '%s'\n", addrspec);

  /* Encrypt the key part.  */
  es_rewind (key);
  err = encrypt_response (&keyenc, key, submission_to, fingerprint);
  if (err)
    goto leave;
  es_fclose (key);
  key = NULL;


  /* Send the key.  */
  err = mime_maker_new (&mime, NULL);
  if (err)
    goto leave;
  err = mime_maker_add_header (mime, "From", addrspec);
  if (err)
    goto leave;
  err = mime_maker_add_header (mime, "To", submission_to);
  if (err)
    goto leave;
  err = mime_maker_add_header (mime, "Subject", "Key publishing request");
  if (err)
    goto leave;

  /* Tell server which draft we support.  */
  err = mime_maker_add_header (mime, "Wks-Draft-Version",
                               STR2(WKS_DRAFT_VERSION));
  if (err)
    goto leave;

  err = mime_maker_add_header (mime, "Content-Type",
                               "multipart/encrypted; "
                               "protocol=\"application/pgp-encrypted\"");
  if (err)
    goto leave;
  err = mime_maker_add_container (mime);
  if (err)
    goto leave;

  err = mime_maker_add_header (mime, "Content-Type",
                               "application/pgp-encrypted");
  if (err)
    goto leave;
  err = mime_maker_add_body (mime, "Version: 1\n");
  if (err)
    goto leave;
  err = mime_maker_add_header (mime, "Content-Type",
                               "application/octet-stream");
  if (err)
    goto leave;

  err = mime_maker_add_stream (mime, &keyenc);
  if (err)
    goto leave;

  err = wks_send_mime (mime);

 leave:
  mime_maker_release (mime);
  xfree (submission_to);
  es_fclose (keyenc);
  es_fclose (key);
  xfree (addrspec);
  return err;
}



static void
encrypt_response_status_cb (void *opaque, const char *keyword, char *args)
{
  gpg_error_t *failure = opaque;
  char *fields[2];

  if (DBG_CRYPTO)
    log_debug ("gpg status: %s %s\n", keyword, args);

  if (!strcmp (keyword, "FAILURE"))
    {
      if (split_fields (args, fields, DIM (fields)) >= 2
          && !strcmp (fields[0], "encrypt"))
        *failure = strtoul (fields[1], NULL, 10);
    }

}


/* Encrypt the INPUT stream to a new stream which is stored at success
 * at R_OUTPUT.  Encryption is done for ADDRSPEC and for FINGERPRINT
 * (so that the sent message may later be inspected by the user).  We
 * currently retrieve that key from the WKD, DANE, or from "local".
 * "local" is last to prefer the latest key version but use a local
 * copy in case we are working offline.  It might be useful for the
 * server to send the fingerprint of its encryption key - or even the
 * entire key back.  */
static gpg_error_t
encrypt_response (estream_t *r_output, estream_t input, const char *addrspec,
                  const char *fingerprint)
{
  gpg_error_t err;
  ccparray_t ccp;
  const char **argv;
  estream_t output;
  gpg_error_t gpg_err = 0;

  *r_output = NULL;

  output = es_fopenmem (0, "w+b");
  if (!output)
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
  ccparray_put (&ccp, "--armor");
  if (fake_submission_addr)
    ccparray_put (&ccp, "--auto-key-locate=clear,local");
  else
    ccparray_put (&ccp, "--auto-key-locate=clear,wkd,dane,local");
  ccparray_put (&ccp, "--recipient");
  ccparray_put (&ccp, addrspec);
  ccparray_put (&ccp, "--recipient");
  ccparray_put (&ccp, fingerprint);
  ccparray_put (&ccp, "--encrypt");
  ccparray_put (&ccp, "--");

  ccparray_put (&ccp, NULL);
  argv = ccparray_get (&ccp, NULL);
  if (!argv)
    {
      err = gpg_error_from_syserror ();
      goto leave;
    }
  err = gnupg_exec_tool_stream (opt.gpg_program, argv, input,
                                NULL, output,
                                encrypt_response_status_cb, &gpg_err);
  if (err)
    {
      if (gpg_err)
        err = gpg_err;
      log_error ("encryption failed: %s\n", gpg_strerror (err));
      goto leave;
    }

  es_rewind (output);
  *r_output = output;
  output = NULL;

 leave:
  es_fclose (output);
  xfree (argv);
  return err;
}


static gpg_error_t
send_confirmation_response (const char *sender, const char *address,
                            const char *nonce, int encrypt,
                            const char *fingerprint)
{
  gpg_error_t err;
  estream_t body = NULL;
  estream_t bodyenc = NULL;
  mime_maker_t mime = NULL;

  body = es_fopenmem (0, "w+b");
  if (!body)
    {
      err = gpg_error_from_syserror ();
      log_error ("error allocating memory buffer: %s\n", gpg_strerror (err));
      return err;
    }

  /* It is fine to use 8 bit encoding because that is encrypted and
   * only our client will see it.  */
  if (encrypt)
    {
      es_fputs ("Content-Type: application/vnd.gnupg.wks\n"
                "Content-Transfer-Encoding: 8bit\n"
                "\n",
                body);
    }

  es_fprintf (body, ("type: confirmation-response\n"
                     "sender: %s\n"
                     "address: %s\n"
                     "nonce: %s\n"),
              sender,
              address,
              nonce);

  es_rewind (body);
  if (encrypt)
    {
      err = encrypt_response (&bodyenc, body, sender, fingerprint);
      if (err)
        goto leave;
      es_fclose (body);
      body = NULL;
    }

  err = mime_maker_new (&mime, NULL);
  if (err)
    goto leave;
  err = mime_maker_add_header (mime, "From", address);
  if (err)
    goto leave;
  err = mime_maker_add_header (mime, "To", sender);
  if (err)
    goto leave;
  err = mime_maker_add_header (mime, "Subject", "Key publication confirmation");
  if (err)
    goto leave;
  err = mime_maker_add_header (mime, "Wks-Draft-Version",
                               STR2(WKS_DRAFT_VERSION));
  if (err)
    goto leave;

  if (encrypt)
    {
      err = mime_maker_add_header (mime, "Content-Type",
                                   "multipart/encrypted; "
                                   "protocol=\"application/pgp-encrypted\"");
      if (err)
        goto leave;
      err = mime_maker_add_container (mime);
      if (err)
        goto leave;

      err = mime_maker_add_header (mime, "Content-Type",
                                   "application/pgp-encrypted");
      if (err)
        goto leave;
      err = mime_maker_add_body (mime, "Version: 1\n");
      if (err)
        goto leave;
      err = mime_maker_add_header (mime, "Content-Type",
                                   "application/octet-stream");
      if (err)
        goto leave;

      err = mime_maker_add_stream (mime, &bodyenc);
      if (err)
        goto leave;
    }
  else
    {
      err = mime_maker_add_header (mime, "Content-Type",
                                   "application/vnd.gnupg.wks");
      if (err)
        goto leave;
      err = mime_maker_add_stream (mime, &body);
      if (err)
        goto leave;
    }

  err = wks_send_mime (mime);

 leave:
  mime_maker_release (mime);
  es_fclose (bodyenc);
  es_fclose (body);
  return err;
}


/* Reply to a confirmation request.  The MSG has already been
 * decrypted and we only need to send the nonce back.  MAINFPR is
 * either NULL or the primary key fingerprint of the key used to
 * decrypt the request.  */
static gpg_error_t
process_confirmation_request (estream_t msg, const char *mainfpr)
{
  gpg_error_t err;
  nvc_t nvc;
  nve_t item;
  const char *value, *sender, *address, *fingerprint, *nonce;

  err = nvc_parse (&nvc, NULL, msg);
  if (err)
    {
      log_error ("parsing the WKS message failed: %s\n", gpg_strerror (err));
      goto leave;
    }

  if (DBG_MIME)
    {
      log_debug ("request follows:\n");
      nvc_write (nvc, log_get_stream ());
    }

  /* Check that this is a confirmation request.  */
  if (!((item = nvc_lookup (nvc, "type:")) && (value = nve_value (item))
        && !strcmp (value, "confirmation-request")))
    {
      if (item && value)
        log_error ("received unexpected wks message '%s'\n", value);
      else
        log_error ("received invalid wks message: %s\n", "'type' missing");
      err = gpg_error (GPG_ERR_UNEXPECTED_MSG);
      goto leave;
    }

  /* Get the fingerprint.  */
  if (!((item = nvc_lookup (nvc, "fingerprint:"))
        && (value = nve_value (item))
        && strlen (value) >= 40))
    {
      log_error ("received invalid wks message: %s\n",
                 "'fingerprint' missing or invalid");
      err = gpg_error (GPG_ERR_INV_DATA);
      goto leave;
    }
  fingerprint = value;

  /* Check that the fingerprint matches the key used to decrypt the
   * message.  In --read mode or with the old format we don't have the
   * decryption key; thus we can't bail out.  */
  if (!mainfpr || ascii_strcasecmp (mainfpr, fingerprint))
    {
      log_info ("target fingerprint: %s\n", fingerprint);
      log_info ("but decrypted with: %s\n", mainfpr);
      log_error ("confirmation request not decrypted with target key\n");
      if (mainfpr)
        {
          err = gpg_error (GPG_ERR_INV_DATA);
          goto leave;
        }
    }

  /* Get the address.  */
  if (!((item = nvc_lookup (nvc, "address:")) && (value = nve_value (item))
        && is_valid_mailbox (value)))
    {
      log_error ("received invalid wks message: %s\n",
                 "'address' missing or invalid");
      err = gpg_error (GPG_ERR_INV_DATA);
      goto leave;
    }
  address = value;
  /* FIXME: Check that the "address" matches the User ID we want to
   * publish.  */

  /* Get the sender.  */
  if (!((item = nvc_lookup (nvc, "sender:")) && (value = nve_value (item))
        && is_valid_mailbox (value)))
    {
      log_error ("received invalid wks message: %s\n",
                 "'sender' missing or invalid");
      err = gpg_error (GPG_ERR_INV_DATA);
      goto leave;
    }
  sender = value;
  /* FIXME: Check that the "sender" matches the From: address.  */

  /* Get the nonce.  */
  if (!((item = nvc_lookup (nvc, "nonce:")) && (value = nve_value (item))
        && strlen (value) > 16))
    {
      log_error ("received invalid wks message: %s\n",
                 "'nonce' missing or too short");
      err = gpg_error (GPG_ERR_INV_DATA);
      goto leave;
    }
  nonce = value;

  /* Send the confirmation.  If no key was found, try again without
   * encryption.  */
  err = send_confirmation_response (sender, address, nonce, 1, fingerprint);
  if (gpg_err_code (err) == GPG_ERR_NO_PUBKEY)
    {
      log_info ("no encryption key found - sending response in the clear\n");
      err = send_confirmation_response (sender, address, nonce, 0, NULL);
    }

 leave:
  nvc_release (nvc);
  return err;
}


/* Read a confirmation request and decrypt it if needed.  This
 * function may not be used with a mail or MIME message but only with
 * the actual encrypted or plaintext WKS data.  */
static gpg_error_t
read_confirmation_request (estream_t msg)
{
  gpg_error_t err;
  int c;
  estream_t plaintext = NULL;

  /* We take a really simple approach to check whether MSG is
   * encrypted: We know that an encrypted message is always armored
   * and thus starts with a few dashes.  It is even sufficient to
   * check for a single dash, because that can never be a proper first
   * WKS data octet.  We need to skip leading spaces, though. */
  while ((c = es_fgetc (msg)) == ' ' || c == '\t' || c == '\r' || c == '\n')
    ;
  if (c == EOF)
    {
      log_error ("can't process an empty message\n");
      return gpg_error (GPG_ERR_INV_DATA);
    }
  if (es_ungetc (c, msg) != c)
    {
      log_error ("error ungetting octet from message\n");
      return gpg_error (GPG_ERR_INTERNAL);
    }

  if (c != '-')
    err = process_confirmation_request (msg, NULL);
  else
    {
      struct decrypt_stream_parm_s decinfo;

      err = decrypt_stream (&plaintext, &decinfo, msg);
      if (err)
        log_error ("decryption failed: %s\n", gpg_strerror (err));
      else if (decinfo.otrust != 'u')
        {
          err = gpg_error (GPG_ERR_WRONG_SECKEY);
          log_error ("key used to decrypt the confirmation request"
                     " was not generated by us\n");
        }
      else
        err = process_confirmation_request (plaintext, decinfo.mainfpr);
      xfree (decinfo.fpr);
      xfree (decinfo.mainfpr);
    }

  es_fclose (plaintext);
  return err;
}


/* Called from the MIME receiver to process the plain text data in MSG.  */
static gpg_error_t
command_receive_cb (void *opaque, const char *mediatype,
                    estream_t msg, unsigned int flags)
{
  gpg_error_t err;

  (void)opaque;
  (void)flags;

  if (!strcmp (mediatype, "application/vnd.gnupg.wks"))
    err = read_confirmation_request (msg);
  else
    {
      log_info ("ignoring unexpected message of type '%s'\n", mediatype);
      err = gpg_error (GPG_ERR_UNEXPECTED_MSG);
    }

  return err;
}
