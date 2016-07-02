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
 * along with this program; if not, see <http://www.gnu.org/licenses/>.
 */

#include <config.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "util.h"
#include "i18n.h"
#include "sysutils.h"
#include "init.h"
#include "asshelp.h"
#include "userids.h"
#include "ccparray.h"
#include "exectool.h"
#include "mbox-util.h"
#include "name-value.h"
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

    aCreate,
    aReceive,

    oGpgProgram,
    oSend,

    oDummy
  };


/* The list of commands and options. */
static ARGPARSE_OPTS opts[] = {
  ARGPARSE_group (300, ("@Commands:\n ")),

  ARGPARSE_c (aCreate,   "create",
              ("create a publication request")),
  ARGPARSE_c (aReceive,   "receive",
              ("receive a confirmation request")),

  ARGPARSE_group (301, ("@\nOptions:\n ")),

  ARGPARSE_s_n (oVerbose, "verbose", ("verbose")),
  ARGPARSE_s_n (oQuiet,	"quiet",  ("be somewhat more quiet")),
  ARGPARSE_s_s (oDebug, "debug", "@"),
  ARGPARSE_s_s (oGpgProgram, "gpg", "@"),
  ARGPARSE_s_n (oSend, "send", "send the mail using sendmail"),
  ARGPARSE_s_s (oOutput, "output", "|FILE|write the mail to FILE"),


  ARGPARSE_end ()
};


/* The list of supported debug flags.  */
static struct debug_flags_s debug_flags [] =
  {
    { DBG_CRYPTO_VALUE , "crypto"  },
    { DBG_MEMORY_VALUE , "memory"  },
    { DBG_MEMSTAT_VALUE, "memstat" },
    { DBG_IPC_VALUE    , "ipc"     },
    { DBG_EXTPROG_VALUE, "extprog" },
    { 0, NULL }
  };


static void wrong_args (const char *text) GPGRT_ATTR_NORETURN;
static gpg_error_t command_send (const char *fingerprint, char *userid);
static gpg_error_t command_receive_cb (void *opaque,
                                       const char *mediatype, estream_t fp);



/* Print usage information and and provide strings for help. */
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

	case aCreate:
	case aReceive:
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
  setup_libassuan_logging (&opt.debug);

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
    case aCreate:
      if (argc != 2)
        wrong_args ("--create FINGERPRINT USER-ID");
      err = command_send (argv[0], argv[1]);
      if (err)
        log_error ("creating request failed: %s\n", gpg_strerror (err));
      break;

    case aReceive:
      if (argc)
        wrong_args ("--receive");
      err = wks_receive (es_stdin, command_receive_cb, NULL);
      if (err)
        log_error ("processing mail failed: %s\n", gpg_strerror (err));
      break;

    default:
      usage (1);
      break;
    }

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
  const char **argv;
  estream_t key;
  struct get_key_status_parm_s parm;

  (void)addrspec;  /* FIXME - need to use it.  */

  memset (&parm, 0, sizeof parm);

  *r_key = NULL;

  key = es_fopenmem (0, "w+b");
  if (!key)
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
  ccparray_put (&ccp, "--export-options=export-minimal");
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
  char *submission_to = NULL;
  mime_maker_t mime = NULL;

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
  log_debug ("fixme: Check that the key has the requested user-id.\n");

  /* Get the submission address.  */
  err = wkd_get_submission_address (addrspec, &submission_to);
  if (err)
    goto leave;
  log_info ("submitting request to '%s'\n", submission_to);

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

  err = mime_maker_add_header (mime, "Content-type", "application/pgp-keys");
  if (err)
    goto leave;

  err = mime_maker_add_stream (mime, &key);
  if (err)
    goto leave;

  err = wks_send_mime (mime);

 leave:
  mime_maker_release (mime);
  xfree (submission_to);
  es_fclose (key);
  xfree (addrspec);
  return err;
}



static gpg_error_t
send_confirmation_response (const char *sender, const char *address,
                            const char *nonce)
{
  gpg_error_t err;
  estream_t body = NULL;
  /* FIXME: Encrypt and sign the response.  */
  /* estream_t bodyenc = NULL; */
  mime_maker_t mime = NULL;

  body = es_fopenmem (0, "w+b");
  if (!body)
    {
      err = gpg_error_from_syserror ();
      log_error ("error allocating memory buffer: %s\n", gpg_strerror (err));
      return err;
    }
  /* It is fine to use 8 bit encosind because that is encrypted and
   * only our client will see it.  */
  /* es_fputs ("Content-Type: application/vnd.gnupg.wks\n" */
  /*           "Content-Transfer-Encoding: 8bit\n" */
  /*           "\n", */
  /*           body); */

  es_fprintf (body, ("type: confirmation-response\n"
                     "sender: %s\n"
                     "address: %s\n"
                     "nonce: %s\n"),
              sender,
              address,
              nonce);

  es_rewind (body);
  /* err = encrypt_stream (&bodyenc, body, ctx->fpr); */
  /* if (err) */
  /*   goto leave; */
  /* es_fclose (body); */
  /* body = NULL; */


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

  /* err = mime_maker_add_header (mime, "Content-Type", */
  /*                              "multipart/encrypted; " */
  /*                              "protocol=\"application/pgp-encrypted\""); */
  /* if (err) */
  /*   goto leave; */
  /* err = mime_maker_add_container (mime, "multipart/encrypted"); */
  /* if (err) */
  /*   goto leave; */

  /* err = mime_maker_add_header (mime, "Content-Type", */
  /*                              "application/pgp-encrypted"); */
  /* if (err) */
  /*   goto leave; */
  /* err = mime_maker_add_body (mime, "Version: 1\n"); */
  /* if (err) */
  /*   goto leave; */
  /* err = mime_maker_add_header (mime, "Content-Type", */
  /*                              "application/octet-stream"); */
  /* if (err) */
  /*   goto leave; */

  err = mime_maker_add_header (mime, "Content-Type",
                               "application/vnd.gnupg.wks");
  if (err)
    goto leave;

  err = mime_maker_add_stream (mime, &body);
  if (err)
    goto leave;

  err = wks_send_mime (mime);

 leave:
  mime_maker_release (mime);
  /* xfree (bodyenc); */
  xfree (body);
  return err;
}


/* Reply to a confirmation request.  The MSG has already been
 * decrypted and we only need to send the nonce back.  */
static gpg_error_t
process_confirmation_request (estream_t msg)
{
  gpg_error_t err;
  nvc_t nvc;
  nve_t item;
  const char *value, *sender, *address, *nonce;

  err = nvc_parse (&nvc, NULL, msg);
  if (err)
    {
      log_error ("parsing the WKS message failed: %s\n", gpg_strerror (err));
      goto leave;
    }

  if (opt.debug)
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

  /* FIXME: Check that the fingerprint matches the key used to decrypt the
   * message.  */

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

  err = send_confirmation_response (sender, address, nonce);


 leave:
  nvc_release (nvc);
  return err;
}


/* Called from the MIME receiver to process the plain text data in MSG.  */
static gpg_error_t
command_receive_cb (void *opaque, const char *mediatype, estream_t msg)
{
  gpg_error_t err;

  (void)opaque;

  if (!strcmp (mediatype, "application/vnd.gnupg.wks"))
    err = process_confirmation_request (msg);
  else
    {
      log_info ("ignoring unexpected message of type '%s'\n", mediatype);
      err = gpg_error (GPG_ERR_UNEXPECTED_MSG);
    }

  return err;
}
