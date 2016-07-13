/* gpg-wks-server.c - A server for the Web Key Service protocols.
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

/* The Web Key Service I-D defines an update protocol to stpre a
 * public key in the Web Key Directory.  The current specification is
 * draft-koch-openpgp-webkey-service-01.txt.
 */

#include <config.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <dirent.h>

#include "util.h"
#include "init.h"
#include "sysutils.h"
#include "ccparray.h"
#include "exectool.h"
#include "zb32.h"
#include "mbox-util.h"
#include "name-value.h"
#include "mime-maker.h"
#include "send-mail.h"
#include "gpg-wks.h"


/* The time we wait for a confirmation response.  */
#define PENDING_TTL (86400 * 3)  /* 3 days.  */


/* Constants to identify the commands and options. */
enum cmd_and_opt_values
  {
    aNull = 0,

    oQuiet      = 'q',
    oVerbose	= 'v',
    oOutput     = 'o',

    oDebug      = 500,

    aReceive,
    aCron,
    aListDomains,

    oGpgProgram,
    oSend,
    oFrom,
    oHeader,

    oDummy
  };


/* The list of commands and options. */
static ARGPARSE_OPTS opts[] = {
  ARGPARSE_group (300, ("@Commands:\n ")),

  ARGPARSE_c (aReceive,   "receive",
              ("receive a submission or confirmation")),
  ARGPARSE_c (aCron,      "cron",
              ("run regular jobs")),
  ARGPARSE_c (aListDomains, "list-domains",
              ("list configured domains")),

  ARGPARSE_group (301, ("@\nOptions:\n ")),

  ARGPARSE_s_n (oVerbose, "verbose", ("verbose")),
  ARGPARSE_s_n (oQuiet,	"quiet",  ("be somewhat more quiet")),
  ARGPARSE_s_s (oDebug, "debug", "@"),
  ARGPARSE_s_s (oGpgProgram, "gpg", "@"),
  ARGPARSE_s_n (oSend, "send", "send the mail using sendmail"),
  ARGPARSE_s_s (oOutput, "output", "|FILE|write the mail to FILE"),
  ARGPARSE_s_s (oFrom, "from", "|ADDR|use ADDR as the default sender"),
  ARGPARSE_s_s (oHeader, "header" ,
                "|NAME=VALUE|add \"NAME: VALUE\" as header to all mails"),

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


/* State for processing a message.  */
struct server_ctx_s
{
  char *fpr;
  strlist_t mboxes;  /* List of addr-specs taken from the UIDs.  */
};
typedef struct server_ctx_s *server_ctx_t;

/* Prototypes.  */
static gpg_error_t get_domain_list (strlist_t *r_list);

static gpg_error_t command_receive_cb (void *opaque,
                                       const char *mediatype, estream_t fp);
static gpg_error_t command_list_domains (void);
static gpg_error_t command_cron (void);



/* Print usage information and and provide strings for help. */
static const char *
my_strusage( int level )
{
  const char *p;

  switch (level)
    {
    case 11: p = "gpg-wks-server (@GNUPG@)";
      break;
    case 13: p = VERSION; break;
    case 17: p = PRINTABLE_OS_NAME; break;
    case 19: p = ("Please report bugs to <@EMAIL@>.\n"); break;

    case 1:
    case 40:
      p = ("Usage: gpg-wks-server command [options] (-h for help)");
      break;
    case 41:
      p = ("Syntax: gpg-wks-server command [options]\n"
           "Server for the Web Key Service protocol\n");
      break;

    default: p = NULL; break;
    }
  return p;
}


static void
wrong_args (const char *text)
{
  es_fprintf (es_stderr, "usage: %s [options] %s\n", strusage (11), text);
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
        case oFrom:
          opt.default_from = pargs->r.ret_str;
          break;
        case oHeader:
          append_to_strlist (&opt.extra_headers, pargs->r.ret_str);
          break;
        case oSend:
          opt.use_sendmail = 1;
          break;
        case oOutput:
          opt.output = pargs->r.ret_str;
          break;

	case aReceive:
        case aCron:
        case aListDomains:
          cmd = pargs->r_opt;
          break;

        default: pargs->err = 2; break;
	}
    }

  return cmd;
}



/* gpg-wks-server main. */
int
main (int argc, char **argv)
{
  gpg_error_t err;
  ARGPARSE_ARGS pargs;
  enum cmd_and_opt_values cmd;

  gnupg_reopen_std ("gpg-wks-server");
  set_strusage (my_strusage);
  log_set_prefix ("gpg-wks-server", GPGRT_LOG_WITH_PREFIX);

  /* Make sure that our subsystems are ready.  */
  init_common_subsystems (&argc, &argv);

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

  if (!opt.directory)
    opt.directory = "/var/lib/gnupg/wks";

  /* Check for syntax errors in the --header option to avoid later
   * error messages with a not easy to find cause */
  if (opt.extra_headers)
    {
      strlist_t sl;

      for (sl = opt.extra_headers; sl; sl = sl->next)
        {
          err = mime_maker_add_header (NULL, sl->d, NULL);
          if (err)
            log_error ("syntax error in \"--header %s\": %s\n",
                       sl->d, gpg_strerror (err));
        }
    }

  if (log_get_errorcount (0))
    exit (2);


  /* Check that we have a working directory.  */
#if defined(HAVE_STAT)
  {
    struct stat sb;

    if (stat (opt.directory, &sb))
      {
        err = gpg_error_from_syserror ();
        log_error ("error accessing directory '%s': %s\n",
                   opt.directory, gpg_strerror (err));
        exit (2);
      }
    if (!S_ISDIR(sb.st_mode))
      {
        log_error ("error accessing directory '%s': %s\n",
                   opt.directory, "not a directory");
        exit (2);
      }
    if (sb.st_uid != getuid())
      {
        log_error ("directory '%s' not owned by user\n", opt.directory);
        exit (2);
      }
    if ((sb.st_mode & S_IRWXO))
      {
        log_error ("directory '%s' has too relaxed permissions\n",
                   opt.directory);
        exit (2);
      }
  }
#else /*!HAVE_STAT*/
  log_fatal ("program build w/o stat() call\n");
#endif /*!HAVE_STAT*/

  /* Run the selected command.  */
  switch (cmd)
    {
    case aReceive:
      if (argc)
        wrong_args ("--receive");
      err = wks_receive (es_stdin, command_receive_cb, NULL);
      break;

    case aCron:
      if (argc)
        wrong_args ("--cron");
      err = command_cron ();
      break;

    case aListDomains:
      err = command_list_domains ();
      break;

    default:
      usage (1);
      err = gpg_error (GPG_ERR_BUG);
      break;
    }

  if (err)
    log_error ("command failed: %s\n", gpg_strerror (err));
  return log_get_errorcount (0)? 1:0;
}



static void
list_key_status_cb (void *opaque, const char *keyword, char *args)
{
  server_ctx_t ctx = opaque;
  (void)ctx;
  if (opt.debug)
    log_debug ("%s: %s\n", keyword, args);
}


static gpg_error_t
list_key (server_ctx_t ctx, estream_t key)
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
  char *mbox = NULL;

  /* We store our results in the context - clear it first.  */
  xfree (ctx->fpr);
  ctx->fpr = NULL;
  free_strlist (ctx->mboxes);
  ctx->mboxes = NULL;

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
                                list_key_status_cb, ctx);
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

      if (!strcmp (fields[0], "fpr") && nfields > 9 && !ctx->fpr)
        {
          ctx->fpr = xtrystrdup (fields[9]);
          if (!ctx->fpr)
            {
              err = gpg_error_from_syserror ();
              goto leave;
            }
        }
      else if (!strcmp (fields[0], "uid") && nfields > 9)
        {
          /* Fixme: Unescape fields[9] */
          xfree (mbox);
          mbox = mailbox_from_userid (fields[9]);
          if (mbox && !append_to_strlist_try (&ctx->mboxes, mbox))
            {
              err = gpg_error_from_syserror ();
              goto leave;
            }
        }
    }
  if (len < 0 || es_ferror (listing))
    log_error ("error reading memory stream\n");

 leave:
  xfree (mbox);
  xfree (fields);
  es_free (line);
  xfree (argv);
  es_fclose (listing);
  return err;
}


/* Take the key in KEYFILE and write it to DANEFILE using the DANE
 * output format. */
static gpg_error_t
copy_key_as_dane (const char *keyfile, const char *danefile)
{
  gpg_error_t err;
  ccparray_t ccp;
  const char **argv;

  ccparray_init (&ccp, 0);

  ccparray_put (&ccp, "--no-options");
  if (!opt.verbose)
    ccparray_put (&ccp, "--quiet");
  else if (opt.verbose > 1)
    ccparray_put (&ccp, "--verbose");
  ccparray_put (&ccp, "--batch");
  ccparray_put (&ccp, "--yes");
  ccparray_put (&ccp, "--always-trust");
  ccparray_put (&ccp, "--no-keyring");
  ccparray_put (&ccp, "--output");
  ccparray_put (&ccp, danefile);
  ccparray_put (&ccp, "--export-options=export-dane");
  ccparray_put (&ccp, "--import-options=import-export");
  ccparray_put (&ccp, "--import");
  ccparray_put (&ccp, "--");
  ccparray_put (&ccp, keyfile);

  ccparray_put (&ccp, NULL);
  argv = ccparray_get (&ccp, NULL);
  if (!argv)
    {
      err = gpg_error_from_syserror ();
      goto leave;
    }
  err = gnupg_exec_tool_stream (opt.gpg_program, argv, NULL,
                                NULL, NULL, NULL, NULL);
  if (err)
    {
      log_error ("%s failed: %s\n", __func__, gpg_strerror (err));
      goto leave;
    }

 leave:
  xfree (argv);
  return err;
}


static void
encrypt_stream_status_cb (void *opaque, const char *keyword, char *args)
{
  (void)opaque;

  if (opt.debug)
    log_debug ("%s: %s\n", keyword, args);
}


/* Encrypt the INPUT stream to a new stream which is stored at success
 * at R_OUTPUT.  Encryption is done for the key in file KEYFIL.  */
static gpg_error_t
encrypt_stream (estream_t *r_output, estream_t input, const char *keyfile)
{
  gpg_error_t err;
  ccparray_t ccp;
  const char **argv;
  estream_t output;

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
  ccparray_put (&ccp, "--no-keyring");
  ccparray_put (&ccp, "--armor");
  ccparray_put (&ccp, "--recipient-file");
  ccparray_put (&ccp, keyfile);
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
                                encrypt_stream_status_cb, NULL);
  if (err)
    {
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


/* Get the submission address for address MBOX.  Caller must free the
 * value.  If no address can be found NULL is returned.  */
static char *
get_submission_address (const char *mbox)
{
  gpg_error_t err;
  const char *domain;
  char *fname, *line, *p;
  size_t n;
  estream_t fp;

  domain = strchr (mbox, '@');
  if (!domain)
    return NULL;
  domain++;

  fname = make_filename_try (opt.directory, domain, "submission-address", NULL);
  if (!fname)
    {
      err = gpg_error_from_syserror ();
      log_error ("make_filename failed in %s: %s\n",
                 __func__, gpg_strerror (err));
      return NULL;
    }

  fp = es_fopen (fname, "r");
  if (!fp)
    {
      err = gpg_error_from_syserror ();
      if (gpg_err_code (err) == GPG_ERR_ENOENT)
        log_info ("Note: no specific submission address configured"
                  " for domain '%s'\n", domain);
      else
        log_error ("error reading '%s': %s\n", fname, gpg_strerror (err));
      xfree (fname);
      return NULL;
    }

  line = NULL;
  n = 0;
  if (es_getline (&line, &n, fp) < 0)
    {
      err = gpg_error_from_syserror ();
      log_error ("error reading '%s': %s\n", fname, gpg_strerror (err));
      xfree (line);
      es_fclose (fp);
      xfree (fname);
      return NULL;
    }
  es_fclose (fp);
  xfree (fname);

  p = strchr (line, '\n');
  if (p)
    *p = 0;
  trim_spaces (line);
  if (!is_valid_mailbox (line))
    {
      log_error ("invalid submission address for domain '%s' detected\n",
                 domain);
      xfree (line);
      return NULL;
    }

  return line;
}


/* We store the key under the name of the nonce we will then send to
 * the user.  On success the nonce is stored at R_NONCE and the file
 * name at R_FNAME.  */
static gpg_error_t
store_key_as_pending (const char *dir, estream_t key,
                      char **r_nonce, char **r_fname)
{
  gpg_error_t err;
  char *dname = NULL;
  char *fname = NULL;
  char *nonce = NULL;
  estream_t outfp = NULL;
  char buffer[1024];
  size_t nbytes, nwritten;

  *r_nonce = NULL;
  *r_fname = NULL;

  dname = make_filename_try (dir, "pending", NULL);
  if (!dname)
    {
      err = gpg_error_from_syserror ();
      goto leave;
    }

  /* Create the nonce.  We use 20 bytes so that we don't waste a
   * character in our zBase-32 encoding.  Using the gcrypt's nonce
   * function is faster than using the strong random function; this is
   * Good Enough for our purpose.  */
  log_assert (sizeof buffer > 20);
  gcry_create_nonce (buffer, 20);
  nonce = zb32_encode (buffer, 8 * 20);
  memset (buffer, 0, 20);  /* Not actually needed but it does not harm. */
  if (!nonce)
    {
      err = gpg_error_from_syserror ();
      goto leave;
    }

  fname = strconcat (dname, "/", nonce, NULL);
  if (!fname)
    {
      err = gpg_error_from_syserror ();
      goto leave;
    }

  /* With 128 bits of random we can expect that no other file exists
   * under this name.  We use "x" to detect internal errors.  */
  outfp = es_fopen (fname, "wbx,mode=-rw");
  if (!outfp)
    {
      err = gpg_error_from_syserror ();
      log_error ("error creating '%s': %s\n", fname, gpg_strerror (err));
      goto leave;
    }
  es_rewind (key);
  for (;;)
    {
      if (es_read (key, buffer, sizeof buffer, &nbytes))
        {
          err = gpg_error_from_syserror ();
          log_error ("error reading '%s': %s\n",
                     es_fname_get (key), gpg_strerror (err));
          break;
        }

      if (!nbytes)
        {
          err = 0;
          goto leave; /* Ready.  */
        }
      if (es_write (outfp, buffer, nbytes, &nwritten))
        {
          err = gpg_error_from_syserror ();
          log_error ("error writing '%s': %s\n", fname, gpg_strerror (err));
          goto leave;
        }
      else if (nwritten != nbytes)
        {
          err = gpg_error (GPG_ERR_EIO);
          log_error ("error writing '%s': %s\n", fname, "short write");
          goto leave;
        }
    }

 leave:
  if (err)
    {
      es_fclose (outfp);
      gnupg_remove (fname);
    }
  else if (es_fclose (outfp))
    {
      err = gpg_error_from_syserror ();
      log_error ("error closing '%s': %s\n", fname, gpg_strerror (err));
    }

  if (!err)
    {
      *r_nonce = nonce;
      *r_fname = fname;
    }
  else
    {
      xfree (nonce);
      xfree (fname);
    }
  xfree (dname);
  return err;
}


/* Send a confirmation rewqyest.  DIR is the directory used for the
 * address MBOX.  NONCE is the nonce we want to see in the response to
 * this mail.  FNAME the name of the file with the key.  */
static gpg_error_t
send_confirmation_request (server_ctx_t ctx,
                           const char *mbox, const char *nonce,
                           const char *keyfile)
{
  gpg_error_t err;
  estream_t body = NULL;
  estream_t bodyenc = NULL;
  mime_maker_t mime = NULL;
  char *from_buffer = NULL;
  const char *from;
  strlist_t sl;

  from = from_buffer = get_submission_address (mbox);
  if (!from)
    {
      from = opt.default_from;
      if (!from)
        {
          log_error ("no sender address found for '%s'\n", mbox);
          err = gpg_error (GPG_ERR_CONFIGURATION);
          goto leave;
        }
      log_info ("Note: using default sender address '%s'\n", from);
    }

  body = es_fopenmem (0, "w+b");
  if (!body)
    {
      err = gpg_error_from_syserror ();
      log_error ("error allocating memory buffer: %s\n", gpg_strerror (err));
      goto leave;
    }
  /* It is fine to use 8 bit encoding because that is encrypted and
   * only our client will see it.  */
  es_fputs ("Content-Type: application/vnd.gnupg.wks\n"
            "Content-Transfer-Encoding: 8bit\n"
            "\n",
            body);

  es_fprintf (body, ("type: confirmation-request\n"
                     "sender: %s\n"
                     "address: %s\n"
                     "fingerprint: %s\n"
                     "nonce: %s\n"),
              from,
              mbox,
              ctx->fpr,
              nonce);

  es_rewind (body);
  err = encrypt_stream (&bodyenc, body, keyfile);
  if (err)
    goto leave;
  es_fclose (body);
  body = NULL;


  err = mime_maker_new (&mime, NULL);
  if (err)
    goto leave;
  err = mime_maker_add_header (mime, "From", from);
  if (err)
    goto leave;
  err = mime_maker_add_header (mime, "To", mbox);
  if (err)
    goto leave;
  err = mime_maker_add_header (mime, "Subject", "Confirm your key publication");
  if (err)
    goto leave;
  for (sl = opt.extra_headers; sl; sl = sl->next)
    {
      err = mime_maker_add_header (mime, sl->d, NULL);
      if (err)
        goto leave;
    }

  err = mime_maker_add_header (mime, "Content-Type",
                               "multipart/encrypted; "
                               "protocol=\"application/pgp-encrypted\"");
  if (err)
    goto leave;
  err = mime_maker_add_container (mime, "multipart/encrypted");
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

  err = wks_send_mime (mime);

 leave:
  mime_maker_release (mime);
  es_fclose (bodyenc);
  es_fclose (body);
  xfree (from_buffer);
  return err;
}


/* Store the key given by KEY into the pending directory and send a
 * confirmation requests.  */
static gpg_error_t
process_new_key (server_ctx_t ctx, estream_t key)
{
  gpg_error_t err;
  strlist_t sl;
  const char *s;
  char *dname = NULL;
  char *nonce = NULL;
  char *fname = NULL;

  /* First figure out the user id from the key.  */
  err = list_key (ctx, key);
  if (err)
    goto leave;
  if (!ctx->fpr)
    {
      log_error ("error parsing key (no fingerprint)\n");
      err = gpg_error (GPG_ERR_NO_PUBKEY);
      goto leave;
    }
  log_info ("fingerprint: %s\n", ctx->fpr);
  for (sl = ctx->mboxes; sl; sl = sl->next)
    {
      log_info ("  addr-spec: %s\n", sl->d);
    }

  /* Walk over all user ids and send confirmation requests for those
   * we support.  */
  for (sl = ctx->mboxes; sl; sl = sl->next)
    {
      s = strchr (sl->d, '@');
      log_assert (s && s[1]);
      xfree (dname);
      dname = make_filename_try (opt.directory, s+1, NULL);
      if (!dname)
        {
          err = gpg_error_from_syserror ();
          goto leave;
        }
      /* Fixme: check for proper directory permissions.  */
      if (access (dname, W_OK))
        {
          log_info ("skipping address '%s': Domain not configured\n", sl->d);
          continue;
        }
      log_info ("storing address '%s'\n", sl->d);

      xfree (nonce);
      xfree (fname);
      err = store_key_as_pending (dname, key, &nonce, &fname);
      if (err)
        goto leave;

      err = send_confirmation_request (ctx, sl->d, nonce, fname);
      if (err)
        goto leave;
    }

 leave:
  if (nonce)
    wipememory (nonce, strlen (nonce));
  xfree (nonce);
  xfree (fname);
  xfree (dname);
  return err;
}



/* Check that we have send a request with NONCE and publish the key.  */
static gpg_error_t
check_and_publish (server_ctx_t ctx, const char *address, const char *nonce)
{
  gpg_error_t err;
  char *fname = NULL;
  char *fnewname = NULL;
  estream_t key = NULL;
  char *hash = NULL;
  const char *domain;
  const char *s;
  strlist_t sl;
  char shaxbuf[32]; /* Used for SHA-1 and SHA-256 */

  /* FIXME: There is a bug in name-value.c which adds white space for
   * the last pair and thus we strip the nonce here until this has
   * been fixed.  */
  char *nonce2 = xstrdup (nonce);
  trim_trailing_spaces (nonce2);
  nonce = nonce2;


  domain = strchr (address, '@');
  log_assert (domain && domain[1]);
  domain++;
  fname = make_filename_try (opt.directory, domain, "pending", nonce, NULL);
  if (!fname)
    {
      err = gpg_error_from_syserror ();
      goto leave;
    }

  /* Try to open the file with the key.  */
  key = es_fopen (fname, "rb");
  if (!key)
    {
      err = gpg_error_from_syserror ();
      if (gpg_err_code (err) == GPG_ERR_ENOENT)
        {
          log_info ("no pending request for '%s'\n", address);
          err = gpg_error (GPG_ERR_NOT_FOUND);
        }
      else
        log_error ("error reading '%s': %s\n", fname, gpg_strerror (err));
      goto leave;
    }

  /* We need to get the fingerprint from the key.  */
  err = list_key (ctx, key);
  if (err)
    goto leave;
  if (!ctx->fpr)
    {
      log_error ("error parsing key (no fingerprint)\n");
      err = gpg_error (GPG_ERR_NO_PUBKEY);
      goto leave;
    }
  log_info ("fingerprint: %s\n", ctx->fpr);
  for (sl = ctx->mboxes; sl; sl = sl->next)
    log_info ("  addr-spec: %s\n", sl->d);

  /* Check that the key has 'address' as a user id.  We use
   * case-insensitive matching because the client is expected to
   * return the address verbatim.  */
  for (sl = ctx->mboxes; sl; sl = sl->next)
    if (!strcmp (sl->d, address))
      break;
  if (!sl)
    {
      log_error ("error publishing key: '%s' is not a user ID of %s\n",
                 address, ctx->fpr);
      err = gpg_error (GPG_ERR_NO_PUBKEY);
      goto leave;
    }


  /* Hash user ID and create filename.  */
  s = strchr (address, '@');
  log_assert (s);
  gcry_md_hash_buffer (GCRY_MD_SHA1, shaxbuf, address, s - address);
  hash = zb32_encode (shaxbuf, 8*20);
  if (!hash)
    {
      err = gpg_error_from_syserror ();
      goto leave;
    }

  fnewname = make_filename_try (opt.directory, domain, "hu", hash, NULL);
  if (!fnewname)
    {
      err = gpg_error_from_syserror ();
      goto leave;
    }

  /* Publish.  */
  if (rename (fname, fnewname))
    {
      err = gpg_error_from_syserror ();
      log_error ("renaming '%s' to '%s' failed: %s\n",
                 fname, fnewname, gpg_strerror (err));
      goto leave;
    }

  log_info ("key %s published for '%s'\n", ctx->fpr, address);


  /* Try to publish as DANE record if the DANE directory exists.  */
  xfree (fname);
  fname = fnewname;
  fnewname = make_filename_try (opt.directory, domain, "dane", NULL);
  if (!fnewname)
    {
      err = gpg_error_from_syserror ();
      goto leave;
    }
  if (!access (fnewname, W_OK))
    {
      /* Yes, we have a dane directory.  */
      s = strchr (address, '@');
      log_assert (s);
      gcry_md_hash_buffer (GCRY_MD_SHA256, shaxbuf, address, s - address);
      xfree (hash);
      hash = bin2hex (shaxbuf, 28, NULL);
      if (!hash)
        {
          err = gpg_error_from_syserror ();
          goto leave;
        }
      xfree (fnewname);
      fnewname = make_filename_try (opt.directory, domain, "dane", hash, NULL);
      if (!fnewname)
        {
          err = gpg_error_from_syserror ();
          goto leave;
        }
      err = copy_key_as_dane (fname, fnewname);
      if (err)
        goto leave;
      log_info ("key %s published for '%s' (DANE record)\n", ctx->fpr, address);
    }


 leave:
  es_fclose (key);
  xfree (hash);
  xfree (fnewname);
  xfree (fname);
  xfree (nonce2);
  return err;
}


/* Process a confirmation response in MSG.  */
static gpg_error_t
process_confirmation_response (server_ctx_t ctx, estream_t msg)
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
      log_debug ("response follows:\n");
      nvc_write (nvc, log_get_stream ());
    }

  /* Check that this is a confirmation response.  */
  if (!((item = nvc_lookup (nvc, "type:")) && (value = nve_value (item))
        && !strcmp (value, "confirmation-response")))
    {
      if (item && value)
        log_error ("received unexpected wks message '%s'\n", value);
      else
        log_error ("received invalid wks message: %s\n", "'type' missing");
      err = gpg_error (GPG_ERR_UNEXPECTED_MSG);
      goto leave;
    }

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
  (void)sender;
  /* FIXME: Do we really need the sender?.  */

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

  err = check_and_publish (ctx, address, nonce);


 leave:
  nvc_release (nvc);
  return err;
}



/* Called from the MIME receiver to process the plain text data in MSG .  */
static gpg_error_t
command_receive_cb (void *opaque, const char *mediatype, estream_t msg)
{
  gpg_error_t err;
  struct server_ctx_s ctx;

  memset (&ctx, 0, sizeof ctx);

  (void)opaque;

  if (!strcmp (mediatype, "application/pgp-keys"))
    err = process_new_key (&ctx, msg);
  else if (!strcmp (mediatype, "application/vnd.gnupg.wks"))
    err = process_confirmation_response (&ctx, msg);
  else
    {
      log_info ("ignoring unexpected message of type '%s'\n", mediatype);
      err = gpg_error (GPG_ERR_UNEXPECTED_MSG);
    }

  xfree (ctx.fpr);
  free_strlist (ctx.mboxes);

  return err;
}



/* Return a list of all configured domains.  ECh list element is the
 * top directory for for the domain.  To figure out the actual domain
 * name strrchr(name, '/') can be used.  */
static gpg_error_t
get_domain_list (strlist_t *r_list)
{
  gpg_error_t err;
  DIR *dir = NULL;
  char *fname = NULL;
  struct dirent *dentry;
  struct stat sb;
  strlist_t list = NULL;

  *r_list = NULL;

  dir = opendir (opt.directory);
  if (!dir)
    {
      err = gpg_error_from_syserror ();
      goto leave;
    }

  while ((dentry = readdir (dir)))
    {
      if (*dentry->d_name == '.')
        continue;
      if (!strchr (dentry->d_name, '.'))
        continue; /* No dot - can't be a domain subdir.  */

      xfree (fname);
      fname = make_filename_try (opt.directory, dentry->d_name, NULL);
      if (!fname)
        {
          err = gpg_error_from_syserror ();
          log_error ("make_filename failed in %s: %s\n",
                     __func__, gpg_strerror (err));
          goto leave;
        }

      if (stat (fname, &sb))
        {
          err = gpg_error_from_syserror ();
          log_error ("error accessing '%s': %s\n", fname, gpg_strerror (err));
          continue;
        }
      if (!S_ISDIR(sb.st_mode))
        continue;

      if (!add_to_strlist_try (&list, fname))
        {
          err = gpg_error_from_syserror ();
          log_error ("add_to_strlist failed in %s: %s\n",
                     __func__, gpg_strerror (err));
          goto leave;
        }
    }
  err = 0;
  *r_list = list;
  list = NULL;

 leave:
  free_strlist (list);
  if (dir)
    closedir (dir);
  xfree (fname);
  return err;
}



static gpg_error_t
expire_one_domain (const char *top_dirname, const char *domain)
{
  gpg_error_t err;
  char *dirname;
  char *fname = NULL;
  DIR *dir = NULL;
  struct dirent *dentry;
  struct stat sb;
  time_t now = gnupg_get_time ();

  dirname = make_filename_try (top_dirname, "pending", NULL);
  if (!dirname)
    {
      err = gpg_error_from_syserror ();
      log_error ("make_filename failed in %s: %s\n",
                 __func__, gpg_strerror (err));
      goto leave;
    }

  dir = opendir (dirname);
  if (!dir)
    {
      err = gpg_error_from_syserror ();
      log_error (("can't access directory '%s': %s\n"),
                 dirname, gpg_strerror (err));
      goto leave;
    }

  while ((dentry = readdir (dir)))
    {
      if (*dentry->d_name == '.')
        continue;
      xfree (fname);
      fname = make_filename_try (dirname, dentry->d_name, NULL);
      if (!fname)
        {
          err = gpg_error_from_syserror ();
          log_error ("make_filename failed in %s: %s\n",
                     __func__, gpg_strerror (err));
          goto leave;
        }
      if (strlen (dentry->d_name) != 32)
        {
          log_info ("garbage file '%s' ignored\n", fname);
          continue;
        }
      if (stat (fname, &sb))
        {
          err = gpg_error_from_syserror ();
          log_error ("error accessing '%s': %s\n", fname, gpg_strerror (err));
          continue;
        }
      if (S_ISDIR(sb.st_mode))
        {
          log_info ("garbage directory '%s' ignored\n", fname);
          continue;
        }
      if (sb.st_mtime + PENDING_TTL < now)
        {
          if (opt.verbose)
            log_info ("domain %s: removing pending key '%s'\n",
                      domain, dentry->d_name);
          if (remove (fname))
            {
              err = gpg_error_from_syserror ();
              /* In case the file has just been renamed or another
               * processes is cleaning up, we don't print a diagnostic
               * for ENOENT.  */
              if (gpg_err_code (err) != GPG_ERR_ENOENT)
                log_error ("error removing '%s': %s\n",
                           fname, gpg_strerror (err));
            }
        }
    }
  err = 0;

 leave:
  if (dir)
    closedir (dir);
  xfree (dirname);
  xfree (fname);
  return err;

}


/* Scan spool directories and expire too old pending keys.  */
static gpg_error_t
expire_pending_confirmations (strlist_t domaindirs)
{
  gpg_error_t err = 0;
  strlist_t sl;
  const char *domain;

  for (sl = domaindirs; sl; sl = sl->next)
    {
      domain = strrchr (sl->d, '/');
      log_assert (domain);
      domain++;

      expire_one_domain (sl->d, domain);
    }

  return err;
}


/* List all configured domains.  */
static gpg_error_t
command_list_domains (void)
{
  static struct {
    const char *name;
    const char *perm;
  } requireddirs[] = {
    { "pending", "-rwx" },
    { "hu",      "-rwxr-xr-x" }
  };

  gpg_error_t err;
  strlist_t domaindirs;
  strlist_t sl;
  const char *domain;
  char *fname = NULL;
  int i;

  err = get_domain_list (&domaindirs);
  if (err)
    {
      log_error ("error reading list of domains: %s\n", gpg_strerror (err));
      return err;
    }

  for (sl = domaindirs; sl; sl = sl->next)
    {
      domain = strrchr (sl->d, '/');
      log_assert (domain);
      domain++;
      es_printf ("%s\n", domain);

      /* Check that the required directories are there.  */
      for (i=0; i < DIM (requireddirs); i++)
        {
          xfree (fname);
          fname = make_filename_try (sl->d, requireddirs[i].name, NULL);
          if (!fname)
            {
              err = gpg_error_from_syserror ();
              goto leave;
            }
          if (access (fname, W_OK))
            {
              err = gpg_error_from_syserror ();
              if (gpg_err_code (err) == GPG_ERR_ENOENT)
                {
                  if (gnupg_mkdir (fname, requireddirs[i].perm))
                    {
                      err = gpg_error_from_syserror ();
                      log_error ("domain %s: error creating subdir '%s': %s\n",
                                 domain, requireddirs[i].name,
                                 gpg_strerror (err));
                    }
                  else
                    log_info ("domain %s: subdir '%s' created\n",
                              domain, requireddirs[i].name);
                }
              else if (err)
                log_error ("domain %s: problem with subdir '%s': %s\n",
                           domain, requireddirs[i].name, gpg_strerror (err));
            }
        }

      /* Print a warning if the sumbission address is not configured.  */
      xfree (fname);
      fname = make_filename_try (sl->d, "submission-address", NULL);
      if (!fname)
        {
          err = gpg_error_from_syserror ();
          goto leave;
        }
      if (access (fname, F_OK))
        {
          err = gpg_error_from_syserror ();
          if (gpg_err_code (err) == GPG_ERR_ENOENT)
            log_error ("domain %s: submission address not configured\n",
                       domain);
          else
            log_error ("domain %s: problem with '%s': %s\n",
                       domain, fname, gpg_strerror (err));
        }
    }
  err = 0;

 leave:
  xfree (fname);
  free_strlist (domaindirs);
  return err;
}


/* Run regular maintenance jobs.  */
static gpg_error_t
command_cron (void)
{
  gpg_error_t err;
  strlist_t domaindirs;

  err = get_domain_list (&domaindirs);
  if (err)
    {
      log_error ("error reading list of domains: %s\n", gpg_strerror (err));
      return err;
    }

  err = expire_pending_confirmations (domaindirs);

  free_strlist (domaindirs);
  return err;
}
