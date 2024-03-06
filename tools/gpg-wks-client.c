/* gpg-wks-client.c - A client for the Web Key Service protocols.
 * Copyright (C) 2016, 2022 g10 Code GmbH
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
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with this program; if not, see <https://www.gnu.org/licenses/>.
 * SPDX-License-Identifier: LGPL-2.1-or-later
 */

#include <config.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>

#define INCLUDED_BY_MAIN_MODULE 1
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
    oDirectory  = 'C',

    oDebug      = 500,

    aSupported,
    aCheck,
    aCreate,
    aReceive,
    aRead,
    aMirror,
    aInstallKey,
    aRemoveKey,
    aPrintWKDHash,
    aPrintWKDURL,

    oGpgProgram,
    oSend,
    oFakeSubmissionAddr,
    oStatusFD,
    oWithColons,
    oBlacklist,
    oNoAutostart,
    oAddRevocs,
    oNoAddRevocs,

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
  ARGPARSE_c (aMirror, "mirror",
              "mirror an LDAP directory"),
  ARGPARSE_c (aInstallKey, "install-key",
              "install a key into a directory"),
  ARGPARSE_c (aRemoveKey, "remove-key",
              "remove a key from a directory"),
  ARGPARSE_c (aPrintWKDHash, "print-wkd-hash",
              "print the WKD identifier for the given user ids"),
  ARGPARSE_c (aPrintWKDURL, "print-wkd-url",
              "print the WKD URL for the given user id"),

  ARGPARSE_group (301, ("@\nOptions:\n ")),

  ARGPARSE_s_n (oVerbose, "verbose", ("verbose")),
  ARGPARSE_s_n (oQuiet,	"quiet",  ("be somewhat more quiet")),
  ARGPARSE_s_s (oDebug, "debug", "@"),
  ARGPARSE_s_s (oGpgProgram, "gpg", "@"),
  ARGPARSE_s_n (oSend, "send", "send the mail using sendmail"),
  ARGPARSE_s_s (oOutput, "output", "|FILE|write the mail to FILE"),
  ARGPARSE_s_i (oStatusFD, "status-fd", N_("|FD|write status info to this FD")),
  ARGPARSE_s_n (oNoAutostart, "no-autostart", "@"),
  ARGPARSE_s_n (oWithColons, "with-colons", "@"),
  ARGPARSE_s_s (oBlacklist, "blacklist", "@"),
  ARGPARSE_s_s (oDirectory, "directory", "@"),
  ARGPARSE_s_n (oAddRevocs, "add-revocs", "add revocation certificates"),
  ARGPARSE_s_n (oNoAddRevocs, "no-add-revocs", "do not add revocation certificates"),

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

/* An array with blacklisted addresses and its length.  Use
 * is_in_blacklist to check.  */
static char **blacklist_array;
static size_t blacklist_array_len;


static void wrong_args (const char *text) GPGRT_ATTR_NORETURN;
static void add_blacklist (const char *fname);
static gpg_error_t proc_userid_from_stdin (gpg_error_t (*func)(const char *),
                                           const char *text);
static gpg_error_t command_supported (char *userid);
static gpg_error_t command_check (char *userid);
static gpg_error_t command_create (const char *fingerprint, const char *userid);
static gpg_error_t encrypt_response (estream_t *r_output, estream_t input,
                                     const char *addrspec,
                                     const char *fingerprint);
static gpg_error_t read_confirmation_request (estream_t msg);
static gpg_error_t command_receive_cb (void *opaque,
                                       const char *mediatype, estream_t fp,
                                       unsigned int flags);
static gpg_error_t command_mirror (char *domain[]);



/* Print usage information and provide strings for help. */
static const char *
my_strusage( int level )
{
  const char *p;

  switch (level)
    {
    case  9: p = "LGPL-2.1-or-later"; break;
    case 11: p = "gpg-wks-client"; break;
    case 12: p = "@GNUPG@"; break;
    case 13: p = VERSION; break;
    case 14: p = GNUPG_DEF_COPYRIGHT_LINE; break;
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

  while (!no_more_options && gnupg_argparse (NULL, pargs, popts))
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
        case oDirectory:
          opt.directory = pargs->r.ret_str;
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
        case oWithColons:
          opt.with_colons = 1;
          break;
        case oNoAutostart:
          opt.no_autostart = 1;
          break;
        case oBlacklist:
          add_blacklist (pargs->r.ret_str);
          break;
        case oAddRevocs:
          opt.add_revocs = 1;
          break;
        case oNoAddRevocs:
          opt.add_revocs = 0;
          break;

	case aSupported:
	case aCreate:
	case aReceive:
	case aRead:
        case aCheck:
        case aMirror:
        case aInstallKey:
        case aRemoveKey:
        case aPrintWKDHash:
        case aPrintWKDURL:
          cmd = pargs->r_opt;
          break;

        default: pargs->err = ARGPARSE_PRINT_ERROR; break;
	}
    }

  return cmd;
}



/* gpg-wks-client main. */
int
main (int argc, char **argv)
{
  gpg_error_t err, delayed_err;
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

  opt.add_revocs = 1;  /* Default add revocation certs.  */

  /* Parse the command line. */
  pargs.argc  = &argc;
  pargs.argv  = &argv;
  pargs.flags = ARGPARSE_FLAG_KEEP;
  cmd = parse_arguments (&pargs, opts);
  gnupg_argparse (NULL, &pargs, NULL);

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
    opt.directory = "openpgpkey";

  /* Tell call-dirmngr what options we want.  */
  set_dirmngr_options (opt.verbose, (opt.debug & DBG_IPC_VALUE),
                       !opt.no_autostart);


  /* Check that the top directory exists.  */
  if (cmd == aInstallKey || cmd == aRemoveKey || cmd == aMirror)
    {
      struct stat sb;

      if (gnupg_stat (opt.directory, &sb))
        {
          err = gpg_error_from_syserror ();
          log_error ("error accessing directory '%s': %s\n",
                     opt.directory, gpg_strerror (err));
          goto leave;
        }
      if (!S_ISDIR(sb.st_mode))
        {
          log_error ("error accessing directory '%s': %s\n",
                     opt.directory, "not a directory");
          err = gpg_error (GPG_ERR_ENOENT);
          goto leave;
        }
    }

  /* Run the selected command.  */
  switch (cmd)
    {
    case aSupported:
      if (opt.with_colons)
        {
          for (; argc; argc--, argv++)
            command_supported (*argv);
          err = 0;
        }
      else
        {
          if (argc != 1)
            wrong_args ("--supported DOMAIN");
          err = command_supported (argv[0]);
          if (err && gpg_err_code (err) != GPG_ERR_FALSE)
            log_error ("checking support failed: %s\n", gpg_strerror (err));
        }
      break;

    case aCreate:
      if (argc != 2)
        wrong_args ("--create FINGERPRINT USER-ID");
      err = command_create (argv[0], argv[1]);
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

    case aMirror:
      if (!argc)
        err = command_mirror (NULL);
      else
        err = command_mirror (argv);
      break;

    case aInstallKey:
      if (!argc)
        err = wks_cmd_install_key (NULL, NULL);
      else if (argc == 2)
        err = wks_cmd_install_key (*argv, argv[1]);
      else
        wrong_args ("--install-key [FILE|FINGERPRINT USER-ID]");
      break;

    case aRemoveKey:
      if (argc != 1)
        wrong_args ("--remove-key USER-ID");
      err = wks_cmd_remove_key (*argv);
      break;

    case aPrintWKDHash:
    case aPrintWKDURL:
      if (!argc)
        {
          if (cmd == aPrintWKDHash)
            err = proc_userid_from_stdin (wks_cmd_print_wkd_hash,
                                          "printing WKD hash");
          else
            err = proc_userid_from_stdin (wks_cmd_print_wkd_url,
                                          "printing WKD URL");
        }
      else
        {
          for (err = delayed_err = 0; !err && argc; argc--, argv++)
            {
              if (cmd == aPrintWKDHash)
                err = wks_cmd_print_wkd_hash (*argv);
              else
                err = wks_cmd_print_wkd_url (*argv);
              if (gpg_err_code (err) == GPG_ERR_INV_USER_ID)
                {
                  /* Diagnostic already printed.  */
                  delayed_err = err;
                  err = 0;
                }
              else if (err)
                log_error ("printing hash failed: %s\n", gpg_strerror (err));
            }
          if (!err)
            err = delayed_err;
        }
      break;

    default:
      usage (1);
      err = 0;
      break;
    }

 leave:
  if (err)
    wks_write_status (STATUS_FAILURE, "- %u", err);
  else if (log_get_errorcount (0))
    wks_write_status (STATUS_FAILURE, "- %u", GPG_ERR_GENERAL);
  else
    wks_write_status (STATUS_SUCCESS, NULL);
  return (err || log_get_errorcount (0))? 1:0;
}



/* Read a file FNAME into a buffer and return that malloced buffer.
 * Caller must free the buffer.  On error NULL is returned, on success
 * the valid length of the buffer is stored at R_LENGTH.  The returned
 * buffer is guaranteed to be Nul terminated.  */
static char *
read_file (const char *fname, size_t *r_length)
{
  estream_t fp;
  char *buf;
  size_t buflen;

  if (!strcmp (fname, "-"))
    {
      size_t nread, bufsize = 0;

      fp = es_stdin;
      es_set_binary (fp);
      buf = NULL;
      buflen = 0;
#define NCHUNK 32767
      do
        {
          bufsize += NCHUNK;
          if (!buf)
            buf = xmalloc (bufsize+1);
          else
            buf = xrealloc (buf, bufsize+1);

          nread = es_fread (buf+buflen, 1, NCHUNK, fp);
          if (nread < NCHUNK && es_ferror (fp))
            {
              log_error ("error reading '[stdin]': %s\n", strerror (errno));
              xfree (buf);
              return NULL;
            }
          buflen += nread;
        }
      while (nread == NCHUNK);
#undef NCHUNK
    }
  else
    {
      struct stat st;

      fp = es_fopen (fname, "rb");
      if (!fp)
        {
          log_error ("can't open '%s': %s\n", fname, strerror (errno));
          return NULL;
        }

      if (fstat (es_fileno (fp), &st))
        {
          log_error ("can't stat '%s': %s\n", fname, strerror (errno));
          es_fclose (fp);
          return NULL;
        }

      buflen = st.st_size;
      buf = xmalloc (buflen+1);
      if (es_fread (buf, buflen, 1, fp) != 1)
        {
          log_error ("error reading '%s': %s\n", fname, strerror (errno));
          es_fclose (fp);
          xfree (buf);
          return NULL;
        }
      es_fclose (fp);
    }
  buf[buflen] = 0;
  if (r_length)
    *r_length = buflen;
  return buf;
}


static int
cmp_blacklist (const void *arg_a, const void *arg_b)
{
  const char *a = *(const char **)arg_a;
  const char *b = *(const char **)arg_b;
  return strcmp (a, b);
}


/* Add a blacklist to our global table.  This is called during option
 * parsing and thus any use of log_error will eventually stop further
 * processing.  */
static void
add_blacklist (const char *fname)
{
  char *buffer;
  char *p, *pend;
  char **array;
  size_t arraysize, arrayidx;

  buffer = read_file (fname, NULL);
  if (!buffer)
    return;

  /* Estimate the number of entries by counting the non-comment lines.  */
  arraysize = 2; /* For the first and an extra NULL item.  */
  for (p=buffer; *p; p++)
    if (*p == '\n' && p[1] && p[1] != '#')
      arraysize++;

  array = xcalloc (arraysize, sizeof *array);
  arrayidx = 0;

  /* Loop over all lines.  */
  for (p = buffer; p && *p; p = pend)
    {
      pend = strchr (p, '\n');
      if (pend)
        *pend++ = 0;
      trim_spaces (p);
      if (!*p || *p == '#' )
        continue;
      ascii_strlwr (p);
      log_assert (arrayidx < arraysize);
      array[arrayidx] = p;
      arrayidx++;
    }
  log_assert (arrayidx < arraysize);

  qsort (array, arrayidx, sizeof *array, cmp_blacklist);

  blacklist_array = array;
  blacklist_array_len = arrayidx;
  gpgrt_annotate_leaked_object (buffer);
  gpgrt_annotate_leaked_object (blacklist_array);
}


/* Return true if NAME is in a blacklist.  */
static int
is_in_blacklist (const char *name)
{
  if (!name || !blacklist_array)
    return 0;
  return !!bsearch (&name, blacklist_array, blacklist_array_len,
                    sizeof *blacklist_array, cmp_blacklist);
}



/* Read user ids from stdin and call FUNC for each user id.  TEXT is
 * used for error messages.  */
static gpg_error_t
proc_userid_from_stdin (gpg_error_t (*func)(const char *), const char *text)
{
  gpg_error_t err = 0;
  gpg_error_t delayed_err = 0;
  char line[2048];
  size_t n = 0;

  /* If we are on a terminal disable buffering to get direct response.  */
  if (gnupg_isatty (es_fileno (es_stdin))
      && gnupg_isatty (es_fileno (es_stdout)))
    {
      es_setvbuf (es_stdin, NULL, _IONBF, 0);
      es_setvbuf (es_stdout, NULL, _IOLBF, 0);
    }

  while (es_fgets (line, sizeof line - 1, es_stdin))
    {
      n = strlen (line);
      if (!n || line[n-1] != '\n')
        {
          err = gpg_error (*line? GPG_ERR_LINE_TOO_LONG
                           : GPG_ERR_INCOMPLETE_LINE);
          log_error ("error reading stdin: %s\n", gpg_strerror (err));
          break;
        }
      trim_spaces (line);
      err = func (line);
      if (gpg_err_code (err) == GPG_ERR_INV_USER_ID)
        {
          delayed_err = err;
          err = 0;
        }
      else if (err)
        log_error ("%s failed: %s\n", text, gpg_strerror (err));
    }
  if (es_ferror (es_stdin))
    {
      err = gpg_error_from_syserror ();
      log_error ("error reading stdin: %s\n", gpg_strerror (err));
      goto leave;
    }

 leave:
  if (!err)
    err = delayed_err;
  return err;
}




/* Add the user id UID to the key identified by FINGERPRINT.  */
static gpg_error_t
add_user_id (const char *fingerprint, const char *uid)
{
  gpg_error_t err;
  ccparray_t ccp;
  const char **argv = NULL;

  ccparray_init (&ccp, 0);

  ccparray_put (&ccp, "--no-options");
  if (opt.verbose < 2)
    ccparray_put (&ccp, "--quiet");
  else
    ccparray_put (&ccp, "--verbose");
  ccparray_put (&ccp, "--batch");
  ccparray_put (&ccp, "--always-trust");
  ccparray_put (&ccp, "--quick-add-uid");
  ccparray_put (&ccp, fingerprint);
  ccparray_put (&ccp, uid);

  ccparray_put (&ccp, NULL);
  argv = ccparray_get (&ccp, NULL);
  if (!argv)
    {
      err = gpg_error_from_syserror ();
      goto leave;
    }
  err = gnupg_exec_tool_stream (opt.gpg_program, argv, NULL,
                                NULL, NULL,
                                NULL, NULL);
  if (err)
    {
      log_error ("adding user id failed: %s\n", gpg_strerror (err));
      goto leave;
    }

 leave:
  xfree (argv);
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
  if (opt.verbose < 2)
    ccparray_put (&ccp, "--quiet");
  else
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


/* Return the submission address for the address or just the domain in
 * ADDRSPEC.  The submission address is stored as a malloced string at
 * R_SUBMISSION_ADDRESS.  At R_POLICY the policy flags of the domain
 * are stored.  The caller needs to free them with wks_free_policy.
 * The function returns an error code on failure to find a submission
 * address or policy file.  Note: The function may store NULL at
 * R_SUBMISSION_ADDRESS but return success to indicate that the web
 * key directory is supported but not the web key service.  As per WKD
 * specs a policy file is always required and will thus be return on
 * success.  */
static gpg_error_t
get_policy_and_sa (const char *addrspec, int silent,
                   policy_flags_t *r_policy, char **r_submission_address)
{
  gpg_error_t err;
  estream_t mbuf = NULL;
  const char *domain;
  const char *s;
  policy_flags_t policy = NULL;
  char *submission_to = NULL;

  *r_submission_address = NULL;
  *r_policy = NULL;

  domain = strchr (addrspec, '@');
  if (domain)
    domain++;

  if (opt.with_colons)
    {
      s = domain? domain : addrspec;
      es_write_sanitized (es_stdout, s, strlen (s), ":", NULL);
      es_putc (':', es_stdout);
    }

  /* We first try to get the submission address from the policy file
   * (this is the new method).  If both are available we check that
   * they match and print a warning if not.  In the latter case we
   * keep on using the one from the submission-address file.    */
  err = wkd_get_policy_flags (addrspec, &mbuf);
  if (err && gpg_err_code (err) != GPG_ERR_NO_DATA
      && gpg_err_code (err) != GPG_ERR_NO_NAME)
    {
      if (!opt.with_colons)
        log_error ("error reading policy flags for '%s': %s\n",
                   domain, gpg_strerror (err));
      goto leave;
    }
  if (!mbuf)
    {
      if (!opt.with_colons)
        log_error ("provider for '%s' does NOT support the Web Key Directory\n",
                   addrspec);
      err = gpg_error (GPG_ERR_FALSE);
      goto leave;
    }

  policy = xtrycalloc (1, sizeof *policy);
  if (!policy)
    err = gpg_error_from_syserror ();
  else
    err = wks_parse_policy (policy, mbuf, 1);
  es_fclose (mbuf);
  mbuf = NULL;
  if (err)
    goto leave;

  err = wkd_get_submission_address (addrspec, &submission_to);
  if (err && !policy->submission_address)
    {
      if (!silent && !opt.with_colons)
        log_error (_("error looking up submission address for domain '%s'"
                     ": %s\n"), domain, gpg_strerror (err));
      if (!silent && gpg_err_code (err) == GPG_ERR_NO_DATA && !opt.with_colons)
        log_error (_("this domain probably doesn't support WKS.\n"));
      goto leave;
    }

  if (submission_to && policy->submission_address
      && ascii_strcasecmp (submission_to, policy->submission_address))
    log_info ("Warning: different submission addresses (sa=%s, po=%s)\n",
              submission_to, policy->submission_address);

  if (!submission_to && policy->submission_address)
    {
      submission_to = xtrystrdup (policy->submission_address);
      if (!submission_to)
        {
          err = gpg_error_from_syserror ();
          goto leave;
        }
    }

 leave:
  *r_submission_address = submission_to;
  submission_to = NULL;
  *r_policy = policy;
  policy = NULL;

  if (opt.with_colons)
    {
      if (*r_policy && !*r_submission_address)
        es_fprintf (es_stdout, "1:0::");
      else if (*r_policy && *r_submission_address)
        es_fprintf (es_stdout, "1:1::");
      else if (err && !(gpg_err_code (err) == GPG_ERR_FALSE
                        || gpg_err_code (err) == GPG_ERR_NO_DATA
                        || gpg_err_code (err) == GPG_ERR_UNKNOWN_HOST))
        es_fprintf (es_stdout, "0:0:%d:", err);
      else
        es_fprintf (es_stdout, "0:0::");
      if (*r_policy)
        {
          es_fprintf (es_stdout, "%u:%u:%u:",
                      (*r_policy)->protocol_version,
                      (*r_policy)->auth_submit,
                      (*r_policy)->mailbox_only);
        }
      es_putc ('\n', es_stdout);
    }

  xfree (submission_to);
  wks_free_policy (policy);
  xfree (policy);
  es_fclose (mbuf);
  return err;
}



/* Check whether the  provider supports the WKS protocol.  */
static gpg_error_t
command_supported (char *userid)
{
  gpg_error_t err;
  char *addrspec = NULL;
  char *submission_to = NULL;
  policy_flags_t policy = NULL;

  if (!strchr (userid, '@'))
    {
      char *tmp = xstrconcat ("foo@", userid, NULL);
      addrspec = mailbox_from_userid (tmp);
      xfree (tmp);
    }
  else
    addrspec = mailbox_from_userid (userid);
  if (!addrspec)
    {
      log_error (_("\"%s\" is not a proper mail address\n"), userid);
      err = gpg_error (GPG_ERR_INV_USER_ID);
      goto leave;
    }

  /* Get the submission address.  */
  err = get_policy_and_sa (addrspec, 1, &policy, &submission_to);
  if (err || !submission_to)
    {
      if (!submission_to
          || gpg_err_code (err) == GPG_ERR_FALSE
          || gpg_err_code (err) == GPG_ERR_NO_DATA
          || gpg_err_code (err) == GPG_ERR_UNKNOWN_HOST
          )
        {
          /* FALSE is returned if we already figured out that even the
           * Web Key Directory is not supported and thus printed an
           * error message.  */
          if (opt.verbose && gpg_err_code (err) != GPG_ERR_FALSE
              && !opt.with_colons)
            {
              if (gpg_err_code (err) == GPG_ERR_NO_DATA)
                log_info ("provider for '%s' does NOT support WKS\n",
                          addrspec);
              else
                log_info ("provider for '%s' does NOT support WKS (%s)\n",
                          addrspec, gpg_strerror (err));
            }
          err = gpg_error (GPG_ERR_FALSE);
          if (!opt.with_colons)
            log_inc_errorcount ();
        }
      goto leave;
    }

  if (opt.verbose && !opt.with_colons)
    log_info ("provider for '%s' supports WKS\n", addrspec);

 leave:
  wks_free_policy (policy);
  xfree (policy);
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
  uidinfo_list_t mboxes = NULL;
  uidinfo_list_t sl;
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
  if (err)
    {
      log_error ("error parsing key: %s\n", gpg_strerror (err));
      err = gpg_error (GPG_ERR_NO_PUBKEY);
      goto leave;
    }

  if (opt.verbose)
    log_info ("fingerprint: %s\n", fpr);

  for (sl = mboxes; sl; sl = sl->next)
    {
      if (sl->mbox && !strcmp (sl->mbox, addrspec))
        found = 1;
      if (opt.verbose)
        {
          log_info ("    user-id: %s\n", sl->uid);
          log_info ("    created: %s\n", asctimestamp (sl->created));
          if (sl->mbox)
            log_info ("  addr-spec: %s\n", sl->mbox);
          if (sl->expired || sl->revoked)
            log_info ("    flags:%s%s\n",
                      sl->expired? " expired":"", sl->revoked?" revoked":"");
        }
    }
  if (!found)
    {
      log_error ("public key for '%s' has no user id with the mail address\n",
                 addrspec);
      err = gpg_error (GPG_ERR_CERT_REVOKED);
    }

 leave:
  xfree (fpr);
  free_uidinfo_list (mboxes);
  es_fclose (key);
  xfree (addrspec);
  return err;
}



/* Locate the key by fingerprint and userid and send a publication
 * request.  */
static gpg_error_t
command_create (const char *fingerprint, const char *userid)
{
  gpg_error_t err;
  KEYDB_SEARCH_DESC desc;
  char *addrspec = NULL;
  estream_t key = NULL;
  estream_t keyenc = NULL;
  char *submission_to = NULL;
  mime_maker_t mime = NULL;
  policy_flags_t policy = NULL;
  int no_encrypt = 0;
  int posteo_hack = 0;
  const char *domain;
  uidinfo_list_t uidlist = NULL;
  uidinfo_list_t uid, thisuid;
  time_t thistime;
  int any;

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
  err = wks_get_key (&key, fingerprint, addrspec, 0, 1);
  if (err)
    goto leave;

  domain = strchr (addrspec, '@');
  log_assert (domain);
  domain++;

  /* Get the submission address.  */
  if (fake_submission_addr)
    {
      policy = xcalloc (1, sizeof *policy);
      submission_to = xstrdup (fake_submission_addr);
      err = 0;
    }
  else
    {
      err = get_policy_and_sa (addrspec, 0, &policy, &submission_to);
      if (err)
        goto leave;
      if (!submission_to)
        {
          log_error (_("this domain probably doesn't support WKS.\n"));
          err = gpg_error (GPG_ERR_NO_DATA);
          goto leave;
        }
    }

  log_info ("submitting request to '%s'\n", submission_to);

  if (policy->auth_submit)
    log_info ("no confirmation required for '%s'\n", addrspec);

  /* In case the key has several uids with the same addr-spec we will
   * use the newest one.  */
  err = wks_list_key (key, NULL, &uidlist);
  if (err)
    {
      log_error ("error parsing key: %s\n",gpg_strerror (err));
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
      if (policy->mailbox_only && ascii_strcasecmp (uid->uid, uid->mbox))
        continue; /* UID has more than just the mailbox.  */
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
      log_error ("public key %s has no mail address '%s'\n",
                 fingerprint, addrspec);
      err = gpg_error (GPG_ERR_INV_USER_ID);
      goto leave;
    }

  if (opt.verbose)
    log_info ("submitting key with user id '%s'\n", thisuid->uid);

  /* If we have more than one user id we need to filter the key to
   * include only THISUID.  */
  if (uidlist->next)
    {
      estream_t newkey;

      es_rewind (key);
      err = wks_filter_uid (&newkey, key, thisuid->uid, 1);
      if (err)
        {
          log_error ("error filtering key: %s\n", gpg_strerror (err));
          err = gpg_error (GPG_ERR_NO_PUBKEY);
          goto leave;
        }
      es_fclose (key);
      key = newkey;
    }

  if (policy->mailbox_only
      && (!thisuid->mbox || ascii_strcasecmp (thisuid->uid, thisuid->mbox)))
    {
      log_info ("Warning: policy requires 'mailbox-only'"
                " - adding user id '%s'\n", addrspec);
      err = add_user_id (fingerprint, addrspec);
      if (err)
        goto leave;

      /* Need to get the key again.  This time we request filtering
       * for the full user id, so that we do not need check and filter
       * the key again.  */
      es_fclose (key);
      key = NULL;
      err = wks_get_key (&key, fingerprint, addrspec, 1, 1);
      if (err)
        goto leave;
    }

  if (opt.add_revocs)
    {
      if (es_fseek (key, 0, SEEK_END))
        {
          err = gpg_error_from_syserror ();
          log_error ("error seeking stream: %s\n", gpg_strerror (err));
          goto leave;
        }
      err = wks_find_add_revocs (key, addrspec);
      if (err)
        {
          log_error ("error finding revocations for '%s': %s\n",
                     addrspec, gpg_strerror (err));
          goto leave;
        }
    }


  /* Now put the armor around the key.  */
  {
    estream_t newkey;

    es_rewind (key);
    err = wks_armor_key (&newkey, key,
                         no_encrypt? NULL
                         /* */    : ("Content-Type: application/pgp-keys\n"
                                     "\n"));
    if (err)
      {
        log_error ("error armoring key: %s\n", gpg_strerror (err));
        goto leave;
      }
    es_fclose (key);
    key = newkey;
  }

  /* Hack to support posteo but let them disable this by setting the
   * new policy-version flag.  */
  if (policy->protocol_version < 3
      && !ascii_strcasecmp (domain, "posteo.de"))
    {
      log_info ("Warning: Using draft-1 method for domain '%s'\n", domain);
      no_encrypt = 1;
      posteo_hack = 1;
    }

  /* Encrypt the key part.  */
  if (!no_encrypt)
    {
      es_rewind (key);
      err = encrypt_response (&keyenc, key, submission_to, fingerprint);
      if (err)
        goto leave;
      es_fclose (key);
      key = NULL;
    }

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

  if (no_encrypt)
    {
      void *data;
      size_t datalen;

      if (posteo_hack)
        {
          /* Needs a multipart/mixed with one(!) attachment.  It does
           * not grok a non-multipart mail.  */
          err = mime_maker_add_header (mime, "Content-Type", "multipart/mixed");
          if (err)
            goto leave;
          err = mime_maker_add_container (mime);
          if (err)
            goto leave;
        }

      err = mime_maker_add_header (mime, "Content-type",
                                   "application/pgp-keys");
      if (err)
        goto leave;

      if (es_fclose_snatch (key, &data, &datalen))
        {
          err = gpg_error_from_syserror ();
          goto leave;
        }
      key = NULL;
      err = mime_maker_add_body_data (mime, data, datalen);
      xfree (data);
      if (err)
        goto leave;
    }
  else
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

      err = mime_maker_add_stream (mime, &keyenc);
      if (err)
        goto leave;
    }

  err = wks_send_mime (mime);

 leave:
  mime_maker_release (mime);
  xfree (submission_to);
  free_uidinfo_list (uidlist);
  es_fclose (keyenc);
  es_fclose (key);
  wks_free_policy (policy);
  xfree (policy);
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
  if (opt.verbose < 2)
    ccparray_put (&ccp, "--quiet");
  else
    ccparray_put (&ccp, "--verbose");
  ccparray_put (&ccp, "--batch");
  ccparray_put (&ccp, "--status-fd=2");
  ccparray_put (&ccp, "--always-trust");
  ccparray_put (&ccp, "--armor");
  ccparray_put (&ccp, "-z0");  /* No compression for improved robustness.  */
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



/* An object used to communicate with the mirror_one_key callback.  */
struct
{
  const char *domain;
  int anyerror;
  unsigned int nkeys;   /* Number of keys processed.  */
  unsigned int nuids;   /* Number of published user ids.  */
} mirror_one_key_parm;


/* Return true if the Given a mail DOMAIN and the full addrspec MBOX
 * match.  */
static int
domain_matches_mbox (const char *domain, const char *mbox)
{
  const char *s;

  if (!domain || !mbox)
    return 0;
  s = strchr (domain, '@');
  if (s)
    domain = s+1;
  if (!*domain)
    return 0; /* Not a valid domain.  */

  s = strchr (mbox, '@');
  if (!s || !s[1])
    return 0; /* Not a valid mbox.  */
  mbox = s+1;

  return !ascii_strcasecmp (domain, mbox);
}


/* Core of mirror_one_key with the goal of mirroring just one uid.
 * UIDLIST is used to figure out whether the given MBOX occurs several
 * times in UIDLIST and then to single out the newest one.  This is
 * so that for a key with
 *    uid: Joe Someone <joe@example.org>
 *    uid: Joe <joe@example.org>
 * only the news user id (and thus its self-signature) is used.
 * UIDLIST is nodified to set all MBOX fields to NULL for a processed
 * user id.  FPR is the fingerprint of the key.
 */
static gpg_error_t
mirror_one_keys_userid (estream_t key, const char *mbox, uidinfo_list_t uidlist,
                        const char *fpr)
{
  gpg_error_t err;
  uidinfo_list_t uid, thisuid, firstuid;
  time_t thistime;
  estream_t newkey = NULL;

  /* Find the UID we want to use.  */
  thistime = 0;
  thisuid = firstuid = NULL;
  for (uid = uidlist; uid; uid = uid->next)
    {
      if ((uid->flags & 1) || !uid->mbox || strcmp (uid->mbox, mbox))
        continue; /* Already processed or no matching mbox.  */
      uid->flags |= 1;  /* Set "processed" flag.  */
      if (!firstuid)
        firstuid = uid;
      if (uid->created > thistime)
        {
          thistime = uid->created;
          thisuid = uid;
        }
    }
  if (!thisuid)
    thisuid = firstuid;  /* This is the case for a missing timestamp.  */
  if (!thisuid)
    {
      log_error ("error finding the user id for %s (%s)\n", fpr, mbox);
      err = gpg_error (GPG_ERR_NO_USER_ID);
      goto leave;
    }

  /* Always filter the key so that the result will be non-armored.  */
  es_rewind (key);
  err = wks_filter_uid (&newkey, key, thisuid->uid, 1);
  if (err)
    {
      log_error ("error filtering key %s: %s\n", fpr, gpg_strerror (err));
      err = gpg_error (GPG_ERR_NO_PUBKEY);
      goto leave;
    }

  if (opt.add_revocs)
    {
      if (es_fseek (newkey, 0, SEEK_END))
        {
          err = gpg_error_from_syserror ();
          log_error ("error seeking stream: %s\n", gpg_strerror (err));
          goto leave;
        }
      err = wks_find_add_revocs (newkey, mbox);
      if (err)
        {
          log_error ("error finding revocations for '%s': %s\n",
                     mbox, gpg_strerror (err));
          goto leave;
        }
      es_rewind (newkey);
    }

  err = wks_install_key_core (newkey, mbox);
  if (opt.verbose)
    log_info ("key %s published for '%s'\n", fpr, mbox);
  mirror_one_key_parm.nuids++;
  if (!opt.quiet && !(mirror_one_key_parm.nuids % 25))
    log_info ("%u user ids from %d keys so far\n",
              mirror_one_key_parm.nuids, mirror_one_key_parm.nkeys);

 leave:
  es_fclose (newkey);
  return err;
}


/* The callback used by command_mirror.  It received an estream with
 * one key and should return success to process the next key.  */
static gpg_error_t
mirror_one_key (estream_t key)
{
  gpg_error_t err = 0;
  char *fpr;
  uidinfo_list_t uidlist = NULL;
  uidinfo_list_t uid;
  const char *domain = mirror_one_key_parm.domain;

  /* List the key to get all user ids.  */
  err = wks_list_key (key, &fpr, &uidlist);
  if (err)
    {
      log_error ("error parsing a key: %s - skipped\n",
                 gpg_strerror (err));
      mirror_one_key_parm.anyerror = 1;
      err = 0;
      goto leave;
    }
  for (uid = uidlist; uid; uid = uid->next)
    {
      if (!uid->mbox || (uid->flags & 1))
        continue; /* No mail box or already processed.  */
      if (uid->expired)
        continue;
      if (*domain && !domain_matches_mbox (domain, uid->mbox))
        continue; /* We don't want this one.  */
      if (is_in_blacklist (uid->mbox))
        continue;

      err = mirror_one_keys_userid (key, uid->mbox, uidlist, fpr);
      if (err)
        {
          log_error ("error processing key %s: %s - skipped\n",
                     fpr, gpg_strerror (err));
          mirror_one_key_parm.anyerror = 1;
          err = 0;
          goto leave;
        }
    }
  mirror_one_key_parm.nkeys++;


 leave:
  free_uidinfo_list (uidlist);
  xfree (fpr);
  return err;
}


/* Copy the keys from the configured LDAP server into a local WKD.
 * DOMAINLIST is an array of domain names to restrict the copy to only
 * the given domains; if it is NULL all keys are mirrored.  */
static gpg_error_t
command_mirror (char *domainlist[])
{
  gpg_error_t err;
  const char *domain;
  char *domainbuf = NULL;

  mirror_one_key_parm.anyerror = 0;
  mirror_one_key_parm.nkeys = 0;
  mirror_one_key_parm.nuids = 0;

  if (!domainlist)
    {
      mirror_one_key_parm.domain = "";
      err = wkd_dirmngr_ks_get (NULL, mirror_one_key);
    }
  else
    {
      while ((domain = *domainlist++))
        {
          if (*domain != '.' && domain[1] != '@')
            {
              /* This does not already specify a mail search by
               * domain.  Change it.  */
              xfree (domainbuf);
              domainbuf = xstrconcat (".@", domain, NULL);
              domain = domainbuf;
            }
          mirror_one_key_parm.domain = domain;
          if (opt.verbose)
            log_info ("mirroring keys for domain '%s'\n", domain+2);
          err = wkd_dirmngr_ks_get (domain, mirror_one_key);
          if (err)
            break;
        }
    }

  if (!opt.quiet)
    log_info ("a total of %u user ids from %d keys published\n",
              mirror_one_key_parm.nuids, mirror_one_key_parm.nkeys);
  if (err)
    log_error ("error mirroring LDAP directory: %s <%s>\n",
               gpg_strerror (err), gpg_strsource (err));
  else if (mirror_one_key_parm.anyerror)
    log_info ("warning: errors encountered - not all keys are mirrored\n");

  xfree (domainbuf);
  return err;
}
