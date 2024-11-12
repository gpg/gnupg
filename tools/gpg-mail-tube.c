/* gpg-mail-tube.c - A tool to encrypt mails in a pipeline
 * Copyright (C) 2024 g10 Code GmbH
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
#include <unistd.h>
#include <fcntl.h>

#ifdef HAVE_W32_SYSTEM
# error this program does not work for Windows
#endif

#define INCLUDED_BY_MAIN_MODULE 1
#include "../common/util.h"
#include "../common/init.h"
#include "../common/sysutils.h"
#include "../common/ccparray.h"
#include "../common/exechelp.h"
#include "../common/mbox-util.h"
#include "../common/zb32.h"
#include "rfc822parse.h"
#include "mime-maker.h"



/* Constants to identify the commands and options. */
enum cmd_and_opt_values
  {
    aDefault = 0,

    oQuiet      = 'q',
    oVerbose	= 'v',
    oAsAttach   = 'a',

    oDebug      = 500,

    oGpgProgram,
    oHeader,
    oVSD,
    oLogFile,
    oNoStderr,
    oSetenv,

    oDummy
  };


/* The list of commands and options. */
static gpgrt_opt_t opts[] = {
  ARGPARSE_group (301, ("@\nOptions:\n ")),

  ARGPARSE_s_n (oVerbose, "verbose", ("verbose")),
  ARGPARSE_s_n (oQuiet,	"quiet",  ("be somewhat more quiet")),
  ARGPARSE_s_s (oDebug, "debug", "@"),
  ARGPARSE_s_s (oGpgProgram, "gpg", "@"),
  ARGPARSE_s_s (oHeader, "header" ,
                "|NAME=VALUE|add \"NAME: VALUE\" as header to all mails"),
  ARGPARSE_s_s (oSetenv, "setenv" , "|NAME=VALUE|set envvar NAME to VALUE"),
  ARGPARSE_s_n (oVSD, "vsd", "run the vsd installation of gpg"),
  ARGPARSE_s_s (oLogFile, "log-file", "|FILE|write diagnostics to FILE"),
  ARGPARSE_s_n (oNoStderr, "no-stderr", "suppress all output to stderr"),
  ARGPARSE_s_n (oAsAttach, "as-attachment","attach the encrypted mail"),

  ARGPARSE_end ()
};


/* We keep all global options in the structure OPT.  */
static struct
{
  int verbose;
  unsigned int debug;
  int quiet;
  const char *logfile;  /* Name of a log file or NULL.  */
  char *gpg_program;
  strlist_t extra_headers;

  unsigned int vsd:1;
  unsigned int no_stderr:1;/* Avoid any writes to stderr.  */
  unsigned int as_attach:1;/* Create an encrypted attachment.  */
} opt;


/* Debug values and macros.  */
#define DBG_MIME_VALUE        1 /* Debug the MIME structure.  */
#define DBG_PARSER_VALUE      2 /* Debug the Mail parser.  */
#define DBG_CRYPTO_VALUE      4	/* Debug low level crypto.  */
#define DBG_EXTPROG_VALUE 16384 /* debug external program calls */

#define DBG_MIME     (opt.debug & DBG_MIME_VALUE)
#define DBG_PARSER   (opt.debug & DBG_PARSER_VALUE)
#define DBG_CRYPTO   (opt.debug & DBG_CRYPTO_VALUE)
#define DBG_EXTPROG  (opt.debug & DBG_EXTPROG_VALUE)


/* The list of supported debug flags.  */
static struct debug_flags_s debug_flags [] =
  {
    { DBG_MIME_VALUE   , "mime"    },
    { DBG_PARSER_VALUE , "parser"  },
    { DBG_CRYPTO_VALUE , "crypto"  },
    { DBG_EXTPROG_VALUE, "extprog" },
    { 0, NULL }
  };


/* Definition of the parser object.  */
struct parser_context_s
{
  /* The RFC822 parser context is stored here during callbacks.  */
  rfc822parse_t msg;

  /* Helper to convey error codes from user callbacks.  */
  gpg_error_t err;

  /* Flag is set if a MIME-Version header was found.  */
  unsigned int mime_version_seen:1;

  /* Set when the body of a mail has been reached.  */
  unsigned int in_body:1;

  /* Set as long as we are in a content-type or a continuation of
   * it.  */
  unsigned int in_ct:1;

  /* A buffer for reading a mail line.  */
  char line[5000];
};




/* Prototypes.  */
static gpg_error_t mail_tube_encrypt (estream_t fpin, strlist_t recipients);
static void prepare_for_appimage (void);
static gpg_error_t start_gpg_encrypt (estream_t *r_input,
                                      pid_t *r_pid,
                                      strlist_t recipients);



/* Print usage information and provide strings for help. */
static const char *
my_strusage( int level )
{
  const char *p;

  switch (level)
    {
    case  9: p = "LGPL-2.1-or-later"; break;
    case 11: p = "gpg-mail-tube"; break;
    case 12: p = "@GNUPG@"; break;
    case 13: p = VERSION; break;
    case 14: p = GNUPG_DEF_COPYRIGHT_LINE; break;
    case 17: p = PRINTABLE_OS_NAME; break;
    case 19: p = ("Please report bugs to <@EMAIL@>.\n"); break;

    case 1:
    case 40:
      p = ("Usage: gpg-mail-tube [options] recipients (-h for help)");
      break;
    case 41:
      p = ("Syntax: gpg-mail-tube [options]\n"
           "Tool to encrypt rfc822 formatted mail in a pipeline\n");
      break;

    default: p = NULL; break;
    }
  return p;
}


/* static void */
/* wrong_args (const char *text) */
/* { */
/*   es_fprintf (es_stderr, "usage: %s [options] %s\n", gpgrt_strusage (11), text); */
/*   exit (2); */
/* } */



/* Command line parsing.  */
static enum cmd_and_opt_values
parse_arguments (gpgrt_argparse_t *pargs, gpgrt_opt_t *popts)
{
  enum cmd_and_opt_values cmd = 0;
  int no_more_options = 0;

  while (!no_more_options && gpgrt_argparse (NULL, pargs, popts))
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
        case oLogFile: opt.logfile = pargs->r.ret_str; break;
        case oNoStderr: opt.no_stderr = 1; break;
        case oAsAttach: opt.as_attach = 1; break;

        case oGpgProgram:
          opt.gpg_program = pargs->r.ret_str;
          break;
        case oHeader:
          append_to_strlist (&opt.extra_headers, pargs->r.ret_str);
          break;
        case oSetenv: putenv (pargs->r.ret_str); break;
        case oVSD: opt.vsd = 1; break;

        default: pargs->err = ARGPARSE_PRINT_ERROR; break;
	}
    }

  return cmd;
}



/* gpg-mail-tube main. */
int
main (int argc, char **argv)
{
  gpg_error_t err;
  gpgrt_argparse_t pargs;
  enum cmd_and_opt_values cmd;
  strlist_t recipients = NULL;
  int i;

  gnupg_reopen_std ("gpg-mail-tube");
  gpgrt_set_strusage (my_strusage);
  log_set_prefix ("gpg-mail-tube", GPGRT_LOG_WITH_PREFIX);

  /* Make sure that our subsystems are ready.  */
  init_common_subsystems (&argc, &argv);

  /* Parse the command line. */
  pargs.argc  = &argc;
  pargs.argv  = &argv;
  pargs.flags = ARGPARSE_FLAG_KEEP;
  cmd = parse_arguments (&pargs, opts);
  gpgrt_argparse (NULL, &pargs, NULL);

  if (log_get_errorcount (0))
    exit (2);

  /* Some applications do not distinguish between stdout and stderr
   * and would thus clutter the mail with diagnostics.  This option
   * can be used to inhibit this.  */
  if (opt.no_stderr)
    {
      es_fflush (es_stderr);
      fflush (stderr);
      i = open ("/dev/null", O_WRONLY);
      if (i == -1)
        log_fatal ("failed to open '/dev/null': %s\n",
                   gpg_strerror (gpg_err_code_from_syserror ()));
      else if (dup2 (i, 2) == -1)
        log_fatal ("directing stderr to '/dev/null' failed: %s\n",
                   gpg_strerror (gpg_err_code_from_syserror ()));
    }

  if (opt.logfile)
    {
      log_set_file (opt.logfile);
      log_set_prefix (NULL, (GPGRT_LOG_WITH_PREFIX
                             | GPGRT_LOG_WITH_TIME
                             | GPGRT_LOG_WITH_PID));
    }

  /* Print a warning if an argument looks like an option.  */
  if (!opt.quiet && !(pargs.flags & ARGPARSE_FLAG_STOP_SEEN))
    {
      for (i=0; i < argc; i++)
        if (argv[i][0] == '-' && argv[i][1] == '-')
          log_info (("NOTE: '%s' is not considered an option\n"), argv[i]);
    }

  /* Set defaults for non given options.  */
  if (!opt.gpg_program)
    opt.gpg_program = xstrdup (gnupg_module_name (GNUPG_MODULE_NAME_GPG));

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

  /* The remaining argumenst are the recipients - put them into a list.  */
  /* TODO: Check that these are all valid mail addresses so that gpg
   * will consider them as such.  */
  for (i=0; i < argc; i++)
    add_to_strlist (&recipients, argv[i]);

  if (opt.vsd)
    prepare_for_appimage ();

  if (log_get_errorcount (0))
    exit (2);


  /* Run the selected command.  */
  switch (cmd)
    {
    case aDefault:
      err = mail_tube_encrypt (es_stdin, recipients);
      break;

    default:
      gpgrt_usage (1);
      err = gpg_error (GPG_ERR_BUG);
      break;
    }

  if (err)
    log_error ("command failed: %s\n", gpg_strerror (err));
  free_strlist (recipients);
  return log_get_errorcount (0)? 1:0;
}


/* This function is called by the mail parser to communicate events.
 * This callback communicates with the main function using a structure
 * passed in OPAQUE. Should return 0 or set errno and return -1. */
static int
mail_tube_message_cb (void *opaque,
                      rfc822parse_event_t event, rfc822parse_t msg)
{
  struct parser_context_s *ctx = opaque;
  const char *s;

  if (event == RFC822PARSE_HEADER_SEEN)
    {
      /* We don't need this because we will output the header lines as
       * collected by the parser and thus with canonicalized names.
       * The original idea was to keep the lines as received so not to
       * break DKIM.  But DKIM would break anyway because DKIM should
       * always cover the CT field which we have to replace.  */
      if (!(s = rfc822parse_last_header_line (msg)))
        ;
      else if (!rfc822_cmp_header_name (s, "Content-Type"))
        ctx->in_ct = 1;
      else if (*s)
        ctx->in_ct = 0; /* Another header started.  */

      if (s && *s && !rfc822_cmp_header_name (s, "MIME-Version"))
        ctx->mime_version_seen = 1;

    }
  else if (event == RFC822PARSE_T2BODY)
    {
      ctx->in_ct = 0;
      ctx->in_body = 1;
    }

  return 0;
}


/* Receive a mail from FPIN and process to STDOUT.  RECIPIENTS is a
 * string list with the recipients of for this message. */
static gpg_error_t
mail_tube_encrypt (estream_t fpin, strlist_t recipients)
{
  static const char *ct_names[] =
    { "Content-Type",  "Content-Transfer-Encoding",
      "Content-Description", "Content-Disposition" };
  gpg_error_t err;
  struct parser_context_s parser_context = { NULL };
  struct parser_context_s *ctx = &parser_context;
  unsigned int lineno = 0;
  size_t length;
  char *line;
  strlist_t sl;
  void *iterp;
  const char *s;
  char *boundary = NULL;  /* Actually only the random part of it.  */
  estream_t gpginfp = NULL;
  pid_t pid = (pid_t)(-1);
  int exitcode;
  int i, found;
  int ct_is_text = 0;

  ctx->msg = rfc822parse_open (mail_tube_message_cb, ctx);
  if (!ctx->msg)
    {
      err = gpg_error_from_syserror ();
      log_error ("can't open mail parser: %s", gpg_strerror (err));
      goto leave;
    }

  /* Fixme: We should not use fgets because it can't cope with
     embedded nul characters. */
  while (!ctx->in_body && es_fgets (ctx->line, sizeof (ctx->line), fpin))
    {
      lineno++;
      if (lineno == 1 && !strncmp (line, "From ", 5))
        continue;  /* We better ignore a leading From line. */

      line = ctx->line;
      length = strlen (line);
      if (length && line[length - 1] == '\n')
	line[--length] = 0;
      else
        log_error ("mail parser detected too long or"
                   " non terminated last line (lnr=%u)\n", lineno);
      if (length && line[length - 1] == '\r')
	line[--length] = 0;

      ctx->err = 0;
      if (rfc822parse_insert (ctx->msg, line, length))
        {
          err = gpg_error_from_syserror ();
          log_error ("mail parser failed: %s", gpg_strerror (err));
          goto leave;
        }
      if (ctx->err) /* Error from a callback detected.  */
        {
          err = ctx->err;
          goto leave;
        }
    }
  if (!ctx->in_body)
    {
      log_error ("mail w/o a body\n");
      err = gpg_error (GPG_ERR_NO_DATA);
      goto leave;
    }

  /* Replace the content-type and output the collected headers. */
  ctx->in_ct = 0;
  for (iterp=NULL; (s = rfc822parse_enum_header_lines (ctx->msg, &iterp)); )
    {
      for (i=found=0; !found && i < DIM (ct_names); i++)
        if (!rfc822_cmp_header_name (s, ct_names[i]))
          found = 1;
      if (found)
        ctx->in_ct = 1;
      else if (*s == ' ' || *s == '\t')
        ; /* Continuation */
      else
        ctx->in_ct = 0;

      if (!ctx->in_ct)
        es_fprintf (es_stdout, "%s\r\n", s);
    }
  rfc822parse_enum_header_lines (NULL, &iterp); /* Close enumerator. */

  if (opt.as_attach)
    {
      rfc822parse_field_t field;
      const char *media;

      field = rfc822parse_parse_field (ctx->msg, "Content-Type", -1);
      if (!field)
        ct_is_text = 1;  /* Assumed CT is text/plain.  */
      else if ((media = rfc822parse_query_media_type (field, NULL))
               && !strcmp (media, "text"))
        ct_is_text = 1;

      rfc822parse_release_field (field);
    }

  /* Create a boundary.  We use a pretty simple random string to avoid
   * the Libgcrypt overhead.  It could actually be a constant string
   * because this is the outer container.  */
  {
    uint32_t noncebuf = time (NULL);

    boundary = zb32_encode (&noncebuf, 8 * sizeof noncebuf);
    if (!boundary)
      {
        err = gpg_error_from_syserror ();
        goto leave;
      }
  }

  if (!ctx->mime_version_seen)
    es_fprintf (es_stdout, "MIME-Version: 1.0\r\n");

  if (opt.as_attach)
    es_fprintf (es_stdout,
                "Content-Type: multipart/mixed;"
                " boundary=\"=-=mt-%s=-=\r\n", boundary);
  else
    es_fprintf (es_stdout,
                "Content-Type: multipart/encrypted;"
                " protocol=\"application/pgp-encrypted\";\r\n"
                "\tboundary=\"=-=mt-%s=-=\r\n", boundary);

  /* Add the extra headers.  */
  for (sl = opt.extra_headers; sl; sl = sl->next)
    {
      s = strchr (sl->d, '=');
      log_assert (s);
      es_fprintf (es_stdout, "%.*s: %s\r\n", (int)(s - sl->d), sl->d, s + 1);
    }

  /* Output the plain or PGP/MIME boilerplate.  */
  if (opt.as_attach)
    {
      /* FIXME: Need to have a configurable message here.  */
      es_fprintf (es_stdout,
                  "\r\n"
                  "\r\n"
                  "--=-=mt-%s=-=\r\n"
                  "Content-Type: text/plain; charset=us-ascii\r\n"
                  "Content-Disposition: inline\r\n"
                  "\r\n"
                  "Please find attached an encrypted %s.\r\n"
                  "\r\n"
                  "--=-=mt-%s=-=\r\n",
                  boundary,
                  ct_is_text? "file":"message",
                  boundary);
      if (ct_is_text)
        es_fprintf (es_stdout,
                    "Content-Type: text/plain; charset=us-ascii\r\n"
                    "Content-Description: PGP encrypted file\r\n"
                    "Content-Disposition: attachment; filename=\"%s\"\r\n"
                    "\r\n", "pgp-encrypted-file.txt.asc");
      else
        es_fprintf (es_stdout,
                    "Content-Type: text/plain; charset=us-ascii\r\n"
                    "Content-Description: PGP encrypted message\r\n"
                    "Content-Disposition: attachment; filename=\"%s\"\r\n"
                    "\r\n", "pgp-encrypted-msg.eml.asc");
    }
  else /* PGP/MIME */
    es_fprintf (es_stdout,
              "\r\n"
              "\r\n"
              "--=-=mt-%s=-=\r\n"
              "Content-Type: application/pgp-encrypted\r\n"
              "Content-Description: PGP/MIME version id\r\n"
              "\r\n"
              "Version: 1\r\n"
              "\r\n"
              "--=-=mt-%s=-=\r\n"
              "Content-Type: application/octet-stream; name=\"encmsg.asc\"\r\n"
              "Content-Description: PGP/MIME encrypted message\r\n"
              "Content-Disposition: inline; filename=\"encmsg.asc\"\r\n"
              "\r\n", boundary, boundary);

  /* Start gpg and get a stream to fed data to gpg */
  err = start_gpg_encrypt (&gpginfp, &pid, recipients);
  if (err)
    {
      log_error ("failed to start gpg process: %s\n", gpg_strerror (err));
      goto leave;
    }

  if (opt.as_attach && ct_is_text)
    {
      /* No headers at all; write as plain file and ignore the encoding.  */
      /* FIXME: Should we do a base64 or QP decoding?  */
    }
  else
    {
      /* Write new mime headers using the original content-* values.  */
      for (i=0; i < DIM (ct_names); i++)
        {
          line = rfc822parse_get_field (ctx->msg, ct_names[i], -1, NULL);
          if (opt.verbose)
            log_info ("original Content-type is '%s'\n", line);
          if (line)
            {
              es_fprintf (gpginfp, "%s\r\n", line);
              rfc822_free (line);
            }
        }
      es_fprintf (gpginfp, "\r\n");  /* End of MIME header.  */
    }

  /* Read the remaining input and feed it to gpg.  */
  while (es_fgets (ctx->line, sizeof (ctx->line), fpin))
    {
      lineno++;
      line = ctx->line;
      length = strlen (line);
      if (length && line[length - 1] == '\n')
	line[--length] = 0;
      else
        log_error ("mail parser detected too long or"
                   " non terminated last line (lnr=%u)\n", lineno);
      if (length && line[length - 1] == '\r')
	line[--length] = 0;
      es_fprintf (gpginfp, "%s\r\n", line);
    }

  /* Wait for gpg to finish.  */
  err = es_fclose (gpginfp);
  gpginfp = NULL;
  if (err)
    log_error ("error closing pipe: %s\n", gpg_strerror (err));

  err = gnupg_wait_process (opt.gpg_program, pid, 1 /* hang */, &exitcode);
  if (err)
    {
      log_error ("waiting for process %s failed: %s\n",
                 opt.gpg_program, gpg_strerror (err));
      goto leave;
    }
  pid = (pid_t)(-1);
  if (exitcode)
    {
      log_error ("running %s failed: exitcode=%d\n",
                 opt.gpg_program, exitcode);
      goto leave;
    }

  /* Output the final boundary.  */
  es_fflush (es_stdout);
  fflush (stdout);
  es_fprintf (es_stdout,
              "\r\n"
              "--=-=mt-%s=-=--\r\n"
              "\r\n",
              boundary);


  /* Success */
  rfc822parse_close (ctx->msg);
  ctx->msg = NULL;
  err = 0;

 leave:
  gpgrt_fcancel (gpginfp);
  rfc822parse_cancel (ctx->msg);
  xfree (boundary);
  return err;
}


/* This function returns the name of the gpg binary unter the APPDIR
 * of the VSD version as a malloced string.  It also tests whether
 * this binary is executable.  Returns NULL if the APPDIR was not
 * found or the gpg is not executable (i.e. not yet/anymore properly
 * mounted) */
static char *
get_vsd_gpgbin (void)
{
  gpg_error_t err;
  char *fname;
  estream_t fp = NULL;
  char *line = NULL;
  size_t linelen;
  char *gpgbin = NULL;
  char *p, *pend;

  fname = make_filename ("~/.gnupg-vsd/run-gpgconf", NULL);
  /* Although we could simply run that script with -L bindir to get
   * the bin directory we parse the script instead and look for the
   * assignment of the APPDIR variable which should always be like
   *   APPDIR="/somepath"
   * Doing this is much faster and avoids the overhead of running the
   * script and the gpgconf tool.   */

  if (gnupg_access (fname, F_OK))
    goto leave; /* File not available.  */

  fp = es_fopen (fname, "r");
  if (!fp)
    {
      err = gpg_error_from_syserror ();
      if (gpg_err_code (err) != GPG_ERR_ENOENT)
        log_info ("error opening '%s': %s\n", fname, gpg_strerror (err));
      goto leave;
    }

  line = NULL;
  linelen = 0;
  while (es_read_line (fp, &line, &linelen, NULL) > 0)
    {
      if (strncmp (line, "APPDIR=", 7))
        continue;
      p = line + 7;
      if (*p != '\"' && *p != '\'')
        continue;
      pend = strchr (p+1, *p);
      if (!pend || p+1 == pend)
        continue;
      *pend = 0;
      gpgbin = xstrconcat (p+1, "/usr/bin/gpg", NULL);
      break;
    }
  if (gpgbin && gnupg_access (gpgbin, X_OK))
    {
      xfree (gpgbin);
      gpgbin = NULL;
    }

 leave:
  es_fclose (fp);
  xfree (line);
  xfree (fname);
  return gpgbin;
}



/* This function is used in VSD mode to override the opt.gpg_program
 * by replacing it with the gpg from the "GnuPG VS-Desktop®" AppImage.
 * Start that AppImage if it has not yet been started.  No error
 * return but it bumps the error counter.  */
static void
prepare_for_appimage (void)
{
  gpg_error_t err;
  char *gpgbin;
  char *fname = NULL;
  int i;

  gpgbin = get_vsd_gpgbin ();
  if (!gpgbin)
    {
      /* Run the sleep program for 2^30 seconds (34 years). */
      static const char *args[4] = { "-c", "sleep", "1073741824", NULL };

      fname = make_filename ("~/.gnupg-vsd/gnupg-vs-desktop.AppImage", NULL);

      err = gnupg_spawn_process_detached (fname, args, NULL);
      if (err)
        {
          log_error ("failed to spawn '%s': %s\n", fname, gpg_strerror (err));
          return;
        }
      for (i=0; i < 30 && !(gpgbin = get_vsd_gpgbin ()); i++)
        {
          if (opt.verbose)
            log_info ("waiting until the AppImage has started ...\n");
          gnupg_sleep (1);
        }
      if (opt.verbose && gpgbin)
        log_info ("using AppImage gpg binary '%s'\n", gpgbin);
    }

  if (!gpgbin)
    log_error ("AppImage did not start up properly\n");
  else
    {
      xfree (opt.gpg_program);
      opt.gpg_program = gpgbin;
    }
  xfree (fname);
}


/* Create a new gpg process for encryption.  On success a new stream
 * is stored at R_INPUT and the process' pid at R_PID.  The gpg
 * output is sent to stdout and is always armored.  */
static gpg_error_t
start_gpg_encrypt (estream_t *r_input, pid_t *r_pid,
                   strlist_t recipients)
{
  gpg_error_t err;
  strlist_t sl;
  ccparray_t ccp;
  int except[2] = { -1, -1 };
  const char **argv;
  char *logfilebuf = NULL;

  *r_input = NULL;
  *r_pid = (pid_t)(-1);
  es_fflush (es_stdout);

  if (opt.verbose)
    log_info ("starting gpg as %u:%u with HOME=%s\n",
              (unsigned int)getuid (), (unsigned int)getgid (),
              getenv ("HOME"));
  ccparray_init (&ccp, 0);
  ccparray_put (&ccp, "--batch");
  if (opt.logfile)
    {
      logfilebuf = xasprintf ("--log-file=%s", opt.logfile);
      ccparray_put (&ccp, logfilebuf);
    }
  if (DBG_EXTPROG)
    ccparray_put (&ccp, "--debug=0");
  ccparray_put (&ccp, "--armor");
  ccparray_put (&ccp, "--output");
  ccparray_put (&ccp, "-");
  if (opt.vsd)
    ccparray_put (&ccp, "--require-compliance");
  ccparray_put (&ccp, "--auto-key-locate=clear,local,ldap");
  ccparray_put (&ccp, "--encrypt");
  for (sl = recipients; sl; sl = sl->next)
    {
      ccparray_put (&ccp, "-r");
      ccparray_put (&ccp, sl->d);
      if (opt.verbose)
        log_info ("encrypting to '%s'\n", sl->d);
    }
  ccparray_put (&ccp, "--");

  ccparray_put (&ccp, NULL);
  argv = ccparray_get (&ccp, NULL);
  if (!argv)
    {
      err = gpg_error_from_syserror ();
      goto leave;
    }

  err = gnupg_spawn_process (opt.gpg_program, argv,
                             except[0] == -1? NULL : except,
                             (GNUPG_SPAWN_KEEP_STDOUT
                              | GNUPG_SPAWN_KEEP_STDERR),
                             r_input, NULL, NULL, r_pid);

  xfree (argv);
  if (err)
    goto leave;

 leave:
  if (err)
    *r_pid = (pid_t)(-1);
  xfree (logfilebuf);
  return err;
}
