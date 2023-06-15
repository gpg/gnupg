/* gpgtar.c - A simple TAR implementation mainly useful for Windows.
 * Copyright (C) 2010 Free Software Foundation, Inc.
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
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

/* GnuPG comes with a shell script gpg-zip which creates archive files
   in the same format as PGP Zip, which is actually a USTAR format.
   That is fine and works nicely on all Unices but for Windows we
   don't have a compatible shell and the supply of tar programs is
   limited.  Given that we need just a few tar option and it is an
   open question how many Unix concepts are to be mapped to Windows,
   we might as well write our own little tar customized for use with
   gpg.  So here we go.  */

#include <config.h>

#include <ctype.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define INCLUDED_BY_MAIN_MODULE 1
#include "../common/util.h"
#include "../common/i18n.h"
#include "../common/sysutils.h"
#include "../common/openpgpdefs.h"
#include "../common/init.h"
#include "../common/strlist.h"
#include "../common/comopt.h"

#include "gpgtar.h"


/* Constants to identify the commands and options. */
enum cmd_and_opt_values
  {
    aNull = 0,
    aCreate = 600,
    aExtract,
    aEncrypt    = 'e',
    aDecrypt    = 'd',
    aSign       = 's',
    aList       = 't',

    oSymmetric  = 'c',
    oRecipient	= 'r',
    oUser       = 'u',
    oOutput	= 'o',
    oDirectory  = 'C',
    oQuiet      = 'q',
    oVerbose	= 'v',
    oFilesFrom  = 'T',
    oNoVerbose	= 500,

    aSignEncrypt,
    oGpgProgram,
    oSkipCrypto,
    oOpenPGP,
    oCMS,
    oSetFilename,
    oNull,
    oUtf8Strings,
    oNoCompress,

    oBatch,
    oAnswerYes,
    oAnswerNo,
    oStatusFD,
    oRequireCompliance,
    oWithLog,

    /* Compatibility with gpg-zip.  */
    oGpgArgs,
    oTarArgs,
    oTarProgram,

    /* Debugging.  */
    oDebug,
    oDryRun
  };


/* The list of commands and options. */
static gpgrt_opt_t opts[] = {
  ARGPARSE_group (300, N_("@Commands:\n ")),

  ARGPARSE_c (aCreate,    "create",  N_("create an archive")),
  ARGPARSE_c (aExtract,   "extract", N_("extract an archive")),
  ARGPARSE_c (aEncrypt,   "encrypt", N_("create an encrypted archive")),
  ARGPARSE_c (aDecrypt,   "decrypt", N_("extract an encrypted archive")),
  ARGPARSE_c (aSign,      "sign",    N_("create a signed archive")),
  ARGPARSE_c (aList,      "list-archive", N_("list an archive")),

  ARGPARSE_group (301, N_("@\nOptions:\n ")),

  ARGPARSE_s_n (oSymmetric, "symmetric", N_("use symmetric encryption")),
  ARGPARSE_s_s (oRecipient, "recipient", N_("|USER-ID|encrypt for USER-ID")),
  ARGPARSE_s_s (oUser, "local-user",
                N_("|USER-ID|use USER-ID to sign or decrypt")),
  ARGPARSE_s_s (oOutput, "output", N_("|FILE|write output to FILE")),
  ARGPARSE_s_n (oVerbose, "verbose", N_("verbose")),
  ARGPARSE_s_n (oQuiet,	"quiet",  N_("be somewhat more quiet")),
  ARGPARSE_s_s (oGpgProgram, "gpg", "@"),
  ARGPARSE_s_n (oSkipCrypto, "skip-crypto", N_("skip the crypto processing")),
  ARGPARSE_s_n (oDryRun, "dry-run", N_("do not make any changes")),
  ARGPARSE_s_s (oSetFilename, "set-filename", "@"),
  ARGPARSE_s_n (oOpenPGP, "openpgp", "@"),
  ARGPARSE_s_n (oCMS, "cms", "@"),
  ARGPARSE_s_n (oNoCompress,   "no-compress", "@"),

  ARGPARSE_s_n (oBatch, "batch", "@"),
  ARGPARSE_s_n (oAnswerYes, "yes", "@"),
  ARGPARSE_s_n (oAnswerNo, "no", "@"),
  ARGPARSE_s_i (oStatusFD, "status-fd", "@"),
  ARGPARSE_s_n (oRequireCompliance, "require-compliance", "@"),
  ARGPARSE_s_n (oWithLog, "with-log", "@"),

  ARGPARSE_group (302, N_("@\nTar options:\n ")),

  ARGPARSE_s_s (oDirectory, "directory",
                N_("|DIRECTORY|change to DIRECTORY first")),
  ARGPARSE_s_s (oFilesFrom, "files-from",
                N_("|FILE|get names to create from FILE")),
  ARGPARSE_s_n (oNull, "null", N_("-T reads null-terminated names")),
#ifdef HAVE_W32_SYSTEM
  ARGPARSE_s_n (oUtf8Strings, "utf8-strings",
                N_("-T reads UTF-8 encoded names")),
#else
  ARGPARSE_s_n (oUtf8Strings, "utf8-strings", "@"),
#endif

  ARGPARSE_s_s (oGpgArgs, "gpg-args", "@"),
  ARGPARSE_s_s (oTarArgs, "tar-args", "@"),
  ARGPARSE_s_s (oTarProgram, "tar", "@"),

  ARGPARSE_s_s (oDebug, "debug", "@"),

  ARGPARSE_end ()
};


/* The list of commands and options for tar that we understand. */
static gpgrt_opt_t tar_opts[] = {
  ARGPARSE_s_s (oDirectory, "directory",
                N_("|DIRECTORY|extract files into DIRECTORY")),
  ARGPARSE_s_s (oFilesFrom, "files-from",
                N_("|FILE|get names to create from FILE")),
  ARGPARSE_s_n (oNull, "null", N_("-T reads null-terminated names")),

  ARGPARSE_end ()
};


/* Global flags.  */
static enum cmd_and_opt_values cmd = 0;
static int skip_crypto = 0;
static const char *files_from = NULL;
static int null_names = 0;
static int any_debug;



/* Print usage information and provide strings for help. */
static const char *
my_strusage( int level )
{
  const char *p;

  switch (level)
    {
    case  9: p = "GPL-3.0-or-later"; break;
    case 11: p = "@GPGTAR@ (@GNUPG@)";
      break;
    case 13: p = VERSION; break;
    case 14: p = GNUPG_DEF_COPYRIGHT_LINE; break;
    case 17: p = PRINTABLE_OS_NAME; break;
    case 19: p = _("Please report bugs to <@EMAIL@>.\n"); break;

    case 1:
    case 40:
      p = _("Usage: gpgtar [options] [files] [directories] (-h for help)");
      break;
    case 41:
      p = _("Syntax: gpgtar [options] [files] [directories]\n"
            "Encrypt or sign files into an archive\n");
      break;

    default: p = NULL; break;
    }
  return p;
}


static void
set_cmd (enum cmd_and_opt_values *ret_cmd, enum cmd_and_opt_values new_cmd)
{
  enum cmd_and_opt_values c = *ret_cmd;

  if (!c || c == new_cmd)
    c = new_cmd;
  else if (c == aSign && new_cmd == aEncrypt)
    c = aSignEncrypt;
  else if (c == aEncrypt && new_cmd == aSign)
    c = aSignEncrypt;
  else
    {
      log_error (_("conflicting commands\n"));
      exit (2);
    }

  *ret_cmd = c;
}



/* Shell-like argument splitting.

   For compatibility with gpg-zip we accept arguments for GnuPG and
   tar given as a string argument to '--gpg-args' and '--tar-args'.
   gpg-zip was implemented as a Bourne Shell script, and therefore, we
   need to split the string the same way the shell would.  */
static int
shell_parse_stringlist (const char *str, strlist_t *r_list)
{
  strlist_t list = NULL;
  const char *s = str;
  char quoted = 0;
  char arg[1024];
  char *p = arg;
#define addchar(c) \
  do { if (p - arg + 2 < sizeof arg) *p++ = (c); else return 1; } while (0)
#define addargument()                           \
  do {                                          \
    if (p > arg)                                \
      {                                         \
        *p = 0;                                 \
        append_to_strlist (&list, arg);         \
        p = arg;                                \
      }                                         \
  } while (0)

#define unquoted	0
#define singlequote	'\''
#define doublequote	'"'

  for (; *s; s++)
    {
      switch (quoted)
        {
        case unquoted:
          if (isspace (*s))
            addargument ();
          else if (*s == singlequote || *s == doublequote)
            quoted = *s;
          else
            addchar (*s);
          break;

        case singlequote:
          if (*s == singlequote)
            quoted = unquoted;
          else
            addchar (*s);
          break;

        case doublequote:
          log_assert (s > str || !"cannot be quoted at first char");
          if (*s == doublequote && *(s - 1) != '\\')
            quoted = unquoted;
          else
            addchar (*s);
          break;

        default:
          log_assert (! "reached");
        }
    }

  /* Append the last argument.  */
  addargument ();

#undef doublequote
#undef singlequote
#undef unquoted
#undef addargument
#undef addchar
  *r_list = list;
  return 0;
}


/* Like shell_parse_stringlist, but returns an argv vector
   instead of a strlist.  */
static int
shell_parse_argv (const char *s, int *r_argc, char ***r_argv)
{
  int i;
  strlist_t list;

  if (shell_parse_stringlist (s, &list))
    return 1;

  *r_argc = strlist_length (list);
  *r_argv = xtrycalloc (*r_argc, sizeof **r_argv);
  if (*r_argv == NULL)
    return 1;

  for (i = 0; list; i++)
    {
      gpgrt_annotate_leaked_object (list);
      (*r_argv)[i] = list->d;
      list = list->next;
    }
  gpgrt_annotate_leaked_object (*r_argv);
  return 0;
}



/* Command line parsing.  */
static void
parse_arguments (gpgrt_argparse_t *pargs, gpgrt_opt_t *popts)
{
  int no_more_options = 0;

  while (!no_more_options && gpgrt_argparse (NULL, pargs, popts))
    {
      switch (pargs->r_opt)
        {
        case oOutput:    opt.outfile = pargs->r.ret_str; break;
        case oDirectory: opt.directory = pargs->r.ret_str; break;
        case oSetFilename: opt.filename = pargs->r.ret_str; break;
	case oQuiet:     opt.quiet = 1; break;
        case oVerbose:   opt.verbose++; break;
        case oNoVerbose: opt.verbose = 0; break;
        case oFilesFrom: files_from = pargs->r.ret_str; break;
        case oNull: null_names = 1; break;
        case oUtf8Strings: opt.utf8strings = 1; break;
        case oNoCompress:  opt.no_compress = 1; break;

	case aList:
        case aDecrypt:
        case aEncrypt:
        case aSign:
          set_cmd (&cmd, pargs->r_opt);
	  break;

        case aCreate:
          set_cmd (&cmd, aEncrypt);
          skip_crypto = 1;
          break;

        case aExtract:
          set_cmd (&cmd, aDecrypt);
          skip_crypto = 1;
          break;

        case oRecipient:
          add_to_strlist (&opt.recipients, pargs->r.ret_str);
          break;

        case oUser:
          opt.user = pargs->r.ret_str;
          break;

        case oSymmetric:
          set_cmd (&cmd, aEncrypt);
          opt.symmetric = 1;
          break;

        case oGpgProgram:
          opt.gpg_program = pargs->r.ret_str;
          break;

        case oSkipCrypto:
          skip_crypto = 1;
          break;

        case oOpenPGP: /* Dummy option for now.  */ break;
        case oCMS:     /* Dummy option for now.  */ break;

        case oBatch: opt.batch = 1; break;
        case oAnswerYes: opt.answer_yes = 1; break;
        case oAnswerNo: opt.answer_no = 1; break;
        case oStatusFD: opt.status_fd = pargs->r.ret_int; break;
        case oRequireCompliance: opt.require_compliance = 1; break;
        case oWithLog: opt.with_log = 1; break;

        case oGpgArgs:;
          {
            strlist_t list;
            if (shell_parse_stringlist (pargs->r.ret_str, &list))
              log_error ("failed to parse gpg arguments '%s'\n",
                         pargs->r.ret_str);
            else
              {
                if (opt.gpg_arguments)
                  strlist_last (opt.gpg_arguments)->next = list;
                else
                  opt.gpg_arguments = list;
              }
          }
          break;

        case oTarProgram:  /* Dummy option.  */
          break;

        case oTarArgs:
          {
            int tar_argc;
            char **tar_argv;

            if (shell_parse_argv (pargs->r.ret_str, &tar_argc, &tar_argv))
              log_error ("failed to parse tar arguments '%s'\n",
                         pargs->r.ret_str);
            else
              {
                gpgrt_argparse_t tar_args;
                tar_args.argc = &tar_argc;
                tar_args.argv = &tar_argv;
                tar_args.flags = ARGPARSE_FLAG_ARG0;
                parse_arguments (&tar_args, tar_opts);
                gpgrt_argparse (NULL, &tar_args, NULL);
                if (tar_args.err)
                  log_error ("unsupported tar arguments '%s'\n",
                             pargs->r.ret_str);
                pargs->err = tar_args.err;
              }
          }
          break;

        case oDebug:
          any_debug = 1;
          break;

        case oDryRun:
          opt.dry_run = 1;
          break;

        default: pargs->err = 2; break;
	}
    }
}



/* gpgtar main. */
int
main (int argc, char **argv)
{
  gpg_error_t err;
  const char *fname;
  gpgrt_argparse_t pargs;

  gnupg_reopen_std (GPGTAR_NAME);
  gpgrt_set_strusage (my_strusage);
  log_set_prefix (GPGTAR_NAME, GPGRT_LOG_WITH_PREFIX|GPGRT_LOG_NO_REGISTRY);

  /* Make sure that our subsystems are ready.  */
  i18n_init();
  init_common_subsystems (&argc, &argv);
  gnupg_init_signals (0, NULL);

  log_assert (sizeof (struct ustar_raw_header) == 512);

  /* Set default options */
  opt.status_fd = -1;

  /* The configuraton directories for use by gpgrt_argparser.  */
  gpgrt_set_confdir (GPGRT_CONFDIR_SYS, gnupg_sysconfdir ());
  gpgrt_set_confdir (GPGRT_CONFDIR_USER, gnupg_homedir ());

  /* Parse the command line. */
  pargs.argc  = &argc;
  pargs.argv  = &argv;
  pargs.flags = ARGPARSE_FLAG_KEEP;
  parse_arguments (&pargs, opts);
  gpgrt_argparse (NULL, &pargs, NULL);

  if (log_get_errorcount (0))
    exit (2);

  /* Get a log file from common.conf.  */
  if (!parse_comopt (GNUPG_MODULE_NAME_GPGTAR, any_debug) && comopt.logfile)
    log_set_file (comopt.logfile);

  /* Print a warning if an argument looks like an option.  */
  if (!opt.quiet && !(pargs.flags & ARGPARSE_FLAG_STOP_SEEN))
    {
      int i;

      for (i=0; i < argc; i++)
        if (argv[i][0] == '-' && argv[i][1] == '-')
          log_info (_("NOTE: '%s' is not considered an option\n"), argv[i]);
    }

  /* Set status stream for our own use of --status-fd.  The original
   * status fd is passed verbatim to gpg.  */
  if (opt.status_fd != -1)
    {
      int fd = translate_sys2libc_fd_int (opt.status_fd, 1);

      if (!gnupg_fd_valid (fd))
        log_fatal ("status-fd is invalid: %s\n", strerror (errno));

      if (fd == 1)
        {
          opt.status_stream = es_stdout;
          if (!skip_crypto)
            log_fatal ("using stdout for the status-fd is not possible\n");
        }
      else if (fd == 2)
        opt.status_stream = es_stderr;
      else
        {
          opt.status_stream = es_fdopen (fd, "w");
          if (opt.status_stream)
            es_setvbuf (opt.status_stream, NULL, _IOLBF, 0);
        }
      if (!opt.status_stream)
        {
          log_fatal ("can't open fd %d for status output: %s\n",
                     fd, strerror (errno));
        }
    }

  if (! opt.gpg_program)
    opt.gpg_program = gnupg_module_name (GNUPG_MODULE_NAME_GPG);

  if (opt.verbose > 1)
    opt.debug_level = 1024;

  switch (cmd)
    {
    case aDecrypt:
    case aList:
      if (argc > 1)
        gpgrt_usage (1);
      fname = (argc && strcmp (*argv, "-"))? *argv : NULL;
      if (opt.filename)
        log_info ("note: ignoring option --set-filename\n");
      if (files_from)
        log_info ("note: ignoring option --files-from\n");
      if (cmd == aDecrypt)
        {
          err = gpgtar_extract (fname, !skip_crypto);
          if (err && !log_get_errorcount (0))
            log_error ("extracting archive failed: %s\n", gpg_strerror (err));
        }
      else
        {
          err = gpgtar_list (fname, !skip_crypto);
          if (err && !log_get_errorcount (0))
            log_error ("listing archive failed: %s\n", gpg_strerror (err));
        }
      break;

    case aEncrypt:
    case aSign:
    case aSignEncrypt:
      if ((!argc && !files_from)
          || (argc && files_from))
        gpgrt_usage (1);
      if (opt.filename)
        log_info ("note: ignoring option --set-filename\n");
      err = gpgtar_create (files_from? NULL : argv,
                           files_from,
                           null_names,
                           !skip_crypto
                           && (cmd == aEncrypt || cmd == aSignEncrypt),
                           cmd == aSign || cmd == aSignEncrypt);
      if (err && log_get_errorcount (0) == 0)
        log_error ("creating archive failed: %s\n", gpg_strerror (err));
      break;

    default:
      log_error (_("invalid command (there is no implicit command)\n"));
      err = 0;
      break;
    }

  if (opt.status_stream)
    {
      if (err || log_get_errorcount (0))
        es_fprintf (opt.status_stream, "[GNUPG:] FAILURE - %u\n",
                    err? err : gpg_error (GPG_ERR_GENERAL));
      else
        es_fprintf (opt.status_stream, "[GNUPG:] SUCCESS\n");
    }

  return log_get_errorcount (0)? 1:0;
}


/* Read the next record from STREAM.  RECORD is a buffer provided by
   the caller and must be at least of size RECORDSIZE.  The function
   return 0 on success and error code on failure; a diagnostic
   printed as well.  Note that there is no need for an EOF indicator
   because a tarball has an explicit EOF record. */
gpg_error_t
read_record (estream_t stream, void *record)
{
  gpg_error_t err;
  size_t nread;

  nread = es_fread (record, 1, RECORDSIZE, stream);
  if (nread != RECORDSIZE)
    {
      err = gpg_error_from_syserror ();
      if (es_ferror (stream))
        log_error ("error reading '%s': %s\n",
                   es_fname_get (stream), gpg_strerror (err));
      else
        log_error ("error reading '%s': premature EOF "
                   "(size of last record: %zu)\n",
                   es_fname_get (stream), nread);
    }
  else
    err = 0;

  return err;
}


/* Write the RECORD of size RECORDSIZE to STREAM.  FILENAME is the
   name of the file used for diagnostics.  */
gpg_error_t
write_record (estream_t stream, const void *record)
{
  gpg_error_t err;
  size_t nwritten;

  nwritten = es_fwrite (record, 1, RECORDSIZE, stream);
  if (nwritten != RECORDSIZE)
    {
      err = gpg_error_from_syserror ();
      log_error ("error writing '%s': %s\n",
                 es_fname_get (stream), gpg_strerror (err));
    }
  else
    err = 0;

  return err;
}


/* Return true if FP is an unarmored OpenPGP message.  Note that this
   function reads a few bytes from FP but pushes them back.  */
#if 0
static int
openpgp_message_p (estream_t fp)
{
  int ctb;

  ctb = es_getc (fp);
  if (ctb != EOF)
    {
      if (es_ungetc (ctb, fp))
        log_fatal ("error ungetting first byte: %s\n",
                   gpg_strerror (gpg_error_from_syserror ()));

      if ((ctb & 0x80))
        {
          switch ((ctb & 0x40) ? (ctb & 0x3f) : ((ctb>>2)&0xf))
            {
            case PKT_MARKER:
            case PKT_SYMKEY_ENC:
            case PKT_ONEPASS_SIG:
            case PKT_PUBKEY_ENC:
            case PKT_SIGNATURE:
            case PKT_COMMENT:
            case PKT_OLD_COMMENT:
            case PKT_PLAINTEXT:
            case PKT_COMPRESSED:
            case PKT_ENCRYPTED:
              return 1; /* Yes, this seems to be an OpenPGP message.  */
            default:
              break;
            }
        }
    }
  return 0;
}
#endif
