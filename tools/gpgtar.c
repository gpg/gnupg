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
 * along with this program; if not, see <http://www.gnu.org/licenses/>.
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
#include <assuan.h>
#include <errno.h>
#include <npth.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>

#include "util.h"
#include "i18n.h"
#include "sysutils.h"
#include "../common/asshelp.h"
#include "../common/openpgpdefs.h"
#include "../common/init.h"

#include "gpgtar.h"


/* Constants to identify the commands and options. */
enum cmd_and_opt_values
  {
    aNull = 0,
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
    oNull
  };


/* The list of commands and options. */
static ARGPARSE_OPTS opts[] = {
  ARGPARSE_group (300, N_("@Commands:\n ")),

  ARGPARSE_c (aEncrypt,   "encrypt", N_("create an archive")),
  ARGPARSE_c (aDecrypt,   "decrypt", N_("extract an archive")),
  ARGPARSE_c (aSign,      "sign",    N_("create a signed archive")),
  ARGPARSE_c (aList,      "list-archive", N_("list an archive")),

  ARGPARSE_group (301, N_("@\nOptions:\n ")),

  ARGPARSE_s_n (oSymmetric, "symmetric", N_("use symmetric encryption")),
  ARGPARSE_s_s (oRecipient, "recipient", N_("|USER-ID|encrypt for USER-ID")),
  ARGPARSE_s_s (oUser, "local-user",
                N_("|USER-ID|use USER-ID to sign or decrypt")),
  ARGPARSE_s_s (oOutput, "output", N_("|FILE|write output to FILE")),
  ARGPARSE_s_s (oDirectory, "directory",
                N_("|DIRECTORY|extract files into DIRECTORY")),
  ARGPARSE_s_n (oVerbose, "verbose", N_("verbose")),
  ARGPARSE_s_n (oQuiet,	"quiet",  N_("be somewhat more quiet")),
  ARGPARSE_s_s (oGpgProgram, "gpg", "@"),
  ARGPARSE_s_n (oSkipCrypto, "skip-crypto", N_("skip the crypto processing")),
  ARGPARSE_s_s (oSetFilename, "set-filename", "@"),
  ARGPARSE_s_s (oFilesFrom, "files-from",
                N_("|FILE|get names to create from FILE")),
  ARGPARSE_s_n (oNull, "null", N_("-T reads null-terminated names")),
  ARGPARSE_s_n (oOpenPGP, "openpgp", "@"),
  ARGPARSE_s_n (oCMS, "cms", "@"),

  ARGPARSE_end ()
};



/* Print usage information and and provide strings for help. */
static const char *
my_strusage( int level )
{
  const char *p;

  switch (level)
    {
    case 11: p = "@GPGTAR@ (@GNUPG@)";
      break;
    case 13: p = VERSION; break;
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
  enum cmd_and_opt_values cmd = *ret_cmd;

  if (!cmd || cmd == new_cmd)
    cmd = new_cmd;
  else if (cmd == aSign && new_cmd == aEncrypt)
    cmd = aSignEncrypt;
  else if (cmd == aEncrypt && new_cmd == aSign)
    cmd = aSignEncrypt;
  else
    {
      log_error (_("conflicting commands\n"));
      exit (2);
    }

  *ret_cmd = cmd;
}

ASSUAN_SYSTEM_NPTH_IMPL;


/* gpgtar main. */
int
main (int argc, char **argv)
{
  gpg_error_t err;
  ARGPARSE_ARGS pargs;
  const char *fname;
  int no_more_options = 0;
  enum cmd_and_opt_values cmd = 0;
  int skip_crypto = 0;
  const char *files_from = NULL;
  int null_names = 0;

  assert (sizeof (struct ustar_raw_header) == 512);

  gnupg_reopen_std (GPGTAR_NAME);
  set_strusage (my_strusage);
  log_set_prefix (GPGTAR_NAME, 1);

  /* Make sure that our subsystems are ready.  */
  i18n_init();
  init_common_subsystems (&argc, &argv);
  npth_init ();
  assuan_set_assuan_log_prefix (log_get_prefix (NULL));
  assuan_set_gpg_err_source (GPG_ERR_SOURCE_DEFAULT);
  assuan_set_system_hooks (ASSUAN_SYSTEM_NPTH);
  assuan_sock_init ();

  /* Parse the command line. */
  pargs.argc  = &argc;
  pargs.argv  = &argv;
  pargs.flags = ARGPARSE_FLAG_KEEP;
  while (!no_more_options && optfile_parse (NULL, NULL, NULL, &pargs, opts))
    {
      switch (pargs.r_opt)
        {
        case oOutput:    opt.outfile = pargs.r.ret_str; break;
        case oDirectory: opt.directory = pargs.r.ret_str; break;
        case oSetFilename: opt.filename = pargs.r.ret_str; break;
	case oQuiet:     opt.quiet = 1; break;
        case oVerbose:   opt.verbose++; break;
        case oNoVerbose: opt.verbose = 0; break;
        case oFilesFrom: files_from = pargs.r.ret_str; break;
        case oNull: null_names = 1; break;

	case aList:
        case aDecrypt:
        case aEncrypt:
        case aSign:
          set_cmd (&cmd, pargs.r_opt);
	  break;

        case oRecipient:
          add_to_strlist (&opt.recipients, pargs.r.ret_str);
          break;

        case oUser:
          log_info ("note: ignoring option --user\n");
          opt.user = pargs.r.ret_str;
          break;

        case oSymmetric:
          log_info ("note: ignoring option --symmetric\n");
          set_cmd (&cmd, aEncrypt);
          opt.symmetric = 1;
          break;

        case oGpgProgram:
          opt.gpg_program = pargs.r.ret_str;
          break;

        case oSkipCrypto:
          skip_crypto = 1;
          break;

        case oOpenPGP: /* Dummy option for now.  */ break;
        case oCMS:     /* Dummy option for now.  */ break;

        default: pargs.err = 2; break;
	}
    }

  if ((files_from && !null_names) || (!files_from && null_names))
    log_error ("--files-from and --null may only be used in conjunction\n");
  if (files_from && strcmp (files_from, "-"))
    log_error ("--files-from only supports argument \"-\"\n");

  if (log_get_errorcount (0))
    exit (2);

  /* Print a warning if an argument looks like an option.  */
  if (!opt.quiet && !(pargs.flags & ARGPARSE_FLAG_STOP_SEEN))
    {
      int i;

      for (i=0; i < argc; i++)
        if (argv[i][0] == '-' && argv[i][1] == '-')
          log_info (_("NOTE: '%s' is not considered an option\n"), argv[i]);
    }

  if (opt.verbose > 1)
    opt.debug_level = 1024;
  setup_libassuan_logging (&opt.debug_level);

  switch (cmd)
    {
    case aList:
      if (argc > 1)
        usage (1);
      fname = argc ? *argv : NULL;
      if (opt.filename)
        log_info ("note: ignoring option --set-filename\n");
      if (files_from)
        log_info ("note: ignoring option --files-from\n");
      err = gpgtar_list (fname, !skip_crypto);
      if (err && log_get_errorcount (0) == 0)
        log_error ("listing archive failed: %s\n", gpg_strerror (err));
      break;

    case aEncrypt:
      if ((!argc && !null_names)
          || (argc && null_names))
        usage (1);
      if (opt.filename)
        log_info ("note: ignoring option --set-filename\n");
      err = gpgtar_create (null_names? NULL :argv, !skip_crypto);
      if (err && log_get_errorcount (0) == 0)
        log_error ("creating archive failed: %s\n", gpg_strerror (err));
      break;

    case aDecrypt:
      if (argc != 1)
        usage (1);
      if (opt.outfile)
        log_info ("note: ignoring option --output\n");
      if (files_from)
        log_info ("note: ignoring option --files-from\n");
      fname = argc ? *argv : NULL;
      err = gpgtar_extract (fname, !skip_crypto);
      if (err && log_get_errorcount (0) == 0)
        log_error ("extracting archive failed: %s\n", gpg_strerror (err));
      break;

    default:
      log_error (_("invalid command (there is no implicit command)\n"));
      break;
    }

  return log_get_errorcount (0)? 1:0;
}


/* Read the next record from STREAM.  RECORD is a buffer provided by
   the caller and must be at leadt of size RECORDSIZE.  The function
   return 0 on success and and error code on failure; a diagnostic
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
