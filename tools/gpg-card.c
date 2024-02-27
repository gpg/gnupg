/* gpg-card.c - An interactive tool to work with cards.
 * Copyright (C) 2019--2022 g10 Code GmbH
 *
 * This file is part of GnuPG.
 *
 * This file is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 *
 * This file is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, see <https://gnu.org/licenses/>.
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

#include <config.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#ifdef HAVE_LIBREADLINE
# define GNUPG_LIBREADLINE_H_INCLUDED
# include <readline/readline.h>
#endif /*HAVE_LIBREADLINE*/

#define INCLUDED_BY_MAIN_MODULE 1

#include "../common/util.h"
#include "../common/status.h"
#include "../common/i18n.h"
#include "../common/init.h"
#include "../common/sysutils.h"
#include "../common/asshelp.h"
#include "../common/userids.h"
#include "../common/ccparray.h"
#include "../common/exectool.h"
#include "../common/exechelp.h"
#include "../common/ttyio.h"
#include "../common/server-help.h"
#include "../common/openpgpdefs.h"
#include "../common/tlv.h"
#include "../common/comopt.h"

#include "gpg-card.h"


#define CONTROL_D ('D' - 'A' + 1)

#define HISTORYNAME ".gpg-card_history"

/* Constants to identify the commands and options. */
enum opt_values
  {
    aNull = 0,

    oQuiet      = 'q',
    oVerbose	= 'v',

    oDebug      = 500,

    oGpgProgram,
    oGpgsmProgram,
    oStatusFD,
    oWithColons,
    oNoAutostart,
    oAgentProgram,

    oDisplay,
    oTTYname,
    oTTYtype,
    oXauthority,
    oLCctype,
    oLCmessages,

    oNoKeyLookup,
    oNoHistory,
    oChUid,

    oDummy
  };


/* The list of commands and options. */
static gpgrt_opt_t opts[] = {
  ARGPARSE_group (301, ("@\nOptions:\n ")),

  ARGPARSE_s_n (oVerbose, "verbose", ("verbose")),
  ARGPARSE_s_n (oQuiet,	"quiet",  ("be somewhat more quiet")),
  ARGPARSE_s_s (oDebug, "debug", "@"),
  ARGPARSE_s_s (oGpgProgram, "gpg", "@"),
  ARGPARSE_s_s (oGpgsmProgram, "gpgsm", "@"),
  ARGPARSE_s_i (oStatusFD, "status-fd", N_("|FD|write status info to this FD")),
  ARGPARSE_s_n (oWithColons, "with-colons", "@"),
  ARGPARSE_s_n (oNoAutostart, "no-autostart", "@"),
  ARGPARSE_s_s (oAgentProgram, "agent-program", "@"),
  ARGPARSE_s_s (oDisplay,    "display",    "@"),
  ARGPARSE_s_s (oTTYname,    "ttyname",    "@"),
  ARGPARSE_s_s (oTTYtype,    "ttytype",    "@"),
  ARGPARSE_s_s (oXauthority, "xauthority", "@"),
  ARGPARSE_s_s (oLCctype,    "lc-ctype",   "@"),
  ARGPARSE_s_s (oLCmessages, "lc-messages","@"),
  ARGPARSE_s_n (oNoKeyLookup,"no-key-lookup",
                "use --no-key-lookup for \"list\""),
  ARGPARSE_s_n (oNoHistory,"no-history",
                "do not use the command history file"),
  ARGPARSE_s_s (oChUid,      "chuid",      "@"),

  ARGPARSE_end ()
};

/* The list of supported debug flags.  */
static struct debug_flags_s debug_flags [] =
  {
    { DBG_IPC_VALUE    , "ipc"     },
    { DBG_EXTPROG_VALUE, "extprog" },
    { 0, NULL }
  };


/* An object to create lists of labels and keyrefs.  */
struct keyinfolabel_s
{
  const char *label;
  const char *keyref;
};
typedef struct keyinfolabel_s *keyinfolabel_t;

/* Helper for --chuid.  */
static const char *changeuser;

/* Limit of size of data we read from a file for certain commands.  */
#define MAX_GET_DATA_FROM_FILE 16384

/* Constants for OpenPGP cards.  */
#define OPENPGP_USER_PIN_DEFAULT  "123456"
#define OPENPGP_ADMIN_PIN_DEFAULT "12345678"
#define OPENPGP_KDF_DATA_LENGTH_MIN  90
#define OPENPGP_KDF_DATA_LENGTH_MAX 110




/* Local prototypes.  */
static void show_keysize_warning (void);
static gpg_error_t dispatch_command (card_info_t info, const char *command);
static void interactive_loop (void);
#ifdef HAVE_LIBREADLINE
static char **command_completion (const char *text, int start, int end);
#endif /*HAVE_LIBREADLINE*/



/* Print usage information and provide strings for help. */
static const char *
my_strusage( int level )
{
  const char *p;

  switch (level)
    {
    case  9: p = "GPL-3.0-or-later"; break;
    case 11: p = "gpg-card"; break;
    case 12: p = "@GNUPG@"; break;
    case 13: p = VERSION; break;
    case 14: p = GNUPG_DEF_COPYRIGHT_LINE; break;
    case 17: p = PRINTABLE_OS_NAME; break;
    case 19: p = ("Please report bugs to <@EMAIL@>.\n"); break;

    case 1:
    case 40:
      p = ("Usage: gpg-card"
           " [options] [{[--] command [args]}]  (-h for help)");
      break;
    case 41:
      p = ("Syntax: gpg-card"
           " [options] [command [args] {-- command [args]}]\n\n"
           "Tool to manage cards and tokens.  Without a command an interactive\n"
           "mode is used.  Use command \"help\" to list all commands.");
      break;

    default: p = NULL; break;
    }
  return p;
}


static void
set_opt_session_env (const char *name, const char *value)
{
  gpg_error_t err;

  err = session_env_setenv (opt.session_env, name, value);
  if (err)
    log_fatal ("error setting session environment: %s\n",
               gpg_strerror (err));
}



/* Command line parsing.  */
static void
parse_arguments (gpgrt_argparse_t *pargs, gpgrt_opt_t *popts)
{
  while (gpgrt_argparse (NULL, pargs, popts))
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
          opt.gpg_program = make_filename (pargs->r.ret_str, NULL);
          break;
        case oGpgsmProgram:
          opt.gpgsm_program = make_filename (pargs->r.ret_str, NULL);
          break;
        case oAgentProgram:
          opt.agent_program = make_filename (pargs->r.ret_str, NULL);
          break;

        case oStatusFD:
          gnupg_set_status_fd (translate_sys2libc_fd_int (pargs->r.ret_int, 1));
          break;

        case oWithColons:  opt.with_colons = 1; break;
        case oNoAutostart: opt.autostart = 0; break;

        case oDisplay: set_opt_session_env ("DISPLAY", pargs->r.ret_str); break;
        case oTTYname: set_opt_session_env ("GPG_TTY", pargs->r.ret_str); break;
        case oTTYtype: set_opt_session_env ("TERM", pargs->r.ret_str); break;
        case oXauthority: set_opt_session_env ("XAUTHORITY",
                                               pargs->r.ret_str); break;
        case oLCctype:     opt.lc_ctype = pargs->r.ret_str; break;
        case oLCmessages:  opt.lc_messages = pargs->r.ret_str; break;

        case oNoKeyLookup: opt.no_key_lookup = 1; break;
        case oNoHistory:   opt.no_history = 1; break;

        case oChUid:       changeuser = pargs->r.ret_str; break;

        default: pargs->err = 2; break;
	}
    }
}



/* gpg-card main. */
int
main (int argc, char **argv)
{
  gpg_error_t err;
  gpgrt_argparse_t pargs;
  char **command_list = NULL;
  int cmdidx;
  char *command;

  gnupg_reopen_std ("gpg-card");
  gpgrt_set_strusage (my_strusage);
  gnupg_rl_initialize ();
  log_set_prefix ("gpg-card", GPGRT_LOG_WITH_PREFIX);

  /* Make sure that our subsystems are ready.  */
  i18n_init();
  init_common_subsystems (&argc, &argv);

  assuan_set_gpg_err_source (GPG_ERR_SOURCE_DEFAULT);
  setup_libassuan_logging (&opt.debug, NULL);

  /* Setup default options.  */
  opt.autostart = 1;
  opt.session_env = session_env_new ();
  if (!opt.session_env)
    log_fatal ("error allocating session environment block: %s\n",
               gpg_strerror (gpg_error_from_syserror ()));


  /* Parse the command line. */
  pargs.argc  = &argc;
  pargs.argv  = &argv;
  pargs.flags = ARGPARSE_FLAG_KEEP;
  parse_arguments (&pargs, opts);
  gpgrt_argparse (NULL, &pargs, NULL);  /* Release internal state.  */

  if (changeuser && gnupg_chuid (changeuser, 0))
    log_inc_errorcount (); /* Force later termination.  */

  if (log_get_errorcount (0))
    exit (2);

  /* Process common component options.  */
  gpgrt_set_confdir (GPGRT_CONFDIR_SYS, gnupg_sysconfdir ());
  gpgrt_set_confdir (GPGRT_CONFDIR_USER, gnupg_homedir ());
  if (parse_comopt (GNUPG_MODULE_NAME_CARD, opt.debug))
    {
      gnupg_status_printf (STATUS_FAILURE, "option-parser %u",
                           gpg_error (GPG_ERR_GENERAL));
      exit(2);
    }

  if (comopt.no_autostart)
     opt.autostart = 0;

  /* Set defaults for non given options.  */
  if (!opt.gpg_program)
    opt.gpg_program = gnupg_module_name (GNUPG_MODULE_NAME_GPG);
  if (!opt.gpgsm_program)
    opt.gpgsm_program = gnupg_module_name (GNUPG_MODULE_NAME_GPGSM);

  /* Now build the list of commands.  We guess the size of the array
   * by assuming each item is a complete command.  Obviously this will
   * be rarely the case, but it is less code to allocate a possible
   * too large array.  */
  command_list = xcalloc (argc+1, sizeof *command_list);
  cmdidx = 0;
  command = NULL;
  while (argc)
    {
      for ( ; argc && strcmp (*argv, "--"); argc--, argv++)
        {
          if (!command)
            command = xstrdup (*argv);
          else
            {
              char *tmp = xstrconcat (command, " ", *argv, NULL);
              xfree (command);
              command = tmp;
            }
        }
      if (argc)
        { /* Skip the double dash.  */
          argc--;
          argv++;
        }
      if (command)
        {
          command_list[cmdidx++] = command;
          command = NULL;
        }
    }
  opt.interactive = !cmdidx;

  if (!opt.interactive)
    opt.no_history = 1;

  if (opt.interactive)
    {
      interactive_loop ();
      err = 0;
    }
  else
    {
      struct card_info_s info_buffer = { 0 };
      card_info_t info = &info_buffer;

      err = 0;
      for (cmdidx=0; (command = command_list[cmdidx]); cmdidx++)
        {
          err = dispatch_command (info, command);
          if (err)
            break;
        }
      if (gpg_err_code (err) == GPG_ERR_EOF)
        err = 0; /* This was a "quit".  */
      else if (command && !opt.quiet)
        log_info ("stopped at command '%s'\n", command);
    }

  flush_keyblock_cache ();
  if (command_list)
    {
      for (cmdidx=0; command_list[cmdidx]; cmdidx++)
        xfree (command_list[cmdidx]);
      xfree (command_list);
    }
  if (err)
    gnupg_status_printf (STATUS_FAILURE, "- %u", err);
  else if (log_get_errorcount (0))
    gnupg_status_printf (STATUS_FAILURE, "- %u", GPG_ERR_GENERAL);
  else
    gnupg_status_printf (STATUS_SUCCESS, NULL);
  return log_get_errorcount (0)? 1:0;
}


/* Return S or the string "[none]" if S is NULL.  */
static GPGRT_INLINE const char *
nullnone (const char *s)
{
  return s? s: "[none]";
}


/* Read data from file FNAME up to MAX_GET_DATA_FROM_FILE characters.
 * On error return an error code and stores NULL at R_BUFFER; on
 * success returns 0 and stores the number of bytes read at R_BUFLEN
 * and the address of a newly allocated buffer at R_BUFFER.  A
 * complementary nul byte is always appended to the data but not
 * counted; this allows one to pass NULL for R-BUFFER and consider the
 * returned data as a string. */
static gpg_error_t
get_data_from_file (const char *fname, char **r_buffer, size_t *r_buflen)
{
  gpg_error_t err;
  estream_t fp;
  char *data;
  int n;

  *r_buffer = NULL;
  if (r_buflen)
    *r_buflen = 0;

  fp = es_fopen (fname, "rb");
  if (!fp)
    {
      err = gpg_error_from_syserror ();
      log_error (_("can't open '%s': %s\n"), fname, gpg_strerror (err));
      return err;
    }

  data = xtrymalloc (MAX_GET_DATA_FROM_FILE);
  if (!data)
    {
      err = gpg_error_from_syserror ();
      log_error (_("error allocating enough memory: %s\n"), gpg_strerror (err));
      es_fclose (fp);
      return err;
    }

  n = es_fread (data, 1, MAX_GET_DATA_FROM_FILE - 1, fp);
  es_fclose (fp);
  if (n < 0)
    {
      err = gpg_error_from_syserror ();
      tty_printf (_("error reading '%s': %s\n"), fname, gpg_strerror (err));
      xfree (data);
      return err;
    }
  data[n] = 0;

  *r_buffer = data;
  if (r_buflen)
    *r_buflen = n;
  return 0;
}


/* Fixup the ENODEV error from scdaemon which we may see after
 * removing a card due to scdaemon scanning for readers with cards.
 * We also map the CAERD REMOVED error to the more useful CARD_NOT
 * PRESENT.  */
static gpg_error_t
fixup_scd_errors (gpg_error_t err)
{
  if ((gpg_err_code (err) == GPG_ERR_ENODEV
       || gpg_err_code (err) == GPG_ERR_CARD_REMOVED)
      && gpg_err_source (err) == GPG_ERR_SOURCE_SCD)
    err = gpg_error (GPG_ERR_CARD_NOT_PRESENT);
  return err;
}


/* Set the card removed flag from INFO depending on ERR.  This does
 * not clear the flag.  */
static gpg_error_t
maybe_set_card_removed (card_info_t info, gpg_error_t err)
{
  if ((gpg_err_code (err) == GPG_ERR_ENODEV
       || gpg_err_code (err) == GPG_ERR_CARD_REMOVED)
      && gpg_err_source (err) == GPG_ERR_SOURCE_SCD)
    info->card_removed = 1;
  return err;
}


/* Write LENGTH bytes from BUFFER to file FNAME.  Return 0 on
 * success.  */
static gpg_error_t
put_data_to_file (const char *fname, const void *buffer, size_t length)
{
  gpg_error_t err;
  estream_t fp;

  fp = es_fopen (fname, "wb");
  if (!fp)
    {
      err = gpg_error_from_syserror ();
      log_error (_("can't create '%s': %s\n"), fname, gpg_strerror (err));
      return err;
    }

  if (length && es_fwrite (buffer, length, 1, fp) != 1)
    {
      err = gpg_error_from_syserror ();
      log_error (_("error writing '%s': %s\n"), fname, gpg_strerror (err));
      es_fclose (fp);
      return err;
    }
  if (es_fclose (fp))
    {
      err = gpg_error_from_syserror ();
      log_error (_("error writing '%s': %s\n"), fname, gpg_strerror (err));
      return err;
    }
  return 0;
}


/* Return a malloced string with the number opf the menu PROMPT.
 * Control-D is mapped to "Q".  */
static char *
get_selection (const char *prompt)
{
  char *answer;

  tty_printf ("\n");
  tty_printf ("%s", prompt);
  tty_printf ("\n");
  answer = tty_get (_("Your selection? "));
  tty_kill_prompt ();
  if (*answer == CONTROL_D)
    strcpy (answer, "q");
  return answer;
}



/* Simply prints TEXT to the output.  Returns 0 as a convenience.
 * This is a separate function so that it can be extended to run
 * less(1) or so.  The extra arguments are int values terminated by a
 * 0 to indicate card application types supported with this command.
 * If none are given (just the final 0), this is a general
 * command.  */
static gpg_error_t
print_help (const char *text, ...)
{
  estream_t fp;
  va_list arg_ptr;
  int value;
  int any = 0;

  fp = opt.interactive? NULL : es_stdout;
  tty_fprintf (fp, "%s\n", text);

  va_start (arg_ptr, text);
  while ((value = va_arg (arg_ptr, int)))
    {
      if (!any)
        tty_fprintf (fp, "[Supported by: ");
      tty_fprintf (fp, "%s%s", any?", ":"", app_type_string (value));
      any = 1;
    }
  if (any)
    tty_fprintf (fp, "]\n");

  va_end (arg_ptr);
  return 0;
}


/* Print an (OpenPGP) fingerprint.  */
static void
print_shax_fpr (estream_t fp, const unsigned char *fpr, unsigned int fprlen)
{
  int i;

  if (fpr)
    {
      for (i=0; i < fprlen ; i++, fpr++)
        tty_fprintf (fp, "%02X", *fpr);
    }
  else
    tty_fprintf (fp, " [none]");
  tty_fprintf (fp, "\n");
}

/* Print the keygrip GRP.  */
static void
print_keygrip (estream_t fp, const unsigned char *grp, int with_lf)
{
  int i;

  for (i=0; i < 20 ; i++, grp++)
    tty_fprintf (fp, "%02X", *grp);
  if (with_lf)
    tty_fprintf (fp, "\n");
}


/* Print a string but avoid printing control characters.  */
static void
print_string (estream_t fp, const char *text, const char *name)
{
  tty_fprintf (fp, "%s", text);

  /* FIXME: tty_printf_utf8_string2 eats everything after and
     including an @ - e.g. when printing an url. */
  if (name && *name)
    {
      if (fp)
        print_utf8_buffer2 (fp, name, strlen (name), '\n');
      else
        tty_print_utf8_string2 (NULL, name, strlen (name), 0);
    }
  else
    tty_fprintf (fp, _("[not set]"));
  tty_fprintf (fp, "\n");
}


/* Print an ISO formatted name or "[not set]".  */
static void
print_isoname (estream_t fp, const char *name)
{
  if (name && *name)
    {
      char *p, *given, *buf;

      buf = xstrdup (name);
      given = strstr (buf, "<<");
      for (p=buf; *p; p++)
        if (*p == '<')
          *p = ' ';
      if (given && given[2])
        {
          *given = 0;
          given += 2;
          if (fp)
            print_utf8_buffer2 (fp, given, strlen (given), '\n');
          else
            tty_print_utf8_string2 (NULL, given, strlen (given), 0);

          if (*buf)
            tty_fprintf (fp, " ");
        }

      if (fp)
        print_utf8_buffer2 (fp, buf, strlen (buf), '\n');
      else
        tty_print_utf8_string2 (NULL, buf, strlen (buf), 0);

      xfree (buf);
    }
  else
    {
      tty_fprintf (fp, _("[not set]"));
    }

  tty_fprintf (fp, "\n");
}


/* Return true if the buffer MEM of length memlen consists only of zeroes. */
static int
mem_is_zero (const char *mem, unsigned int memlen)
{
  int i;

  for (i=0; i < memlen && !mem[i]; i++)
    ;
  return (i == memlen);
}



/* Helper to list a single keyref.  LABEL_KEYREF is a fallback key
 * reference if no info is available; it may be NULL.  */
static void
list_one_kinfo (card_info_t info, key_info_t kinfo,
                const char *label_keyref, estream_t fp, int no_key_lookup,
                int create_shadow)
{
  gpg_error_t err;
  key_info_t firstkinfo = info->kinfo;
  keyblock_t keyblock = NULL;
  keyblock_t kb;
  pubkey_t pubkey;
  userid_t uid;
  key_info_t ki;
  const char *s;
  gcry_sexp_t s_pkey;
  int any;

  if (firstkinfo && kinfo)
    {
      tty_fprintf (fp, " ");
      if (mem_is_zero (kinfo->grip, sizeof kinfo->grip))
        {
          tty_fprintf (fp, "[none]\n");
          tty_fprintf (fp, "      keyref .....: %s\n", kinfo->keyref);
          if (kinfo->label)
            tty_fprintf (fp, "      label ......: %s\n", kinfo->label);
          tty_fprintf (fp, "      algorithm ..: %s\n",
                       nullnone (kinfo->keyalgo));
          goto leave;
        }

      print_keygrip (fp, kinfo->grip, 1);
      tty_fprintf (fp, "      keyref .....: %s", kinfo->keyref);
      if (kinfo->usage)
        {
          any = 0;
          tty_fprintf (fp, "  (");
          if ((kinfo->usage & GCRY_PK_USAGE_SIGN))
            { tty_fprintf (fp, "sign"); any=1; }
          if ((kinfo->usage & GCRY_PK_USAGE_CERT))
            { tty_fprintf (fp, "%scert", any?",":""); any=1; }
          if ((kinfo->usage & GCRY_PK_USAGE_AUTH))
            { tty_fprintf (fp, "%sauth", any?",":""); any=1; }
          if ((kinfo->usage & GCRY_PK_USAGE_ENCR))
            { tty_fprintf (fp, "%sencr", any?",":""); any=1; }
          tty_fprintf (fp, ")");
        }
      tty_fprintf (fp, "\n");

      if (kinfo->label)
        tty_fprintf (fp, "      label ......: %s\n", kinfo->label);

      if (!(err = scd_readkey (kinfo->keyref, create_shadow, &s_pkey)))
        {
          char *tmp = pubkey_algo_string (s_pkey, NULL);
          tty_fprintf (fp, "      algorithm ..: %s\n", nullnone (tmp));
          xfree (tmp);
          gcry_sexp_release (s_pkey);
          s_pkey = NULL;
        }
      else
        {
          maybe_set_card_removed (info, err);
          tty_fprintf (fp, "      algorithm ..: %s\n",
                       nullnone (kinfo->keyalgo));
        }

      if (kinfo->fprlen && kinfo->created)
        {
          tty_fprintf (fp, "      stored fpr .: ");
          print_shax_fpr (fp, kinfo->fpr, kinfo->fprlen);
          tty_fprintf (fp, "      created ....: %s\n",
                       isotimestamp (kinfo->created));
        }
      if (no_key_lookup)
        err = 0;
      else
        err = get_matching_keys (kinfo->grip,
                                 (GNUPG_PROTOCOL_OPENPGP | GNUPG_PROTOCOL_CMS),
                                 &keyblock);
      if (err)
        {
          if (gpg_err_code (err) != GPG_ERR_NO_PUBKEY)
            tty_fprintf (fp, "      used for ...: [%s]\n", gpg_strerror (err));
          goto leave;
        }
      for (kb = keyblock; kb; kb = kb->next)
        {
          tty_fprintf (fp, "      used for ...: %s\n",
                       kb->protocol == GNUPG_PROTOCOL_OPENPGP? "OpenPGP" :
                       kb->protocol == GNUPG_PROTOCOL_CMS? "X.509" : "?");
          pubkey = kb->keys;
          if (kb->protocol == GNUPG_PROTOCOL_OPENPGP)
            {
              /* If this is not the primary key print the primary
               * key's fingerprint or a reference to it.  */
              tty_fprintf (fp, "        main key .: ");
              for (ki=firstkinfo; ki; ki = ki->next)
                if (pubkey->grip_valid
                    && !memcmp (ki->grip, pubkey->grip, KEYGRIP_LEN))
                  break;
              if (ki)
                {
                  /* Fixme: Replace mapping by a table lookup.  */
                  if (!memcmp (kinfo->grip, pubkey->grip, KEYGRIP_LEN))
                    s = "this";
                  else if (!strcmp (ki->keyref, "OPENPGP.1"))
                    s = "Signature key";
                  else if (!strcmp (ki->keyref, "OPENPGP.2"))
                    s = "Encryption key";
                  else if (!strcmp (ki->keyref, "OPENPGP.3"))
                    s = "Authentication key";
                  else
                    s = NULL;
                  if (s)
                    tty_fprintf (fp, "<%s>\n", s);
                  else
                    tty_fprintf (fp, "<Key %s>\n", ki->keyref);
                }
              else /* Print the primary key as fallback.  */
                print_shax_fpr (fp, pubkey->fpr, pubkey->fprlen);
            }
          if (kb->protocol == GNUPG_PROTOCOL_OPENPGP
              || kb->protocol == GNUPG_PROTOCOL_CMS)
            {
              /* Find the primary or subkey of that key.  */
              for (; pubkey; pubkey = pubkey->next)
                if (pubkey->grip_valid
                    && !memcmp (kinfo->grip, pubkey->grip, KEYGRIP_LEN))
                  break;
              if (pubkey)
                {
                  tty_fprintf (fp, "        fpr ......: ");
                  print_shax_fpr (fp, pubkey->fpr, pubkey->fprlen);
                  tty_fprintf (fp, "        created ..: %s\n",
                               isotimestamp (pubkey->created));
                }
            }
          for (uid = kb->uids; uid; uid = uid->next)
            {
              print_string (fp, "        user id ..: ", uid->value);
            }

        }
    }
  else
    {
      tty_fprintf (fp, " [none]\n");
      if (label_keyref)
        tty_fprintf (fp, "      keyref .....: %s\n", label_keyref);
      if (kinfo)
        tty_fprintf (fp, "      algorithm ..: %s\n",
                     nullnone (kinfo->keyalgo));
    }

 leave:
  release_keyblock (keyblock);
}


/* List all keyinfo in INFO using the list of LABELS.  */
static void
list_all_kinfo (card_info_t info, keyinfolabel_t labels, estream_t fp,
                int no_key_lookup, int create_shadow)
{
  key_info_t kinfo;
  int idx, i, j;

  /* Print the keyinfo.  We first print those we known and then all
   * remaining item.  */
  for (kinfo = info->kinfo; kinfo; kinfo = kinfo->next)
    kinfo->xflag = 0;
  if (labels)
    {
      for (idx=0; labels[idx].label; idx++)
        {
          tty_fprintf (fp, "%s", labels[idx].label);
          kinfo = find_kinfo (info, labels[idx].keyref);
          list_one_kinfo (info, kinfo, labels[idx].keyref,
                          fp, no_key_lookup, create_shadow);
          if (kinfo)
            kinfo->xflag = 1;
        }
    }
  for (kinfo = info->kinfo; kinfo; kinfo = kinfo->next)
    {
      if (kinfo->xflag)
        continue;
      tty_fprintf (fp, "Key %s", kinfo->keyref);
      for (i=4+strlen (kinfo->keyref), j=0; i < 18; i++, j=1)
        tty_fprintf (fp, j? ".":" ");
      tty_fprintf (fp, ":");
      list_one_kinfo (info, kinfo, NULL, fp, no_key_lookup, create_shadow);
    }
}


static void
list_retry_counter (card_info_t info, estream_t fp)
{
  const char *s;
  int i;

  if (info->chvlabels)
    tty_fprintf (fp, "PIN labels .......: %s\n", info->chvlabels);
  tty_fprintf (fp, "PIN retry counter :");
  for (i=0; i < DIM (info->chvinfo) && i < info->nchvinfo; i++)
    {
      if (info->chvinfo[i] >= 0)
        tty_fprintf (fp, " %d", info->chvinfo[i]);
      else
        {
          switch (info->chvinfo[i])
            {
            case -1: s = "[error]"; break;
            case -2: s = "-"; break;  /* No such PIN or info not available. */
            case -3: s = "[blocked]"; break;
            case -4: s = "[nullpin]"; break;
            case -5: s = "[verified]"; break;
            default: s = "[?]"; break;
            }
          tty_fprintf (fp, " %s", s);
        }
    }
  tty_fprintf (fp, "\n");
}


/* List OpenPGP card specific data.  */
static void
list_openpgp (card_info_t info, estream_t fp,
              int no_key_lookup, int create_shadow)
{
  static struct keyinfolabel_s keyinfolabels[] = {
    { "Signature key ....:", "OPENPGP.1" },
    { "Encryption key....:", "OPENPGP.2" },
    { "Authentication key:", "OPENPGP.3" },
    { NULL, NULL }
  };

  if (info->apptype != APP_TYPE_OPENPGP)
    {
      tty_fprintf (fp, "invalid OpenPGP card\n");
      return;
    }

  tty_fprintf (fp, "Name of cardholder: ");
  print_isoname (fp, info->disp_name);

  print_string (fp, "Language prefs ...: ", info->disp_lang);
  tty_fprintf (fp, "Salutation .......: %s\n",
               info->disp_sex == 1? _("Mr."):
               info->disp_sex == 2? _("Ms.") : "");
  print_string (fp, "URL of public key : ", info->pubkey_url);
  print_string (fp, "Login data .......: ", info->login_data);
  if (info->private_do[0])
    print_string (fp, "Private DO 1 .....: ", info->private_do[0]);
  if (info->private_do[1])
    print_string (fp, "Private DO 2 .....: ", info->private_do[1]);
  if (info->private_do[2])
    print_string (fp, "Private DO 3 .....: ", info->private_do[2]);
  if (info->private_do[3])
    print_string (fp, "Private DO 4 .....: ", info->private_do[3]);
  if (info->cafpr1len)
    {
      tty_fprintf (fp, "CA fingerprint %d .:", 1);
      print_shax_fpr (fp, info->cafpr1, info->cafpr1len);
    }
  if (info->cafpr2len)
    {
      tty_fprintf (fp, "CA fingerprint %d .:", 2);
      print_shax_fpr (fp, info->cafpr2, info->cafpr2len);
    }
  if (info->cafpr3len)
    {
      tty_fprintf (fp, "CA fingerprint %d .:", 3);
      print_shax_fpr (fp, info->cafpr3, info->cafpr3len);
    }
  tty_fprintf (fp, "Signature PIN ....: %s\n",
               info->chv1_cached? _("not forced"): _("forced"));
  tty_fprintf (fp, "Max. PIN lengths .: %d %d %d\n",
               info->chvmaxlen[0], info->chvmaxlen[1], info->chvmaxlen[2]);
  list_retry_counter (info, fp);
  tty_fprintf (fp, "Signature counter : %lu\n", info->sig_counter);
  tty_fprintf (fp, "Capabilities .....:");
  if (info->extcap.ki)
    tty_fprintf (fp, " key-import");
  if (info->extcap.aac)
    tty_fprintf (fp, " algo-change");
  if (info->extcap.bt)
    tty_fprintf (fp, " button");
  if (info->extcap.sm)
    tty_fprintf (fp, " sm(%s)", gcry_cipher_algo_name (info->extcap.smalgo));
  if (info->extcap.private_dos)
    tty_fprintf (fp, " priv-data");
  tty_fprintf (fp, "\n");
  if (info->extcap.kdf)
    {
      tty_fprintf (fp, "KDF setting ......: %s\n",
                   info->kdf_do_enabled ? "on" : "off");
    }
  if (info->extcap.bt)
    {
      tty_fprintf (fp, "UIF setting ......: Sign=%s Decrypt=%s Auth=%s\n",
                   info->uif[0] ? (info->uif[0]==2? "permanent": "on") : "off",
                   info->uif[1] ? (info->uif[0]==2? "permanent": "on") : "off",
                   info->uif[2] ? (info->uif[0]==2? "permanent": "on") : "off");
    }

  list_all_kinfo (info, keyinfolabels, fp, no_key_lookup, create_shadow);

}


/* List PIV card specific data.  */
static void
list_piv (card_info_t info, estream_t fp, int no_key_lookup, int create_shadow)
{
  static struct keyinfolabel_s keyinfolabels[] = {
    { "PIV authentication:", "PIV.9A" },
    { "Card authenticat. :", "PIV.9E" },
    { "Digital signature :", "PIV.9C" },
    { "Key management ...:", "PIV.9D" },
    { NULL, NULL }
  };

  if (info->chvusage[0] || info->chvusage[1])
    {
      tty_fprintf (fp, "PIN usage policy .:");
      if ((info->chvusage[0] & 0x40))
          tty_fprintf (fp, " app-pin");
      if ((info->chvusage[0] & 0x20))
        tty_fprintf (fp, " global-pin");
      if ((info->chvusage[0] & 0x10))
        tty_fprintf (fp, " occ");
      if ((info->chvusage[0] & 0x08))
        tty_fprintf (fp, " vci");
      if ((info->chvusage[0] & 0x08) && !(info->chvusage[0] & 0x04))
        tty_fprintf (fp, " pairing");

      if (info->chvusage[1] == 0x10)
        tty_fprintf (fp, " primary:card");
      else if (info->chvusage[1] == 0x20)
        tty_fprintf (fp, " primary:global");

      tty_fprintf (fp, "\n");
    }

  list_retry_counter (info, fp);
  list_all_kinfo (info, keyinfolabels, fp, no_key_lookup, create_shadow);
}


/* List Netkey card specific data.  */
static void
list_nks (card_info_t info, estream_t fp, int no_key_lookup, int create_shadow)
{
  static struct keyinfolabel_s keyinfolabels[] = {
    { NULL, NULL }
  };

  list_retry_counter (info, fp);
  list_all_kinfo (info, keyinfolabels, fp, no_key_lookup, create_shadow);
}


/* List PKCS#15 card specific data.  */
static void
list_p15 (card_info_t info, estream_t fp, int no_key_lookup, int create_shadow)
{
  static struct keyinfolabel_s keyinfolabels[] = {
    { NULL, NULL }
  };

  list_retry_counter (info, fp);
  list_all_kinfo (info, keyinfolabels, fp, no_key_lookup, create_shadow);
}


static void
print_a_version (estream_t fp, const char *prefix, unsigned int value)
{
  unsigned int a, b, c, d;
  a = ((value >> 24) & 0xff);
  b = ((value >> 16) & 0xff);
  c = ((value >>  8) & 0xff);
  d = ((value      ) & 0xff);

  if (a)
    tty_fprintf (fp, "%s %u.%u.%u.%u\n", prefix, a, b, c, d);
  else if (b)
    tty_fprintf (fp, "%s %u.%u.%u\n", prefix, b, c, d);
  else if (c)
    tty_fprintf (fp, "%s %u.%u\n", prefix, c, d);
  else
    tty_fprintf (fp, "%s %u\n", prefix, d);
}


/* Print all available information about the current card.  With
 * NO_KEY_LOOKUP the sometimes expensive listing of all matching
 * OpenPGP and X.509 keys is not done */
static void
list_card (card_info_t info, int no_key_lookup, int create_shadow)
{
  estream_t fp = opt.interactive? NULL : es_stdout;

  tty_fprintf (fp, "Reader ...........: %s\n", nullnone (info->reader));
  if (info->cardtype)
    tty_fprintf (fp, "Card type ........: %s\n", info->cardtype);
  if (info->cardversion)
    print_a_version (fp, "Card firmware ....:", info->cardversion);
  tty_fprintf (fp, "Serial number ....: %s\n", nullnone (info->serialno));
  tty_fprintf (fp, "Application type .: %s%s%s%s\n",
               app_type_string (info->apptype),
               info->apptype == APP_TYPE_UNKNOWN && info->apptypestr? "(":"",
               info->apptype == APP_TYPE_UNKNOWN && info->apptypestr
               ? info->apptypestr:"",
               info->apptype == APP_TYPE_UNKNOWN && info->apptypestr? ")":"");
  if (info->appversion)
    print_a_version (fp, "Version ..........:", info->appversion);
  if (info->serialno && info->dispserialno
      && strcmp (info->serialno, info->dispserialno))
    tty_fprintf (fp, "Displayed s/n ....: %s\n", info->dispserialno);

  if (info->manufacturer_name && info->manufacturer_id)
    tty_fprintf (fp, "Manufacturer .....: %s (%x)\n",
                 info->manufacturer_name, info->manufacturer_id);
  else if (info->manufacturer_name && !info->manufacturer_id)
    tty_fprintf (fp, "Manufacturer .....: %s\n", info->manufacturer_name);
  else if (info->manufacturer_id)
    tty_fprintf (fp, "Manufacturer .....: (%x)\n", info->manufacturer_id);

  switch (info->apptype)
    {
    case APP_TYPE_OPENPGP:
      list_openpgp (info, fp, no_key_lookup, create_shadow);
      break;
    case APP_TYPE_PIV:
      list_piv (info, fp, no_key_lookup, create_shadow);
      break;
    case APP_TYPE_NKS:
      list_nks (info, fp, no_key_lookup, create_shadow);
      break;
    case APP_TYPE_P15:
      list_p15 (info, fp, no_key_lookup, create_shadow);
      break;
    default: break;
    }
}



/* Helper for cmd_list.  */
static void
print_card_list (estream_t fp, card_info_t info, strlist_t cards,
                 int only_current)
{
  int count;
  strlist_t sl;
  size_t snlen;
  int star;
  const char *s;

  for (count = 0, sl = cards; sl; sl = sl->next, count++)
    {
      if (info && info->serialno)
        {
          s = strchr (sl->d, ' ');
          if (s)
            snlen = s - sl->d;
          else
            snlen = strlen (sl->d);
          star = (strlen (info->serialno) == snlen
                  && !memcmp (info->serialno, sl->d, snlen));
        }
      else
        star = 0;
      if (!only_current || star)
        tty_fprintf (fp, "%d%c %s\n", count, star? '*':' ', sl->d);
    }
}


/* The LIST command.  This also updates INFO if needed. */
static gpg_error_t
cmd_list (card_info_t info, char *argstr)
{
  gpg_error_t err;
  int opt_cards, opt_apps, opt_info, opt_reread, opt_no_key_lookup;
  int opt_shadow;
  strlist_t cards = NULL;
  strlist_t sl;
  estream_t fp = opt.interactive? NULL : es_stdout;
  const char *cardsn = NULL;
  char *appstr = NULL;
  int count;
  int need_learn = 0;

  if (!info)
    return print_help
      ("LIST [--cards] [--apps] [--info] [--reread] [--shadow]"
       " [--no-key-lookup] [N] [APP]\n\n"
       "Show the content of the current card.\n"
       "With N given select and list the N-th card;\n"
       "with APP also given select that application.\n"
       "To select an APP on the current card use '-' for N.\n"
       "The S/N of the card may be used instead of N.\n"
       "  --cards   list available cards\n"
       "  --apps    list additional card applications\n"
       "  --info    select a card and prints its s/n\n"
       "  --reread  read infos from PCKS#15 cards again\n"
       "  --shadow  create shadow keys for all card keys\n"
       "  --no-key-lookup do not list matching OpenPGP or X.509 keys\n"
       , 0);

  opt_cards = has_leading_option (argstr, "--cards");
  opt_apps = has_leading_option (argstr, "--apps");
  opt_info = has_leading_option (argstr, "--info");
  opt_reread = has_leading_option (argstr, "--reread");
  opt_shadow = has_leading_option (argstr, "--shadow");
  opt_no_key_lookup = has_leading_option (argstr, "--no-key-lookup");
  argstr = skip_options (argstr);

  if (opt_shadow)
    opt_no_key_lookup = 1;

  if (opt.no_key_lookup)
    opt_no_key_lookup = 1;

  if (hexdigitp (argstr) || (*argstr == '-' && spacep (argstr+1)))
    {
      if (*argstr == '-' && (argstr[1] || spacep (argstr+1)))
        argstr++;  /* Keep current card.  */
      else
        {
          cardsn = argstr;
          while (hexdigitp (argstr))
            argstr++;
          if (*argstr && !spacep (argstr))
            {
              err = gpg_error (GPG_ERR_INV_ARG);
              goto leave;
            }
          if (*argstr)
            *argstr++ = 0;
        }

      while (spacep (argstr))
        argstr++;
      if (*argstr)
        {
          appstr = argstr;
          while (*argstr && !spacep (argstr))
            argstr++;
          while (spacep (argstr))
            argstr++;
          if (*argstr)
            {
              /* Extra arguments found.  */
              err = gpg_error (GPG_ERR_INV_ARG);
              goto leave;
            }
        }
    }
  else if (*argstr)
    {
      /* First argument needs to be a digit.  */
      err = gpg_error (GPG_ERR_INV_ARG);
      goto leave;
    }

  if (!info->serialno || info->need_sn_cmd)
    {
      /* This is probably the first call or was explicitly requested.
       * We need to send a SERIALNO command to scdaemon so that our
       * session knows all cards.  */
      err = scd_serialno (NULL, NULL);
      if (err)
        goto leave;
      info->need_sn_cmd = 0;
      need_learn = 1;
    }

  if (opt_cards || opt_apps)
    {
      /* Note that with option --apps CARDS is here the list of all
       * apps.  Format is "SERIALNO APPNAME {APPNAME}".  We print the
       * card number in the first column. */
      if (opt_apps)
        err = scd_applist (&cards, opt_cards);
      else
        err = scd_cardlist (&cards);
      if (err)
        goto leave;
      print_card_list (fp, info, cards, 0);
    }
  else
    {
      if (cardsn)
        {
          int i, cardno;

          err = scd_cardlist (&cards);
          if (err)
            goto leave;

          /* Switch to the requested card.  */
          for (i=0; digitp (cardsn+i); i++)
            ;
          if (i && i < 4 && !cardsn[i])
            { /* Looks like an index into the card list.  */
              cardno = atoi (cardsn);
              for (count = 0, sl = cards; sl; sl = sl->next, count++)
                if (count == cardno)
                  break;
              if (!sl)
                {
                  err = gpg_error (GPG_ERR_INV_INDEX);
                  goto leave;
                }
            }
          else  /* S/N of card specified.  */
            {
              for (sl = cards; sl; sl = sl->next)
                if (!ascii_strcasecmp (sl->d, cardsn))
                  break;
              if (!sl)
                {
                  err = gpg_error (GPG_ERR_INV_INDEX);
                  goto leave;
                }
            }
          err = scd_switchcard (sl->d);
          need_learn = 1;
        }
      else /* show app list.  */
        {
          err = scd_applist (&cards, 1);
          if (err)
            goto leave;
        }

      if (appstr && *appstr)
        {
          /* Switch to the requested app.  */
          err = scd_switchapp (appstr);
          if (err)
            goto leave;
          need_learn = 1;
        }

      if (need_learn)
        err = scd_learn (info, opt_reread);
      else
        err = 0;

      if (err)
        ;
      else if (opt_info)
        print_card_list (fp, info, cards, 1);
      else
        {
          size_t snlen;
          const char *s;

          /* First get the list of active cards and check whether the
           * current card is still in the list.  If not the card has
           * been removed.  Note that during the listing the card
           * remove state might also be detected but only if an access
           * to the scdaemon is required; it is anyway better to test
           * that before starting a listing.  */
          free_strlist (cards);
          err = scd_cardlist (&cards);
          if (err)
            goto leave;
          for (sl = cards; sl; sl = sl->next)
            {
              if (info && info->serialno)
                {
                  s = strchr (sl->d, ' ');
                  if (s)
                    snlen = s - sl->d;
                  else
                    snlen = strlen (sl->d);
                  if (strlen (info->serialno) == snlen
                      && !memcmp (info->serialno, sl->d, snlen))
                    break;
                }
            }
          if (!sl)
            {
              info->need_sn_cmd = 1;
              err = gpg_error (GPG_ERR_CARD_REMOVED);
              goto leave;
            }

          list_card (info, opt_no_key_lookup, opt_shadow);
        }
    }

 leave:
  free_strlist (cards);
  return err;
}



/* The CHECKKEYS command. */
static gpg_error_t
cmd_checkkeys (card_info_t callerinfo, char *argstr)
{
  gpg_error_t err;
  estream_t fp = opt.interactive? NULL : es_stdout;
  strlist_t cards = NULL;
  strlist_t sl;
  int opt_ondisk;
  int opt_delete_clear;
  int opt_delete_protected;
  int delete_count = 0;
  struct card_info_s info_buffer = { 0 };
  card_info_t info = &info_buffer;
  key_info_t kinfo;


  if (!callerinfo)
    return print_help
      ("CHECKKEYS [--ondisk] [--delete-clear-copy] [--delete-protected-copy]"
       "\n\n"
       "Print a list of keys on all inserted cards.  With --ondisk only\n"
       "keys are listed which also have a copy on disk.  Missing shadow\n"
       "keys are created. With --delete-clear-copy, copies of keys also\n"
       "stored on disk without any protection will be deleted.\n"
       , 0);


  opt_ondisk = has_leading_option (argstr, "--ondisk");
  opt_delete_clear = has_leading_option (argstr, "--delete-clear-copy");
  opt_delete_protected = has_leading_option (argstr, "--delete-protected-copy");
  argstr = skip_options (argstr);

  if (*argstr)
    {
      /* No args expected  */
      err = gpg_error (GPG_ERR_INV_ARG);
      goto leave;
    }

  if (!callerinfo->serialno)
    {
      /* This is probably the first call We need to send a SERIALNO
       * command to scdaemon so that our session knows all cards.  */
      err = scd_serialno (NULL, NULL);
      if (err)
        goto leave;
    }

  /* Get the list of all cards.  */
  err = scd_cardlist (&cards);
  if (err)
    goto leave;

  /* Loop over all cards.  We use our own info buffer here. */
  for (sl = cards; sl; sl = sl->next)
    {
      err = scd_switchcard (sl->d);
      if (err)
        {
          log_error ("Error switching to card %s: %s\n",
                     sl->d, gpg_strerror (err));
          continue;
        }
      release_card_info (info);
      err = scd_learn (info, 0);
      if (err)
        {
          log_error ("Error getting infos from card %s: %s\n",
                     sl->d, gpg_strerror (err));
          continue;
        }

      for (kinfo = info->kinfo; kinfo; kinfo = kinfo->next)
        {
          char *infostr;

          err = scd_havekey_info (kinfo->grip, &infostr);
          if (gpg_err_code (err) == GPG_ERR_NOT_FOUND)
            {
              /* Create a shadow key and try again.  */
              scd_readkey (kinfo->keyref, 1, NULL);
              err = scd_havekey_info (kinfo->grip, &infostr);
            }
          if (err && gpg_err_code (err) != GPG_ERR_NOT_FOUND)
            log_error ("Error getting infos for a key: %s\n",
                       gpg_strerror (err));

          if (gpg_err_code (err) == GPG_ERR_NOT_FOUND)
            ; /* does not make sense to show this.  */
          else if (opt_ondisk && infostr && !strcmp (infostr, "shadowed"))
            ; /* Don't print this one.  */
          else
            {
              tty_fprintf (fp, "%s %s ",
                           nullnone (info->serialno),
                           app_type_string (info->apptype));
              print_keygrip (fp, kinfo->grip, 0);
              tty_fprintf (fp, " %s %s\n",
                           kinfo->keyref, infostr? infostr: "error");
            }
          if (infostr
              && ((opt_delete_clear && !strcmp (infostr, "clear"))
                  || (opt_delete_protected && !strcmp (infostr, "protected"))))
            {
              err = scd_delete_key (kinfo->grip, 0);
              if (err)
                log_error ("Error deleting a key copy: %s\n",
                           gpg_strerror (err));
              else
                delete_count++;
            }
          xfree (infostr);
        }
    }
  es_fflush (es_stdout);
  if (delete_count)
    log_info ("Number of deleted key copies: %d\n", delete_count);

  err = 0;

 leave:
  release_card_info (info);
  free_strlist (cards);
  /* Better reset to the original card.  */
  scd_learn (callerinfo, 0);
  return err;
}



/* The VERIFY command.  */
static gpg_error_t
cmd_verify (card_info_t info, char *argstr)
{
  gpg_error_t err, err2;
  const char *pinref;

  if (!info)
    return print_help ("verify [chvid]", 0);

  if (*argstr)
    pinref = argstr;
  else if (info->apptype == APP_TYPE_OPENPGP)
    pinref = info->serialno;
  else if (info->apptype == APP_TYPE_PIV)
    pinref = "PIV.80";
  else
    return gpg_error (GPG_ERR_MISSING_VALUE);

  err = scd_checkpin (pinref);
  if (err)
    log_error ("verify failed: %s <%s>\n",
               gpg_strerror (err), gpg_strsource (err));
  /* In any case update the CHV status, so that the next "list" shows
   * the correct retry counter values.  */
  err2 = scd_getattr ("CHV-STATUS", info);
  return err ? err : err2;
}


static gpg_error_t
cmd_authenticate (card_info_t info, char *argstr)
{
  gpg_error_t err;
  int opt_setkey;
  int opt_raw;
  char *string = NULL;
  char *key = NULL;
  size_t keylen;

  if (!info)
    return print_help
      ("AUTHENTICATE [--setkey] [--raw] [< FILE]|KEY\n\n"
       "Perform a mutual authentication either by reading the key\n"
       "from FILE or by taking it from the command line.  Without\n"
       "the option --raw the key is expected to be hex encoded.\n"
       "To install a new administration key --setkey is used; this\n"
       "requires a prior authentication with the old key.",
       APP_TYPE_PIV, 0);

  if (info->apptype != APP_TYPE_PIV)
    {
      log_info ("Note: This is a PIV only command.\n");
      return gpg_error (GPG_ERR_NOT_SUPPORTED);
    }

  opt_setkey = has_leading_option (argstr, "--setkey");
  opt_raw = has_leading_option (argstr, "--raw");
  argstr = skip_options (argstr);

  if (*argstr == '<')  /* Read key from a file. */
    {
      for (argstr++; spacep (argstr); argstr++)
        ;
      err = get_data_from_file (argstr, &string, NULL);
      if (err)
        goto leave;
    }

  if (opt_raw)
    {
      key = string? string : xstrdup (argstr);
      string = NULL;
      keylen = strlen (key);
    }
  else
    {
      key = hex_to_buffer (string? string: argstr, &keylen);
      if (!key)
        {
          err = gpg_error_from_syserror ();
          goto leave;
        }
    }
  err = scd_setattr (opt_setkey? "SET-ADM-KEY":"AUTH-ADM-KEY", key, keylen);

 leave:
  if (key)
    {
      wipememory (key, keylen);
      xfree (key);
    }
  xfree (string);
  return err;
}


/* Helper for cmd_name to qyery a part of name.  */
static char *
ask_one_name (const char *prompt)
{
  char *name;
  int i;

  for (;;)
    {
      name = tty_get (prompt);
      trim_spaces (name);
      tty_kill_prompt ();
      if (!*name || *name == CONTROL_D)
        {
          if (*name == CONTROL_D)
            tty_fprintf (NULL, "\n");
          xfree (name);
          return NULL;
        }
      for (i=0; name[i] && name[i] >= ' ' && name[i] <= 126; i++)
        ;

      /* The name must be in Latin-1 and not UTF-8 - lacking the code
       * to ensure this we restrict it to ASCII. */
      if (name[i])
        tty_printf (_("Error: Only plain ASCII is currently allowed.\n"));
      else if (strchr (name, '<'))
        tty_printf (_("Error: The \"<\" character may not be used.\n"));
      else if (strstr (name, "  "))
        tty_printf (_("Error: Double spaces are not allowed.\n"));
      else
        return name;
      xfree (name);
    }
}


/* The NAME command.  */
static gpg_error_t
cmd_name (card_info_t info, const char *argstr)
{
  gpg_error_t err;
  char *surname, *givenname;
  char *isoname, *p;

  if (!info)
    return print_help
      ("name [--clear]\n\n"
       "Set the name field of an OpenPGP card.  With --clear the stored\n"
       "name is cleared off the card.", APP_TYPE_OPENPGP, APP_TYPE_NKS, 0);

  if (info->apptype != APP_TYPE_OPENPGP)
    {
      log_info ("Note: This is an OpenPGP only command.\n");
      return gpg_error (GPG_ERR_NOT_SUPPORTED);
    }

 again:
  if (!strcmp (argstr, "--clear"))
    isoname = xstrdup (" "); /* No real way to clear; set to space instead. */
  else
    {
      surname = ask_one_name (_("Cardholder's surname: "));
      givenname = ask_one_name (_("Cardholder's given name: "));
      if (!surname || !givenname || (!*surname && !*givenname))
        {
          xfree (surname);
          xfree (givenname);
          return gpg_error (GPG_ERR_CANCELED);
        }

      isoname = xstrconcat (surname, "<<", givenname, NULL);
      xfree (surname);
      xfree (givenname);
      for (p=isoname; *p; p++)
        if (*p == ' ')
          *p = '<';

      if (strlen (isoname) > 39 )
        {
          log_info (_("Error: Combined name too long "
                      "(limit is %d characters).\n"), 39);
          xfree (isoname);
          goto again;
        }
    }

  err = scd_setattr ("DISP-NAME", isoname, strlen (isoname));

  xfree (isoname);
  return err;
}


static gpg_error_t
cmd_url (card_info_t info, const char *argstr)
{
  gpg_error_t err;
  char *url;

  if (!info)
    return print_help
      ("URL [--clear]\n\n"
       "Set the URL data object.  That data object can be used by\n"
       "the FETCH command to retrieve the full public key.  The\n"
       "option --clear deletes the content of that data object.",
       APP_TYPE_OPENPGP, 0);

  if (info->apptype != APP_TYPE_OPENPGP)
    {
      log_info ("Note: This is an OpenPGP only command.\n");
      return gpg_error (GPG_ERR_NOT_SUPPORTED);
    }

  if (!strcmp (argstr, "--clear"))
    url = xstrdup (" "); /* No real way to clear; set to space instead. */
  else
    {
      url = tty_get (_("URL to retrieve public key: "));
      trim_spaces (url);
      tty_kill_prompt ();
      if (!*url || *url == CONTROL_D)
        {
          err = gpg_error (GPG_ERR_CANCELED);
          goto leave;
        }
    }

  err = scd_setattr ("PUBKEY-URL", url, strlen (url));

 leave:
  xfree (url);
  return err;
}


/* Fetch the key from the URL given on the card or try to get it from
 * the default keyserver.  */
static gpg_error_t
cmd_fetch (card_info_t info)
{
  gpg_error_t err;
  key_info_t kinfo;

  if (!info)
    return print_help
      ("FETCH\n\n"
       "Retrieve a key using the URL data object or if that is missing\n"
       "using the fingerprint.", APP_TYPE_OPENPGP, 0);

  if (info->pubkey_url && *info->pubkey_url)
    {
      /* strlist_t sl = NULL; */

      /* add_to_strlist (&sl, info.pubkey_url); */
      /* err = keyserver_fetch (ctrl, sl, KEYORG_URL); */
      /* free_strlist (sl); */
      err = gpg_error (GPG_ERR_NOT_IMPLEMENTED);  /* FIXME */
    }
  else if ((kinfo = find_kinfo (info, "OPENPGP.1")) && kinfo->fprlen)
    {
      /* rc = keyserver_import_fprint (ctrl, info.fpr1, info.fpr1len, */
      /*                               opt.keyserver, 0); */
      err = gpg_error (GPG_ERR_NOT_IMPLEMENTED);  /* FIXME */
    }
  else
    err = gpg_error (GPG_ERR_NO_DATA);

  return err;
}


static gpg_error_t
cmd_login (card_info_t info, char *argstr)
{
  gpg_error_t err;
  char *data;
  size_t datalen;
  int use_default_pin;

  if (!info)
    return print_help
      ("LOGIN [--clear|--use-default-pin] [< FILE]\n\n"
       "Set the login data object.  If FILE is given the data is\n"
       "is read from that file.  This allows for binary data.\n"
       "The option --clear deletes the login data.  --use-default-pin\n"
       "tells the card to always use the default PIN (\"123456\").",
       APP_TYPE_OPENPGP, 0);

  use_default_pin = has_leading_option (argstr, "--use-default-pin");
  argstr = skip_options (argstr);

  if (!strcmp (argstr, "--clear"))
    {
      data = xstrdup (" "); /* kludge.  */
      datalen = 1;
    }
  else if (*argstr == '<')  /* Read it from a file */
    {
      for (argstr++; spacep (argstr); argstr++)
        ;
      err = get_data_from_file (argstr, &data, &datalen);
      if (err)
        goto leave;
    }
  else
    {
      data = tty_get (_("Login data (account name): "));
      trim_spaces (data);
      tty_kill_prompt ();
      if ((!*data && !use_default_pin) || *data == CONTROL_D)
        {
          err = gpg_error (GPG_ERR_CANCELED);
          goto leave;
        }
      datalen = strlen (data);
    }

  if (use_default_pin)
    {
      char *tmpdata = xmalloc (datalen + 5);
      memcpy (tmpdata, data, datalen);
      memcpy (tmpdata+datalen, "\n\x14" "F=3", 5);
      xfree (data);
      data = tmpdata;
      datalen += 5;
    }

  err = scd_setattr ("LOGIN-DATA", data, datalen);

 leave:
  xfree (data);
  return err;
}


static gpg_error_t
cmd_lang (card_info_t info, const char *argstr)
{
  gpg_error_t err;
  char *data, *p;

  if (!info)
    return print_help
      ("LANG [--clear]\n\n"
       "Change the language info for the card.  This info can be used\n"
       "by applications for a personalized greeting.  Up to 4 two-digit\n"
       "language identifiers can be entered as a preference.  The option\n"
       "--clear removes all identifiers.  GnuPG does not use this info.",
       APP_TYPE_OPENPGP, 0);

  if (!strcmp (argstr, "--clear"))
    data = xstrdup ("  "); /* Note that we need two spaces here.  */
  else
    {
    again:
      data = tty_get (_("Language preferences: "));
      trim_spaces (data);
      tty_kill_prompt ();
      if (!*data || *data == CONTROL_D)
        {
          err = gpg_error (GPG_ERR_CANCELED);
          goto leave;
        }

      if (strlen (data) > 8 || (strlen (data) & 1))
        {
          log_info (_("Error: invalid length of preference string.\n"));
          xfree (data);
          goto again;
        }

      for (p=data; *p && *p >= 'a' && *p <= 'z'; p++)
        ;
      if (*p)
        {
          log_info (_("Error: invalid characters in preference string.\n"));
          xfree (data);
          goto again;
        }
    }

  err = scd_setattr ("DISP-LANG", data, strlen (data));

 leave:
  xfree (data);
  return err;
}


static gpg_error_t
cmd_salut (card_info_t info, const char *argstr)
{
  gpg_error_t err;
  char *data = NULL;
  const char *str;

  if (!info)
    return print_help
      ("SALUT [--clear]\n\n"
       "Change the salutation info for the card.  This info can be used\n"
       "by applications for a personalized greeting.  The option --clear\n"
       "removes this data object.  GnuPG does not use this info.",
       APP_TYPE_OPENPGP, 0);

 again:
  if (!strcmp (argstr, "--clear"))
    str = "9";
  else
    {
      data = tty_get (_("Salutation (M = Mr., F = Ms., or space): "));
      trim_spaces (data);
      tty_kill_prompt ();
      if (*data == CONTROL_D)
        {
          err = gpg_error (GPG_ERR_CANCELED);
          goto leave;
        }

      if (!*data)
        str = "9";
      else if ((*data == 'M' || *data == 'm') && !data[1])
        str = "1";
      else if ((*data == 'F' || *data == 'f') && !data[1])
        str = "2";
      else
        {
          tty_printf (_("Error: invalid response.\n"));
          xfree (data);
          data = NULL;
          goto again;
        }
    }

  err = scd_setattr ("DISP-SEX", str, 1);
 leave:
  xfree (data);
  return err;
}


static gpg_error_t
cmd_cafpr (card_info_t info, char *argstr)
{
  gpg_error_t err;
  char *data = NULL;
  const char *s;
  int i, c;
  unsigned char fpr[32];
  int fprlen;
  int fprno;
  int opt_clear = 0;

  if (!info)
    return print_help
      ("CAFPR [--clear] N\n\n"
       "Change the CA fingerprint number N.  N must be in the\n"
       "range 1 to 3.  The option --clear clears the specified\n"
       "CA fingerprint N or all of them if N is 0 or not given.",
       APP_TYPE_OPENPGP, 0);


  opt_clear = has_leading_option (argstr, "--clear");
  argstr = skip_options (argstr);

  if (digitp (argstr))
    {
      fprno = atoi (argstr);
      while (digitp (argstr))
        argstr++;
      while (spacep (argstr))
        argstr++;
    }
  else
    fprno = 0;

  if (opt_clear && !fprno)
    ; /* Okay: clear all fprs.  */
  else if (fprno < 1 || fprno > 3)
    {
      err = gpg_error (GPG_ERR_INV_ARG);
      goto leave;
    }

 again:
  if (opt_clear)
    {
      memset (fpr, 0, 20);
      fprlen = 20;
    }
  else
    {
      xfree (data);
      data = tty_get (_("CA fingerprint: "));
      trim_spaces (data);
      tty_kill_prompt ();
      if (!*data || *data == CONTROL_D)
        {
          err = gpg_error (GPG_ERR_CANCELED);
          goto leave;
        }

      for (i=0, s=data; i < sizeof fpr && *s; )
        {
          while (spacep(s))
            s++;
          if (*s == ':')
            s++;
          while (spacep(s))
            s++;
          c = hextobyte (s);
          if (c == -1)
            break;
          fpr[i++] = c;
          s += 2;
        }
      fprlen = i;
      if ((fprlen != 20 && fprlen != 32) || *s)
        {
          log_error (_("Error: invalid formatted fingerprint.\n"));
          goto again;
        }
    }

  if (!fprno)
    {
      log_assert (opt_clear);
      err = scd_setattr ("CA-FPR-1", fpr, fprlen);
      if (!err)
        err = scd_setattr ("CA-FPR-2", fpr, fprlen);
      if (!err)
        err = scd_setattr ("CA-FPR-3", fpr, fprlen);
    }
  else
    err = scd_setattr (fprno==1?"CA-FPR-1":
                       fprno==2?"CA-FPR-2":
                       fprno==3?"CA-FPR-3":"x", fpr, fprlen);

 leave:
  xfree (data);
  return err;
}


static gpg_error_t
cmd_privatedo (card_info_t info, char *argstr)
{
  gpg_error_t err;
  int opt_clear;
  char *do_name = NULL;
  char *data = NULL;
  size_t datalen;
  int do_no;

  if (!info)
    return print_help
      ("PRIVATEDO [--clear] N [< FILE]\n\n"
       "Change the private data object N.  N must be in the\n"
       "range 1 to 4.  If FILE is given the data is is read\n"
       "from that file.  The option --clear clears the data.",
       APP_TYPE_OPENPGP, 0);

  opt_clear = has_leading_option (argstr, "--clear");
  argstr = skip_options (argstr);

  if (digitp (argstr))
    {
      do_no = atoi (argstr);
      while (digitp (argstr))
        argstr++;
      while (spacep (argstr))
        argstr++;
    }
  else
    do_no = 0;

  if (do_no < 1 || do_no > 4)
    {
      err = gpg_error (GPG_ERR_INV_ARG);
      goto leave;
    }
  do_name = xasprintf ("PRIVATE-DO-%d", do_no);

  if (opt_clear)
    {
      data = xstrdup (" ");
      datalen = 1;
    }
  else if (*argstr == '<')  /* Read it from a file */
    {
      for (argstr++; spacep (argstr); argstr++)
        ;
      err = get_data_from_file (argstr, &data, &datalen);
      if (err)
        goto leave;
    }
  else if (*argstr)
    {
      err = gpg_error (GPG_ERR_INV_ARG);
      goto leave;
    }
  else
    {
      data = tty_get (_("Private DO data: "));
      trim_spaces (data);
      tty_kill_prompt ();
      datalen = strlen (data);
      if (!*data || *data == CONTROL_D)
        {
          err = gpg_error (GPG_ERR_CANCELED);
          goto leave;
        }
    }

  err = scd_setattr (do_name, data, datalen);

 leave:
  xfree (do_name);
  xfree (data);
  return err;
}


static gpg_error_t
cmd_writecert (card_info_t info, char *argstr)
{
  gpg_error_t err;
  int opt_clear;
  int opt_openpgp;
  char *certref_buffer = NULL;
  char *certref;
  char *data = NULL;
  size_t datalen;
  estream_t key = NULL;


  if (!info)
    return print_help
      ("WRITECERT CERTREF '<' FILE\n"
       "WRITECERT --openpgp CERTREF ['<' FILE|FPR]\n"
       "WRITECERT --clear CERTREF\n\n"
       "Write a certificate to the card under the id CERTREF.\n"
       "The option --clear removes the certificate from the card.\n"
       "The option --openpgp expects an OpenPGP keyblock and stores\n"
       "it encapsulated in a CMS container; the keyblock is taken\n"
       "from FILE or directly from the OpenPGP key with FPR",
       APP_TYPE_OPENPGP, APP_TYPE_PIV, 0);

  opt_clear = has_leading_option (argstr, "--clear");
  opt_openpgp = has_leading_option (argstr, "--openpgp");
  argstr = skip_options (argstr);

  certref = argstr;
  if ((argstr = strchr (certref, ' ')))
    {
      *argstr++ = 0;
      trim_spaces (certref);
      trim_spaces (argstr);
    }
  else /* Let argstr point to an empty string.  */
    argstr = certref + strlen (certref);

  if (info->apptype == APP_TYPE_OPENPGP)
    {
      if (!ascii_strcasecmp (certref, "OPENPGP.3") || !strcmp (certref, "3"))
        certref_buffer = xstrdup ("OPENPGP.3");
      else if (!ascii_strcasecmp (certref, "OPENPGP.2")||!strcmp (certref,"2"))
        certref_buffer = xstrdup ("OPENPGP.2");
      else if (!ascii_strcasecmp (certref, "OPENPGP.1")||!strcmp (certref,"1"))
        certref_buffer = xstrdup ("OPENPGP.1");
      else
        {
          err = gpg_error (GPG_ERR_INV_ID);
          log_error ("Error: CERTREF must be OPENPGP.N or just N"
                     " with N being 1..3\"");
          goto leave;
        }
      certref = certref_buffer;
    }
  else /* Upcase the certref; prepend cardtype if needed.  */
    {
      if (!strchr (certref, '.'))
        certref_buffer = xstrconcat (app_type_string (info->apptype), ".",
                                     certref, NULL);
      else
        certref_buffer = xstrdup (certref);
      ascii_strupr (certref_buffer);
      certref = certref_buffer;
    }

  if (opt_clear)
    {
      data = xstrdup (" ");
      datalen = 1;
    }
  else if (*argstr == '<')  /* Read it from a file */
    {
      for (argstr++; spacep (argstr); argstr++)
        ;
      err = get_data_from_file (argstr, &data, &datalen);
      if (err)
        goto leave;
      if (ascii_memistr (data, datalen, "-----BEGIN CERTIFICATE-----")
          && ascii_memistr (data, datalen, "-----END CERTIFICATE-----")
          && !memchr (data, 0, datalen) && !memchr (data, 1, datalen))
        {
          struct b64state b64;

          err = b64dec_start (&b64, "");
          if (!err)
            err = b64dec_proc (&b64, data, datalen, &datalen);
          if (!err)
            err = b64dec_finish (&b64);
          if (err)
            goto leave;
        }
    }
  else if (opt_openpgp && *argstr)
    {
      err = get_minimal_openpgp_key (&key, argstr);
      if (err)
        goto leave;
      if (es_fclose_snatch (key, (void*)&data, &datalen))
        {
          err = gpg_error_from_syserror ();
          goto leave;
        }
      key = NULL;
    }
  else
    {
      err = gpg_error (GPG_ERR_INV_ARG);
      goto leave;
    }

  if (opt_openpgp && !opt_clear)
    {
      tlv_builder_t tb;
      void *tmpder;
      size_t tmpderlen;

      tb = tlv_builder_new (0);
      if (!tb)
        {
          err = gpg_error_from_syserror ();
          goto leave;
        }

      tlv_builder_add_tag (tb, 0, TAG_SEQUENCE);
      tlv_builder_add_ptr (tb, 0, TAG_OBJECT_ID,
                           "\x2B\x06\x01\x04\x01\xDA\x47\x02\x03\x01", 10);
      tlv_builder_add_tag (tb, CLASS_CONTEXT, 0);
      tlv_builder_add_ptr (tb, 0, TAG_OCTET_STRING, data, datalen);
      tlv_builder_add_end (tb);
      tlv_builder_add_end (tb);

      err = tlv_builder_finalize (tb, &tmpder, &tmpderlen);
      if (err)
        goto leave;
      xfree (data);
      data = tmpder;
      datalen = tmpderlen;
    }


  err = scd_writecert (certref, data, datalen);

 leave:
  es_fclose (key);
  xfree (data);
  xfree (certref_buffer);
  return err;
}


static gpg_error_t
cmd_readcert (card_info_t info, char *argstr)
{
  gpg_error_t err;
  char *certref_buffer = NULL;
  char *certref;
  void *data = NULL;
  size_t datalen, dataoff;
  const char *fname;
  int opt_openpgp;

  if (!info)
    return print_help
      ("READCERT [--openpgp] CERTREF > FILE\n\n"
       "Read the certificate for key CERTREF and store it in FILE.\n"
       "With option \"--openpgp\" an OpenPGP keyblock is expected\n"
       "and stored in FILE.\n",
       APP_TYPE_OPENPGP, APP_TYPE_PIV, 0);

  opt_openpgp = has_leading_option (argstr, "--openpgp");
  argstr = skip_options (argstr);

  certref = argstr;
  if ((argstr = strchr (certref, ' ')))
    {
      *argstr++ = 0;
      trim_spaces (certref);
      trim_spaces (argstr);
    }
  else /* Let argstr point to an empty string.  */
    argstr = certref + strlen (certref);

  if (info->apptype == APP_TYPE_OPENPGP)
    {
      if (!ascii_strcasecmp (certref, "OPENPGP.3") || !strcmp (certref, "3"))
        certref_buffer = xstrdup ("OPENPGP.3");
      else if (!ascii_strcasecmp (certref, "OPENPGP.2")||!strcmp (certref,"2"))
        certref_buffer = xstrdup ("OPENPGP.2");
      else if (!ascii_strcasecmp (certref, "OPENPGP.1")||!strcmp (certref,"1"))
        certref_buffer = xstrdup ("OPENPGP.1");
      else
        {
          err = gpg_error (GPG_ERR_INV_ID);
          log_error ("Error: CERTREF must be OPENPGP.N or just N"
                     " with N being 1..3\"");
          goto leave;
        }
      certref = certref_buffer;
    }

  if (*argstr == '>')  /* Write it to a file */
    {
      for (argstr++; spacep (argstr); argstr++)
        ;
      fname = argstr;
    }
  else
    {
      err = gpg_error (GPG_ERR_INV_ARG);
      goto leave;
    }

  dataoff = 0;
  err = scd_readcert (certref, &data, &datalen);
  if (err)
    goto leave;

  if (opt_openpgp)
    {
      /* Check whether DATA contains an OpenPGP keyblock and put only
       * this into FILE.  If the data is something different, return
       * an error.  */
      const unsigned char *p;
      size_t n, objlen, hdrlen;
      int class, tag, cons, ndef;

      p = data;
      n = datalen;
      if (parse_ber_header (&p,&n,&class,&tag,&cons,&ndef,&objlen,&hdrlen))
        goto not_openpgp;
      if (!(class == CLASS_UNIVERSAL && tag == TAG_SEQUENCE && cons))
        goto not_openpgp; /* Does not start with a sequence.  */
      if (parse_ber_header (&p,&n,&class,&tag,&cons,&ndef,&objlen,&hdrlen))
        goto not_openpgp;
      if (!(class == CLASS_UNIVERSAL && tag == TAG_OBJECT_ID && !cons))
        goto not_openpgp; /* No Object ID.  */
      if (objlen > n)
        goto not_openpgp; /* Inconsistent lengths.  */
      if (objlen != 10
          || memcmp (p, "\x2B\x06\x01\x04\x01\xDA\x47\x02\x03\x01", objlen))
        goto not_openpgp; /* Wrong Object ID.  */
      p += objlen;
      n -= objlen;
      if (parse_ber_header (&p,&n,&class,&tag,&cons,&ndef,&objlen,&hdrlen))
        goto not_openpgp;
      if (!(class == CLASS_CONTEXT && tag == 0 && cons))
        goto not_openpgp; /* Not a [0] context tag.  */
      if (parse_ber_header (&p,&n,&class,&tag,&cons,&ndef,&objlen,&hdrlen))
        goto not_openpgp;
      if (!(class == CLASS_UNIVERSAL && tag == TAG_OCTET_STRING && !cons))
        goto not_openpgp; /* Not an octet string.  */
      if (objlen > n)
        goto not_openpgp; /* Inconsistent lengths.  */
      dataoff = p - (const unsigned char*)data;
      datalen = objlen;
    }

  err = put_data_to_file (fname, (unsigned char*)data+dataoff, datalen);
  goto leave;

 not_openpgp:
  err = gpg_error (GPG_ERR_WRONG_BLOB_TYPE);

 leave:
  xfree (data);
  xfree (certref_buffer);
  return err;
}


static gpg_error_t
cmd_writekey (card_info_t info, char *argstr)
{
  gpg_error_t err;
  int opt_force;
  const char *argv[2];
  int argc;
  char *keyref_buffer = NULL;
  const char *keyref;
  const char *keygrip;

  if (!info)
    return print_help
      ("WRITEKEY [--force] KEYREF KEYGRIP\n\n"
       "Write a private key object identified by KEYGRIP to slot KEYREF.\n"
       "Use --force to overwrite an existing key.",
       APP_TYPE_OPENPGP, APP_TYPE_PIV, 0);

  opt_force = has_leading_option (argstr, "--force");
  argstr = skip_options (argstr);

  argc = split_fields (argstr, argv, DIM (argv));
  if (argc < 2)
    {
      err = gpg_error (GPG_ERR_INV_ARG);
      goto leave;
    }

  /* Upcase the keyref; prepend cardtype if needed.  */
  keyref = argv[0];
  if (!strchr (keyref, '.'))
    keyref_buffer = xstrconcat (app_type_string (info->apptype), ".",
                                keyref, NULL);
  else
    keyref_buffer = xstrdup (keyref);
  ascii_strupr (keyref_buffer);
  keyref = keyref_buffer;

  /* Get the keygrip.  */
  keygrip = argv[1];
  if (strlen (keygrip) != 40
      && !(keygrip[0] == '&' && strlen (keygrip+1) == 40))
    {
      log_error (_("Not a valid keygrip (expecting 40 hex digits)\n"));
      err = gpg_error (GPG_ERR_INV_ARG);
      goto leave;
    }

  err = scd_writekey (keyref, opt_force, keygrip);

 leave:
  xfree (keyref_buffer);
  return err;
}


static gpg_error_t
cmd_forcesig (card_info_t info)
{
  gpg_error_t err;
  int newstate;

  if (!info)
    return print_help
      ("FORCESIG\n\n"
       "Toggle the forcesig flag of an OpenPGP card.",
       APP_TYPE_OPENPGP, 0);

  if (info->apptype != APP_TYPE_OPENPGP)
    {
      log_info ("Note: This is an OpenPGP only command.\n");
      return gpg_error (GPG_ERR_NOT_SUPPORTED);
    }

  newstate = !info->chv1_cached;

  err = scd_setattr ("CHV-STATUS-1", newstate? "\x01":"", 1);
  if (err)
    goto leave;

  /* Read it back to be sure we have the right toggle state the next
   * time.  */
  err = scd_getattr ("CHV-STATUS", info);

 leave:
  return err;
}



/* Helper for cmd_generate_openpgp.  Note that either 0 or 1 is stored at
 * FORCED_CHV1. */
static gpg_error_t
check_pin_for_key_operation (card_info_t info, int *forced_chv1)
{
  gpg_error_t err = 0;

  *forced_chv1 = !info->chv1_cached;
  if (*forced_chv1)
    { /* Switch off the forced mode so that during key generation we
       * don't get bothered with PIN queries for each self-signature. */
      err = scd_setattr ("CHV-STATUS-1", "\x01", 1);
      if (err)
        {
          log_error ("error clearing forced signature PIN flag: %s\n",
                     gpg_strerror (err));
          *forced_chv1 = -1;  /* Not changed.  */
          goto leave;
        }
    }

  /* Check the PIN now, so that we won't get asked later for each
   * binding signature.  */
  err = scd_checkpin (info->serialno);
  if (err)
    log_error ("error checking the PIN: %s\n", gpg_strerror (err));

 leave:
  return err;
}


/* Helper for cmd_generate_openpgp.  */
static void
restore_forced_chv1 (int *forced_chv1)
{
  gpg_error_t err;

  /* Note the possible values stored at FORCED_CHV1:
   *   0 - forcesig was not enabled.
   *   1 - forcesig was enabled - enable it again.
   *  -1 - We have not changed anything.  */
  if (*forced_chv1 == 1)
    { /* Switch back to forced state. */
      err = scd_setattr ("CHV-STATUS-1", "", 1);
      if (err)
        log_error ("error setting forced signature PIN flag: %s\n",
                   gpg_strerror (err));
      *forced_chv1 = 0;
    }
}


/* Ask whether existing keys shall be overwritten.  With NULL used for
 * KINFO it will ask for all keys, other wise for the given key.  */
static gpg_error_t
ask_replace_keys (key_info_t kinfo)
{
  gpg_error_t err;
  char *answer;

  tty_printf ("\n");
  if (kinfo)
    log_info (_("Note: key %s is already stored on the card!\n"),
              kinfo->keyref);
  else
    log_info (_("Note: Keys are already stored on the card!\n"));
  tty_printf ("\n");
  if (kinfo)
    answer = tty_getf (_("Replace existing key %s ? (y/N) "), kinfo->keyref);
  else
    answer = tty_get (_("Replace existing keys? (y/N) "));
  tty_kill_prompt ();
  if (*answer == CONTROL_D)
    err = gpg_error (GPG_ERR_CANCELED);
  else if (!answer_is_yes_no_default (answer, 0/*(default to No)*/))
    err = gpg_error (GPG_ERR_CANCELED);
  else
    err = 0;

  xfree (answer);
  return err;
}


/* Implementation of cmd_generate for OpenPGP cards to generate all
 * standard keys at once.  */
static gpg_error_t
generate_all_openpgp_card_keys (card_info_t info, char **algos)
{
  gpg_error_t err;
  int forced_chv1 = -1;
  int want_backup;
  char *answer = NULL;
  key_info_t kinfo1, kinfo2, kinfo3;

  if (info->extcap.ki)
    {
      xfree (answer);
      answer = tty_get (_("Make off-card backup of encryption key? (Y/n) "));
      want_backup = answer_is_yes_no_default (answer, 1/*(default to Yes)*/);
      tty_kill_prompt ();
      if (*answer == CONTROL_D)
        {
          err = gpg_error (GPG_ERR_CANCELED);
          goto leave;
        }
    }
  else
    want_backup = 0;

  kinfo1 = find_kinfo (info, "OPENPGP.1");
  kinfo2 = find_kinfo (info, "OPENPGP.2");
  kinfo3 = find_kinfo (info, "OPENPGP.3");

  if ((kinfo1 && kinfo1->fprlen && !mem_is_zero (kinfo1->fpr,kinfo1->fprlen))
      || (kinfo2 && kinfo2->fprlen && !mem_is_zero (kinfo2->fpr,kinfo2->fprlen))
      || (kinfo3 && kinfo3->fprlen && !mem_is_zero (kinfo3->fpr,kinfo3->fprlen))
      )
    {
      err = ask_replace_keys (NULL);
      if (err)
        goto leave;
    }

  /* If no displayed name has been set, we assume that this is a fresh
   * card and print a hint about the default PINs.  */
  if (!info->disp_name || !*info->disp_name)
    {
      tty_printf ("\n");
      tty_printf (_("Please note that the factory settings of the PINs are\n"
                    "   PIN = '%s'     Admin PIN = '%s'\n"
                    "You should change them using the command --change-pin\n"),
                  OPENPGP_USER_PIN_DEFAULT, OPENPGP_ADMIN_PIN_DEFAULT);
      tty_printf ("\n");
    }

  err = check_pin_for_key_operation (info, &forced_chv1);
  if (err)
    goto leave;

  (void)algos;  /* FIXME: If we have ALGOS, we need to change the key attr. */

  /* FIXME: We need to divert to a function which spawns gpg which
   * will then create the key.  This also requires new features in
   * gpg.  We might also first create the keys on the card and then
   * tell gpg to use them to create the OpenPGP keyblock. */
  /* generate_keypair (ctrl, 1, NULL, info.serialno, want_backup); */
  (void)want_backup;
  err = scd_genkey ("OPENPGP.1", 1, NULL, NULL);

 leave:
  restore_forced_chv1 (&forced_chv1);
  xfree (answer);
  return err;
}


/* Create a single key.  This is a helper for cmd_generate.  */
static gpg_error_t
generate_key (card_info_t info, const char *keyref, int force,
              const char *algo)
{
  gpg_error_t err;
  key_info_t kinfo;

  if (info->apptype == APP_TYPE_OPENPGP)
    {
      kinfo = find_kinfo (info, keyref);
      if (!kinfo)
        {
          err = gpg_error (GPG_ERR_INV_ID);
          goto leave;
        }

      if (!force
          && kinfo->fprlen && !mem_is_zero (kinfo->fpr, kinfo->fprlen))
        {
          err = ask_replace_keys (NULL);
          if (err)
            goto leave;
          force = 1;
        }
    }

  err = scd_genkey (keyref, force, algo, NULL);

 leave:
  return err;
}


static gpg_error_t
cmd_generate (card_info_t info, char *argstr)
{
  static char * const valid_algos[] =
    { "rsa2048", "rsa3072", "rsa4096", "",
      "nistp256", "nistp384", "nistp521", "",
      "brainpoolP256r1", "brainpoolP384r1", "brainpoolP512r1", "",
      "ed25519", "cv25519",
      NULL
    };
  gpg_error_t err;
  int opt_force;
  char *p;
  char **opt_algo = NULL;      /* Malloced.  */
  char *keyref_buffer = NULL;  /* Malloced.  */
  char *keyref;          /* Points into argstr or keyref_buffer.  */
  int i, j;

  if (!info)
    return print_help
      ("GENERATE [--force] [--algo=ALGO{+ALGO2}] KEYREF\n\n"
       "Create a new key on a card.\n"
       "Use --force to overwrite an existing key.\n"
       "Use \"help\" for ALGO to get a list of known algorithms.\n"
       "For OpenPGP cards several algos may be given.\n"
       "Note that the OpenPGP key generation is done interactively\n"
       "unless a single ALGO or KEYREF are given.",
       APP_TYPE_OPENPGP, APP_TYPE_PIV, 0);

  if (opt.interactive || opt.verbose)
    log_info (_("%s card no. %s detected\n"),
              app_type_string (info->apptype),
              info->dispserialno? info->dispserialno : info->serialno);

  opt_force = has_leading_option (argstr, "--force");
  err = get_option_value (argstr, "--algo", &p);
  if (err)
    goto leave;
  if (p)
    {
      opt_algo = strtokenize (p, "+");
      if (!opt_algo)
        {
          err = gpg_error_from_syserror ();
          xfree (p);
          goto leave;
        }
      xfree (p);
    }

  argstr = skip_options (argstr);

  keyref = argstr;
  if ((argstr = strchr (keyref, ' ')))
    {
      *argstr++ = 0;
      trim_spaces (keyref);
      trim_spaces (argstr);
    }
  else /* Let argstr point to an empty string.  */
    argstr = keyref + strlen (keyref);

  if (!*keyref)
    keyref = NULL;

  if (*argstr)
    {
      /* Extra arguments found.  */
      err = gpg_error (GPG_ERR_INV_ARG);
      goto leave;
    }

  if (opt_algo)
    {
      /* opt_algo is an array of algos.  */
      for (i=0; opt_algo[i]; i++)
        {
          for (j=0; valid_algos[j]; j++)
            if (*valid_algos[j] && !strcmp (valid_algos[j], opt_algo[i]))
              break;
          if (!valid_algos[j])
            {
              int lf = 1;
              if (!ascii_strcasecmp (opt_algo[i], "help"))
                log_info ("Known algorithms:\n");
              else
                {
                  log_info ("Invalid algorithm '%s' given.  Use one of:\n",
                            opt_algo[i]);
                  err = gpg_error (GPG_ERR_PUBKEY_ALGO);
                }
              for (i=0; valid_algos[i]; i++)
                {
                  if (!*valid_algos[i])
                    lf = 1;
                  else if (lf)
                    {
                      lf = 0;
                      log_info ("  %s%s",
                                valid_algos[i], valid_algos[i+1]?",":".");
                    }
                  else
                    log_printf (" %s%s",
                                valid_algos[i], valid_algos[i+1]?",":".");
                }
              log_printf ("\n");
              show_keysize_warning ();
              goto leave;
            }
        }
    }

  /* Upcase the keyref; if it misses the cardtype, prepend it.  */
  if (keyref)
    {
      if (!strchr (keyref, '.'))
        keyref_buffer = xstrconcat (app_type_string (info->apptype), ".",
                                    keyref, NULL);
      else
        keyref_buffer = xstrdup (keyref);
      ascii_strupr (keyref_buffer);
      keyref = keyref_buffer;
    }

  /* Special checks.  */
  if ((info->cardtype && !strcmp (info->cardtype, "yubikey"))
      && info->cardversion >= 0x040200 && info->cardversion < 0x040305)
    {
      log_error ("On-chip key generation on this YubiKey has been blocked.\n");
      log_info ("Please see <https://yubi.co/ysa201701> for details\n");
      err = gpg_error (GPG_ERR_NOT_SUPPORTED);
      goto leave;
    }

  /* Divert to dedicated functions.  */
  if (info->apptype == APP_TYPE_OPENPGP
      && !keyref
      && (!opt_algo || (opt_algo[0] && opt_algo[1])))
    {
      /* With no algo requested or more than one algo requested and no
       * keyref given we create all keys.  */
      if (opt_force || keyref)
        log_info ("Note: OpenPGP key generation is interactive.\n");
      err = generate_all_openpgp_card_keys (info, opt_algo);
    }
  else if (!keyref)
    err = gpg_error (GPG_ERR_INV_ID);
  else if (opt_algo && opt_algo[0] && opt_algo[1])
    {
      log_error ("only one algorithm expected as value for --algo.\n");
      err = gpg_error (GPG_ERR_INV_ARG);
    }
  else
    err = generate_key (info, keyref, opt_force, opt_algo? opt_algo[0]:NULL);

  if (!err)
    {
      err = scd_learn (info, 0);
      if (err)
        log_error ("Error re-reading card: %s\n", gpg_strerror (err));
    }

 leave:
  xfree (opt_algo);
  xfree (keyref_buffer);
  return err;
}



/* Change a PIN.  */
static gpg_error_t
cmd_passwd (card_info_t info, char *argstr)
{
  gpg_error_t err = 0;
  char *answer = NULL;
  const char *pinref = NULL;
  int reset_mode = 0;
  int nullpin = 0;
  int menu_used = 0;

  if (!info)
    return print_help
      ("PASSWD [--reset|--nullpin] [PINREF]\n\n"
       "Change or unblock the PINs.  Note that in interactive mode\n"
       "and without a PINREF a menu is presented for certain cards;\n"
       "in non-interactive and without a PINREF a default value is\n"
       "used for these cards.  The option --reset is used with TCOS\n"
       "cards to reset the PIN using the PUK or vice versa; --nullpin\n"
       "is used for these cards to set the initial PIN.",
       0);

  if (opt.interactive || opt.verbose)
    log_info (_("%s card no. %s detected\n"),
              app_type_string (info->apptype),
              info->dispserialno? info->dispserialno : info->serialno);


  if (has_option (argstr, "--reset"))
    reset_mode = 1;
  else if (has_option (argstr, "--nullpin"))
    nullpin = 1;
  argstr = skip_options (argstr);

  /* If --reset or --nullpin has been given we force non-interactive mode.  */
  if (*argstr || reset_mode || nullpin)
    {
      pinref = argstr;
      if (!*pinref)
        {
          err = gpg_error (GPG_ERR_MISSING_VALUE);
          goto leave;
        }
    }
  else if (opt.interactive && info->apptype == APP_TYPE_OPENPGP)
    {
      menu_used = 1;
      while (!pinref)
        {
          xfree (answer);
          answer = get_selection ("1 - change the PIN\n"
                                  "2 - unblock and set new a PIN\n"
                                  "3 - change the Admin PIN\n"
                                  "4 - set the Reset Code\n"
                                  "Q - quit\n");
          if (strlen (answer) != 1)
            continue;
          else if (*answer == 'q' || *answer == 'Q')
            goto leave;
          else if (*answer == '1')
            pinref = "OPENPGP.1";
          else if (*answer == '2')
            { pinref = "OPENPGP.1"; reset_mode = 1; }
          else if (*answer == '3')
            pinref = "OPENPGP.3";
          else if (*answer == '4')
            { pinref = "OPENPGP.2"; reset_mode = 1; }
        }
    }
  else if (info->apptype == APP_TYPE_OPENPGP)
    pinref = "OPENPGP.1";
  else if (opt.interactive && info->apptype == APP_TYPE_PIV)
    {
      menu_used = 1;
      while (!pinref)
        {
          xfree (answer);
          answer = get_selection ("1 - change the PIN\n"
                                  "2 - change the PUK\n"
                                  "3 - change the Global PIN\n"
                                  "Q - quit\n");
          if (strlen (answer) != 1)
            ;
          else if (*answer == 'q' || *answer == 'Q')
            goto leave;
          else if (*answer == '1')
            pinref = "PIV.80";
          else if (*answer == '2')
            pinref = "PIV.81";
          else if (*answer == '3')
            pinref = "PIV.00";
        }
    }
  else if (opt.interactive && info->apptype == APP_TYPE_NKS)
    {
      int for_qualified = 0;

      menu_used = 1;

      log_assert (DIM (info->chvinfo) >= 4);

      /* If there is a qualified signature use a menu to select
       * between standard PIN and QES PINs.  */
      if (info->chvinfo[2] != -2 || info->chvinfo[3] != -2)
        {
          for (;;)
            {
              xfree (answer);
              answer = get_selection (" 1 - Standard PIN/PUK\n"
                                      " 2 - PIN/PUK for qualified signature\n"
                                  " Q - quit\n");
              if (!ascii_strcasecmp (answer, "q"))
                goto leave;
              else if (!strcmp (answer, "1"))
                break;
              else if (!strcmp (answer, "2"))
                {
                  for_qualified = 1;
                  break;
                }
            }
        }

      if (info->chvinfo[for_qualified? 2 : 0] == -4)
        {
          while (!pinref)
            {
              xfree (answer);
              answer = get_selection
                ("The NullPIN is still active on this card.\n"
                 "You need to choose and set a PIN first.\n"
                 "\n"
                 " 1 - Set your PIN\n"
                 " Q - quit\n");
              if (!ascii_strcasecmp (answer, "q"))
                goto leave;
              else if (!strcmp (answer, "1"))
                {
                  pinref = for_qualified? "PW1.CH.SIG" : "PW1.CH";
                  nullpin = 1;
                }
            }
        }
      else
        {
          while (!pinref)
            {
              xfree (answer);
              answer = get_selection (" 1 - change PIN\n"
                                      " 2 - reset PIN\n"
                                      " 3 - change PUK\n"
                                      " 4 - reset PUK\n"
                                      " Q - quit\n");
              if (!ascii_strcasecmp (answer, "q"))
                goto leave;
              else if (!strcmp (answer, "1"))
                {
                  pinref = for_qualified? "PW1.CH.SIG" : "PW1.CH";
                }
              else if (!strcmp (answer, "2"))
                {
                  pinref = for_qualified? "PW1.CH.SIG" : "PW1.CH";
                  reset_mode = 1;
                }
              else if (!strcmp (answer, "3"))
                {
                  pinref = for_qualified? "PW2.CH.SIG" : "PW2.CH";
                }
              else if (!strcmp (answer, "4"))
                {
                  pinref = for_qualified? "PW2.CH.SIG" : "PW2.CH";
                  reset_mode = 1;
                }
            }
        }
    }
  else if (info->apptype == APP_TYPE_PIV)
    pinref = "PIV.80";
  else
    {
      err = gpg_error (GPG_ERR_MISSING_VALUE);
      goto leave;
    }

  err = scd_change_pin (pinref, reset_mode, nullpin);
  if (err)
    {
      if (!opt.interactive && !menu_used && !opt.verbose)
        ;
      else if (gpg_err_code (err) == GPG_ERR_CANCELED
               && gpg_err_source (err) == GPG_ERR_SOURCE_PINENTRY)
        log_info ("%s\n", gpg_strerror (err));
      else if (!ascii_strcasecmp (pinref, "PIV.81"))
        log_error ("Error changing the PUK.\n");
      else if (!ascii_strcasecmp (pinref, "OPENPGP.1") && reset_mode)
        log_error ("Error unblocking the PIN.\n");
      else if (!ascii_strcasecmp (pinref, "OPENPGP.2") && reset_mode)
        log_error ("Error setting the Reset Code.\n");
      else if (!ascii_strcasecmp (pinref, "OPENPGP.3"))
        log_error ("Error changing the Admin PIN.\n");
      else if (reset_mode)
        log_error ("Error resetting the PIN.\n");
      else
        log_error ("Error changing the PIN.\n");
    }
  else
    {
      if (!opt.interactive && !opt.verbose)
        ;
      else if (!ascii_strcasecmp (pinref, "PIV.81"))
        log_info ("PUK changed.\n");
      else if (!ascii_strcasecmp (pinref, "OPENPGP.1") && reset_mode)
        log_info ("PIN unblocked and new PIN set.\n");
      else if (!ascii_strcasecmp (pinref, "OPENPGP.2") && reset_mode)
        log_info ("Reset Code set.\n");
      else if (!ascii_strcasecmp (pinref, "OPENPGP.3"))
        log_info ("Admin PIN changed.\n");
      else if (reset_mode)
        log_info ("PIN reset.\n");
      else
        log_info ("PIN changed.\n");

      /* Update the CHV status.  */
      err = scd_getattr ("CHV-STATUS", info);
    }

 leave:
  xfree (answer);
  return err;
}


static gpg_error_t
cmd_unblock (card_info_t info)
{
  gpg_error_t err = 0;

  if (!info)
    return print_help
      ("UNBLOCK\n\n"
       "Unblock a PIN using a PUK or Reset Code.  Note that OpenPGP\n"
       "cards prior to version 2 can't use this; instead the PASSWD\n"
       "command can be used to set a new PIN.",
       0);

  if (opt.interactive || opt.verbose)
    log_info (_("%s card no. %s detected\n"),
              app_type_string (info->apptype),
              info->dispserialno? info->dispserialno : info->serialno);

  if (info->apptype == APP_TYPE_OPENPGP)
    {
      if (!info->is_v2)
        {
          log_error (_("This command is only available for version 2 cards\n"));
          err = gpg_error (GPG_ERR_NOT_SUPPORTED);
        }
      else if (!info->chvinfo[1])
        {
          log_error (_("Reset Code not or not anymore available\n"));
          err = gpg_error (GPG_ERR_NO_RESET_CODE);
        }
      else
        {
          err = scd_change_pin ("OPENPGP.2", 0, 0);
          if (!err)
            log_info ("PIN changed.\n");
        }
    }
  else if (info->apptype == APP_TYPE_PIV)
    {
      /* Unblock the Application PIN.  */
      err = scd_change_pin ("PIV.80", 1, 0);
      if (!err)
        log_info ("PIN unblocked and changed.\n");
    }
  else
    {
      log_info ("Unblocking not supported for '%s'.\n",
                app_type_string (info->apptype));
      err = gpg_error (GPG_ERR_NOT_IMPLEMENTED);
    }

  return err;
}


/* Note: On successful execution a redisplay should be scheduled.  If
 * this function fails the card may be in an unknown state. */
static gpg_error_t
cmd_factoryreset (card_info_t info)
{
  gpg_error_t err;
  char *answer = NULL;
  int termstate = 0;
  int any_apdu = 0;
  int is_yubikey = 0;
  int locked = 0;
  int i;


  if (!info)
    return print_help
      ("FACTORY-RESET\n\n"
       "Do a complete reset of some OpenPGP and PIV cards.  This\n"
       "deletes all data and keys and resets the PINs to their default.\n"
       "This is mainly used by developers with scratch cards.  Don't\n"
       "worry, you need to confirm before the command proceeds.",
       APP_TYPE_OPENPGP, APP_TYPE_PIV, 0);

  /* We support the factory reset for most OpenPGP cards and Yubikeys
   * with the PIV application.  */
  if (info->apptype == APP_TYPE_OPENPGP)
    ;
  else if (info->apptype == APP_TYPE_PIV
           && info->cardtype && !strcmp (info->cardtype, "yubikey"))
    is_yubikey = 1;
  else

    return gpg_error (GPG_ERR_NOT_SUPPORTED);

  /* For an OpenPGP card the code below basically does the same what
   * this gpg-connect-agent script does:
   *
   *   scd reset
   *   scd serialno undefined
   *   scd apdu 00 A4 04 00 06 D2 76 00 01 24 01
   *   scd apdu 00 20 00 81 08 40 40 40 40 40 40 40 40
   *   scd apdu 00 20 00 81 08 40 40 40 40 40 40 40 40
   *   scd apdu 00 20 00 81 08 40 40 40 40 40 40 40 40
   *   scd apdu 00 20 00 81 08 40 40 40 40 40 40 40 40
   *   scd apdu 00 20 00 83 08 40 40 40 40 40 40 40 40
   *   scd apdu 00 20 00 83 08 40 40 40 40 40 40 40 40
   *   scd apdu 00 20 00 83 08 40 40 40 40 40 40 40 40
   *   scd apdu 00 20 00 83 08 40 40 40 40 40 40 40 40
   *   scd apdu 00 e6 00 00
   *   scd apdu 00 44 00 00
   *   scd reset
   *   /echo Card has been reset to factory defaults
   *
   * For a PIV application on a Yubikey it merely issues the Yubikey
   * specific resset command.
   */

  err = scd_learn (info, 0);
  if (gpg_err_code (err) == GPG_ERR_OBJ_TERM_STATE
      && gpg_err_source (err) == GPG_ERR_SOURCE_SCD)
    termstate = 1;
  else if (err)
    {
      log_error (_("OpenPGP card not available: %s\n"), gpg_strerror (err));
      goto leave;
    }

  if (opt.interactive || opt.verbose)
    log_info (_("%s card no. %s detected\n"),
              app_type_string (info->apptype),
              info->dispserialno? info->dispserialno : info->serialno);

  if (!termstate || is_yubikey)
    {
      if (!is_yubikey)
        {
          if (!(info->status_indicator == 3 || info->status_indicator == 5))
            {
              /* Note: We won't see status-indicator 3 here because it
               * is not possible to select a card application in
               * termination state.  */
              log_error (_("This command is not supported by this card\n"));
              err = gpg_error (GPG_ERR_NOT_SUPPORTED);
              goto leave;
            }
        }

      tty_printf ("\n");
      log_info
        (_("Note: This command destroys all keys stored on the card!\n"));
      tty_printf ("\n");
      xfree (answer);
      answer = tty_get (_("Continue? (y/N) "));
      tty_kill_prompt ();
      trim_spaces (answer);
      if (*answer == CONTROL_D
          || !answer_is_yes_no_default (answer, 0/*(default to no)*/))
        {
          err = gpg_error (GPG_ERR_CANCELED);
          goto leave;
        }

      xfree (answer);
      answer = tty_get (_("Really do a factory reset? (enter \"yes\") "));
      tty_kill_prompt ();
      trim_spaces (answer);
      if (strcmp (answer, "yes") && strcmp (answer,_("yes")))
        {
          err = gpg_error (GPG_ERR_CANCELED);
          goto leave;
        }


      if (is_yubikey)
        {
          /* If the PIV application is already selected, we only need to
           * send the special reset APDU after having blocked PIN and
           * PUK.  Note that blocking the PUK is done using the
           * unblock PIN command.  */
          any_apdu = 1;
          for (i=0; i < 5; i++)
            send_apdu ("0020008008FFFFFFFFFFFFFFFF", "VERIFY", 0xffff,
                       NULL, NULL);
          for (i=0; i < 5; i++)
            send_apdu ("002C008010FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF",
                       "RESET RETRY COUNTER", 0xffff, NULL, NULL);
          err = send_apdu ("00FB000001FF", "YUBIKEY RESET", 0, NULL, NULL);
          if (err)
            goto leave;
        }
      else /* OpenPGP card.  */
        {
          any_apdu = 1;
          /* We need to select a card application before we can send
           * APDUs to the card without scdaemon doing anything on its
           * own.  We then lock the connection so that other tools
           * (e.g. Kleopatra) don't try a new select.  */
          err = send_apdu ("lock", "locking connection ", 0, NULL, NULL);
          if (err)
            goto leave;
          locked = 1;
          err = send_apdu ("reset-keep-lock", "reset", 0, NULL, NULL);
          if (err)
            goto leave;
          err = send_apdu ("undefined", "dummy select ", 0, NULL, NULL);
          if (err)
            goto leave;
          /* Select the OpenPGP application.  */
          err = send_apdu ("00A4040006D27600012401", "SELECT AID", 0,
                           NULL, NULL);
          if (err)
            goto leave;

          /* Do some dummy verifies with wrong PINs to set the retry
           * counter to zero.  We can't easily use the card version 2.1
           * feature of presenting the admin PIN to allow the terminate
           * command because there is no machinery in scdaemon to catch
           * the verify command and ask for the PIN when the "APDU"
           * command is used.
           * Here, the length of dummy wrong PIN is 32-byte, also
           * supporting authentication with KDF DO.  */
          for (i=0; i < 4; i++)
            send_apdu ("0020008120"
                       "40404040404040404040404040404040"
                       "40404040404040404040404040404040", "VERIFY", 0xffff,
                       NULL, NULL);
          for (i=0; i < 4; i++)
            send_apdu ("0020008320"
                       "40404040404040404040404040404040"
                       "40404040404040404040404040404040", "VERIFY", 0xffff,
                       NULL, NULL);

          /* Send terminate datafile command.  */
          err = send_apdu ("00e60000", "TERMINATE DF", 0x6985, NULL, NULL);
          if (err)
            goto leave;
        }
    }

  if (!is_yubikey)
    {
      any_apdu = 1;
      /* Send activate datafile command.  This is used without
       * confirmation if the card is already in termination state.  */
      err = send_apdu ("00440000", "ACTIVATE DF", 0, NULL, NULL);
      if (err)
        goto leave;
    }

  /* Finally we reset the card reader once more.  */
  if (locked)
    err = send_apdu ("reset-keep-lock", "reset", 0, NULL, NULL);
  else
    err = send_apdu (NULL, "RESET", 0, NULL, NULL);
  if (err)
    goto leave;

  /* Then, connect the card again.  */
  err = scd_serialno (NULL, NULL);
  if (!err)
    info->need_sn_cmd = 0;

 leave:
  if (err && any_apdu && !is_yubikey)
    {
      log_info ("Due to an error the card might be in an inconsistent state\n"
                "You should run the LIST command to check this.\n");
      /* FIXME: We need a better solution in the case that the card is
       * in a termination state, i.e. the card was removed before the
       * activate was sent.  The best solution I found with v2.1
       * Zeitcontrol card was to kill scdaemon and the issue this
       * sequence with gpg-connect-agent:
       *   scd reset
       *   scd serialno undefined
       *   scd apdu 00A4040006D27600012401 (returns error)
       *   scd apdu 00440000
       * Then kill scdaemon again and issue:
       *   scd reset
       *   scd serialno openpgp
       */
    }
  if (locked)
    send_apdu ("unlock", "unlocking connection ", 0, NULL, NULL);
  xfree (answer);
  return err;
}


/* Generate KDF data.  This is a helper for cmd_kdfsetup.  */
static gpg_error_t
gen_kdf_data (unsigned char *data, int single_salt)
{
  gpg_error_t err;
  const unsigned char h0[] = { 0x81, 0x01, 0x03,
                               0x82, 0x01, 0x08,
                               0x83, 0x04 };
  const unsigned char h1[] = { 0x84, 0x08 };
  const unsigned char h2[] = { 0x85, 0x08 };
  const unsigned char h3[] = { 0x86, 0x08 };
  const unsigned char h4[] = { 0x87, 0x20 };
  const unsigned char h5[] = { 0x88, 0x20 };
  unsigned char *p, *salt_user, *salt_admin;
  unsigned char s2k_char;
  unsigned int iterations;
  unsigned char count_4byte[4];

  p = data;

  s2k_char = encode_s2k_iterations (agent_get_s2k_count ());
  iterations = S2K_DECODE_COUNT (s2k_char);
  count_4byte[0] = (iterations >> 24) & 0xff;
  count_4byte[1] = (iterations >> 16) & 0xff;
  count_4byte[2] = (iterations >>  8) & 0xff;
  count_4byte[3] = (iterations & 0xff);

  memcpy (p, h0, sizeof h0);
  p += sizeof h0;
  memcpy (p, count_4byte, sizeof count_4byte);
  p += sizeof count_4byte;
  memcpy (p, h1, sizeof h1);
  salt_user = (p += sizeof h1);
  gcry_randomize (p, 8, GCRY_STRONG_RANDOM);
  p += 8;

  if (single_salt)
    salt_admin = salt_user;
  else
    {
      memcpy (p, h2, sizeof h2);
      p += sizeof h2;
      gcry_randomize (p, 8, GCRY_STRONG_RANDOM);
      p += 8;
      memcpy (p, h3, sizeof h3);
      salt_admin = (p += sizeof h3);
      gcry_randomize (p, 8, GCRY_STRONG_RANDOM);
      p += 8;
    }

  memcpy (p, h4, sizeof h4);
  p += sizeof h4;
  err = gcry_kdf_derive (OPENPGP_USER_PIN_DEFAULT,
                         strlen (OPENPGP_USER_PIN_DEFAULT),
                         GCRY_KDF_ITERSALTED_S2K, GCRY_MD_SHA256,
                         salt_user, 8, iterations, 32, p);
  p += 32;
  if (!err)
    {
      memcpy (p, h5, sizeof h5);
      p += sizeof h5;
      err = gcry_kdf_derive (OPENPGP_ADMIN_PIN_DEFAULT,
                             strlen (OPENPGP_ADMIN_PIN_DEFAULT),
                             GCRY_KDF_ITERSALTED_S2K, GCRY_MD_SHA256,
                             salt_admin, 8, iterations, 32, p);
    }

  return err;
}


static gpg_error_t
cmd_kdfsetup (card_info_t info, char *argstr)
{
  gpg_error_t err;
  unsigned char kdf_data[OPENPGP_KDF_DATA_LENGTH_MAX];
  int single = (*argstr != 0);

  if (!info)
    return print_help
      ("KDF-SETUP\n\n"
       "Prepare the OpenPGP card KDF feature for this card.",
       APP_TYPE_OPENPGP, 0);

  if (info->apptype != APP_TYPE_OPENPGP)
    {
      log_info ("Note: This is an OpenPGP only command.\n");
      return gpg_error (GPG_ERR_NOT_SUPPORTED);
    }

  if (!info->extcap.kdf)
    {
      log_error (_("This command is not supported by this card\n"));
      err = gpg_error (GPG_ERR_NOT_SUPPORTED);
      goto leave;
    }

  err = gen_kdf_data (kdf_data, single);
  if (err)
    goto leave;

  err = scd_setattr ("KDF", kdf_data,
                     single ? OPENPGP_KDF_DATA_LENGTH_MIN
                     /* */  : OPENPGP_KDF_DATA_LENGTH_MAX);
  if (err)
    goto leave;

  err = scd_getattr ("KDF", info);

 leave:
  return err;
}



static void
show_keysize_warning (void)
{
  static int shown;

  if (shown)
    return;
  shown = 1;
  tty_printf
    (_("Note: There is no guarantee that the card supports the requested\n"
       "      key type or size.  If the key generation does not succeed,\n"
       "      please check the documentation of your card to see which\n"
       "      key types and sizes are supported.\n")
     );
}


static gpg_error_t
cmd_uif (card_info_t info, char *argstr)
{
  gpg_error_t err;
  int keyno;
  char name[50];
  unsigned char data[2];
  char *answer = NULL;
  int opt_yes;

  if (!info)
    return print_help
      ("UIF N [on|off|permanent]\n\n"
       "Change the User Interaction Flag.  N must in the range 1 to 3.",
       APP_TYPE_OPENPGP, APP_TYPE_PIV, 0);

  if (!info->extcap.bt)
    {
      log_error (_("This command is not supported by this card\n"));
      err = gpg_error (GPG_ERR_NOT_SUPPORTED);
      goto leave;
    }

  opt_yes = has_leading_option (argstr, "--yes");
  argstr = skip_options (argstr);

  if (digitp (argstr))
    {
      keyno = atoi (argstr);
      while (digitp (argstr))
        argstr++;
      while (spacep (argstr))
        argstr++;
    }
  else
    keyno = 0;

  if (keyno < 1 || keyno > 3)
    {
      err = gpg_error (GPG_ERR_INV_ARG);
      goto leave;
    }

  if ( !strcmp (argstr, "off") )
    data[0] = 0x00;
  else if ( !strcmp (argstr, "on") )
    data[0] = 0x01;
  else if ( !strcmp (argstr, "permanent") )
    data[0] = 0x02;
  else
    {
      err = gpg_error (GPG_ERR_INV_ARG);
      goto leave;
    }
  data[1] = 0x20;


  log_assert (keyno - 1 < DIM(info->uif));
  if (info->uif[keyno-1] == 2)
    {
      log_info (_("User Interaction Flag is set to \"%s\" - can't change\n"),
                "permanent");
      err = gpg_error (GPG_ERR_INV_STATE);
      goto leave;
    }

  if (data[0] == 0x02)
    {
      if (opt.interactive)
        {
          tty_printf (_("Warning: Setting the User Interaction Flag to \"%s\"\n"
                        "         can only be reverted using a factory reset!\n"
                        ), "permanent");
          answer = tty_get (_("Continue? (y/N) "));
          tty_kill_prompt ();
          if (*answer == CONTROL_D)
            err = gpg_error (GPG_ERR_CANCELED);
          else if (!answer_is_yes_no_default (answer, 0/*(default to No)*/))
            err = gpg_error (GPG_ERR_CANCELED);
          else
            err = 0;
        }
      else if (!opt_yes)
        {
          log_info (_("Warning: Setting the User Interaction Flag to \"%s\"\n"
                      "         can only be reverted using a factory reset!\n"
                      ), "permanent");
          log_info (_("Please use \"uif --yes %d %s\"\n"),
                    keyno, "permanent");
          err = gpg_error (GPG_ERR_CANCELED);
        }
      else
        err = 0;

      if (err)
        goto leave;
    }

  snprintf (name, sizeof name, "UIF-%d", keyno);
  err = scd_setattr (name, data, 2);
  if (!err) /* Read all UIF attributes again.  */
    err = scd_getattr ("UIF", info);

 leave:
  xfree (answer);
  return err;
}


static gpg_error_t
cmd_yubikey (card_info_t info, char *argstr)
{
  gpg_error_t err, err2;
  estream_t fp = opt.interactive? NULL : es_stdout;
  const char *words[20];
  int nwords;

  if (!info)
    return print_help
      ("YUBIKEY <cmd> args\n\n"
       "Various commands pertaining to Yubikey tokens with <cmd> being:\n"
       "\n"
       "  LIST \n"
       "\n"
       "List supported and enabled applications.\n"
       "\n"
       "  ENABLE  usb|nfc|all [otp|u2f|opgp|piv|oath|fido2|all]\n"
       "  DISABLE usb|nfc|all [otp|u2f|opgp|piv|oath|fido2|all]\n"
       "\n"
       "Enable or disable the specified or all applications on the\n"
       "given interface.",
       0);

  argstr = skip_options (argstr);

  if (!info->cardtype || strcmp (info->cardtype, "yubikey"))
    {
      log_info ("This command can only be used with Yubikeys.\n");
      err = gpg_error (GPG_ERR_NOT_SUPPORTED);
      goto leave;
    }

  nwords = split_fields (argstr, words, DIM (words));
  if (nwords < 1)
    {
      err = gpg_error (GPG_ERR_SYNTAX);
      goto leave;
    }


  /* Note that we always do a learn to get a chance to the card back
   * into a usable state.  */
  err = yubikey_commands (info, fp, nwords, words);
  err2 = scd_learn (info, 0);
  if (err2)
    log_error ("Error re-reading card: %s\n", gpg_strerror (err2));

 leave:
  return err;
}


static gpg_error_t
cmd_apdu (card_info_t info, char *argstr)
{
  gpg_error_t err;
  estream_t fp = opt.interactive? NULL : es_stdout;
  int with_atr;
  int handle_more;
  const char *s;
  const char  *exlenstr;
  int exlenstrlen;
  char *options = NULL;
  unsigned int sw;
  unsigned char *result = NULL;
  size_t i, j, resultlen;

  if (!info)
    return print_help
      ("APDU [--more] [--exlen[=N]] <hexstring>\n"
       "\n"
       "Send an APDU to the current card.  This command bypasses the high\n"
       "level functions and sends the data directly to the card.  HEXSTRING\n"
       "is expected to be a proper APDU.\n"
       "\n"
       "Using the option \"--more\" handles the card status word MORE_DATA\n"
       "(61xx) and concatenates all responses to one block.\n"
       "\n"
       "Using the option \"--exlen\" the returned APDU may use extended\n"
       "length up to N bytes.  If N is not given a default value is used.\n",
       0);

  if (has_option (argstr, "--dump-atr"))
    with_atr = 2;
  else
    with_atr = has_option (argstr, "--atr");
  handle_more = has_option (argstr, "--more");

  exlenstr = has_option_name (argstr, "--exlen");
  exlenstrlen = 0;
  if (exlenstr)
    {
      for (s=exlenstr; *s && !spacep (s); s++)
        exlenstrlen++;
    }

  argstr = skip_options (argstr);

  if (with_atr || handle_more || exlenstr)
    options = xasprintf ("%s%s%s%.*s",
                         with_atr == 2? " --dump-atr":
                         with_atr? " --data-atr":"",
                         handle_more?" --more":"",
                         exlenstr?" --exlen=":"",
                         exlenstrlen, exlenstr?exlenstr:"");

  err = scd_apdu (argstr, options, &sw, &result, &resultlen);
  if (err)
    goto leave;
  if (!with_atr)
    {
      if (opt.interactive || opt.verbose)
        {
          char *p = scd_apdu_strerror (sw);
          log_info ("Statusword: 0x%04x (%s)\n", sw, p? p: "?");
          xfree (p);
        }
      else
        log_info ("Statusword: 0x%04x\n", sw);
    }
  for (i=0; i < resultlen; )
    {
      size_t save_i = i;

      tty_fprintf (fp, "D[%04X] ", (unsigned int)i);
      for (j=0; j < 16 ; j++, i++)
        {
          if (j == 8)
            tty_fprintf (fp, " ");
          if (i < resultlen)
            tty_fprintf (fp, " %02X", result[i]);
          else
            tty_fprintf (fp, "   ");
        }
      tty_fprintf (fp, "   ");
      i = save_i;
      for (j=0; j < 16; j++, i++)
        {
          unsigned int c = result[i];
          if ( i >= resultlen )
            tty_fprintf (fp, " ");
          else if (isascii (c) && isprint (c) && !iscntrl (c))
            tty_fprintf (fp, "%c", c);
          else
            tty_fprintf (fp, ".");
        }
      tty_fprintf (fp, "\n");
    }

 leave:
  xfree (result);
  xfree (options);
  return err;
}


static gpg_error_t
cmd_gpg (card_info_t info, char *argstr, int use_gpgsm)
{
  gpg_error_t err;
  char **argarray;
  ccparray_t ccp;
  const char **argv = NULL;
  pid_t pid;
  int i;

  if (!info)
    return print_help
      ("GPG[SM] <commands_and_options>\n"
       "\n"
       "Run gpg/gpgsm directly from this shell.\n",
       0);

  /* Fixme: We need to write and use a version of strtokenize which
   * takes care of shell-style quoting.  */
  argarray = strtokenize (argstr, " \t\n\v");
  if (!argarray)
    {
      err = gpg_error_from_syserror ();
      goto leave;
    }
  ccparray_init (&ccp, 0);
  for (i=0; argarray[i]; i++)
    ccparray_put (&ccp, argarray[i]);
  argv = ccparray_get (&ccp, NULL);
  if (!argv)
    {
      err = gpg_error_from_syserror ();
      goto leave;
    }

  err = gnupg_spawn_process (use_gpgsm? opt.gpgsm_program:opt.gpg_program,
                             argv, NULL, (GNUPG_SPAWN_KEEP_STDOUT
                                          |GNUPG_SPAWN_KEEP_STDERR),
                             NULL, NULL, NULL, &pid);
  if (!err)
    {
      err = gnupg_wait_process (use_gpgsm? opt.gpgsm_program:opt.gpg_program,
                                pid, 1, NULL);
      gnupg_release_process (pid);
    }


 leave:
  xfree (argv);
  xfree (argarray);
  return err;
}


static gpg_error_t
cmd_history (card_info_t info, char *argstr)
{
  int opt_list, opt_clear;

  opt_list  = has_option (argstr, "--list");
  opt_clear = has_option (argstr, "--clear");

  if (!info || !(opt_list || opt_clear))
    return print_help
      ("HISTORY --list\n"
       "   List the command history\n"
       "HISTORY --clear\n"
       "   Clear the command history",
       0);

  if (opt_list)
    tty_printf ("Sorry, history listing not yet possible\n");

  if (opt_clear)
    tty_read_history (NULL, 0);

  return 0;
}




/* Data used by the command parser.  This needs to be outside of the
 * function scope to allow readline based command completion.  */
enum cmdids
  {
    cmdNOP = 0,
    cmdQUIT, cmdHELP, cmdLIST, cmdRESET, cmdVERIFY,
    cmdNAME, cmdURL, cmdFETCH, cmdLOGIN, cmdLANG, cmdSALUT, cmdCAFPR,
    cmdFORCESIG, cmdGENERATE, cmdPASSWD, cmdPRIVATEDO, cmdWRITECERT,
    cmdREADCERT, cmdWRITEKEY,  cmdUNBLOCK, cmdFACTRST, cmdKDFSETUP,
    cmdUIF, cmdAUTH, cmdYUBIKEY, cmdAPDU, cmdGPG, cmdGPGSM, cmdHISTORY,
    cmdCHECKKEYS,
    cmdINVCMD
  };

static struct
{
  const char *name;
  enum cmdids id;
  const char *desc;
} cmds[] = {
  { "quit"    ,  cmdQUIT,       N_("quit this menu")},
  { "q"       ,  cmdQUIT,       NULL },
  { "bye"     ,  cmdQUIT,       NULL },
  { "help"    ,  cmdHELP,       N_("show this help")},
  { "?"       ,  cmdHELP,       NULL },
  { "list"    ,  cmdLIST,       N_("list all available data")},
  { "l"       ,  cmdLIST,       NULL },
  { "name"    ,  cmdNAME,       N_("change card holder's name")},
  { "url"     ,  cmdURL,        N_("change URL to retrieve key")},
  { "fetch"   ,  cmdFETCH,      N_("fetch the key specified in the card URL")},
  { "login"   ,  cmdLOGIN,      N_("change the login name")},
  { "lang"    ,  cmdLANG,       N_("change the language preferences")},
  { "salutation",cmdSALUT,      N_("change card holder's salutation")},
  { "salut"   ,  cmdSALUT,      NULL },
  { "cafpr"   ,  cmdCAFPR ,     N_("change a CA fingerprint")},
  { "forcesig",  cmdFORCESIG,   N_("toggle the signature force PIN flag")},
  { "generate",  cmdGENERATE,   N_("generate new keys")},
  { "passwd"  ,  cmdPASSWD,     N_("menu to change or unblock the PIN")},
  { "verify"  ,  cmdVERIFY,     N_("verify the PIN and list all data")},
  { "unblock" ,  cmdUNBLOCK,    N_("unblock the PIN using a Reset Code")},
  { "authenticate",cmdAUTH,     N_("authenticate to the card")},
  { "auth"    ,  cmdAUTH,       NULL },
  { "reset"   ,  cmdRESET,      N_("send a reset to the card daemon")},
  { "factory-reset",cmdFACTRST, N_("destroy all keys and data")},
  { "kdf-setup", cmdKDFSETUP,   N_("setup KDF for PIN authentication")},
  { "uif",       cmdUIF,        N_("change the User Interaction Flag")},
  { "privatedo", cmdPRIVATEDO,  N_("change a private data object")},
  { "readcert",  cmdREADCERT,   N_("read a certificate from a data object")},
  { "writecert", cmdWRITECERT,  N_("store a certificate to a data object")},
  { "writekey",  cmdWRITEKEY,   N_("store a private key to a data object")},
  { "checkkeys", cmdCHECKKEYS,  N_("run various checks on the keys")},
  { "yubikey",   cmdYUBIKEY,    N_("Yubikey management commands")},
  { "gpg",       cmdGPG,        NULL},
  { "gpgsm",     cmdGPGSM,      NULL},
  { "apdu",      cmdAPDU,       NULL},
  { "history",   cmdHISTORY,    N_("manage the command history")},
  { NULL, cmdINVCMD, NULL }
};


/* The command line command dispatcher.  */
static gpg_error_t
dispatch_command (card_info_t info, const char *orig_command)
{
  gpg_error_t err = 0;
  enum cmdids cmd;             /* The command.  */
  char *command;               /* A malloced copy of ORIG_COMMAND.  */
  char *argstr;                /* The argument as a string.  */
  int i;
  int ignore_error;

  if ((ignore_error = *orig_command == '-'))
    orig_command++;
  command = xstrdup (orig_command);
  argstr = NULL;
  if ((argstr = strchr (command, ' ')))
    {
      *argstr++ = 0;
      trim_spaces (command);
      trim_spaces (argstr);
    }

  for (i=0; cmds[i].name; i++ )
    if (!ascii_strcasecmp (command, cmds[i].name ))
      break;
  cmd = cmds[i].id; /* (If not found this will be cmdINVCMD). */

  /* Make sure we have valid strings for the args.  They are allowed
   * to be modified and must thus point to a buffer.  */
  if (!argstr)
    argstr = command + strlen (command);

  /* For most commands we need to make sure that we have a card.  */
  if (!info)
    ;  /* Help mode */
  else if (!(cmd == cmdNOP || cmd == cmdQUIT || cmd == cmdHELP
             || cmd == cmdINVCMD)
           && !info->initialized)
    {
      err = scd_learn (info, 0);
      if (err)
        {
          err = fixup_scd_errors (err);
          log_error ("Error reading card: %s\n", gpg_strerror (err));
          goto leave;
        }
    }

  if (info)
    info->card_removed = 0;

  switch (cmd)
    {
    case cmdNOP:
      if (!info)
        print_help ("NOP\n\n"
                    "Dummy command.", 0);
      break;

    case cmdQUIT:
      if (!info)
        print_help ("QUIT\n\n"
                    "Stop processing.", 0);
      else
        {
          err = gpg_error (GPG_ERR_EOF);
          goto leave;
        }
      break;

    case cmdHELP:
      if (!info)
        print_help ("HELP [command]\n\n"
                    "Show all commands.  With an argument show help\n"
                    "for that command.", 0);
      else if (*argstr)
        dispatch_command (NULL, argstr);
      else
        {
          es_printf
            ("List of commands (\"help <command>\" for details):\n");
          for (i=0; cmds[i].name; i++ )
            if(cmds[i].desc)
              es_printf("%-14s %s\n", cmds[i].name, _(cmds[i].desc) );
          es_printf ("Prefix a command with a dash to ignore its error.\n");
        }
      break;

    case cmdRESET:
      if (!info)
        print_help ("RESET\n\n"
                    "Send a RESET to the card daemon.", 0);
      else
        {
          flush_keyblock_cache ();
          err = scd_apdu (NULL, NULL, NULL, NULL, NULL);
          if (!err)
            info->need_sn_cmd = 1;
        }
      break;

    case cmdLIST:         err = cmd_list (info, argstr); break;
    case cmdVERIFY:       err = cmd_verify (info, argstr); break;
    case cmdAUTH:         err = cmd_authenticate (info, argstr); break;
    case cmdNAME:         err = cmd_name (info, argstr); break;
    case cmdURL:          err = cmd_url (info, argstr);  break;
    case cmdFETCH:        err = cmd_fetch (info);  break;
    case cmdLOGIN:        err = cmd_login (info, argstr); break;
    case cmdLANG:         err = cmd_lang (info, argstr); break;
    case cmdSALUT:        err = cmd_salut (info, argstr); break;
    case cmdCAFPR:        err = cmd_cafpr (info, argstr); break;
    case cmdPRIVATEDO:    err = cmd_privatedo (info, argstr); break;
    case cmdWRITECERT:    err = cmd_writecert (info, argstr); break;
    case cmdREADCERT:     err = cmd_readcert (info, argstr); break;
    case cmdWRITEKEY:     err = cmd_writekey (info, argstr); break;
    case cmdFORCESIG:     err = cmd_forcesig (info); break;
    case cmdGENERATE:     err = cmd_generate (info, argstr); break;
    case cmdPASSWD:       err = cmd_passwd (info, argstr); break;
    case cmdUNBLOCK:      err = cmd_unblock (info); break;
    case cmdFACTRST:      err = cmd_factoryreset (info); break;
    case cmdKDFSETUP:     err = cmd_kdfsetup (info, argstr); break;
    case cmdUIF:          err = cmd_uif (info, argstr); break;
    case cmdYUBIKEY:      err = cmd_yubikey (info, argstr); break;
    case cmdAPDU:         err = cmd_apdu (info, argstr); break;
    case cmdGPG:          err = cmd_gpg (info, argstr, 0); break;
    case cmdGPGSM:        err = cmd_gpg (info, argstr, 1); break;
    case cmdHISTORY:      err = 0; break; /* Only used in interactive mode.  */
    case cmdCHECKKEYS:    err = cmd_checkkeys (info, argstr); break;

    case cmdINVCMD:
    default:
      log_error (_("Invalid command  (try \"help\")\n"));
      break;
    } /* End command switch. */


 leave:
  /* Return GPG_ERR_EOF only if its origin was "quit".  */
  es_fflush (es_stdout);
  if (gpg_err_code (err) == GPG_ERR_EOF && cmd != cmdQUIT)
    err = gpg_error (GPG_ERR_GENERAL);

  if (!err && info && info->card_removed)
    {
      info->card_removed = 0;
      info->need_sn_cmd = 1;
      err = gpg_error (GPG_ERR_CARD_REMOVED);
    }

  if (err && gpg_err_code (err) != GPG_ERR_EOF)
    {
      err = fixup_scd_errors (err);
      if (ignore_error)
        {
          log_info ("Command '%s' failed: %s\n", command, gpg_strerror (err));
          err = 0;
        }
      else
        {
          log_error ("Command '%s' failed: %s\n", command, gpg_strerror (err));
          if (gpg_err_code (err) == GPG_ERR_CARD_NOT_PRESENT)
            info->need_sn_cmd = 1;
        }
    }
  xfree (command);

  return err;
}


/* The interactive main loop.  */
static void
interactive_loop (void)
{
  gpg_error_t err;
  char *answer = NULL;         /* The input line.  */
  enum cmdids cmd = cmdNOP;    /* The command.  */
  char *argstr;                /* The argument as a string.  */
  int redisplay = 1;           /* Whether to redisplay the main info.  */
  char *help_arg = NULL;       /* Argument of the HELP command.         */
  struct card_info_s info_buffer = { 0 };
  card_info_t info = &info_buffer;
  char *p;
  int i;
  char *historyname = NULL;

  /* In the interactive mode we do not want to print the program prefix.  */
  log_set_prefix (NULL, 0);

  if (!opt.no_history)
    {
      historyname = make_filename (gnupg_homedir (), HISTORYNAME, NULL);
      if (tty_read_history (historyname, 500))
        log_info ("error reading '%s': %s\n",
                  historyname, gpg_strerror (gpg_error_from_syserror ()));
    }

  for (;;)
    {
      if (help_arg)
        {
          /* Clear info to indicate helpmode */
          info = NULL;
        }
      else if (!info)
        {
          /* Get out of help.  */
          info = &info_buffer;
          help_arg = NULL;
          redisplay = 0;
        }
      else if (redisplay)
        {
          err = cmd_list (info, "");
          if (err)
            {
              err = fixup_scd_errors (err);
              log_error ("Error reading card: %s\n", gpg_strerror (err));
            }
          else
            {
              tty_printf("\n");
              redisplay = 0;
            }
	}

      if (!info)
        {
          /* Copy the pending help arg into our answer.  Note that
           * help_arg points into answer.  */
          p = xstrdup (help_arg);
          help_arg = NULL;
          xfree (answer);
          answer = p;
        }
      else
        {
          do
            {
              xfree (answer);
              tty_enable_completion (command_completion);
              answer = tty_get (_("gpg/card> "));
              tty_kill_prompt();
              tty_disable_completion ();
              trim_spaces(answer);
            }
          while ( *answer == '#' );
        }

      argstr = NULL;
      if (!*answer)
        cmd = cmdLIST; /* We default to the list command */
      else if (*answer == CONTROL_D)
        cmd = cmdQUIT;
      else
        {
          if ((argstr = strchr (answer,' ')))
            {
              *argstr++ = 0;
              trim_spaces (answer);
              trim_spaces (argstr);
            }

          for (i=0; cmds[i].name; i++ )
            if (!ascii_strcasecmp (answer, cmds[i].name ))
              break;

          cmd = cmds[i].id;
        }

      /* Make sure we have valid strings for the args.  They are
       * allowed to be modified and must thus point to a buffer.  */
      if (!argstr)
        argstr = answer + strlen (answer);

      if (!(cmd == cmdNOP || cmd == cmdQUIT || cmd == cmdHELP
            || cmd == cmdHISTORY || cmd == cmdINVCMD))
        {
          /* If redisplay is set we know that there was an error reading
           * the card.  In this case we force a LIST command to retry.  */
          if (!info)
            ; /* In help mode.  */
          else if (redisplay)
            {
              cmd = cmdLIST;
            }
          else if (!info->serialno)
            {
              /* Without a serial number most commands won't work.
               * Catch it here.  */
              if (cmd == cmdRESET || cmd == cmdLIST)
                info->need_sn_cmd = 1;
              else
                {
                  tty_printf ("\n");
                  tty_printf ("Serial number missing\n");
                  continue;
                }
            }
        }

      if (info)
        info->card_removed = 0;
      err = 0;
      switch (cmd)
        {
        case cmdNOP:
          if (!info)
            print_help ("NOP\n\n"
                        "Dummy command.", 0);
          break;

        case cmdQUIT:
          if (!info)
            print_help ("QUIT\n\n"
                        "Leave this tool.", 0);
          else
            {
              tty_printf ("\n");
              goto leave;
            }
          break;

        case cmdHELP:
          if (!info)
            print_help ("HELP [command]\n\n"
                        "Show all commands.  With an argument show help\n"
                        "for that command.", 0);
          else if (*argstr)
            help_arg = argstr; /* Trigger help for a command.  */
          else
            {
              tty_printf
                ("List of commands (\"help <command>\" for details):\n");
              for (i=0; cmds[i].name; i++ )
                if(cmds[i].desc)
                  tty_printf("%-14s %s\n", cmds[i].name, _(cmds[i].desc) );
            }
          break;

        case cmdRESET:
          if (!info)
            print_help ("RESET\n\n"
                        "Send a RESET to the card daemon.", 0);
          else
            {
              flush_keyblock_cache ();
              err = scd_apdu (NULL, NULL, NULL, NULL, NULL);
              if (!err)
                info->need_sn_cmd = 1;
            }
          break;

        case cmdLIST:      err = cmd_list (info, argstr); break;
        case cmdVERIFY:
          err = cmd_verify (info, argstr);
          if (!err)
            redisplay = 1;
          break;
        case cmdAUTH:      err = cmd_authenticate (info, argstr); break;
        case cmdNAME:      err = cmd_name (info, argstr); break;
        case cmdURL:       err = cmd_url (info, argstr);  break;
	case cmdFETCH:     err = cmd_fetch (info);  break;
        case cmdLOGIN:     err = cmd_login (info, argstr); break;
        case cmdLANG:      err = cmd_lang (info, argstr); break;
        case cmdSALUT:     err = cmd_salut (info, argstr); break;
        case cmdCAFPR:     err = cmd_cafpr (info, argstr); break;
        case cmdPRIVATEDO: err = cmd_privatedo (info, argstr); break;
        case cmdWRITECERT: err = cmd_writecert (info, argstr); break;
        case cmdREADCERT:  err = cmd_readcert (info, argstr); break;
        case cmdWRITEKEY:  err = cmd_writekey (info, argstr); break;
        case cmdFORCESIG:  err = cmd_forcesig (info); break;
        case cmdGENERATE:  err = cmd_generate (info, argstr); break;
        case cmdPASSWD:    err = cmd_passwd (info, argstr); break;
        case cmdUNBLOCK:   err = cmd_unblock (info); break;
        case cmdFACTRST:
          err = cmd_factoryreset (info);
          if (!err)
            redisplay = 1;
          break;
        case cmdKDFSETUP:  err = cmd_kdfsetup (info, argstr); break;
        case cmdUIF:       err = cmd_uif (info, argstr); break;
        case cmdYUBIKEY:   err = cmd_yubikey (info, argstr); break;
        case cmdAPDU:      err = cmd_apdu (info, argstr); break;
        case cmdGPG:       err = cmd_gpg (info, argstr, 0); break;
        case cmdGPGSM:     err = cmd_gpg (info, argstr, 1); break;
        case cmdHISTORY:   err = cmd_history (info, argstr); break;
        case cmdCHECKKEYS: err = cmd_checkkeys (info, argstr); break;

        case cmdINVCMD:
        default:
          tty_printf ("\n");
          tty_printf (_("Invalid command  (try \"help\")\n"));
          break;
        } /* End command switch. */

      if (!err && info && info->card_removed)
        {
          info->card_removed = 0;
          info->need_sn_cmd = 1;
          err = gpg_error (GPG_ERR_CARD_REMOVED);
        }

      if (gpg_err_code (err) == GPG_ERR_CANCELED)
        tty_fprintf (NULL, "\n");
      else if (err)
        {
          const char *s = "?";
          for (i=0; cmds[i].name; i++ )
            if (cmd == cmds[i].id)
              {
                s = cmds[i].name;
                break;
              }

          err = fixup_scd_errors (err);
          log_error ("Command '%s' failed: %s\n", s, gpg_strerror (err));
          if (gpg_err_code (err) == GPG_ERR_CARD_NOT_PRESENT)
            info->need_sn_cmd = 1;
        }

    } /* End of main menu loop. */

 leave:
  if (historyname && tty_write_history (historyname))
    log_info ("error writing '%s': %s\n",
              historyname, gpg_strerror (gpg_error_from_syserror ()));

  release_card_info (info);
  xfree (historyname);
  xfree (answer);
}

#ifdef HAVE_LIBREADLINE
/* Helper function for readline's command completion. */
static char *
command_generator (const char *text, int state)
{
  static int list_index, len;
  const char *name;

  /* If this is a new word to complete, initialize now.  This includes
   * saving the length of TEXT for efficiency, and initializing the
   index variable to 0. */
  if (!state)
    {
      list_index = 0;
      len = strlen(text);
    }

  /* Return the next partial match */
  while ((name = cmds[list_index].name))
    {
      /* Only complete commands that have help text. */
      if (cmds[list_index++].desc && !strncmp (name, text, len))
	return strdup(name);
    }

  return NULL;
}

/* Second helper function for readline's command completion.  */
static char **
command_completion (const char *text, int start, int end)
{
  (void)end;

  /* If we are at the start of a line, we try and command-complete.
   * If not, just do nothing for now.  The support for help completion
   * needs to be more smarter. */
  if (!start)
    return rl_completion_matches (text, command_generator);
  else if (start == 5 && !ascii_strncasecmp (rl_line_buffer, "help ", 5))
    return rl_completion_matches (text, command_generator);

  rl_attempted_completion_over = 1;

  return NULL;
}
#endif /*HAVE_LIBREADLINE*/
