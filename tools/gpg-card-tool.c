/* gpg-card-tool.c - An interactive tool to work with cards.
 * Copyright (C) 2019 g10 Code GmbH
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
#ifdef HAVE_LIBREADLINE
# define GNUPG_LIBREADLINE_H_INCLUDED
# include <readline/readline.h>
#endif /*HAVE_LIBREADLINE*/

#include "../common/util.h"
#include "../common/status.h"
#include "../common/i18n.h"
#include "../common/init.h"
#include "../common/sysutils.h"
#include "../common/asshelp.h"
#include "../common/userids.h"
#include "../common/ccparray.h"
#include "../common/exectool.h"
#include "../common/ttyio.h"
#include "../common/server-help.h"
#include "../common/openpgpdefs.h"

#include "card-tool.h"


#define CONTROL_D ('D' - 'A' + 1)

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

    oDummy
  };


/* The list of commands and options. */
static ARGPARSE_OPTS opts[] = {
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


/* Limit of size of data we read from a file for certain commands.  */
#define MAX_GET_DATA_FROM_FILE 16384

/* Constants for OpenPGP cards.  */
#define OPENPGP_USER_PIN_DEFAULT  "123456"
#define OPENPGP_ADMIN_PIN_DEFAULT "12345678"
#define OPENPGP_KDF_DATA_LENGTH_MIN  90
#define OPENPGP_KDF_DATA_LENGTH_MAX 110




/* Local prototypes.  */
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
    case 11: p = "gpg-card-tool"; break;
    case 12: p = "@GNUPG@"; break;
    case 13: p = VERSION; break;
    case 17: p = PRINTABLE_OS_NAME; break;
    case 19: p = ("Please report bugs to <@EMAIL@>.\n"); break;

    case 1:
    case 40:
      p = ("Usage: gpg-card-tool"
           " [options] [{[--] command [args]}]  (-h for help)");
      break;
    case 41:
      p = ("Syntax: gpg-card-tool"
           " [options] [command [args] {-- command [args]}]\n\n"
           "Tool to manage cards and tokens.  With a command an interactive\n"
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
parse_arguments (ARGPARSE_ARGS *pargs, ARGPARSE_OPTS *popts)
{
  while (optfile_parse (NULL, NULL, NULL, pargs, popts))
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

        case oGpgProgram:   opt.gpg_program = pargs->r.ret_str; break;
        case oGpgsmProgram: opt.gpgsm_program = pargs->r.ret_str; break;
        case oAgentProgram: opt.agent_program = pargs->r.ret_str; break;

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

        default: pargs->err = 2; break;
	}
    }
}



/* gpg-card-tool main. */
int
main (int argc, char **argv)
{
  gpg_error_t err;
  ARGPARSE_ARGS pargs;
  char **command_list = NULL;
  int cmdidx;
  char *command;

  gnupg_reopen_std ("gpg-card-tool");
  set_strusage (my_strusage);
  gnupg_rl_initialize ();
  log_set_prefix ("gpg-card-tool", GPGRT_LOG_WITH_PREFIX);

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

  if (log_get_errorcount (0))
    exit (2);

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


/* Read data from file FNAME up to MAX_GET_DATA_FROM_FILE characters.
 * On error return an error code and stores NULL at R_BUFFER; on
 * success returns 0 and stores the number of bytes read at R_BUFLEN
 * and the address of a newly allocated buffer at R_BUFFER.  A
 * complementary nul byte is always appended to the data but not
 * counted; this allows to pass NULL for R-BUFFER and consider the
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



/* Simply prints TEXT to the output.  Returns 0 as a convenience.
 * This is a separate fucntion so that it can be extended to run
 * less(1) or so.  The extra arguments are int values terminated by a
 * 0 to indicate card application types supported with this command.
 * If none are given (just teh final 0), this is a general
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


/* Return the OpenPGP card manufacturer name.  */
static const char *
get_manufacturer (unsigned int no)
{
  /* Note:  Make sure that there is no colon or linefeed in the string. */
  switch (no)
    {
    case 0x0001: return "PPC Card Systems";
    case 0x0002: return "Prism";
    case 0x0003: return "OpenFortress";
    case 0x0004: return "Wewid";
    case 0x0005: return "ZeitControl";
    case 0x0006: return "Yubico";
    case 0x0007: return "OpenKMS";
    case 0x0008: return "LogoEmail";
    case 0x0009: return "Fidesmo";
    case 0x000A: return "Dangerous Things";

    case 0x002A: return "Magrathea";
    case 0x0042: return "GnuPG e.V.";

    case 0x1337: return "Warsaw Hackerspace";
    case 0x2342: return "warpzone"; /* hackerspace Muenster.  */
    case 0x4354: return "Confidential Technologies";   /* cotech.de */
    case 0x63AF: return "Trustica";
    case 0xBD0E: return "Paranoidlabs";
    case 0xF517: return "FSIJ";

      /* 0x0000 and 0xFFFF are defined as test cards per spec,
       * 0xFF00 to 0xFFFE are assigned for use with randomly created
       * serial numbers.  */
    case 0x0000:
    case 0xffff: return "test card";
    default: return (no & 0xff00) == 0xff00? "unmanaged S/N range":"unknown";
    }
}

/* Print an (OpenPGP) fingerprint.  */
static void
print_shax_fpr (estream_t fp, const unsigned char *fpr, unsigned int fprlen)
{
  int i;

  if (fpr)
    {
      /* FIXME: Fix formatting for FPRLEN != 20 */
      for (i=0; i < fprlen ; i+=2, fpr += 2 )
        {
          if (i == 10 )
            tty_fprintf (fp, " ");
          tty_fprintf (fp, " %02X%02X", *fpr, fpr[1]);
        }
    }
  else
    tty_fprintf (fp, " [none]");
  tty_fprintf (fp, "\n");
}

/* Print the keygrip GRP.  */
static void
print_keygrip (estream_t fp, const unsigned char *grp)
{
  int i;

  for (i=0; i < 20 ; i++, grp++)
    tty_fprintf (fp, "%02X", *grp);
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



/* Helper to list a single keyref.  */
static void
list_one_kinfo (key_info_t firstkinfo, key_info_t kinfo, estream_t fp)
{
  gpg_error_t err;
  keyblock_t keyblock = NULL;
  keyblock_t kb;
  pubkey_t pubkey;
  userid_t uid;
  key_info_t ki;
  const char *s;
  gcry_sexp_t s_pkey;

  if (firstkinfo && kinfo)
    {
      tty_fprintf (fp, " ");
      if (mem_is_zero (kinfo->grip, sizeof kinfo->grip))
        {
          tty_fprintf (fp, "[none]\n");
          goto leave;
        }
      print_keygrip (fp, kinfo->grip);
      if (!scd_readkey (kinfo->keyref, &s_pkey))
        {
          char *tmp = pubkey_algo_string (s_pkey);
          tty_fprintf (fp, "      algorithm ..: %s\n", tmp);
          xfree (tmp);
          gcry_sexp_release (s_pkey);
          s_pkey = NULL;
        }

      if (kinfo->fprlen && kinfo->created)
        {
          tty_fprintf (fp, "      fingerprint :");
          print_shax_fpr (fp, kinfo->fpr, kinfo->fprlen);
          tty_fprintf (fp, "      created ....: %s\n",
                       isotimestamp (kinfo->created));
        }
      err = get_matching_keys (kinfo->grip,
                               (GNUPG_PROTOCOL_OPENPGP | GNUPG_PROTOCOL_CMS),
                               &keyblock);
      if (err)
        {
          if (gpg_err_code (err) != GPG_ERR_NO_PUBKEY)
            tty_fprintf (fp, "      error ......: %s\n", gpg_strerror (err));
          goto leave;
        }
      for (kb = keyblock; kb; kb = kb->next)
        {
          tty_fprintf (fp, "      used for ...: %s\n",
                       kb->protocol == GNUPG_PROTOCOL_OPENPGP? "OpenPGP" :
                       kb->protocol == GNUPG_PROTOCOL_CMS? "X.509" : "?");
          pubkey = kb->keys;
          /* If this is not the primary key print the primary key's
           * fingerprint or a reference to it.  */
          if (kb->protocol == GNUPG_PROTOCOL_OPENPGP)
            {
              tty_fprintf (fp, "        main key .:");
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
                    tty_fprintf (fp, " <%s>\n", s);
                  else
                    tty_fprintf (fp, " <Key %s>\n", ki->keyref);
                }
              else
                print_shax_fpr (fp, pubkey->fpr, pubkey->fprlen);
            }
          for (uid = kb->uids; uid; uid = uid->next)
            {
              print_string (fp, "        user id ..: ", uid->value);
            }

        }
    }
  else
    tty_fprintf (fp, " [none]\n");

 leave:
  release_keyblock (keyblock);
}


/* List all keyinfo in INFO using the list of LABELS.  */
static void
list_all_kinfo (card_info_t info, keyinfolabel_t labels, estream_t fp)
{
  key_info_t kinfo;
  int idx, i;

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
          list_one_kinfo (info->kinfo, kinfo, fp);
          if (kinfo)
            kinfo->xflag = 1;
        }
    }
  for (kinfo = info->kinfo; kinfo; kinfo = kinfo->next)
    {
      if (kinfo->xflag)
        continue;
      tty_fprintf (fp, "Key %s ", kinfo->keyref);
      for (i=5+strlen (kinfo->keyref); i < 18; i++)
        tty_fprintf (fp, ".");
      tty_fprintf (fp, ":");
      list_one_kinfo (info->kinfo, kinfo, fp);
    }
}


/* List OpenPGP card specific data.  */
static void
list_openpgp (card_info_t info, estream_t fp)
{
  static struct keyinfolabel_s keyinfolabels[] = {
    { "Signature key ....:", "OPENPGP.1" },
    { "Encryption key....:", "OPENPGP.2" },
    { "Authentication key:", "OPENPGP.3" },
    { NULL, NULL }
  };
  int i;

  if (!info->serialno
      || strncmp (info->serialno, "D27600012401", 12)
      || strlen (info->serialno) != 32 )
    {
      tty_fprintf (fp, "invalid OpenPGP card\n");
      return;
    }

  tty_fprintf (fp, "Version ..........: %.1s%c.%.1s%c\n",
               info->serialno[12] == '0'?"":info->serialno+12,
               info->serialno[13],
               info->serialno[14] == '0'?"":info->serialno+14,
               info->serialno[15]);
  tty_fprintf (fp, "Manufacturer .....: %s\n",
               get_manufacturer (xtoi_2(info->serialno+16)*256
                                 + xtoi_2 (info->serialno+18)));
  tty_fprintf (fp, "Name of cardholder: ");
  print_isoname (fp, info->disp_name);

  print_string (fp, "Language prefs ...: ", info->disp_lang);
  tty_fprintf (fp, "Salutation .......: %s\n",
               info->disp_sex == 1? _("Mr."):
               info->disp_sex == 2? _("Mrs.") : "");
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
  if (info->key_attr[0].algo)
    {
      tty_fprintf (fp,    "Key attributes ...:");
      for (i=0; i < DIM (info->key_attr); i++)
        if (info->key_attr[i].algo == PUBKEY_ALGO_RSA)
          tty_fprintf (fp, " rsa%u", info->key_attr[i].nbits);
        else if (info->key_attr[i].algo == PUBKEY_ALGO_ECDH
                 || info->key_attr[i].algo == PUBKEY_ALGO_ECDSA
                 || info->key_attr[i].algo == PUBKEY_ALGO_EDDSA)
          {
            const char *curve_for_print = "?";
            const char *oid;

            if (info->key_attr[i].curve
                && (oid = openpgp_curve_to_oid (info->key_attr[i].curve, NULL)))
              curve_for_print = openpgp_oid_to_curve (oid, 0);
            tty_fprintf (fp, " %s", curve_for_print);
          }
      tty_fprintf (fp, "\n");
    }
  tty_fprintf (fp, "Max. PIN lengths .: %d %d %d\n",
               info->chvmaxlen[0], info->chvmaxlen[1], info->chvmaxlen[2]);
  tty_fprintf (fp, "PIN retry counter : %d %d %d\n",
               info->chvinfo[0], info->chvinfo[1], info->chvinfo[2]);
  tty_fprintf (fp, "Signature counter : %lu\n", info->sig_counter);
  if (info->extcap.kdf)
    {
      tty_fprintf (fp, "KDF setting ......: %s\n",
                   info->kdf_do_enabled ? "on" : "off");
    }
  if (info->extcap.bt)
    {
      tty_fprintf (fp, "UIF setting ......: Sign=%s Decrypt=%s Auth=%s\n",
                   info->uif[0] ? "on" : "off", info->uif[1] ? "on" : "off",
                   info->uif[2] ? "on" : "off");
    }

  list_all_kinfo (info, keyinfolabels, fp);

  /* tty_fprintf (fp, "General key info->.: "); */
  /* thefpr = (info->fpr1len? info->fpr1 : info->fpr2len? info->fpr2 : */
  /*           info->fpr3len? info->fpr3 : NULL); */
  /* thefprlen = (info->fpr1len? info->fpr1len : info->fpr2len? info->fpr2len : */
  /*              info->fpr3len? info->fpr3len : 0); */
  /* If the fingerprint is all 0xff, the key has no associated
     OpenPGP certificate.  */
  /* if ( thefpr && !mem_is_ff (thefpr, thefprlen) */
  /*      && !get_pubkey_byfprint (ctrl, pk, &keyblock, thefpr, thefprlen)) */
  /*   { */
      /* print_pubkey_info (ctrl, fp, pk); */
      /* if (keyblock) */
      /*   print_card_key_info (fp, keyblock); */
  /*   } */
  /* else */
  /*   tty_fprintf (fp, "[none]\n"); */
}


/* List PIV card specific data.  */
static void
list_piv (card_info_t info, estream_t fp)
{
  static struct keyinfolabel_s keyinfolabels[] = {
    { "PIV authentication:", "PIV.9A" },
    { "Card authenticat. :", "PIV.9E" },
    { "Digital signature :", "PIV.9C" },
    { "Key management ...:", "PIV.9D" },
    { NULL, NULL }
  };
  const char *s;
  int i;

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

  tty_fprintf (fp, "PIN retry counter :");
  for (i=0; i < DIM (info->chvinfo); i++)
    {
      if (info->chvinfo[i] > 0)
        tty_fprintf (fp, " %d", info->chvinfo[i]);
      else
        {
          switch (info->chvinfo[i])
            {
            case -1: s = "[error]"; break;
            case -2: s = "-"; break;  /* No such PIN or info not available. */
            case -3: s = "[blocked]"; break;
            case -5: s = "[verified]"; break;
            default: s = "[?]"; break;
            }
          tty_fprintf (fp, " %s", s);
        }
    }
  tty_fprintf (fp, "\n");
  list_all_kinfo (info, keyinfolabels, fp);

}


/* Print all available information about the current card. */
static void
list_card (card_info_t info)
{
  estream_t fp = opt.interactive? NULL : es_stdout;

  tty_fprintf (fp, "Reader ...........: %s\n",
               info->reader? info->reader : "[none]");
  if (info->cardtype)
    tty_fprintf (fp, "Card type ........: %s\n", info->cardtype);
  tty_fprintf (fp, "Serial number ....: %s\n",
               info->serialno? info->serialno : "[none]");
  tty_fprintf (fp, "Application type .: %s%s%s%s\n",
               app_type_string (info->apptype),
               info->apptype == APP_TYPE_UNKNOWN && info->apptypestr? "(":"",
               info->apptype == APP_TYPE_UNKNOWN && info->apptypestr
               ? info->apptypestr:"",
               info->apptype == APP_TYPE_UNKNOWN && info->apptypestr? ")":"");
  if (info->serialno && info->dispserialno
      && strcmp (info->serialno, info->dispserialno))
    tty_fprintf (fp, "Displayed S/N ....: %s\n", info->dispserialno);

  switch (info->apptype)
    {
    case APP_TYPE_OPENPGP: list_openpgp (info, fp); break;
    case APP_TYPE_PIV:     list_piv (info, fp); break;
    default: break;
    }
}



/* The VERIFY command.  */
static gpg_error_t
cmd_verify (card_info_t info, char *argstr)
{
  gpg_error_t err;
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
  return err;
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
       "Perform a mutual autentication either by reading the key\n"
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

  if (!info)
    return print_help
      ("LOGIN [--clear] [< FILE]\n\n"
       "Set the login data object.  If FILE is given the data is\n"
       "is read from that file.  This allows for binary data.\n"
       "The option --clear deletes the login data.",
       APP_TYPE_OPENPGP, 0);

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
      if (!*data || *data == CONTROL_D)
        {
          err = gpg_error (GPG_ERR_CANCELED);
          goto leave;
        }
      datalen = strlen (data);
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
      data = tty_get (_("Salutation (M = Mr., F = Mrs., or space): "));
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
  char *certref_buffer = NULL;
  char *certref;
  char *data = NULL;
  size_t datalen;

  if (!info)
    return print_help
      ("WRITECERT [--clear] CERTREF < FILE\n\n"
       "Write a certificate for key 3.  Unless --clear is given\n"
       "the file argument is mandatory.  The option --clear removes\n"
       "the certificate from the card.",
       APP_TYPE_OPENPGP, APP_TYPE_PIV, 0);

  opt_clear = has_leading_option (argstr, "--clear");
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
      if (ascii_strcasecmp (certref, "OPENPGP.3") && strcmp (certref, "3"))
        {
          err = gpg_error (GPG_ERR_INV_ID);
          log_error ("Error: CERTREF must be \"3\" or \"OPENPGP.3\"\n");
          goto leave;
        }
      certref = certref_buffer = xstrdup ("OPENPGP.3");
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
    }
  else
    {
      err = gpg_error (GPG_ERR_INV_ARG);
      goto leave;
    }

  err = scd_writecert (certref, data, datalen);

 leave:
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
  size_t datalen;
  const char *fname;

  if (!info)
    return print_help
      ("READCERT CERTREF > FILE\n\n"
       "Read the certificate for key 3 and store it in FILE.",
       APP_TYPE_OPENPGP, APP_TYPE_PIV, 0);

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
      if (ascii_strcasecmp (certref, "OPENPGP.3") && strcmp (certref, "3"))
        {
          err = gpg_error (GPG_ERR_INV_ID);
          log_error ("Error: CERTREF must be \"3\" or \"OPENPGP.3\"\n");
          goto leave;
        }
      certref = certref_buffer = xstrdup ("OPENPGP.3");
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

  err = scd_readcert (certref, &data, &datalen);
  if (err)
    goto leave;

  err = put_data_to_file (fname, data, datalen);

 leave:
  xfree (data);
  xfree (certref_buffer);
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



/* Helper for cmd_generate_openpgp.  Noe that either 0 or 1 is stored at
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


/* Implementation of cmd_generate for OpenPGP cards.  */
static gpg_error_t
generate_openpgp (card_info_t info)
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
      tty_printf ("\n");
      log_info (_("Note: keys are already stored on the card!\n"));
      tty_printf ("\n");
      answer = tty_get (_("Replace existing keys? (y/N) "));
      tty_kill_prompt ();
      if (*answer == CONTROL_D)
        {
          err = gpg_error (GPG_ERR_CANCELED);
          goto leave;
        }

      if (!answer_is_yes_no_default (answer, 0/*(default to No)*/))
        {
          err = gpg_error (GPG_ERR_CANCELED);
          goto leave;
        }
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

  /* FIXME: We need to divert to a function which spwans gpg which
   * will then create the key.  This also requires new features in
   * gpg.  We might also first create the keys on the card and then
   * tell gpg to use them to create the OpenPGP keyblock. */
  /* generate_keypair (ctrl, 1, NULL, info.serialno, want_backup); */
  (void)want_backup;
  err = gpg_error (GPG_ERR_NOT_IMPLEMENTED);

 leave:
  restore_forced_chv1 (&forced_chv1);
  xfree (answer);
  return err;
}


/* Generic implementation of cmd_generate.  */
static gpg_error_t
generate_generic (card_info_t info, const char *keyref, int force,
                  const char *algo)
{
  gpg_error_t err;

  (void)info;

  err = scd_genkey (keyref, force, algo, NULL);

  return err;
}


static gpg_error_t
cmd_generate (card_info_t info, char *argstr)
{
  static char * const valid_algos[] =
    { "rsa2048", "rsa3072", "rsa4096",
      "nistp256", "nistp384", "nistp521",
      "ed25519", "cv25519",
      NULL
    };
  gpg_error_t err;
  int opt_force;
  char *opt_algo = NULL; /* Malloced.  */
  char *keyref_buffer = NULL;  /* Malloced.  */
  char *keyref;          /* Points into argstr or keyref_buffer.  */
  int i;

  if (!info)
    return print_help
      ("GENERATE [--force] [--algo=ALGO] KEYREF\n\n"
       "Create a new key on a card.  For OpenPGP cards are menu is used\n"
       "and KEYREF is ignored.  Use --force to overwrite an existing key.",
       APP_TYPE_OPENPGP, APP_TYPE_PIV, 0);

  if (opt.interactive || opt.verbose)
    log_info (_("%s card no. %s detected\n"),
              app_type_string (info->apptype),
              info->dispserialno? info->dispserialno : info->serialno);

  opt_force = has_leading_option (argstr, "--force");
  err = get_option_value (argstr, "--algo", &opt_algo);
  if (err)
    goto leave;
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
      for (i=0; valid_algos[i]; i++)
        if (!strcmp (valid_algos[i], opt_algo))
          break;
      if (!valid_algos[i])
        {
          err = gpg_error (GPG_ERR_PUBKEY_ALGO);
          log_info ("Invalid algorithm '%s' given.  Use one:\n", opt_algo);
          for (i=0; valid_algos[i]; i++)
            if (!(i%5))
              log_info ("  %s%s", valid_algos[i], valid_algos[i+1]?",":".");
            else
              log_printf (" %s%s", valid_algos[i], valid_algos[i+1]?",":".");
          log_info ("Note that the card may not support all of them.\n");
          goto leave;
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

  /* Divert to dedicated functions.  */
  if (info->apptype == APP_TYPE_OPENPGP)
    {
      if (opt_force || opt_algo || keyref)
        log_info ("Note: Options are ignored for OpenPGP cards.\n");
      err = generate_openpgp (info);
    }
  else if (!keyref)
    err = gpg_error (GPG_ERR_INV_ID);
  else
    err = generate_generic (info, keyref, opt_force, opt_algo);

 leave:
  xfree (opt_algo);
  xfree (keyref_buffer);
  return err;
}



/* Sub-menu to change a PIN.  The presented options may depend on the
 * the ALLOW_ADMIN flag.  */
static gpg_error_t
cmd_passwd (card_info_t info, int allow_admin, char *argstr)
{
  gpg_error_t err;
  char *answer = NULL;
  const char *pinref;

  if (!info)
    return print_help
      ("PASSWD [PINREF]\n\n"
       "Menu to change or unblock the PINs.  Note that the\n"
       "presented menu options depend on the type of card\n"
       "and whether the admin mode is enabled.  For OpenPGP\n"
       "and PIV cards defaults for PINREF are available.",
       0);

  if (opt.interactive || opt.verbose)
    log_info (_("%s card no. %s detected\n"),
              app_type_string (info->apptype),
              info->dispserialno? info->dispserialno : info->serialno);

  if (!allow_admin || info->apptype != APP_TYPE_OPENPGP)
    {
      if (*argstr)
        pinref = argstr;
      else if (info->apptype == APP_TYPE_OPENPGP)
        pinref = "OPENPGP.1";
      else if (info->apptype == APP_TYPE_PIV)
        pinref = "PIV.80";
      else
        {
          err = gpg_error (GPG_ERR_MISSING_VALUE);
          goto leave;
        }
      err = scd_change_pin (pinref, 0);
      if (err)
        goto leave;

      if (info->apptype == APP_TYPE_PIV
          && !ascii_strcasecmp (pinref, "PIV.81"))
        log_info ("PUK changed.\n");
      else
        log_info ("PIN changed.\n");
    }
  else if (info->apptype == APP_TYPE_OPENPGP)
    {
      for (;;)
        {
          tty_printf ("\n");
          tty_printf ("1 - change PIN\n"
                      "2 - unblock and set new PIN\n"
                      "3 - change Admin PIN\n"
                      "4 - set the Reset Code\n"
                      "Q - quit\n");
          tty_printf ("\n");

          err = 0;
          xfree (answer);
          answer = tty_get (_("Your selection? "));
          tty_kill_prompt ();
          if (*answer == CONTROL_D)
            break;  /* Quit.  */
          if (strlen (answer) != 1)
            continue;
          if (*answer == 'q' || *answer == 'Q')
            break;  /* Quit.  */

          if (*answer == '1')
            {
              /* Change PIN (same as the direct thing in non-admin mode).  */
              err = scd_change_pin ("OPENPGP.1", 0);
              if (err)
                log_error ("Error changing the PIN: %s\n", gpg_strerror (err));
              else
                log_info ("PIN changed.\n");
            }
          else if (*answer == '2')
            {
              /* Unblock PIN by setting a new PIN.  */
              err = scd_change_pin ("OPENPGP.1", 1);
              if (err)
                log_error ("Error unblocking the PIN: %s\n", gpg_strerror(err));
              else
                log_info ("PIN unblocked and new PIN set.\n");
            }
          else if (*answer == '3')
            {
              /* Change Admin PIN.  */
              err = scd_change_pin ("OPENPGP.3", 0);
              if (err)
                log_error ("Error changing the PIN: %s\n", gpg_strerror (err));
              else
                log_info ("PIN changed.\n");
	  }
          else if (*answer == '4')
            {
              /* Set a new Reset Code.  */
              err = scd_change_pin ("OPENPGP.2", 1);
              if (err)
                log_error ("Error setting the Reset Code: %s\n",
                           gpg_strerror (err));
              else
                log_info ("Reset Code set.\n");
            }

        } /*end for loop*/
    }
  else
    {
      log_info ("Admin related passwd options not yet supported for '%s'\n",
                app_type_string (info->apptype));
      err = gpg_error (GPG_ERR_NOT_SUPPORTED);
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
          err = gpg_error (GPG_ERR_PIN_BLOCKED);
        }
      else
        {
          err = scd_change_pin ("OPENPGP.2", 0);
          if (!err)
            log_info ("PIN changed.\n");
        }
    }
  else if (info->apptype == APP_TYPE_PIV)
    {
      /* Unblock the Application PIN.  */
      err = scd_change_pin ("PIV.80", 1);
      if (!err)
        log_info ("PIN unblocked and changed.\n");
    }
  else
    {
      log_info ("Unblocking not yet supported for '%s'\n",
                app_type_string (info->apptype));
      err = gpg_error (GPG_ERR_NOT_IMPLEMENTED);
    }

  return err;
}


/* Direct sending of an hex encoded APDU with error printing.  */
static gpg_error_t
send_apdu (const char *hexapdu, const char *desc, unsigned int ignore)
{
  gpg_error_t err;
  unsigned int sw;

  err = scd_apdu (hexapdu, &sw);
  if (err)
    log_error ("sending card command %s failed: %s\n", desc,
               gpg_strerror (err));
  else if (!hexapdu || !strcmp (hexapdu, "undefined"))
    ;
  else if (ignore == 0xffff)
    ; /* Ignore all status words.  */
  else if (sw != 0x9000)
    {
      switch (sw)
        {
        case 0x6285: err = gpg_error (GPG_ERR_OBJ_TERM_STATE); break;
        case 0x6982: err = gpg_error (GPG_ERR_BAD_PIN); break;
        case 0x6985: err = gpg_error (GPG_ERR_USE_CONDITIONS); break;
        default: err = gpg_error (GPG_ERR_CARD);
        }
      if (!(ignore && ignore == sw))
        log_error ("card command %s failed: %s (0x%04x)\n", desc,
                   gpg_strerror (err),  sw);
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

  err = scd_learn (info);
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
          /* The PIV application si already selected, we only need to
           * send the special reset APDU after having blocked PIN and
           * PUK.  Note that blocking the PUK is done using the
           * unblock PIN command.  */
          any_apdu = 1;
          for (i=0; i < 5; i++)
            send_apdu ("0020008008FFFFFFFFFFFFFFFF", "VERIFY", 0xffff);
          for (i=0; i < 5; i++)
            send_apdu ("002C008010FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF",
                       "RESET RETRY COUNTER", 0xffff);
          err = send_apdu ("00FB000001FF", "YUBIKEY RESET", 0);
          if (err)
            goto leave;
        }
      else /* OpenPGP card.  */
        {
          any_apdu = 1;
          /* We need to select a card application before we can send APDUs
           * to the card without scdaemon doing anything on its own.  */
          err = send_apdu (NULL, "RESET", 0);
          if (err)
            goto leave;
          err = send_apdu ("undefined", "dummy select ", 0);
          if (err)
            goto leave;
          /* Select the OpenPGP application.  */
          err = send_apdu ("00A4040006D27600012401", "SELECT AID", 0);
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
                       "40404040404040404040404040404040", "VERIFY", 0xffff);
          for (i=0; i < 4; i++)
            send_apdu ("0020008320"
                       "40404040404040404040404040404040"
                       "40404040404040404040404040404040", "VERIFY", 0xffff);

          /* Send terminate datafile command.  */
          err = send_apdu ("00e60000", "TERMINATE DF", 0x6985);
          if (err)
            goto leave;
        }
    }

  if (!is_yubikey)
    {
      any_apdu = 1;
      /* Send activate datafile command.  This is used without
       * confirmation if the card is already in termination state.  */
      err = send_apdu ("00440000", "ACTIVATE DF", 0);
      if (err)
        goto leave;
    }

  /* Finally we reset the card reader once more.  */
  err = send_apdu (NULL, "RESET", 0);
  if (err)
    goto leave;

  /* Then, connect the card again (answer used as a dummy).  */
  xfree (answer); answer = NULL;
  err = scd_serialno (&answer, NULL);

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


/* Ask for the size of a card key.  NBITS is the current size
 * configured for the card.  Returns 0 on success and stored the
 * chosen key size at R_KEYSIZE; 0 is stored to indicate that the
 * default size shall be used.  */
static gpg_error_t
ask_card_rsa_keysize (unsigned int nbits, unsigned int *r_keysize)
{
  unsigned int min_nbits = 1024;
  unsigned int max_nbits = 4096;
  char*answer;
  unsigned int req_nbits;

  for (;;)
    {
      answer = tty_getf (_("What keysize do you want? (%u) "), nbits);
      trim_spaces (answer);
      tty_kill_prompt ();
      if (*answer == CONTROL_D)
        {
          xfree (answer);
          return gpg_error (GPG_ERR_CANCELED);
        }
      req_nbits = *answer? atoi (answer): nbits;
      xfree (answer);

      if (req_nbits != nbits && (req_nbits % 32) )
        {
          req_nbits = ((req_nbits + 31) / 32) * 32;
          tty_printf (_("rounded up to %u bits\n"), req_nbits);
        }

      if (req_nbits == nbits)
        {
          /* Use default.  */
          *r_keysize = 0;
          return 0;
        }

      if (req_nbits < min_nbits || req_nbits > max_nbits)
        {
          tty_printf (_("%s keysizes must be in the range %u-%u\n"),
                      "RSA", min_nbits, max_nbits);
        }
      else
        {
          *r_keysize = req_nbits;
          return 0;
        }
    }
}


/* Ask for the key attribute of a card key.  CURRENT is the current
 * attribute configured for the card.  KEYNO is the number of the key
 * used to select the prompt.  Stores NULL at result to use the
 * default attribute or stores the selected attribute structure at
 * RESULT.  On error an error code is returned.  */
static gpg_error_t
ask_card_keyattr (int keyno, const struct key_attr *current,
                  struct key_attr **result)
{
  gpg_error_t err;
  struct key_attr *key_attr = NULL;
  char *answer = NULL;
  int selection;

  *result = NULL;

  key_attr = xcalloc (1, sizeof *key_attr);

  tty_printf (_("Changing card key attribute for: "));
  if (keyno == 0)
    tty_printf (_("Signature key\n"));
  else if (keyno == 1)
    tty_printf (_("Encryption key\n"));
  else
    tty_printf (_("Authentication key\n"));

  tty_printf (_("Please select what kind of key you want:\n"));
  tty_printf (_("   (%d) RSA\n"), 1 );
  tty_printf (_("   (%d) ECC\n"), 2 );

  for (;;)
    {
      xfree (answer);
      answer = tty_get (_("Your selection? "));
      trim_spaces (answer);
      tty_kill_prompt ();
      if (!*answer || *answer == CONTROL_D)
        {
          err = gpg_error (GPG_ERR_CANCELED);
          goto leave;
        }
      selection = *answer? atoi (answer) : 0;

      if (selection == 1 || selection == 2)
        break;
      else
        tty_printf (_("Invalid selection.\n"));
    }


  if (selection == 1)
    {
      unsigned int nbits, result_nbits;

      if (current->algo == PUBKEY_ALGO_RSA)
        nbits = current->nbits;
      else
        nbits = 2048;

      err = ask_card_rsa_keysize (nbits, &result_nbits);
      if (err)
        goto leave;
      if (result_nbits == 0)
        {
          if (current->algo == PUBKEY_ALGO_RSA)
            {
              xfree (key_attr);
              key_attr = NULL;
            }
          else
            result_nbits = nbits;
        }

      if (key_attr)
        {
          key_attr->algo = PUBKEY_ALGO_RSA;
          key_attr->nbits = result_nbits;
        }
    }
  else if (selection == 2)
    {
      const char *curve;
      /* const char *oid_str; */
      int algo;

      if (current->algo == PUBKEY_ALGO_RSA)
        {
          if (keyno == 1) /* Encryption key */
            algo = PUBKEY_ALGO_ECDH;
          else /* Signature key or Authentication key */
            algo = PUBKEY_ALGO_ECDSA;
          curve = NULL;
        }
      else
        {
          algo = current->algo;
          curve = current->curve;
        }

      (void)curve;
      (void)algo;
      err = GPG_ERR_NOT_IMPLEMENTED;
      goto leave;
      /* FIXME: We need to mve the ask_cure code out to common or
       * provide another sultion.  */
      /* curve = ask_curve (&algo, NULL, curve); */
      /* if (curve) */
      /*   { */
      /*     key_attr->algo = algo; */
      /*     oid_str = openpgp_curve_to_oid (curve, NULL); */
      /*     key_attr->curve = openpgp_oid_to_curve (oid_str, 0); */
      /*   } */
      /* else */
      /*   { */
      /*     xfree (key_attr); */
      /*     key_attr = NULL; */
      /*   } */
    }
  else
    {
      err = gpg_error (GPG_ERR_BUG);
      goto leave;
    }

  /* Tell the user what we are going to do.  */
  if (key_attr->algo == PUBKEY_ALGO_RSA)
    {
      tty_printf (_("The card will now be re-configured"
                    " to generate a key of %u bits\n"), key_attr->nbits);
    }
  else if (key_attr->algo == PUBKEY_ALGO_ECDH
           || key_attr->algo == PUBKEY_ALGO_ECDSA
           || key_attr->algo == PUBKEY_ALGO_EDDSA)
    {
      tty_printf (_("The card will now be re-configured"
                    " to generate a key of type: %s\n"), key_attr->curve);
    }
  show_keysize_warning ();

  *result = key_attr;
  key_attr = NULL;

 leave:
  xfree (key_attr);
  xfree (answer);
  return err;
}


/* Change the key attribute of key KEYNO (0..2) and show an error
 * message if that fails.  */
static gpg_error_t
do_change_keyattr (int keyno, const struct key_attr *key_attr)
{
  gpg_error_t err = 0;
  char args[100];

  if (key_attr->algo == PUBKEY_ALGO_RSA)
    snprintf (args, sizeof args, "--force %d 1 rsa%u", keyno+1,
              key_attr->nbits);
  else if (key_attr->algo == PUBKEY_ALGO_ECDH
           || key_attr->algo == PUBKEY_ALGO_ECDSA
           || key_attr->algo == PUBKEY_ALGO_EDDSA)
    snprintf (args, sizeof args, "--force %d %d %s",
              keyno+1, key_attr->algo, key_attr->curve);
  else
    {
      /* FIXME: Above we use opnepgp algo names but in the error
       * message we use the gcrypt names.  We should settle for a
       * consistent solution. */
      log_error (_("public key algorithm %d (%s) is not supported\n"),
                 key_attr->algo, gcry_pk_algo_name (key_attr->algo));
      err = gpg_error (GPG_ERR_PUBKEY_ALGO);
      goto leave;
    }

  err = scd_setattr ("KEY-ATTR", args, strlen (args));
  if (err)
    log_error (_("error changing key attribute for key %d: %s\n"),
               keyno+1, gpg_strerror (err));
 leave:
  return err;
}


static gpg_error_t
cmd_keyattr (card_info_t info, char *argstr)
{
  gpg_error_t err = 0;
  int keyno;
  struct key_attr *key_attr = NULL;

  (void)argstr;

  if (!info)
    return print_help
      ("KEY-ATTR\n\n"
       "Menu to change the key attributes of an OpenPGP card.",
       APP_TYPE_OPENPGP, 0);

  if (info->apptype != APP_TYPE_OPENPGP)
    {
      log_info ("Note: This is an OpenPGP only command.\n");
      return gpg_error (GPG_ERR_NOT_SUPPORTED);
    }

  if (!(info->is_v2 && info->extcap.aac))
    {
      log_error (_("This command is not supported by this card\n"));
      err = gpg_error (GPG_ERR_NOT_SUPPORTED);
      goto leave;
    }

  for (keyno = 0; keyno < DIM (info->key_attr); keyno++)
    {
      xfree (key_attr);
      key_attr = NULL;
      err = ask_card_keyattr (keyno, &info->key_attr[keyno], &key_attr);
      if (err)
        goto leave;

      err = do_change_keyattr (keyno, key_attr);
      if (err)
        {
          /* Error: Better read the default key attribute again.  */
          log_debug ("FIXME\n");
          /* Ask again for this key. */
          keyno--;
        }
    }

 leave:
  xfree (key_attr);
  return err;
}


static gpg_error_t
cmd_uif (card_info_t info, char *argstr)
{
  gpg_error_t err;
  int keyno;

  if (!info)
    return print_help
      ("UIF N [on|off|permanent]\n\n"
       "Change the User Interaction Flag.  N must in the range 1 to 3.",
       APP_TYPE_OPENPGP, APP_TYPE_PIV, 0);

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


  err = GPG_ERR_NOT_IMPLEMENTED;

 leave:
  return err;
}



/* Data used by the command parser.  This needs to be outside of the
 * function scope to allow readline based command completion.  */
enum cmdids
  {
    cmdNOP = 0,
    cmdQUIT, cmdADMIN, cmdHELP, cmdLIST, cmdRESET, cmdVERIFY,
    cmdNAME, cmdURL, cmdFETCH, cmdLOGIN, cmdLANG, cmdSALUT, cmdCAFPR,
    cmdFORCESIG, cmdGENERATE, cmdPASSWD, cmdPRIVATEDO, cmdWRITECERT,
    cmdREADCERT, cmdUNBLOCK, cmdFACTORYRESET, cmdKDFSETUP,
    cmdKEYATTR, cmdUIF, cmdAUTHENTICATE,
    cmdINVCMD
  };

static struct
{
  const char *name;
  enum cmdids id;
  int admin_only;
  const char *desc;
} cmds[] = {
  { "quit"    , cmdQUIT  , 0, N_("quit this menu")},
  { "q"       , cmdQUIT  , 0, NULL },
  { "admin"   , cmdADMIN , 0, N_("show admin commands")},
  { "help"    , cmdHELP  , 0, N_("show this help")},
  { "?"       , cmdHELP  , 0, NULL },
  { "list"    , cmdLIST  , 0, N_("list all available data")},
  { "l"       , cmdLIST  , 0, NULL },
  { "name"    , cmdNAME  , 1, N_("change card holder's name")},
  { "url"     , cmdURL   , 1, N_("change URL to retrieve key")},
  { "fetch"   , cmdFETCH , 0, N_("fetch the key specified in the card URL")},
  { "login"   , cmdLOGIN , 1, N_("change the login name")},
  { "lang"    , cmdLANG  , 1, N_("change the language preferences")},
  { "salutation",cmdSALUT, 1, N_("change card holder's salutation")},
  { "salut"   , cmdSALUT,  1, NULL },
  { "cafpr"   , cmdCAFPR , 1, N_("change a CA fingerprint")},
  { "forcesig", cmdFORCESIG, 1, N_("toggle the signature force PIN flag")},
  { "generate", cmdGENERATE, 1, N_("generate new keys")},
  { "passwd"  , cmdPASSWD, 0, N_("menu to change or unblock the PIN")},
  { "verify"  , cmdVERIFY, 0, N_("verify the PIN and list all data")},
  { "unblock" , cmdUNBLOCK,0, N_("unblock the PIN using a Reset Code")},
  { "authenticate",cmdAUTHENTICATE, 0,N_("authenticate to the card")},
  { "auth"    , cmdAUTHENTICATE, 0, NULL },
  { "reset"   , cmdRESET,  0, N_("send a reset to the card daemon")},
  { "factory-reset", cmdFACTORYRESET, 1, N_("destroy all keys and data")},
  { "kdf-setup", cmdKDFSETUP, 1, N_("setup KDF for PIN authentication")},
  { "key-attr", cmdKEYATTR, 1, N_("change the key attribute")},
  { "uif", cmdUIF, 1, N_("change the User Interaction Flag")},
  /* Note, that we do not announce these command yet. */
  { "privatedo", cmdPRIVATEDO, 0, N_("change a private data object")},
  { "readcert",  cmdREADCERT,  0, N_("read a certificate from a data object")},
  { "writecert", cmdWRITECERT, 1, N_("store a certificate to a data object")},
  { NULL, cmdINVCMD, 0, NULL }
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
      err = scd_learn (info);
      if (err)
        {
          log_error ("Error reading card: %s\n", gpg_strerror (err));
          goto leave;
        }
    }

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

    case cmdLIST:
      if (!info)
        print_help ("LIST\n\n"
                    "Show content of the card.", 0);
      else
        {
          err = scd_learn (info);
          if (err)
            log_error ("Error reading card: %s\n", gpg_strerror (err));
          else
            list_card (info);
        }
      break;

    case cmdRESET:
      if (!info)
        print_help ("RESET\n\n"
                    "Send a RESET to the card daemon.", 0);
      else
        {
          flush_keyblock_cache ();
          err = scd_apdu (NULL, NULL);
        }
      break;

    case cmdADMIN:
      /* This is a NOP in non-interactive mode.  */
      break;

    case cmdVERIFY:       err = cmd_verify (info, argstr); break;
    case cmdAUTHENTICATE: err = cmd_authenticate (info, argstr); break;
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
    case cmdFORCESIG:     err = cmd_forcesig (info); break;
    case cmdGENERATE:     err = cmd_generate (info, argstr); break;
    case cmdPASSWD:       err = cmd_passwd (info, 1, argstr); break;
    case cmdUNBLOCK:      err = cmd_unblock (info); break;
    case cmdFACTORYRESET: err = cmd_factoryreset (info); break;
    case cmdKDFSETUP:     err = cmd_kdfsetup (info, argstr); break;
    case cmdKEYATTR:      err = cmd_keyattr (info, argstr); break;
    case cmdUIF:          err = cmd_uif (info, argstr); break;

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
  if (err && gpg_err_code (err) != GPG_ERR_EOF)
    {
      if (ignore_error)
        {
          log_info ("Command '%s' failed: %s\n", command, gpg_strerror (err));
          err = 0;
        }
      else
        log_error ("Command '%s' failed: %s\n", command, gpg_strerror (err));
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
  int cmd_admin_only;          /* The command is an admin only command.  */
  char *argstr;                /* The argument as a string.  */
  int redisplay = 1;           /* Whether to redisplay the main info.  */
  int allow_admin = 0;         /* Whether admin commands are allowed.  */
  char *help_arg = NULL;       /* Argument of the HELP command.         */
  struct card_info_s info_buffer = { 0 };
  card_info_t info = &info_buffer;
  char *p;
  int i;

  /* In the interactive mode we do not want to print the program prefix.  */
  log_set_prefix (NULL, 0);

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
          err = scd_learn (info);
          if (err)
            {
              log_error ("Error reading card: %s\n", gpg_strerror (err));
            }
          else
            {
              list_card (info);
              tty_printf("\n");
              redisplay = 0;
            }
	}

      if (!info)
        {
          /* Copy the pending help arg into our answer.  Noe that
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
      cmd_admin_only = 0;
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
          cmd_admin_only = cmds[i].admin_only;
        }

      /* Make sure we have valid strings for the args.  They are
       * allowed to be modified and must thus point to a buffer.  */
      if (!argstr)
        argstr = answer + strlen (answer);

      if (!(cmd == cmdNOP || cmd == cmdQUIT || cmd == cmdHELP
            || cmd == cmdINVCMD))
        {
          /* If redisplay is set we know that there was an error reading
           * the card.  In this case we force a LIST command to retry.  */
          if (!info)
            ; /* In help mode.  */
          else if (redisplay)
            {
              cmd = cmdLIST;
              cmd_admin_only = 0;
            }
          else if (!info->serialno)
            {
              /* Without a serial number most commands won't work.
               * Catch it here.  */
              tty_printf ("\n");
              tty_printf ("Serial number missing\n");
              continue;
            }
          else if (!allow_admin && cmd_admin_only)
            {
              tty_printf ("\n");
              tty_printf (_("Admin-only command\n"));
              continue;
            }
        }

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
                if(cmds[i].desc
                   && (!cmds[i].admin_only
                       || (cmds[i].admin_only && allow_admin)))
                  tty_printf("%-14s %s\n", cmds[i].name, _(cmds[i].desc) );
            }
          break;

        case cmdLIST:
          if (!info)
            print_help ("LIST\n\n"
                        "Show content of the card.", 0);
          else
            {
              /* Actual work is done by the redisplay code block.  */
              redisplay = 1;
            }
          break;

        case cmdRESET:
          if (!info)
            print_help ("RESET\n\n"
                        "Send a RESET to the card daemon.", 0);
          else
            {
              flush_keyblock_cache ();
              err = scd_apdu (NULL, NULL);
            }
          break;

	case cmdADMIN:
          if ( !strcmp (argstr, "on") )
            allow_admin = 1;
          else if ( !strcmp (argstr, "off") )
            allow_admin = 0;
          else if ( !strcmp (argstr, "verify") )
            {
              /* Force verification of the Admin Command.  However,
                 this is only done if the retry counter is at initial
                 state.  */
              /* FIXME: Must depend on the type of the card.  */
              /* char *tmp = xmalloc (strlen (serialnobuf) + 6 + 1); */
              /* strcpy (stpcpy (tmp, serialnobuf), "[CHV3]"); */
              /* allow_admin = !agent_scd_checkpin (tmp); */
              /* xfree (tmp); */
            }
          else /* Toggle. */
            allow_admin=!allow_admin;
	  if(allow_admin)
	    tty_printf(_("Admin commands are allowed\n"));
	  else
	    tty_printf(_("Admin commands are not allowed\n"));
	  break;

        case cmdVERIFY:
          err = cmd_verify (info, argstr);
          if (!err)
            redisplay = 1;
          break;
        case cmdAUTHENTICATE: err = cmd_authenticate (info, argstr); break;
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
        case cmdFORCESIG:  err = cmd_forcesig (info); break;
        case cmdGENERATE:  err = cmd_generate (info, argstr); break;
        case cmdPASSWD:    err = cmd_passwd (info, allow_admin, argstr); break;
        case cmdUNBLOCK:   err = cmd_unblock (info); break;
        case cmdFACTORYRESET:
          err = cmd_factoryreset (info);
          if (!err)
            redisplay = 1;
          break;
        case cmdKDFSETUP:  err = cmd_kdfsetup (info, argstr); break;
        case cmdKEYATTR:   err = cmd_keyattr (info, argstr); break;
        case cmdUIF:       err = cmd_uif (info, argstr); break;

        case cmdINVCMD:
        default:
          tty_printf ("\n");
          tty_printf (_("Invalid command  (try \"help\")\n"));
          break;
        } /* End command switch. */

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
          log_error ("Command '%s' failed: %s\n", s, gpg_strerror (err));
        }

    } /* End of main menu loop. */

 leave:
  release_card_info (info);
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
