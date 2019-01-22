/* gpg-card-tool.c - An interactive tool to work with cards.
 * Copyright (C) 2019 g10 Code GmbH Werner Koch
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
 * SPDX-License-Identifier: GPL-3.0+
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

#define CONTROL_D ('D' - 'A' + 1)

/* Constants to identify the commands and options. */
enum cmd_and_opt_values
  {
    aNull = 0,

    oQuiet      = 'q',
    oVerbose	= 'v',

    oDebug      = 500,

    oGpgProgram,
    oGpgsmProgram,
    oStatusFD,
    oWithColons,

    oDummy
  };


/* The list of commands and options. */
static ARGPARSE_OPTS opts[] = {
  ARGPARSE_group (300, ("@Commands:\n ")),

  ARGPARSE_group (301, ("@\nOptions:\n ")),

  ARGPARSE_s_n (oVerbose, "verbose", ("verbose")),
  ARGPARSE_s_n (oQuiet,	"quiet",  ("be somewhat more quiet")),
  ARGPARSE_s_s (oDebug, "debug", "@"),
  ARGPARSE_s_s (oGpgProgram, "gpg", "@"),
  ARGPARSE_s_s (oGpgsmProgram, "gpgsm", "@"),
  ARGPARSE_s_i (oStatusFD, "status-fd", N_("|FD|write status info to this FD")),
  ARGPARSE_s_n (oWithColons, "with-colons", "@"),

  ARGPARSE_end ()
};

/* Debug values and macros.  */
#define DBG_IPC_VALUE      1024 /* Debug assuan communication.  */
#define DBG_EXTPROG_VALUE 16384 /* debug external program calls */


/* The list of supported debug flags.  */
static struct debug_flags_s debug_flags [] =
  {
    { DBG_IPC_VALUE    , "ipc"     },
    { DBG_EXTPROG_VALUE, "extprog" },
    { 0, NULL }
  };



/* We keep all global options in the structure OPT.  */
struct
{
  int verbose;
  unsigned int debug;
  int quiet;
  int with_colons;
  const char *gpg_program;
  const char *gpgsm_program;
} opt;


static void wrong_args (const char *text) GPGRT_ATTR_NORETURN;
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
      p = ("Usage: gpg-card-tool [command] [options] [args] (-h for help)");
      break;
    case 41:
      p = ("Syntax: gpg-card-tool [command] [options] [args]\n"
           "Tool to configure cards and tokens\n");
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
        case oGpgsmProgram:
          opt.gpgsm_program = pargs->r.ret_str;
          break;
        case oStatusFD:
          gnupg_set_status_fd (translate_sys2libc_fd_int (pargs->r.ret_int, 1));
          break;
        case oWithColons:
          opt.with_colons = 1;
          break;

        default: pargs->err = 2; break;
	}
    }

  return cmd;
}



/* gpg-card-tool main. */
int
main (int argc, char **argv)
{
  gpg_error_t err;
  ARGPARSE_ARGS pargs;
  enum cmd_and_opt_values cmd;

  gnupg_reopen_std ("gpg-card-tool");
  set_strusage (my_strusage);
  gnupg_rl_initialize ();
  log_set_prefix ("gpg-card-tool", GPGRT_LOG_WITH_PREFIX);

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
  if (!opt.gpgsm_program)
    opt.gpgsm_program = gnupg_module_name (GNUPG_MODULE_NAME_GPGSM);

  /* Run the selected command.  */
  switch (cmd)
    {
    default:
      interactive_loop ();
      err = 0;
      break;
    }

  if (err)
    gnupg_status_printf (STATUS_FAILURE, "- %u", err);
  else if (log_get_errorcount (0))
    gnupg_status_printf (STATUS_FAILURE, "- %u", GPG_ERR_GENERAL);
  else
    gnupg_status_printf (STATUS_SUCCESS, NULL);
  return log_get_errorcount (0)? 1:0;
}



/* Print all available information about the current card. */
static void
print_card_status (char *serialno, size_t serialnobuflen)
{
  /* struct agent_card_info_s info; */
  /* PKT_public_key *pk = xcalloc (1, sizeof *pk); */
  /* kbnode_t keyblock = NULL; */
  /* int rc; */
  /* unsigned int uval; */
  /* const unsigned char *thefpr; */
  /* unsigned int thefprlen; */
  /* int i; */

  /* if (serialno && serialnobuflen) */
  /*   *serialno = 0; */

  /* rc = agent_scd_learn (&info, 0); */
  /* if (rc) */
  /*   { */
  /*     if (opt.with_colons) */
  /*       es_fputs ("AID:::\n", fp); */
  /*     log_error (_("OpenPGP card not available: %s\n"), gpg_strerror (rc)); */
  /*     xfree (pk); */
  /*     return; */
  /*   } */

  /* if (opt.with_colons) */
  /*   es_fprintf (fp, "Reader:%s:", info.reader? info.reader : ""); */
  /* else */
  /*   tty_fprintf (fp, "Reader ...........: %s\n", */
  /*                info.reader? info.reader : "[none]"); */
  /* if (opt.with_colons) */
  /*   es_fprintf (fp, "AID:%s:", info.serialno? info.serialno : ""); */
  /* else */
  /*   tty_fprintf (fp, "Application ID ...: %s\n", */
  /*                info.serialno? info.serialno : "[none]"); */
  /* if (!info.serialno || strncmp (info.serialno, "D27600012401", 12) */
  /*     || strlen (info.serialno) != 32 ) */
  /*   { */
  /*     if (info.apptype && !strcmp (info.apptype, "NKS")) */
  /*       { */
  /*         if (opt.with_colons) */
  /*           es_fputs ("netkey-card:\n", fp); */
  /*         log_info ("this is a NetKey card\n"); */
  /*       } */
  /*     else if (info.apptype && !strcmp (info.apptype, "DINSIG")) */
  /*       { */
  /*         if (opt.with_colons) */
  /*           es_fputs ("dinsig-card:\n", fp); */
  /*         log_info ("this is a DINSIG compliant card\n"); */
  /*       } */
  /*     else if (info.apptype && !strcmp (info.apptype, "P15")) */
  /*       { */
  /*         if (opt.with_colons) */
  /*           es_fputs ("pkcs15-card:\n", fp); */
  /*         log_info ("this is a PKCS#15 compliant card\n"); */
  /*       } */
  /*     else if (info.apptype && !strcmp (info.apptype, "GELDKARTE")) */
  /*       { */
  /*         if (opt.with_colons) */
  /*           es_fputs ("geldkarte-card:\n", fp); */
  /*         log_info ("this is a Geldkarte compliant card\n"); */
  /*       } */
  /*     else */
  /*       { */
  /*         if (opt.with_colons) */
  /*           es_fputs ("unknown:\n", fp); */
  /*       } */
  /*     log_info ("not an OpenPGP card\n"); */
  /*     agent_release_card_info (&info); */
  /*     xfree (pk); */
  /*     return; */
  /*   } */

  /* if (!serialno) */
  /*   ; */
  /* else if (strlen (info.serialno)+1 > serialnobuflen) */
  /*   log_error ("serial number longer than expected\n"); */
  /* else */
  /*   strcpy (serialno, info.serialno); */

  /* if (opt.with_colons) */
  /*   es_fputs ("openpgp-card:\n", fp); */


  /*     tty_fprintf (fp, "Version ..........: %.1s%c.%.1s%c\n", */
  /*                  info.serialno[12] == '0'?"":info.serialno+12, */
  /*                  info.serialno[13], */
  /*                  info.serialno[14] == '0'?"":info.serialno+14, */
  /*                  info.serialno[15]); */
  /*     tty_fprintf (fp, "Manufacturer .....: %s\n", */
  /*                  get_manufacturer (xtoi_2(info.serialno+16)*256 */
  /*                                    + xtoi_2 (info.serialno+18))); */
  /*     tty_fprintf (fp, "Serial number ....: %.8s\n", info.serialno+20); */

  /*     print_isoname (fp, "Name of cardholder: ", "name", info.disp_name); */
  /*     print_name (fp, "Language prefs ...: ", info.disp_lang); */
  /*     tty_fprintf (fp, "Salutation .......: %s\n", */
  /*                  info.disp_sex == 1? _("Mr."): */
  /*                  info.disp_sex == 2? _("Mrs.") : ""); */
  /*     print_name (fp, "URL of public key : ", info.pubkey_url); */
  /*     print_name (fp, "Login data .......: ", info.login_data); */
  /*     if (info.private_do[0]) */
  /*       print_name (fp, "Private DO 1 .....: ", info.private_do[0]); */
  /*     if (info.private_do[1]) */
  /*       print_name (fp, "Private DO 2 .....: ", info.private_do[1]); */
  /*     if (info.private_do[2]) */
  /*       print_name (fp, "Private DO 3 .....: ", info.private_do[2]); */
  /*     if (info.private_do[3]) */
  /*       print_name (fp, "Private DO 4 .....: ", info.private_do[3]); */
  /*     if (info.cafpr1len) */
  /*       { */
  /*         tty_fprintf (fp, "CA fingerprint %d .:", 1); */
  /*         print_shax_fpr (fp, info.cafpr1, info.cafpr1len); */
  /*       } */
  /*     if (info.cafpr2len) */
  /*       { */
  /*         tty_fprintf (fp, "CA fingerprint %d .:", 2); */
  /*         print_shax_fpr (fp, info.cafpr2, info.cafpr2len); */
  /*       } */
  /*     if (info.cafpr3len) */
  /*       { */
  /*         tty_fprintf (fp, "CA fingerprint %d .:", 3); */
  /*         print_shax_fpr (fp, info.cafpr3, info.cafpr3len); */
  /*       } */
  /*     tty_fprintf (fp,    "Signature PIN ....: %s\n", */
  /*                  info.chv1_cached? _("not forced"): _("forced")); */
  /*     if (info.key_attr[0].algo) */
  /*       { */
  /*         tty_fprintf (fp,    "Key attributes ...:"); */
  /*         for (i=0; i < DIM (info.key_attr); i++) */
  /*           if (info.key_attr[i].algo == PUBKEY_ALGO_RSA) */
  /*             tty_fprintf (fp, " rsa%u", info.key_attr[i].nbits); */
  /*           else if (info.key_attr[i].algo == PUBKEY_ALGO_ECDH */
  /*                    || info.key_attr[i].algo == PUBKEY_ALGO_ECDSA */
  /*                    || info.key_attr[i].algo == PUBKEY_ALGO_EDDSA) */
  /*             { */
  /*               const char *curve_for_print = "?"; */

  /*               if (info.key_attr[i].curve) */
  /*                 { */
  /*                   const char *oid; */
  /*                   oid = openpgp_curve_to_oid (info.key_attr[i].curve, NULL); */
  /*                   if (oid) */
  /*                     curve_for_print = openpgp_oid_to_curve (oid, 0); */
  /*                 } */
  /*               tty_fprintf (fp, " %s", curve_for_print); */
  /*             } */
  /*         tty_fprintf (fp, "\n"); */
  /*       } */
  /*     tty_fprintf (fp,    "Max. PIN lengths .: %d %d %d\n", */
  /*                  info.chvmaxlen[0], info.chvmaxlen[1], info.chvmaxlen[2]); */
  /*     tty_fprintf (fp,    "PIN retry counter : %d %d %d\n", */
  /*                  info.chvretry[0], info.chvretry[1], info.chvretry[2]); */
  /*     tty_fprintf (fp,    "Signature counter : %lu\n", info.sig_counter); */
  /*     if (info.extcap.kdf) */
  /*       { */
  /*         tty_fprintf (fp, "KDF setting ......: %s\n", */
  /*                      info.kdf_do_enabled ? "on" : "off"); */
  /*       } */
  /*     if (info.extcap.bt) */
  /*       { */
  /*         tty_fprintf (fp, "UIF setting ......: Sign=%s Decrypt=%s Auth=%s\n", */
  /*                      info.uif[0] ? "on" : "off", info.uif[1] ? "on" : "off", */
  /*                      info.uif[2] ? "on" : "off"); */
  /*       } */
  /*     tty_fprintf (fp, "Signature key ....:"); */
  /*     print_shax_fpr (fp, info.fpr1len? info.fpr1:NULL, info.fpr1len); */
  /*     if (info.fpr1len && info.fpr1time) */
  /*       { */
  /*         tty_fprintf (fp, "      created ....: %s\n", */
  /*                      isotimestamp (info.fpr1time)); */
  /*         print_keygrip (fp, info.grp1); */
  /*       } */
  /*     tty_fprintf (fp, "Encryption key....:"); */
  /*     print_shax_fpr (fp, info.fpr2len? info.fpr2:NULL, info.fpr2len); */
  /*     if (info.fpr2len && info.fpr2time) */
  /*       { */
  /*         tty_fprintf (fp, "      created ....: %s\n", */
  /*                      isotimestamp (info.fpr2time)); */
  /*         print_keygrip (fp, info.grp2); */
  /*       } */
  /*     tty_fprintf (fp, "Authentication key:"); */
  /*     print_shax_fpr (fp, info.fpr3len? info.fpr3:NULL, info.fpr3len); */
  /*     if (info.fpr3len && info.fpr3time) */
  /*       { */
  /*         tty_fprintf (fp, "      created ....: %s\n", */
  /*                      isotimestamp (info.fpr3time)); */
  /*         print_keygrip (fp, info.grp3); */
  /*       } */
  /*     tty_fprintf (fp, "General key info..: "); */

  /*     thefpr = (info.fpr1len? info.fpr1 : info.fpr2len? info.fpr2 : */
  /*               info.fpr3len? info.fpr3 : NULL); */
  /*     thefprlen = (info.fpr1len? info.fpr1len : info.fpr2len? info.fpr2len : */
  /*                  info.fpr3len? info.fpr3len : 0); */
  /*     /\* If the fingerprint is all 0xff, the key has no associated */
  /*        OpenPGP certificate.  *\/ */
  /*     if ( thefpr && !fpr_is_ff (thefpr, thefprlen) */
  /*          && !get_pubkey_byfprint (ctrl, pk, &keyblock, thefpr, thefprlen)) */
  /*       { */
  /*         print_pubkey_info (ctrl, fp, pk); */
  /*         if (keyblock) */
  /*           print_card_key_info (fp, keyblock); */
  /*       } */
  /*     else */
  /*       tty_fprintf (fp, "[none]\n"); */

  /* release_kbnode (keyblock); */
  /* free_public_key (pk); */
  /* agent_release_card_info (&info); */
}



static void
cmd_verify (void)
{
  /* agent_scd_checkpin (serialnobuf); */
}


static void
cmd_name (void)
{
  /* change_name (); */
}


static void
cmd_url (void)
{
  /* change_url (); */
}


static void
cmd_fetch (void)
{
  /* fetch_url (); */
}


static void
cmd_login (char *arg_string)
{
  /* change_login (arg_string); */
}


static void
cmd_lang (void)
{
  /* change_lang (); */
}


static void
cmd_salut (void)
{
  /* change_salut (); */
}


static void
cmd_cafpr (int arg_number)
{
  if ( arg_number < 1 || arg_number > 3 )
    tty_printf ("usage: cafpr N\n"
                "       1 <= N <= 3\n");
  /* else */
  /*   change_cafpr (arg_number); */
}


static void
cmd_privatedo (int arg_number, char *arg_string)
{
  if ( arg_number < 1 || arg_number > 4 )
    tty_printf ("usage: privatedo N\n"
                "       1 <= N <= 4\n");
  /* else */
  /*   change_private_do (arg_string, arg_number); */
}


static void
cmd_writecert (int arg_number, char *arg_rest)
{
  if ( arg_number != 3 )
    tty_printf ("usage: writecert 3 < FILE\n");
  /* else */
  /*   change_cert (arg_rest); */
}


static void
cmd_readcert (int arg_number, char *arg_rest)
{
  if ( arg_number != 3 )
    tty_printf ("usage: readcert 3 > FILE\n");
  /* else */
  /*   read_cert (arg_rest); */
}


static void
cmd_forcesig (void)
{
  /* toggle_forcesig (); */
}


static void
cmd_generate (void)
{
  /* generate_card_keys (); */
}


static void
cmd_passwd (int allow_admin)
{
  /* change_pin (0, allow_admin); */
}


static void
cmd_unblock (int allow_admin)
{
  /* change_pin (1, allow_admin); */
}


static void
cmd_factoryreset (void)
{
  /* factory_reset (); */
}


static void
cmd_kdfsetup (char *argstring)
{
  /* kdf_setup (arg_string); */
}


static void
cmd_keyattr (void)
{
  /* key_attr (); */
}


static void
cmd_uif (int arg_number, char *arg_rest)
{
  if ( arg_number < 1 || arg_number > 3 )
    tty_printf ("usage: uif N [on|off|permanent]\n"
                "       1 <= N <= 3\n");
  /* else */
  /*   uif (arg_number, arg_rest); */
}



/* Data used by the command parser.  This needs to be outside of the
 * function scope to allow readline based command completion.  */
enum cmdids
  {
    cmdNOP = 0,
    cmdQUIT, cmdADMIN, cmdHELP, cmdLIST, cmdDEBUG, cmdVERIFY,
    cmdNAME, cmdURL, cmdFETCH, cmdLOGIN, cmdLANG, cmdSALUT, cmdCAFPR,
    cmdFORCESIG, cmdGENERATE, cmdPASSWD, cmdPRIVATEDO, cmdWRITECERT,
    cmdREADCERT, cmdUNBLOCK, cmdFACTORYRESET, cmdKDFSETUP,
    cmdKEYATTR, cmdUIF,
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
  { "debug"   , cmdDEBUG , 0, NULL },
  { "name"    , cmdNAME  , 1, N_("change card holder's name")},
  { "url"     , cmdURL   , 1, N_("change URL to retrieve key")},
  { "fetch"   , cmdFETCH , 0, N_("fetch the key specified in the card URL")},
  { "login"   , cmdLOGIN , 1, N_("change the login name")},
  { "lang"    , cmdLANG  , 1, N_("change the language preferences")},
  { "salutation",cmdSALUT, 1, N_("change card holder's salutation")},
  { "cafpr"   , cmdCAFPR , 1, N_("change a CA fingerprint")},
  { "forcesig", cmdFORCESIG, 1, N_("toggle the signature force PIN flag")},
  { "generate", cmdGENERATE, 1, N_("generate new keys")},
  { "passwd"  , cmdPASSWD, 0, N_("menu to change or unblock the PIN")},
  { "verify"  , cmdVERIFY, 0, N_("verify the PIN and list all data")},
  { "unblock" , cmdUNBLOCK,0, N_("unblock the PIN using a Reset Code")},
  { "factory-reset", cmdFACTORYRESET, 1, N_("destroy all keys and data")},
  { "kdf-setup", cmdKDFSETUP, 1, N_("setup KDF for PIN authentication")},
  { "key-attr", cmdKEYATTR, 1, N_("change the key attribute")},
  { "uif", cmdUIF, 1, N_("change the User Interaction Flag")},
  /* Note, that we do not announce these command yet. */
  { "privatedo", cmdPRIVATEDO, 0, NULL },
  { "readcert", cmdREADCERT, 0, NULL },
  { "writecert", cmdWRITECERT, 1, NULL },
  { NULL, cmdINVCMD, 0, NULL }
};


/* The main loop.  */
static void
interactive_loop (void)
{
  char *answer = NULL;         /* The input line.  */
  enum cmdids cmd = cmdNOP;    /* The command.  */
  int cmd_admin_only;          /* The command is an admin only command.  */
  int arg_number;              /* The first argument as a number.  */
  char *arg_string = "";       /* The first argument as a string.  */
  char *arg_rest = "";         /* The remaining arguments.  */
  int redisplay = 1;           /* Whether to redisplay the main info.  */
  int allow_admin = 0;         /* Whether admin commands are allowed.  */
  char serialnobuf[50];
  char *p;
  int i;

  for (;;)
    {

      tty_printf ("\n");
      if (redisplay)
        {
          print_card_status (serialnobuf, DIM (serialnobuf));
          tty_printf("\n");
          redisplay = 0;
	}

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

      arg_number = 0;
      cmd_admin_only = 0;
      if (!*answer)
        cmd = cmdLIST; /* We default to the list command */
      else if (*answer == CONTROL_D)
        cmd = cmdQUIT;
      else
        {
          if ((p=strchr (answer,' ')))
            {
              *p++ = 0;
              trim_spaces (answer);
              trim_spaces (p);
              arg_number = atoi (p);
              arg_string = p;
              arg_rest = p;
              while (digitp (arg_rest))
                arg_rest++;
              while (spacep (arg_rest))
                arg_rest++;
            }

          for (i=0; cmds[i].name; i++ )
            if (!ascii_strcasecmp (answer, cmds[i].name ))
              break;

          cmd = cmds[i].id;
          cmd_admin_only = cmds[i].admin_only;
        }

      if (!allow_admin && cmd_admin_only)
	{
          tty_printf ("\n");
          tty_printf (_("Admin-only command\n"));
          continue;
        }

      switch (cmd)
        {
        case cmdNOP:
          break;

        case cmdQUIT:
          goto leave;

        case cmdHELP:
          for (i=0; cmds[i].name; i++ )
            if(cmds[i].desc
	       && (!cmds[i].admin_only || (cmds[i].admin_only && allow_admin)))
              tty_printf("%-14s %s\n", cmds[i].name, _(cmds[i].desc) );
          break;

	case cmdADMIN:
          if ( !strcmp (arg_string, "on") )
            allow_admin = 1;
          else if ( !strcmp (arg_string, "off") )
            allow_admin = 0;
          else if ( !strcmp (arg_string, "verify") )
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

        case cmdVERIFY:    cmd_verify (); redisplay = 1; break;
        case cmdLIST:                     redisplay = 1; break;
        case cmdNAME:      cmd_name ();   break;
        case cmdURL:       cmd_url ();    break;
	case cmdFETCH:     cmd_fetch ();  break;
        case cmdLOGIN:     cmd_login (arg_string); break;
        case cmdLANG:      cmd_lang ();   break;
        case cmdSALUT:     cmd_salut ();  break;
        case cmdCAFPR:     cmd_cafpr (arg_number); break;
        case cmdPRIVATEDO: cmd_privatedo (arg_number, arg_string); break;
        case cmdWRITECERT: cmd_writecert (arg_number, arg_rest); break;
        case cmdREADCERT:  cmd_readcert (arg_number, arg_rest); break;
        case cmdFORCESIG:  cmd_forcesig (); break;
        case cmdGENERATE:  cmd_generate (); break;
        case cmdPASSWD:    cmd_passwd (allow_admin); break;
        case cmdUNBLOCK:   cmd_unblock (allow_admin); break;
        case cmdFACTORYRESET: cmd_factoryreset (); break;
        case cmdKDFSETUP:  cmd_kdfsetup (arg_string); break;
        case cmdKEYATTR:   cmd_keyattr (); break;
        case cmdUIF:       cmd_uif (arg_number, arg_rest); break;

        case cmdINVCMD:
        default:
          tty_printf ("\n");
          tty_printf (_("Invalid command  (try \"help\")\n"));
          break;
        } /* End command switch. */
    } /* End of main menu loop. */

 leave:
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
   * If not, just do nothing for now. */
  if (!start)
    return rl_completion_matches (text, command_generator);

  rl_attempted_completion_over = 1;

  return NULL;
}
#endif /*HAVE_LIBREADLINE*/
