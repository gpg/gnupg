/* gpg-pair-tool.c - The tool to run the pairing protocol.
 * Copyright (C) 2018 g10 Code GmbH
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

/* Protocol:
 *
 *    Initiator             Responder
 *       |                     |
 *       |    COMMIT           |
 *       |-------------------->|
 *       |                     |
 *       |    DHPART1          |
 *       |<--------------------|
 *       |                     |
 *       |    DHPART2          |
 *       |-------------------->|
 *       |                     |
 *       |    CONFIRM          |
 *       |<--------------------|
 *       |                     |
 *
 * The initiator creates a keypair (PKi,SKi) and sends this COMMIT
 * message to the responder:
 *
 *   7 byte Magic, value: "GPG-pa1"
 *   1 byte MessageType, value 1 (COMMIT)
 *   8 byte SessionId, value: 8 random bytes
 *   1 byte Realm, value 1
 *   2 byte reserved, value 0
 *   5 byte ExpireTime, value: seconds since Epoch as an unsigned int.
 *  32 byte Hash(PKi)
 *
 * The initiator also needs to locally store the sessionid, the realm,
 * the expiration time, the keypair and a hash of the entire message
 * sent.
 *
 * The responder checks that the received message has not expired and
 * stores sessionid, realm, expiretime and the Hash(PKi).  The
 * Responder then creates and locally stores its own keypair (PKr,SKr)
 * and sends the DHPART1 message back:
 *
 *   7 byte Magic, value: "GPG-pa1"
 *   1 byte MessageType, value 2 (DHPART1)
 *   8 byte SessionId from COMMIT message
 *  32 byte PKr
 *  32 byte Hash(Hash(COMMIT) || DHPART1[0..47])
 *
 * Note that Hash(COMMIT) is the hash over the entire received COMMIT
 * message.  DHPART1[0..47] are the first 48 bytes of the created
 * DHPART1 message.
 *
 * The Initiator receives the DHPART1 message and checks that the hash
 * matches.  Although this hash is easily malleable it is later in the
 * protocol used to assert the integrity of all messages.  The
 * Initiator then computes the shared master secret from its SKi and
 * the received PKr.  Using this master secret several keys are
 * derived:
 *
 *  - HMACi-key using the label "GPG-pa1-HMACi-key".
 *  - SYMx-key using the label "GPG-pa1-SYMx-key"
 *
 * For details on the KDF see the implementation of the function kdf.
 * The master secret is stored securely in the local state.  The
 * DHPART2 message is then created and send to the Responder:
 *
 *   7 byte Magic, value: "GPG-pa1"
 *   1 byte MessageType, value 3 (DHPART2)
 *   8 byte SessionId from COMMIT message
 *  32 byte PKi
 *  32 byte MAC(HMACi-key, Hash(DHPART1) || DHPART2[0..47] || SYMx-key)
 *
 * The Responder receives the DHPART2 message and checks that the hash
 * of the received PKi matches the Hash(PKi) value as received earlier
 * with the COMMIT message.  The Responder now also computes the
 * shared master secret from its SKr and the received PKi and derives
 * the keys:
 *
 *  - HMACi-key using the label "GPG-pa1-HMACi-key".
 *  - HMACr-key using the label "GPG-pa1-HMACr-key".
 *  - SYMx-key using the label "GPG-pa1-SYMx-key"
 *  - SAS using the label "GPG-pa1-SAS"
 *
 * With these keys the MAC from the received DHPART2 message is
 * checked.  On success a SAS is displayed to the user and a CONFIRM
 * message send back:
 *
 *   7 byte Magic, value: "GPG-pa1"
 *   1 byte MessageType, value 4 (CONFIRM)
 *   8 byte SessionId from COMMIT message
 *  32 byte MAC(HMACr-key, Hash(DHPART2) || CONFIRM[0..15] || SYMx-key)
 *
 * The Initiator receives this CONFIRM message, gets the master shared
 * secret from its local state and derives the keys.  It checks the
 * MAC in the received CONFIRM message and ask the user to enter
 * the SAS as displayed by the responder.  Iff the SAS matches the
 * master key is flagged as confirmed and the Initiator may now use a
 * derived key to send encrypted data to the Responder.
 *
 * In case the Responder also needs to send encrypted data we need to
 * introduce another final message to tell the responder that the
 * Initiator validated the SAS.
 *
 * TODO:  Encrypt the state files using a key stored in gpg-agent's cache.
 *
 */

#include <config.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <dirent.h>
#include <stdarg.h>

#include "../common/util.h"
#include "../common/status.h"
#include "../common/i18n.h"
#include "../common/sysutils.h"
#include "../common/init.h"
#include "../common/name-value.h"

/* Constants to identify the commands and options. */
enum cmd_and_opt_values
  {
    aNull       = 0,

    oQuiet      = 'q',
    oVerbose	= 'v',
    oOutput     = 'o',
    oArmor      = 'a',

    aInitiate   = 400,
    aRespond    = 401,
    aGet        = 402,
    aCleanup    = 403,

    oDebug      = 500,
    oStatusFD,
    oHomedir,
    oSAS,

    oDummy
  };


/* The list of commands and options. */
static gpgrt_opt_t opts[] = {
  ARGPARSE_group (300, ("@Commands:\n ")),

  ARGPARSE_c (aInitiate, "initiate", N_("initiate a pairing request")),
  ARGPARSE_c (aRespond,  "respond", N_("respond to a pairing request")),
  ARGPARSE_c (aGet,      "get",     N_("return the keys")),
  ARGPARSE_c (aCleanup,  "cleanup", N_("remove expired states etc.")),

  ARGPARSE_group (301, ("@\nOptions:\n ")),

  ARGPARSE_s_n (oVerbose, "verbose", N_("verbose")),
  ARGPARSE_s_n (oQuiet,	"quiet", N_("be somewhat more quiet")),
  ARGPARSE_s_n (oArmor, "armor", N_("create ascii armored output")),
  ARGPARSE_s_s (oSAS, "sas", N_("|SAS|the SAS as shown by the peer")),
  ARGPARSE_s_s (oDebug, "debug", "@"),
  ARGPARSE_s_s (oOutput, "output", N_("|FILE|write the request to FILE")),
  ARGPARSE_s_i (oStatusFD, "status-fd", N_("|FD|write status info to this FD")),

  ARGPARSE_s_s (oHomedir, "homedir", "@"),

  ARGPARSE_end ()
};


/* We keep all global options in the structure OPT.  */
static struct
{
  int verbose;
  unsigned int debug;
  int quiet;
  int armor;
  const char *output;
  estream_t statusfp;
  unsigned int ttl;
  const char *sas;
} opt;


/* Debug values and macros.  */
#define DBG_MESSAGE_VALUE     2 /* Debug the messages.  */
#define DBG_CRYPTO_VALUE      4	/* Debug low level crypto.  */
#define DBG_MEMORY_VALUE     32	/* Debug memory allocation stuff.  */

#define DBG_MESSAGE  (opt.debug & DBG_MESSAGE_VALUE)
#define DBG_CRYPTO   (opt.debug & DBG_CRYPTO_VALUE)


/* The list of supported debug flags.  */
static struct debug_flags_s debug_flags [] =
  {
    { DBG_MESSAGE_VALUE, "message"  },
    { DBG_CRYPTO_VALUE , "crypto"  },
    { DBG_MEMORY_VALUE , "memory"  },
    { 0, NULL }
  };


/* The directory name below the cache dir to store paring states.  */
#define PAIRING_STATE_DIR  "state"

/* Message types.  */
#define MSG_TYPE_COMMIT  1
#define MSG_TYPE_DHPART1 2
#define MSG_TYPE_DHPART2 3
#define MSG_TYPE_CONFIRM 4


/* Realm values.  */
#define REALM_STANDARD  1




/* Local prototypes.  */
static void wrong_args (const char *text) GPGRT_ATTR_NORETURN;
static void xnvc_set_printf (nvc_t nvc, const char *name, const char *format,
                             ...) GPGRT_ATTR_PRINTF(3,4);
static void *hash_data (void *result, size_t resultsize,
                        ...) GPGRT_ATTR_SENTINEL(0);
static void *hmac_data (void *result, size_t resultsize,
                        const unsigned char *key, size_t keylen,
                        ...) GPGRT_ATTR_SENTINEL(0);


static gpg_error_t command_initiate (void);
static gpg_error_t command_respond (void);
static gpg_error_t command_cleanup (void);
static gpg_error_t command_get (const char *sessionidstr);




/* Print usage information and provide strings for help. */
static const char *
my_strusage( int level )
{
  const char *p;

  switch (level)
    {
    case 9:  p = "LGPL-2.1-or-later"; break;
    case 11: p = "gpg-pair-tool"; break;
    case 12: p = "@GNUPG@"; break;
    case 13: p = VERSION; break;
    case 14: p = GNUPG_DEF_COPYRIGHT_LINE; break;
    case 17: p = PRINTABLE_OS_NAME; break;
    case 19: p = _("Please report bugs to <@EMAIL@>.\n"); break;

    case 1:
    case 40:
      p = ("Usage: gpg-pair-tool [command] [options] [args] (-h for help)");
      break;
    case 41:
      p = ("Syntax: gpg-pair-tool [command] [options] [args]\n"
           "Client to run the pairing protocol\n");
      break;

    default: p = NULL; break;
    }
  return p;
}


static void
wrong_args (const char *text)
{
  es_fprintf (es_stderr, _("usage: %s [options] %s\n"),
              gpgrt_strusage (11), text);
  exit (2);
}


/* Set the status FD.  */
static void
set_status_fd (int fd)
{
  static int last_fd = -1;

  if (fd != -1 && last_fd == fd)
    return;

  if (opt.statusfp && opt.statusfp != es_stdout && opt.statusfp != es_stderr)
    es_fclose (opt.statusfp);
  opt.statusfp = NULL;
  if (fd == -1)
    return;

  if (fd == 1)
    opt.statusfp = es_stdout;
  else if (fd == 2)
    opt.statusfp = es_stderr;
  else
    opt.statusfp = es_fdopen (fd, "w");
  if (!opt.statusfp)
    {
      log_fatal ("can't open fd %d for status output: %s\n",
                 fd, gpg_strerror (gpg_error_from_syserror ()));
    }
  last_fd = fd;
}


/* Write a status line with code NO followed by the output of the
 * printf style FORMAT.  The caller needs to make sure that LFs and
 * CRs are not printed.  */
static void
write_status (int no, const char *format, ...)
{
  va_list arg_ptr;

  if (!opt.statusfp)
    return;  /* Not enabled.  */

  es_fputs ("[GNUPG:] ", opt.statusfp);
  es_fputs (get_status_string (no), opt.statusfp);
  if (format)
    {
      es_putc (' ', opt.statusfp);
      va_start (arg_ptr, format);
      es_vfprintf (opt.statusfp, format, arg_ptr);
      va_end (arg_ptr);
    }
  es_putc ('\n', opt.statusfp);
}



/* gpg-pair-tool main. */
int
main (int argc, char **argv)
{
  gpg_error_t err;
  gpgrt_argparse_t pargs = { &argc, &argv };
  enum cmd_and_opt_values cmd = 0;

  opt.ttl = 8*3600; /* Default to 8 hours.  */

  gnupg_reopen_std ("gpg-pair-tool");
  gpgrt_set_strusage (my_strusage);
  log_set_prefix ("gpg-pair-tool", GPGRT_LOG_WITH_PREFIX);

  /* Make sure that our subsystems are ready.  */
  i18n_init();
  init_common_subsystems (&argc, &argv);

  /* Parse the command line. */
  while (gpgrt_argparse (NULL, &pargs, opts))
    {
      switch (pargs.r_opt)
        {
	case oQuiet:     opt.quiet = 1; break;
        case oVerbose:   opt.verbose++; break;
        case oArmor:     opt.armor = 1; break;

        case oDebug:
          if (parse_debug_flag (pargs.r.ret_str, &opt.debug, debug_flags))
            {
              pargs.r_opt = ARGPARSE_INVALID_ARG;
              pargs.err   = ARGPARSE_PRINT_ERROR;
            }
          break;

        case oOutput:
          opt.output = pargs.r.ret_str;
          break;

        case oStatusFD:
          set_status_fd (translate_sys2libc_fd_int (pargs.r.ret_int, 1));
          break;

        case oHomedir:
          gnupg_set_homedir (pargs.r.ret_str);
          break;

        case oSAS:
          opt.sas = pargs.r.ret_str;
          break;

	case aInitiate:
	case aRespond:
	case aGet:
	case aCleanup:
          if (cmd && cmd != pargs.r_opt)
            log_error (_("conflicting commands\n"));
          else
            cmd = pargs.r_opt;
          break;

        default: pargs.err = ARGPARSE_PRINT_WARNING; break;
	}
    }
  gpgrt_argparse (NULL, &pargs, NULL);  /* Release internal state.  */

  /* Print a warning if an argument looks like an option.  */
  if (!opt.quiet && !(pargs.flags & ARGPARSE_FLAG_STOP_SEEN))
    {
      int i;

      for (i=0; i < argc; i++)
        if (argv[i][0] == '-' && argv[i][1] == '-')
          log_info (("NOTE: '%s' is not considered an option\n"), argv[i]);
    }
  gpgrt_argparse (NULL, &pargs, NULL);  /* Free internal memory.  */

  if (opt.sas)
    {
      if (strlen (opt.sas) != 11
          || !digitp (opt.sas+0) || !digitp (opt.sas+1) || !digitp (opt.sas+2)
          || opt.sas[3] != '-'
          || !digitp (opt.sas+4) || !digitp (opt.sas+5) || !digitp (opt.sas+6)
          || opt.sas[7] != '-'
          || !digitp (opt.sas+8) || !digitp (opt.sas+9) || !digitp (opt.sas+10))
        log_error ("invalid formatted SAS\n");
    }

  /* Stop if any error, including ARGPARSE_PRINT_WARNING, occurred.  */
  if (log_get_errorcount (0))
    exit (2);

  if (DBG_CRYPTO)
    gcry_control (GCRYCTL_SET_DEBUG_FLAGS, 1|2);


  /* Now run the requested command.  */
  switch (cmd)
    {
    case aInitiate:
      if (argc)
        wrong_args ("--initiate");
      err = command_initiate ();
      break;

    case aRespond:
      if (argc)
        wrong_args ("--respond");
      err = command_respond ();
      break;

    case aGet:
      if (argc > 1)
        wrong_args ("--respond [sessionid]");
      err = command_get (argc? *argv:NULL);
      break;

    case aCleanup:
      if (argc)
        wrong_args ("--cleanup");
      err = command_cleanup ();
      break;

    default:
      gpgrt_usage (1);
      err = 0;
      break;
    }

  if (err)
    write_status (STATUS_FAILURE, "- %u", err);
  else if (log_get_errorcount (0))
    write_status (STATUS_FAILURE, "- %u", GPG_ERR_GENERAL);
  else
    write_status (STATUS_SUCCESS, NULL);
  return log_get_errorcount (0)? 1:0;
}



/* Wrapper around nvc_new which terminates in the error case.  */
static nvc_t
xnvc_new (void)
{
  nvc_t c = nvc_new ();
  if (!c)
    log_fatal ("error creating NVC object: %s\n",
               gpg_strerror (gpg_error_from_syserror ()));
  return c;
}

/* Wrapper around nvc_set which terminates in the error case.  */
static void
xnvc_set (nvc_t nvc, const char *name, const char *value)
{
  gpg_error_t err = nvc_set (nvc, name, value);
  if (err)
    log_fatal ("error updating NVC object: %s\n", gpg_strerror (err));
}

/* Call vnc_set with (BUFFER, BUFLEN) converted to a hex string as
 * value.  Terminates in the error case.  */
static void
xnvc_set_hex (nvc_t nvc, const char *name, const void *buffer, size_t buflen)
{
  char *hex;

  hex = bin2hex (buffer, buflen, NULL);
  if (!hex)
    xoutofcore ();
  strlwr (hex);
  xnvc_set (nvc, name, hex);
  xfree (hex);
}

/* Call nvc_set with a value created from the string generated using
 * the printf style FORMAT.  Terminates in the error case.  */
static void
xnvc_set_printf (nvc_t nvc, const char *name, const char *format, ...)
{
  va_list arg_ptr;
  char *buffer;

  va_start (arg_ptr, format);
  if (gpgrt_vasprintf (&buffer, format, arg_ptr) < 0)
    log_fatal ("estream_asprintf failed: %s\n",
               gpg_strerror (gpg_error_from_syserror ()));
  va_end (arg_ptr);
  xnvc_set (nvc, name, buffer);
  xfree (buffer);
}


/* Return the string for the first entry in NVC with NAME.  If NAME is
 * missing, an empty string is returned.  The returned string is a
 * pointer into NVC.  */
static const char *
xnvc_get_string (nvc_t nvc, const char *name)
{
  nve_t item;

  if (!nvc)
    return "";
  item = nvc_lookup (nvc, name);
  if (!item)
    return "";
  return nve_value (item);
}



/* Return a string for MSGTYPE.  */
const char *
msgtypestr (int msgtype)
{
  switch (msgtype)
    {
    case MSG_TYPE_COMMIT:  return "Commit";
    case MSG_TYPE_DHPART1: return "DHPart1";
    case MSG_TYPE_DHPART2: return "DHPart2";
    case MSG_TYPE_CONFIRM: return "Confirm";
    }
  return "?";
}


/* Private to {get,set}_session_id().  */
static struct {
  int initialized;
  unsigned char sessid[8];
} session_id;


/* Return the 8 octet session.  */
static unsigned char *
get_session_id (void)
{
  if (!session_id.initialized)
    {
      session_id.initialized = 1;
      gcry_create_nonce (session_id.sessid, sizeof session_id.sessid);
    }

  return session_id.sessid;
}

static void
set_session_id (const void *sessid, size_t len)
{
  log_assert (!session_id.initialized);
  if (len > sizeof session_id.sessid)
    len = sizeof session_id.sessid;
  memcpy (session_id.sessid, sessid, len);
  if (len < sizeof session_id.sessid)
    memset (session_id.sessid+len, 0, sizeof session_id.sessid - len);
  session_id.initialized = 1;
}

/* Return a string with the hexified session id.  */
static const char *
get_session_id_hex (void)
{
  static char hexstr[16+1];

  bin2hex (get_session_id (), 8, hexstr);
  strlwr (hexstr);
  return hexstr;
}


/* Return a fixed string with the directory used to store the state of
 * pairings.  On error a diagnostic is printed but the file name is
 * returned anyway.  It is expected that the expected failure of the
 * following open is responsible for error handling.  */
static const char *
get_pairing_statedir (void)
{
  static char *fname;
  gpg_error_t err = 0;
  char *tmpstr;
  struct stat statbuf;

  if (fname)
    return fname;

  fname = make_filename (gnupg_homedir (), GNUPG_CACHE_DIR, NULL);
  if (gnupg_stat (fname, &statbuf) && errno == ENOENT)
    {
      if (gnupg_mkdir (fname, "-rwx"))
        {
          err = gpg_error_from_syserror ();
          log_error (_("can't create directory '%s': %s\n"),
                     fname, gpg_strerror (err) );
        }
      else if (!opt.quiet)
        log_info (_("directory '%s' created\n"), fname);
    }

  tmpstr = make_filename (fname, PAIRING_STATE_DIR, NULL);
  xfree (fname);
  fname = tmpstr;
  if (gnupg_stat (fname, &statbuf) && errno == ENOENT)
    {
      if (gnupg_mkdir (fname, "-rwx"))
        {
          if (!err)
            {
              err = gpg_error_from_syserror ();
              log_error (_("can't create directory '%s': %s\n"),
                         fname, gpg_strerror (err) );
            }
        }
      else if (!opt.quiet)
        log_info (_("directory '%s' created\n"), fname);
    }

  return fname;
}


/* Open the pairing state file.  SESSIONID is a 8 byte buffer with the
 * session-id.  If CREATE_FLAG is set the file is created and will
 * always return a valid stream.  If CREATE_FLAG is not set the file
 * is opened for reading and writing.  If the file does not exist NULL
 * is return; in all other error cases the process is terminated.  If
 * R_FNAME is not NULL the name of the file is stored there and the
 * caller needs to free it.  */
static estream_t
open_pairing_state (const unsigned char *sessionid, int create_flag,
                    char **r_fname)
{
  gpg_error_t err;
  char *fname, *tmpstr;
  estream_t fp;

  /* The filename is the session id with a "pa1" suffix.  Note that
   * the state dir may eventually be used for other purposes as well
   * and thus the suffix identifies that the file belongs to this
   * tool.  We use lowercase file names for no real reason.  */
  tmpstr = bin2hex (sessionid, 8, NULL);
  if (!tmpstr)
    xoutofcore ();
  strlwr (tmpstr);
  fname = xstrconcat (tmpstr, ".pa1", NULL);
  xfree (tmpstr);
  tmpstr = make_filename (get_pairing_statedir (), fname, NULL);
  xfree (fname);
  fname = tmpstr;

  fp = es_fopen (fname, create_flag? "wbx,mode=-rw": "rb+,mode=-rw");
  if (!fp)
    {
      err = gpg_error_from_syserror ();
      if (create_flag)
        {
          /* We should always be able to create a file.  Also we use a
           * 64 bit session id, it is theoretically possible that such
           * a session already exists.  However, that is rare enough
           * and thus the fatal error message should still be  okay.  */
          log_fatal ("can't create '%s': %s\n", fname, gpg_strerror (err));
        }
      else if (gpg_err_code (err) == GPG_ERR_ENOENT)
        {
          /* That is an expected error; return NULL.  */
        }
      else
        {
          log_fatal ("can't open '%s': %s\n", fname, gpg_strerror (err));
        }
    }

  if (r_fname)
    *r_fname = fname;
  else
    xfree (fname);

  return fp;
}


/* Write the state to a possible new state file.  */
static void
write_state (nvc_t state, int create_flag)
{
  gpg_error_t err;
  char *fname = NULL;
  estream_t fp;

  fp = open_pairing_state (get_session_id (), create_flag, &fname);
  log_assert (fp);

  err = nvc_write (state, fp);
  if (err)
    {
      es_fclose  (fp);
      gnupg_remove (fname);
      log_fatal ("error writing '%s': %s\n", fname, gpg_strerror (err));
    }

  /* If we did not create the file, we need to truncate the file.  */
  if (!create_flag && ftruncate (es_fileno (fp), es_ftello (fp)))
    {
      err = gpg_error_from_syserror ();
      log_fatal ("error truncating '%s': %s\n", fname, gpg_strerror (err));
    }
  if (es_ferror (fp) || es_fclose (fp))
    {
      err = gpg_error_from_syserror ();
      es_fclose  (fp);
      gnupg_remove (fname);
      log_fatal ("error writing '%s': %s\n", fname, gpg_strerror (err));
    }
}


/* Read the state into a newly allocated state object and store that
 * at R_STATE. If no state is available GPG_ERR_NOT_FOUND is returned
 * and as with all errors NULL is stored at R_STATE.  SESSIONID is an
 * input with the 8 session id.  */
static gpg_error_t
read_state (nvc_t *r_state)
{
  gpg_error_t err;
  char *fname = NULL;
  estream_t fp;
  nvc_t state = NULL;
  nve_t item;
  const char *value;
  unsigned long expire;

  *r_state = NULL;

  fp = open_pairing_state (get_session_id (), 0, &fname);
  if (!fp)
    return gpg_error (GPG_ERR_NOT_FOUND);

  err = nvc_parse (&state, NULL, fp);
  if (err)
    {
      log_info ("failed to parse state file '%s': %s\n",
                fname, gpg_strerror (err));
      goto leave;
    }

  /* Check whether the state already expired.  */
  item = nvc_lookup (state, "Expires:");
  if (!item)
    {
      log_info ("invalid state file '%s': %s\n",
                fname, "field 'expire' not found");
      goto leave;
    }
  value = nve_value (item);
  if (!value || !(expire = strtoul (value, NULL, 10)))
    {
      log_info ("invalid state file '%s': %s\n",
                fname, "field 'expire' has an invalid value");
      goto leave;
    }
  if (expire <= gnupg_get_time ())
    {
      es_fclose (fp);
      fp = NULL;
      if (gnupg_remove (fname))
        {
          err = gpg_error_from_syserror ();
          log_info ("failed to delete state file '%s': %s\n",
                    fname, gpg_strerror (err));
        }
      else if (opt.verbose)
        log_info ("state file '%s' deleted\n", fname);
      err = gpg_error (GPG_ERR_NOT_FOUND);
      goto leave;
    }

  *r_state = state;
  state = NULL;

 leave:
  nvc_release (state);
  es_fclose (fp);
  return err;
}


/* Send (MSG,MSGLEN) to the output device.  */
static void
send_message (const unsigned char *msg, size_t msglen)
{
  gpg_error_t err;

  if (opt.verbose)
    log_info ("session %s: sending %s message\n",
              get_session_id_hex (), msgtypestr (msg[7]));

  if (DBG_MESSAGE)
    log_printhex (msg, msglen, "send msg(%s):", msgtypestr (msg[7]));

  /* FIXME: For now only stdout.  */
  if (opt.armor)
    {
      gpgrt_b64state_t state;

      state = gpgrt_b64enc_start (es_stdout, "");
      if (!state)
        log_fatal ("error setting up base64 encoder: %s\n",
                   gpg_strerror (gpg_error_from_syserror ()));
      err = gpgrt_b64enc_write (state, msg, msglen);
      if (!err)
        err = gpgrt_b64enc_finish (state);
      if (err)
        log_fatal ("error writing base64 to stdout: %s\n", gpg_strerror (err));
    }
  else
    {
      if (es_fwrite (msg, msglen, 1, es_stdout) != 1)
        log_fatal ("error writing to stdout: %s\n",
                   gpg_strerror (gpg_error_from_syserror ()));
    }
  es_fputc ('\n', es_stdout);
}


/* Read a message from stdin and store it at the address (R_MSG,
 * R_MSGLEN).  This function detects armoring and removes it.  On
 * error NULL is stored at R_MSG, a diagnostic printed and an error
 * code returned.  The returned message has a proper message type and
 * an appropriate length.  The message type is stored at R_MSGTYPE and
 * if a state is available it is stored at R_STATE.  */
static gpg_error_t
read_message (unsigned char **r_msg, size_t *r_msglen, int *r_msgtype,
              nvc_t *r_state)
{
  gpg_error_t err;
  unsigned char msg[128];  /* max msg size is 80 but 107 with base64.  */
  size_t msglen;
  size_t reqlen;

  *r_msg = NULL;
  *r_state = NULL;

  es_setvbuf (es_stdin, NULL, _IONBF, 0);
  es_set_binary (es_stdin);

  if (es_read (es_stdin, msg, sizeof msg, &msglen))
    {
      err = gpg_error_from_syserror ();
      log_error ("error reading from message: %s\n", gpg_strerror (err));
      return err;
    }

  if (msglen > 4 && !memcmp (msg, "R1BH", 4))
    {
      /* This is base64 of the first 3 bytes.  */
      gpgrt_b64state_t state = gpgrt_b64dec_start (NULL);
      if (!state)
        log_fatal ("error setting up base64 decoder: %s\n",
                   gpg_strerror (gpg_error_from_syserror ()));
      err = gpgrt_b64dec_proc (state, msg, msglen, &msglen);
      gpgrt_b64dec_finish (state);
      if (err)
        {
          log_error ("error decoding message: %s\n", gpg_strerror (err));
          return err;
        }
    }

  if (msglen < 16 || memcmp (msg, "GPG-pa1", 7))
    {
      log_error ("error parsing message: %s\n",
                 msglen? "invalid header":"empty message");
      return gpg_error (GPG_ERR_INV_RESPONSE);
    }
  switch (msg[7])
    {
    case MSG_TYPE_COMMIT:  reqlen = 56; break;
    case MSG_TYPE_DHPART1: reqlen = 80; break;
    case MSG_TYPE_DHPART2: reqlen = 80; break;
    case MSG_TYPE_CONFIRM: reqlen = 48; break;

    default:
      log_error ("error parsing message: %s\n", "invalid message type");
      return gpg_error (GPG_ERR_INV_RESPONSE);
    }
  if (msglen < reqlen)
    {
      log_error ("error parsing message: %s\n", "message too short");
      return gpg_error (GPG_ERR_INV_RESPONSE);
    }

  if (DBG_MESSAGE)
    log_printhex (msg, msglen, "recv msg(%s):", msgtypestr (msg[7]));

  /* Note that we ignore any garbage at the end of a message.  */
  msglen = reqlen;

  set_session_id (msg+8, 8);

  if (opt.verbose)
    log_info ("session %s: received %s message\n",
              get_session_id_hex (), msgtypestr (msg[7]));

  /* Read the state.  */
  err = read_state (r_state);
  if (err && gpg_err_code (err) != GPG_ERR_NOT_FOUND)
    return err;

  *r_msg = xmalloc (msglen);
  memcpy (*r_msg, msg, msglen);
  *r_msglen = msglen;
  *r_msgtype = msg[7];
  return err;
}


/* Display the Short Authentication String (SAS). If WAIT is true the
 * function waits until the user has entered the SAS as seen at the
 * peer.
 *
 * To construct the SAS we take the 4 most significant octets of HASH,
 * interpret them as a 32 bit big endian unsigned integer, divide that
 * integer by 10^9 and take the remainder.  The remainder is displayed
 * as 3 groups of 3 decimal digits delimited by a hyphens.  This gives
 * a search space of close to 2^30 and is still easy to compare.
 */
static gpg_error_t
display_sas (const unsigned char *hash, size_t hashlen, int wait)
{
  gpg_error_t err = 0;
  unsigned long sas = 0;
  char sasbuf[12];

  log_assert (hashlen >= 4);

  sas |= (unsigned long)hash[20] << 24;
  sas |= (unsigned long)hash[21] << 16;
  sas |= (unsigned long)hash[22] <<  8;
  sas |= (unsigned long)hash[23];
  sas %= 1000000000ul;
  snprintf (sasbuf, sizeof sasbuf, "%09lu", sas);
  memmove (sasbuf+8, sasbuf+6, 3);
  memmove (sasbuf+4, sasbuf+3, 3);
  sasbuf[3] = sasbuf[7] = '-';
  sasbuf[11] = 0;

  if (wait)
    log_info ("Please check the SAS:\n");
  else
    log_info ("Please note the SAS:\n");
  log_info ("\n");
  log_info ("   %s\n", sasbuf);
  log_info ("\n");

  if (wait)
    {
      if (!opt.sas || strcmp (sasbuf, opt.sas))
        err = gpg_error (GPG_ERR_NOT_CONFIRMED);
      else
        log_info ("SAS confirmed\n");
    }

  if (err)
    log_info ("checking SAS failed: %s\n", gpg_strerror (err));
  return err;
}



static gpg_error_t
create_dh_keypair (unsigned char *dh_secret, size_t dh_secret_len,
                   unsigned char *dh_public, size_t dh_public_len)
{
  gpg_error_t err;
  unsigned char *p;

  /* We need a temporary buffer for the public key.  Check the length
   * for the later memcpy.  */
  if (dh_public_len < 32 || dh_secret_len < 32)
    return gpg_error (GPG_ERR_BUFFER_TOO_SHORT);

  if (gcry_ecc_get_algo_keylen (GCRY_ECC_CURVE25519) > dh_public_len)
    return gpg_error (GPG_ERR_BUFFER_TOO_SHORT);

  p = gcry_random_bytes (32, GCRY_VERY_STRONG_RANDOM);
  if (!p)
    return gpg_error_from_syserror ();

  memcpy (dh_secret, p, 32);
  xfree (p);

  err = gcry_ecc_mul_point (GCRY_ECC_CURVE25519, dh_public, dh_secret, NULL);
  if (err)
    return err;

  if (DBG_CRYPTO)
    {
      log_printhex (dh_secret, 32, "DH secret:");
      log_printhex (dh_public, 32, "DH public:");
    }

  return 0;
}


/* SHA256 the data given as varargs tuples of (const void*, size_t)
 * and store the result in RESULT.  The end of the list is indicated
 * by a NULL element in a tuple.  RESULTLEN gives the length of the
 * RESULT buffer which must be at least 32.  Note that the second item
 * of the tuple is the length and it is a size_t.  */
static void *
hash_data (void *result, size_t resultsize, ...)
{
  va_list arg_ptr;
  gpg_error_t err;
  gcry_md_hd_t hd;
  const void *data;
  size_t datalen;

  log_assert (resultsize >= 32);

  err = gcry_md_open (&hd, GCRY_MD_SHA256, 0);
  if (err)
    log_fatal ("error creating a Hash handle: %s\n", gpg_strerror (err));
  /* log_printhex ("", 0, "Hash-256:"); */

  va_start (arg_ptr, resultsize);
  while ((data = va_arg (arg_ptr, const void *)))
    {
      datalen = va_arg (arg_ptr, size_t);
      /* log_printhex (data, datalen, "    data:"); */
      gcry_md_write (hd, data, datalen);
    }
  va_end (arg_ptr);

  memcpy (result, gcry_md_read (hd, 0), 32);
  /* log_printhex (result, 32, "  result:"); */

  gcry_md_close (hd);

  return result;
}


/* HMAC-SHA256 the data given as varargs tuples of (const void*,
 * size_t) using (KEYLEN,KEY) and store the result in RESULT.  The end
 * of the list is indicated by a NULL element in a tuple.  RESULTLEN
 * gives the length of the RESULT buffer which must be at least 32.
 * Note that the second item of the tuple is the length and it is a
 * size_t.  */
static void *
hmac_data (void *result, size_t resultsize,
           const unsigned char *key, size_t keylen, ...)
{
  va_list arg_ptr;
  gpg_error_t err;
  gcry_mac_hd_t hd;
  const void *data;
  size_t datalen;

  log_assert (resultsize >= 32);

  err = gcry_mac_open (&hd, GCRY_MAC_HMAC_SHA256, 0, NULL);
  if (err)
    log_fatal ("error creating a MAC handle: %s\n", gpg_strerror (err));
  err = gcry_mac_setkey (hd, key, keylen);
  if (err)
    log_fatal ("error setting the MAC key: %s\n", gpg_strerror (err));
  /* log_printhex (key, keylen, "HMAC-key:"); */

  va_start (arg_ptr, keylen);
  while ((data = va_arg (arg_ptr, const void *)))
    {
      datalen = va_arg (arg_ptr, size_t);
      /* log_printhex (data, datalen, "    data:"); */
      err = gcry_mac_write (hd, data, datalen);
      if (err)
        log_fatal ("error writing to the MAC handle: %s\n", gpg_strerror (err));
    }
  va_end (arg_ptr);

  err = gcry_mac_read (hd, result, &resultsize);
  if (err || resultsize != 32)
    log_fatal ("error reading MAC value: %s\n", gpg_strerror (err));
  /* log_printhex (result, resultsize, "  result:"); */

  gcry_mac_close (hd);

  return result;
}


/* Key derivation function:
 *
 * FIXME(doc)
 */
static void
kdf (unsigned char *result, size_t resultlen,
     const unsigned char *master, size_t masterlen,
     const unsigned char *sessionid, size_t sessionidlen,
     const unsigned char *expire, size_t expirelen,
     const char *label)
{
  log_assert (masterlen == 32 && sessionidlen == 8 && expirelen == 5);
  log_assert (*label);
  log_assert (resultlen == 32);

  hmac_data (result, resultlen, master, masterlen,
             "\x00\x00\x00\x01", (size_t)4,      /* Counter=1*/
             label, strlen (label) + 1,          /* Label, 0x00 */
             sessionid, sessionidlen,            /* Context */
             expire, expirelen,                  /* Context */
             "\x00\x00\x01\x00", (size_t)4,      /* L=256 */
             NULL);
}


static gpg_error_t
compute_master_secret (unsigned char *master, size_t masterlen,
                       const unsigned char *sk_a, size_t sk_a_len,
                       const unsigned char *pk_b, size_t pk_b_len)
{
  gpg_error_t err;

  log_assert (masterlen == 32);
  log_assert (sk_a_len == 32);
  log_assert (pk_b_len == 32);

  err = gcry_ecc_mul_point (GCRY_ECC_CURVE25519, master, sk_a, pk_b);
  if (err)
    log_error ("error computing DH: %s\n", gpg_strerror (err));

  return err;
}


/* We are the Initiator: Create the commit message.  This function
 * sends the COMMIT message and writes STATE. */
static gpg_error_t
make_msg_commit (nvc_t state)
{
  gpg_error_t err;
  uint64_t now, expire;
  unsigned char secret[32];
  unsigned char public[32];
  unsigned char *newmsg;
  size_t newmsglen;
  unsigned char tmphash[32];

  err = create_dh_keypair (secret, sizeof secret, public, sizeof public );
  if (err)
    log_error ("creating DH keypair failed: %s\n", gpg_strerror (err));

  now = gnupg_get_time ();
  expire = now + opt.ttl;

  newmsglen = 7+1+8+1+2+5+32;
  newmsg = xmalloc (newmsglen);
  memcpy (newmsg+0, "GPG-pa1", 7);
  newmsg[7] = MSG_TYPE_COMMIT;
  memcpy (newmsg+8, get_session_id (), 8);
  newmsg[16] = REALM_STANDARD;
  newmsg[17] = 0;
  newmsg[18] = 0;
  newmsg[19] = expire >> 32;
  newmsg[20] = expire >> 24;
  newmsg[21] = expire >> 16;
  newmsg[22] = expire >> 8;
  newmsg[23] = expire;
  gcry_md_hash_buffer (GCRY_MD_SHA256, newmsg+24, public, 32);

  /* Create the state file.  */
  xnvc_set (state, "State:", "Commit-sent");
  xnvc_set_printf (state, "Created:", "%llu", (unsigned long long)now);
  xnvc_set_printf (state, "Expires:", "%llu", (unsigned long long)expire);
  xnvc_set_hex (state, "DH-PKi:", public, 32);
  xnvc_set_hex (state, "DH-SKi:", secret, 32);
  gcry_md_hash_buffer (GCRY_MD_SHA256, tmphash, newmsg, newmsglen);
  xnvc_set_hex (state, "Hash-Commit:", tmphash, 32);

  /* Write the state.  Note that we need to create it.  The state
   * updating should in theory be done atomically with send_message.
   * However, we can't assure that the message will actually be
   * delivered and thus it doesn't matter whether we have an already
   * update state when we later fail in send_message.  */
  write_state (state, 1);

  /* Write the message.  */
  send_message (newmsg, newmsglen);

   xfree (newmsg);
  return err;
}


/* We are the Responder: Process a commit message in (MSG,MSGLEN)
 * which has already been validated to have a correct header and
 * message type.  Sends the DHPart1 message and writes STATE.  */
static gpg_error_t
proc_msg_commit (nvc_t state, const unsigned char *msg, size_t msglen)
{
  gpg_error_t err;
  uint64_t now, expire;
  unsigned char tmphash[32];
  unsigned char secret[32];
  unsigned char public[32];
  unsigned char *newmsg = NULL;
  size_t newmsglen;

  log_assert (msglen >= 56);
  now = gnupg_get_time ();

  /* Check that the message has not expired.  */
  expire  = (uint64_t)msg[19] << 32;
  expire |= (uint64_t)msg[20] << 24;
  expire |= (uint64_t)msg[21] << 16;
  expire |= (uint64_t)msg[22] <<  8;
  expire |= (uint64_t)msg[23];
  if (expire < now)
    {
      log_error ("received %s message is too old\n",
                 msgtypestr (MSG_TYPE_COMMIT));
      err = gpg_error (GPG_ERR_TOO_OLD);
      goto leave;
    }

  /* Create the response.  */
  err = create_dh_keypair (secret, sizeof secret, public, sizeof public );
  if (err)
    {
      log_error ("creating DH keypair failed: %s\n", gpg_strerror (err));
      goto leave;
    }

  newmsglen = 7+1+8+32+32;
  newmsg = xmalloc (newmsglen);
  memcpy (newmsg+0, "GPG-pa1", 7);
  newmsg[7] = MSG_TYPE_DHPART1;
  memcpy (newmsg+8, msg + 8, 8);   /* SessionID.  */
  memcpy (newmsg+16, public, 32);  /* PKr */
  /* Hash(Hash(Commit) || DHPart1[0..47]) */
  gcry_md_hash_buffer (GCRY_MD_SHA256, tmphash, msg, msglen);
  hash_data (newmsg+48, 32,
             tmphash, sizeof tmphash,
             newmsg, (size_t)48,
             NULL);

  /* Update the state.  */
  xnvc_set (state, "State:", "DHPart1-sent");
  xnvc_set_printf (state, "Created:", "%llu", (unsigned long long)now);
  xnvc_set_printf (state, "Expires:", "%llu", (unsigned long long)expire);
  xnvc_set_hex (state, "Hash-PKi:", msg+24, 32);
  xnvc_set_hex (state, "DH-PKr:", public, 32);
  xnvc_set_hex (state, "DH-SKr:", secret, 32);
  gcry_md_hash_buffer (GCRY_MD_SHA256, tmphash, newmsg, newmsglen);
  xnvc_set_hex (state, "Hash-DHPart1:", tmphash, 32);

  /* Write the state.  Note that we need to create it. */
  write_state (state, 1);

  /* Write the message.  */
  send_message (newmsg, newmsglen);

 leave:
  xfree (newmsg);
  return err;
}


/* We are the Initiator: Process a DHPART1 message in (MSG,MSGLEN)
 * which has already been validated to have a correct header and
 * message type.  Sends the DHPart2 message and writes STATE.  */
static gpg_error_t
proc_msg_dhpart1 (nvc_t state, const unsigned char *msg, size_t msglen)
{
  gpg_error_t err;
  unsigned char hash[32];
  unsigned char tmphash[32];
  unsigned char pki[32];
  unsigned char pkr[32];
  unsigned char ski[32];
  unsigned char master[32];
  uint64_t expire;
  unsigned char expirebuf[5];
  unsigned char hmacikey[32];
  unsigned char symxkey[32];
  unsigned char *newmsg = NULL;
  size_t newmsglen;

  log_assert (msglen >= 80);

  /* Check that the message includes the Hash(Commit). */
  if (hex2bin (xnvc_get_string (state, "Hash-Commit:"), hash, sizeof hash) < 0)
    {
      err = gpg_error (GPG_ERR_INV_VALUE);
      log_error ("no or garbled 'Hash-Commit' in our state file\n");
      goto leave;
    }
  hash_data (tmphash, 32,
             hash, sizeof hash,
             msg, (size_t)48,
             NULL);
  if (memcmp (msg+48, tmphash, 32))
    {
      err = gpg_error (GPG_ERR_BAD_DATA);
      log_error ("manipulation of received %s message detected: %s\n",
                 msgtypestr (MSG_TYPE_DHPART1), "Bad Hash");
      goto leave;
    }
  /* Check that the received PKr is different from our PKi and copy
   * PKr into PKR.  */
  if (hex2bin (xnvc_get_string (state, "DH-PKi:"), pki, sizeof pki) < 0)
    {
      err = gpg_error (GPG_ERR_INV_VALUE);
      log_error ("no or garbled 'DH-PKi' in our state file\n");
      goto leave;
    }
  if (!memcmp (msg+16, pki, 32))
    {
      /* This can only happen if the state file leaked to the
       * responder.  */
      err = gpg_error (GPG_ERR_BAD_DATA);
      log_error ("received our own public key PKi instead of PKr\n");
      goto leave;
    }
  memcpy (pkr, msg+16, 32);

  /* Put the expire value into a buffer.  */
  expire = string_to_u64 (xnvc_get_string (state, "Expires:"));
  if (!expire)
    {
      err = gpg_error (GPG_ERR_INV_VALUE);
      log_error ("no 'Expire' in our state file\n");
      goto leave;
    }
  expirebuf[0] = expire >> 32;
  expirebuf[1] = expire >> 24;
  expirebuf[2] = expire >> 16;
  expirebuf[3] = expire >> 8;
  expirebuf[4] = expire;

  /* Get our secret from the state.  */
  if (hex2bin (xnvc_get_string (state, "DH-SKi:"), ski, sizeof ski) < 0)
    {
      err = gpg_error (GPG_ERR_INV_VALUE);
      log_error ("no or garbled 'DH-SKi' in our state file\n");
      goto leave;
    }

  /* Compute the shared secrets.  */
  err = compute_master_secret (master, sizeof master,
                               ski, sizeof ski, pkr, sizeof pkr);
  if (err)
    {
      log_error ("creating DH keypair failed: %s\n", gpg_strerror (err));
      goto leave;
    }

  kdf (hmacikey, sizeof hmacikey,
       master, sizeof master, msg+8, 8, expirebuf, sizeof expirebuf,
       "GPG-pa1-HMACi-key");
  kdf (symxkey, sizeof symxkey,
       master, sizeof master, msg+8, 8, expirebuf, sizeof expirebuf,
       "GPG-pa1-SYMx-key");


  /* Create the response.  */
  newmsglen = 7+1+8+32+32;
  newmsg = xmalloc (newmsglen);
  memcpy (newmsg+0, "GPG-pa1", 7);
  newmsg[7] = MSG_TYPE_DHPART2;
  memcpy (newmsg+8, msg + 8, 8); /* SessionID.  */
  memcpy (newmsg+16, pki, 32);   /* PKi */
  /* MAC(HMACi-key, Hash(DHPART1) || DHPART2[0..47] || SYMx-key) */
  gcry_md_hash_buffer (GCRY_MD_SHA256, tmphash, msg, msglen);
  hmac_data (newmsg+48, 32, hmacikey, sizeof hmacikey,
             tmphash, sizeof tmphash,
             newmsg, (size_t)48,
             symxkey, sizeof symxkey,
             NULL);

  /* Update the state.  */
  xnvc_set (state, "State:", "DHPart2-sent");
  xnvc_set_hex (state, "DH-Master:", master, sizeof master);
  gcry_md_hash_buffer (GCRY_MD_SHA256, tmphash, newmsg, newmsglen);
  xnvc_set_hex (state, "Hash-DHPart2:", tmphash, 32);

  /* Write the state.  */
  write_state (state, 0);

  /* Write the message.  */
  send_message (newmsg, newmsglen);

 leave:
  xfree (newmsg);
  return err;
}


/* We are the Responder: Process a DHPART2 message in (MSG,MSGLEN)
 * which has already been validated to have a correct header and
 * message type.  Sends the CONFIRM message and writes STATE.  */
static gpg_error_t
proc_msg_dhpart2 (nvc_t state, const unsigned char *msg, size_t msglen)
{
  gpg_error_t err;
  unsigned char hash[32];
  unsigned char tmphash[32];
  uint64_t expire;
  unsigned char expirebuf[5];
  unsigned char pki[32];
  unsigned char pkr[32];
  unsigned char skr[32];
  unsigned char master[32];
  unsigned char hmacikey[32];
  unsigned char hmacrkey[32];
  unsigned char symxkey[32];
  unsigned char sas[32];
  unsigned char *newmsg = NULL;
  size_t newmsglen;

  log_assert (msglen >= 80);

  /* Check that the PKi in the message matches the Hash(Pki) received
   * with the Commit message. */
  memcpy (pki, msg + 16, 32);
  gcry_md_hash_buffer (GCRY_MD_SHA256, hash, pki, 32);
  if (hex2bin (xnvc_get_string (state, "Hash-PKi:"),
               tmphash, sizeof tmphash) < 0)
    {
      err = gpg_error (GPG_ERR_INV_VALUE);
      log_error ("no or garbled 'Hash-PKi' in our state file\n");
      goto leave;
    }
  if (memcmp (hash, tmphash, 32))
    {
      err = gpg_error (GPG_ERR_BAD_DATA);
      log_error ("Initiator sent a different key in %s than announced in %s\n",
                 msgtypestr (MSG_TYPE_DHPART2),
                 msgtypestr (MSG_TYPE_COMMIT));
      goto leave;
    }
  /* Check that the received PKi is different from our PKr.  */
  if (hex2bin (xnvc_get_string (state, "DH-PKr:"), pkr, sizeof pkr) < 0)
    {
      err = gpg_error (GPG_ERR_INV_VALUE);
      log_error ("no or garbled 'DH-PKr' in our state file\n");
      goto leave;
    }
  if (!memcmp (pkr, pki, 32))
    {
      err = gpg_error (GPG_ERR_BAD_DATA);
      log_error ("Initiator sent our own PKr back\n");
      goto leave;
    }

  /* Put the expire value into a buffer.  */
  expire = string_to_u64 (xnvc_get_string (state, "Expires:"));
  if (!expire)
    {
      err = gpg_error (GPG_ERR_INV_VALUE);
      log_error ("no 'Expire' in our state file\n");
      goto leave;
    }
  expirebuf[0] = expire >> 32;
  expirebuf[1] = expire >> 24;
  expirebuf[2] = expire >> 16;
  expirebuf[3] = expire >> 8;
  expirebuf[4] = expire;

  /* Get our secret from the state.  */
  if (hex2bin (xnvc_get_string (state, "DH-SKr:"), skr, sizeof skr) < 0)
    {
      err = gpg_error (GPG_ERR_INV_VALUE);
      log_error ("no or garbled 'DH-SKr' in our state file\n");
      goto leave;
    }

  /* Compute the shared secrets.  */
  err = compute_master_secret (master, sizeof master,
                               skr, sizeof skr, pki, sizeof pki);
  if (err)
    {
      log_error ("creating DH keypair failed: %s\n", gpg_strerror (err));
      goto leave;
    }

  kdf (hmacikey, sizeof hmacikey,
       master, sizeof master, msg+8, 8, expirebuf, sizeof expirebuf,
       "GPG-pa1-HMACi-key");
  kdf (hmacrkey, sizeof hmacrkey,
       master, sizeof master, msg+8, 8, expirebuf, sizeof expirebuf,
       "GPG-pa1-HMACr-key");
  kdf (symxkey, sizeof symxkey,
       master, sizeof master, msg+8, 8, expirebuf, sizeof expirebuf,
       "GPG-pa1-SYMx-key");
  kdf (sas, sizeof sas,
       master, sizeof master, msg+8, 8, expirebuf, sizeof expirebuf,
       "GPG-pa1-SAS");

  /* Check the MAC from the message which is
   *   MAC(HMACi-key, Hash(DHPART1) || DHPART2[0..47] || SYMx-key).
   * For that we need to fetch the stored hash from the state.  */
  if (hex2bin (xnvc_get_string (state, "Hash-DHPart1:"),
               tmphash, sizeof tmphash) < 0)
    {
      err = gpg_error (GPG_ERR_INV_VALUE);
      log_error ("no or garbled 'Hash-DHPart1' in our state file\n");
      goto leave;
    }
  hmac_data (hash, 32, hmacikey, sizeof hmacikey,
             tmphash, sizeof tmphash,
             msg, 48,
             symxkey, sizeof symxkey,
             NULL);
  if (memcmp (msg+48, hash, 32))
    {
      err = gpg_error (GPG_ERR_BAD_DATA);
      log_error ("manipulation of received %s message detected: %s\n",
                 msgtypestr (MSG_TYPE_DHPART2), "Bad MAC");
      goto leave;
    }

  /* Create the response.  */
  newmsglen = 7+1+8+32;
  newmsg = xmalloc (newmsglen);
  memcpy (newmsg+0, "GPG-pa1", 7);
  newmsg[7] = MSG_TYPE_CONFIRM;
  memcpy (newmsg+8, msg + 8, 8); /* SessionID.  */
  /* MAC(HMACr-key, Hash(DHPART2) || CONFIRM[0..15] || SYMx-key) */
  gcry_md_hash_buffer (GCRY_MD_SHA256, tmphash, msg, msglen);
  hmac_data (newmsg+16, 32, hmacrkey, sizeof hmacrkey,
             tmphash, sizeof tmphash,
             newmsg, (size_t)16,
             symxkey, sizeof symxkey,
             NULL);

  /* Update the state.  */
  xnvc_set (state, "State:", "Confirm-sent");
  xnvc_set_hex (state, "DH-Master:", master, sizeof master);

  /* Write the state.  */
  write_state (state, 0);

  /* Write the message.  */
  send_message (newmsg, newmsglen);

  display_sas (sas, sizeof sas, 0);


 leave:
  xfree (newmsg);
  return err;
}


/* We are the Initiator: Process a CONFIRM message in (MSG,MSGLEN)
 * which has already been validated to have a correct header and
 * message type.  Does not send anything back.  */
static gpg_error_t
proc_msg_confirm (nvc_t state, const unsigned char *msg, size_t msglen)
{
  gpg_error_t err;
  unsigned char hash[32];
  unsigned char tmphash[32];
  unsigned char master[32];
  uint64_t expire;
  unsigned char expirebuf[5];
  unsigned char hmacrkey[32];
  unsigned char symxkey[32];
  unsigned char sas[32];

  log_assert (msglen >= 48);

  /* Put the expire value into a buffer.  */
  expire = string_to_u64 (xnvc_get_string (state, "Expires:"));
  if (!expire)
    {
      err = gpg_error (GPG_ERR_INV_VALUE);
      log_error ("no 'Expire' in our state file\n");
      goto leave;
    }
  expirebuf[0] = expire >> 32;
  expirebuf[1] = expire >> 24;
  expirebuf[2] = expire >> 16;
  expirebuf[3] = expire >> 8;
  expirebuf[4] = expire;

  /* Get the master secret.  */
  if (hex2bin (xnvc_get_string (state, "DH-Master:"),master,sizeof master) < 0)
    {
      err = gpg_error (GPG_ERR_INV_VALUE);
      log_error ("no or garbled 'DH-Master' in our state file\n");
      goto leave;
    }

  kdf (hmacrkey, sizeof hmacrkey,
       master, sizeof master, msg+8, 8, expirebuf, sizeof expirebuf,
       "GPG-pa1-HMACr-key");
  kdf (symxkey, sizeof symxkey,
       master, sizeof master, msg+8, 8, expirebuf, sizeof expirebuf,
       "GPG-pa1-SYMx-key");
  kdf (sas, sizeof sas,
       master, sizeof master, msg+8, 8, expirebuf, sizeof expirebuf,
       "GPG-pa1-SAS");

  /* Check the MAC from the message which is */
  /*   MAC(HMACr-key, Hash(DHPART2) || CONFIRM[0..15] || SYMx-key). */
  if (hex2bin (xnvc_get_string (state, "Hash-DHPart2:"),
               tmphash, sizeof tmphash) < 0)
    {
      err = gpg_error (GPG_ERR_INV_VALUE);
      log_error ("no or garbled 'Hash-DHPart2' in our state file\n");
      goto leave;
    }
  hmac_data (hash, 32, hmacrkey, sizeof hmacrkey,
             tmphash, sizeof tmphash,
             msg, (size_t)16,
             symxkey, sizeof symxkey,
             NULL);
  if (!memcmp (msg+48, hash, 32))
    {
      err = gpg_error (GPG_ERR_BAD_DATA);
      log_error ("manipulation of received %s message detected: %s\n",
                 msgtypestr (MSG_TYPE_CONFIRM), "Bad MAC");
      goto leave;
    }


  err = display_sas (sas, sizeof sas, 1);
  if (err)
    goto leave;

  /* Update the state.  */
  xnvc_set (state, "State:", "Confirmed");

  /* Write the state.  */
  write_state (state, 0);

 leave:
  return err;
}



/* Expire old state files.  This loops over all state files and remove
 * those which are expired.  */
static void
expire_old_states (void)
{
  gpg_error_t err = 0;
  const char *dirname;
  gnupg_dir_t dir = NULL;
  gnupg_dirent_t dir_entry;
  char *fname = NULL;
  estream_t fp = NULL;
  nvc_t nvc = NULL;
  nve_t item;
  const char *value;
  unsigned long expire;
  unsigned long now = gnupg_get_time ();

  dirname = get_pairing_statedir ();
  dir = gnupg_opendir (dirname);
  if (!dir)
    {
      err = gpg_error_from_syserror ();
      goto leave;
    }

  while ((dir_entry = gnupg_readdir (dir)))
    {
      if (strlen (dir_entry->d_name) != 16+4
          || strcmp (dir_entry->d_name + 16, ".pa1"))
        continue;

      xfree (fname);
      fname = make_filename (dirname, dir_entry->d_name, NULL);
      es_fclose (fp);
      fp = es_fopen (fname, "rb");
      if (!fp)
        {
          err = gpg_error_from_syserror ();
          if (gpg_err_code (err) != GPG_ERR_ENOENT)
            log_info ("failed to open state file '%s': %s\n",
                      fname, gpg_strerror (err));
          continue;
        }
      nvc_release (nvc);

      /* NB.: The following is similar to code in read_state.  */
      err = nvc_parse (&nvc, NULL, fp);
      if (err)
        {
          log_info ("failed to parse state file '%s': %s\n",
                    fname, gpg_strerror (err));
          continue; /* Skip */
        }
      item = nvc_lookup (nvc, "Expires:");
      if (!item)
        {
          log_info ("invalid state file '%s': %s\n",
                    fname, "field 'expire' not found");
          continue; /* Skip */
        }
      value = nve_value (item);
      if (!value || !(expire = strtoul (value, NULL, 10)))
        {
          log_info ("invalid state file '%s': %s\n",
                    fname, "field 'expire' has an invalid value");
          continue; /* Skip */
        }

      if (expire <= now)
        {
          es_fclose (fp);
          fp = NULL;
          if (gnupg_remove (fname))
            {
              err = gpg_error_from_syserror ();
              log_info ("failed to delete state file '%s': %s\n",
                        fname, gpg_strerror (err));
            }
          else if (opt.verbose)
            log_info ("state file '%s' deleted\n", fname);
        }
    }

 leave:
  if (err)
    log_error ("expiring old states in '%s' failed: %s\n",
               dirname, gpg_strerror (err));
  gnupg_closedir (dir);
  es_fclose (fp);
  xfree (fname);
}



/* Initiate a pairing.  The output needs to be conveyed to the
 * peer  */
static gpg_error_t
command_initiate (void)
{
  gpg_error_t err;
  nvc_t state;

  state = xnvc_new ();
  xnvc_set (state, "Version:", "GPG-pa1");
  xnvc_set_hex (state, "Session:", get_session_id (), 8);
  xnvc_set (state, "Role:", "Initiator");

  err = make_msg_commit (state);

  nvc_release (state);
  return err;
}



/* Helper for command_respond().  */
static gpg_error_t
expect_state (int msgtype, const char *statestr, const char *expected)
{
  if (strcmp (statestr, expected))
    {
      log_error ("received %s message in %s state (should be %s)\n",
                 msgtypestr (msgtype), statestr, expected);
      return gpg_error (GPG_ERR_INV_RESPONSE);
    }
  return 0;
}

/* Respond to a pairing initiation.  This is used by the peer and later
 * by the original responder.  Depending on the state the output needs
 * to be conveyed to the peer.  */
static gpg_error_t
command_respond (void)
{
  gpg_error_t err;
  unsigned char *msg;
  size_t msglen = 0; /* In case that read_message returns an error.  */
  int msgtype = 0;   /* ditto.  */
  nvc_t state;
  const char *rolestr;
  const char *statestr;

  err = read_message (&msg, &msglen, &msgtype, &state);
  if (err && gpg_err_code (err) != GPG_ERR_NOT_FOUND)
    goto leave;
  rolestr = xnvc_get_string (state, "Role:");
  statestr = xnvc_get_string (state, "State:");
  if (DBG_MESSAGE)
    {
      if (!state)
        log_debug ("no state available\n");
      else
        log_debug ("we are %s, our current state is %s\n", rolestr, statestr);
      log_debug ("got message of type %s (%d)\n",
                 msgtypestr (msgtype), msgtype);
    }

  if (!state)
    {
      if (msgtype == MSG_TYPE_COMMIT)
        {
          state = xnvc_new ();
          xnvc_set (state, "Version:", "GPG-pa1");
          xnvc_set_hex (state, "Session:", get_session_id (), 8);
          xnvc_set (state, "Role:", "Responder");
          err = proc_msg_commit (state, msg, msglen);
        }
      else
        {
          log_error ("%s message expected but got %s\n",
                     msgtypestr (MSG_TYPE_COMMIT), msgtypestr (msgtype));
          if (msgtype == MSG_TYPE_DHPART1)
            log_info ("the pairing probably took too long and timed out\n");
          err = gpg_error (GPG_ERR_INV_RESPONSE);
          goto leave;
        }
    }
  else if (!strcmp (rolestr, "Initiator"))
    {
      if (msgtype == MSG_TYPE_DHPART1)
        {
          if (!(err = expect_state (msgtype, statestr, "Commit-sent")))
            err = proc_msg_dhpart1 (state, msg, msglen);
        }
      else if (msgtype == MSG_TYPE_CONFIRM)
        {
          if (!(err = expect_state (msgtype, statestr, "DHPart2-sent")))
            err = proc_msg_confirm (state, msg, msglen);
        }
      else
        {
          log_error ("%s message not expected by Initiator\n",
                     msgtypestr (msgtype));
          err = gpg_error (GPG_ERR_INV_RESPONSE);
          goto leave;
        }
    }
  else if (!strcmp (rolestr, "Responder"))
    {
      if (msgtype == MSG_TYPE_DHPART2)
        {
          if (!(err = expect_state (msgtype, statestr, "DHPart1-sent")))
            err = proc_msg_dhpart2 (state, msg, msglen);
        }
      else
        {
          log_error ("%s message not expected by Responder\n",
                     msgtypestr (msgtype));
          err = gpg_error (GPG_ERR_INV_RESPONSE);
          goto leave;
        }
    }
  else
    log_fatal ("invalid role '%s' in state file\n", rolestr);


 leave:
  xfree (msg);
  nvc_release (state);
  return err;
}



/* Return the keys for SESSIONIDSTR or the last one if it is NULL.
 * Two keys are returned: The first is the one for sending encrypted
 * data and the second one for decrypting received data.  The keys are
 * always returned hex encoded and both are terminated by a LF. */
static gpg_error_t
command_get (const char *sessionidstr)
{
  gpg_error_t err;
  unsigned char sessid[8];
  nvc_t state;

  if (!sessionidstr)
    {
      log_error ("calling without session-id is not yet implemented\n");
      err = gpg_error (GPG_ERR_NOT_IMPLEMENTED);
      goto leave;
    }
  if (hex2bin (sessionidstr, sessid, sizeof sessid) < 0)
    {
      err = gpg_error (GPG_ERR_INV_VALUE);
      log_error ("invalid session id given\n");
      goto leave;
    }
  set_session_id (sessid, sizeof sessid);
  err = read_state (&state);
  if (err)
    {
      log_error ("reading state of session %s failed: %s\n",
                 sessionidstr, gpg_strerror (err));
      goto leave;
    }

 leave:
  return err;
}



/* Cleanup command.  */
static gpg_error_t
command_cleanup (void)
{
  expire_old_states ();
  return 0;
}
