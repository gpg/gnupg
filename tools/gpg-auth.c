/* gpg-auth.c - Authenticate using GnuPG
 * Copyright (C) 2022 g10 Code GmbH
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

#define INCLUDED_BY_MAIN_MODULE 1

#include "../common/util.h"
#include "../common/status.h"
#include "../common/i18n.h"
#include "../common/init.h"
#include "../common/sysutils.h"
#include "../common/asshelp.h"
#include "../common/session-env.h"
#include "../common/membuf.h"
#include "../common/exechelp.h"


/* We keep all global options in the structure OPT.  */
struct
{
  int interactive;
  int verbose;
  unsigned int debug;
  int quiet;
  int with_colons;
  const char *agent_program;
  int autostart;
  int use_scd_directly;

  /* Options passed to the gpg-agent: */
  char *lc_ctype;
  char *lc_messages;
} opt;

/* Debug values and macros.  */
#define DBG_IPC_VALUE      1024 /* Debug assuan communication.  */
#define DBG_EXTPROG_VALUE 16384 /* Debug external program calls */

#define DBG_IPC       (opt.debug & DBG_IPC_VALUE)
#define DBG_EXTPROG   (opt.debug & DBG_EXTPROG_VALUE)


/* Constants to identify the commands and options. */
enum opt_values
  {
    aNull = 0,

    oQuiet      = 'q',
    oVerbose	= 'v',

    oDebug      = 500,

    oGpgProgram,
    oGpgsmProgram,
    oAgentProgram,
    oStatusFD,
    oWithColons,
    oNoAutostart,

    oLCctype,
    oLCmessages,

    oUseSCDDirectly,

    oDummy
  };


/* The list of commands and options. */
static gpgrt_opt_t opts[] = {
  ARGPARSE_group (301, ("@\nOptions:\n ")),

  ARGPARSE_s_n (oVerbose, "verbose", ("verbose")),
  ARGPARSE_s_n (oQuiet,	"quiet",  ("be somewhat more quiet")),
  ARGPARSE_s_s (oDebug, "debug", "@"),
  ARGPARSE_s_i (oStatusFD, "status-fd", N_("|FD|write status info to this FD")),
  ARGPARSE_s_n (oWithColons, "with-colons", "@"),
  ARGPARSE_s_n (oNoAutostart, "no-autostart", "@"),
  ARGPARSE_s_s (oAgentProgram, "agent-program", "@"),
  ARGPARSE_s_s (oLCctype,    "lc-ctype",   "@"),
  ARGPARSE_s_s (oLCmessages, "lc-messages","@"),
  ARGPARSE_s_n (oUseSCDDirectly, "use-scdaemon-directly", "@"),

  ARGPARSE_end ()
};

/* The list of supported debug flags.  */
static struct debug_flags_s debug_flags [] =
  {
    { DBG_IPC_VALUE    , "ipc"     },
    { DBG_EXTPROG_VALUE, "extprog" },
    { 0, NULL }
  };


/* Print usage information and provide strings for help. */
static const char *
my_strusage( int level )
{
  const char *p;

  switch (level)
    {
    case  9: p = "GPL-3.0-or-later"; break;
    case 11: p = "gpg-auth"; break;
    case 12: p = "@GNUPG@"; break;
    case 13: p = VERSION; break;
    case 14: p = GNUPG_DEF_COPYRIGHT_LINE; break;
    case 17: p = PRINTABLE_OS_NAME; break;
    case 19: p = ("Please report bugs to <@EMAIL@>.\n"); break;

    case 1:
    case 40:
      p = ("Usage: gpg-auth"
           " [options] (-h for help)");
      break;
    case 41:
      p = ("Syntax: gpg-auth"
           " [options] \n\n"
           "Tool to authenticate a user using a smartcard.\n"
           "Use command \"help\" to list all commands.");
      break;

    default: p = NULL; break;
    }
  return p;
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

        case oAgentProgram: opt.agent_program = pargs->r.ret_str; break;

        case oStatusFD:
          gnupg_set_status_fd (translate_sys2libc_fd_int (pargs->r.ret_int, 1));
          break;

        case oWithColons:  opt.with_colons = 1; break;
        case oNoAutostart: opt.autostart = 0; break;

        case oLCctype:     opt.lc_ctype = pargs->r.ret_str; break;
        case oLCmessages:  opt.lc_messages = pargs->r.ret_str; break;

	case oUseSCDDirectly: opt.use_scd_directly = 1; break;

        default: pargs->err = ARGPARSE_PRINT_ERROR; break;
	}
    }
}



struct ga_key_list {
  struct ga_key_list *next;
  char keygrip[41];  /* Keygrip to identify a key.  */
  size_t pubkey_len;
  char *pubkey;      /* Public key in SSH format.   */
  char *comment;
};

/* Local prototypes.  */
static gpg_error_t scd_passwd_reset (assuan_context_t ctx, const char *keygrip);
static gpg_error_t ga_scd_connect (assuan_context_t *r_scd_ctx, int use_agent);
static gpg_error_t ga_scd_get_auth_keys (assuan_context_t ctx,
                                         struct ga_key_list **r_key_list);
static gpg_error_t ga_filter_by_authorized_keys (const char *user,
                                                 struct ga_key_list **r_key_list);
static void ga_release_auth_keys (struct ga_key_list *key_list);
static gpg_error_t scd_pkauth (assuan_context_t ctx, const char *keygrip);
static gpg_error_t authenticate (assuan_context_t ctx, struct ga_key_list *key_list);
static int getpin (const char *comment, const char *info, char *buf, size_t *r_len);

/* gpg-auth main. */
int
main (int argc, char **argv)
{
  gpg_error_t err;
  gpgrt_argparse_t pargs;
  assuan_context_t scd_ctx = NULL;
  struct ga_key_list *key_list = NULL;
  const char *user;

  gnupg_reopen_std ("gpg-auth");
  gpgrt_set_strusage (my_strusage);
  log_set_prefix ("gpg-auth", GPGRT_LOG_WITH_PREFIX);

  /* Make sure that our subsystems are ready.  */
  i18n_init();
  init_common_subsystems (&argc, &argv);

  assuan_set_gpg_err_source (GPG_ERR_SOURCE_DEFAULT);
  setup_libassuan_logging (&opt.debug, NULL);

  /* Setup default options.  */
  opt.autostart = 1;

  /* Parse the command line. */
  pargs.argc  = &argc;
  pargs.argv  = &argv;
  pargs.flags = ARGPARSE_FLAG_KEEP;
  parse_arguments (&pargs, opts);
  gpgrt_argparse (NULL, &pargs, NULL);  /* Release internal state.  */

  if (log_get_errorcount (0))
    exit (2);

  if (argc != 0)
    gpgrt_usage (1);            /* Never returns.  */

  if (opt.use_scd_directly)
    {
      user = getenv ("PAM_USER");
      if (user == NULL)
        exit (2);
    }
  else
    user = NULL;

  err = ga_scd_connect (&scd_ctx, opt.use_scd_directly);

  if (!err)
    err = ga_scd_get_auth_keys (scd_ctx, &key_list);

  if (!err)
    err = ga_filter_by_authorized_keys (user, &key_list);

  if (!err)
    err = authenticate (scd_ctx, key_list);

  ga_release_auth_keys (key_list);

  if (scd_ctx)
    assuan_release (scd_ctx);

  if (err)
    exit (1);

  return 0;
}

static gpg_error_t
authenticate (assuan_context_t ctx, struct ga_key_list *key_list)
{
  gpg_error_t err;

  while (key_list)
    {
      err = scd_passwd_reset (ctx, key_list->keygrip);
      if (err)
        return err;

      assuan_set_pointer (ctx, key_list->comment);
      err = scd_pkauth (ctx,  key_list->keygrip);
      if (!err)
        /* Success!  */
        return 0;

      key_list = key_list->next;
    }

  return gpg_error (GPG_ERR_NOT_FOUND);
}

static gpg_error_t
get_serialno_cb (void *opaque, const char *line)
{
  char **serialno = opaque;
  const char *keyword = line;
  const char *s;
  int keywordlen, n;

  for (keywordlen=0; *line && !spacep (line); line++, keywordlen++)
    ;
  while (spacep (line))
    line++;

  if (keywordlen == 8 && !memcmp (keyword, "SERIALNO", keywordlen))
    {
      if (*serialno)
        return gpg_error (GPG_ERR_CONFLICT); /* Unexpected status line. */
      for (n=0,s=line; hexdigitp (s); s++, n++)
        ;
      if (!n || (n&1)|| !(spacep (s) || !*s) )
        return gpg_error (GPG_ERR_ASS_PARAMETER);
      *serialno = xtrymalloc (n+1);
      if (!*serialno)
        return gpg_error_from_syserror ();
      memcpy (*serialno, line, n);
      (*serialno)[n] = 0;
    }

  return 0;
}

/* Helper function, which is used by scd_connect.

   Try to retrieve the SCDaemon's socket name from the gpg-agent
   context CTX.  On success, *SOCKET_NAME is filled with a copy of the
   socket name.  Return proper error code or zero on success. */
static gpg_error_t
agent_scd_getinfo_socket_name (assuan_context_t ctx, char **socket_name)
{
  membuf_t data;
  gpg_error_t err = 0;
  unsigned char *databuf;
  size_t datalen;

  init_membuf (&data, 256);
  *socket_name = NULL;

  err = assuan_transact (ctx, "SCD GETINFO socket_name", put_membuf_cb, &data,
			 NULL, NULL, NULL, NULL);
  databuf = get_membuf (&data, &datalen);
  if (!err)
    {
      if (databuf && datalen)
	{
	  char *res = xtrymalloc (datalen + 1);
	  if (!res)
	    err = gpg_error_from_syserror ();
	  else
	    {
	      memcpy (res, databuf, datalen);
	      res[datalen] = 0;
	      *socket_name = res;
	    }
	}
    }

  xfree (databuf);

  return err;
}

/* Callback parameter for learn card */
struct learn_parm_s
{
  void (*kpinfo_cb)(void*, const char *);
  void *kpinfo_cb_arg;
  void (*certinfo_cb)(void*, const char *);
  void *certinfo_cb_arg;
  void (*sinfo_cb)(void*, const char *, size_t, const char *);
  void *sinfo_cb_arg;
};

/* Connect to the agent and send the standard options.  */
static gpg_error_t
start_agent (assuan_context_t *ctx_p)
{
  gpg_error_t err;
  session_env_t session_env;

  session_env = session_env_new ();
  if (!session_env)
    log_fatal ("error allocating session environment block: %s\n",
               strerror (errno));

  err = start_new_gpg_agent (ctx_p,
                             GPG_ERR_SOURCE_DEFAULT,
                             opt.agent_program,
                             NULL, NULL,
                             session_env,
                             opt.autostart,
                             !opt.quiet, 0,
                             NULL, NULL);

  session_env_release (session_env);
  return err;
}

static gpg_error_t
scd_serialno (assuan_context_t ctx)
{
  char *serialno = NULL;
  gpg_error_t err;

  err = assuan_transact (ctx, "SERIALNO", NULL, NULL, NULL, NULL,
                         get_serialno_cb, &serialno);
  xfree (serialno);
  return err;
}


static gpg_error_t
scd_passwd_reset (assuan_context_t ctx, const char *keygrip)
{
  char line[ASSUAN_LINELENGTH];
  gpg_error_t err;

  snprintf (line, DIM(line), "PASSWD --clear OPENPGP.2 %s", keygrip);
  err = assuan_transact (ctx, line, NULL, NULL, NULL, NULL,
                         NULL, NULL);
  return err;
}


/* Connect to scdaemon by pipe or socket.  Execute initial "SEREIALNO"
   command to enable all connected token under scdaemon control.  */
static gpg_error_t
ga_scd_connect (assuan_context_t *r_scd_ctx, int use_scd_directly)
{
  assuan_context_t assuan_ctx;
  gpg_error_t err;

  err = assuan_new (&assuan_ctx);
  if (err)
    return err;

  if (!use_scd_directly)
    /* Use scdaemon under gpg-agent.  */
    {
      char *scd_socket_name = NULL;
      assuan_context_t ctx;

      err = start_agent (&ctx);
      if (err)
        return err;

      /* Note that if gpg-agent is there but no scdaemon yet,
       * gpg-agent automatically invokes scdaemon by this query
       * itself.
       */
      err = agent_scd_getinfo_socket_name (ctx, &scd_socket_name);
      assuan_release (ctx);

      if (!err)
	err = assuan_socket_connect (assuan_ctx, scd_socket_name, 0, 0);

      if (!err && DBG_IPC)
	log_debug ("got scdaemon socket name from gpg-agent, "
                   "connected to socket '%s'", scd_socket_name);

      xfree (scd_socket_name);
    }
  else
    {
      const char *scd_path;
      const char *pgmname;
      const char *argv[3];
      int no_close_list[2];

      scd_path = gnupg_module_name (GNUPG_MODULE_NAME_SCDAEMON);
      if (!(pgmname = strrchr (scd_path, '/')))
        pgmname = scd_path;
      else
        pgmname++;

      /* Fill argument vector for scdaemon.  */
      argv[0] = pgmname;
      argv[1] = "--server";
      argv[2] = NULL;

      no_close_list[0] = assuan_fd_from_posix_fd (fileno (stderr));
      no_close_list[1] = ASSUAN_INVALID_FD;

      /* Connect to the scdaemon */
      err = assuan_pipe_connect (assuan_ctx, scd_path, argv, no_close_list,
                                 NULL, NULL, 0);
      if (err)
	{
	  log_error ("could not spawn scdaemon: %s\n", gpg_strerror (err));
          return err;
	}

      if (DBG_IPC)
	log_debug ("spawned a new scdaemon (path: '%s')", scd_path);
    }

  if (err)
    assuan_release (assuan_ctx);
  else
    {
      scd_serialno (assuan_ctx);
      *r_scd_ctx = assuan_ctx;
    }

  return err;
}


/* Handle the NEEDPIN inquiry. */
static gpg_error_t
inq_needpin (void *opaque, const char *line)
{
  assuan_context_t ctx = opaque;
  const char *s;
  char *pin;
  size_t pinlen;
  int rc;
  const char *comment = assuan_get_pointer (ctx);

  rc = 0;

  if ((s = has_leading_keyword (line, "NEEDPIN")))
    {
      line = s;
      pinlen = 90;
      pin = gcry_malloc_secure (pinlen);
      if (!pin)
        return out_of_core ();

      rc = getpin (comment, line, pin, &pinlen);
      if (!rc)
        {
          assuan_begin_confidential (ctx);
          rc = assuan_send_data (ctx, pin, pinlen);
          assuan_end_confidential (ctx);
        }
      wipememory (pin, pinlen);
      xfree (pin);
    }
  else if ((s = has_leading_keyword (line, "POPUPPINPADPROMPT")))
    {

      if (comment)
        {
          int msg_len = 27 + strlen (comment);
          fprintf (stdout, "i %d\n", msg_len);
          fprintf (stdout, "Please use PINPAD for KEY: %s\n", comment);
          fflush (stdout);
        }
      else
        {
          fputs ("i 18\n", stdout);
          fputs ("Please use PINPAD!\n", stdout);
          fflush (stdout);
        }
    }
  else if ((s = has_leading_keyword (line, "DISMISSPINPADPROMPT")))
    {
      ;
    }
  else
    {
      log_error ("unsupported inquiry '%s'\n", line);
      rc = gpg_error (GPG_ERR_ASS_UNKNOWN_INQUIRE);
    }

  return gpg_error (rc);
}

struct card_keyinfo_parm_s {
  int error;
  struct ga_key_list *list;
};

/* Callback function for scd_keyinfo_list.  */
static gpg_error_t
card_keyinfo_cb (void *opaque, const char *line)
{
  gpg_error_t err = 0;
  struct card_keyinfo_parm_s *parm = opaque;
  const char *keyword = line;
  int keywordlen;
  struct ga_key_list *keyinfo = NULL;

  for (keywordlen=0; *line && !spacep (line); line++, keywordlen++)
    ;
  while (spacep (line))
    line++;

  if (keywordlen == 7 && !memcmp (keyword, "KEYINFO", keywordlen))
    {
      const char *s;
      int n;
      struct ga_key_list **l_p = &parm->list;

      /* It's going to append the information at the end.  */
      while ((*l_p))
        l_p = &(*l_p)->next;

      keyinfo = xtrycalloc (1, sizeof *keyinfo);
      if (!keyinfo)
        goto alloc_error;

      for (n=0,s=line; hexdigitp (s); s++, n++)
        ;

      if (n != 40)
        goto parm_error;

      memcpy (keyinfo->keygrip, line, 40);
      keyinfo->keygrip[40] = 0;

      line = s;

      if (!*line)
        goto parm_error;

      while (spacep (line))
        line++;

      if (*line++ != 'T')
        goto parm_error;

      if (!*line)
        goto parm_error;

      while (spacep (line))
        line++;

      for (n=0,s=line; hexdigitp (s); s++, n++)
        ;

      if (!n)
        goto skip;

    skip:
      *l_p = keyinfo;
    }

  return err;

 alloc_error:
  xfree (keyinfo);
  if (!parm->error)
    parm->error = gpg_error_from_syserror ();
  return 0;

 parm_error:
  xfree (keyinfo);
  if (!parm->error)
    parm->error = gpg_error (GPG_ERR_ASS_PARAMETER);
  return 0;
}


/* Call the scdaemon to retrieve list of available keys on cards.  On
   success, the allocated structure is stored at R_KEY_LIST.  On
   error, an error code is returned and NULL is stored at R_KEY_LIST.  */
static gpg_error_t
scd_keyinfo_list (assuan_context_t ctx, struct ga_key_list **r_key_list)
{
  int err;
  struct card_keyinfo_parm_s parm;

  memset (&parm, 0, sizeof parm);

  err = assuan_transact (ctx, "KEYINFO --list=auth", NULL, NULL, NULL, NULL,
                         card_keyinfo_cb, &parm);
  if (!err && parm.error)
    err = parm.error;

  if (!err)
    *r_key_list = parm.list;
  else
    ga_release_auth_keys (parm.list);

  return err;
}

/* A variant of put_membuf_cb, which only put the second field.  */
static gpg_error_t
put_second_field_cb (void *opaque, const void *buf, size_t len)
{
  char line[ASSUAN_LINELENGTH];
  membuf_t *data = opaque;

  if (buf && len < ASSUAN_LINELENGTH)
    {
      const char *fields[3];
      size_t field_len;

      memcpy (line, buf, len);
      if (split_fields (line, fields, DIM (fields)) < 2)
	return 0;

      field_len = strlen (fields[1]);
      put_membuf (data, fields[1], field_len);
    }
  return 0;
}

static gpg_error_t
scd_get_pubkey (assuan_context_t ctx, struct ga_key_list *key)
{
  char line[ASSUAN_LINELENGTH];
  membuf_t data;
  unsigned char *databuf;
  size_t datalen;
  gpg_error_t err = 0;

  init_membuf (&data, 256);

  snprintf (line, DIM(line), "READKEY --format=ssh %s", key->keygrip);
  err = assuan_transact (ctx, line, put_second_field_cb, &data,
                         NULL, NULL, NULL, NULL);
  databuf = get_membuf (&data, &datalen);

  if (!err)
    {
      key->pubkey_len = datalen;
      key->pubkey = databuf;
    }
  else
    xfree (databuf);

  return err;
}


static gpg_error_t
ga_scd_get_auth_keys (assuan_context_t ctx, struct ga_key_list **r_key_list)
{
  gpg_error_t err;
  struct ga_key_list *kl, *key_list = NULL;

  /* Get list of auth keys with their keygrips.  */
  err = scd_keyinfo_list (ctx, &key_list);

  /* And retrieve public key for each key.  */
  kl = key_list;
  while (kl)
    {
      err = scd_get_pubkey (ctx, kl);
      if (err)
        break;
      kl = kl->next;
    }

  if (err)
    ga_release_auth_keys (key_list);
  else
    *r_key_list = key_list;

  return err;
}

struct ssh_key_list {
  struct ssh_key_list *next;
  char *pubkey; /* Public key in SSH format.   */
  char *comment;
};

static void
release_ssh_key_list (struct ssh_key_list *key_list)
{
  struct ssh_key_list *key;

  while (key_list)
    {
      key = key_list;
      key_list = key_list->next;
      xfree (key->pubkey);
      xfree (key->comment);
      xfree (key);
    }
}

static gpg_error_t
ssh_authorized_keys (const char *user, struct ssh_key_list **r_ssh_key_list)
{
  gpg_error_t err = 0;
  char *fname = NULL;
  estream_t fp = NULL;
  char *line = NULL;
  size_t length_of_line = 0;
  size_t  maxlen;
  ssize_t len;
  const char *fields[3];
  struct ssh_key_list *ssh_key_list = NULL;
  struct ssh_key_list *ssh_key_prev = NULL;
  struct ssh_key_list *ssh_key = NULL;

  if (user)
    {
      char tilde_user[256];

      snprintf (tilde_user, sizeof tilde_user, "~%s", user);
      fname = make_absfilename_try (tilde_user, ".ssh", "authorized_keys", NULL);
    }
  else
    fname = make_absfilename_try ("~", ".ssh", "authorized_keys", NULL);

  if (fname == NULL)
    return gpg_error (GPG_ERR_INV_NAME);

  fp = es_fopen (fname, "r");
  if (!fp)
    {
      err = gpg_error_from_syserror ();
      xfree (fname);
      return err;
    }
  xfree (fname);

  maxlen = 2048; /* Set limit.  */
  while ((len = es_read_line (fp, &line, &length_of_line, &maxlen)) > 0)
    {
      if (!maxlen)
        {
          err = gpg_error (GPG_ERR_LINE_TOO_LONG);
          log_error (_("error reading '%s': %s\n"), fname, gpg_strerror (err));
          goto leave;
        }

      /* Strip newline and carriage return, if present.  */
      while (len > 0 && (line[len - 1] == '\n' || line[len - 1] == '\r'))
	line[--len] = '\0';

      fields[2] = NULL;
      if (split_fields (line, fields, DIM (fields)) < 2)
        continue; /* Skip empty lines or line with only a field.  */
      if (*fields[0] == '#')
        continue; /* Skip comments.  */

      ssh_key = xtrycalloc (1, sizeof *ssh_key);
      if (!ssh_key)
        {
          err = gpg_error_from_syserror ();
          release_ssh_key_list (ssh_key_list);
          goto leave;
        }

      ssh_key->pubkey = strdup (fields[1]);
      ssh_key->comment = strdup (fields[2]);
      if (ssh_key_list)
        ssh_key_prev->next = ssh_key;
      else
        ssh_key_list = ssh_key;

      ssh_key_prev = ssh_key;
    }

  *r_ssh_key_list = ssh_key_list;

 leave:
  xfree (line);
  es_fclose (fp);
  return err;
}

static gpg_error_t
ga_filter_by_authorized_keys (const char *user, struct ga_key_list **r_key_list)
{
  gpg_error_t err;
  struct ga_key_list *cur = *r_key_list;
  struct ga_key_list *key_list = NULL;
  struct ga_key_list *prev = NULL;
  struct ssh_key_list *ssh_key_list = NULL;

  err = ssh_authorized_keys (user, &ssh_key_list);
  if (err)
    return err;

  if (ssh_key_list == NULL)
    return gpg_error (GPG_ERR_NOT_FOUND);

  while (cur)
    {
      struct ssh_key_list *skl = ssh_key_list;

      while (skl)
        if (!strncmp (cur->pubkey, skl->pubkey, cur->pubkey_len))
          break;
        else
          skl = skl->next;

      /* valid? */
      if (skl)
        {
          if (key_list)
            prev->next = cur;
          else
            key_list = cur;
          cur->comment = skl->comment;
          skl->comment = NULL;
          prev = cur;
          cur = cur->next;
        }
      else
        {
          struct ga_key_list *k = cur;

          cur = cur->next;
          xfree (k->pubkey);
          xfree (k);
        }
    }

  if (prev && prev->next)
    prev->next = NULL;

  release_ssh_key_list (ssh_key_list);
  *r_key_list = key_list;
  return 0;
}

static void
ga_release_auth_keys (struct ga_key_list *key_list)
{
  struct ga_key_list *key;

  while (key_list)
    {
      key = key_list;
      key_list = key_list->next;
      xfree (key->pubkey);
      xfree (key);
    }
}

static int
getpin (const char *comment, const char *info, char *buf, size_t *r_len)
{
  int rc = 0;
  char line[ASSUAN_LINELENGTH];
  const char *fields[2];

  (void)info;

  if (comment)
    {
      int msg_len = 29 + strlen (comment);
      fprintf (stdout, "P %d\n", msg_len);
      fprintf (stdout, "Please input PIN for KEY (%s): \n", comment);
      fflush (stdout);
    }
  else
    {
      fputs ("P 18\n", stdout);
      fputs ("Please input PIN: \n", stdout);
      fflush (stdout);
    }

  fgets (line, ASSUAN_LINELENGTH, stdin);
  if (split_fields (line, fields, DIM (fields)) < DIM (fields))
    rc = GPG_ERR_PROTOCOL_VIOLATION;
  else if (strcmp (fields[0], "p") != 0)
    rc = GPG_ERR_CANCELED;
  if (!fgets (line, ASSUAN_LINELENGTH, stdin))
    rc = GPG_ERR_PROTOCOL_VIOLATION;
  if (!rc)
    {
      size_t len = strlen (line);

      /* Strip newline and carriage return, if present.  */
      while (len > 0 && (line[len - 1] == '\n' || line[len - 1] == '\r'))
        line[--len] = '\0';

      len++;			/* Include last '\0' in the data.  */
      if (len > *r_len)
        rc = GPG_ERR_BUFFER_TOO_SHORT;
      else
        memcpy (buf, line, len);
      *r_len = len;
    }

  return rc;
}


static gpg_error_t
scd_pkauth (assuan_context_t ctx, const char *keygrip)
{
  char line[ASSUAN_LINELENGTH];
  gpg_error_t err;

  snprintf (line, DIM(line), "PKAUTH --challenge-response %s", keygrip);
  err = assuan_transact (ctx, line, NULL, NULL, inq_needpin, ctx,
                         NULL, NULL);
  return err;
}
