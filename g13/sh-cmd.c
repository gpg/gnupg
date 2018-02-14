/* sh-cmd.c - The Assuan server for g13-syshelp
 * Copyright (C) 2015 Werner Koch
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
 */

#include <config.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <errno.h>
#include <assert.h>

#include "g13-syshelp.h"
#include <assuan.h>
#include "../common/i18n.h"
#include "../common/asshelp.h"
#include "keyblob.h"


/* Local data for this server module.  A pointer to this is stored in
   the CTRL object of each connection.  */
struct server_local_s
{
  /* The Assuan context we are working on.  */
  assuan_context_t assuan_ctx;

  /* The malloced name of the device.  */
  char *devicename;

  /* A stream open for read of the device set by the DEVICE command or
     NULL if no DEVICE command has been used.  */
  estream_t devicefp;
};




/* Local prototypes.  */




/*
   Helper functions.
 */

/* Set an error and a description.  */
#define set_error(e,t) assuan_set_error (ctx, gpg_error (e), (t))
#define set_error_fail_cmd() set_error (GPG_ERR_NOT_INITIALIZED, \
                                        "not called via userv or unknown user")


/* Skip over options.  Blanks after the options are also removed.  */
static char *
skip_options (const char *line)
{
  while (spacep (line))
    line++;
  while ( *line == '-' && line[1] == '-' )
    {
      while (*line && !spacep (line))
        line++;
      while (spacep (line))
        line++;
    }
  return (char*)line;
}


/* Check whether the option NAME appears in LINE.  */
/* static int */
/* has_option (const char *line, const char *name) */
/* { */
/*   const char *s; */
/*   int n = strlen (name); */

/*   s = strstr (line, name); */
/*   if (s && s >= skip_options (line)) */
/*     return 0; */
/*   return (s && (s == line || spacep (s-1)) && (!s[n] || spacep (s+n))); */
/* } */


/* Helper to print a message while leaving a command.  */
static gpg_error_t
leave_cmd (assuan_context_t ctx, gpg_error_t err)
{
  if (err)
    {
      const char *name = assuan_get_command_name (ctx);
      if (!name)
        name = "?";
      if (gpg_err_source (err) == GPG_ERR_SOURCE_DEFAULT)
        log_error ("command '%s' failed: %s\n", name,
                   gpg_strerror (err));
      else
        log_error ("command '%s' failed: %s <%s>\n", name,
                   gpg_strerror (err), gpg_strsource (err));
    }
  return err;
}




/* The handler for Assuan OPTION commands.  */
static gpg_error_t
option_handler (assuan_context_t ctx, const char *key, const char *value)
{
  ctrl_t ctrl = assuan_get_pointer (ctx);
  gpg_error_t err = 0;

  (void)ctrl;
  (void)key;
  (void)value;

  if (ctrl->fail_all_cmds)
    err = set_error_fail_cmd ();
  else
    err = gpg_error (GPG_ERR_UNKNOWN_OPTION);

  return err;
}


/* The handler for an Assuan RESET command.  */
static gpg_error_t
reset_notify (assuan_context_t ctx, char *line)
{
  ctrl_t ctrl = assuan_get_pointer (ctx);

  (void)line;

  xfree (ctrl->server_local->devicename);
  ctrl->server_local->devicename = NULL;
  es_fclose (ctrl->server_local->devicefp);
  ctrl->server_local->devicefp = NULL;
  ctrl->devti = NULL;

  assuan_close_input_fd (ctx);
  assuan_close_output_fd (ctx);
  return 0;
}


static const char hlp_finddevice[] =
  "FINDDEVICE <name>\n"
  "\n"
  "Find the device matching NAME.  NAME be any identifier from\n"
  "g13tab permissible for the user.  The corresponding block\n"
  "device is returned using a status line.";
static gpg_error_t
cmd_finddevice (assuan_context_t ctx, char *line)
{
  ctrl_t ctrl = assuan_get_pointer (ctx);
  gpg_error_t err = 0;
  tab_item_t ti;
  const char *s;
  const char *name;

  name = skip_options (line);

  /* Are we allowed to use the given device?  We check several names:
   *  1. The full block device
   *  2. The label
   *  3. The final part of the block device if NAME does not have a slash.
   *  4. The mountpoint
   */
  for (ti=ctrl->client.tab; ti; ti = ti->next)
    if (!strcmp (name, ti->blockdev))
      break;
  if (!ti)
    {
      for (ti=ctrl->client.tab; ti; ti = ti->next)
        if (ti->label && !strcmp (name, ti->label))
          break;
    }
  if (!ti && !strchr (name, '/'))
    {
      for (ti=ctrl->client.tab; ti; ti = ti->next)
        {
          s = strrchr (ti->blockdev, '/');
          if (s && s[1] && !strcmp (name, s+1))
            break;
        }
    }
  if (!ti)
    {
      for (ti=ctrl->client.tab; ti; ti = ti->next)
        if (ti->mountpoint && !strcmp (name, ti->mountpoint))
          break;
    }

  if (!ti)
    {
      err = set_error (GPG_ERR_NOT_FOUND, "device not configured for user");
      goto leave;
    }

  /* Check whether we have permissions to open the device.  */
  {
    estream_t fp = es_fopen (ti->blockdev, "rb");
    if (!fp)
      {
        err = gpg_error_from_syserror ();
        log_error ("error opening '%s': %s\n",
                   ti->blockdev, gpg_strerror (err));
        goto leave;
      }
    es_fclose (fp);
  }

  err = g13_status (ctrl, STATUS_BLOCKDEV, ti->blockdev, NULL);
  if (err)
    return err;

 leave:
  return leave_cmd (ctx, err);
}


static const char hlp_device[] =
  "DEVICE <name>\n"
  "\n"
  "Set the device used by further commands.\n"
  "A device name or a PARTUUID string may be used.\n"
  "Access to that device (by the g13 system) is locked\n"
  "until a new DEVICE command or end of this process\n";
static gpg_error_t
cmd_device (assuan_context_t ctx, char *line)
{
  ctrl_t ctrl = assuan_get_pointer (ctx);
  gpg_error_t err = 0;
  tab_item_t ti;
  estream_t fp = NULL;

  line = skip_options (line);

/* # warning hardwired to /dev/sdb1 ! */
/*   if (strcmp (line, "/dev/sdb1")) */
/*     { */
/*       err = gpg_error (GPG_ERR_ENOENT); */
/*       goto leave; */
/*     } */

  /* Always close an open device stream of this session. */
  xfree (ctrl->server_local->devicename);
  ctrl->server_local->devicename = NULL;
  es_fclose (ctrl->server_local->devicefp);
  ctrl->server_local->devicefp = NULL;

  /* Are we allowed to use the given device?  */
  for (ti=ctrl->client.tab; ti; ti = ti->next)
    if (!strcmp (line, ti->blockdev))
      break;
  if (!ti)
    {
      err = set_error (GPG_ERR_EACCES, "device not configured for user");
      goto leave;
    }

  ctrl->server_local->devicename = xtrystrdup (line);
  if (!ctrl->server_local->devicename)
    {
      err = gpg_error_from_syserror ();
      goto leave;
    }


  /* Check whether we have permissions to open the device and keep an
     FD open.  */
  fp = es_fopen (ctrl->server_local->devicename, "rb");
  if (!fp)
    {
      err = gpg_error_from_syserror ();
      log_error ("error opening '%s': %s\n",
                 ctrl->server_local->devicename, gpg_strerror (err));
      goto leave;
    }

  es_fclose (ctrl->server_local->devicefp);
  ctrl->server_local->devicefp = fp;
  fp = NULL;
  ctrl->devti = ti;

  /* Fixme: Take some kind of lock.  */

 leave:
  es_fclose (fp);
  if (err)
    {
      xfree (ctrl->server_local->devicename);
      ctrl->server_local->devicename = NULL;
      ctrl->devti = NULL;
    }
  return leave_cmd (ctx, err);
}


static const char hlp_create[] =
  "CREATE <type>\n"
  "\n"
  "Create a new encrypted partition on the current device.\n"
  "<type> must be \"dm-crypt\" for now.";
static gpg_error_t
cmd_create (assuan_context_t ctx, char *line)
{
  ctrl_t ctrl = assuan_get_pointer (ctx);
  gpg_error_t err = 0;
  estream_t fp = NULL;

  line = skip_options (line);
  if (strcmp (line, "dm-crypt"))
    {
      err = set_error (GPG_ERR_INV_ARG, "Type must be \"dm-crypt\"");
      goto leave;
    }

  if (!ctrl->server_local->devicename
      || !ctrl->server_local->devicefp
      || !ctrl->devti)
    {
      err = set_error (GPG_ERR_ENOENT, "No device has been set");
      goto leave;
    }

  err = sh_is_empty_partition (ctrl->server_local->devicename);
  if (err)
    {
      if (gpg_err_code (err) == GPG_ERR_FALSE)
        err = gpg_error (GPG_ERR_CONFLICT);
      err = assuan_set_error (ctx, err, "Partition is not empty");
      goto leave;
    }

  /* We need a writeable stream to create the container.  */
  fp = es_fopen (ctrl->server_local->devicename, "r+b");
  if (!fp)
    {
      err = gpg_error_from_syserror ();
      log_error ("error opening '%s': %s\n",
                 ctrl->server_local->devicename, gpg_strerror (err));
      goto leave;
    }
  if (es_setvbuf (fp, NULL, _IONBF, 0))
    {
      err = gpg_error_from_syserror ();
      log_error ("error setting '%s' to _IONBF: %s\n",
                 ctrl->server_local->devicename, gpg_strerror (err));
      goto leave;
    }

  err = sh_dmcrypt_create_container (ctrl,
                                     ctrl->server_local->devicename,
                                     fp);
  if (es_fclose (fp))
    {
      gpg_error_t err2 = gpg_error_from_syserror ();
      log_error ("error closing '%s': %s\n",
                 ctrl->server_local->devicename, gpg_strerror (err2));
      if (!err)
        err = err2;
    }
  fp = NULL;

 leave:
  es_fclose (fp);
  return leave_cmd (ctx, err);
}


static const char hlp_getkeyblob[] =
  "GETKEYBLOB\n"
  "\n"
  "Return the encrypted keyblob of the current device.";
static gpg_error_t
cmd_getkeyblob (assuan_context_t ctx, char *line)
{
  ctrl_t ctrl = assuan_get_pointer (ctx);
  gpg_error_t err;
  void *enckeyblob = NULL;
  size_t enckeybloblen;

  line = skip_options (line);

  if (!ctrl->server_local->devicename
      || !ctrl->server_local->devicefp
      || !ctrl->devti)
    {
      err = set_error (GPG_ERR_ENOENT, "No device has been set");
      goto leave;
    }

  err = sh_is_empty_partition (ctrl->server_local->devicename);
  if (!err)
    {
      err = gpg_error (GPG_ERR_ENODEV);
      assuan_set_error (ctx, err, "Partition is empty");
      goto leave;
    }
  err = 0;

  err = g13_keyblob_read (ctrl->server_local->devicename,
                          &enckeyblob, &enckeybloblen);
  if (err)
    goto leave;

  err = assuan_send_data (ctx, enckeyblob, enckeybloblen);
  if (!err)
    err = assuan_send_data (ctx, NULL, 0); /* Flush  */

 leave:
  xfree (enckeyblob);
  return leave_cmd (ctx, err);
}


static const char hlp_mount[] =
  "MOUNT <type>\n"
  "\n"
  "Mount an encrypted partition on the current device.\n"
  "<type> must be \"dm-crypt\" for now.";
static gpg_error_t
cmd_mount (assuan_context_t ctx, char *line)
{
  ctrl_t ctrl = assuan_get_pointer (ctx);
  gpg_error_t err = 0;
  unsigned char *keyblob = NULL;
  size_t keybloblen;
  tupledesc_t tuples = NULL;

  line = skip_options (line);

  if (strcmp (line, "dm-crypt"))
    {
      err = set_error (GPG_ERR_INV_ARG, "Type must be \"dm-crypt\"");
      goto leave;
    }

  if (!ctrl->server_local->devicename
      || !ctrl->server_local->devicefp
      || !ctrl->devti)
    {
      err = set_error (GPG_ERR_ENOENT, "No device has been set");
      goto leave;
    }

  err = sh_is_empty_partition (ctrl->server_local->devicename);
  if (!err)
    {
      err = gpg_error (GPG_ERR_ENODEV);
      assuan_set_error (ctx, err, "Partition is empty");
      goto leave;
    }
  err = 0;

  /* We expect that the client already decrypted the keyblob.
   * Eventually we should move reading of the keyblob to here and ask
   * the client to decrypt it.  */
  assuan_begin_confidential (ctx);
  err = assuan_inquire (ctx, "KEYBLOB",
                        &keyblob, &keybloblen, 4 * 1024);
  assuan_end_confidential (ctx);
  if (err)
    {
      log_error (_("assuan_inquire failed: %s\n"), gpg_strerror (err));
      goto leave;
    }
  err = create_tupledesc (&tuples, keyblob, keybloblen);
  if (!err)
    keyblob = NULL;
  else
    {
      if (gpg_err_code (err) == GPG_ERR_NOT_SUPPORTED)
        log_error ("unknown keyblob version received\n");
      goto leave;
    }

  err = sh_dmcrypt_mount_container (ctrl,
                                    ctrl->server_local->devicename,
                                    tuples);

 leave:
  destroy_tupledesc (tuples);
  return leave_cmd (ctx, err);
}


static const char hlp_umount[] =
  "UMOUNT <type>\n"
  "\n"
  "Unmount an encrypted partition and wipe the key.\n"
  "<type> must be \"dm-crypt\" for now.";
static gpg_error_t
cmd_umount (assuan_context_t ctx, char *line)
{
  ctrl_t ctrl = assuan_get_pointer (ctx);
  gpg_error_t err = 0;

  line = skip_options (line);

  if (strcmp (line, "dm-crypt"))
    {
      err = set_error (GPG_ERR_INV_ARG, "Type must be \"dm-crypt\"");
      goto leave;
    }

  if (!ctrl->server_local->devicename
      || !ctrl->server_local->devicefp
      || !ctrl->devti)
    {
      err = set_error (GPG_ERR_ENOENT, "No device has been set");
      goto leave;
    }

  err = sh_dmcrypt_umount_container (ctrl, ctrl->server_local->devicename);

 leave:
  return leave_cmd (ctx, err);
}


static const char hlp_suspend[] =
  "SUSPEND <type>\n"
  "\n"
  "Suspend an encrypted partition and wipe the key.\n"
  "<type> must be \"dm-crypt\" for now.";
static gpg_error_t
cmd_suspend (assuan_context_t ctx, char *line)
{
  ctrl_t ctrl = assuan_get_pointer (ctx);
  gpg_error_t err = 0;

  line = skip_options (line);

  if (strcmp (line, "dm-crypt"))
    {
      err = set_error (GPG_ERR_INV_ARG, "Type must be \"dm-crypt\"");
      goto leave;
    }

  if (!ctrl->server_local->devicename
      || !ctrl->server_local->devicefp
      || !ctrl->devti)
    {
      err = set_error (GPG_ERR_ENOENT, "No device has been set");
      goto leave;
    }

  err = sh_is_empty_partition (ctrl->server_local->devicename);
  if (!err)
    {
      err = gpg_error (GPG_ERR_ENODEV);
      assuan_set_error (ctx, err, "Partition is empty");
      goto leave;
    }
  err = 0;

  err = sh_dmcrypt_suspend_container (ctrl, ctrl->server_local->devicename);

 leave:
  return leave_cmd (ctx, err);
}


static const char hlp_resume[] =
  "RESUME <type>\n"
  "\n"
  "Resume an encrypted partition and set the key.\n"
  "<type> must be \"dm-crypt\" for now.";
static gpg_error_t
cmd_resume (assuan_context_t ctx, char *line)
{
  ctrl_t ctrl = assuan_get_pointer (ctx);
  gpg_error_t err = 0;
  unsigned char *keyblob = NULL;
  size_t keybloblen;
  tupledesc_t tuples = NULL;

  line = skip_options (line);

  if (strcmp (line, "dm-crypt"))
    {
      err = set_error (GPG_ERR_INV_ARG, "Type must be \"dm-crypt\"");
      goto leave;
    }

  if (!ctrl->server_local->devicename
      || !ctrl->server_local->devicefp
      || !ctrl->devti)
    {
      err = set_error (GPG_ERR_ENOENT, "No device has been set");
      goto leave;
    }

  err = sh_is_empty_partition (ctrl->server_local->devicename);
  if (!err)
    {
      err = gpg_error (GPG_ERR_ENODEV);
      assuan_set_error (ctx, err, "Partition is empty");
      goto leave;
    }
  err = 0;

  /* We expect that the client already decrypted the keyblob.
   * Eventually we should move reading of the keyblob to here and ask
   * the client to decrypt it.  */
  assuan_begin_confidential (ctx);
  err = assuan_inquire (ctx, "KEYBLOB",
                        &keyblob, &keybloblen, 4 * 1024);
  assuan_end_confidential (ctx);
  if (err)
    {
      log_error (_("assuan_inquire failed: %s\n"), gpg_strerror (err));
      goto leave;
    }
  err = create_tupledesc (&tuples, keyblob, keybloblen);
  if (!err)
    keyblob = NULL;
  else
    {
      if (gpg_err_code (err) == GPG_ERR_NOT_SUPPORTED)
        log_error ("unknown keyblob version received\n");
      goto leave;
    }

  err = sh_dmcrypt_resume_container (ctrl,
                                     ctrl->server_local->devicename,
                                     tuples);

 leave:
  destroy_tupledesc (tuples);
  return leave_cmd (ctx, err);
}


static const char hlp_getinfo[] =
  "GETINFO <what>\n"
  "\n"
  "Multipurpose function to return a variety of information.\n"
  "Supported values for WHAT are:\n"
  "\n"
  "  version     - Return the version of the program.\n"
  "  pid         - Return the process id of the server.\n"
  "  showtab     - Show the table for the user.";
static gpg_error_t
cmd_getinfo (assuan_context_t ctx, char *line)
{
  ctrl_t ctrl = assuan_get_pointer (ctx);
  gpg_error_t err = 0;
  char *buf;

  if (!strcmp (line, "version"))
    {
      const char *s = PACKAGE_VERSION;
      err = assuan_send_data (ctx, s, strlen (s));
    }
  else if (!strcmp (line, "pid"))
    {
      char numbuf[50];

      snprintf (numbuf, sizeof numbuf, "%lu", (unsigned long)getpid ());
      err = assuan_send_data (ctx, numbuf, strlen (numbuf));
    }
  else if (!strncmp (line, "getsz", 5))
    {
      unsigned long long nblocks;
      err = sh_blockdev_getsz (line+6, &nblocks);
      if (!err)
        log_debug ("getsz=%llu\n", nblocks);
    }
  else if (!strcmp (line, "showtab"))
    {
      tab_item_t ti;

      for (ti=ctrl->client.tab; !err && ti; ti = ti->next)
        {
          buf = es_bsprintf ("%s %s%s %s %s%s\n",
                             ctrl->client.uname,
                             *ti->blockdev=='/'? "":"partuuid=",
                             ti->blockdev,
                             ti->label? ti->label : "-",
                             ti->mountpoint? " ":"",
                             ti->mountpoint? ti->mountpoint:"");
          if (!buf)
            err = gpg_error_from_syserror ();
          else
            {
              err = assuan_send_data (ctx, buf, strlen (buf));
              if (!err)
                err = assuan_send_data (ctx, NULL, 0); /* Flush  */
            }
          xfree (buf);
        }
    }
  else
    err = set_error (GPG_ERR_ASS_PARAMETER, "unknown value for WHAT");

  return leave_cmd (ctx, err);
}


/* This command handler is used for all commands if this process has
   not been started as expected.  */
static gpg_error_t
fail_command (assuan_context_t ctx, char *line)
{
  gpg_error_t err;
  const char *name = assuan_get_command_name (ctx);

  (void)line;

  if (!name)
    name = "?";

  err = set_error_fail_cmd ();
  log_error ("command '%s' failed: %s\n", name, gpg_strerror (err));
  return err;
}


/* Tell the Assuan library about our commands.  */
static int
register_commands (assuan_context_t ctx, int fail_all)
{
  static struct {
    const char *name;
    assuan_handler_t handler;
    const char * const help;
  } table[] =  {
    { "FINDDEVICE",    cmd_finddevice, hlp_finddevice },
    { "DEVICE",        cmd_device, hlp_device },
    { "CREATE",        cmd_create, hlp_create },
    { "GETKEYBLOB",    cmd_getkeyblob,  hlp_getkeyblob },
    { "MOUNT",         cmd_mount,  hlp_mount  },
    { "UMOUNT",        cmd_umount, hlp_umount  },
    { "SUSPEND",       cmd_suspend,hlp_suspend},
    { "RESUME",        cmd_resume, hlp_resume },
    { "INPUT",         NULL },
    { "OUTPUT",        NULL },
    { "GETINFO",       cmd_getinfo, hlp_getinfo },
    { NULL }
  };
  gpg_error_t err;
  int i;

  for (i=0; table[i].name; i++)
    {
      err = assuan_register_command (ctx, table[i].name,
                                     fail_all ? fail_command : table[i].handler,
                                     table[i].help);
      if (err)
        return err;
    }
  return 0;
}


/* Startup the server.  */
gpg_error_t
syshelp_server (ctrl_t ctrl)
{
  gpg_error_t err;
  assuan_fd_t filedes[2];
  assuan_context_t ctx = NULL;

  /* We use a pipe based server so that we can work from scripts.
     assuan_init_pipe_server will automagically detect when we are
     called with a socketpair and ignore FILEDES in this case. */
  filedes[0] = assuan_fdopen (0);
  filedes[1] = assuan_fdopen (1);
  err = assuan_new (&ctx);
  if (err)
    {
      log_error ("failed to allocate an Assuan context: %s\n",
                 gpg_strerror (err));
      goto leave;
    }

  err = assuan_init_pipe_server (ctx, filedes);
  if (err)
    {
      log_error ("failed to initialize the server: %s\n", gpg_strerror (err));
      goto leave;
    }

  err = register_commands (ctx, 0 /*FIXME:ctrl->fail_all_cmds*/);
  if (err)
    {
      log_error ("failed to the register commands with Assuan: %s\n",
                 gpg_strerror (err));
      goto leave;
    }

  assuan_set_pointer (ctx, ctrl);

  {
    char *tmp = xtryasprintf ("G13-syshelp %s ready to serve requests "
                              "from %lu(%s)",
                              PACKAGE_VERSION,
                              (unsigned long)ctrl->client.uid,
                              ctrl->client.uname);
    if (tmp)
      {
        assuan_set_hello_line (ctx, tmp);
        xfree (tmp);
      }
  }

  assuan_register_reset_notify (ctx, reset_notify);
  assuan_register_option_handler (ctx, option_handler);

  ctrl->server_local = xtrycalloc (1, sizeof *ctrl->server_local);
  if (!ctrl->server_local)
    {
      err = gpg_error_from_syserror ();
      goto leave;
    }
  ctrl->server_local->assuan_ctx = ctx;

  while ( !(err = assuan_accept (ctx)) )
    {
      err = assuan_process (ctx);
      if (err)
        log_info ("Assuan processing failed: %s\n", gpg_strerror (err));
    }
  if (err == -1)
    err = 0;
  else
    log_info ("Assuan accept problem: %s\n", gpg_strerror (err));

 leave:
  reset_notify (ctx, NULL);  /* Release all items hold by SERVER_LOCAL.  */
  if (ctrl->server_local)
    {
      xfree (ctrl->server_local);
      ctrl->server_local = NULL;
    }

  assuan_release (ctx);
  return err;
}


gpg_error_t
sh_encrypt_keyblob (ctrl_t ctrl, const void *keyblob, size_t keybloblen,
                    char **r_enckeyblob, size_t *r_enckeybloblen)
{
  assuan_context_t ctx = ctrl->server_local->assuan_ctx;
  gpg_error_t err;
  unsigned char *enckeyblob;
  size_t enckeybloblen;

  *r_enckeyblob = NULL;

  /* Send the plaintext.  */
  err = g13_status (ctrl, STATUS_PLAINTEXT_FOLLOWS, NULL);
  if (err)
    return err;
  assuan_begin_confidential (ctx);
  err = assuan_send_data (ctx, keyblob, keybloblen);
  if (!err)
    err = assuan_send_data (ctx, NULL, 0);
  assuan_end_confidential (ctx);
  if (!err)
    err = assuan_write_line (ctx, "END");
  if (err)
    {
      log_error (_("error sending data: %s\n"), gpg_strerror (err));
      return err;
    }

  /* Inquire the ciphertext.  */
  err = assuan_inquire (ctx, "ENCKEYBLOB",
                        &enckeyblob, &enckeybloblen, 16 * 1024);
  if (err)
    {
      log_error (_("assuan_inquire failed: %s\n"), gpg_strerror (err));
      return err;
    }

  *r_enckeyblob = enckeyblob;
  *r_enckeybloblen = enckeybloblen;
  return 0;
}


/* Send a status line with status ID NO.  The arguments are a list of
   strings terminated by a NULL argument.  */
gpg_error_t
g13_status (ctrl_t ctrl, int no, ...)
{
  gpg_error_t err;
  va_list arg_ptr;

  va_start (arg_ptr, no);

  err = vprint_assuan_status_strings (ctrl->server_local->assuan_ctx,
                                      get_status_string (no), arg_ptr);
  va_end (arg_ptr);
  return err;
}
