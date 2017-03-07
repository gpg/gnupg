/* be-encfs.c - The EncFS based backend
 * Copyright (C) 2009 Free Software Foundation, Inc.
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
#include <errno.h>
#include <unistd.h>
#include <assert.h>

#include "g13.h"
#include "../common/i18n.h"
#include "keyblob.h"
#include "be-encfs.h"
#include "runner.h"
#include "../common/sysutils.h"
#include "../common/exechelp.h"


/* Command values used to run the encfs tool.  */
enum encfs_cmds
  {
    ENCFS_CMD_CREATE,
    ENCFS_CMD_MOUNT,
    ENCFS_CMD_UMOUNT
  };


/* An object to keep the private state of the encfs tool.  It is
   released by encfs_handler_cleanup.  */
struct encfs_parm_s
{
  enum encfs_cmds cmd;  /* The current command. */
  tupledesc_t tuples;   /* NULL or the tuples object.  */
  char *mountpoint;     /* The mountpoint.  */
};
typedef struct encfs_parm_s *encfs_parm_t;


static gpg_error_t
send_cmd_bin (runner_t runner, const void *data, size_t datalen)
{
  return runner_send_line (runner, data, datalen);
}


static gpg_error_t
send_cmd (runner_t runner, const char *string)
{
  log_debug ("sending command  -->%s<--\n", string);
  return send_cmd_bin (runner, string, strlen (string));
}



static void
run_umount_helper (const char *mountpoint)
{
  gpg_error_t err;
  const char pgmname[] = FUSERMOUNT;
  const char *args[3];

  args[0] = "-u";
  args[1] = mountpoint;
  args[2] = NULL;

  err = gnupg_spawn_process_detached (pgmname, args, NULL);
  if (err)
    log_error ("failed to run '%s': %s\n",
               pgmname, gpg_strerror (err));
}


/* Handle one line of the encfs tool's output.  This function is
   allowed to modify the content of BUFFER.  */
static gpg_error_t
handle_status_line (runner_t runner, const char *line,
                    enum encfs_cmds cmd, tupledesc_t tuples)
{
  gpg_error_t err;

  /* Check that encfs understands our new options.  */
  if (!strncmp (line, "$STATUS$", 8))
    {
      for (line +=8; *line && spacep (line); line++)
        ;
      log_info ("got status '%s'\n", line);
      if (!strcmp (line, "fuse_main_start"))
        {
          /* Send a special error code back to let the caller know
             that everything has been setup by encfs.  */
          err = gpg_error (GPG_ERR_UNFINISHED);
        }
      else
        err = 0;
    }
  else if (!strncmp (line, "$PROMPT$", 8))
    {
      for (line +=8; *line && spacep (line); line++)
        ;
      log_info ("got prompt '%s'\n", line);
      if (!strcmp (line, "create_root_dir"))
        err = send_cmd (runner, cmd == ENCFS_CMD_CREATE? "y":"n");
      else if (!strcmp (line, "create_mount_point"))
        err = send_cmd (runner, "y");
      else if (!strcmp (line, "passwd")
               || !strcmp (line, "new_passwd"))
        {
          if (tuples)
            {
              size_t n;
              const void *value;

              value = find_tuple (tuples, KEYBLOB_TAG_ENCKEY, &n);
              if (!value)
                err = gpg_error (GPG_ERR_INV_SESSION_KEY);
              else if ((err = send_cmd_bin (runner, value, n)))
                {
                  if (gpg_err_code (err) == GPG_ERR_BUG
                      && gpg_err_source (err) == GPG_ERR_SOURCE_DEFAULT)
                    err = gpg_error (GPG_ERR_INV_SESSION_KEY);
                }
            }
          else
            err = gpg_error (GPG_ERR_NO_DATA);
        }
      else
        err = send_cmd (runner, ""); /* Default to send an empty line.  */
    }
  else if (strstr (line, "encfs: unrecognized option '"))
    err = gpg_error (GPG_ERR_INV_ENGINE);
  else
    err = 0;

  return err;
}


/* The main processing function as used by the runner.  */
static gpg_error_t
encfs_handler (void *opaque, runner_t runner, const char *status_line)
{
  encfs_parm_t parm = opaque;
  gpg_error_t err;

  if (!parm || !runner)
    return gpg_error (GPG_ERR_BUG);
  if (!status_line)
    {
      /* Runner requested internal flushing - nothing to do here. */
      return 0;
    }

  err = handle_status_line (runner, status_line, parm->cmd, parm->tuples);
  if (gpg_err_code (err) == GPG_ERR_UNFINISHED
      && gpg_err_source (err) == GPG_ERR_SOURCE_DEFAULT)
    {
      err = 0;
      /* No more need for the tuples.  */
      destroy_tupledesc (parm->tuples);
      parm->tuples = NULL;

      if (parm->cmd == ENCFS_CMD_CREATE)
        {
          /* The encfs tool keeps on running after creation of the
             container.  We don't want that and thus need to stop the
             encfs process. */
          run_umount_helper (parm->mountpoint);
          /* In case the umount helper does not work we try to kill
             the engine.  FIXME: We should figure out how to make
             fusermount work.  */
          runner_cancel (runner);
        }
    }

  return err;
}


/* Called by the runner to cleanup the private data. */
static void
encfs_handler_cleanup (void *opaque)
{
  encfs_parm_t parm = opaque;

  if (!parm)
    return;

  destroy_tupledesc (parm->tuples);
  xfree (parm->mountpoint);
  xfree (parm);
}


/* Run the encfs tool.  */
static gpg_error_t
run_encfs_tool (ctrl_t ctrl, enum encfs_cmds cmd,
                const char *rawdir, const char *mountpoint, tupledesc_t tuples,
                unsigned int *r_id)
{
  gpg_error_t err;
  encfs_parm_t parm;
  runner_t runner = NULL;
  int outbound[2] = { -1, -1 };
  int inbound[2]  = { -1, -1 };
  const char *pgmname;
  const char *argv[10];
  pid_t pid = (pid_t)(-1);
  int idx;

  (void)ctrl;

  parm = xtrycalloc (1, sizeof *parm);
  if (!parm)
    {
      err = gpg_error_from_syserror ();
      goto leave;
    }
  parm->cmd = cmd;
  parm->tuples = ref_tupledesc (tuples);
  parm->mountpoint = xtrystrdup (mountpoint);
  if (!parm->mountpoint)
    {
      err = gpg_error_from_syserror ();
      goto leave;
    }

  err = runner_new (&runner, "encfs");
  if (err)
    goto leave;

  err = gnupg_create_inbound_pipe (inbound, NULL, 0);
  if (!err)
    err = gnupg_create_outbound_pipe (outbound, NULL, 0);
  if (err)
    {
      log_error (_("error creating a pipe: %s\n"), gpg_strerror (err));
      goto leave;
    }

  pgmname = ENCFS;
  idx = 0;
  argv[idx++] = "-f";
  if (opt.verbose)
    argv[idx++] = "-v";
  argv[idx++] = "--stdinpass";
  argv[idx++] = "--annotate";
  argv[idx++] = rawdir;
  argv[idx++] = mountpoint;
  argv[idx++] = NULL;
  assert (idx <= DIM (argv));

  err = gnupg_spawn_process_fd (pgmname, argv,
                                outbound[0], -1, inbound[1], &pid);
  if (err)
    {
      log_error ("error spawning '%s': %s\n", pgmname, gpg_strerror (err));
      goto leave;
    }
  close (outbound[0]); outbound[0] = -1;
  close ( inbound[1]);  inbound[1] = -1;

  runner_set_fds (runner, inbound[0], outbound[1]);
  inbound[0] = -1;  /* Now owned by RUNNER.  */
  outbound[1] = -1; /* Now owned by RUNNER.  */

  runner_set_handler (runner, encfs_handler, encfs_handler_cleanup, parm);
  parm = NULL; /* Now owned by RUNNER.  */

  runner_set_pid (runner, pid);
  pid = (pid_t)(-1); /* The process is now owned by RUNNER.  */

  err = runner_spawn (runner);
  if (err)
    goto leave;

  *r_id = runner_get_rid (runner);
  log_info ("running '%s' in the background\n", pgmname);

 leave:
  if (inbound[0] != -1)
    close (inbound[0]);
  if (inbound[1] != -1)
    close (inbound[1]);
  if (outbound[0] != -1)
    close (outbound[0]);
  if (outbound[1] != -1)
    close (outbound[1]);
  if (pid != (pid_t)(-1))
    {
      gnupg_wait_process (pgmname, pid, 1, NULL);
      gnupg_release_process (pid);
    }
  runner_release (runner);
  encfs_handler_cleanup (parm);
  return err;
}





/* See be_get_detached_name for a description.  Note that the
   dispatcher code makes sure that NULL is stored at R_NAME before
   calling us. */
gpg_error_t
be_encfs_get_detached_name (const char *fname, char **r_name, int *r_isdir)
{
  char *result;

  if (!fname || !*fname)
    return gpg_error (GPG_ERR_INV_ARG);

  result = strconcat (fname, ".d", NULL);
  if (!result)
    return gpg_error_from_syserror ();
  *r_name = result;
  *r_isdir = 1;
  return 0;
}


/* Create a new session key and append it as a tuple to the memory
   buffer MB.

   The EncFS daemon takes a passphrase from stdin and internally
   mangles it by means of some KDF from OpenSSL.  We want to store a
   binary key but we need to make sure that certain characters are not
   used because the EncFS utility reads it from stdin and obviously
   acts on some of the characters.  This we replace CR (in case of an
   MSDOS version of EncFS), LF (the delimiter used by EncFS) and Nul
   (because it is unlikely to work).  We use 32 bytes (256 bit)
   because that is sufficient for the largest cipher (AES-256) and in
   addition gives enough margin for a possible entropy degradation by
   the KDF.  */
gpg_error_t
be_encfs_create_new_keys (membuf_t *mb)
{
  char *buffer;
  int i, j;

  /* Allocate a buffer of 32 bytes plus 8 spare bytes we may need to
     replace the unwanted values.  */
  buffer = xtrymalloc_secure (32+8);
  if (!buffer)
    return gpg_error_from_syserror ();

  /* Randomize the buffer.  STRONG random should be enough as it is a
     good compromise between security and performance.  The
     anticipated usage of this tool is the quite often creation of new
     containers and thus this should not deplete the system's entropy
     tool too much.  */
  gcry_randomize (buffer, 32+8, GCRY_STRONG_RANDOM);
  for (i=j=0; i < 32; i++)
    {
      if (buffer[i] == '\r' || buffer[i] == '\n' || buffer[i] == 0 )
        {
          /* Replace.  */
          if (j == 8)
            {
              /* Need to get more random.  */
              gcry_randomize (buffer+32, 8, GCRY_STRONG_RANDOM);
              j = 0;
            }
          buffer[i] = buffer[32+j];
          j++;
        }
    }

  /* Store the key.  */
  append_tuple (mb, KEYBLOB_TAG_ENCKEY, buffer, 32);

  /* Free the temporary buffer.  */
  wipememory (buffer, 32+8);  /*  A failsafe extra wiping.  */
  xfree (buffer);

  return 0;
}


/* Create the container described by the filename FNAME and the keyblob
   information in TUPLES. */
gpg_error_t
be_encfs_create_container (ctrl_t ctrl, const char *fname, tupledesc_t tuples,
                           unsigned int *r_id)
{
  gpg_error_t err;
  int dummy;
  char *containername = NULL;
  char *mountpoint = NULL;

  err = be_encfs_get_detached_name (fname, &containername, &dummy);
  if (err)
    goto leave;

  mountpoint = xtrystrdup ("/tmp/.#g13_XXXXXX");
  if (!mountpoint)
    {
      err = gpg_error_from_syserror ();
      goto leave;
    }
  if (!gnupg_mkdtemp (mountpoint))
    {
      err = gpg_error_from_syserror ();
      log_error (_("can't create directory '%s': %s\n"),
                 "/tmp/.#g13_XXXXXX", gpg_strerror (err));
      goto leave;
    }

  err = run_encfs_tool (ctrl, ENCFS_CMD_CREATE, containername, mountpoint,
                        tuples, r_id);

  /* In any case remove the temporary mount point.  */
  if (rmdir (mountpoint))
    log_error ("error removing temporary mount point '%s': %s\n",
               mountpoint, gpg_strerror (gpg_error_from_syserror ()));


 leave:
  xfree (containername);
  xfree (mountpoint);
  return err;
}


/* Mount the container described by the filename FNAME and the keyblob
   information in TUPLES.  On success the runner id is stored at R_ID. */
gpg_error_t
be_encfs_mount_container (ctrl_t ctrl,
                          const char *fname, const char *mountpoint,
                          tupledesc_t tuples, unsigned int *r_id)
{
  gpg_error_t err;
  int dummy;
  char *containername = NULL;

  if (!mountpoint)
    {
      log_error ("the encfs backend requires an explicit mountpoint\n");
      err = gpg_error (GPG_ERR_NOT_SUPPORTED);
      goto leave;
    }

  err = be_encfs_get_detached_name (fname, &containername, &dummy);
  if (err)
    goto leave;

  err = run_encfs_tool (ctrl, ENCFS_CMD_MOUNT, containername, mountpoint,
                        tuples, r_id);

 leave:
  xfree (containername);
  return err;
}
