/* decrypt.c - decrypt and verify data
 * Copyright (C) 1998, 1999, 2000, 2001, 2002, 2003, 2004, 2005, 2006,
 *               2007, 2009 Free Software Foundation, Inc.
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

#include "gpg.h"
#include "options.h"
#include "packet.h"
#include "../common/status.h"
#include "../common/iobuf.h"
#include "keydb.h"
#include "../common/util.h"
#include "main.h"
#include "../common/status.h"
#include "../common/i18n.h"

/* Assume that the input is an encrypted message and decrypt
 * (and if signed, verify the signature on) it.
 * This command differs from the default operation, as it never
 * writes to the filename which is included in the file and it
 * rejects files which don't begin with an encrypted message.
 */
int
decrypt_message (ctrl_t ctrl, const char *filename)
{
  IOBUF fp;
  armor_filter_context_t *afx = NULL;
  progress_filter_context_t *pfx;
  int rc;
  int no_out = 0;

  pfx = new_progress_context ();

  /* Open the message file.  */
  fp = iobuf_open (filename);
  if (fp && is_secured_file (iobuf_get_fd (fp)))
    {
      iobuf_close (fp);
      fp = NULL;
      gpg_err_set_errno (EPERM);
    }
  if ( !fp )
    {
      rc = gpg_error_from_syserror ();
      log_error (_("can't open '%s': %s\n"), print_fname_stdin(filename),
                 gpg_strerror (rc));
      release_progress_context (pfx);
      return rc;
    }

  handle_progress (pfx, fp, filename);

  if ( !opt.no_armor )
    {
      if ( use_armor_filter( fp ) )
        {
          afx = new_armor_context ();
          push_armor_filter ( afx, fp );
	}
    }

  if (!opt.outfile)
    {
      no_out = 1;
      opt.outfile = "-";
    }
  rc = proc_encryption_packets (ctrl, NULL, fp );
  if (no_out)
    opt.outfile = NULL;

  iobuf_close (fp);
  release_armor_context (afx);
  release_progress_context (pfx);
  return rc;
}


/* Same as decrypt_message but takes a file descriptor for input and
   output.  */
gpg_error_t
decrypt_message_fd (ctrl_t ctrl, int input_fd, int output_fd)
{
#ifdef HAVE_W32_SYSTEM
  /* No server mode yet.  */
  (void)ctrl;
  (void)input_fd;
  (void)output_fd;
  return gpg_error (GPG_ERR_NOT_IMPLEMENTED);
#else
  gpg_error_t err;
  IOBUF fp;
  armor_filter_context_t *afx = NULL;
  progress_filter_context_t *pfx;

  if (opt.outfp)
    return gpg_error (GPG_ERR_BUG);

  pfx = new_progress_context ();

  /* Open the message file.  */
  fp = iobuf_fdopen_nc (FD2INT(input_fd), "rb");
  if (fp && is_secured_file (iobuf_get_fd (fp)))
    {
      iobuf_close (fp);
      fp = NULL;
      gpg_err_set_errno (EPERM);
    }
  if (!fp)
    {
      char xname[64];

      err = gpg_error_from_syserror ();
      snprintf (xname, sizeof xname, "[fd %d]", input_fd);
      log_error (_("can't open '%s': %s\n"), xname, gpg_strerror (err));
      release_progress_context (pfx);
      return err;
    }

#ifdef HAVE_W32CE_SYSTEM
#warning Need to fix this if we want to use g13
  opt.outfp = NULL;
#else
  opt.outfp = es_fdopen_nc (output_fd, "wb");
#endif
  if (!opt.outfp)
    {
      char xname[64];

      err = gpg_error_from_syserror ();
      snprintf (xname, sizeof xname, "[fd %d]", output_fd);
      log_error (_("can't open '%s': %s\n"), xname, gpg_strerror (err));
      iobuf_close (fp);
      release_progress_context (pfx);
      return err;
    }

  if (!opt.no_armor)
    {
      if (use_armor_filter (fp))
        {
          afx = new_armor_context ();
          push_armor_filter ( afx, fp );
	}
    }

  err = proc_encryption_packets (ctrl, NULL, fp );

  iobuf_close (fp);
  es_fclose (opt.outfp);
  opt.outfp = NULL;
  release_armor_context (afx);
  release_progress_context (pfx);
  return err;
#endif
}


void
decrypt_messages (ctrl_t ctrl, int nfiles, char *files[])
{
  IOBUF fp;
  progress_filter_context_t *pfx;
  char *p, *output = NULL;
  int rc=0,use_stdin=0;
  unsigned int lno=0;

  if (opt.outfile)
    {
      log_error(_("--output doesn't work for this command\n"));
      return;
    }

  pfx = new_progress_context ();

  if(!nfiles)
    use_stdin=1;

  for(;;)
    {
      char line[2048];
      char *filename=NULL;

      if(use_stdin)
	{
	  if(fgets(line, DIM(line), stdin))
	    {
	      lno++;
	      if (!*line || line[strlen(line)-1] != '\n')
		log_error("input line %u too long or missing LF\n", lno);
	      else
		{
		  line[strlen(line)-1] = '\0';
		  filename=line;
		}
	    }
	}
      else
	{
	  if(nfiles)
	    {
	      filename=*files;
	      nfiles--;
	      files++;
	    }
	}

      if(filename==NULL)
	break;

      print_file_status(STATUS_FILE_START, filename, 3);
      output = make_outfile_name(filename);
      if (!output)
        goto next_file;
      fp = iobuf_open(filename);
      if (fp)
        iobuf_ioctl (fp, IOBUF_IOCTL_NO_CACHE, 1, NULL);
      if (fp && is_secured_file (iobuf_get_fd (fp)))
        {
          iobuf_close (fp);
          fp = NULL;
          gpg_err_set_errno (EPERM);
        }
      if (!fp)
        {
          log_error(_("can't open '%s'\n"), print_fname_stdin(filename));
          goto next_file;
        }

      handle_progress (pfx, fp, filename);

      if (!opt.no_armor)
        {
          if (use_armor_filter(fp))
            {
              armor_filter_context_t *afx = new_armor_context ();
              rc = push_armor_filter (afx, fp);
              if (rc)
                log_error("failed to push armor filter");
              release_armor_context (afx);
            }
        }
      rc = proc_packets (ctrl,NULL, fp);
      iobuf_close(fp);
      if (rc)
        log_error("%s: decryption failed: %s\n", print_fname_stdin(filename),
                  gpg_strerror (rc));
      p = get_last_passphrase();
      set_next_passphrase(p);
      xfree (p);

    next_file:
      /* Note that we emit file_done even after an error. */
      write_status( STATUS_FILE_DONE );
      xfree(output);
      reset_literals_seen();
    }

  set_next_passphrase(NULL);
  release_progress_context (pfx);
}
