/* send-mail.c - Invoke sendmail or other delivery tool.
 * Copyright (C) 2016 g10 Code GmbH
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

#include "../common/util.h"
#include "../common/exectool.h"
#include "../common/sysutils.h"
#include "send-mail.h"


static gpg_error_t
run_sendmail (estream_t data)
{
  gpg_error_t err;
  const char pgmname[] = "/usr/lib/sendmail";
  const char *argv[3];

  argv[0] = "-oi";
  argv[1] = "-t";
  argv[2] = NULL;

  err = gnupg_exec_tool_stream (pgmname, argv, data, NULL, NULL, NULL, NULL);
  if (err)
    log_error ("running '%s' failed: %s\n", pgmname, gpg_strerror (err));
  return err;
}


/* Send the data in FP as mail.  */
gpg_error_t
send_mail (estream_t fp)
{
  return run_sendmail (fp);
}


/* Convenience function to write a mail to a named file. */
gpg_error_t
send_mail_to_file (estream_t fp, const char *fname)
{
  gpg_error_t err;
  estream_t outfp = NULL;
  char *buffer = NULL;
  size_t buffersize = 32 * 1024;
  size_t nbytes, nwritten;

  if (!fname)
    fname = "-";

  buffer = xtrymalloc (buffersize);
  if (!buffer)
    return gpg_error_from_syserror ();


  if (!strcmp (fname,"-"))
    {
      outfp = es_stdout;
      es_set_binary (es_stdout);
    }
  else
    {
      outfp = es_fopen (fname, "wb");
      if (!outfp)
        {
          err = gpg_error_from_syserror ();
          log_error ("error creating '%s': %s\n", fname, gpg_strerror (err));
          goto leave;
        }
    }

  for (;;)
    {
      if (es_read (fp, buffer, sizeof buffer, &nbytes))
        {
          err = gpg_error_from_syserror ();
          log_error ("error reading '%s': %s\n",
                     es_fname_get (fp), gpg_strerror (err));
          goto leave;
        }

      if (!nbytes)
        {
          err = 0;
          break; /* Ready.  */
        }

      if (es_write (outfp, buffer, nbytes, &nwritten))
        {
          err = gpg_error_from_syserror ();
          log_error ("error writing '%s': %s\n", fname, gpg_strerror (err));
          goto leave;
        }
      else if (nwritten != nbytes)
        {
          err = gpg_error (GPG_ERR_EIO);
          log_error ("error writing '%s': %s\n", fname, "short write");
          goto leave;
        }
    }


 leave:
  if (err)
    {
      if (outfp && outfp != es_stdout)
        {
          es_fclose (outfp);
          gnupg_remove (fname);
        }
    }
  else if (outfp && outfp != es_stdout && es_fclose (outfp))
    {
      err = gpg_error_from_syserror ();
      log_error ("error closing '%s': %s\n", fname, gpg_strerror (err));
    }

  xfree (buffer);
  return err;
}
