/* import.c - Import certificates
 *	Copyright (C) 2001 Free Software Foundation, Inc.
 *
 * This file is part of GnuPG.
 *
 * GnuPG is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * GnuPG is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA
 */

#include <config.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h> 
#include <time.h>
#include <assert.h>

#include <gcrypt.h>
#include <ksba.h>

#include "gpgsm.h"
#include "keydb.h"
#include "i18n.h"

struct reader_cb_parm_s {
  FILE *fp;
};


static int
reader_cb (void *cb_value, char *buffer, size_t count, size_t *nread)
{
  struct reader_cb_parm_s *parm = cb_value;
  size_t n;
  int c = 0;

  *nread = 0;
  if (!buffer)
    return -1; /* not supported */

  for (n=0; n < count; n++)
    {
      c = getc (parm->fp);
      if (c == EOF)
        {
          if ( ferror (parm->fp) )
            return -1;
          if (n)
            break; /* return what we have before an EOF */
          return -1;
        }
      *(byte *)buffer++ = c;
    }

  *nread = n;
  return 0;
}


static void
store_cert (KsbaCert cert)
{
  KEYDB_HANDLE kh;
  int rc;

  kh = keydb_new (0);
  if (!kh)
    {
      log_error (_("failed to allocated keyDB handle\n"));
      return;
    }
  rc = keydb_locate_writable (kh, 0);
  if (rc)
      log_error (_("error finding writable keyDB: %s\n"), gpgsm_strerror (rc));

  rc = keydb_insert_cert (kh, cert);
  if (rc)
    {
      log_error (_("error storing certificate: %s\n"), gpgsm_strerror (rc));
    }
  keydb_release (kh);               
}




int
gpgsm_import (int in_fd)
{
  int rc;
  KsbaReader reader = NULL;
  KsbaCert cert = NULL;
  struct reader_cb_parm_s rparm;

  memset (&rparm, 0, sizeof rparm);

  rparm.fp = fdopen ( dup (in_fd), "rb");
  if (!rparm.fp)
    {
      log_error ("fdopen() failed: %s\n", strerror (errno));
      rc = seterr (IO_Error);
      goto leave;
    }

  /* setup a skaba reader which uses a callback function so that we can 
     strip off a base64 encoding when necessary */
  reader = ksba_reader_new ();
  if (!reader)
    {
      rc = seterr (Out_Of_Core);
      goto leave;
    }

  rc = ksba_reader_set_cb (reader, reader_cb, &rparm );
  if (rc)
    {
      ksba_reader_release (reader);
      rc = map_ksba_err (rc);
      goto leave;
    }

  cert = ksba_cert_new ();
  if (!cert)
    {
      rc = seterr (Out_Of_Core);
      goto leave;
    }

  rc = ksba_cert_read_der (cert, reader);
  if (rc)
    {
      rc = map_ksba_err (rc);
      goto leave;
    }

  if ( !gpgsm_validate_path (cert) )
    store_cert (cert);

 leave:
  ksba_cert_release (cert);
  ksba_reader_release (reader);
  if (rparm.fp)
    fclose (rparm.fp);
  return rc;
}


