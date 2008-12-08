/* gpgkey2ssh.c - Converter  (Debug helper)
 *	Copyright (C) 2005 Free Software Foundation, Inc.
 *
 * This file is part of GnuPG.
 *
 * GnuPG is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 *
 * GnuPG is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
 * or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public
 * License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, see <http://www.gnu.org/licenses/>.
 */

/* 
   FIXME:  This tool needs some cleanup:

   - Do not use assert() for error output.
   - Add proper option parsing and standard options.
   - retrieve_key_material needs to take the ordinal at field 1 in account.
   0 Write a man page.
*/

#include <config.h>

#include <gcrypt.h>
#include <unistd.h>
#include <stdlib.h>
#include <assert.h>
#include <stdio.h>
#include <errno.h>

#include "util.h"
#include "sysutils.h"



typedef struct pkdbuf
{
  unsigned char *buffer;
  size_t buffer_n;
} pkdbuf_t;



/* Retrieve the public key material for the RSA key, whose fingerprint
   is FPR, from gpg output, which can be read through the stream FP.
   The RSA modulus will be stored at the address of M and MLEN, the
   public exponent at E and ELEN.  Returns zero on success, an error
   code on failure.  Caller must release the allocated buffers at M
   and E if the function returns success.  */
static gpg_error_t
retrieve_key_material (FILE *fp, const char *hexkeyid, int *algorithm_id,
		       pkdbuf_t **pkdbuf, size_t *pkdbuf_n)
{
  pkdbuf_t *pkdbuf_new;
  pkdbuf_t *pkdbuf_tmp;
  size_t pkdbuf_new_n;
  gcry_error_t err = 0;
  char *line = NULL;    /* read_line() buffer. */
  size_t line_size = 0; /* Helper for for read_line. */
  int found_key = 0;    /* Helper to find a matching key. */
  int id;
  unsigned char *buffer;
  size_t buffer_n;
  int i;

  pkdbuf_new = NULL;
  pkdbuf_new_n = 0;
  id = 0;

  /* Loop over all records until we have found the subkey
     corresponsing to the fingerprint. Inm general the first record
     should be the pub record, but we don't rely on that.  Given that
     we only need to look at one key, it is sufficient to compare the
     keyid so that we don't need to look at "fpr" records. */
  for (;;)
    {
      char *p;
      char *fields[6];
      int nfields;
      size_t max_length;
      gcry_mpi_t mpi;

      max_length = 4096;
      i = read_line (fp, &line, &line_size, &max_length);
      if (!i)
        break; /* EOF. */
      if (i < 0)
	{
	  err = gpg_error_from_syserror ();
	  goto leave; /* Error. */
	}
      if (!max_length)
        {
          err = gpg_error (GPG_ERR_TRUNCATED);
          goto leave;  /* Line truncated - we better stop processing.  */
        }

      /* Parse the line into fields. */
      for (nfields=0, p=line; p && nfields < DIM (fields); nfields++)
        {
          fields[nfields] = p;
          p = strchr (p, ':');
          if (p)
            *(p++) = 0;
        }
      if (!nfields)
        continue; /* No fields at all - skip line.  */

      if (!found_key)
        {
          if ( (!strcmp (fields[0], "sub") || !strcmp (fields[0], "pub") )
               && nfields > 4 &&
	       (((strlen (hexkeyid) == 8)
		 && (strlen (fields[4]) == 16)
		 && (! strcmp (fields[4] + 8, hexkeyid)))
		|| ((strlen (hexkeyid) == 16)
		    && (! strcmp (fields[4], hexkeyid)))))
	    {
	      found_key = 1;
	      /* Save algorithm ID.  */
	      id = atoi (fields[3]);
	    }
          continue;
      	}
      
      if ( !strcmp (fields[0], "sub") || !strcmp (fields[0], "pub") )
        break; /* Next key - stop.  */

      if ( strcmp (fields[0], "pkd") )
        continue; /* Not a key data record.  */

      /* FIXME, necessary?  */

      i = atoi (fields[1]);
      if ((nfields < 4) || (i < 0))
        {
          err = gpg_error (GPG_ERR_GENERAL);
	  goto leave;
        }

      err = gcry_mpi_scan (&mpi, GCRYMPI_FMT_HEX, fields[3], 0, NULL);
      if (err)
        mpi = NULL;

      err = gcry_mpi_aprint (GCRYMPI_FMT_STD, &buffer, &buffer_n, mpi);
      gcry_mpi_release (mpi);
      if (err)
	goto leave;

      pkdbuf_tmp = xrealloc (pkdbuf_new, sizeof (*pkdbuf_new) * (pkdbuf_new_n + 1));
      if (pkdbuf_new != pkdbuf_tmp)
	pkdbuf_new = pkdbuf_tmp;
      pkdbuf_new[pkdbuf_new_n].buffer = buffer;
      pkdbuf_new[pkdbuf_new_n].buffer_n = buffer_n;
      pkdbuf_new_n++;
    }

  *algorithm_id = id;
  *pkdbuf = pkdbuf_new;
  *pkdbuf_n = pkdbuf_new_n;

 leave:

  if (err)
    if (pkdbuf_new)
      {
	for (i = 0; i < pkdbuf_new_n; i++)
	  xfree (pkdbuf_new[i].buffer);
	xfree (pkdbuf_new);
      }
  xfree (line);

  return err;
}



int
key_to_blob (unsigned char **blob, size_t *blob_n, const char *identifier, ...)
{
  unsigned char *blob_new;
  size_t blob_new_n;
  unsigned char uint32_buffer[4];
  u32 identifier_n;
  FILE *stream;
  va_list ap;
  int ret;
  pkdbuf_t *pkd;

  stream = gnupg_tmpfile ();
  assert (stream);

  identifier_n = strlen (identifier);
  uint32_buffer[0] = identifier_n >> 24;
  uint32_buffer[1] = identifier_n >> 16;
  uint32_buffer[2] = identifier_n >>  8;
  uint32_buffer[3] = identifier_n >>  0;
  ret = fwrite (uint32_buffer, sizeof (uint32_buffer), 1, stream);
  assert (ret == 1);
  ret = fwrite (identifier, identifier_n, 1, stream);
  assert (ret == 1);

  va_start (ap, identifier);
  while (1)
    {
      pkd = va_arg (ap, pkdbuf_t *);
      if (! pkd)
	break;

      uint32_buffer[0] = pkd->buffer_n >> 24;
      uint32_buffer[1] = pkd->buffer_n >> 16;
      uint32_buffer[2] = pkd->buffer_n >>  8;
      uint32_buffer[3] = pkd->buffer_n >>  0;
      ret = fwrite (uint32_buffer, sizeof (uint32_buffer), 1, stream);
      assert (ret == 1);
      ret = fwrite (pkd->buffer, pkd->buffer_n, 1, stream);
      assert (ret == 1);
    }

  blob_new_n = ftell (stream);
  rewind (stream);

  blob_new = xmalloc (blob_new_n);
  ret = fread (blob_new, blob_new_n, 1, stream);
  assert (ret == 1);

  *blob = blob_new;
  *blob_n = blob_new_n;

  fclose (stream);

  return 0;
}

int
main (int argc, char **argv)
{
  const char *keyid;
  int algorithm_id;
  pkdbuf_t *pkdbuf;
  size_t pkdbuf_n;
  char *command;
  FILE *fp;
  int ret;
  gcry_error_t err;
  unsigned char *blob;
  size_t blob_n;
  struct b64state b64_state;
  const char *identifier;

  pkdbuf = NULL;
  pkdbuf_n = 0;

  algorithm_id = 0;  /* (avoid cc warning) */
  identifier = NULL; /* (avoid cc warning) */

  assert (argc == 2);

  keyid = argv[1];

  ret = asprintf (&command,
		  "gpg --list-keys --with-colons --with-key-data '%s'",
		  keyid);
  assert (ret > 0);

  fp = popen (command, "r");
  assert (fp);

  err = retrieve_key_material (fp, keyid, &algorithm_id, &pkdbuf, &pkdbuf_n);
  assert (! err);
  assert ((algorithm_id == 1) || (algorithm_id == 17));

  if (algorithm_id == 1)
    {
      identifier = "ssh-rsa";
      ret = key_to_blob (&blob, &blob_n, identifier,
			 &pkdbuf[1], &pkdbuf[0], NULL);
    }
  else if (algorithm_id == 17)
    {
      identifier = "ssh-dss";
      ret = key_to_blob (&blob, &blob_n, identifier,
			 &pkdbuf[0], &pkdbuf[1], &pkdbuf[2], &pkdbuf[3], NULL);
    }
  assert (! ret);

  printf ("%s ", identifier);

  err = b64enc_start (&b64_state, stdout, "");
  assert (! err);
  err = b64enc_write (&b64_state, blob, blob_n);
  assert (! err);
  err = b64enc_finish (&b64_state);
  assert (! err);

  printf (" COMMENT\n");

  return 0;
}
