/* verify.c - Verify a messages signature
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

/* FIXME: We need to write a generic reader callback which should be able
   to detect and convert base-64 */
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

/* fixme: duplicated from import.c */
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



static void
print_integer (unsigned char *p)
{
  unsigned long len;

  if (!p)
    printf ("none");
  else
    {
      len = (p[0] << 24) | (p[1] << 16) | (p[2] << 8) | p[3];
      for (p+=4; len; len--, p++)
        printf ("%02X", *p);
    }
}


static void
hash_data (int fd, GCRY_MD_HD md)
{
  FILE *fp;
  char buffer[4096];
  int nread;

  fp = fdopen ( dup (fd), "rb");
  if (!fp)
    {
      log_error ("fdopen(%d) failed: %s\n", fd, strerror (errno));
      return;
    }

  do 
    {
      nread = fread (buffer, 1, DIM(buffer), fp);
      gcry_md_write (md, buffer, nread);
    }
  while (nread);
  if (ferror (fp))
      log_error ("read error on fd %d: %s\n", fd, strerror (errno));
  fclose (fp);
}



/* Perform a verify operation.  To verify detached signatures, data_fd
   must be different than -1 */
int
gpgsm_verify (int in_fd, int data_fd)
{
  int i, rc;
  KsbaError err;
  KsbaReader reader = NULL;
  KsbaWriter writer = NULL;
  KsbaCMS cms = NULL;
  KsbaStopReason stopreason;
  KsbaCert cert;
  KEYDB_HANDLE kh;
  GCRY_MD_HD data_md = NULL;
  struct reader_cb_parm_s rparm;
  int signer;
  int algo;
  int is_detached;

  memset (&rparm, 0, sizeof rparm);

  kh = keydb_new (0);
  if (!kh)
    {
      log_error (_("failed to allocated keyDB handle\n"));
      rc = GPGSM_General_Error;
      goto leave;
    }


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
  writer = ksba_writer_new ();
  if (!reader || !writer)
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

  cms = ksba_cms_new ();
  if (!cms)
    {
      rc = seterr (Out_Of_Core);
      goto leave;
    }

  err = ksba_cms_set_reader_writer (cms, reader, writer);
  if (err)
    {
      log_debug ("ksba_cms_set_reader_writer failed: %s\n",
                 ksba_strerror (err));
      rc = map_ksba_err (err);
      goto leave;
    }

  data_md = gcry_md_open (0, 0);
  if (!data_md)
    {
      rc = map_gcry_err (gcry_errno());
      log_error ("md_open failed: %s\n", gcry_strerror (-1));
      goto leave;
    }

  is_detached = 0;
  do 
    {
      err = ksba_cms_parse (cms, &stopreason);
      if (err)
        {
          log_debug ("ksba_cms_parse failed: %s\n", ksba_strerror (err));
          rc = map_ksba_err (err);
          goto leave;
        }
      log_debug ("ksba_cms_parse - stop reason %d\n", stopreason);
      if (stopreason == KSBA_SR_NEED_HASH)
        {
          is_detached = 1;
          log_debug ("Detached signature\n");
        }
      if (stopreason == KSBA_SR_BEGIN_DATA)
        {
          log_error ("error: only detached signatures are supportted\n");
          rc = GPGSM_Not_Implemented;
          goto leave;
        }

      if (stopreason == KSBA_SR_NEED_HASH
          || stopreason == KSBA_SR_BEGIN_DATA)
        { /* We are now able to enable the hash algorithms */
          for (i=0; (algo = ksba_cms_get_digest_algo_list (cms, i)) >= 0; i++)
            {
              if (algo)
                gcry_md_enable (data_md, algo);
            }
          if (is_detached)
            {
              if (data_fd == -1)
                {
                  log_error ("detached signature but no data given\n");
                  rc = GPGSM_Bad_Signature;
                  goto leave;
                }
              hash_data (data_fd, data_md);  
            }
        }
    }
  while (stopreason != KSBA_SR_READY);   

  if (data_fd != -1 && !is_detached)
    {
      log_error ("data given for a non-detached signature");
      rc = GPGSM_Conflict;
      goto leave;
    }

  for (i=0; (cert=ksba_cms_get_cert (cms, i)); i++)
    {
      log_debug ("storing certifcate %d\n", i);
      /* Fixme: we should mark the stored certificates as temporary
         and put them in a cache first */
      store_cert (cert);
      ksba_cert_release (cert);
    }

  cert = NULL;
  err = 0;
  for (signer=0; signer < 1; signer++)
    {
      char *issuer = NULL;
      char *sigval = NULL;
      unsigned char *serial;
      char *msgdigest = NULL;
      size_t msgdigestlen;

      err = ksba_cms_get_issuer_serial (cms, signer, &issuer, &serial);
      if (err)
        break;
      printf ("signer %d - issuer: `%s'\n", signer, issuer? issuer:"[NONE]");
      printf ("signer %d - serial: ", signer);
      print_integer (serial);
      putchar ('\n');

      err = ksba_cms_get_message_digest (cms, signer,
                                         &msgdigest, &msgdigestlen);
      if (err)
        break;

      algo = ksba_cms_get_digest_algo (cms, signer);
      printf ("signer %d - digest algo: %d\n", signer, algo);
      if ( !gcry_md_info (data_md, GCRYCTL_IS_ALGO_ENABLED, &algo, NULL) )
        {
          log_debug ("digest algo %d has not been enabled\n", algo);
          goto next_signer;
        }

      sigval = ksba_cms_get_sig_val (cms, signer);
      printf ("signer %d - signature: `%s'\n",
              signer, sigval? sigval: "[ERROR]");

      /* Find the certificate of the signer */
      keydb_search_reset (kh);
      rc = keydb_search_issuer_sn (kh, issuer, serial);
      if (rc)
        {
          log_debug ("failed to find the certificate: %s\n",
                     gpgsm_strerror(rc));
          goto next_signer;
        }

      rc = keydb_get_cert (kh, &cert);
      if (rc)
        {
          log_debug ("failed to get cert: %s\n", gpgsm_strerror (rc));
          goto next_signer;
        }

      if (msgdigest)
        { /* Signed attributes are available. */
          GCRY_MD_HD md;
          unsigned char *s;

          /* check that the message digest in the signed attributes
             matches the one we calculated on the data */
          s = gcry_md_read (data_md, algo);
          if ( !s || !msgdigestlen
               || gcry_md_get_algo_dlen (algo) != msgdigestlen
               || !s || memcmp (s, msgdigest, msgdigestlen) )
            {
              log_error ("message digest attribute does not "
                         "match calculated one\n");
              goto next_signer; 
            }
            
          md = gcry_md_open (algo, 0);
          if (!md)
            {
              log_error ("md_open failed: %s\n", gcry_strerror (-1));
              goto next_signer;
            }
          ksba_cms_set_hash_function (cms, gcry_md_write, md);
          rc = ksba_cms_hash_signed_attrs (cms, signer);
          if (rc)
            {
              log_debug ("hashing signed attrs failed: %s\n",
                         ksba_strerror (rc));
              gcry_md_close (md);
              goto next_signer;
            }
          rc = gpgsm_check_cms_signature (cert, sigval, md, algo);
          gcry_md_close (md);
        }
      else
        {
          rc = gpgsm_check_cms_signature (cert, sigval, data_md, algo);
        }

      if (rc)
        {
          log_error ("invalid signature: %s\n", gpgsm_strerror (rc));
          goto next_signer;
        }
      log_debug ("signature okay - checking certs\n");
      rc = gpgsm_validate_path (cert);
      if (rc)
        {
          log_error ("invalid certification path: %s\n", gpgsm_strerror (rc));
          goto next_signer;
        }
      log_info ("signature is good\n");
          

    next_signer:
      rc = 0;
      xfree (issuer);
      xfree (serial);
      xfree (sigval);
      xfree (msgdigest);
      ksba_cert_release (cert);
      cert = NULL;
    }
  rc = 0;
  if (err)
    {
      log_debug ("ksba error: %s\n", ksba_strerror (err));
      rc = map_ksba_err (rc);
    }    



 leave:
  ksba_cms_release (cms);
  ksba_reader_release (reader);
  keydb_release (kh); 
  gcry_md_close (data_md);
  if (rparm.fp)
    fclose (rparm.fp);
  return rc;
}


