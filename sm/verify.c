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

/* FIXME: Move this to jnlib */
static char *
strtimestamp (time_t atime)
{
  char *buffer = xmalloc (15);
  
  if (atime < 0) 
    strcpy (buffer, "????" "-??" "-??");
  else if (!atime)
    strcpy (buffer, "none");
  else
    {
      struct tm *tp;
      
      tp = gmtime( &atime );
      sprintf (buffer, "%04d-%02d-%02d",
               1900+tp->tm_year, tp->tm_mon+1, tp->tm_mday);
    }
  return buffer;
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
      log_error (_("error finding writable keyDB: %s\n"), gnupg_strerror (rc));

  rc = keydb_insert_cert (kh, cert);
  if (rc)
    {
      log_error (_("error storing certificate: %s\n"), gnupg_strerror (rc));
    }
  keydb_release (kh);               
}



static void
print_integer (unsigned char *p)
{
  unsigned long len;

  if (!p)
    log_printf ("none");
  else
    {
      len = (p[0] << 24) | (p[1] << 16) | (p[2] << 8) | p[3];
      for (p+=4; len; len--, p++)
        log_printf ("%02X", *p);
    }
}

static void
print_time (time_t t)
{

  if (!t)
    log_printf ("none");
  else if ( t == (time_t)(-1) )
    log_printf ("error");
  else
    {
      struct tm *tp;

      tp = gmtime (&t);
      log_printf ("%04d-%02d-%02d %02d:%02d:%02d",
                  1900+tp->tm_year, tp->tm_mon+1, tp->tm_mday,
                  tp->tm_hour, tp->tm_min, tp->tm_sec);
      assert (!tp->tm_isdst);
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
gpgsm_verify (CTRL ctrl, int in_fd, int data_fd)
{
  int i, rc;
  Base64Context b64reader = NULL;
  KsbaError err;
  KsbaReader reader;
  KsbaCMS cms = NULL;
  KsbaStopReason stopreason;
  KsbaCert cert;
  KEYDB_HANDLE kh;
  GCRY_MD_HD data_md = NULL;
  int signer;
  const char *algoid;
  int algo;
  int is_detached;
  FILE *fp = NULL;

  kh = keydb_new (0);
  if (!kh)
    {
      log_error (_("failed to allocated keyDB handle\n"));
      rc = GNUPG_General_Error;
      goto leave;
    }


  fp = fdopen ( dup (in_fd), "rb");
  if (!fp)
    {
      log_error ("fdopen() failed: %s\n", strerror (errno));
      rc = seterr (IO_Error);
      goto leave;
    }

  rc = gpgsm_create_reader (&b64reader, ctrl, fp, &reader);
  if (rc)
    {
      log_error ("can't create reader: %s\n", gnupg_strerror (rc));
      goto leave;
    }

  cms = ksba_cms_new ();
  if (!cms)
    {
      rc = seterr (Out_Of_Core);
      goto leave;
    }

  err = ksba_cms_set_reader_writer (cms, reader, NULL);
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
          rc = GNUPG_Not_Implemented;
          goto leave;
        }

      if (stopreason == KSBA_SR_NEED_HASH
          || stopreason == KSBA_SR_BEGIN_DATA)
        { /* We are now able to enable the hash algorithms */
          for (i=0; (algoid=ksba_cms_get_digest_algo_list (cms, i)); i++)
            {
              algo = gcry_md_map_name (algoid);
              if (!algo)
                log_error ("unknown hash algorithm `%s'\n",
                           algoid? algoid:"?");
              else
                gcry_md_enable (data_md, algo);
            }
          if (is_detached)
            {
              if (data_fd == -1)
                {
                  log_error ("detached signature but no data given\n");
                  rc = GNUPG_Bad_Signature;
                  goto leave;
                }
              hash_data (data_fd, data_md);  
            }
        }
    }
  while (stopreason != KSBA_SR_READY);   

  if (data_fd != -1 && !is_detached)
    {
      log_error ("data given for a non-detached signature\n");
      rc = GNUPG_Conflict;
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
      time_t sigtime;
      unsigned char *serial;
      char *msgdigest = NULL;
      size_t msgdigestlen;

      err = ksba_cms_get_issuer_serial (cms, signer, &issuer, &serial);
      if (err)
        break;
      log_debug ("signer %d - issuer: `%s'\n", signer, issuer? issuer:"[NONE]");
      log_debug ("signer %d - serial: ", signer);
      print_integer (serial);
      log_printf ("\n");

      err = ksba_cms_get_signing_time (cms, signer, &sigtime);
      if (err)
        {
          log_debug ("error getting signing time: %s\n", ksba_strerror (err));
          sigtime = (time_t)-1;
        }
      log_debug ("signer %d - sigtime: ", signer);
      print_time (sigtime);  
      log_printf ("\n");


      err = ksba_cms_get_message_digest (cms, signer,
                                         &msgdigest, &msgdigestlen);
      if (err)
        break;

      algoid = ksba_cms_get_digest_algo (cms, signer);
      algo = gcry_md_map_name (algoid);
      log_debug ("signer %d - digest algo: %d\n", signer, algo);
      if ( !gcry_md_info (data_md, GCRYCTL_IS_ALGO_ENABLED, &algo, NULL) )
        {
          log_debug ("digest algo %d has not been enabled\n", algo);
          goto next_signer;
        }

      sigval = ksba_cms_get_sig_val (cms, signer);
      if (!sigval)
        {
          log_error ("no signature value available\n");
          goto next_signer;
        }
      log_debug ("signer %d - signature: `%s'\n", signer, sigval);

      /* Find the certificate of the signer */
      keydb_search_reset (kh);
      rc = keydb_search_issuer_sn (kh, issuer, serial);
      if (rc)
        {
          log_debug ("failed to find the certificate: %s\n",
                     gnupg_strerror(rc));
          goto next_signer;
        }

      rc = keydb_get_cert (kh, &cert);
      if (rc)
        {
          log_debug ("failed to get cert: %s\n", gnupg_strerror (rc));
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
              gpgsm_status (ctrl, STATUS_BADSIG, NULL);
              goto next_signer; 
            }
            
          md = gcry_md_open (algo, 0);
          if (!md)
            {
              log_error ("md_open failed: %s\n", gcry_strerror (-1));
              goto next_signer;
            }
          ksba_cms_set_hash_function (cms, HASH_FNC, md);
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
          log_error ("invalid signature: %s\n", gnupg_strerror (rc));
          gpgsm_status (ctrl, STATUS_BADSIG, NULL);
          goto next_signer;
        }
      log_debug ("signature okay - checking certs\n");
      gpgsm_status (ctrl, STATUS_GOODSIG, NULL);
      {
        char *buf, *fpr, *tstr;

        fpr = gpgsm_get_fingerprint_hexstring (cert, GCRY_MD_SHA1);
        tstr = strtimestamp (sigtime);
        buf = xmalloc ( strlen(fpr) + strlen (tstr) + 100);
        sprintf (buf, "%s %s %lu", fpr, tstr, (unsigned long)sigtime );
        xfree (tstr);
        xfree (fpr);
        gpgsm_status (ctrl, STATUS_VALIDSIG, buf);
        xfree (buf);
      }

      rc = gpgsm_validate_path (cert);
      if (rc)
        {
          log_error ("invalid certification path: %s\n", gnupg_strerror (rc));
          if (rc == GNUPG_Bad_Certificate_Path
              || rc == GNUPG_Bad_Certificate)
            gpgsm_status (ctrl, STATUS_TRUST_NEVER, NULL);
          else
            gpgsm_status (ctrl, STATUS_TRUST_UNDEFINED, NULL);
          goto next_signer;
        }
      log_info ("signature is good\n");
      gpgsm_status (ctrl, STATUS_TRUST_FULLY, NULL);
          

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
  gpgsm_destroy_reader (b64reader);
  keydb_release (kh); 
  gcry_md_close (data_md);
  if (fp)
    fclose (fp);
  return rc;
}


