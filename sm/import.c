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
print_integer (unsigned char *p)
{
  unsigned long len;

  if (!p)
    fputs ("none", stdout);
  else
    {
      len = (p[0] << 24) | (p[1] << 16) | (p[2] << 8) | p[3];
      for (p+=4; len; len--, p++)
        printf ("%02X", *p);
    }
}

static void
print_time (time_t t)
{

  if (!t)
    fputs ("none", stdout);
  else if ( t == (time_t)(-1) )
    fputs ("error", stdout);
  else
    {
      struct tm *tp;

      tp = gmtime (&t);
      printf ("%04d-%02d-%02d %02d:%02d:%02d",
              1900+tp->tm_year, tp->tm_mon+1, tp->tm_mday,
              tp->tm_hour, tp->tm_min, tp->tm_sec);
      assert (!tp->tm_isdst);
    }
}

static void
print_dn (char *p)
{

  if (!p)
    fputs ("error", stdout);
  else
    printf ("`%s'", p);
}

static void 
print_cert (KsbaCert cert)
{
  unsigned char *p;
  char *dn;
  time_t t;
    
  p = ksba_cert_get_serial (cert);
  fputs ("serial: ", stdout);
  print_integer (p);
  ksba_free (p);
  putchar ('\n');

  t = ksba_cert_get_validity (cert, 0);
  fputs ("notBefore: ", stdout);
  print_time (t);
  putchar ('\n');
  t = ksba_cert_get_validity (cert, 1);
  fputs ("notAfter: ", stdout);
  print_time (t);
  putchar ('\n');
    
  dn = ksba_cert_get_issuer (cert);
  fputs ("issuer: ", stdout);
  print_dn (dn);
  ksba_free (dn);
  putchar ('\n');
    
  dn = ksba_cert_get_subject (cert);
  fputs ("subject: ", stdout);
  print_dn (dn);
  ksba_free (dn);
  putchar ('\n');

  printf ("hash algo: %d\n", ksba_cert_get_digest_algo (cert));
}



static MPI
do_encode_md (GCRY_MD_HD md, int algo, size_t len, unsigned nbits,
	      const byte *asn, size_t asnlen)
{
    int nframe = (nbits+7) / 8;
    byte *frame;
    int i,n;
    MPI a;

    if( len + asnlen + 4  > nframe )
	log_bug("can't encode a %d bit MD into a %d bits frame\n",
		    (int)(len*8), (int)nbits);

    /* We encode the MD in this way:
     *
     *	   0  A PAD(n bytes)   0  ASN(asnlen bytes)  MD(len bytes)
     *
     * PAD consists of FF bytes.
     */
    frame = xmalloc (nframe);
    n = 0;
    frame[n++] = 0;
    frame[n++] = 1; /* block type */
    i = nframe - len - asnlen -3 ;
    assert( i > 1 );
    memset( frame+n, 0xff, i ); n += i;
    frame[n++] = 0;
    memcpy( frame+n, asn, asnlen ); n += asnlen;
    memcpy( frame+n, gcry_md_read(md, algo), len ); n += len;
    assert( n == nframe );
    gcry_mpi_scan ( &a, GCRYMPI_FMT_USG, frame, &nframe);
    xfree(frame);
    return a;
}




static void
check_selfsigned_cert (KsbaCert cert)
{
  /* OID for MD5 as defined in PKCS#1 (rfc2313) */
  static byte asn[18] = /* Object ID is 1.2.840.113549.2.5 (md5) */
  { 0x30, 0x20, 0x30, 0x0c, 0x06, 0x08, 0x2a, 0x86, 0x48,
    0x86, 0xf7, 0x0d, 0x02, 0x05, 0x05, 0x00, 0x04, 0x10
  };

  GCRY_MD_HD md;
  int rc, algo;
  GCRY_MPI frame;
  char *p;
  GCRY_SEXP s_sig, s_hash, s_pkey;

  algo = ksba_cert_get_digest_algo (cert);
  md = gcry_md_open (algo, 0);
  if (!md)
    {
      log_error ("md_open failed: %s\n", gcry_strerror (-1));
      return;
    }

  gcry_md_start_debug (md, "cert");
  rc = ksba_cert_hash (cert, gcry_md_write, md);
  if (rc)
    {
      log_error ("ksba_cert_hash failed: %s\n", ksba_strerror (rc));
      gcry_md_close (md);
      return;
    }
  gcry_md_final (md);

  p = ksba_cert_get_sig_val (cert);
  printf ("signature: %s\n", p);

  rc = gcry_sexp_sscan ( &s_sig, NULL, p, strlen(p));
  if (rc)
    {
      log_error ("gcry_sexp_scan failed: %s\n", gcry_strerror (rc));
      return;
    }
  /*gcry_sexp_dump (s_sig);*/


  /* FIXME: need to map the algo to the ASN OID - we assume a fixed
     one for now */
  frame = do_encode_md (md, algo, 16, 2048, asn, DIM(asn));

  /* put hash into the S-Exp s_hash */
  if ( gcry_sexp_build (&s_hash, NULL, "%m", frame) )
    BUG ();
  /*fputs ("hash:\n", stderr); gcry_sexp_dump (s_hash);*/
  _gcry_log_mpidump ("hash", frame);

  p = ksba_cert_get_public_key (cert);
  printf ("public key: %s\n", p);

  rc = gcry_sexp_sscan ( &s_pkey, NULL, p, strlen(p));
  if (rc)
    {
      log_error ("gcry_sexp_scan failed: %s\n", gcry_strerror (rc));
      return;
    }
  /*gcry_sexp_dump (s_pkey);*/
  
  rc = gcry_pk_verify (s_sig, s_hash, s_pkey);
  log_error ("gcry_pk_verify: %s\n", gcry_strerror (rc));

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

  print_cert (cert);
  check_selfsigned_cert (cert);


 leave:
  ksba_cert_release (cert);
  ksba_reader_release (reader);
  if (rparm.fp)
    fclose (rparm.fp);
  return rc;
}

