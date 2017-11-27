/* import.c - Import certificates
 * Copyright (C) 2001, 2003, 2004, 2009, 2010 Free Software Foundation, Inc.
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
#include <time.h>
#include <assert.h>
#include <unistd.h>

#include "gpgsm.h"
#include <gcrypt.h>
#include <ksba.h>

#include "keydb.h"
#include "../common/exechelp.h"
#include "../common/i18n.h"
#include "../common/sysutils.h"
#include "../kbx/keybox.h" /* for KEYBOX_FLAG_* */
#include "../common/membuf.h"
#include "minip12.h"

/* The arbitrary limit of one PKCS#12 object.  */
#define MAX_P12OBJ_SIZE 128 /*kb*/


struct stats_s {
  unsigned long count;
  unsigned long imported;
  unsigned long unchanged;
  unsigned long not_imported;
  unsigned long secret_read;
  unsigned long secret_imported;
  unsigned long secret_dups;
 };


struct rsa_secret_key_s
{
  gcry_mpi_t n;	    /* public modulus */
  gcry_mpi_t e;	    /* public exponent */
  gcry_mpi_t d;	    /* exponent */
  gcry_mpi_t p;	    /* prime  p. */
  gcry_mpi_t q;	    /* prime  q. */
  gcry_mpi_t u;	    /* inverse of p mod q. */
};


static gpg_error_t parse_p12 (ctrl_t ctrl, ksba_reader_t reader,
                              struct stats_s *stats);



static void
print_imported_status (ctrl_t ctrl, ksba_cert_t cert, int new_cert)
{
  char *fpr;

  fpr = gpgsm_get_fingerprint_hexstring (cert, GCRY_MD_SHA1);
  if (new_cert)
    gpgsm_status2 (ctrl, STATUS_IMPORTED, fpr, "[X.509]", NULL);

  gpgsm_status2 (ctrl, STATUS_IMPORT_OK,
                 new_cert? "1":"0",  fpr, NULL);

  xfree (fpr);
}


/* Print an IMPORT_PROBLEM status.  REASON is one of:
   0 := "No specific reason given".
   1 := "Invalid Certificate".
   2 := "Issuer Certificate missing".
   3 := "Certificate Chain too long".
   4 := "Error storing certificate".
*/
static void
print_import_problem (ctrl_t ctrl, ksba_cert_t cert, int reason)
{
  char *fpr = NULL;
  char buf[25];
  int i;

  sprintf (buf, "%d", reason);
  if (cert)
    {
      fpr = gpgsm_get_fingerprint_hexstring (cert, GCRY_MD_SHA1);
      /* detetect an error (all high) value */
      for (i=0; fpr[i] == 'F'; i++)
        ;
      if (!fpr[i])
        {
          xfree (fpr);
          fpr = NULL;
        }
    }
  gpgsm_status2 (ctrl, STATUS_IMPORT_PROBLEM, buf, fpr, NULL);
  xfree (fpr);
}


void
print_imported_summary (ctrl_t ctrl, struct stats_s *stats)
{
  char buf[14*25];

  if (!opt.quiet)
    {
      log_info (_("total number processed: %lu\n"), stats->count);
      if (stats->imported)
        {
          log_info (_("              imported: %lu"), stats->imported );
          log_printf ("\n");
	}
      if (stats->unchanged)
        log_info (_("             unchanged: %lu\n"), stats->unchanged);
      if (stats->secret_read)
        log_info (_("      secret keys read: %lu\n"), stats->secret_read );
      if (stats->secret_imported)
        log_info (_("  secret keys imported: %lu\n"), stats->secret_imported );
      if (stats->secret_dups)
        log_info (_(" secret keys unchanged: %lu\n"), stats->secret_dups );
      if (stats->not_imported)
        log_info (_("          not imported: %lu\n"), stats->not_imported);
    }

  sprintf(buf, "%lu %lu %lu %lu %lu %lu %lu %lu %lu %lu %lu %lu %lu %lu",
          stats->count,
          0l /*stats->no_user_id*/,
          stats->imported,
          0l /*stats->imported_rsa*/,
          stats->unchanged,
          0l /*stats->n_uids*/,
          0l /*stats->n_subk*/,
          0l /*stats->n_sigs*/,
          0l /*stats->n_revoc*/,
          stats->secret_read,
          stats->secret_imported,
          stats->secret_dups,
          0l /*stats->skipped_new_keys*/,
          stats->not_imported
          );
  gpgsm_status (ctrl, STATUS_IMPORT_RES, buf);
}



static void
check_and_store (ctrl_t ctrl, struct stats_s *stats,
                 ksba_cert_t cert, int depth)
{
  int rc;

  if (stats)
    stats->count++;
  if ( depth >= 50 )
    {
      log_error (_("certificate chain too long\n"));
      if (stats)
        stats->not_imported++;
      print_import_problem (ctrl, cert, 3);
      return;
    }

  /* Some basic checks, but don't care about missing certificates;
     this is so that we are able to import entire certificate chains
     w/o requiring a special order (i.e. root-CA first).  This used
     to be different but because gpgsm_verify even imports
     certificates without any checks, it doesn't matter much and the
     code gets much cleaner.  A housekeeping function to remove
     certificates w/o an anchor would be nice, though.

     Optionally we do a full validation in addition to the basic test.
  */
  rc = gpgsm_basic_cert_check (ctrl, cert);
  if (!rc && ctrl->with_validation)
    rc = gpgsm_validate_chain (ctrl, cert, "", NULL, 0, NULL, 0, NULL);
  if (!rc || (!ctrl->with_validation
              && (gpg_err_code (rc) == GPG_ERR_MISSING_CERT
                  || gpg_err_code (rc) == GPG_ERR_MISSING_ISSUER_CERT)))
    {
      int existed;

      if (!keydb_store_cert (ctrl, cert, 0, &existed))
        {
          ksba_cert_t next = NULL;

          if (!existed)
            {
              print_imported_status (ctrl, cert, 1);
              if (stats)
                stats->imported++;
            }
          else
            {
              print_imported_status (ctrl, cert, 0);
              if (stats)
                stats->unchanged++;
            }

          if (opt.verbose > 1 && existed)
            {
              if (depth)
                log_info ("issuer certificate already in DB\n");
              else
                log_info ("certificate already in DB\n");
            }
          else if (opt.verbose && !existed)
            {
              if (depth)
                log_info ("issuer certificate imported\n");
              else
                log_info ("certificate imported\n");
            }

          /* Now lets walk up the chain and import all certificates up
             the chain.  This is required in case we already stored
             parent certificates in the ephemeral keybox.  Do not
             update the statistics, though. */
          if (!gpgsm_walk_cert_chain (ctrl, cert, &next))
            {
              check_and_store (ctrl, NULL, next, depth+1);
              ksba_cert_release (next);
            }
        }
      else
        {
          log_error (_("error storing certificate\n"));
          if (stats)
            stats->not_imported++;
          print_import_problem (ctrl, cert, 4);
        }
    }
  else
    {
      log_error (_("basic certificate checks failed - not imported\n"));
      if (stats)
        stats->not_imported++;
      /* We keep the test for GPG_ERR_MISSING_CERT only in case
         GPG_ERR_MISSING_CERT has been used instead of the newer
         GPG_ERR_MISSING_ISSUER_CERT.  */
      print_import_problem
        (ctrl, cert,
         gpg_err_code (rc) == GPG_ERR_MISSING_ISSUER_CERT? 2 :
         gpg_err_code (rc) == GPG_ERR_MISSING_CERT? 2 :
         gpg_err_code (rc) == GPG_ERR_BAD_CERT?     1 : 0);
    }
}




static int
import_one (ctrl_t ctrl, struct stats_s *stats, int in_fd)
{
  int rc;
  gnupg_ksba_io_t b64reader = NULL;
  ksba_reader_t reader;
  ksba_cert_t cert = NULL;
  ksba_cms_t cms = NULL;
  estream_t fp = NULL;
  ksba_content_type_t ct;
  int any = 0;

  fp = es_fdopen_nc (in_fd, "rb");
  if (!fp)
    {
      rc = gpg_error_from_syserror ();
      log_error ("fdopen() failed: %s\n", strerror (errno));
      goto leave;
    }

  rc = gnupg_ksba_create_reader
    (&b64reader, ((ctrl->is_pem? GNUPG_KSBA_IO_PEM : 0)
                  | (ctrl->is_base64? GNUPG_KSBA_IO_BASE64 : 0)
                  | (ctrl->autodetect_encoding? GNUPG_KSBA_IO_AUTODETECT : 0)
                  | GNUPG_KSBA_IO_MULTIPEM),
     fp, &reader);
  if (rc)
    {
      log_error ("can't create reader: %s\n", gpg_strerror (rc));
      goto leave;
    }


  /* We need to loop here to handle multiple PEM objects in one
     file. */
  do
    {
      ksba_cms_release (cms); cms = NULL;
      ksba_cert_release (cert); cert = NULL;

      ct = ksba_cms_identify (reader);
      if (ct == KSBA_CT_SIGNED_DATA)
        { /* This is probably a signed-only message - import the certs */
          ksba_stop_reason_t stopreason;
          int i;

          rc = ksba_cms_new (&cms);
          if (rc)
            goto leave;

          rc = ksba_cms_set_reader_writer (cms, reader, NULL);
          if (rc)
            {
              log_error ("ksba_cms_set_reader_writer failed: %s\n",
                         gpg_strerror (rc));
              goto leave;
            }

          do
            {
              rc = ksba_cms_parse (cms, &stopreason);
              if (rc)
                {
                  log_error ("ksba_cms_parse failed: %s\n", gpg_strerror (rc));
                  goto leave;
                }

              if (stopreason == KSBA_SR_BEGIN_DATA)
                log_info ("not a certs-only message\n");
            }
          while (stopreason != KSBA_SR_READY);

          for (i=0; (cert=ksba_cms_get_cert (cms, i)); i++)
            {
              check_and_store (ctrl, stats, cert, 0);
              ksba_cert_release (cert);
              cert = NULL;
            }
          if (!i)
            log_error ("no certificate found\n");
          else
            any = 1;
        }
      else if (ct == KSBA_CT_PKCS12)
        {
          /* This seems to be a pkcs12 message. */
          rc = parse_p12 (ctrl, reader, stats);
          if (!rc)
            any = 1;
        }
      else if (ct == KSBA_CT_NONE)
        { /* Failed to identify this message - assume a certificate */

          rc = ksba_cert_new (&cert);
          if (rc)
            goto leave;

          rc = ksba_cert_read_der (cert, reader);
          if (rc)
            goto leave;

          check_and_store (ctrl, stats, cert, 0);
          any = 1;
        }
      else
        {
          log_error ("can't extract certificates from input\n");
          rc = gpg_error (GPG_ERR_NO_DATA);
        }

      ksba_reader_clear (reader, NULL, NULL);
    }
  while (!gnupg_ksba_reader_eof_seen (b64reader));

 leave:
  if (any && gpg_err_code (rc) == GPG_ERR_EOF)
    rc = 0;
  ksba_cms_release (cms);
  ksba_cert_release (cert);
  gnupg_ksba_destroy_reader (b64reader);
  es_fclose (fp);
  return rc;
}



/* Re-import certifciates.  IN_FD is a list of linefeed delimited
   fingerprints t re-import.  The actual re-import is done by clearing
   the ephemeral flag.  */
static int
reimport_one (ctrl_t ctrl, struct stats_s *stats, int in_fd)
{
  gpg_error_t err = 0;
  estream_t fp = NULL;
  char line[100];  /* Sufficient for a fingerprint.  */
  KEYDB_HANDLE kh;
  KEYDB_SEARCH_DESC desc;
  ksba_cert_t cert = NULL;
  unsigned int flags;

  kh = keydb_new ();
  if (!kh)
    {
      err = gpg_error (GPG_ERR_ENOMEM);;
      log_error (_("failed to allocate keyDB handle\n"));
      goto leave;
    }
  keydb_set_ephemeral (kh, 1);

  fp = es_fdopen_nc (in_fd, "r");
  if (!fp)
    {
      err = gpg_error_from_syserror ();
      log_error ("es_fdopen(%d) failed: %s\n", in_fd, gpg_strerror (err));
      goto leave;
    }

  while (es_fgets (line, DIM(line)-1, fp) )
    {
      if (*line && line[strlen(line)-1] != '\n')
        {
          err = gpg_error (GPG_ERR_LINE_TOO_LONG);
          goto leave;
	}
      trim_spaces (line);
      if (!*line)
        continue;

      stats->count++;

      err = classify_user_id (line, &desc, 0);
      if (err)
        {
          print_import_problem (ctrl, NULL, 0);
          stats->not_imported++;
          continue;
        }

      keydb_search_reset (kh);
      err = keydb_search (ctrl, kh, &desc, 1);
      if (err)
        {
          print_import_problem (ctrl, NULL, 0);
          stats->not_imported++;
          continue;
        }

      ksba_cert_release (cert);
      cert = NULL;
      err = keydb_get_cert (kh, &cert);
      if (err)
        {
          log_error ("keydb_get_cert() failed: %s\n", gpg_strerror (err));
          print_import_problem (ctrl, NULL, 1);
          stats->not_imported++;
          continue;
        }

      err = keydb_get_flags (kh, KEYBOX_FLAG_BLOB, 0, &flags);
      if (err)
        {
          log_error (_("error getting stored flags: %s\n"), gpg_strerror (err));
          print_imported_status (ctrl, cert, 0);
          stats->not_imported++;
          continue;
        }
      if ( !(flags & KEYBOX_FLAG_BLOB_EPHEMERAL) )
        {
          print_imported_status (ctrl, cert, 0);
          stats->unchanged++;
          continue;
        }

      err = keydb_set_cert_flags (ctrl, cert, 1, KEYBOX_FLAG_BLOB, 0,
                                  KEYBOX_FLAG_BLOB_EPHEMERAL, 0);
      if (err)
        {
          log_error ("clearing ephemeral flag failed: %s\n",
                     gpg_strerror (err));
          print_import_problem (ctrl, cert, 0);
          stats->not_imported++;
          continue;
        }

      print_imported_status (ctrl, cert, 1);
      stats->imported++;
    }
  err = 0;
  if (es_ferror (fp))
    {
      err = gpg_error_from_syserror ();
      log_error ("error reading fd %d: %s\n", in_fd, gpg_strerror (err));
      goto leave;
    }

 leave:
  ksba_cert_release (cert);
  keydb_release (kh);
  es_fclose (fp);
  return err;
}



int
gpgsm_import (ctrl_t ctrl, int in_fd, int reimport_mode)
{
  int rc;
  struct stats_s stats;

  memset (&stats, 0, sizeof stats);
  if (reimport_mode)
    rc = reimport_one (ctrl, &stats, in_fd);
  else
    rc = import_one (ctrl, &stats, in_fd);
  print_imported_summary (ctrl, &stats);
  /* If we never printed an error message do it now so that a command
     line invocation will return with an error (log_error keeps a
     global errorcount) */
  if (rc && !log_get_errorcount (0))
    log_error (_("error importing certificate: %s\n"), gpg_strerror (rc));
  return rc;
}


int
gpgsm_import_files (ctrl_t ctrl, int nfiles, char **files,
                    int (*of)(const char *fname))
{
  int rc = 0;
  struct stats_s stats;

  memset (&stats, 0, sizeof stats);

  if (!nfiles)
    rc = import_one (ctrl, &stats, 0);
  else
    {
      for (; nfiles && !rc ; nfiles--, files++)
        {
          int fd = of (*files);
          rc = import_one (ctrl, &stats, fd);
          close (fd);
          if (rc == -1)
            rc = 0;
        }
    }
  print_imported_summary (ctrl, &stats);
  /* If we never printed an error message do it now so that a command
     line invocation will return with an error (log_error keeps a
     global errorcount) */
  if (rc && !log_get_errorcount (0))
    log_error (_("error importing certificate: %s\n"), gpg_strerror (rc));
  return rc;
}


/* Check that the RSA secret key SKEY is valid.  Swap parameters to
   the libgcrypt standard.  */
static gpg_error_t
rsa_key_check (struct rsa_secret_key_s *skey)
{
  int err = 0;
  gcry_mpi_t t = gcry_mpi_snew (0);
  gcry_mpi_t t1 = gcry_mpi_snew (0);
  gcry_mpi_t t2 = gcry_mpi_snew (0);
  gcry_mpi_t phi = gcry_mpi_snew (0);

  /* Check that n == p * q.  */
  gcry_mpi_mul (t, skey->p, skey->q);
  if (gcry_mpi_cmp( t, skey->n) )
    {
      log_error ("RSA oops: n != p * q\n");
      err++;
    }

  /* Check that p is less than q.  */
  if (gcry_mpi_cmp (skey->p, skey->q) > 0)
    {
      gcry_mpi_t tmp;

      log_info ("swapping secret primes\n");
      tmp = gcry_mpi_copy (skey->p);
      gcry_mpi_set (skey->p, skey->q);
      gcry_mpi_set (skey->q, tmp);
      gcry_mpi_release (tmp);
      /* Recompute u.  */
      gcry_mpi_invm (skey->u, skey->p, skey->q);
    }

  /* Check that e divides neither p-1 nor q-1.  */
  gcry_mpi_sub_ui (t, skey->p, 1 );
  gcry_mpi_div (NULL, t, t, skey->e, 0);
  if (!gcry_mpi_cmp_ui( t, 0) )
    {
      log_error ("RSA oops: e divides p-1\n");
      err++;
    }
  gcry_mpi_sub_ui (t, skey->q, 1);
  gcry_mpi_div (NULL, t, t, skey->e, 0);
  if (!gcry_mpi_cmp_ui( t, 0))
    {
      log_info ("RSA oops: e divides q-1\n" );
      err++;
    }

  /* Check that d is correct.  */
  gcry_mpi_sub_ui (t1, skey->p, 1);
  gcry_mpi_sub_ui (t2, skey->q, 1);
  gcry_mpi_mul (phi, t1, t2);
  gcry_mpi_invm (t, skey->e, phi);
  if (gcry_mpi_cmp (t, skey->d))
    {
      /* No: try universal exponent. */
      gcry_mpi_gcd (t, t1, t2);
      gcry_mpi_div (t, NULL, phi, t, 0);
      gcry_mpi_invm (t, skey->e, t);
      if (gcry_mpi_cmp (t, skey->d))
        {
          log_error ("RSA oops: bad secret exponent\n");
          err++;
        }
    }

  /* Check for correctness of u.  */
  gcry_mpi_invm (t, skey->p, skey->q);
  if (gcry_mpi_cmp (t, skey->u))
    {
      log_info ("RSA oops: bad u parameter\n");
      err++;
    }

  if (err)
    log_info ("RSA secret key check failed\n");

  gcry_mpi_release (t);
  gcry_mpi_release (t1);
  gcry_mpi_release (t2);
  gcry_mpi_release (phi);

  return err? gpg_error (GPG_ERR_BAD_SECKEY):0;
}


/* Object passed to store_cert_cb.  */
struct store_cert_parm_s
{
  gpg_error_t err;        /* First error seen.  */
  struct stats_s *stats;  /* The stats object.  */
  ctrl_t ctrl;            /* The control object.  */
};

/* Helper to store the DER encoded certificate CERTDATA of length
   CERTDATALEN.  */
static void
store_cert_cb (void *opaque,
               const unsigned char *certdata, size_t certdatalen)
{
  struct store_cert_parm_s *parm = opaque;
  gpg_error_t err;
  ksba_cert_t cert;

  err = ksba_cert_new (&cert);
  if (err)
    {
      if (!parm->err)
        parm->err = err;
      return;
    }

  err = ksba_cert_init_from_mem (cert, certdata, certdatalen);
  if (err)
    {
      log_error ("failed to parse a certificate: %s\n", gpg_strerror (err));
      if (!parm->err)
        parm->err = err;
    }
  else
    check_and_store (parm->ctrl, parm->stats, cert, 0);
  ksba_cert_release (cert);
}


/* Assume that the reader is at a pkcs#12 message and try to import
   certificates from that stupid format.  We will transfer secret
   keys to the agent.  */
static gpg_error_t
parse_p12 (ctrl_t ctrl, ksba_reader_t reader, struct stats_s *stats)
{
  gpg_error_t err = 0;
  char buffer[1024];
  size_t ntotal, nread;
  membuf_t p12mbuf;
  char *p12buffer = NULL;
  size_t p12buflen;
  size_t p12bufoff;
  gcry_mpi_t *kparms = NULL;
  struct rsa_secret_key_s sk;
  char *passphrase = NULL;
  unsigned char *key = NULL;
  size_t keylen;
  void *kek = NULL;
  size_t keklen;
  unsigned char *wrappedkey = NULL;
  size_t wrappedkeylen;
  gcry_cipher_hd_t cipherhd = NULL;
  gcry_sexp_t s_key = NULL;
  unsigned char grip[20];
  int bad_pass = 0;
  int i;
  struct store_cert_parm_s store_cert_parm;

  memset (&store_cert_parm, 0, sizeof store_cert_parm);
  store_cert_parm.ctrl = ctrl;
  store_cert_parm.stats = stats;

  init_membuf (&p12mbuf, 4096);
  ntotal = 0;
  while (!(err = ksba_reader_read (reader, buffer, sizeof buffer, &nread)))
    {
      if (ntotal >= MAX_P12OBJ_SIZE*1024)
        {
          /* Arbitrary limit to avoid DoS attacks. */
          err = gpg_error (GPG_ERR_TOO_LARGE);
          log_error ("pkcs#12 object is larger than %dk\n", MAX_P12OBJ_SIZE);
          break;
        }
      put_membuf (&p12mbuf, buffer, nread);
      ntotal += nread;
    }
  if (gpg_err_code (err) == GPG_ERR_EOF)
    err = 0;
  if (!err)
    {
      p12buffer = get_membuf (&p12mbuf, &p12buflen);
      if (!p12buffer)
        err = gpg_error_from_syserror ();
    }
  if (err)
    {
      log_error (_("error reading input: %s\n"), gpg_strerror (err));
      goto leave;
    }

  /* GnuPG 2.0.4 accidentally created binary P12 files with the string
     "The passphrase is %s encoded.\n\n" prepended to the ASN.1 data.
     We fix that here.  */
  if (p12buflen > 29 && !memcmp (p12buffer, "The passphrase is ", 18))
    {
      for (p12bufoff=18;
           p12bufoff < p12buflen && p12buffer[p12bufoff] != '\n';
           p12bufoff++)
        ;
      p12bufoff++;
      if (p12bufoff < p12buflen && p12buffer[p12bufoff] == '\n')
        p12bufoff++;
    }
  else
    p12bufoff = 0;


  err = gpgsm_agent_ask_passphrase
    (ctrl,
     i18n_utf8 ("Please enter the passphrase to unprotect the PKCS#12 object."),
     0, &passphrase);
  if (err)
    goto leave;

  kparms = p12_parse (p12buffer + p12bufoff, p12buflen - p12bufoff,
                      passphrase, store_cert_cb, &store_cert_parm, &bad_pass);

  xfree (passphrase);
  passphrase = NULL;

  if (!kparms)
    {
      log_error ("error parsing or decrypting the PKCS#12 file\n");
      err = gpg_error (GPG_ERR_INV_OBJ);
      goto leave;
    }

/*    print_mpi ("   n", kparms[0]); */
/*    print_mpi ("   e", kparms[1]); */
/*    print_mpi ("   d", kparms[2]); */
/*    print_mpi ("   p", kparms[3]); */
/*    print_mpi ("   q", kparms[4]); */
/*    print_mpi ("dmp1", kparms[5]); */
/*    print_mpi ("dmq1", kparms[6]); */
/*    print_mpi ("   u", kparms[7]); */

  sk.n = kparms[0];
  sk.e = kparms[1];
  sk.d = kparms[2];
  sk.q = kparms[3];
  sk.p = kparms[4];
  sk.u = kparms[7];
  err = rsa_key_check (&sk);
  if (err)
    goto leave;
/*    print_mpi ("   n", sk.n); */
/*    print_mpi ("   e", sk.e); */
/*    print_mpi ("   d", sk.d); */
/*    print_mpi ("   p", sk.p); */
/*    print_mpi ("   q", sk.q); */
/*    print_mpi ("   u", sk.u); */

  /* Create an S-expression from the parameters. */
  err = gcry_sexp_build (&s_key, NULL,
                         "(private-key(rsa(n%m)(e%m)(d%m)(p%m)(q%m)(u%m)))",
                         sk.n, sk.e, sk.d, sk.p, sk.q, sk.u, NULL);
  for (i=0; i < 8; i++)
    gcry_mpi_release (kparms[i]);
  gcry_free (kparms);
  kparms = NULL;
  if (err)
    {
      log_error ("failed to create S-expression from key: %s\n",
                 gpg_strerror (err));
      goto leave;
    }

  /* Compute the keygrip. */
  if (!gcry_pk_get_keygrip (s_key, grip))
    {
      err = gpg_error (GPG_ERR_GENERAL);
      log_error ("can't calculate keygrip\n");
      goto leave;
    }
  log_printhex (grip, 20, "keygrip=");

  /* Convert to canonical encoding using a function which pads it to a
     multiple of 64 bits.  We need this padding for AESWRAP.  */
  err = make_canon_sexp_pad (s_key, 1, &key, &keylen);
  if (err)
    {
      log_error ("error creating canonical S-expression\n");
      goto leave;
    }
  gcry_sexp_release (s_key);
  s_key = NULL;

  /* Get the current KEK.  */
  err = gpgsm_agent_keywrap_key (ctrl, 0, &kek, &keklen);
  if (err)
    {
      log_error ("error getting the KEK: %s\n", gpg_strerror (err));
      goto leave;
    }

  /* Wrap the key.  */
  err = gcry_cipher_open (&cipherhd, GCRY_CIPHER_AES128,
                          GCRY_CIPHER_MODE_AESWRAP, 0);
  if (err)
    goto leave;
  err = gcry_cipher_setkey (cipherhd, kek, keklen);
  if (err)
    goto leave;
  xfree (kek);
  kek = NULL;

  wrappedkeylen = keylen + 8;
  wrappedkey = xtrymalloc (wrappedkeylen);
  if (!wrappedkey)
    {
      err = gpg_error_from_syserror ();
      goto leave;
    }

  err = gcry_cipher_encrypt (cipherhd, wrappedkey, wrappedkeylen, key, keylen);
  if (err)
    goto leave;
  xfree (key);
  key = NULL;
  gcry_cipher_close (cipherhd);
  cipherhd = NULL;

  /* Send the wrapped key to the agent.  */
  err = gpgsm_agent_import_key (ctrl, wrappedkey, wrappedkeylen);
  if (!err)
    {
      stats->count++;
      stats->secret_read++;
      stats->secret_imported++;
    }
  else if ( gpg_err_code (err) == GPG_ERR_EEXIST )
    {
      err = 0;
      stats->count++;
      stats->secret_read++;
      stats->secret_dups++;
    }

  /* If we did not get an error from storing the secret key we return
     a possible error from parsing the certificates.  We do this after
     storing the secret keys so that a bad certificate does not
     inhibit our chance to store the secret key.  */
  if (!err && store_cert_parm.err)
    err = store_cert_parm.err;

 leave:
  if (kparms)
    {
      for (i=0; i < 8; i++)
        gcry_mpi_release (kparms[i]);
      gcry_free (kparms);
      kparms = NULL;
    }
  xfree (key);
  gcry_sexp_release (s_key);
  xfree (passphrase);
  gcry_cipher_close (cipherhd);
  xfree (wrappedkey);
  xfree (kek);
  xfree (get_membuf (&p12mbuf, NULL));
  xfree (p12buffer);

  if (bad_pass)
    {
      /* We only write a plain error code and not direct
         BAD_PASSPHRASE because the pkcs12 parser might issue this
         message multiple times, BAD_PASSPHRASE in general requires a
         keyID and parts of the import might actually succeed so that
         IMPORT_PROBLEM is also not appropriate. */
      gpgsm_status_with_err_code (ctrl, STATUS_ERROR,
                                  "import.parsep12", GPG_ERR_BAD_PASSPHRASE);
    }

  return err;
}
