/* certcache.c - Certificate caching
 * Copyright (C) 2004, 2005, 2007, 2008, 2017 g10 Code GmbH
 *
 * This file is part of DirMngr.
 *
 * DirMngr is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * DirMngr is distributed in the hope that it will be useful,
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
#include <errno.h>
#include <assert.h>
#include <sys/types.h>
#include <dirent.h>
#include <npth.h>

#include "dirmngr.h"
#include "misc.h"
#include "../common/ksba-io-support.h"
#include "crlfetch.h"
#include "certcache.h"

#define MAX_NONPERM_CACHED_CERTS 1000

/* Constants used to classify search patterns.  */
enum pattern_class
  {
    PATTERN_UNKNOWN = 0,
    PATTERN_EMAIL,
    PATTERN_EMAIL_SUBSTR,
    PATTERN_FINGERPRINT16,
    PATTERN_FINGERPRINT20,
    PATTERN_SHORT_KEYID,
    PATTERN_LONG_KEYID,
    PATTERN_SUBJECT,
    PATTERN_SERIALNO,
    PATTERN_SERIALNO_ISSUER,
    PATTERN_ISSUER,
    PATTERN_SUBSTR
  };


/* A certificate cache item.  This consists of a the KSBA cert object
   and some meta data for easier lookup.  We use a hash table to keep
   track of all items and use the (randomly distributed) first byte of
   the fingerprint directly as the hash which makes it pretty easy. */
struct cert_item_s
{
  struct cert_item_s *next; /* Next item with the same hash value. */
  ksba_cert_t cert;         /* The KSBA cert object or NULL is this is
                               not a valid item.  */
  unsigned char fpr[20];    /* The fingerprint of this object. */
  char *issuer_dn;          /* The malloced issuer DN.  */
  ksba_sexp_t sn;           /* The malloced serial number  */
  char *subject_dn;         /* The malloced subject DN - maybe NULL.  */

  /* If this field is set the certificate has been taken from some
   * configuration and shall not be flushed from the cache.  */
  unsigned int permanent:1;

  /* If this field is set the certificate is trusted.  The actual
   * value is a (possible) combination of CERTTRUST_CLASS values.  */
  unsigned int trustclasses:4;
};
typedef struct cert_item_s *cert_item_t;

/* The actual cert cache consisting of 256 slots for items indexed by
   the first byte of the fingerprint.  */
static cert_item_t cert_cache[256];

/* This is the global cache_lock variable. In general locking is not
   needed but it would take extra efforts to make sure that no
   indirect use of npth functions is done, so we simply lock it
   always.  Note: We can't use static initialization, as that is not
   available through w32-pth.  */
static npth_rwlock_t cert_cache_lock;

/* Flag to track whether the cache has been initialized.  */
static int initialization_done;

/* Total number of non-permanent certificates.  */
static unsigned int total_nonperm_certificates;

/* For each cert class the corresponding bit is set if at least one
 * certificate of that class is loaded permanetly.  */
static unsigned int any_cert_of_class;


#ifdef HAVE_W32_SYSTEM
/* We load some functions dynamically.  Provide typedefs for tehse
 * functions.  */
typedef HCERTSTORE (WINAPI *CERTOPENSYSTEMSTORE)
  (HCRYPTPROV hProv, LPCSTR szSubsystemProtocol);
typedef PCCERT_CONTEXT (WINAPI *CERTENUMCERTIFICATESINSTORE)
  (HCERTSTORE hCertStore, PCCERT_CONTEXT pPrevCertContext);
typedef WINBOOL (WINAPI *CERTCLOSESTORE)
  (HCERTSTORE hCertStore,DWORD dwFlags);
#endif /*HAVE_W32_SYSTEM*/




/* Helper to do the cache locking.  */
static void
init_cache_lock (void)
{
  int err;

  err = npth_rwlock_init (&cert_cache_lock, NULL);
  if (err)
    log_fatal (_("can't initialize certificate cache lock: %s\n"),
	       strerror (err));
}

static void
acquire_cache_read_lock (void)
{
  int err;

  err = npth_rwlock_rdlock (&cert_cache_lock);
  if (err)
    log_fatal (_("can't acquire read lock on the certificate cache: %s\n"),
               strerror (err));
}

static void
acquire_cache_write_lock (void)
{
  int err;

  err = npth_rwlock_wrlock (&cert_cache_lock);
  if (err)
    log_fatal (_("can't acquire write lock on the certificate cache: %s\n"),
               strerror (err));
}

static void
release_cache_lock (void)
{
  int err;

  err = npth_rwlock_unlock (&cert_cache_lock);
  if (err)
    log_fatal (_("can't release lock on the certificate cache: %s\n"),
               strerror (err));
}


/* Return false if both serial numbers match.  Can't be used for
   sorting. */
static int
compare_serialno (ksba_sexp_t serial1, ksba_sexp_t serial2 )
{
  unsigned char *a = serial1;
  unsigned char *b = serial2;
  return cmp_simple_canon_sexp (a, b);
}



/* Return a malloced canonical S-Expression with the serial number
 * converted from the hex string HEXSN.  Return NULL on memory
 * error.  */
ksba_sexp_t
hexsn_to_sexp (const char *hexsn)
{
  char *buffer, *p;
  size_t len;
  char numbuf[40];

  len = unhexify (NULL, hexsn);
  snprintf (numbuf, sizeof numbuf, "(%u:", (unsigned int)len);
  buffer = xtrymalloc (strlen (numbuf) + len + 2 );
  if (!buffer)
    return NULL;
  p = stpcpy (buffer, numbuf);
  len = unhexify (p, hexsn);
  p[len] = ')';
  p[len+1] = 0;

  return buffer;
}


/* Compute the fingerprint of the certificate CERT and put it into
   the 20 bytes large buffer DIGEST.  Return address of this buffer.  */
unsigned char *
cert_compute_fpr (ksba_cert_t cert, unsigned char *digest)
{
  gpg_error_t err;
  gcry_md_hd_t md;

  err = gcry_md_open (&md, GCRY_MD_SHA1, 0);
  if (err)
    log_fatal ("gcry_md_open failed: %s\n", gpg_strerror (err));

  err = ksba_cert_hash (cert, 0, HASH_FNC, md);
  if (err)
    {
      log_error ("oops: ksba_cert_hash failed: %s\n", gpg_strerror (err));
      memset (digest, 0xff, 20); /* Use a dummy value. */
    }
  else
    {
      gcry_md_final (md);
      memcpy (digest, gcry_md_read (md, GCRY_MD_SHA1), 20);
    }
  gcry_md_close (md);
  return digest;
}



/* Cleanup one slot.  This releases all resourses but keeps the actual
   slot in the cache marked for reuse. */
static void
clean_cache_slot (cert_item_t ci)
{
  ksba_cert_t cert;

  if (!ci->cert)
    return; /* Already cleaned.  */

  ksba_free (ci->sn);
  ci->sn = NULL;
  ksba_free (ci->issuer_dn);
  ci->issuer_dn = NULL;
  ksba_free (ci->subject_dn);
  ci->subject_dn = NULL;
  cert = ci->cert;
  ci->cert = NULL;

  ci->permanent = 0;
  ci->trustclasses = 0;

  ksba_cert_release (cert);
}


/* Put the certificate CERT into the cache.  It is assumed that the
 * cache is locked while this function is called.
 *
 * FROM_CONFIG indicates that CERT is a permanent certificate and
 * should stay in the cache.  IS_TRUSTED requests that the trusted
 * flag is set for the certificate; a value of 1 indicates the
 * cert is trusted due to GnuPG mechanisms, a value of 2 indicates
 * that it is trusted because it has been taken from the system's
 * store of trusted certificates.  If FPR_BUFFER is not NULL the
 * fingerprint of the certificate will be stored there.  FPR_BUFFER
 * needs to point to a buffer of at least 20 bytes.  The fingerprint
 * will be stored on success or when the function returns
 * GPG_ERR_DUP_VALUE or GPG_ERR_NOT_ENABLED.  */
static gpg_error_t
put_cert (ksba_cert_t cert, int permanent, unsigned int trustclass,
          void *fpr_buffer)
{
  unsigned char help_fpr_buffer[20], *fpr;
  cert_item_t ci;
  fingerprint_list_t ignored;

  /* Do not keep expired certificates in the permanent cache.  */
  if (permanent && !opt.debug_cache_expired_certs)
    {
      ksba_isotime_t not_after;
      ksba_isotime_t current_time;

      if (ksba_cert_get_validity (cert, 1, not_after))
        return gpg_error (GPG_ERR_BAD_CERT);

      gnupg_get_isotime (current_time);

      if (*not_after && strcmp (current_time, not_after) > 0)
        return gpg_error (GPG_ERR_CERT_EXPIRED);
    }

  fpr = fpr_buffer? fpr_buffer : &help_fpr_buffer;

  /* If we already reached the caching limit, drop a couple of certs
   * from the cache.  Our dropping strategy is simple: We keep a
   * static index counter and use this to start looking for
   * certificates, then we drop 5 percent of the oldest certificates
   * starting at that index.  For a large cache this is a fair way of
   * removing items.  An LRU strategy would be better of course.
   * Because we append new entries to the head of the list and we want
   * to remove old ones first, we need to do this from the tail.  The
   * implementation is not very efficient but compared to the long
   * time it takes to retrieve a certificate from an external resource
   * it seems to be reasonable.  */
  if (!permanent && total_nonperm_certificates >= MAX_NONPERM_CACHED_CERTS)
    {
      static int idx;
      cert_item_t ci_mark;
      int i;
      unsigned int drop_count;

      drop_count = MAX_NONPERM_CACHED_CERTS / 20;
      if (drop_count < 2)
        drop_count = 2;

      log_info (_("dropping %u certificates from the cache\n"), drop_count);
      assert (idx < 256);
      for (i=idx; drop_count; i = ((i+1)%256))
        {
          ci_mark = NULL;
          for (ci = cert_cache[i]; ci; ci = ci->next)
            if (ci->cert && !ci->permanent)
              ci_mark = ci;
          if (ci_mark)
            {
              clean_cache_slot (ci_mark);
              drop_count--;
              total_nonperm_certificates--;
            }
        }
      if (i==idx)
        idx++;
      else
        idx = i;
      idx %= 256;
    }

  cert_compute_fpr (cert, fpr);
  /* Compare against the list of to be ignored certificates.  */
  for (ignored = opt.ignored_certs; ignored; ignored = ignored->next)
    if (ignored->binlen == 20 && !memcmp (fpr, ignored->hexfpr, 20))
      {
        /* We are configured not to use this certificate.  */
        return gpg_error (GPG_ERR_NOT_ENABLED);
      }

  for (ci=cert_cache[*fpr]; ci; ci = ci->next)
    if (ci->cert && !memcmp (ci->fpr, fpr, 20))
      return gpg_error (GPG_ERR_DUP_VALUE);
  /* Try to reuse an existing entry.  */
  for (ci=cert_cache[*fpr]; ci; ci = ci->next)
    if (!ci->cert)
      break;
  if (!ci)
    { /* No: Create a new entry.  */
      ci = xtrycalloc (1, sizeof *ci);
      if (!ci)
        return gpg_error_from_errno (errno);
      ci->next = cert_cache[*fpr];
      cert_cache[*fpr] = ci;
    }

  ksba_cert_ref (cert);
  ci->cert = cert;
  memcpy (ci->fpr, fpr, 20);
  ci->sn = ksba_cert_get_serial (cert);
  ci->issuer_dn = ksba_cert_get_issuer (cert, 0);
  if (!ci->issuer_dn || !ci->sn)
    {
      clean_cache_slot (ci);
      return gpg_error (GPG_ERR_INV_CERT_OBJ);
    }
  ci->subject_dn = ksba_cert_get_subject (cert, 0);
  ci->permanent = !!permanent;
  ci->trustclasses = trustclass;

  if (permanent)
    any_cert_of_class |= trustclass;
  else
    total_nonperm_certificates++;

  return 0;
}


/* Load certificates from the directory DIRNAME.  All certificates
   matching the pattern "*.crt" or "*.der"  are loaded.  We assume that
   certificates are DER encoded and not PEM encapsulated.  The cache
   should be in a locked state when calling this function.  */
static gpg_error_t
load_certs_from_dir (const char *dirname, unsigned int trustclass)
{
  gpg_error_t err;
  gnupg_dir_t dir;
  gnupg_dirent_t ep;
  char *p;
  size_t n;
  estream_t fp;
  ksba_reader_t reader;
  ksba_cert_t cert;
  char *fname = NULL;

  dir = gnupg_opendir (dirname);
  if (!dir)
    {
      return 0; /* We do not consider this a severe error.  */
    }

  while ( (ep = gnupg_readdir (dir)) )
    {
      p = ep->d_name;
      if (*p == '.' || !*p)
        continue; /* Skip any hidden files and invalid entries.  */
      n = strlen (p);
      if ( n < 5 || (strcmp (p+n-4,".crt") && strcmp (p+n-4,".der")))
        continue; /* Not the desired "*.crt" or "*.der" pattern.  */

      xfree (fname);
      fname = make_filename (dirname, p, NULL);
      fp = es_fopen (fname, "rb");
      if (!fp)
        {
          log_error (_("can't open '%s': %s\n"),
                     fname, strerror (errno));
          continue;
        }

      err = create_estream_ksba_reader (&reader, fp);
      if (err)
        {
          es_fclose (fp);
          continue;
        }

      err = ksba_cert_new (&cert);
      if (!err)
        err = ksba_cert_read_der (cert, reader);
      ksba_reader_release (reader);
      es_fclose (fp);
      if (err)
        {
          log_error (_("can't parse certificate '%s': %s\n"),
                     fname, gpg_strerror (err));
          ksba_cert_release (cert);
          continue;
        }

      err = put_cert (cert, 1, trustclass, NULL);
      if (gpg_err_code (err) == GPG_ERR_DUP_VALUE)
        log_info (_("certificate '%s' already cached\n"), fname);
      else if (!err)
        {
          if ((trustclass & CERTTRUST_CLASS_CONFIG))
            http_register_cfg_ca (fname);

          if (trustclass)
            log_info (_("trusted certificate '%s' loaded\n"), fname);
          else
            log_info (_("certificate '%s' loaded\n"), fname);
          if (opt.verbose)
            {
              p = get_fingerprint_hexstring_colon (cert);
              log_info (_("  SHA1 fingerprint = %s\n"), p);
              xfree (p);

              cert_log_name (_("   issuer ="), cert);
              cert_log_subject (_("  subject ="), cert);
            }
        }
      else if (gpg_err_code (err) == GPG_ERR_NOT_ENABLED)
        log_info ("certificate '%s' skipped due to configuration\n", fname);
      else
        log_error (_("error loading certificate '%s': %s\n"),
                     fname, gpg_strerror (err));
      ksba_cert_release (cert);
    }

  xfree (fname);
  gnupg_closedir (dir);
  return 0;
}


/* Load certificates from FILE.  The certificates are expected to be
 * PEM encoded so that it is possible to load several certificates.
 * TRUSTCLASSES is used to mark the certificates as trusted.  The
 * cache should be in a locked state when calling this function.
 * NO_ERROR repalces an error message when FNAME was not found by an
 * information message.  */
static gpg_error_t
load_certs_from_file (const char *fname, unsigned int trustclasses,
                      int no_error)
{
  gpg_error_t err;
  estream_t fp = NULL;
  gnupg_ksba_io_t ioctx = NULL;
  ksba_reader_t reader;
  ksba_cert_t cert = NULL;

  fp = es_fopen (fname, "rb");
  if (!fp)
    {
      err = gpg_error_from_syserror ();
      if (gpg_err_code (err) == GPG_ERR_ENONET && no_error)
        log_info (_("can't open '%s': %s\n"), fname, gpg_strerror (err));
      else
        log_error (_("can't open '%s': %s\n"), fname, gpg_strerror (err));
      goto leave;
    }

  err = gnupg_ksba_create_reader (&ioctx,
                                  (GNUPG_KSBA_IO_AUTODETECT
                                   | GNUPG_KSBA_IO_MULTIPEM),
                                  fp, &reader);
  if (err)
    {
      log_error ("can't create reader: %s\n", gpg_strerror (err));
      goto leave;
    }

  /* Loop to read all certificates from the file.  */
  do
    {
      ksba_cert_release (cert);
      cert = NULL;
      err = ksba_cert_new (&cert);
      if (!err)
        err = ksba_cert_read_der (cert, reader);
      if (err)
        {
          if (gpg_err_code (err) == GPG_ERR_EOF)
            err = 0;
          else
            log_error (_("can't parse certificate '%s': %s\n"),
                       fname, gpg_strerror (err));
          goto leave;
        }

      err = put_cert (cert, 1, trustclasses, NULL);
      if (gpg_err_code (err) == GPG_ERR_DUP_VALUE)
        log_info (_("certificate '%s' already cached\n"), fname);
      else if (gpg_err_code (err) == GPG_ERR_NOT_ENABLED)
        log_info ("certificate '%s' skipped due to configuration\n", fname);
      else if (err)
        log_error (_("error loading certificate '%s': %s\n"),
                   fname, gpg_strerror (err));
      else if (opt.verbose > 1)
        {
          char *p;

          log_info (_("trusted certificate '%s' loaded\n"), fname);
          p = get_fingerprint_hexstring_colon (cert);
          log_info (_("  SHA1 fingerprint = %s\n"), p);
          xfree (p);

          cert_log_name    (_("   issuer ="), cert);
          cert_log_subject (_("  subject ="), cert);
        }

      ksba_reader_clear (reader, NULL, NULL);
    }
  while (!gnupg_ksba_reader_eof_seen (ioctx));

 leave:
  ksba_cert_release (cert);
  gnupg_ksba_destroy_reader (ioctx);
  es_fclose (fp);

  return err;
}


#ifdef HAVE_W32_SYSTEM
/* Load all certificates from the Windows store named STORENAME.  All
 * certificates are considered to be system provided trusted
 * certificates.  The cache should be in a locked state when calling
 * this function.  */
static void
load_certs_from_w32_store (const char *storename)
{
  static int init_done;
  static CERTOPENSYSTEMSTORE pCertOpenSystemStore;
  static CERTENUMCERTIFICATESINSTORE pCertEnumCertificatesInStore;
  static CERTCLOSESTORE pCertCloseStore;
  gpg_error_t err;
  HCERTSTORE w32store;
  const CERT_CONTEXT *w32cert;
  ksba_cert_t cert = NULL;
  unsigned int count = 0;

  /* Initialize on the first use.  */
  if (!init_done)
    {
      static HANDLE hCrypt32;

      init_done = 1;

      hCrypt32 = LoadLibrary ("Crypt32.dll");
      if (!hCrypt32)
        {
          log_error ("can't load Crypt32.dll: %s\n",  w32_strerror (-1));
          return;
        }

      pCertOpenSystemStore = (CERTOPENSYSTEMSTORE)
        (void*)GetProcAddress (hCrypt32, "CertOpenSystemStoreA");
      pCertEnumCertificatesInStore = (CERTENUMCERTIFICATESINSTORE)
        (void*)GetProcAddress (hCrypt32, "CertEnumCertificatesInStore");
      pCertCloseStore = (CERTCLOSESTORE)
        (void*)GetProcAddress (hCrypt32, "CertCloseStore");
      if (   !pCertOpenSystemStore
          || !pCertEnumCertificatesInStore
          || !pCertCloseStore)
        {
          log_error ("can't load crypt32.dll: %s\n", "missing function");
          pCertOpenSystemStore = NULL;
        }
    }

  if (!pCertOpenSystemStore)
    return;  /* Not initialized.  */


  w32store = pCertOpenSystemStore (0, storename);
  if (!w32store)
    {
      log_error ("can't open certificate store '%s': %s\n",
                 storename, w32_strerror (-1));
      return;
    }

  w32cert = NULL;
  while ((w32cert = pCertEnumCertificatesInStore (w32store, w32cert)))
    {
      if (w32cert->dwCertEncodingType == X509_ASN_ENCODING)
        {
          ksba_cert_release (cert);
          cert = NULL;
          err = ksba_cert_new (&cert);
          if (!err)
            err = ksba_cert_init_from_mem (cert,
                                           w32cert->pbCertEncoded,
                                           w32cert->cbCertEncoded);
          if (err)
            {
              log_error (_("can't parse certificate '%s': %s\n"),
                         storename, gpg_strerror (err));
              break;
            }

          err = put_cert (cert, 1, CERTTRUST_CLASS_SYSTEM, NULL);
          if (!err)
            count++;
          if (gpg_err_code (err) == GPG_ERR_DUP_VALUE)
            {
              if (DBG_X509)
                log_debug (_("certificate '%s' already cached\n"), storename);
            }
          else if (gpg_err_code (err) == GPG_ERR_NOT_ENABLED)
            log_info ("certificate '%s' skipped due to configuration\n",
                      storename);
          else if (err)
            log_error (_("error loading certificate '%s': %s\n"),
                       storename, gpg_strerror (err));
          else if (opt.verbose > 1)
            {
              char *p;

              log_info (_("trusted certificate '%s' loaded\n"), storename);
              p = get_fingerprint_hexstring_colon (cert);
              log_info (_("  SHA1 fingerprint = %s\n"), p);
              xfree (p);

              cert_log_name    (_("   issuer ="), cert);
              cert_log_subject (_("  subject ="), cert);
            }
        }
    }

  ksba_cert_release (cert);
  pCertCloseStore (w32store, 0);

  if (DBG_X509)
    log_debug ("number of certs loaded from store '%s': %u\n",
               storename, count);

}
#endif /*HAVE_W32_SYSTEM*/


/* Load the trusted certificates provided by the system.  */
static gpg_error_t
load_certs_from_system (void)
{
#ifdef HAVE_W32_SYSTEM

  load_certs_from_w32_store ("ROOT");
  load_certs_from_w32_store ("CA");

  return 0;

#else /*!HAVE_W32_SYSTEM*/

  /* A list of certificate bundles to try.  */
  static struct {
    const char *name;
  } table[] = {
#ifdef DEFAULT_TRUST_STORE_FILE
    { DEFAULT_TRUST_STORE_FILE }
#else
    { "/etc/ssl/ca-bundle.pem" },
    { "/etc/ssl/certs/ca-certificates.crt" },
    { "/etc/pki/tls/cert.pem" },
    { "/usr/local/share/certs/ca-root-nss.crt" },
    { "/etc/ssl/cert.pem" }
#endif /*!DEFAULT_TRUST_STORE_FILE*/
  };
  int idx;
  gpg_error_t err = 0;

  for (idx=0; idx < DIM (table); idx++)
    if (!gnupg_access (table[idx].name, F_OK))
      {
        /* Take the first available bundle.  */
        err = load_certs_from_file (table[idx].name, CERTTRUST_CLASS_SYSTEM, 0);
        break;
      }

  return err;
#endif /*!HAVE_W32_SYSTEM*/
}


/* Initialize the certificate cache if not yet done.  */
void
cert_cache_init (strlist_t hkp_cacerts)
{
  char *fname;
  strlist_t sl;

  if (initialization_done)
    return;
  init_cache_lock ();
  acquire_cache_write_lock ();

  load_certs_from_system ();

  fname = make_filename_try (gnupg_sysconfdir (), "trusted-certs", NULL);
  if (fname)
    load_certs_from_dir (fname, CERTTRUST_CLASS_CONFIG);
  xfree (fname);

  fname = make_filename_try (gnupg_sysconfdir (), "extra-certs", NULL);
  if (fname)
    load_certs_from_dir (fname, 0);
  xfree (fname);

  /* Put the special pool certificate into our store.  This is
   * currently only used with ntbtls.  For GnuTLS http_session_new
   * unfortunately loads that certificate directly from the file.  */
  /* Disabled for 2.3.2 because the service had to be shutdown.  */
  /* fname = make_filename_try (gnupg_datadir (), */
  /*                            "sks-keyservers.netCA.pem", NULL); */
  /* if (fname) */
  /*   load_certs_from_file (fname, CERTTRUST_CLASS_HKPSPOOL, 1); */
  /* xfree (fname); */

  for (sl = hkp_cacerts; sl; sl = sl->next)
    load_certs_from_file (sl->d, CERTTRUST_CLASS_HKP, 0);

  initialization_done = 1;
  release_cache_lock ();

  cert_cache_print_stats (NULL);
}

/* Deinitialize the certificate cache.  With FULL set to true even the
   unused certificate slots are released. */
void
cert_cache_deinit (int full)
{
  cert_item_t ci, ci2;
  int i;

  if (!initialization_done)
    return;

  acquire_cache_write_lock ();

  for (i=0; i < 256; i++)
    for (ci=cert_cache[i]; ci; ci = ci->next)
      clean_cache_slot (ci);

  if (full)
    {
      for (i=0; i < 256; i++)
        {
          for (ci=cert_cache[i]; ci; ci = ci2)
            {
              ci2 = ci->next;
              xfree (ci);
            }
          cert_cache[i] = NULL;
        }
    }

  http_register_cfg_ca (NULL);

  total_nonperm_certificates = 0;
  any_cert_of_class = 0;
  initialization_done = 0;
  release_cache_lock ();
}

/* Print some statistics to the log file.  */
void
cert_cache_print_stats (ctrl_t ctrl)
{
  cert_item_t ci;
  int idx;
  unsigned int n_nonperm = 0;
  unsigned int n_permanent = 0;
  unsigned int n_trusted = 0;
  unsigned int n_trustclass_system = 0;
  unsigned int n_trustclass_config = 0;
  unsigned int n_trustclass_hkp = 0;
  unsigned int n_trustclass_hkpspool = 0;

  acquire_cache_read_lock ();
  for (idx = 0; idx < 256; idx++)
    for (ci=cert_cache[idx]; ci; ci = ci->next)
      if (ci->cert)
        {
          if (ci->permanent)
            n_permanent++;
          else
            n_nonperm++;
          if (ci->trustclasses)
            {
              n_trusted++;
              if ((ci->trustclasses & CERTTRUST_CLASS_SYSTEM))
                n_trustclass_system++;
              if ((ci->trustclasses & CERTTRUST_CLASS_CONFIG))
                n_trustclass_config++;
              if ((ci->trustclasses & CERTTRUST_CLASS_HKP))
                n_trustclass_hkp++;
              if ((ci->trustclasses & CERTTRUST_CLASS_HKPSPOOL))
                n_trustclass_hkpspool++;
            }
        }

  release_cache_lock ();

  dirmngr_status_helpf (ctrl,
                 _("permanently loaded certificates: %u\n"),
                        n_permanent);
  dirmngr_status_helpf (ctrl,
                 _("    runtime cached certificates: %u\n"),
                        n_nonperm);
  dirmngr_status_helpf (ctrl,
                 _("           trusted certificates: %u (%u,%u,%u,%u)\n"),
                        n_trusted,
                        n_trustclass_system,
                        n_trustclass_config,
                        n_trustclass_hkp,
                        n_trustclass_hkpspool);
}


/* Return true if any cert of a class in MASK is permanently
 * loaded.  */
int
cert_cache_any_in_class (unsigned int mask)
{
  return !!(any_cert_of_class & mask);
}


/* Put CERT into the certificate cache.  */
gpg_error_t
cache_cert (ksba_cert_t cert)
{
  gpg_error_t err;

  acquire_cache_write_lock ();
  err = put_cert (cert, 0, 0, NULL);
  release_cache_lock ();
  if (gpg_err_code (err) == GPG_ERR_DUP_VALUE)
    log_info (_("certificate already cached\n"));
  else if (!err)
    log_info (_("certificate cached\n"));
  else if (gpg_err_code (err) == GPG_ERR_NOT_ENABLED)
    log_info ("certificate skipped due to configuration\n");
  else
    log_error (_("error caching certificate: %s\n"), gpg_strerror (err));
  return err;
}


/* Put CERT into the certificate cache and store the fingerprint of
   the certificate into FPR_BUFFER.  If the certificate is already in
   the cache do not print a warning; just store the
   fingerprint. FPR_BUFFER needs to be at least 20 bytes. */
gpg_error_t
cache_cert_silent (ksba_cert_t cert, void *fpr_buffer)
{
  gpg_error_t err;

  acquire_cache_write_lock ();
  err = put_cert (cert, 0, 0, fpr_buffer);
  release_cache_lock ();
  if (gpg_err_code (err) == GPG_ERR_DUP_VALUE)
    err = 0;

  if (gpg_err_code (err) == GPG_ERR_NOT_ENABLED)
    log_info ("certificate skipped due to configuration\n");
  else if (err)
    log_error (_("error caching certificate: %s\n"), gpg_strerror (err));
  return err;
}



/* Return a certificate object for the given fingerprint.  FPR is
   expected to be a 20 byte binary SHA-1 fingerprint.  If no matching
   certificate is available in the cache NULL is returned.  The caller
   must release a returned certificate.  Note that although we are
   using reference counting the caller should not just compare the
   pointers to check for identical certificates. */
ksba_cert_t
get_cert_byfpr (const unsigned char *fpr)
{
  cert_item_t ci;

  acquire_cache_read_lock ();
  for (ci=cert_cache[*fpr]; ci; ci = ci->next)
    if (ci->cert && !memcmp (ci->fpr, fpr, 20))
      {
        ksba_cert_ref (ci->cert);
        release_cache_lock ();
        return ci->cert;
      }

  release_cache_lock ();
  return NULL;
}

/* Return a certificate object for the given fingerprint.  STRING is
   expected to be a SHA-1 fingerprint in standard hex notation with or
   without colons.  If no matching certificate is available in the
   cache NULL is returned.  The caller must release a returned
   certificate.  Note that although we are using reference counting
   the caller should not just compare the pointers to check for
   identical certificates. */
ksba_cert_t
get_cert_byhexfpr (const char *string)
{
  unsigned char fpr[20];
  const char *s;
  int i;

  if (strchr (string, ':'))
    {
      for (s=string,i=0; i < 20 && hexdigitp (s) && hexdigitp(s+1);)
        {
          if (s[2] && s[2] != ':')
            break; /* Invalid string. */
          fpr[i++] = xtoi_2 (s);
          s += 2;
          if (i!= 20 && *s == ':')
            s++;
        }
    }
  else
    {
      for (s=string,i=0; i < 20 && hexdigitp (s) && hexdigitp(s+1); s+=2 )
        fpr[i++] = xtoi_2 (s);
    }
  if (i!=20 || *s)
    {
      log_error (_("invalid SHA1 fingerprint string '%s'\n"), string);
      return NULL;
    }

  return get_cert_byfpr (fpr);
}



/* Return the certificate matching ISSUER_DN and SERIALNO.  */
ksba_cert_t
get_cert_bysn (const char *issuer_dn, ksba_sexp_t serialno)
{
  /* Simple and inefficient implementation.   fixme! */
  cert_item_t ci;
  int i;

  acquire_cache_read_lock ();
  for (i=0; i < 256; i++)
    {
      for (ci=cert_cache[i]; ci; ci = ci->next)
        if (ci->cert && !strcmp (ci->issuer_dn, issuer_dn)
            && !compare_serialno (ci->sn, serialno))
          {
            ksba_cert_ref (ci->cert);
            release_cache_lock ();
            return ci->cert;
          }
    }

  release_cache_lock ();
  return NULL;
}


/* Return the certificate matching ISSUER_DN.  SEQ should initially be
   set to 0 and bumped up to get the next issuer with that DN. */
ksba_cert_t
get_cert_byissuer (const char *issuer_dn, unsigned int seq)
{
  /* Simple and very inefficient implementation and API.  fixme! */
  cert_item_t ci;
  int i;

  acquire_cache_read_lock ();
  for (i=0; i < 256; i++)
    {
      for (ci=cert_cache[i]; ci; ci = ci->next)
        if (ci->cert && !strcmp (ci->issuer_dn, issuer_dn))
          if (!seq--)
            {
              ksba_cert_ref (ci->cert);
              release_cache_lock ();
              return ci->cert;
            }
    }

  release_cache_lock ();
  return NULL;
}


/* Return the certificate matching SUBJECT_DN.  SEQ should initially be
   set to 0 and bumped up to get the next subject with that DN. */
ksba_cert_t
get_cert_bysubject (const char *subject_dn, unsigned int seq)
{
  /* Simple and very inefficient implementation and API.  fixme! */
  cert_item_t ci;
  int i;

  if (!subject_dn)
    return NULL;

  acquire_cache_read_lock ();
  for (i=0; i < 256; i++)
    {
      for (ci=cert_cache[i]; ci; ci = ci->next)
        if (ci->cert && ci->subject_dn
            && !strcmp (ci->subject_dn, subject_dn))
          if (!seq--)
            {
              ksba_cert_ref (ci->cert);
              release_cache_lock ();
              return ci->cert;
            }
    }

  release_cache_lock ();
  return NULL;
}



/* Return a value describing the class of PATTERN.  The offset of
   the actual string to be used for the comparison is stored at
   R_OFFSET.  The offset of the serialnumer is stored at R_SN_OFFSET. */
static enum pattern_class
classify_pattern (const char *pattern, size_t *r_offset, size_t *r_sn_offset)
{
  enum pattern_class result;
  const char *s;
  int hexprefix = 0;
  int hexlength;

  *r_offset = *r_sn_offset = 0;

  /* Skip leading spaces. */
  for(s = pattern; *s && spacep (s); s++ )
    ;

  switch (*s)
    {
    case 0:  /* Empty string is an error. */
      result = PATTERN_UNKNOWN;
      break;

    case '.': /* An email address, compare from end.  */
      result = PATTERN_UNKNOWN;  /* Not implemented.  */
      break;

    case '<': /* An email address.  */
      result = PATTERN_EMAIL;
      s++;
      break;

    case '@': /* Part of an email address.  */
      result = PATTERN_EMAIL_SUBSTR;
      s++;
      break;

    case '=':  /* Exact compare. */
      result = PATTERN_UNKNOWN; /* Does not make sense for X.509.  */
      break;

    case '*':  /* Case insensitive substring search.  */
      result = PATTERN_SUBSTR;
      s++;
      break;

    case '+':  /* Compare individual words. */
      result = PATTERN_UNKNOWN;  /* Not implemented.  */
      break;

    case '/': /* Subject's DN. */
      s++;
      if (!*s || spacep (s))
        result = PATTERN_UNKNOWN; /* No DN or prefixed with a space. */
      else
        result = PATTERN_SUBJECT;
      break;

    case '#': /* Serial number or issuer DN. */
      {
        const char *si;

        s++;
        if ( *s == '/')
          {
            /* An issuer's DN is indicated by "#/" */
            s++;
            if (!*s || spacep (s))
              result = PATTERN_UNKNOWN; /* No DN or prefixed with a space. */
            else
              result = PATTERN_ISSUER;
          }
        else
          { /* Serialnumber + optional issuer ID. */
            for (si=s; *si && *si != '/'; si++)
              if (!strchr("01234567890abcdefABCDEF", *si))
                break;
            if (*si && *si != '/')
              result = PATTERN_UNKNOWN; /* Invalid digit in serial number. */
            else
              {
                *r_sn_offset = s - pattern;
                if (!*si)
                  result = PATTERN_SERIALNO;
                else
                  {
                    s = si+1;
                    if (!*s || spacep (s))
                      result = PATTERN_UNKNOWN; /* No DN or prefixed
                                                   with a space. */
                    else
                      result = PATTERN_SERIALNO_ISSUER;
                  }
              }
          }
      }
      break;

    case ':': /* Unified fingerprint. */
      {
        const char *se, *si;
        int i;

        se = strchr (++s, ':');
        if (!se)
          result = PATTERN_UNKNOWN;
        else
          {
            for (i=0, si=s; si < se; si++, i++ )
              if (!strchr("01234567890abcdefABCDEF", *si))
                break;
            if ( si < se )
              result = PATTERN_UNKNOWN; /* Invalid digit. */
            else if (i == 32)
              result = PATTERN_FINGERPRINT16;
            else if (i == 40)
              result = PATTERN_FINGERPRINT20;
            else
              result = PATTERN_UNKNOWN; /* Invalid length for a fingerprint. */
          }
      }
      break;

    case '&': /* Keygrip. */
      result = PATTERN_UNKNOWN;  /* Not implemented.  */
      break;

    default:
      if (s[0] == '0' && s[1] == 'x')
        {
          hexprefix = 1;
          s += 2;
        }

      hexlength = strspn(s, "0123456789abcdefABCDEF");

      /* Check if a hexadecimal number is terminated by EOS or blank. */
      if (hexlength && s[hexlength] && !spacep (s+hexlength))
        {
          /* If the "0x" prefix is used a correct termination is required. */
          if (hexprefix)
            {
              result = PATTERN_UNKNOWN;
              break; /* switch */
            }
          hexlength = 0;  /* Not a hex number.  */
        }

      if (hexlength == 8 || (!hexprefix && hexlength == 9 && *s == '0'))
        {
          if (hexlength == 9)
            s++;
          result = PATTERN_SHORT_KEYID;
        }
      else if (hexlength == 16 || (!hexprefix && hexlength == 17 && *s == '0'))
        {
          if (hexlength == 17)
            s++;
          result = PATTERN_LONG_KEYID;
        }
      else if (hexlength == 32 || (!hexprefix && hexlength == 33 && *s == '0'))
        {
          if (hexlength == 33)
            s++;
          result = PATTERN_FINGERPRINT16;
        }
      else if (hexlength == 40 || (!hexprefix && hexlength == 41 && *s == '0'))
        {
          if (hexlength == 41)
            s++;
          result = PATTERN_FINGERPRINT20;
        }
      else if (!hexprefix)
        {
          /* The fingerprints used with X.509 are often delimited by
             colons, so we try to single this case out. */
          result = PATTERN_UNKNOWN;
          hexlength = strspn (s, ":0123456789abcdefABCDEF");
          if (hexlength == 59 && (!s[hexlength] || spacep (s+hexlength)))
            {
              int i, c;

              for (i=0; i < 20; i++, s += 3)
                {
                  c = hextobyte(s);
                  if (c == -1 || (i < 19 && s[2] != ':'))
                    break;
                }
              if (i == 20)
                result = PATTERN_FINGERPRINT20;
            }
          if (result == PATTERN_UNKNOWN) /* Default to substring match. */
            {
              result = PATTERN_SUBSTR;
            }
        }
      else /* A hex number with a prefix but with a wrong length.  */
        result = PATTERN_UNKNOWN;
    }

  if (result != PATTERN_UNKNOWN)
    *r_offset = s - pattern;
  return result;
}



/* Given PATTERN, which is a string as used by GnuPG to specify a
   certificate, return all matching certificates by calling the
   supplied function RETFNC.  */
gpg_error_t
get_certs_bypattern (const char *pattern,
                     gpg_error_t (*retfnc)(void*,ksba_cert_t),
                     void *retfnc_data)
{
  gpg_error_t err = GPG_ERR_BUG;
  enum pattern_class class;
  size_t offset, sn_offset;
  const char *hexserialno;
  ksba_sexp_t serialno = NULL;
  ksba_cert_t cert = NULL;
  unsigned int seq;

  if (!pattern || !retfnc)
    return gpg_error (GPG_ERR_INV_ARG);

  class = classify_pattern (pattern, &offset, &sn_offset);
  hexserialno = pattern + sn_offset;
  pattern += offset;
  switch (class)
    {
    case PATTERN_UNKNOWN:
      err = gpg_error (GPG_ERR_INV_NAME);
      break;

    case PATTERN_FINGERPRINT20:
      cert = get_cert_byhexfpr (pattern);
      err = cert? 0 : gpg_error (GPG_ERR_NOT_FOUND);
      break;

    case PATTERN_SERIALNO_ISSUER:
      serialno = hexsn_to_sexp (hexserialno);
      if (!serialno)
        err = gpg_error_from_syserror ();
      else
        {
          cert = get_cert_bysn (pattern, serialno);
          err = cert? 0 : gpg_error (GPG_ERR_NOT_FOUND);
        }
      break;

    case PATTERN_ISSUER:
      for (seq=0,err=0; !err && (cert = get_cert_byissuer (pattern, seq)); seq++)
        {
          err = retfnc (retfnc_data, cert);
          ksba_cert_release (cert);
          cert = NULL;
        }
      if (!err && !seq)
        err = gpg_error (GPG_ERR_NOT_FOUND);
      break;

    case PATTERN_SUBJECT:
      for (seq=0,err=0; !err && (cert = get_cert_bysubject (pattern, seq));seq++)
        {
          err = retfnc (retfnc_data, cert);
          ksba_cert_release (cert);
          cert = NULL;
        }
      if (!err && !seq)
        err = gpg_error (GPG_ERR_NOT_FOUND);
      break;

    case PATTERN_EMAIL:
    case PATTERN_EMAIL_SUBSTR:
    case PATTERN_FINGERPRINT16:
    case PATTERN_SHORT_KEYID:
    case PATTERN_LONG_KEYID:
    case PATTERN_SUBSTR:
    case PATTERN_SERIALNO:
      /* Not supported.  */
      err = gpg_error (GPG_ERR_INV_NAME);
    }


  if (!err && cert)
    err = retfnc (retfnc_data, cert);
  ksba_cert_release (cert);
  xfree (serialno);
  return err;
}





/* Return the certificate matching ISSUER_DN and SERIALNO; if it is
 * not already in the cache, try to find it from other resources.  */
ksba_cert_t
find_cert_bysn (ctrl_t ctrl, const char *issuer_dn, ksba_sexp_t serialno)
{
  gpg_error_t err;
  ksba_cert_t cert;
  cert_fetch_context_t context = NULL;
  char *hexsn, *buf;

  /* First check whether it has already been cached.  */
  cert = get_cert_bysn (issuer_dn, serialno);
  if (cert)
    return cert;

  /* Ask back to the service requester to return the certificate.
   * This is because we can assume that he already used the
   * certificate while checking for the CRL.  */
  hexsn = serial_hex (serialno);
  if (!hexsn)
    {
      log_error ("serial_hex() failed\n");
      return NULL;
    }
  buf = strconcat ("#", hexsn, "/", issuer_dn, NULL);
  if (!buf)
    {
      log_error ("can't allocate enough memory: %s\n", strerror (errno));
      xfree (hexsn);
      return NULL;
    }
  xfree (hexsn);

  cert = get_cert_local (ctrl, buf);
  xfree (buf);
  if (cert)
    {
      cache_cert (cert);
      return cert; /* Done. */
    }

  if (DBG_LOOKUP)
    log_debug ("find_cert_bysn: certificate not returned by caller"
               " - doing lookup\n");

  /* Retrieve the certificate from external resources. */
  while (!cert)
    {
      ksba_sexp_t sn;
      char *issdn;

      if (!context)
        {
          err = ca_cert_fetch (ctrl, &context, issuer_dn);
          if (err)
            {
              log_error (_("error fetching certificate by S/N: %s\n"),
                         gpg_strerror (err));
              break;
            }
        }

      err = fetch_next_ksba_cert (context, &cert);
      if (err)
        {
          log_error (_("error fetching certificate by S/N: %s\n"),
                     gpg_strerror (err) );
          break;
        }

      issdn = ksba_cert_get_issuer (cert, 0);
      if (strcmp (issuer_dn, issdn))
        {
          log_debug ("find_cert_bysn: Ooops: issuer DN does not match\n");
          ksba_cert_release (cert);
          cert = NULL;
          ksba_free (issdn);
          break;
        }

      sn = ksba_cert_get_serial (cert);

      if (DBG_LOOKUP)
        {
          log_debug ("   considering certificate (#");
          dump_serial (sn);
          log_printf ("/");
          dump_string (issdn);
          log_printf (")\n");
        }

      if (!compare_serialno (serialno, sn))
        {
          ksba_free (sn);
          ksba_free (issdn);
          cache_cert (cert);
          if (DBG_LOOKUP)
            log_debug ("   found\n");
          break; /* Ready.  */
        }

      ksba_free (sn);
      ksba_free (issdn);
      ksba_cert_release (cert);
      cert = NULL;
    }

  end_cert_fetch (context);
  return cert;
}


/* Return the certificate matching SUBJECT_DN and (if not NULL)
 * KEYID. If it is not already in the cache, try to find it from other
 * resources.  Note, that the external search does not work for user
 * certificates because the LDAP lookup is on the caCertificate
 * attribute. For our purposes this is just fine.  */
ksba_cert_t
find_cert_bysubject (ctrl_t ctrl, const char *subject_dn, ksba_sexp_t keyid)
{
  gpg_error_t err;
  int seq;
  ksba_cert_t cert = NULL;
  ksba_cert_t first;         /* The first certificate found.  */
  cert_fetch_context_t context = NULL;
  ksba_sexp_t subj;

  /* If we have certificates from an OCSP request we first try to use
   * them.  This is because these certificates will really be the
   * required ones and thus even in the case that they can't be
   * uniquely located by the following code we can use them.  This is
   * for example required by Telesec certificates where a keyId is
   * used but the issuer certificate comes without a subject keyId! */
  if (ctrl->ocsp_certs && subject_dn)
    {
      cert_item_t ci;
      cert_ref_t cr;
      int i;

      /* For efficiency reasons we won't use get_cert_bysubject here. */
      acquire_cache_read_lock ();
      for (i=0; i < 256; i++)
        for (ci=cert_cache[i]; ci; ci = ci->next)
          if (ci->cert && ci->subject_dn
              && !strcmp (ci->subject_dn, subject_dn))
            for (cr=ctrl->ocsp_certs; cr; cr = cr->next)
              if (!memcmp (ci->fpr, cr->fpr, 20))
                {
                  ksba_cert_ref (ci->cert);
                  release_cache_lock ();
                  if (DBG_LOOKUP)
                    log_debug ("%s: certificate found in the cache"
                               " via ocsp_certs\n", __func__);
                  return ci->cert; /* We use this certificate. */
                }
      release_cache_lock ();
      if (DBG_LOOKUP)
        log_debug ("find_cert_bysubject: certificate not in ocsp_certs\n");
    }

  /* Now check whether the certificate is cached.  */
  first = NULL;
  subj = NULL;
  for (seq=0; (cert = get_cert_bysubject (subject_dn, seq)); seq++)
    {
      if (!keyid
          || (!ksba_cert_get_subj_key_id (cert, NULL, &subj)
              && !cmp_simple_canon_sexp (keyid, subj)))
        {
          xfree (subj);
          subj = NULL;
          if (DBG_LOOKUP)
            log_debug ("%s: certificate found in the cache"
                       " %sby subject DN\n", __func__, !keyid?"only ":"");

          /* If this a trusted cert - then prefer it.  */
          if (!is_trusted_cert (cert, (CERTTRUST_CLASS_SYSTEM
                                       | CERTTRUST_CLASS_CONFIG)))
            {
              ksba_cert_release (first);
              first = cert;
              cert = NULL;
              /* We stop at the first trusted certificate and ignore
               * any yet found non-trusted certificates.   */
              break;
            }
          else if (!first)
            {
              /* Not trusted.  Save only the first one but continue
               * the loop in case there is also a trusted one.  */
              ksba_cert_release (first);
              first = cert;
              cert = NULL;
            }
        }
      xfree (subj);
      subj = NULL;
      ksba_cert_release (cert);
    }
  if (first)
    return first; /* Return the first found certificate.  */

  /* If we do not have a subject DN but have a keyid, try to locate it
   * by keyid.  */
  if (!subject_dn && keyid)
    {
      int i;
      cert_item_t ci;
      ksba_sexp_t ski;

      acquire_cache_read_lock ();
      for (i=0; i < 256; i++)
        for (ci=cert_cache[i]; ci; ci = ci->next)
          if (ci->cert && !ksba_cert_get_subj_key_id (ci->cert, NULL, &ski))
            {
              if (!cmp_simple_canon_sexp (keyid, ski))
                {
                  ksba_free (ski);
                  ksba_cert_ref (ci->cert);
                  release_cache_lock ();
                  if (DBG_LOOKUP)
                    log_debug ("%s: certificate found in the cache"
                               " via ski\n", __func__);
                  return ci->cert;
                }
              ksba_free (ski);
            }
      release_cache_lock ();
    }

  if (DBG_LOOKUP)
    log_debug ("find_cert_bysubject: certificate not in cache\n");

  /* Ask back to the service requester to return the certificate.
   * This is because we can assume that he already used the
   * certificate while checking for the CRL. */
  if (keyid)
    cert = get_cert_local_ski (ctrl, subject_dn, keyid);
  else
    {
      /* In contrast to get_cert_local_ski, get_cert_local uses any
       * passed pattern, so we need to make sure that an exact subject
       * search is done.  */
      char *buf;

      buf = strconcat ("/", subject_dn, NULL);
      if (!buf)
        {
          log_error ("can't allocate enough memory: %s\n", strerror (errno));
          return NULL;
        }
      cert = get_cert_local (ctrl, buf);
      xfree (buf);
    }
  if (cert)
    {
      cache_cert (cert);
      return cert; /* Done. */
    }

  if (DBG_LOOKUP)
    log_debug ("find_cert_bysubject: certificate not returned by caller"
               " - doing lookup\n");

  /* Locate the certificate using external resources. */
  while (!cert)
    {
      char *subjdn;

      if (!context)
        {
          err = ca_cert_fetch (ctrl, &context, subject_dn);
          if (err)
            {
              log_error (_("error fetching certificate by subject: %s\n"),
                         gpg_strerror (err));
              break;
            }
        }

      err = fetch_next_ksba_cert (context, &cert);
      if (err)
        {
          log_error (_("error fetching certificate by subject: %s\n"),
                     gpg_strerror (err) );
          break;
        }

      subjdn = ksba_cert_get_subject (cert, 0);
      if (strcmp (subject_dn, subjdn))
        {
          log_info ("find_cert_bysubject: subject DN does not match\n");
          ksba_cert_release (cert);
          cert = NULL;
          ksba_free (subjdn);
          continue;
        }


      if (DBG_LOOKUP)
        {
          log_debug ("   considering certificate (/");
          dump_string (subjdn);
          log_printf (")\n");
        }
      ksba_free (subjdn);

      /* If no key ID has been provided, we return the first match.  */
      if (!keyid)
        {
          cache_cert (cert);
          if (DBG_LOOKUP)
            log_debug ("   found\n");
          break; /* Ready.  */
        }

      /* With the key ID given we need to compare it.  */
      if (!ksba_cert_get_subj_key_id (cert, NULL, &subj))
        {
          if (!cmp_simple_canon_sexp (keyid, subj))
            {
              ksba_free (subj);
              cache_cert (cert);
              if (DBG_LOOKUP)
                log_debug ("   found\n");
              break; /* Ready.  */
            }
        }

      ksba_free (subj);
      ksba_cert_release (cert);
      cert = NULL;
    }

  end_cert_fetch (context);
  return cert;
}


/* Return 0 if the certificate is a trusted certificate. Returns
 * GPG_ERR_NOT_TRUSTED if it is not trusted or other error codes in
 * case of systems errors.  TRUSTCLASSES are the bitwise ORed
 * CERTTRUST_CLASS values to use for the check.  */
gpg_error_t
is_trusted_cert (ksba_cert_t cert, unsigned int trustclasses)
{
  unsigned char fpr[20];
  cert_item_t ci;

  cert_compute_fpr (cert, fpr);

  acquire_cache_read_lock ();
  for (ci=cert_cache[*fpr]; ci; ci = ci->next)
    if (ci->cert && !memcmp (ci->fpr, fpr, 20))
      {
        if ((ci->trustclasses & trustclasses))
          {
            /* The certificate is trusted in one of the given
             * TRUSTCLASSES.  */
            release_cache_lock ();
            return 0; /* Yes, it is trusted. */
          }
        break;
      }

  release_cache_lock ();
  return gpg_error (GPG_ERR_NOT_TRUSTED);
}



/* Given the certificate CERT locate the issuer for this certificate
 * and return it at R_CERT.  Returns 0 on success or
 * GPG_ERR_NOT_FOUND.  */
gpg_error_t
find_issuing_cert (ctrl_t ctrl, ksba_cert_t cert, ksba_cert_t *r_cert)
{
  gpg_error_t err;
  char *issuer_dn;
  ksba_cert_t issuer_cert = NULL;
  ksba_name_t authid;
  ksba_sexp_t authidno;
  ksba_sexp_t keyid;

  *r_cert = NULL;

  issuer_dn = ksba_cert_get_issuer (cert, 0);
  if (!issuer_dn)
    {
      log_error (_("no issuer found in certificate\n"));
      err = gpg_error (GPG_ERR_BAD_CERT);
      goto leave;
    }

  /* First we need to check whether we can return that certificate
     using the authorithyKeyIdentifier.  */
  err = ksba_cert_get_auth_key_id (cert, &keyid, &authid, &authidno);
  if (err)
    {
      log_info (_("error getting authorityKeyIdentifier: %s\n"),
                gpg_strerror (err));
    }
  else
    {
      const char *s = ksba_name_enum (authid, 0);
      if (s && *authidno)
        {
          issuer_cert = find_cert_bysn (ctrl, s, authidno);
        }

      if (!issuer_cert && keyid)
        {
          /* Not found by issuer+s/n.  Now that we have an AKI
           * keyIdentifier look for a certificate with a matching
           * SKI. */
          issuer_cert = find_cert_bysubject (ctrl, issuer_dn, keyid);
        }

      /* Print a note so that the user does not feel too helpless when
       * an issuer certificate was found and gpgsm prints BAD
       * signature because it is not the correct one.  */
      if (!issuer_cert)
        {
          log_info ("issuer certificate ");
          if (keyid)
            {
              log_printf ("{");
              dump_serial (keyid);
              log_printf ("} ");
            }
          if (authidno)
            {
              log_printf ("(#");
              dump_serial (authidno);
              log_printf ("/");
              dump_string (s);
              log_printf (") ");
            }
          log_printf ("not found using authorityKeyIdentifier\n");
        }
      ksba_name_release (authid);
      xfree (authidno);
      xfree (keyid);
    }

  /* If this did not work, try just with the issuer's name and assume
   * that there is only one such certificate.  We only look into our
   * cache then.  */
  if (err || !issuer_cert)
    {
      issuer_cert = get_cert_bysubject (issuer_dn, 0);
      if (issuer_cert)
        err = 0;
    }

 leave:
  if (!err && !issuer_cert)
    err = gpg_error (GPG_ERR_NOT_FOUND);

  xfree (issuer_dn);

  if (err)
    ksba_cert_release (issuer_cert);
  else
    *r_cert = issuer_cert;

  return err;
}



/* Read a list of certificates in PEM format from stream FP and store
 * them on success at R_CERTLIST.  On error NULL is stored at R_CERT
 * list and an error code returned.  Note that even on success an
 * empty list of certificates can be returned (i.e. NULL stored at
 * R_CERTLIST) iff the input stream has no certificates.  */
gpg_error_t
read_certlist_from_stream (certlist_t *r_certlist, estream_t fp)
{
  gpg_error_t err;
  gnupg_ksba_io_t ioctx = NULL;
  ksba_reader_t reader;
  ksba_cert_t cert = NULL;
  certlist_t certlist = NULL;
  certlist_t cl, *cltail;

  *r_certlist = NULL;

  err = gnupg_ksba_create_reader (&ioctx,
                                  (GNUPG_KSBA_IO_PEM | GNUPG_KSBA_IO_MULTIPEM),
                                  fp, &reader);
  if (err)
    goto leave;

  /* Loop to read all certificates from the stream.  */
  cltail = &certlist;
  do
    {
      ksba_cert_release (cert);
      cert = NULL;
      err = ksba_cert_new (&cert);
      if (!err)
        err = ksba_cert_read_der (cert, reader);
      if (err)
        {
          if (gpg_err_code (err) == GPG_ERR_EOF)
            err = 0;
          goto leave;
        }

      /* Append the certificate to the list.  We also store the
       * fingerprint and check whether we have a cached certificate;
       * in that case the cached certificate is put into the list to
       * take advantage of a validation result which might be stored
       * in the cached certificate.  */
      cl = xtrycalloc (1, sizeof *cl);
      if (!cl)
        {
          err = gpg_error_from_syserror ();
          goto leave;
        }
      cert_compute_fpr (cert, cl->fpr);
      cl->cert = get_cert_byfpr (cl->fpr);
      if (!cl->cert)
        {
          cl->cert = cert;
          cert = NULL;
        }
      *cltail = cl;
      cltail = &cl->next;
      ksba_reader_clear (reader, NULL, NULL);
    }
  while (!gnupg_ksba_reader_eof_seen (ioctx));

 leave:
  ksba_cert_release (cert);
  gnupg_ksba_destroy_reader (ioctx);
  if (err)
    release_certlist (certlist);
  else
    *r_certlist = certlist;

  return err;
}


/* Release the certificate list CL.  */
void
release_certlist (certlist_t cl)
{
  while (cl)
    {
      certlist_t next = cl->next;
      ksba_cert_release (cl->cert);
      cl = next;
    }
}
