/* certcache.c - Certificate caching
 *      Copyright (C) 2004, 2005, 2007, 2008 g10 Code GmbH
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
 * along with this program; if not, see <http://www.gnu.org/licenses/>.
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
#include "crlfetch.h"
#include "certcache.h"


#define MAX_EXTRA_CACHED_CERTS 1000

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
  struct
  {
    unsigned int loaded:1;  /* It has been explicitly loaded.  */
    unsigned int trusted:1; /* This is a trusted root certificate.  */
  } flags;
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

/* Total number of certificates loaded during initialization and
   cached during operation.  */
static unsigned int total_loaded_certificates;
static unsigned int total_extra_certificates;



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
   converted from the hex string HEXSN.  Return NULL on memory
   error. */
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

  ksba_cert_release (cert);
}


/* Put the certificate CERT into the cache.  It is assumed that the
   cache is locked while this function is called. If FPR_BUFFER is not
   NULL the fingerprint of the certificate will be stored there.
   FPR_BUFFER neds to point to a buffer of at least 20 bytes. The
   fingerprint will be stored on success or when the function returns
   gpg_err_code(GPG_ERR_DUP_VALUE). */
static gpg_error_t
put_cert (ksba_cert_t cert, int is_loaded, int is_trusted, void *fpr_buffer)
{
  unsigned char help_fpr_buffer[20], *fpr;
  cert_item_t ci;

  fpr = fpr_buffer? fpr_buffer : &help_fpr_buffer;

  /* If we already reached the caching limit, drop a couple of certs
     from the cache.  Our dropping strategy is simple: We keep a
     static index counter and use this to start looking for
     certificates, then we drop 5 percent of the oldest certificates
     starting at that index.  For a large cache this is a fair way of
     removing items. An LRU strategy would be better of course.
     Because we append new entries to the head of the list and we want
     to remove old ones first, we need to do this from the tail.  The
     implementation is not very efficient but compared to the long
     time it takes to retrieve a certifciate from an external resource
     it seems to be reasonable. */
  if (!is_loaded && total_extra_certificates >= MAX_EXTRA_CACHED_CERTS)
    {
      static int idx;
      cert_item_t ci_mark;
      int i;
      unsigned int drop_count;

      drop_count = MAX_EXTRA_CACHED_CERTS / 20;
      if (drop_count < 2)
        drop_count = 2;

      log_info (_("dropping %u certificates from the cache\n"), drop_count);
      assert (idx < 256);
      for (i=idx; drop_count; i = ((i+1)%256))
        {
          ci_mark = NULL;
          for (ci = cert_cache[i]; ci; ci = ci->next)
            if (ci->cert && !ci->flags.loaded)
              ci_mark = ci;
          if (ci_mark)
            {
              clean_cache_slot (ci_mark);
              drop_count--;
              total_extra_certificates--;
            }
        }
      if (i==idx)
        idx++;
      else
        idx = i;
      idx %= 256;
    }

  cert_compute_fpr (cert, fpr);
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
  else
    memset (&ci->flags, 0, sizeof ci->flags);

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
  ci->flags.loaded  = !!is_loaded;
  ci->flags.trusted = !!is_trusted;

  if (is_loaded)
    total_loaded_certificates++;
  else
    total_extra_certificates++;

  return 0;
}


/* Load certificates from the directory DIRNAME.  All certificates
   matching the pattern "*.crt" or "*.der"  are loaded.  We assume that
   certificates are DER encoded and not PEM encapsulated. The cache
   should be in a locked state when calling this function.  */
static gpg_error_t
load_certs_from_dir (const char *dirname, int are_trusted)
{
  gpg_error_t err;
  DIR *dir;
  struct dirent *ep;
  char *p;
  size_t n;
  estream_t fp;
  ksba_reader_t reader;
  ksba_cert_t cert;
  char *fname = NULL;

  dir = opendir (dirname);
  if (!dir)
    {
      if (opt.system_daemon)
        log_info (_("can't access directory '%s': %s\n"),
                  dirname, strerror (errno));
      return 0; /* We do not consider this a severe error.  */
    }

  while ( (ep=readdir (dir)) )
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

      err = put_cert (cert, 1, are_trusted, NULL);
      if (gpg_err_code (err) == GPG_ERR_DUP_VALUE)
        log_info (_("certificate '%s' already cached\n"), fname);
      else if (!err)
        {
          if (are_trusted)
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
      else
        log_error (_("error loading certificate '%s': %s\n"),
                     fname, gpg_strerror (err));
      ksba_cert_release (cert);
    }

  xfree (fname);
  closedir (dir);
  return 0;
}


/* Initialize the certificate cache if not yet done.  */
void
cert_cache_init (void)
{
  char *dname;

  if (initialization_done)
    return;
  init_cache_lock ();
  acquire_cache_write_lock ();

  dname = make_filename (gnupg_sysconfdir (), "trusted-certs", NULL);
  load_certs_from_dir (dname, 1);
  xfree (dname);

  dname = make_filename (gnupg_sysconfdir (), "extra-certs", NULL);
  load_certs_from_dir (dname, 0);
  xfree (dname);

  initialization_done = 1;
  release_cache_lock ();

  cert_cache_print_stats ();
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

  total_loaded_certificates = 0;
  total_extra_certificates = 0;
  initialization_done = 0;
  release_cache_lock ();
}

/* Print some statistics to the log file.  */
void
cert_cache_print_stats (void)
{
  log_info (_("permanently loaded certificates: %u\n"),
            total_loaded_certificates);
  log_info (_("    runtime cached certificates: %u\n"),
            total_extra_certificates);
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
  if (err)
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



/* Return a value describing the the class of PATTERN.  The offset of
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
   not already in the cache, try to find it from other resources.  */
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
     This is because we can assume that he already used the
     certificate while checking for the CRL. */
  hexsn = serial_hex (serialno);
  if (!hexsn)
    {
      log_error ("serial_hex() failed\n");
      return NULL;
    }
  buf = xtrymalloc (1 + strlen (hexsn) + 1 + strlen (issuer_dn) + 1);
  if (!buf)
    {
      log_error ("can't allocate enough memory: %s\n", strerror (errno));
      xfree (hexsn);
      return NULL;
    }
  strcpy (stpcpy (stpcpy (stpcpy (buf, "#"), hexsn),"/"), issuer_dn);
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
   KEYID. If it is not already in the cache, try to find it from other
   resources.  Note, that the external search does not work for user
   certificates because the LDAP lookup is on the caCertificate
   attribute. For our purposes this is just fine.  */
ksba_cert_t
find_cert_bysubject (ctrl_t ctrl, const char *subject_dn, ksba_sexp_t keyid)
{
  gpg_error_t err;
  int seq;
  ksba_cert_t cert = NULL;
  cert_fetch_context_t context = NULL;
  ksba_sexp_t subj;

  /* If we have certificates from an OCSP request we first try to use
     them.  This is because these certificates will really be the
     required ones and thus even in the case that they can't be
     uniquely located by the following code we can use them.  This is
     for example required by Telesec certificates where a keyId is
     used but the issuer certificate comes without a subject keyId! */
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
                  return ci->cert; /* We use this certificate. */
                }
      release_cache_lock ();
      if (DBG_LOOKUP)
        log_debug ("find_cert_bysubject: certificate not in ocsp_certs\n");
    }


  /* First we check whether the certificate is cached.  */
  for (seq=0; (cert = get_cert_bysubject (subject_dn, seq)); seq++)
    {
      if (!keyid)
        break; /* No keyid requested, so return the first one found. */
      if (!ksba_cert_get_subj_key_id (cert, NULL, &subj)
          && !cmp_simple_canon_sexp (keyid, subj))
        {
          xfree (subj);
          break; /* Found matching cert. */
        }
      xfree (subj);
      ksba_cert_release (cert);
    }
  if (cert)
    return cert; /* Done.  */

  if (DBG_LOOKUP)
    log_debug ("find_cert_bysubject: certificate not in cache\n");

  /* Ask back to the service requester to return the certificate.
     This is because we can assume that he already used the
     certificate while checking for the CRL. */
  if (keyid)
    cert = get_cert_local_ski (ctrl, subject_dn, keyid);
  else
    {
      /* In contrast to get_cert_local_ski, get_cert_local uses any
         passed pattern, so we need to make sure that an exact subject
         search is done. */
      char *buf;

      buf = xtrymalloc (1 + strlen (subject_dn) + 1);
      if (!buf)
        {
          log_error ("can't allocate enough memory: %s\n", strerror (errno));
          return NULL;
        }
      strcpy (stpcpy (buf, "/"), subject_dn);
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
   GPG_ERR_NOT_TRUSTED if it is not trusted or other error codes in
   case of systems errors. */
gpg_error_t
is_trusted_cert (ksba_cert_t cert)
{
  unsigned char fpr[20];
  cert_item_t ci;

  cert_compute_fpr (cert, fpr);

  acquire_cache_read_lock ();
  for (ci=cert_cache[*fpr]; ci; ci = ci->next)
    if (ci->cert && !memcmp (ci->fpr, fpr, 20))
      {
        if (ci->flags.trusted)
          {
            release_cache_lock ();
            return 0; /* Yes, it is trusted. */
          }
        break;
      }

  release_cache_lock ();
  return gpg_error (GPG_ERR_NOT_TRUSTED);
}



/* Given the certificate CERT locate the issuer for this certificate
   and return it at R_CERT.  Returns 0 on success or
   GPG_ERR_NOT_FOUND.  */
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
             keyIdentifier look for a certificate with a matching
             SKI. */
          issuer_cert = find_cert_bysubject (ctrl, issuer_dn, keyid);
        }
      /* Print a note so that the user does not feel too helpless when
         an issuer certificate was found and gpgsm prints BAD
         signature because it is not the correct one. */
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
     that there is only one such certificate.  We only look into our
     cache then. */
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
