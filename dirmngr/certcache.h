/* certcache.h - Certificate caching
 *      Copyright (C) 2004, 2008 g10 Code GmbH
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
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA
 */

#ifndef CERTCACHE_H
#define CERTCACHE_H

/* First time initialization of the certificate cache.  */
void cert_cache_init (void);

/* Deinitialize the certificate cache.  */
void cert_cache_deinit (int full);

/* Print some statistics to the log file.  */
void cert_cache_print_stats (void);

/* Compute the fingerprint of the certificate CERT and put it into
   the 20 bytes large buffer DIGEST.  Return address of this buffer.  */
unsigned char *cert_compute_fpr (ksba_cert_t cert, unsigned char *digest);

/* Put CERT into the certificate cache.  */
gpg_error_t cache_cert (ksba_cert_t cert);

/* Put CERT into the certificate cache and return the fingerprint. */
gpg_error_t cache_cert_silent (ksba_cert_t cert, void *fpr_buffer);

/* Return 0 if the certificate is a trusted certificate. Returns
   GPG_ERR_NOT_TRUSTED if it is not trusted or other error codes in
   case of systems errors. */
gpg_error_t is_trusted_cert (ksba_cert_t cert);


/* Return a certificate object for the given fingerprint.  FPR is
   expected to be a 20 byte binary SHA-1 fingerprint.  If no matching
   certificate is available in the cache NULL is returned.  The caller
   must release a returned certificate.  */
ksba_cert_t get_cert_byfpr (const unsigned char *fpr);

/* Return a certificate object for the given fingerprint.  STRING is
   expected to be a SHA-1 fingerprint in standard hex notation with or
   without colons.  If no matching certificate is available in the
   cache NULL is returned.  The caller must release a returned
   certificate.  */
ksba_cert_t get_cert_byhexfpr (const char *string);

/* Return the certificate matching ISSUER_DN and SERIALNO.  */
ksba_cert_t get_cert_bysn (const char *issuer_dn, ksba_sexp_t serialno);

/* Return the certificate matching ISSUER_DN.  SEQ should initially be
   set to 0 and bumped up to get the next issuer with that DN. */
ksba_cert_t get_cert_byissuer (const char *issuer_dn, unsigned int seq);

/* Return the certificate matching SUBJECT_DN.  SEQ should initially be
   set to 0 and bumped up to get the next issuer with that DN. */
ksba_cert_t get_cert_bysubject (const char *subject_dn, unsigned int seq);

/* Given PATTERN, which is a string as used by GnuPG to specify a
   certificate, return all matching certificates by calling the
   supplied function RETFNC.  */
gpg_error_t get_certs_bypattern (const char *pattern,
                                 gpg_error_t (*retfnc)(void*,ksba_cert_t),
                                 void *retfnc_data);

/* Return the certificate matching ISSUER_DN and SERIALNO; if it is
   not already in the cache, try to find it from other resources.  */
ksba_cert_t find_cert_bysn (ctrl_t ctrl,
                            const char *issuer_dn, ksba_sexp_t serialno);


/* Return the certificate matching SUBJECT_DN and (if not NULL) KEYID. If
   it is not already in the cache, try to find it from other
   resources.  Note, that the external search does not work for user
   certificates because the LDAP lookup is on the caCertificate
   attribute. For our purposes this is just fine.  */
ksba_cert_t find_cert_bysubject (ctrl_t ctrl,
                                 const char *subject_dn, ksba_sexp_t keyid);

/* Given the certificate CERT locate the issuer for this certificate
   and return it at R_CERT.  Returns 0 on success or
   GPG_ERR_NOT_FOUND.  */
gpg_error_t find_issuing_cert (ctrl_t ctrl,
                               ksba_cert_t cert, ksba_cert_t *r_cert);




#endif /*CERTCACHE_H*/
