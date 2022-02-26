/* validate.h - Certificate validation
 *      Copyright (C) 2004 g10 Code GmbH
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

#ifndef VALIDATE_H
#define VALIDATE_H


/* Flag values matching the CERTTRUST_CLASS values and a MASK for
 * them.  check_header_constants() checks their consistency.  */
#define VALIDATE_FLAG_TRUST_SYSTEM     1
#define VALIDATE_FLAG_TRUST_CONFIG     2
#define VALIDATE_FLAG_TRUST_HKP        4
#define VALIDATE_FLAG_TRUST_HKPSPOOL   8
#define VALIDATE_FLAG_MASK_TRUST      0x0f

/* Standard CRL issuer certificate validation; i.e. CRLs are not
 * considered for CRL issuer certificates.  */
#define VALIDATE_FLAG_CRL          64

/* If this flag is set along with VALIDATE_FLAG_CRL a full CRL
 * verification is done.  */
#define VALIDATE_FLAG_RECURSIVE    128

/* Validation mode as used for OCSP.  */
#define VALIDATE_FLAG_OCSP         256

/* Validation mode as used with TLS.  */
#define VALIDATE_FLAG_TLS          512

/* Don't do CRL checks.  */
#define VALIDATE_FLAG_NOCRLCHECK  1024


/* Helper to get the public key algo from a public key.  */
int pk_algo_from_sexp (gcry_sexp_t pkey);

/* Validate the certificate CHAIN up to the trust anchor. Optionally
   return the closest expiration time in R_EXPTIME. */
gpg_error_t validate_cert_chain (ctrl_t ctrl,
                                 ksba_cert_t cert, ksba_isotime_t r_exptime,
                                 unsigned int flags, char **r_trust_anchor);

/* Return 0 if the certificate CERT is usable for certification.  */
gpg_error_t check_cert_use_cert (ksba_cert_t cert);

/* Return 0 if the certificate CERT is usable for signing OCSP
   responses.  */
gpg_error_t check_cert_use_ocsp (ksba_cert_t cert);

/* Return 0 if the certificate CERT is usable for signing CRLs. */
gpg_error_t check_cert_use_crl (ksba_cert_t cert);


#endif /*VALIDATE_H*/
