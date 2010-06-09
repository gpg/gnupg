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


enum {
  /* Simple certificate validation mode. */
  VALIDATE_MODE_CERT = 0,
  /* Standard CRL issuer certificate validation; i.e. CRLs are not
     considered for CRL issuer certificates. */
  VALIDATE_MODE_CRL = 1,
  /* Full CRL validation. */
  VALIDATE_MODE_CRL_RECURSIVE = 2,
  /* Validation as used for OCSP. */
  VALIDATE_MODE_OCSP = 3
};


/* Validate the certificate CHAIN up to the trust anchor. Optionally
   return the closest expiration time in R_EXPTIME. */
gpg_error_t validate_cert_chain (ctrl_t ctrl,
                                 ksba_cert_t cert, ksba_isotime_t r_exptime,
                                 int mode, char **r_trust_anchor);

/* Return 0 if the certificate CERT is usable for certification.  */
gpg_error_t cert_use_cert_p (ksba_cert_t cert);

/* Return 0 if the certificate CERT is usable for signing OCSP
   responses.  */
gpg_error_t cert_use_ocsp_p (ksba_cert_t cert);

/* Return 0 if the certificate CERT is usable for signing CRLs. */
gpg_error_t cert_use_crl_p (ksba_cert_t cert);


#endif /*VALIDATE_H*/
