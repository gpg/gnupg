/* dns-cert.h - DNS CERT definition
 * Copyright (C) 2006 Free Software Foundation, Inc.
 *
 * This file is part of GnuPG.
 *
 * This file is free software; you can redistribute it and/or modify
 * it under the terms of either
 *
 *   - the GNU Lesser General Public License as published by the Free
 *     Software Foundation; either version 3 of the License, or (at
 *     your option) any later version.
 *
 * or
 *
 *   - the GNU General Public License as published by the Free
 *     Software Foundation; either version 2 of the License, or (at
 *     your option) any later version.
 *
 * or both in parallel, as here.
 *
 * This file is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, see <http://www.gnu.org/licenses/>.
 */
#ifndef GNUPG_DIRMNGR_DNS_CERT_H
#define GNUPG_DIRMNGR_DNS_CERT_H


#define DNS_CERTTYPE_ANY       0 /* Internal catch all type. */
/* Certificate types according to RFC-4398:  */
#define DNS_CERTTYPE_PKIX      1 /* X.509 as per PKIX. */
#define DNS_CERTTYPE_SPKI      2 /* SPKI certificate.  */
#define DNS_CERTTYPE_PGP       3 /* OpenPGP packet.  */
#define DNS_CERTTYPE_IPKIX     4 /* The URL of an X.509 data object. */
#define DNS_CERTTYPE_ISPKI     5 /* The URL of an SPKI certificate.  */
#define DNS_CERTTYPE_IPGP      6 /* The fingerprint
                                    and URL of an OpenPGP packet.  */
#define DNS_CERTTYPE_ACPKIX    7 /* Attribute Certificate.  */
#define DNS_CERTTYPE_IACPKIX   8 /* The URL of an Attribute Certificate.  */
#define DNS_CERTTYPE_URI     253 /* URI private.  */
#define DNS_CERTTYPE_OID     254 /* OID private.  */


gpg_error_t get_dns_cert (const char *name, int want_certtype,
                          void **r_key, size_t *r_keylen,
                          unsigned char **r_fpr, size_t *r_fprlen,
                          char **r_url);



#endif /*GNUPG_DIRMNGR_DNS_CERT_H*/
