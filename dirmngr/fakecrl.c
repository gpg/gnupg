/* fakecrl.c - Debug code to test revocations.
 * Copyright (C) 2023 g10 Code GmbH
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
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

/*
 * For regression testing it is useful to have a way to claim that
 * certain certificates are revoked.  We achieve this with the
 * --fake-crl option which takes a file name as argument.  The format
 * of the file is: empty lines and lines starting with a hash sign are
 * ignored.  A line with the issuer DN in brackets starts entries for
 * this issuer.  All following lines up to the next line with a
 * bracket list revoked certificates.  For each revoked certificate
 * the hexadecimal encoded serial number is listed, followed by the
 * revocation date in ISO 14 byte notation, optionally followed by a
 * reason keyword.  Example:
 *---------------------
 * # Sample Fake CRL
 * [CN=Bayern-Softtoken-Issuing-CA-2019,OU=IT-DLZ,O=Freistaat Bayern,C=DE]
 * 7FD62B1A9EA5BBC84971183080717004 20221125T074346
 * 11223344556677                   20230101T000000  key_compromise
 * 0000000000000042                 20221206T121200  certificate_hold
 *
 * [CN=CA IVBB Deutsche Telekom AG 18,OU=Bund,O=PKI-1-Verwaltung,C=DE]
 * 735D1B97389F   20230210T083947
 *---------------------
 */
#include <config.h>

#include <stdio.h>
#include <stdlib.h>

#include "dirmngr.h"
#include "crlcache.h"



/* Returns 0 if the given certificate is not listed in the faked CRL
 * or no fake CRL is configured.  It is expected that the caller then
 * consults the real CRL.  */
gpg_error_t
fakecrl_isvalid (ctrl_t ctrl, const char *issuer_hash, const char *cert_id)
{
  (void)ctrl;
  (void)issuer_hash;
  (void)cert_id;
  return 0;
}
