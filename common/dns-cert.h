/* dns-cert.h - DNS CERT definition
 * Copyright (C) 2006 Free Software Foundation, Inc.
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
 * along with this program; if not, see <http://www.gnu.org/licenses/>.
 */
#ifndef GNUPG_COMMON_DNS_CERT_H
#define GNUPG_COMMON_DNS_CERT_H

int get_dns_cert (const char *name, size_t max_size, IOBUF *iobuf,
                  unsigned char **fpr, size_t *fpr_len, char **url);


#endif /*GNUPG_COMMON_DNS_CERT_H*/
