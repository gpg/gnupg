/* ccid-driver.c - USB ChipCardInterfaceDevices driver
 *	Copyright (C) 2003 Free Software Foundation, Inc.
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

#ifndef CCID_DRIVER_H
#define CCID_DRIVER_H


struct ccid_driver_s;
typedef struct ccid_driver_s *ccid_driver_t;

int ccid_open_reader (ccid_driver_t *handle, int readerno);
int ccid_get_atr (ccid_driver_t handle,
                  unsigned char *atr, size_t maxatrlen, size_t *atrlen);
int ccid_transceive (ccid_driver_t handle,
                     const unsigned char *apdu, size_t apdulen,
                     unsigned char *resp, size_t maxresplen, size_t *nresp);



#endif /*CCID_DRIVER_H*/



