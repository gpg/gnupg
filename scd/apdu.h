/* apdu.h - ISO 7816 APDU functions and low level I/O
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

#ifndef APDU_H
#define APDU_H

/* ISO 7816 values for the statusword are defined here because they
   should not be visible to the users of the actual iso command
   API. */
enum {
  SW_MORE_DATA      = 0x6100, /* Note: that the low byte must be
                                 masked of.*/
  SW_EEPROM_FAILURE = 0x6581,
  SW_WRONG_LENGTH   = 0x6700,
  SW_CHV_WRONG      = 0x6982,
  SW_CHV_BLOCKED    = 0x6983,
  SW_USE_CONDITIONS = 0x6985,
  SW_BAD_PARAMETER  = 0x6a80, /* (in the data field) */
  SW_REF_NOT_FOUND  = 0x6a88,
  SW_BAD_P0_P1      = 0x6b00,
  SW_INS_NOT_SUP    = 0x6d00,
  SW_CLA_NOT_SUP    = 0x6e00,
  SW_SUCCESS        = 0x9000
};



int apdu_open_reader (int port);
unsigned char *apdu_get_atr (int slot, size_t *atrlen);

int apdu_send_simple (int slot, int class, int ins, int p0, int p1,
                      int lc, const char *data);
int apdu_send (int slot, int class, int ins, int p0, int p1,
               int lc, const char *data,
               unsigned char **retbuf, size_t *retbuflen);
int apdu_send_le (int slot, int class, int ins, int p0, int p1,
                  int lc, const char *data, int le,
                  unsigned char **retbuf, size_t *retbuflen);


#endif /*APDU_H*/
