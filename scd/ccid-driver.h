/* ccid-driver.h - USB ChipCardInterfaceDevices driver
 * Copyright (C) 2003 Free Software Foundation, Inc.
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
 *
 * ALTERNATIVELY, this file may be distributed under the terms of the
 * following license, in which case the provisions of this license are
 * required INSTEAD OF the GNU General Public License. If you wish to
 * allow use of your version of this file only under the terms of the
 * GNU General Public License, and not to allow others to use your
 * version of this file under the terms of the following license,
 * indicate your decision by deleting this paragraph and the license
 * below.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, and the entire permission notice in its entirety,
 *    including the disclaimer of warranties.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. The name of the author may not be used to endorse or promote
 *    products derived from this software without specific prior
 *    written permission.
 *
 * THIS SOFTWARE IS PROVIDED "AS IS" AND ANY EXPRESS OR IMPLIED
 * WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT,
 * INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED
 * OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 * $Id$
 */

#ifndef CCID_DRIVER_H
#define CCID_DRIVER_H


#ifdef CCID_DRIVER_INCLUDE_USB_IDS
/* We need to know the vendor to do some hacks. */
enum {
  VENDOR_CHERRY = 0x046a,
  VENDOR_SCM    = 0x04e6,
  VENDOR_OMNIKEY= 0x076b,
  VENDOR_GEMPC  = 0x08e6,
  VENDOR_VEGA   = 0x0982,
  VENDOR_REINER = 0x0c4b,
  VENDOR_KAAN   = 0x0d46,
  VENDOR_FSIJ   = 0x234b,
  VENDOR_VASCO  = 0x1a44
};


/* Some product ids.  */
#define SCM_SCR331      0xe001
#define SCM_SCR331DI    0x5111
#define SCM_SCR335      0x5115
#define SCM_SCR3320     0x5117
#define SCM_SPR532      0xe003    /* Also used succeeding model SPR332. */
#define CHERRY_ST2000   0x003e
#define VASCO_920       0x0920
#define GEMPC_PINPAD    0x3478
#define GEMPC_CT30      0x3437
#define VEGA_ALPHA      0x0008
#define CYBERJACK_GO    0x0504

#endif /*CCID_DRIVER_INCLUDE_USB_IDS*/


/* The CID driver returns the same error codes as the status words
   used by GnuPG's apdu.h.  For ease of maintenance they should always
   match.  */
#define CCID_DRIVER_ERR_OUT_OF_CORE    0x10001
#define CCID_DRIVER_ERR_INV_VALUE      0x10002
#define CCID_DRIVER_ERR_INCOMPLETE_CARD_RESPONSE = 0x10003
#define CCID_DRIVER_ERR_NO_DRIVER      0x10004
#define CCID_DRIVER_ERR_NOT_SUPPORTED  0x10005
#define CCID_DRIVER_ERR_LOCKING_FAILED 0x10006
#define CCID_DRIVER_ERR_BUSY           0x10007
#define CCID_DRIVER_ERR_NO_CARD        0x10008
#define CCID_DRIVER_ERR_CARD_INACTIVE  0x10009
#define CCID_DRIVER_ERR_CARD_IO_ERROR  0x1000a
#define CCID_DRIVER_ERR_GENERAL_ERROR  0x1000b
#define CCID_DRIVER_ERR_NO_READER      0x1000c
#define CCID_DRIVER_ERR_ABORTED        0x1000d
#define CCID_DRIVER_ERR_NO_PINPAD      0x1000e

struct ccid_driver_s;
typedef struct ccid_driver_s *ccid_driver_t;

struct ccid_dev_table;

int ccid_set_debug_level (int level);
char *ccid_get_reader_list (void);

gpg_error_t ccid_dev_scan (int *idx_max, struct ccid_dev_table **t_p);
void ccid_dev_scan_finish (struct ccid_dev_table *tbl, int max);
unsigned int ccid_get_BAI (int, struct ccid_dev_table *tbl);
int ccid_compare_BAI (ccid_driver_t handle, unsigned int);
int ccid_open_reader (const char *spec_reader_name,
                      int idx, struct ccid_dev_table *ccid_table,
                      ccid_driver_t *handle, char **rdrname_p);
int ccid_set_progress_cb (ccid_driver_t handle,
                          void (*cb)(void *, const char *, int, int, int),
                          void *cb_arg);
int ccid_shutdown_reader (ccid_driver_t handle);
int ccid_close_reader (ccid_driver_t handle);
int ccid_get_atr (ccid_driver_t handle,
                  unsigned char *atr, size_t maxatrlen, size_t *atrlen);
int ccid_slot_status (ccid_driver_t handle, int *statusbits, int on_wire);
int ccid_transceive (ccid_driver_t handle,
                     const unsigned char *apdu, size_t apdulen,
                     unsigned char *resp, size_t maxresplen, size_t *nresp);
int ccid_transceive_secure (ccid_driver_t handle,
                     const unsigned char *apdu, size_t apdulen,
                     pininfo_t *pininfo,
                     unsigned char *resp, size_t maxresplen, size_t *nresp);
int ccid_transceive_escape (ccid_driver_t handle,
                            const unsigned char *data, size_t datalen,
                            unsigned char *resp, size_t maxresplen,
                            size_t *nresp);
int ccid_require_get_status (ccid_driver_t handle);


#endif /*CCID_DRIVER_H*/
