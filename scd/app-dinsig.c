/* app-dinsig.c - The DINSIG (DIN V 66291-1) card application.
 *	Copyright (C) 2004 Free Software Foundation, Inc.
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


/* The German signature law and its bylaw (SigG and SigV) is currently
   used with an interface specification described in DIN V 66291-1.
   The AID to be used is: 'D27600006601'.

   The file IDs for certificates utilize the generic format: 
        Cxyz
    C being the hex digit 'C' (12).
    x being the service indicator:
         '0' := SigG conform digital signature.
         '1' := entity authentication.
         '2' := key encipherment.
         '3' := data encipherment.
         '4' := key agreement.
         other values are reserved for future use.
    y being the security environment number using '0' for cards
      not supporting a SE number.
    z being the certificate type:
         '0'        := C.CH (base certificate of card holder) or C.ICC.
         '1' .. '7' := C.CH (business or professional certificate
                       of card holder.
         '8' .. 'D' := C.CA (certificate of a CA issue by the Root-CA).
         'E'        := C.RCA (self certified certificate of the Root-CA).
         'F'        := reserved.
   
   The file IDs used by default are:
   '1F00'  EF.SSD (security service descriptor). [o,o]
   '2F02'  EF.GDO (global data objects) [m,m]
   'A000'  EF.PROT (signature log).  Cyclic file with 20 records of 53 byte.
           Read and update after user authentication. [o,o]
   'B000'  EF.PK.RCA.DS (public keys of Root-CA).  Size is 512b or size 
           of keys. [m (unless a 'C00E' is present),m]
   'B001'  EF.PK.CA.DS (public keys of CAs).  Size is 512b or size
           of keys. [o,o]
   'C00n'  EF.C.CH.DS (digital signature certificate of card holder)
           with n := 0 .. 7.  Size is 2k or size of cert.  Read and
           update allowed after user authentication. [m,m]
   'C00m'  EF.C.CA.DS (digital signature certificate of CA)
           with m := 8 .. E.  Size is 1k or size of cert.  Read always 
           allowed, update after user authentication. [o,o]
   'C100'  EF.C.ICC.AUT (AUT certificate of ICC) [o,m]
   'C108'  EF.C.CA.AUT (AUT certificate of CA) [o,m]
   'D000'  EF.DM (display message) [-,m]
   
   The letters in brackets indicate optional or mandatory files: The
   first for card terminals under full control and the second for
   "business" card terminals.

   FIXME: Needs a lot more explanation.

*/




#include <config.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <time.h>

#include "scdaemon.h"

#include "iso7816.h"
#include "app-common.h"



static int
do_learn_status (APP app, CTRL ctrl)
{
  return 0;
}





/* Select the DINSIG application on the card in SLOT.  This function
   must be used before any other DINSIG application functions. */
int
app_select_dinsig (APP app)
{
  static char const aid[] = { 0xD2, 0x76, 0x00, 0x00, 0x66, 0x01 };
  int slot = app->slot;
  int rc;
  
  rc = iso7816_select_application (slot, aid, sizeof aid);
  if (!rc)
    {
      app->apptype = "DINSIG";

      app->fnc.learn_status = do_learn_status;
      app->fnc.getattr = NULL;
      app->fnc.setattr = NULL;
      app->fnc.genkey = NULL;
      app->fnc.sign = NULL;
      app->fnc.auth = NULL;
      app->fnc.decipher = NULL;
      app->fnc.change_pin = NULL;
      app->fnc.check_pin = NULL;
   }

  return rc;
}


