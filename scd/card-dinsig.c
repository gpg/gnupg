/* card-dinsig.c - German signature law (DINSIG) functions
 *	Copyright (C) 2002 Free Software Foundation, Inc.
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
         '0'        := C.CH (base certificate of ard holder) or C.ICC.
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
           allowed, update after uder authentication. [o,o]
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
#include <time.h>

#ifdef HAVE_OPENSC
#include <opensc/pkcs15.h>
#include "scdaemon.h"
#include <ksba.h>

#include "card-common.h"

static int dinsig_read_cert (CARD card, const char *certidstr,
                             unsigned char **cert, size_t *ncert);



/* See card.c for interface description.  Frankly we don't do any real
   enumeration but just check whether the well know files are
   available.  */
static int
dinsig_enum_keypairs (CARD card, int idx,
                      unsigned char *keygrip, char **keyid)
{
  int rc;
  unsigned char *buf;
  size_t buflen;
  ksba_cert_t cert;

  /* fixme: We should locate the application via the EF(DIR) and not
     assume a Netkey card */
  if (!idx)
    rc = dinsig_read_cert (card, "DINSIG-DF01.C000", &buf, &buflen);
  else if (idx == 1)
    rc = dinsig_read_cert (card, "DINSIG-DF01.C200", &buf, &buflen);
  else
    rc = -1;
  if (rc)
    return rc;

  rc = ksba_cert_new (&cert);
  if (rc)
    {
      xfree (buf);
      return rc;
    }

  rc = ksba_cert_init_from_mem (cert, buf, buflen); 
  xfree (buf);
  if (rc)
    {
      log_error ("failed to parse the certificate at idx %d: %s\n",
                 idx, gpg_strerror (rc));
      ksba_cert_release (cert);
      return rc;
    }
  if (card_help_get_keygrip (cert, keygrip))
    {
      log_error ("failed to calculate the keygrip at index %d\n", idx);
      ksba_cert_release (cert);
      return gpg_error (GPG_ERR_CARD);
    }      
  ksba_cert_release (cert);

  /* return the iD */
  if (keyid)
    {
      *keyid = xtrymalloc (17);
      if (!*keyid)
        return gpg_error (gpg_err_code_from_errno (errno));
      if (!idx)
        strcpy (*keyid, "DINSIG-DF01.C000");
      else
        strcpy (*keyid, "DINSIG-DF01.C200");
    }
  
  return 0;
}



/* See card.c for interface description */
static int
dinsig_read_cert (CARD card, const char *certidstr,
                  unsigned char **cert, size_t *ncert)
{
  int rc;
  struct sc_path path;
  struct sc_file *file;
  unsigned char *buf;
  int buflen;

  if (!strcmp (certidstr, "DINSIG-DF01.C000"))
    sc_format_path ("3F00DF01C000", &path);
  else if (!strcmp (certidstr, "DINSIG-DF01.C200"))
    sc_format_path ("3F00DF01C200", &path);
  else
    return gpg_error (GPG_ERR_INV_ID);

  rc = sc_select_file (card->scard, &path, &file);
  if (rc) 
    {
      log_error ("sc_select_file failed: %s\n", sc_strerror (rc));
      return map_sc_err (rc);
    }
  if (file->type != SC_FILE_TYPE_WORKING_EF
      || file->ef_structure != SC_FILE_EF_TRANSPARENT)
    {
      log_error ("wrong type or structure of certificate EF\n");
      sc_file_free (file);
      return gpg_error (GPG_ERR_CARD);
    }
  if (file->size < 20) /* check against a somewhat arbitrary length */
    { 
      log_error ("certificate EF too short\n");
      sc_file_free (file);
      return gpg_error (GPG_ERR_CARD);
    }
  buf = xtrymalloc (file->size);
  if (!buf)
    {
      gpg_error_t tmperr = gpg_error (gpg_err_code_from_errno (errno));
      sc_file_free (file);
      return tmperr;
    }
      
  rc = sc_read_binary (card->scard, 0, buf, file->size, 0);
  if (rc >= 0 && rc != file->size)
    {
      log_error ("short read on certificate EF\n");
      sc_file_free (file);
      xfree (buf);
      return gpg_error (GPG_ERR_CARD);
    }
  sc_file_free (file);
  if (rc < 0) 
    {
      log_error ("error reading certificate EF: %s\n", sc_strerror (rc));
      xfree (buf);
      return map_sc_err (rc);
    }
  buflen = rc;

  /* The object is not a plain certificate but wrapped into id-at
     userCertificate - fixme: we should check the specs and decided
     whether libksba should support it */
  if (buflen > 9 && buf[0] == 0x30 && buf[4] == 6 && buf[5] == 3
      && buf[6] == 0x55 && buf[7] == 4 && buf[8] == 0x24)
    {
      /* We have to strip the padding.  Although this is a good idea
         anyway, we have to do it due to a KSBA problem; KSBA does not
         work correct when the buffer is larger than the ASN.1
         structure and the certificates here are padded with FF.  So
         as a workaround we look at the outer structure to get the
         size of the entire thing and adjust the buflen.  We can only
         do this when there is a 2 byte length field */
      size_t seqlen;
      if (buf[1] == 0x82)
        {
          seqlen = ((buf[2] << 8) | buf[3]) + 4;
          if (seqlen < buflen)
            buflen = seqlen;
        }
      memmove (buf, buf+9, buflen-9);
      buflen -= 9;
    } 

  *cert = buf;
  *ncert = buflen;
  return 0;
}




/* Bind our operations to the card */
void
card_dinsig_bind (CARD card)
{
  card->fnc.enum_keypairs = dinsig_enum_keypairs;
  card->fnc.read_cert     = dinsig_read_cert;

}
#endif /*HAVE_OPENSC*/
