/* card-dinsig.c - German signature law (DINSIG) functions
 *	Copyright (C) 2002 Free Software Foundation, Inc.
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

#include <config.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include <opensc-pkcs15.h>
#include <ksba.h>

#include "scdaemon.h"
#include "card-common.h"

static int dinsig_read_cert (CARD card, const char *certidstr,
                             unsigned char **cert, size_t *ncert);



/* See card.c for interface description.  Frankly we don't do any real
   enumeration but just check whether the well know files are
   available.
 */
static int
dinsig_enum_keypairs (CARD card, int idx,
                      unsigned char *keygrip, char **keyid)
{
  int rc;
  unsigned char *buf;
  size_t buflen;
  KsbaError krc;
  KsbaCert cert;

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

  cert = ksba_cert_new ();
  if (!cert)
    {
      xfree (buf);
      return GNUPG_Out_Of_Core;
    }

  krc = ksba_cert_init_from_mem (cert, buf, buflen); 
  xfree (buf);
  if (krc)
    {
      log_error ("failed to parse the certificate at idx %d: %s\n",
                 idx, ksba_strerror (krc));
      ksba_cert_release (cert);
      return GNUPG_Card_Error;
    }
  if (card_help_get_keygrip (cert, keygrip))
    {
      log_error ("failed to calculate the keygrip at index %d\n", idx);
      ksba_cert_release (cert);
      return GNUPG_Card_Error;
    }      
  ksba_cert_release (cert);

  /* return the iD */
  if (keyid)
    {
      *keyid = xtrymalloc (17);
      if (!*keyid)
        return GNUPG_Out_Of_Core;
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
    return GNUPG_Invalid_Id;

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
      return GNUPG_Card_Error;
    }
  if (file->size < 20) /* check against a somewhat arbitrary length */
    { 
      log_error ("certificate EF too short\n");
      sc_file_free (file);
      return GNUPG_Card_Error;
    }
  buf = xtrymalloc (file->size);
  if (!buf)
    {
      sc_file_free (file);
      return GNUPG_Out_Of_Core;
    }
      
  rc = sc_read_binary (card->scard, 0, buf, file->size, 0);
  if (rc >= 0 && rc != file->size)
    {
      log_error ("short read on certificate EF\n");
      sc_file_free (file);
      xfree (buf);
      return GNUPG_Card_Error;
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
