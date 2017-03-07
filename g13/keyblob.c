/* keyblob.c - Keyblob parser and builder.
 * Copyright (C) 2009 Free Software Foundation, Inc.
 * Copyright (C) 2015-2016 Werner Koch
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
 */

#include <config.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <sys/stat.h>
#include <assert.h>

#include "g13.h"
#include "mount.h"

#include "keyblob.h"
#include "../common/sysutils.h"
#include "../common/host2net.h"


/* Parse the header prefix and return the length of the entire header.  */
static gpg_error_t
parse_header (const char *filename,
              const unsigned char *packet, size_t packetlen,
              size_t *r_headerlen)
{
  unsigned int len;

  if (packetlen != 32)
    return gpg_error (GPG_ERR_BUG);

  len = buf32_to_uint (packet+2);
  if (packet[0] != (0xc0|61) || len < 26
      || memcmp (packet+6, "GnuPG/G13", 10))
    {
      log_error ("file '%s' is not valid container\n", filename);
      return gpg_error (GPG_ERR_INV_OBJ);
    }
  if (packet[16] != 1)
    {
      log_error ("unknown version %u of container '%s'\n",
                 (unsigned int)packet[16], filename);
      return gpg_error (GPG_ERR_INV_OBJ);
    }
  if (packet[17] || packet[18]
      || packet[26] || packet[27] || packet[28] || packet[29]
      || packet[30] || packet[31])
    log_info ("WARNING: unknown meta information in '%s'\n", filename);
  if (packet[19])
    log_info ("WARNING: OS flag is not supported in '%s'\n", filename);
  if (packet[24] > 1 )
    log_info ("Note: meta data copies in '%s' are ignored\n", filename);

  len = buf32_to_uint (packet+20);

  /* Do a basic sanity check on the length.  */
  if (len < 32 || len > 1024*1024)
    {
      log_error ("bad length given in container '%s'\n", filename);
      return gpg_error (GPG_ERR_INV_OBJ);
    }

  *r_headerlen = len;
  return 0;
}


/* Read the prefix of the keyblob and do some basic parsing.  On
   success returns an open estream file at R_FP and the length of the
   header at R_HEADERLEN.  */
static gpg_error_t
read_keyblob_prefix (const char *filename, estream_t *r_fp, size_t *r_headerlen)
{
  gpg_error_t err;
  estream_t fp;
  unsigned char packet[32];

  *r_fp = NULL;

  fp = es_fopen (filename, "rb");
  if (!fp)
    {
      err = gpg_error_from_syserror ();
      log_error ("error reading '%s': %s\n", filename, gpg_strerror (err));
      return err;
    }

  /* Read the header.  It is defined as 32 bytes thus we read it in one go.  */
  if (es_fread (packet, 32, 1, fp) != 1)
    {
      err = gpg_error_from_syserror ();
      log_error ("error reading the header of '%s': %s\n",
                 filename, gpg_strerror (err));
      es_fclose (fp);
      return err;
    }

  err = parse_header (filename, packet, 32, r_headerlen);
  if (err)
    es_fclose (fp);
  else
    *r_fp = fp;

  return err;
}



/*
 * Test whether the container with name FILENAME is a suitable G13
 * container.  This function may even be called on a mounted
 * container.
 */
gpg_error_t
g13_is_container (ctrl_t ctrl, const char *filename)
{
  gpg_error_t err;
  estream_t fp = NULL;
  size_t dummy;

  (void)ctrl;

  /* Read just the prefix of the header.  */
  err = read_keyblob_prefix (filename, &fp, &dummy);
  if (!err)
    es_fclose (fp);
  return err;
}


/*
 * Read the keyblob at FILENAME.  The caller should have acquired a
 * lockfile and checked that the file exists.
 */
gpg_error_t
g13_keyblob_read (const char *filename,
                  void **r_enckeyblob, size_t *r_enckeybloblen)
{
  gpg_error_t err;
  estream_t fp = NULL;
  size_t headerlen = 0;
  size_t msglen;
  void *msg = NULL;

  *r_enckeyblob = NULL;
  *r_enckeybloblen = 0;

  err = read_keyblob_prefix (filename, &fp, &headerlen);
  if (err)
    goto leave;

  if (opt.verbose)
    log_info ("header length of '%s' is %zu\n", filename, headerlen);

  /* Read everything including the padding.  We should eventually do a
     regular OpenPGP parsing to detect the padding packet and pass
     only the actual used OpenPGP data to the engine.  This is in
     particular required when supporting CMS which will be
     encapsulated in an OpenPGP packet.  */
  assert (headerlen >= 32);
  msglen = headerlen - 32;
  if (!msglen)
    {
      err = gpg_error (GPG_ERR_NO_DATA);
      goto leave;
    }
  msg = xtrymalloc (msglen);
  if (!msglen)
    {
      err = gpg_error_from_syserror ();
      goto leave;
    }
  if (es_fread (msg, msglen, 1, fp) != 1)
    {
      err = gpg_error_from_syserror ();
      log_error ("error reading keyblob of '%s': %s\n",
                 filename, gpg_strerror (err));
      goto leave;
    }

  *r_enckeyblob = msg;
  msg = NULL;
  *r_enckeybloblen = msglen;

 leave:
  xfree (msg);
  es_fclose (fp);

  return err;
}
