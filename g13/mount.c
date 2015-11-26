/* mount.c - Mount a crypto container
 * Copyright (C) 2009 Free Software Foundation, Inc.
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

#include <config.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <sys/stat.h>
#include <assert.h>

#include "g13.h"
#include "i18n.h"
#include "mount.h"

#include "keyblob.h"
#include "backend.h"
#include "utils.h"
#include "../common/sysutils.h"
#include "../common/call-gpg.h"
#include "mountinfo.h"
#include "runner.h"
#include "host2net.h"


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
  if (packet[24] != 1 || packet[25] != 0)
    {
      log_error ("meta data copies in '%s' are not supported\n", filename);
      return gpg_error (GPG_ERR_NOT_IMPLEMENTED);
    }

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


/* Read the keyblob at FILENAME.  The caller should have acquired a
   lockfile and checked that the file exists.  */
static gpg_error_t
read_keyblob (const char *filename,
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




/* Decrypt the keyblob (ENCKEYBLOB,ENCKEYBLOBLEN) and store the result at
   (R_KEYBLOB, R_KEYBLOBLEN).  Returns 0 on success or an error code.
   On error R_KEYBLOB is set to NULL.  */
static gpg_error_t
decrypt_keyblob (ctrl_t ctrl, const void *enckeyblob, size_t enckeybloblen,
                 void **r_keyblob, size_t *r_keybloblen)
{
  gpg_error_t err;

  /* FIXME:  For now we only implement OpenPGP.  */
  err = gpg_decrypt_blob (ctrl, opt.gpg_program, opt.gpg_arguments,
                          enckeyblob, enckeybloblen,
                          r_keyblob, r_keybloblen);

  return err;
}


static void
dump_keyblob (tupledesc_t tuples)
{
  size_t n;
  unsigned int tag;
  const void *value;

  log_info ("keyblob dump:\n");
  tag = KEYBLOB_TAG_BLOBVERSION;
  value = find_tuple (tuples, tag, &n);
  while (value)
    {
      log_info ("   tag: %-5u len: %-2u value: ", tag, (unsigned int)n);
      if (tag == KEYBLOB_TAG_ENCKEY
          ||  tag == KEYBLOB_TAG_MACKEY)
        log_printf ("[confidential]\n");
      else if (!n)
        log_printf ("[none]\n");
      else
        log_printhex ("", value, n);
      value = next_tuple (tuples, &tag, &n);
    }
}



/* Mount the container with name FILENAME at MOUNTPOINT.  */
gpg_error_t
g13_mount_container (ctrl_t ctrl, const char *filename, const char *mountpoint)
{
  gpg_error_t err;
  dotlock_t lock;
  void *enckeyblob = NULL;
  size_t enckeybloblen;
  void *keyblob = NULL;
  size_t keybloblen;
  tupledesc_t tuples = NULL;
  size_t n;
  const unsigned char *value;
  int conttype;
  unsigned int rid;
  char *mountpoint_buffer = NULL;

  /* A quick check to see whether the container exists.  */
  if (access (filename, R_OK))
    return gpg_error_from_syserror ();

  if (!mountpoint)
    {
      mountpoint_buffer = xtrystrdup ("/tmp/g13-XXXXXX");
      if (!mountpoint_buffer)
        return gpg_error_from_syserror ();
      if (!gnupg_mkdtemp (mountpoint_buffer))
        {
          err = gpg_error_from_syserror ();
          log_error (_("can't create directory '%s': %s\n"),
                     "/tmp/g13-XXXXXX", gpg_strerror (err));
          xfree (mountpoint_buffer);
          return err;
        }
      mountpoint = mountpoint_buffer;
    }

  /* Try to take a lock.  */
  lock = dotlock_create (filename, 0);
  if (!lock)
    {
      xfree (mountpoint_buffer);
      return gpg_error_from_syserror ();
    }

  if (dotlock_take (lock, 0))
    {
      err = gpg_error_from_syserror ();
      goto leave;
    }
  else
    err = 0;

  /* Check again that the file exists.  */
  {
    struct stat sb;

    if (stat (filename, &sb))
      {
        err = gpg_error_from_syserror ();
        goto leave;
      }
  }

  /* Read the encrypted keyblob.  */
  err = read_keyblob (filename, &enckeyblob, &enckeybloblen);
  if (err)
    goto leave;

  /* Decrypt that keyblob and store it in a tuple descriptor.  */
  err = decrypt_keyblob (ctrl, enckeyblob, enckeybloblen,
                         &keyblob, &keybloblen);
  if (err)
    goto leave;
  xfree (enckeyblob);
  enckeyblob = NULL;

  err = create_tupledesc (&tuples, keyblob, keybloblen);
  if (!err)
    keyblob = NULL;
  else
    {
      if (gpg_err_code (err) == GPG_ERR_NOT_SUPPORTED)
        log_error ("unknown keyblob version\n");
      goto leave;
    }
  if (opt.verbose)
    dump_keyblob (tuples);

  value = find_tuple (tuples, KEYBLOB_TAG_CONTTYPE, &n);
  if (!value || n != 2)
    conttype = 0;
  else
    conttype = (value[0] << 8 | value[1]);
  if (!be_is_supported_conttype (conttype))
    {
      log_error ("content type %d is not supported\n", conttype);
      err = gpg_error (GPG_ERR_NOT_SUPPORTED);
      goto leave;
    }
  err = be_mount_container (ctrl, conttype, filename, mountpoint, tuples, &rid);
  if (!err)
    {
      err = mountinfo_add_mount (filename, mountpoint, conttype, rid,
                                 !!mountpoint_buffer);
      /* Fixme: What shall we do if this fails?  Add a provisional
         mountinfo entry first and remove it on error? */
      if (!err)
        {
          char *tmp = percent_plus_escape (mountpoint);
          if (!tmp)
            err = gpg_error_from_syserror ();
          else
            {
              g13_status (ctrl, STATUS_MOUNTPOINT, tmp, NULL);
              xfree (tmp);
            }
        }
    }

 leave:
  destroy_tupledesc (tuples);
  xfree (keyblob);
  xfree (enckeyblob);
  dotlock_destroy (lock);
  xfree (mountpoint_buffer);
  return err;
}


/* Unmount the container with name FILENAME or the one mounted at
   MOUNTPOINT.  If both are given the FILENAME takes precedence.  */
gpg_error_t
g13_umount_container (ctrl_t ctrl, const char *filename, const char *mountpoint)
{
  gpg_error_t err;
  unsigned int rid;
  runner_t runner;

  (void)ctrl;

  if (!filename && !mountpoint)
    return gpg_error (GPG_ERR_ENOENT);
  err = mountinfo_find_mount (filename, mountpoint, &rid);
  if (err)
    return err;

  runner = runner_find_by_rid (rid);
  if (!runner)
    {
      log_error ("runner %u not found\n", rid);
      return gpg_error (GPG_ERR_NOT_FOUND);
    }

  runner_cancel (runner);
  runner_release (runner);

  return 0;
}


/* Test whether the container with name FILENAME is a suitable G13
   container.  This function may even be called on a mounted
   container.  */
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
