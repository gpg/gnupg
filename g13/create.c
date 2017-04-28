/* create.c - Create a new crypto container
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
#include "../common/i18n.h"
#include "create.h"

#include "keyblob.h"
#include "backend.h"
#include "g13tuple.h"
#include "../common/call-gpg.h"

/* Create a new blob with all the session keys and other meta
   information which are to be stored encrypted in the crypto
   container header.  On success the malloced blob is stored at R_BLOB
   and its length at R_BLOBLEN.  On error an error code is returned
   and (R_BLOB,R_BLOBLEN) are set to (NULL,0).

   The format of this blob is a sequence of tag-length-value tuples.
   All tuples have this format:

     2 byte TAG           Big endian unsigned integer (0..65535)
                          described by the KEYBLOB_TAG_ constants.
     2 byte LENGTH        Big endian unsigned integer (0..65535)
                          giving the length of the value.
     length bytes VALUE   The value described by the tag.

   The first tag in a keyblob must be a BLOBVERSION.  The other tags
   depend on the type of the container as described by the CONTTYPE
   tag.  See keyblob.h for details.  */
static gpg_error_t
create_new_keyblob (ctrl_t ctrl, int is_detached,
                    void **r_blob, size_t *r_bloblen)
{
  gpg_error_t err;
  unsigned char twobyte[2];
  membuf_t mb;

  *r_blob = NULL;
  *r_bloblen = 0;

  init_membuf_secure (&mb, 512);

  append_tuple (&mb, KEYBLOB_TAG_BLOBVERSION, "\x01", 1);

  twobyte[0] = (ctrl->conttype >> 8);
  twobyte[1] = (ctrl->conttype);
  append_tuple (&mb, KEYBLOB_TAG_CONTTYPE, twobyte, 2);
  if (is_detached)
    append_tuple (&mb, KEYBLOB_TAG_DETACHED, NULL, 0);

  err = be_create_new_keys (ctrl->conttype, &mb);
  if (err)
    goto leave;

  /* Just for testing.  */
  append_tuple (&mb, KEYBLOB_TAG_FILLER, "filler", 6);

  *r_blob = get_membuf (&mb, r_bloblen);
  if (!*r_blob)
    {
      err = gpg_error_from_syserror ();
      *r_bloblen = 0;
    }
  else
    log_debug ("used keyblob size is %zu\n", *r_bloblen);

 leave:
  xfree (get_membuf (&mb, NULL));
  return err;
}



/* Encrypt the keyblob (KEYBLOB,KEYBLOBLEN) and store the result at
   (R_ENCBLOB, R_ENCBLOBLEN).  Returns 0 on success or an error code.
   On error R_EKYBLOB is set to NULL.  Depending on the keys set in
   CTRL the result is a single OpenPGP binary message, a single
   special OpenPGP packet encapsulating a CMS message or a
   concatenation of both with the CMS packet being the last.  */
gpg_error_t
g13_encrypt_keyblob (ctrl_t ctrl, void *keyblob, size_t keybloblen,
                     void **r_encblob, size_t *r_encbloblen)
{
  gpg_error_t err;

  /* FIXME:  For now we only implement OpenPGP.  */
  err = gpg_encrypt_blob (ctrl, opt.gpg_program, opt.gpg_arguments,
                          keyblob, keybloblen,
                          ctrl->recipients,
                          r_encblob, r_encbloblen);

  return err;
}


/* Write a new file under the name FILENAME with the keyblob and an
   appropriate header.  This function is called with a lock file in
   place and after checking that the filename does not exists.  */
static gpg_error_t
write_keyblob (const char *filename,
               const void *keyblob, size_t keybloblen)
{
  gpg_error_t err;
  estream_t fp;
  unsigned char packet[32];
  size_t headerlen, paddinglen;

  fp = es_fopen (filename, "wbx");
  if (!fp)
    {
      err = gpg_error_from_syserror ();
      log_error ("error creating new container '%s': %s\n",
                 filename, gpg_strerror (err));
      return err;
    }

  /* Allow for an least 8 times larger keyblob to accommodate for
     future key changes.  Round it up to 4096 byte. */
  headerlen = ((32 + 8 * keybloblen + 16) + 4095) / 4096 * 4096;
  paddinglen = headerlen - 32 - keybloblen;
  assert (paddinglen >= 16);

  packet[0] = (0xc0|61); /* CTB for the private packet type 0x61.  */
  packet[1] = 0xff;      /* 5 byte length packet, value 20.  */
  packet[2] = 0;
  packet[3] = 0;
  packet[4] = 0;
  packet[5] = 26;
  memcpy (packet+6, "GnuPG/G13", 10); /* Packet subtype.  */
  packet[16] = 1;   /* G13 packet format version.  */
  packet[17] = 0;   /* Reserved.  */
  packet[18] = 0;   /* Reserved.  */
  packet[19] = 0;   /* OS Flag.  */
  packet[20] = (headerlen >> 24);  /* Total length of header.  */
  packet[21] = (headerlen >> 16);
  packet[22] = (headerlen >> 8);
  packet[23] = (headerlen);
  packet[24] = 1;   /* Number of header copies.  */
  packet[25] = 0;   /* Number of header copies at the end.  */
  packet[26] = 0;   /* Reserved.  */
  packet[27] = 0;   /* Reserved.  */
  packet[28] = 0;   /* Reserved.  */
  packet[29] = 0;   /* Reserved.  */
  packet[30] = 0;   /* Reserved.  */
  packet[31] = 0;   /* Reserved.  */

  if (es_fwrite (packet, 32, 1, fp) != 1)
    goto writeerr;

  if (es_fwrite (keyblob, keybloblen, 1, fp) != 1)
    goto writeerr;

  /* Write the padding.  */
  packet[0] = (0xc0|61); /* CTB for Private packet type 0x61.  */
  packet[1] = 0xff;      /* 5 byte length packet, value 20.  */
  packet[2] = (paddinglen-6) >> 24;
  packet[3] = (paddinglen-6) >> 16;
  packet[4] = (paddinglen-6) >> 8;
  packet[5] = (paddinglen-6);
  memcpy (packet+6, "GnuPG/PAD", 10); /* Packet subtype.  */
  if (es_fwrite (packet, 16, 1, fp) != 1)
    goto writeerr;
  memset (packet, 0, 32);
  for (paddinglen-=16; paddinglen >= 32; paddinglen -= 32)
    if (es_fwrite (packet, 32, 1, fp) != 1)
      goto writeerr;
  if (paddinglen)
    if (es_fwrite (packet, paddinglen, 1, fp) != 1)
      goto writeerr;

  if (es_fclose (fp))
    {
      err = gpg_error_from_syserror ();
      log_error ("error closing '%s': %s\n",
                 filename, gpg_strerror (err));
      remove (filename);
      return err;
    }

  return 0;


 writeerr:
  err = gpg_error_from_syserror ();
  log_error ("error writing header to '%s': %s\n",
             filename, gpg_strerror (err));
  es_fclose (fp);
  remove (filename);
  return err;
}



/* Create a new container under the name FILENAME and initialize it
   using the current settings.  If the file already exists an error is
   returned.  */
gpg_error_t
g13_create_container (ctrl_t ctrl, const char *filename)
{
  gpg_error_t err;
  dotlock_t lock;
  void *keyblob = NULL;
  size_t keybloblen;
  void *enckeyblob = NULL;
  size_t enckeybloblen;
  char *detachedname = NULL;
  int detachedisdir;
  tupledesc_t tuples = NULL;
  unsigned int dummy_rid;

  if (!ctrl->recipients)
    return gpg_error (GPG_ERR_NO_PUBKEY);

  err = be_take_lock_for_create (ctrl, filename, &lock);
  if (err)
    goto leave;

  /* And a possible detached file or directory may not exist either.  */
  err = be_get_detached_name (ctrl->conttype, filename,
                              &detachedname, &detachedisdir);
  if (err)
    goto leave;
  if (detachedname)
    {
      struct stat sb;

      if (!stat (detachedname, &sb))
        {
          err = gpg_error (GPG_ERR_EEXIST);
          goto leave;
        }
    }

  if (ctrl->conttype != CONTTYPE_DM_CRYPT)
    {
      /* Create a new keyblob.  */
      err = create_new_keyblob (ctrl, !!detachedname, &keyblob, &keybloblen);
      if (err)
        goto leave;

      /* Encrypt that keyblob.  */
      err = g13_encrypt_keyblob (ctrl, keyblob, keybloblen,
                                 &enckeyblob, &enckeybloblen);
      if (err)
        goto leave;

      /* Put a copy of the keyblob into a tuple structure.  */
      err = create_tupledesc (&tuples, keyblob, keybloblen);
      if (err)
        goto leave;
      keyblob = NULL;
      /* if (opt.verbose) */
      /*   dump_keyblob (tuples); */

      /* Write out the header, the encrypted keyblob and some padding. */
      err = write_keyblob (filename, enckeyblob, enckeybloblen);
      if (err)
        goto leave;
    }

  /* Create and append the container.  FIXME: We should pass the
     estream object in addition to the filename, so that the backend
     can append the container to the g13 file.  */
  err = be_create_container (ctrl, ctrl->conttype, filename, -1, tuples,
                             &dummy_rid);


 leave:
  destroy_tupledesc (tuples);
  xfree (detachedname);
  xfree (enckeyblob);
  xfree (keyblob);
  dotlock_destroy (lock);

  return err;
}
