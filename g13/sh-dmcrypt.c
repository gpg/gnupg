/* sh-dmcrypt.c - The DM-Crypt part for g13-syshelp
 * Copyright (C) 2015 Werner Koch
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
#include <stdarg.h>
#include <errno.h>
#include <assert.h>
#include <sys/types.h>
#ifdef HAVE_STAT
# include <sys/stat.h>
#endif
#include <unistd.h>

#include "g13-syshelp.h"
#include <assuan.h>
#include "i18n.h"
#include "utils.h"
#include "keyblob.h"

/* The standard disk block size (logical).  */
#define SECTOR_SIZE 512

/* The physical block size used by modern devices.  */
#define PHY_SECTOR_SIZE  (SECTOR_SIZE*8)  /* 4 KiB */

/* The length of the crypto setup area in sectors.  16 KiB is a nice
   multiple of a modern block size and should be sufficient for all
   kind of extra public key encryption packet.  */
#define SETUP_AREA_SECTORS 32  /* 16 KiB */

/* The number of header block copies stored at the begin and end of
   the device.  */
#define HEADER_SETUP_AREA_COPIES 2
#define FOOTER_SETUP_AREA_COPIES 2

/* The length in blocks of the space we put at the start and at the
   end of the device.  This space is used to store N copies of the
   setup area for the actual encrypted container inbetween.  */
#define HEADER_SECTORS (SETUP_AREA_SECTORS * HEADER_SETUP_AREA_COPIES)
#define FOOTER_SECTORS (SETUP_AREA_SECTORS * FOOTER_SETUP_AREA_COPIES)

/* Minimim size of the encrypted space in blocks.  This is more or
   less an arbitrary value.  */
#define MIN_ENCRYPTED_SPACE 32

/* Some consistency checks for the above constants.  */
#if (PHY_SECTOR_SIZE % SECTOR_SIZE)
# error the physical secotor size should be a multiple of 512
#endif
#if ((SETUP_AREA_SECTORS*SECTOR_SIZE) % PHY_SECTOR_SIZE)
# error The setup area size should be a multiple of the phy. sector size.
#endif


/* Check whether the block device DEVNAME is used by device mapper.
   Returns: 0 if the device is good and not yet used by DM.  */
static gpg_error_t
check_blockdev (const char *devname)
{
  gpg_error_t err;
  struct stat sb;
  unsigned int devmajor, devminor;
  char *result = NULL;
  char **lines = NULL;
  char **fields = NULL;
  int lno, count;

  if (stat (devname, &sb))
    {
      err = gpg_error_from_syserror ();
      log_error ("error stating '%s': %s\n", devname, gpg_strerror (err));
      return err;
    }
  if (!S_ISBLK (sb.st_mode))
    {
      err = gpg_error (GPG_ERR_ENOTBLK);
      log_error ("can't use '%s': %s\n", devname, gpg_strerror (err));
      return err;
    }
  devmajor = major (sb.st_rdev);
  devminor = minor (sb.st_rdev);

  {
    const char *argv[2];

    argv[0] = "deps";
    argv[1] = NULL;
    err = sh_exec_tool ("/sbin/dmsetup", argv, NULL, &result, NULL);
  }
  if (err)
    {
      log_error ("error running '%s' to search for '%s': %s\n",
                 "dmsetup deps", devname, gpg_strerror (err));
      goto leave;
    }
  lines = strsplit (result, '\n', 0, NULL);
  if (!lines)
    {
      err = gpg_error_from_syserror ();
      goto leave;
    }
  if (lines[0] && !strcmp (lines[0], "No devices found"))
    ;
  else
    {
      for (lno=0; lines[lno]; lno++)
        {
          unsigned int xmajor, xminor;

          if (!*lines[lno])
            continue;
          xfree (fields);
          fields = strsplit (lines[lno], ':', 0, &count);
          if (!fields)
            {
              err = gpg_error_from_syserror ();
              goto leave;
            }
          if (count < 3
              || sscanf (fields[2], " (%u,%u)", &xmajor, &xminor) != 2)
            {
              log_error ("error running '%s' to search for '%s': %s\n",
                         "dmsetup deps", devname, "unexpected output");
              err = gpg_error (GPG_ERR_INV_VALUE);
              goto leave;
            }

          if (xmajor == devmajor && xminor == devminor)
            {
              log_error ("device '%s' (%u:%u) already used by device mapper\n",
                         devname, devmajor, devminor);
              err = gpg_error (GPG_ERR_EBUSY);
              goto leave;
            }
        }
    }


 leave:
  xfree (fields);
  xfree (lines);
  xfree (result);
  return err;
}


/* Return a malloced buffer with the prefix of the setup area.  This
   is the data written right before the encrypted keyblob.  Return NULL
   on error and sets ERRNO.  */
static void *
mk_setup_area_prefix (size_t *r_length)
{
  unsigned char *packet;
  size_t setuparealen;

  packet = xtrymalloc (32);
  if (!packet)
    return NULL;
  *r_length = 32;

  setuparealen = SETUP_AREA_SECTORS * SECTOR_SIZE;

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
  packet[19] = 1;   /* OS Flag = Linux  */
  packet[20] = (setuparealen >> 24);  /* Total length of header.  */
  packet[21] = (setuparealen >> 16);
  packet[22] = (setuparealen >> 8);
  packet[23] = (setuparealen);
  packet[24] = HEADER_SETUP_AREA_COPIES;
  packet[25] = FOOTER_SETUP_AREA_COPIES;
  packet[26] = 0;   /* Reserved.  */
  packet[27] = 0;   /* Reserved.  */
  packet[28] = 0;   /* Reserved.  */
  packet[29] = 0;   /* Reserved.  */
  packet[30] = 0;   /* Reserved.  */
  packet[31] = 0;   /* Reserved.  */

  return packet;
}


gpg_error_t
sh_dmcrypt_create_container (ctrl_t ctrl, const char *devname, estream_t devfp)
{
  gpg_error_t err;
  char *header_space;
  char *targetname = NULL;
  size_t nread;
  char *p;
  char hexkey[16*2+1];
  char *table = NULL;
  unsigned long long nblocks;
  char *result = NULL;
  unsigned char twobyte[2];
  membuf_t keyblob;
  void  *keyblob_buf = NULL;
  size_t keyblob_len;
  size_t n;
  const char *s;

  if (!ctrl->devti)
    return gpg_error (GPG_ERR_INV_ARG);

  header_space = xtrymalloc (HEADER_SECTORS * SECTOR_SIZE);
  if (!header_space)
    return gpg_error_from_syserror ();

  /* Start building the keyblob.  */
  init_membuf (&keyblob, 512);
  append_tuple (&keyblob, KEYBLOB_TAG_BLOBVERSION, "\x01", 1);
  n = CONTTYPE_DM_CRYPT;
  twobyte[0] = (n >> 8);
  twobyte[1] = n;
  append_tuple (&keyblob, KEYBLOB_TAG_CONTTYPE, twobyte, 2);
  {
    gnupg_isotime_t tbuf;

    gnupg_get_isotime (tbuf);
    append_tuple (&keyblob, KEYBLOB_TAG_CREATED, tbuf, strlen (tbuf));
  }

  /* Rewind out stream.  */
  if (es_fseeko (devfp, 0, SEEK_SET))
    {
      err = gpg_error_from_syserror ();
      log_error ("error seeking to begin of '%s': %s\n",
                 devname, gpg_strerror (err));
      goto leave;
    }
  es_clearerr (devfp);

  /* Extra check that the device is empty.  */
  if (es_read (devfp, header_space, HEADER_SECTORS * SECTOR_SIZE, &nread))
    err = gpg_error_from_syserror ();
  else if (nread != HEADER_SECTORS * SECTOR_SIZE)
    err = gpg_error (GPG_ERR_TOO_SHORT);
  else
    err = 0;
  if (err)
    {
      log_error ("error reading header space of '%s': %s\n",
                 devname, gpg_strerror (err));
      goto leave;
    }
  for (p=header_space; nread && !*p; nread--, p++)
    ;
  if (nread)
    {
      log_error ("header space of '%s' already used - use %s to override\n",
                 devname, "--force");
      err = gpg_error (GPG_ERR_NOT_SUPPORTED);
      goto leave;
    }

  /* Check that the device is not used by device mapper. */
  err = check_blockdev (devname);
  if (err)
    goto leave;

  /* Compute the number of blocks.  */
  err = sh_blockdev_getsz (devname, &nblocks);
  if (err)
    {
      log_error ("error getting size of '%s': %s\n",
                 devname, gpg_strerror (err));
      goto leave;
    }
  if (nblocks <= HEADER_SECTORS + MIN_ENCRYPTED_SPACE + FOOTER_SECTORS)
    {
      log_error ("device '%s' is too small (min=%d blocks)\n",
                 devname,
                 HEADER_SECTORS + MIN_ENCRYPTED_SPACE + FOOTER_SECTORS);
      err = gpg_error (GPG_ERR_TOO_SHORT);
      goto leave;
    }
  nblocks -= HEADER_SECTORS + FOOTER_SECTORS;

  /* Device mapper needs a name for the device: Take it from the label
     or use "0".  */
  targetname = strconcat ("g13-", ctrl->client.uname, "-",
                          ctrl->devti->label? ctrl->devti->label : "0",
                          NULL);
  if (!targetname)
    {
      err = gpg_error_from_syserror ();
      goto leave;
    }

  /* Create the key.  */
  {
    char key[16];
    gcry_randomize (key, sizeof key, GCRY_STRONG_RANDOM);
    append_tuple (&keyblob, KEYBLOB_TAG_ENCKEY, key, sizeof key);
    bin2hex (key, 16, hexkey);
    wipememory (key, 16);
    /* Add a 2*(4+16) byte filler to conceal the fact that we use
       AES-128.  If we ever want to switch to 256 bit we can resize
       that filler to keep the keyblob at the same size.  */
    append_tuple (&keyblob, KEYBLOB_TAG_FILLER, key, sizeof key);
    append_tuple (&keyblob, KEYBLOB_TAG_FILLER, key, sizeof key);
  }

  /* Build dmcrypt table. */
  s = "aes-cbc-essiv:sha256";
  append_tuple (&keyblob, KEYBLOB_TAG_ALGOSTR, s, strlen (s));
  table = es_bsprintf ("0 %llu crypt %s %s 0 %s %d",
                       nblocks, s, hexkey, devname, HEADER_SECTORS);
  if (!table)
    {
      err = gpg_error_from_syserror ();
      goto leave;
    }
  wipememory (hexkey, sizeof hexkey);

  /* Add a copy of the setup area prefix to the keyblob.  */
  p = mk_setup_area_prefix (&n);
  if (!p)
    {
      err = gpg_error_from_syserror ();
      goto leave;
    }
  append_tuple (&keyblob, KEYBLOB_TAG_HDRCOPY, p, n);

  /* Turn the keyblob into a buffer and callback to encrypt it.  */
  keyblob_buf = get_membuf (&keyblob, &keyblob_len);
  if (!keyblob_buf)
    {
      err = gpg_error_from_syserror ();
      goto leave;
    }
  err = sh_encrypt_keyblob (ctrl, keyblob_buf, keyblob_len, &p, &n);
  if (err)
    {
      log_error ("encrypting the keyblob failed: %s\n", gpg_strerror (err));
      goto leave;
    }
  wipememory (keyblob_buf, keyblob_len);
  xfree (keyblob_buf);
  keyblob_buf = NULL;

  /* Create the container.  */
  /* { */
  /*   const char *argv[3]; */

  /*   argv[0] = "create"; */
  /*   argv[1] = targetname; */
  /*   argv[2] = NULL; */
  /*   err = sh_exec_tool ("/sbin/dmsetup", argv, table, &result, NULL); */
  /* } */
  /* if (err) */
  /*   { */
  /*     log_error ("error running dmsetup for '%s': %s\n", */
  /*                devname, gpg_strerror (err)); */
  /*     goto leave; */
  /*   } */
  /* log_debug ("dmsetup result: %s\n", result); */

  /* Write the setup area.  */


 leave:
  wipememory (hexkey, sizeof hexkey);
  if (table)
    {
      wipememory (table, strlen (table));
      xfree (table);
    }
  if (keyblob_buf)
    {
      wipememory (keyblob_buf, keyblob_len);
      xfree (keyblob_buf);
    }
  xfree (get_membuf (&keyblob, NULL));
  xfree (targetname);
  xfree (result);
  xfree (header_space);
  return err;
}
