/* sh-dmcrypt.c - The DM-Crypt part for g13-syshelp
 * Copyright (C) 2015, 2016 Werner Koch
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
#include <stdarg.h>
#include <errno.h>
#include <assert.h>
#include <sys/types.h>
#ifdef HAVE_SYS_MKDEV_H
#include <sys/mkdev.h>
#endif
#ifdef HAVE_SYS_SYSMACROS_H
# include <sys/sysmacros.h>
#endif
#ifdef HAVE_STAT
# include <sys/stat.h>
#endif
#include <unistd.h>

#include "g13-syshelp.h"
#include <assuan.h>
#include "../common/i18n.h"
#include "g13tuple.h"
#include "../common/exectool.h"
#include "../common/sysutils.h"
#include "keyblob.h"

/* The standard disk block size (logical).  */
#define SECTOR_SIZE 512

/* The physical block size used by modern devices.  */
#define PHY_SECTOR_SIZE  (SECTOR_SIZE*8)  /* 4 KiB */

/* The length of the crypto setup area in sectors.  16 KiB is a nice
   multiple of a modern block size and should be sufficient for all
   kind of extra public key encryption packets.  */
#define SETUP_AREA_SECTORS 32  /* 16 KiB */

/* The number of header block copies stored at the begin and end of
   the device.  */
#define HEADER_SETUP_AREA_COPIES 2
#define FOOTER_SETUP_AREA_COPIES 2

/* The length in blocks of the space we put at the start and at the
   end of the device.  This space is used to store N copies of the
   setup area for the actual encrypted container in between.  */
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


/*
 * Check whether the block device DEVNAME is used by device mapper.
 * If EXPECT_BUSY is set no error message is printed if the device is
 * busy.  Returns: 0 if the device is good and not yet used by DM.
 */
static gpg_error_t
check_blockdev (const char *devname, int expect_busy)
{
  gpg_error_t err;
  struct stat sb;
  unsigned int devmajor, devminor;
  char *result = NULL;
  char **lines = NULL;
  char **fields = NULL;
  int lno, count;

  if (gnupg_stat (devname, &sb))
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
    err = gnupg_exec_tool ("/sbin/dmsetup", argv, NULL, &result, NULL);
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
              if (!expect_busy)
                log_error ("device '%s' (%u:%u)"
                           " already in use by device mapper\n",
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


/* Create a new g13 style DM-Crypt container on device DEVNAME.  */
gpg_error_t
sh_dmcrypt_create_container (ctrl_t ctrl, const char *devname, estream_t devfp)
{
  gpg_error_t err;
  char *header_space;
  size_t header_space_size, header_space_used;
  size_t paddinglen;
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
  unsigned char *packet;
  int copy;

  if (!ctrl->devti)
    return gpg_error (GPG_ERR_INV_ARG);

  g13_syshelp_i_know_what_i_am_doing ();

  header_space_size = SETUP_AREA_SECTORS * SECTOR_SIZE;
  header_space = xtrymalloc (header_space_size);
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

  /* Rewind device stream.  */
  if (es_fseeko (devfp, 0, SEEK_SET))
    {
      err = gpg_error_from_syserror ();
      log_error ("error seeking to begin of '%s': %s\n",
                 devname, gpg_strerror (err));
      goto leave;
    }
  es_clearerr (devfp);

  /* Extra check that the device is empty.  */
  if (es_read (devfp, header_space, header_space_size, &nread))
    err = gpg_error_from_syserror ();
  else if (nread != header_space_size)
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
  err = check_blockdev (devname, 0);
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
  append_tuple_uint (&keyblob, KEYBLOB_TAG_CONT_NSEC, nblocks);
  nblocks -= HEADER_SECTORS + FOOTER_SECTORS;
  append_tuple_uint (&keyblob, KEYBLOB_TAG_ENC_NSEC, nblocks);
  append_tuple_uint (&keyblob, KEYBLOB_TAG_ENC_OFF, HEADER_SECTORS);

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
  assert (n < header_space_size);
  memcpy (header_space, p, n);
  header_space_used = n;

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
  log_debug ("plain setuparea=%p %zu bytes\n", keyblob_buf, keyblob_len);
  wipememory (keyblob_buf, keyblob_len);
  xfree (keyblob_buf);
  keyblob_buf = NULL;

  log_debug ("encry setuparea=%p %zu bytes\n", p, n);
  if (n >= header_space_size || (header_space_used + n) >= header_space_size)
    {
      err = gpg_error (GPG_ERR_TOO_LARGE);
      log_error ("setup area would overflow: %s\n", gpg_strerror (err));
      goto leave;
    }
  memcpy (header_space + header_space_used, p, n);
  header_space_used += n;

  /* Write the padding.  */
  packet = header_space + header_space_used;
  paddinglen = header_space_size - header_space_used;
  if (paddinglen < 16)
    {
      err = gpg_error (GPG_ERR_TOO_LARGE);
      log_error ("setup area too short for padding: %s\n", gpg_strerror (err));
      goto leave;
    }
  packet[0] = (0xc0|61); /* CTB for Private packet type 0x61.  */
  packet[1] = 0xff;      /* 5 byte length packet, value 20.  */
  packet[2] = (paddinglen-6) >> 24;
  packet[3] = (paddinglen-6) >> 16;
  packet[4] = (paddinglen-6) >> 8;
  packet[5] = (paddinglen-6);
  packet += 6;
  paddinglen -= 6;
  header_space_used += 6;
  for ( ;paddinglen >= 10;
        paddinglen -= 10, packet += 10, header_space_used += 10)
    memcpy (packet, "GnuPG/PAD", 10);
  for ( ;paddinglen; paddinglen--, packet++, header_space_used++)
    *packet = 0;

  if (header_space_used != header_space_size)
    BUG ();

  /* Create the container.  */
  {
    const char *argv[3];

    argv[0] = "create";
    argv[1] = targetname;
    argv[2] = NULL;
    log_debug ("now running \"dmsetup create %s\"\n", targetname);
    log_debug ("  with table='%s'\"\n", table);
    err = gnupg_exec_tool ("/sbin/dmsetup", argv, table, &result, NULL);
  }
  if (err)
    {
      log_error ("error running dmsetup for '%s': %s\n",
                 devname, gpg_strerror (err));
      goto leave;
    }
  if (result && *result)
    log_debug ("dmsetup result: %s\n", result);

  /* Write the setup area.  */
  if (es_fseeko (devfp, 0, SEEK_SET))
    {
      err = gpg_error_from_syserror ();
      log_error ("error seeking to begin of '%s': %s\n",
                 devname, gpg_strerror (err));
      goto leave;
    }
  es_clearerr (devfp);

  for (copy = 0; copy < HEADER_SETUP_AREA_COPIES; copy++)
    {
      size_t nwritten;

      if (es_write (devfp, header_space, header_space_size, &nwritten))
        {
          err = gpg_error_from_syserror ();
          break;
        }
      else if (nwritten != header_space_size)
        {
          err = gpg_error (GPG_ERR_TOO_SHORT);
          break;
        }
    }
  if (err)
    {
      log_error ("error writing header space copy %d of '%s': %s\n",
                 copy, devname, gpg_strerror (err));
      goto leave;
    }

  if (es_fseeko (devfp,
                 (- header_space_size * FOOTER_SETUP_AREA_COPIES), SEEK_END))
    {
      err = gpg_error_from_syserror ();
      log_error ("error seeking to end of '%s': %s\n",
                 devname, gpg_strerror (err));
      goto leave;
    }
  es_clearerr (devfp);

  for (copy = 0; copy < FOOTER_SETUP_AREA_COPIES; copy++)
    {
      size_t nwritten;

      if (es_write (devfp, header_space, header_space_size, &nwritten))
        {
          err = gpg_error_from_syserror ();
          break;
        }
      else if (nwritten != header_space_size)
        {
          err = gpg_error (GPG_ERR_TOO_SHORT);
          break;
        }
    }
  if (!err && es_fflush (devfp))
    err = gpg_error_from_syserror ();
  if (err)
    {
      log_error ("error writing footer space copy %d of '%s': %s\n",
                 copy, devname, gpg_strerror (err));
      goto leave;
    }

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


/* Mount a DM-Crypt container on device DEVNAME taking keys and other
 * meta data from KEYBLOB.  If NOMOUNT is set the actual mount command
 * is not run.  */
gpg_error_t
sh_dmcrypt_mount_container (ctrl_t ctrl, const char *devname,
                            tupledesc_t keyblob, int nomount)
{
  gpg_error_t err;
  char *targetname_abs = NULL;
  const char *targetname;
  char hexkey[16*2+1];
  char *table = NULL;
  unsigned long long nblocks, nblocks2;
  char *result = NULL;
  size_t n;
  const char *s;
  const char *algostr;
  size_t algostrlen;

  if (!ctrl->devti)
    return gpg_error (GPG_ERR_INV_ARG);

  g13_syshelp_i_know_what_i_am_doing ();

  /* Check that the device is not yet used by device mapper. */
  err = check_blockdev (devname, 0);
  if (err)
    goto leave;

  /* Compute the number of blocks and compare them to the value
     provided as meta data.  */
  err = sh_blockdev_getsz (devname, &nblocks);
  if (err)
    {
      log_error ("error getting size of '%s': %s\n",
                 devname, gpg_strerror (err));
      goto leave;
    }
  err = find_tuple_uint (keyblob, KEYBLOB_TAG_CONT_NSEC, &nblocks2);
  if (err)
    {
      log_error ("error getting size from keyblob: %s\n", gpg_strerror (err));
      goto leave;
    }
  if (nblocks != nblocks2)
    {
      log_error ("inconsistent size of container: expected==%llu got=%llu\n",
                 nblocks2, nblocks);
      err = gpg_error (GPG_ERR_INV_DATA);
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
  err = find_tuple_uint (keyblob, KEYBLOB_TAG_ENC_NSEC, &nblocks2);
  if (err)
    {
      log_error ("error getting enc size from keyblob: %s\n",
                 gpg_strerror (err));
      goto leave;
    }
  if (nblocks != nblocks2)
    {
      log_error ("inconsistent size of enc data: expected==%llu got=%llu\n",
                 nblocks2, nblocks);
      err = gpg_error (GPG_ERR_INV_DATA);
      goto leave;
    }
  /* Check that the offset is consistent.  */
  err = find_tuple_uint (keyblob, KEYBLOB_TAG_ENC_OFF, &nblocks2);
  if (err)
    {
      log_error ("error getting enc offset from keyblob: %s\n",
                 gpg_strerror (err));
      goto leave;
    }
  if (nblocks2 != HEADER_SECTORS)
    {
      log_error ("inconsistent offset of enc data: expected==%llu got=%d\n",
                 nblocks2, HEADER_SECTORS);
      err = gpg_error (GPG_ERR_INV_DATA);
      goto leave;
    }

  /* Device mapper needs a name for the device: Take it from the label
     or use "0".  */
  targetname_abs = strconcat ("/dev/mapper/",
                              "g13-", ctrl->client.uname, "-",
                              ctrl->devti->label? ctrl->devti->label : "0",
                              NULL);
  if (!targetname_abs)
    {
      err = gpg_error_from_syserror ();
      goto leave;
    }
  targetname = strrchr (targetname_abs, '/');
  if (!targetname)
    BUG ();
  targetname++;

  /* Get the algorithm string.  */
  algostr = find_tuple (keyblob, KEYBLOB_TAG_ALGOSTR, &algostrlen);
  if (!algostr || algostrlen > 100)
    {
      log_error ("algo string not found in keyblob or too long\n");
      err = gpg_error (GPG_ERR_INV_DATA);
      goto leave;
    }

  /* Get the key.  */
  s = find_tuple (keyblob, KEYBLOB_TAG_ENCKEY, &n);
  if (!s || n != 16)
    {
      if (!s)
        log_error ("no key found in keyblob\n");
      else
        log_error ("unexpected size of key (%zu)\n", n);
      err = gpg_error (GPG_ERR_INV_KEYLEN);
      goto leave;
    }
  bin2hex (s, 16, hexkey);

  /* Build dmcrypt table. */
  table = es_bsprintf ("0 %llu crypt %.*s %s 0 %s %d",
                       nblocks, (int)algostrlen, algostr,
                       hexkey, devname, HEADER_SECTORS);
  wipememory (hexkey, sizeof hexkey);
  if (!table)
    {
      err = gpg_error_from_syserror ();
      goto leave;
    }

  /* Load the table.  */
  {
    const char *argv[3];

    argv[0] = "create";
    argv[1] = targetname;
    argv[2] = NULL;
    log_debug ("now running \"dmsetup create %s\"\n", targetname);
    err = gnupg_exec_tool ("/sbin/dmsetup", argv, table, &result, NULL);
  }
  if (err)
    {
      log_error ("error running dmsetup for '%s': %s\n",
                 devname, gpg_strerror (err));
      goto leave;
    }
  if (result && *result)
    log_debug ("dmsetup result: %s\n", result);
  xfree (result);
  result = NULL;

  g13_status (ctrl, STATUS_PLAINDEV, targetname_abs, NULL);

  /* Mount if a mountpoint has been given.  */
  if (!nomount && ctrl->devti->mountpoint)
    {
      const char *argv[3];

      argv[0] = targetname_abs;
      argv[1] = ctrl->devti->mountpoint;
      argv[2] = NULL;
      log_debug ("now running \"mount %s %s\"\n",
                 targetname_abs, ctrl->devti->mountpoint);
      err = gnupg_exec_tool ("/bin/mount", argv, NULL, &result, NULL);
      if (err)
        {
          log_error ("error running mount: %s\n", gpg_strerror (err));
          goto leave;
        }
      if (result && *result)  /* (We should not see output to stdout).  */
        log_info ("WARNING: mount returned data on stdout! (%s)\n", result);
    }


 leave:
  wipememory (hexkey, sizeof hexkey);
  if (table)
    {
      wipememory (table, strlen (table));
      xfree (table);
    }
  xfree (targetname_abs);
  xfree (result);
  return err;
}


/* Unmount a DM-Crypt container on device DEVNAME and wipe the keys.  */
gpg_error_t
sh_dmcrypt_umount_container (ctrl_t ctrl, const char *devname)
{
  gpg_error_t err;
  char *targetname_abs = NULL;
  char *result = NULL;

  if (!ctrl->devti)
    return gpg_error (GPG_ERR_INV_ARG);

  g13_syshelp_i_know_what_i_am_doing ();

  /* Check that the device is used by device mapper. */
  err = check_blockdev (devname, 1);
  if (gpg_err_code (err) != GPG_ERR_EBUSY)
    {
      log_error ("device '%s' is not used by the device mapper: %s\n",
                 devname, gpg_strerror (err));
      goto leave;
    }

  /* Fixme: Check that this is really a g13 partition.  */

  /* Device mapper needs a name for the device: Take it from the label
     or use "0".  */
  targetname_abs = strconcat ("/dev/mapper/",
                              "g13-", ctrl->client.uname, "-",
                              ctrl->devti->label? ctrl->devti->label : "0",
                              NULL);
  if (!targetname_abs)
    {
      err = gpg_error_from_syserror ();
      goto leave;
    }

  /* Run the regular umount command but first test with findmnt.  */
  {
    const char *argv[3];

    argv[0] = targetname_abs;
    argv[1] = NULL;
    log_debug ("now running \"findmnt %s\"\n", targetname_abs);
    err = gnupg_exec_tool ("/bin/findmnt", argv, NULL, &result, NULL);

    if (err)
      log_info ("Note: device was not mounted\n");
    else
      {
        xfree (result);
        result = NULL;

        argv[0] = targetname_abs;
        argv[1] = NULL;
        log_debug ("now running \"umount %s\"\n", targetname_abs);
        err = gnupg_exec_tool ("/bin/umount", argv, NULL, &result, NULL);
        if (err)
          {
            log_error ("error running umount: %s\n", gpg_strerror (err));
            if (1)
              {
                /* Try to show some info about processes using the partition. */
                argv[0] = "-mv";
                argv[1] = targetname_abs;
                argv[2] = NULL;
                gnupg_exec_tool ("/bin/fuser", argv, NULL, &result, NULL);
              }
            goto leave;
          }
        if (result && *result)  /* (We should not see output to stdout).  */
          log_info ("WARNING: umount returned data on stdout! (%s)\n", result);
      }
  }
  xfree (result);
  result = NULL;

  /* Run the dmsetup remove command.  */
  {
    const char *argv[3];

    argv[0] = "remove";
    argv[1] = targetname_abs;
    argv[2] = NULL;
    log_debug ("now running \"dmsetup remove %s\"\n", targetname_abs);
    err = gnupg_exec_tool ("/sbin/dmsetup", argv, NULL, &result, NULL);
  }
  if (err)
    {
      log_error ("error running \"dmsetup remove %s\": %s\n",
                 targetname_abs, gpg_strerror (err));
      goto leave;
    }
  if (result && *result)
    log_debug ("dmsetup result: %s\n", result);
  xfree (result);
  result = NULL;

 leave:
  xfree (targetname_abs);
  xfree (result);
  return err;
}


/* Suspend a DM-Crypt container on device DEVNAME and wipe the keys.  */
gpg_error_t
sh_dmcrypt_suspend_container (ctrl_t ctrl, const char *devname)
{
  gpg_error_t err;
  char *targetname_abs = NULL;
  const char *targetname;
  char *result = NULL;

  if (!ctrl->devti)
    return gpg_error (GPG_ERR_INV_ARG);

  g13_syshelp_i_know_what_i_am_doing ();

  /* Check that the device is used by device mapper. */
  err = check_blockdev (devname, 1);
  if (gpg_err_code (err) != GPG_ERR_EBUSY)
    {
      log_error ("device '%s' is not used by the device mapper: %s\n",
                 devname, gpg_strerror (err));
      goto leave;
    }

  /* Fixme: Check that this is really a g13 partition.  */

  /* Device mapper needs a name for the device: Take it from the label
     or use "0".  */
  targetname_abs = strconcat ("/dev/mapper/",
                              "g13-", ctrl->client.uname, "-",
                              ctrl->devti->label? ctrl->devti->label : "0",
                              NULL);
  if (!targetname_abs)
    {
      err = gpg_error_from_syserror ();
      goto leave;
    }
  targetname = strrchr (targetname_abs, '/');
  if (!targetname)
    BUG ();
  targetname++;

  /* Send the suspend command.  */
  {
    const char *argv[3];

    argv[0] = "suspend";
    argv[1] = targetname;
    argv[2] = NULL;
    log_debug ("now running \"dmsetup suspend %s\"\n", targetname);
    err = gnupg_exec_tool ("/sbin/dmsetup", argv, NULL, &result, NULL);
  }
  if (err)
    {
      log_error ("error running \"dmsetup suspend %s\": %s\n",
                 targetname, gpg_strerror (err));
      goto leave;
    }
  if (result && *result)
    log_debug ("dmsetup result: %s\n", result);
  xfree (result);
  result = NULL;

  /* Send the wipe key command.  */
  {
    const char *argv[5];

    argv[0] = "message";
    argv[1] = targetname;
    argv[2] = "0";
    argv[3] = "key wipe";
    argv[4] = NULL;
    log_debug ("now running \"dmsetup message %s 0 key wipe\"\n", targetname);
    err = gnupg_exec_tool ("/sbin/dmsetup", argv, NULL, &result, NULL);
  }
  if (err)
    {
      log_error ("error running \"dmsetup message %s 0 key wipe\": %s\n",
                 targetname, gpg_strerror (err));
      goto leave;
    }
  if (result && *result)
    log_debug ("dmsetup result: %s\n", result);
  xfree (result);
  result = NULL;


 leave:
  xfree (targetname_abs);
  xfree (result);
  return err;
}


/* Resume a DM-Crypt container on device DEVNAME taking keys and other
 * meta data from KEYBLOB.  */
gpg_error_t
sh_dmcrypt_resume_container (ctrl_t ctrl, const char *devname,
                             tupledesc_t keyblob)
{
  gpg_error_t err;
  char *targetname_abs = NULL;
  const char *targetname;
  char hexkey[8+16*2+1]; /* 8 is used to prepend "key set ".  */
  char *table = NULL;
  char *result = NULL;
  size_t n;
  const char *s;
  const char *algostr;
  size_t algostrlen;

  if (!ctrl->devti)
    return gpg_error (GPG_ERR_INV_ARG);

  g13_syshelp_i_know_what_i_am_doing ();

  /* Check that the device is used by device mapper. */
  err = check_blockdev (devname, 1);
  if (gpg_err_code (err) != GPG_ERR_EBUSY)
    {
      log_error ("device '%s' is not used by the device mapper: %s\n",
                 devname, gpg_strerror (err));
      goto leave;
    }

  /* Device mapper needs a name for the device: Take it from the label
     or use "0".  */
  targetname_abs = strconcat ("/dev/mapper/",
                              "g13-", ctrl->client.uname, "-",
                              ctrl->devti->label? ctrl->devti->label : "0",
                              NULL);
  if (!targetname_abs)
    {
      err = gpg_error_from_syserror ();
      goto leave;
    }
  targetname = strrchr (targetname_abs, '/');
  if (!targetname)
    BUG ();
  targetname++;

  /* Get the algorithm string.  */
  algostr = find_tuple (keyblob, KEYBLOB_TAG_ALGOSTR, &algostrlen);
  if (!algostr || algostrlen > 100)
    {
      log_error ("algo string not found in keyblob or too long\n");
      err = gpg_error (GPG_ERR_INV_DATA);
      goto leave;
    }

  /* Get the key.  */
  s = find_tuple (keyblob, KEYBLOB_TAG_ENCKEY, &n);
  if (!s || n != 16)
    {
      if (!s)
        log_error ("no key found in keyblob\n");
      else
        log_error ("unexpected size of key (%zu)\n", n);
      err = gpg_error (GPG_ERR_INV_KEYLEN);
      goto leave;
    }
  strcpy (hexkey, "key set ");
  bin2hex (s, 16, hexkey+8);

  /* Send the key */
  {
    const char *argv[4];

    argv[0] = "message";
    argv[1] = targetname;
    argv[2] = "0";
    argv[3] = NULL;
    log_debug ("now running \"dmsetup message %s 0 [key set]\"\n", targetname);
    err = gnupg_exec_tool ("/sbin/dmsetup", argv, hexkey, &result, NULL);
  }
  wipememory (hexkey, sizeof hexkey);
  if (err)
    {
      log_error ("error running \"dmsetup message %s 0 [key set]\": %s\n",
                 devname, gpg_strerror (err));
      goto leave;
    }
  if (result && *result)
    log_debug ("dmsetup result: %s\n", result);
  xfree (result);
  result = NULL;

  /* Send the resume command. */
  {
    const char *argv[3];

    argv[0] = "resume";
    argv[1] = targetname;
    argv[2] = NULL;
    log_debug ("now running \"dmsetup resume %s\"\n", targetname);
    err = gnupg_exec_tool ("/sbin/dmsetup", argv, NULL, &result, NULL);
  }
  if (err)
    {
      log_error ("error running \"dmsetup resume %s\": %s\n",
                 targetname, gpg_strerror (err));
      goto leave;
    }
  if (result && *result)
    log_debug ("dmsetup result: %s\n", result);
  xfree (result);
  result = NULL;

 leave:
  wipememory (hexkey, sizeof hexkey);
  if (table)
    {
      wipememory (table, strlen (table));
      xfree (table);
    }
  xfree (targetname_abs);
  xfree (result);
  return err;
}
