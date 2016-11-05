/* keyblob.h - Defs to describe a keyblob
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

#ifndef G13_KEYBLOB_H
#define G13_KEYBLOB_H

/* The setup area (header block) is the actual core of G13.  Here is
   the format:

   u8   Packet type.  Value is 61 (0x3d).
   u8   Constant value 255 (0xff).
   u32  Length of the following structure
          b10  Value: "GnuPG/G13\x00".
          u8   Version.  Value is 1.
          u8   reserved
          u8   reserved
          u8   OS Flag:  0 = unspecified, 1 = Linux
          u32  Length of the entire header.  This includes all bytes
               starting at the packet type and ending with the last
               padding byte of the header.
          u8   Number of copies of this header (1..255).
          u8   Number of copies of this header at the end of the
               container (usually 0).
          b6   reserved
   n bytes: OpenPGP encrypted and optionally signed keyblob.
   n bytes: CMS encrypted and optionally signed keyblob.  Such a CMS
            packet will be enclosed in a private flagged OpenPGP
            packet.  Either the OpenPGP encrypted packet as described
            above, the CMS encrypted or both packets must exist.  The
            encapsulation packet has this structure:
                u8   Packet type.  Value is 61 (0x3d).
                u8   Constant value 255 (0xff).
                u32  Length of the following structure
                b10  Value: "GnuPG/CMS\x00".
                b(n) Regular CMS structure.
   n bytes: Padding. The structure resembles an OpenPGP packet.
                u8   Packet type.  Value is 61 (0x3d).
                u8   Constant value 255 (0xff).
                u32  Length of the following structure
                b10  Value: "GnuPG/PAD\x00".
                b(n) Padding stuff.
                     (repeat the above value
                      or if the remaining N < 10, all 0x00).
            Given this structure the minimum padding is 16 bytes.

   n bytes: File system container.
   (optionally followed by copies on the header).
*/


#define KEYBLOB_TAG_BLOBVERSION 0
/* This tag is used to describe the version of the keyblob.  It must
   be the first tag in a keyblob and may only occur once.  Its value
   is a single byte giving the blob version.  The only defined version
   is 1.  */

#define KEYBLOB_TAG_CONTTYPE 1
/* This tag gives the type of the container.  The value is a two byte
   big endian integer giving the type of the container as described by
   the CONTTYPE_ constants.  */

#define KEYBLOB_TAG_DETACHED 2
/* Indicates that the actual storage is not in the same file as the
   keyblob.  If a value is given it is expected to be the GUID of the
   partition.  */

#define KEYBLOB_TAG_CREATED  3
/* This is an ISO 8601 time string with the date the container was
   created.  */

#define KEYBLOB_TAG_CONT_NSEC 7
/* Number of 512-byte sectors of the entire container including all
   copies of the setup area.  */

#define KEYBLOB_TAG_ENC_NSEC  8
#define KEYBLOB_TAG_ENC_OFF   9
/* Number of 512-byte sectors used for the encrypted data and its
   start offset in 512-byte sectors from the begin of the container.
   Note that these information can also be deduced from the
   unencrypted part of the setup area.  */

#define KEYBLOB_TAG_ALGOSTR 10
/* For a dm-crypt container this is the used algorithm string.  For
   example: "aes-cbc-essiv:sha256".  */

#define KEYBLOB_TAG_KEYNO  16
/* This tag indicates a new key.  The value is a 4 byte big endian
   integer giving the key number.  If the container type does only
   need one key this key number should be 0.  */

#define KEYBLOB_TAG_ENCALGO  17
/* Describes the algorithm of the key.  It must follow a KEYNO tag.
   The value is a 2 byte big endian algorithm number.  The algorithm
   numbers used are those from Libgcrypt (e.g. AES 128 is described by
   the value 7).  This tag is optional.  */

#define KEYBLOB_TAG_ENCKEY  18
/* This tag gives the actual encryption key.  It must follow a KEYNO
   tag.  The value is the plain key.  */

#define KEYBLOB_TAG_MACALGO  19
/* Describes the MAC algorithm.  It must follow a KEYNO tag.  The
   value is a 2 byte big endian algorithm number describing the MAC
   algorithm with a value of 1 indicating HMAC.  It is followed by
   data specific to the MAC algorithm.  In case of HMAC this data is a
   2 byte big endian integer with the Libgcrypt algorithm id of the
   hash algorithm.  */

#define KEYBLOB_TAG_MACKEY  20
/* This tag gives the actual MACing key.  It must follow a KEYNO tag.
   The value is the key used for MACing.  */


#define KEYBLOB_TAG_HDRCOPY 21
/* The value of this tag is a copy of the setup area prefix header
   block (packet 61 with marker "GnuPG/G13\x00".  We use it to allow
   signing of that cleartext data.  */

#define KEYBLOB_TAG_FILLER   0xffff
/* This tag may be used for alignment and padding purposes.  The value
   has no meaning.  */



#define CONTTYPE_ENCFS      1
/* A EncFS based backend.  This requires a whole directory which
   includes the encrypted files.  Metadata is not encrypted.  */

#define CONTTYPE_DM_CRYPT   2
/* A DM-Crypt based backend.  */


#define CONTTYPE_TRUECRYPT  21571
/* A Truecrypt (www.truecrypt.org) based container.  Due to the design
   of truecrypt this requires a second datafile because it is not
   possible to prepend a truecrypt container with our keyblob.  */



/*-- keyblob.c --*/
gpg_error_t g13_is_container (ctrl_t ctrl, const char *filename);
gpg_error_t g13_keyblob_read (const char *filename,
                              void **r_enckeyblob, size_t *r_enckeybloblen);


#endif /*G13_KEYBLOB_H*/
