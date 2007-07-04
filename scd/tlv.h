/* tlv.h - Tag-Length-Value Utilities
 *	Copyright (C) 2004 Free Software Foundation, Inc.
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

#ifndef SCD_TLV_H
#define SCD_TLV_H 1


enum tlv_tag_class {
  CLASS_UNIVERSAL = 0,
  CLASS_APPLICATION = 1,
  CLASS_CONTEXT = 2,
  CLASS_PRIVATE =3
};

enum tlv_tag_type {
  TAG_NONE = 0,
  TAG_BOOLEAN = 1,
  TAG_INTEGER = 2,
  TAG_BIT_STRING = 3,
  TAG_OCTET_STRING = 4,
  TAG_NULL = 5,
  TAG_OBJECT_ID = 6,
  TAG_OBJECT_DESCRIPTOR = 7,
  TAG_EXTERNAL = 8,
  TAG_REAL = 9,
  TAG_ENUMERATED = 10,
  TAG_EMBEDDED_PDV = 11,
  TAG_UTF8_STRING = 12,
  TAG_REALTIVE_OID = 13,
  TAG_SEQUENCE = 16,
  TAG_SET = 17,
  TAG_NUMERIC_STRING = 18,
  TAG_PRINTABLE_STRING = 19,
  TAG_TELETEX_STRING = 20,
  TAG_VIDEOTEX_STRING = 21,
  TAG_IA5_STRING = 22,
  TAG_UTC_TIME = 23,
  TAG_GENERALIZED_TIME = 24,
  TAG_GRAPHIC_STRING = 25,
  TAG_VISIBLE_STRING = 26,
  TAG_GENERAL_STRING = 27,
  TAG_UNIVERSAL_STRING = 28,
  TAG_CHARACTER_STRING = 29,
  TAG_BMP_STRING = 30
};


/* Locate a TLV encoded data object in BUFFER of LENGTH and return a
   pointer to value as well as its length in NBYTES.  Return NULL if
   it was not found or if the object does not fit into the buffer. */
const unsigned char *find_tlv (const unsigned char *buffer, size_t length,
                               int tag, size_t *nbytes);


/* Locate a TLV encoded data object in BUFFER of LENGTH and return a
   pointer to value as well as its length in NBYTES.  Return NULL if
   it was not found.  Note, that the function does not check whether
   the value fits into the provided buffer.*/
const unsigned char *find_tlv_unchecked (const unsigned char *buffer,
                                         size_t length,
                                         int tag, size_t *nbytes);


/* ASN.1 BER parser: Parse BUFFER of length SIZE and return the tag
   and the length part from the TLV triplet.  Update BUFFER and SIZE
   on success. */
gpg_error_t parse_ber_header (unsigned char const **buffer, size_t *size,
                              int *r_class, int *r_tag, 
                              int *r_constructed,
                              int *r_ndef, size_t *r_length, size_t *r_nhdr);



/* Return the next token of an canconical encoded S-expression.  BUF
   is the pointer to the S-expression and BUFLEN is a pointer to the
   length of this S-expression (used to validate the syntax).  Both
   are updated to reflect the new position.  The token itself is
   returned as a pointer into the orginal buffer at TOK and TOKLEN.
   If a parentheses is the next token, TOK will be set to NULL.
   TOKLEN is checked to be within the bounds.  On error a error code
   is returned and all pointers should are not guaranteed to point to
   a meanigful value. DEPTH should be initialized to 0 and will
   reflect on return the actual depth of the tree. To detect the end
   of the S-expression it is advisable to check DEPTH after a
   successful return. */
gpg_error_t parse_sexp (unsigned char const **buf, size_t *buflen,
                        int *depth, unsigned char const **tok, size_t *toklen);



#endif /* SCD_TLV_H */
