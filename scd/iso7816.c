/* iso7816.c - ISO 7816 commands
 *	Copyright (C) 2003, 2004 Free Software Foundation, Inc.
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

#if defined(GNUPG_SCD_MAIN_HEADER)
#include GNUPG_SCD_MAIN_HEADER
#elif GNUPG_MAJOR_VERSION == 1
/* This is used with GnuPG version < 1.9.  The code has been source
   copied from the current GnuPG >= 1.9  and is maintained over
   there. */
#include "options.h"
#include "errors.h"
#include "memory.h"
#include "util.h"
#include "i18n.h"
#else /* GNUPG_MAJOR_VERSION != 1 */
#include "scdaemon.h"
#endif /* GNUPG_MAJOR_VERSION != 1 */

#include "iso7816.h"
#include "apdu.h"


#define CMD_SELECT_FILE 0xA4
#define CMD_VERIFY      0x20
#define CMD_CHANGE_REFERENCE_DATA 0x24
#define CMD_RESET_RETRY_COUNTER   0x2C
#define CMD_GET_DATA    0xCA
#define CMD_PUT_DATA    0xDA
#define CMD_MSE         0x22
#define CMD_PSO         0x2A
#define CMD_INTERNAL_AUTHENTICATE 0x88
#define CMD_GENERATE_KEYPAIR      0x47
#define CMD_GET_CHALLENGE         0x84
#define CMD_READ_BINARY 0xB0
#define CMD_READ_RECORD 0xB2

static gpg_error_t
map_sw (int sw)
{
  gpg_err_code_t ec;

  switch (sw)
    {
    case SW_EEPROM_FAILURE: ec = GPG_ERR_HARDWARE; break;
    case SW_WRONG_LENGTH:   ec = GPG_ERR_INV_VALUE; break;
    case SW_CHV_WRONG:      ec = GPG_ERR_BAD_PIN; break;
    case SW_CHV_BLOCKED:    ec = GPG_ERR_PIN_BLOCKED; break;
    case SW_USE_CONDITIONS: ec = GPG_ERR_USE_CONDITIONS; break;
    case SW_NOT_SUPPORTED:  ec = GPG_ERR_NOT_SUPPORTED; break;
    case SW_BAD_PARAMETER:  ec = GPG_ERR_INV_VALUE; break;
    case SW_FILE_NOT_FOUND: ec = GPG_ERR_ENOENT; break;
    case SW_RECORD_NOT_FOUND:ec= GPG_ERR_NOT_FOUND; break;
    case SW_REF_NOT_FOUND:  ec = GPG_ERR_NO_OBJ; break;
    case SW_BAD_P0_P1:      ec = GPG_ERR_INV_VALUE; break;
    case SW_INS_NOT_SUP:    ec = GPG_ERR_CARD; break;
    case SW_CLA_NOT_SUP:    ec = GPG_ERR_CARD; break;
    case SW_SUCCESS:        ec = 0; break;

    case SW_HOST_OUT_OF_CORE: ec = GPG_ERR_ENOMEM; break;
    case SW_HOST_INV_VALUE:   ec = GPG_ERR_INV_VALUE; break;
    case SW_HOST_INCOMPLETE_CARD_RESPONSE: ec = GPG_ERR_CARD; break;
    default:
      if ((sw & 0x010000))
        ec = GPG_ERR_GENERAL; /* Should not happen. */
      else if ((sw & 0xff00) == SW_MORE_DATA)
        ec = 0; /* This should actually never been seen here. */
      else
        ec = GPG_ERR_CARD;
    }
  return gpg_error (ec);
}

/* This function is specialized version of the SELECT FILE command.
   SLOT is the card and reader as created for example by
   apdu_open_reader (), AID is a buffer of size AIDLEN holding the
   requested application ID.  The function can't be used to enumerate
   AIDs and won't return the AID on success.  The return value is 0
   for okay or a GPG error code.  Note that ISO error codes are
   internally mapped. */
gpg_error_t
iso7816_select_application (int slot, const char *aid, size_t aidlen)
{
  static char const openpgp_aid[] = { 0xD2, 0x76, 0x00, 0x01, 0x24, 0x01 };
  int sw;
  int p1 = 0x0C; /* No FCI to be returned. */
  
  if (aidlen == sizeof openpgp_aid
      && !memcmp (aid, openpgp_aid, sizeof openpgp_aid))
    p1 = 0; /* The current openpgp cards don't allow 0x0c. */

  sw = apdu_send_simple (slot, 0x00, CMD_SELECT_FILE, 4, p1, aidlen, aid);
  return map_sw (sw);
}


gpg_error_t
iso7816_select_file (int slot, int tag, int is_dir,
                     unsigned char **result, size_t *resultlen)
{
  int sw, p0, p1;
  unsigned char tagbuf[2];

  tagbuf[0] = (tag >> 8) & 0xff;
  tagbuf[1] = tag & 0xff;

  if (result || resultlen)
    {
      *result = NULL;
      *resultlen = 0;
      return gpg_error (GPG_ERR_NOT_IMPLEMENTED);
    }
  else
    {
      p0 = (tag == 0x3F00)? 0: is_dir? 1:2;
      p1 = 0x0c; /* No FC return. */
      sw = apdu_send_simple (slot, 0x00, CMD_SELECT_FILE,
                             p0, p1, 2, tagbuf );
      return map_sw (sw);
    }

  return 0;
}


/* This is a private command currently only working for TCOS cards. */
gpg_error_t
iso7816_list_directory (int slot, int list_dirs,
                        unsigned char **result, size_t *resultlen)
{
  int sw;

  if (!result || !resultlen)
    return gpg_error (GPG_ERR_INV_VALUE);
  *result = NULL;
  *resultlen = 0;

  sw = apdu_send (slot, 0x80, 0xAA, list_dirs? 1:2, 0, -1, NULL,
                  result, resultlen);
  if (sw != SW_SUCCESS)
    {
      /* Make sure that pending buffers are released. */
      xfree (*result);
      *result = NULL;
      *resultlen = 0;
    }
  return map_sw (sw);
}



/* Perform a VERIFY command on SLOT using the card holder verification
   vector CHVNO with a CHV of lenght CHVLEN.  Returns 0 on success. */
gpg_error_t
iso7816_verify (int slot, int chvno, const char *chv, size_t chvlen)
{
  int sw;

  sw = apdu_send_simple (slot, 0x00, CMD_VERIFY, 0, chvno, chvlen, chv);
  return map_sw (sw);
}

/* Perform a CHANGE_REFERENCE_DATA command on SLOT for the card holder
   verification vector CHVNO.  If the OLDCHV is NULL (and OLDCHVLEN
   0), a "change reference data" is done, otherwise an "exchange
   reference data".  The new reference data is expected in NEWCHV of
   length NEWCHVLEN.  */
gpg_error_t
iso7816_change_reference_data (int slot, int chvno,
                               const char *oldchv, size_t oldchvlen,
                               const char *newchv, size_t newchvlen)
{
  int sw;
  char *buf;

  if ((!oldchv && oldchvlen)
      || (oldchv && !oldchvlen)
      || !newchv || !newchvlen )
    return gpg_error (GPG_ERR_INV_VALUE);

  buf = xtrymalloc (oldchvlen + newchvlen);
  if (!buf)
    return gpg_error (gpg_err_code_from_errno (errno));
  if (oldchvlen)
    memcpy (buf, oldchv, oldchvlen);
  memcpy (buf+oldchvlen, newchv, newchvlen);

  sw = apdu_send_simple (slot, 0x00, CMD_CHANGE_REFERENCE_DATA,
                         oldchvlen? 0 : 1, chvno, oldchvlen+newchvlen, buf);
  xfree (buf);
  return map_sw (sw);

}

gpg_error_t
iso7816_reset_retry_counter (int slot, int chvno,
                             const char *newchv, size_t newchvlen)
{
  int sw;

  if (!newchv || !newchvlen )
    return gpg_error (GPG_ERR_INV_VALUE);

  sw = apdu_send_simple (slot, 0x00, CMD_RESET_RETRY_COUNTER,
                         2, chvno, newchvlen, newchv);
  return map_sw (sw);
}


/* Perform a GET DATA command requesting TAG and storing the result in
   a newly allocated buffer at the address passed by RESULT.  Return
   the length of this data at the address of RESULTLEN. */
gpg_error_t
iso7816_get_data (int slot, int tag,
                  unsigned char **result, size_t *resultlen)
{
  int sw;

  if (!result || !resultlen)
    return gpg_error (GPG_ERR_INV_VALUE);
  *result = NULL;
  *resultlen = 0;

  sw = apdu_send (slot, 0x00, CMD_GET_DATA,
                  ((tag >> 8) & 0xff), (tag & 0xff), -1, NULL,
                  result, resultlen);
  if (sw != SW_SUCCESS)
    {
      /* Make sure that pending buffers are released. */
      xfree (*result);
      *result = NULL;
      *resultlen = 0;
      return map_sw (sw);
    }

  return 0;
}


/* Perform a PUT DATA command on card in SLOT.  Write DATA of length
   DATALEN to TAG. */
gpg_error_t
iso7816_put_data (int slot, int tag,
                  const unsigned char *data, size_t datalen)
{
  int sw;

  sw = apdu_send_simple (slot, 0x00, CMD_PUT_DATA,
                         ((tag >> 8) & 0xff), (tag & 0xff),
                         datalen, data);
  return map_sw (sw);
}

/* Manage Security Environment.  This is a weird operation and there
   is no easy abstraction for it.  Furthermore, some card seem to have
   a different interpreation of 7816-8 and thus we resort to let the
   caller decide what to do. */
gpg_error_t
iso7816_manage_security_env (int slot, int p1, int p2,
                             const unsigned char *data, size_t datalen)
{
  int sw;

  if (p1 < 0 || p1 > 255 || p2 < 0 || p2 > 255 || !data || !datalen)
    return gpg_error (GPG_ERR_INV_VALUE);

  sw = apdu_send_simple (slot, 0x00, CMD_MSE, p1, p2, datalen, data);
  return map_sw (sw);
}


/* Perform the security operation COMPUTE DIGITAL SIGANTURE.  On
   success 0 is returned and the data is availavle in a newly
   allocated buffer stored at RESULT with its length stored at
   RESULTLEN. */
gpg_error_t
iso7816_compute_ds (int slot, const unsigned char *data, size_t datalen,
                    unsigned char **result, size_t *resultlen)
{
  int sw;

  if (!data || !datalen || !result || !resultlen)
    return gpg_error (GPG_ERR_INV_VALUE);
  *result = NULL;
  *resultlen = 0;

  sw = apdu_send (slot, 0x00, CMD_PSO, 0x9E, 0x9A, datalen, data,
                  result, resultlen);
  if (sw != SW_SUCCESS)
    {
      /* Make sure that pending buffers are released. */
      xfree (*result);
      *result = NULL;
      *resultlen = 0;
      return map_sw (sw);
    }

  return 0;
}


/* Perform the security operation DECIPHER.  PADIND is the padding
   indicator to be used.  It should be 0 if no padding is required, a
   value of -1 suppresses the padding byte.  On success 0 is returned
   and the plaintext is available in a newly allocated buffer stored
   at RESULT with its length stored at RESULTLEN. */
gpg_error_t
iso7816_decipher (int slot, const unsigned char *data, size_t datalen,
                  int padind, unsigned char **result, size_t *resultlen)
{
  int sw;
  unsigned char *buf;

  if (!data || !datalen || !result || !resultlen)
    return gpg_error (GPG_ERR_INV_VALUE);
  *result = NULL;
  *resultlen = 0;

  if (padind >= 0)
    {
      /* We need to prepend the padding indicator. */
      buf = xtrymalloc (datalen + 1);
      if (!buf)
        return gpg_error (gpg_err_code_from_errno (errno));

      *buf = padind; /* Padding indicator. */
      memcpy (buf+1, data, datalen);
      sw = apdu_send (slot, 0x00, CMD_PSO, 0x80, 0x86, datalen+1, buf,
                      result, resultlen);
      xfree (buf);
    }
  else
    {
      sw = apdu_send (slot, 0x00, CMD_PSO, 0x80, 0x86, datalen, data,
                      result, resultlen);
    }
  if (sw != SW_SUCCESS)
    {
      /* Make sure that pending buffers are released. */
      xfree (*result);
      *result = NULL;
      *resultlen = 0;
      return map_sw (sw);
    }

  return 0;
}


gpg_error_t
iso7816_internal_authenticate (int slot,
                               const unsigned char *data, size_t datalen,
                               unsigned char **result, size_t *resultlen)
{
  int sw;

  if (!data || !datalen || !result || !resultlen)
    return gpg_error (GPG_ERR_INV_VALUE);
  *result = NULL;
  *resultlen = 0;

  sw = apdu_send (slot, 0x00, CMD_INTERNAL_AUTHENTICATE, 0, 0,
                  datalen, data,  result, resultlen);
  if (sw != SW_SUCCESS)
    {
      /* Make sure that pending buffers are released. */
      xfree (*result);
      *result = NULL;
      *resultlen = 0;
      return map_sw (sw);
    }

  return 0;
}


static gpg_error_t
do_generate_keypair (int slot, int readonly,
                  const unsigned char *data, size_t datalen,
                  unsigned char **result, size_t *resultlen)
{
  int sw;

  if (!data || !datalen || !result || !resultlen)
    return gpg_error (GPG_ERR_INV_VALUE);
  *result = NULL;
  *resultlen = 0;

  sw = apdu_send (slot, 0x00, CMD_GENERATE_KEYPAIR, readonly? 0x81:0x80, 0,
                  datalen, data,  result, resultlen);
  if (sw != SW_SUCCESS)
    {
      /* Make sure that pending buffers are released. */
      xfree (*result);
      *result = NULL;
      *resultlen = 0;
      return map_sw (sw);
    }

  return 0;
}


gpg_error_t
iso7816_generate_keypair (int slot,
                          const unsigned char *data, size_t datalen,
                          unsigned char **result, size_t *resultlen)
{
  return do_generate_keypair (slot, 0, data, datalen, result, resultlen);
}


gpg_error_t
iso7816_read_public_key (int slot,
                          const unsigned char *data, size_t datalen,
                          unsigned char **result, size_t *resultlen)
{
  return do_generate_keypair (slot, 1, data, datalen, result, resultlen);
}



gpg_error_t
iso7816_get_challenge (int slot, int length, unsigned char *buffer)
{
  int sw;
  unsigned char *result;
  size_t resultlen, n;

  if (!buffer || length < 1)
    return gpg_error (GPG_ERR_INV_VALUE);

  do
    {
      result = NULL;
      n = length > 254? 254 : length;
      sw = apdu_send_le (slot, 0x00, CMD_GET_CHALLENGE, 0, 0, -1, NULL,
                         n,
                         &result, &resultlen);
      if (sw != SW_SUCCESS)
        {
          /* Make sure that pending buffers are released. */
          xfree (result);
          return map_sw (sw);
        }
      if (resultlen > n)
        resultlen = n;
      memcpy (buffer, result, resultlen);
      buffer += resultlen;
      length -= resultlen;
      xfree (result);
    }
  while (length > 0);

  return 0;
}

/* Perform a READ BINARY command requesting a maximum of NMAX bytes
   from OFFSET.  With NMAX = 0 the entire file is read. The result is
   stored in a newly allocated buffer at the address passed by RESULT.
   Returns the length of this data at the address of RESULTLEN. */
gpg_error_t
iso7816_read_binary (int slot, size_t offset, size_t nmax,
                     unsigned char **result, size_t *resultlen)
{
  int sw;
  unsigned char *buffer;
  size_t bufferlen;
  int read_all = !nmax;
  size_t n;

  if (!result || !resultlen)
    return gpg_error (GPG_ERR_INV_VALUE);
  *result = NULL;
  *resultlen = 0;

  /* We can only encode 15 bits in p0,p1 to indicate an offset. Thus
     we check for this limit. */
  if (offset > 32767)
    return gpg_error (GPG_ERR_INV_VALUE);

  do
    {
      buffer = NULL;
      bufferlen = 0;
      /* Fixme: Either the ccid driver or the TCOS cards have problems
         with an Le of 0. */
      if (read_all || nmax > 254)
        n = 254;
      else
        n = nmax;
      sw = apdu_send_le (slot, 0x00, CMD_READ_BINARY,
                         ((offset>>8) & 0xff), (offset & 0xff) , -1, NULL,
                         n, &buffer, &bufferlen);

      if (sw != SW_SUCCESS && sw != SW_EOF_REACHED)
        {
          /* Make sure that pending buffers are released. */
          xfree (buffer);
          xfree (*result);
          *result = NULL;
          *resultlen = 0;
          return map_sw (sw);
        }
      if (*result) /* Need to extend the buffer. */
        {
          unsigned char *p = xtryrealloc (*result, *resultlen + bufferlen);
          if (!p)
            {
              gpg_error_t err = gpg_error_from_errno (errno);
              xfree (buffer);
              xfree (*result);
              *result = NULL;
              *resultlen = 0;
              return err;
            }
          *result = p;
          memcpy (*result + *resultlen, buffer, bufferlen);
          *resultlen += bufferlen;
          xfree (buffer);
          buffer = NULL;
        }
      else /* Transfer the buffer into our result. */
        {
          *result = buffer;
          *resultlen = bufferlen;
        }
      offset += bufferlen;
      if (offset > 32767)
        break; /* We simply truncate the result for too large
                  files. */
      if (nmax > bufferlen)
        nmax -= bufferlen;
      else
        nmax = 0;
    }
  while ((read_all && sw != SW_EOF_REACHED) || (!read_all && nmax));
  
  return 0;
}

/* Perform a READ RECORD command. RECNO gives the record number to
   read with 0 indicating the current record.  RECCOUNT must be 1 (not
   all cards support reading of more than one record).  SHORT_EF
   should be 0 to read the current EF or contain a short EF. The
   result is stored in a newly allocated buffer at the address passed
   by RESULT.  Returns the length of this data at the address of
   RESULTLEN. */
gpg_error_t
iso7816_read_record (int slot, int recno, int reccount, int short_ef,
                     unsigned char **result, size_t *resultlen)
{
  int sw;
  unsigned char *buffer;
  size_t bufferlen;

  if (!result || !resultlen)
    return gpg_error (GPG_ERR_INV_VALUE);
  *result = NULL;
  *resultlen = 0;

  /* We can only encode 15 bits in p0,p1 to indicate an offset. Thus
     we check for this limit. */
  if (recno < 0 || recno > 255 || reccount != 1
      || short_ef < 0 || short_ef > 254 )
    return gpg_error (GPG_ERR_INV_VALUE);

  buffer = NULL;
  bufferlen = 0;
  /* Fixme: Either the ccid driver of the TCOS cards have problems
     with an Le of 0. */
  sw = apdu_send_le (slot, 0x00, CMD_READ_RECORD,
                     recno, 
                     short_ef? short_ef : 0x04,
                     -1, NULL,
                     254, &buffer, &bufferlen);

  if (sw != SW_SUCCESS && sw != SW_EOF_REACHED)
    {
      /* Make sure that pending buffers are released. */
      xfree (buffer);
      xfree (*result);
      *result = NULL;
      *resultlen = 0;
      return map_sw (sw);
    }
  *result = buffer;
  *resultlen = bufferlen;
  
  return 0;
}

