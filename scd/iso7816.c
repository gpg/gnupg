/* iso7816.c - ISO 7816 commands
 *	Copyright (C) 2003 Free Software Foundation, Inc.
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

#include "scdaemon.h"
#include "iso7816.h"
#include "apdu.h"
#include "dynload.h"

#define CMD_SELECT_FILE 0xA4
#define CMD_VERIFY      0x20
#define CMD_CHANGE_REFERENCE_DATA 0x24
#define CMD_RESET_RETRY_COUNTER   0x2C
#define CMD_GET_DATA    0xCA
#define CMD_PUT_DATA    0xDA
#define CMD_PSO         0x2A
#define CMD_INTERNAL_AUTHENTICATE 0x88
#define CMD_GENERATE_KEYPAIR      0x47
#define CMD_GET_CHALLENGE         0x84

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
   for okay or GNUPG error code.  Note that ISO error codes are
   internally mapped. */
gpg_error_t
iso7816_select_application (int slot, const char *aid, size_t aidlen)
{
  int sw;

  sw = apdu_send_simple (slot, 0x00, CMD_SELECT_FILE, 4, 0, aidlen, aid);
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
    return out_of_core ();
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


/* Perform the security operation DECIPHER.  On
   success 0 is returned and the plaintext is available in a newly
   allocated buffer stored at RESULT with its length stored at
   RESULTLEN. */
gpg_error_t
iso7816_decipher (int slot, const unsigned char *data, size_t datalen,
                  unsigned char **result, size_t *resultlen)
{
  int sw;
  unsigned char *buf;

  if (!data || !datalen || !result || !resultlen)
    return gpg_error (GPG_ERR_INV_VALUE);
  *result = NULL;
  *resultlen = 0;

  /* We need to prepend the padding indicator. */
  buf = xtrymalloc (datalen + 1);
  if (!buf)
    return out_of_core ();
  *buf = 0; /* Padding indicator. */
  memcpy (buf+1, data, datalen);
  sw = apdu_send (slot, 0x00, CMD_PSO, 0x80, 0x86, datalen+1, buf,
                  result, resultlen);
  xfree (buf);
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
generate_keypair (int slot, int readonly,
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
  return generate_keypair (slot, 0, data, datalen, result, resultlen);
}


gpg_error_t
iso7816_read_public_key (int slot,
                          const unsigned char *data, size_t datalen,
                          unsigned char **result, size_t *resultlen)
{
  return generate_keypair (slot, 1, data, datalen, result, resultlen);
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
