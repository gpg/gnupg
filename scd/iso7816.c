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
#include <dlfcn.h>

#include "scdaemon.h"
#include "iso7816.h"
#include "apdu.h"

#define CMD_SELECT_FILE 0xA4
#define CMD_VERIFY      0x20
#define CMD_GET_DATA    0xCA
#define CMD_PUT_DATA    0xDA
#define CMD_PSO         0x2A
#define CMD_INTERNAL_AUTHENTICATE 0x88
#define CMD_GENERATE_KEYPAIR      0x47
#define CMD_GET_CHALLENGE         0x84

/* This function is specialized version of the SELECT FILE command.
   SLOT is the card and reader as created for example by
   apdu_open_reader (), AID is a buffer of size AIDLEN holding the
   requested application ID.  The function can't be used to enumerate
   AIDs and won't return the AID on success.  The return value is 0
   for okay or GNUPG error code.  Note that ISO error codes are
   internally mapped. */
int
iso7816_select_application (int slot, const char *aid, size_t aidlen)
{
  int sw;

  sw = apdu_send_simple (slot, 0x00, CMD_SELECT_FILE, 4, 0, aidlen, aid);
  if (sw == SW_SUCCESS)
    return 0;
  else
    return -1; /* Fixme: we need a real error code. */
}


/* Perform a VERIFY command on SLOT using the card holder verification
   vector CHVNO with a CHV of lenght CHVLEN.  Returns 0 on success. */
int
iso7816_verify (int slot, int chvno, const char *chv, size_t chvlen)
{
  int sw;

  sw = apdu_send_simple (slot, 0x00, CMD_VERIFY, 0, chvno, chvlen, chv);
  if (sw == SW_SUCCESS)
    return 0;
  else
    return -1; /* Fixme: we need a real error code. */
}

/* Perform a GET DATA command requesting TAG and storing the result in
   a newly allocated buffer at the address passed by RESULT.  Return
   the length of this data at the address of RESULTLEN. */
int
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
      return -1;  /* FIXME: Map error codes. */
    }

  return 0;
}


/* Perform a PUT DATA command on card in SLOT.  Write DATA of length
   DATALEN to TAG. */
int 
iso7816_put_data (int slot, int tag,
                  const unsigned char *data, size_t datalen)
{
  int sw;

  sw = apdu_send_simple (slot, 0x00, CMD_PUT_DATA,
                         ((tag >> 8) & 0xff), (tag & 0xff),
                         datalen, data);
  if (sw == SW_SUCCESS)
    return 0;
  else
    return -1; /* Fixme: we need a real error code. */
}


/* Perform the security operation COMPUTE DIGITAL SIGANTURE.  On
   success 0 is returned and the data is availavle in a newly
   allocated buffer stored at RESULT with its length stored at
   RESULTLEN. */
int
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
      return -1;  /* FIXME: Map error codes. */
    }

  return 0;
}


/* Perform the security operation DECIPHER.  On
   success 0 is returned and the plaintext is available in a newly
   allocated buffer stored at RESULT with its length stored at
   RESULTLEN. */
int
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
      return -1;  /* FIXME: Map error codes. */
    }

  return 0;
}


int
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
      return -1;  /* FIXME: Map error codes. */
    }

  return 0;
}


static int
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
      return -1;  /* FIXME: Map error codes. */
    }

  return 0;
}


int
iso7816_generate_keypair (int slot,
                          const unsigned char *data, size_t datalen,
                          unsigned char **result, size_t *resultlen)
{
  return generate_keypair (slot, 0, data, datalen, result, resultlen);
}


int
iso7816_read_public_key (int slot,
                          const unsigned char *data, size_t datalen,
                          unsigned char **result, size_t *resultlen)
{
  return generate_keypair (slot, 1, data, datalen, result, resultlen);
}



int
iso1816_get_challenge (int slot, int length, unsigned char *buffer)
{
  int sw;
  unsigned char *result;
  size_t resultlen;

  if (!buffer || length < 1)
    return gpg_error (GPG_ERR_INV_VALUE);

  do
    {
      result = NULL;
      sw = apdu_send_le (slot, 0x00, CMD_GET_CHALLENGE, 0, 0, -1, NULL,
                         length,
                         &result, &resultlen);
      if (sw != SW_SUCCESS)
        {
          /* Make sure that pending buffers are released. */
          xfree (result);
          return -1;  /* FIXME: Map error codes. */
        }
      if (resultlen > length)
        resultlen = length;
      memcpy (buffer, result, resultlen);
      buffer += resultlen;
      length -= length;
      xfree (result);
    }
  while (length > 0);

  return 0;
}



