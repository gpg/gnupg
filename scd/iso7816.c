/* iso7816.c - ISO 7816 commands
 * Copyright (C) 2003, 2004, 2008, 2009 Free Software Foundation, Inc.
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
#include "../common/util.h"
#include "../common/i18n.h"
#else /* GNUPG_MAJOR_VERSION != 1 */
#include "scdaemon.h"
#endif /* GNUPG_MAJOR_VERSION != 1 */

#include "iso7816.h"
#include "apdu.h"


#define CMD_SELECT_FILE 0xA4
#define CMD_VERIFY                ISO7816_VERIFY
#define CMD_CHANGE_REFERENCE_DATA ISO7816_CHANGE_REFERENCE_DATA
#define CMD_RESET_RETRY_COUNTER   ISO7816_RESET_RETRY_COUNTER
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
    case SW_TERM_STATE:     ec = GPG_ERR_OBJ_TERM_STATE; break;
    case SW_WRONG_LENGTH:   ec = GPG_ERR_INV_VALUE; break;
    case SW_SM_NOT_SUP:     ec = GPG_ERR_NOT_SUPPORTED; break;
    case SW_CC_NOT_SUP:     ec = GPG_ERR_NOT_SUPPORTED; break;
    case SW_CHV_WRONG:      ec = GPG_ERR_BAD_PIN; break;
    case SW_CHV_BLOCKED:    ec = GPG_ERR_PIN_BLOCKED; break;
    case SW_USE_CONDITIONS: ec = GPG_ERR_USE_CONDITIONS; break;
    case SW_NOT_SUPPORTED:  ec = GPG_ERR_NOT_SUPPORTED; break;
    case SW_BAD_PARAMETER:  ec = GPG_ERR_INV_VALUE; break;
    case SW_FILE_NOT_FOUND: ec = GPG_ERR_ENOENT; break;
    case SW_RECORD_NOT_FOUND:ec= GPG_ERR_NOT_FOUND; break;
    case SW_REF_NOT_FOUND:  ec = GPG_ERR_NO_OBJ; break;
    case SW_BAD_P0_P1:      ec = GPG_ERR_INV_VALUE; break;
    case SW_EXACT_LENGTH:   ec = GPG_ERR_INV_VALUE; break;
    case SW_INS_NOT_SUP:    ec = GPG_ERR_CARD; break;
    case SW_CLA_NOT_SUP:    ec = GPG_ERR_CARD; break;
    case SW_SUCCESS:        ec = 0; break;

    case SW_HOST_OUT_OF_CORE: ec = GPG_ERR_ENOMEM; break;
    case SW_HOST_INV_VALUE:   ec = GPG_ERR_INV_VALUE; break;
    case SW_HOST_INCOMPLETE_CARD_RESPONSE: ec = GPG_ERR_CARD; break;
    case SW_HOST_NOT_SUPPORTED: ec = GPG_ERR_NOT_SUPPORTED; break;
    case SW_HOST_LOCKING_FAILED: ec = GPG_ERR_BUG; break;
    case SW_HOST_BUSY:           ec = GPG_ERR_EBUSY; break;
    case SW_HOST_NO_CARD:        ec = GPG_ERR_CARD_NOT_PRESENT; break;
    case SW_HOST_CARD_INACTIVE:  ec = GPG_ERR_CARD_RESET; break;
    case SW_HOST_CARD_IO_ERROR:  ec = GPG_ERR_EIO; break;
    case SW_HOST_GENERAL_ERROR:  ec = GPG_ERR_GENERAL; break;
    case SW_HOST_NO_READER:      ec = GPG_ERR_ENODEV; break;
    case SW_HOST_ABORTED:        ec = GPG_ERR_CANCELED; break;
    case SW_HOST_NO_PINPAD:      ec = GPG_ERR_NOT_SUPPORTED; break;

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

/* Map a status word from the APDU layer to a gpg-error code.  */
gpg_error_t
iso7816_map_sw (int sw)
{
  /* All APDU functions should return 0x9000 on success but for
     historical reasons of the implementation some return 0 to
     indicate success.  We allow for that here. */
  return sw? map_sw (sw) : 0;
}


/* This function is specialized version of the SELECT FILE command.
   SLOT is the card and reader as created for example by
   apdu_open_reader (), AID is a buffer of size AIDLEN holding the
   requested application ID.  The function can't be used to enumerate
   AIDs and won't return the AID on success.  The return value is 0
   for okay or a GPG error code.  Note that ISO error codes are
   internally mapped.  Bit 0 of FLAGS should be set if the card does
   not understand P2=0xC0. */
gpg_error_t
iso7816_select_application (int slot, const char *aid, size_t aidlen,
                            unsigned int flags)
{
  int sw;
  sw = apdu_send_simple (slot, 0, 0x00, CMD_SELECT_FILE, 4,
                         (flags&1)? 0 :0x0c, aidlen, aid);
  return map_sw (sw);
}


gpg_error_t
iso7816_select_file (int slot, int tag, int is_dir)
{
  int sw, p0, p1;
  unsigned char tagbuf[2];

  tagbuf[0] = (tag >> 8) & 0xff;
  tagbuf[1] = tag & 0xff;

  p0 = (tag == 0x3F00)? 0: is_dir? 1:2;
  p1 = 0x0c; /* No FC return. */
  sw = apdu_send_simple (slot, 0, 0x00, CMD_SELECT_FILE,
                         p0, p1, 2, (char*)tagbuf );
  return map_sw (sw);
}


/* Do a select file command with a direct path. */
gpg_error_t
iso7816_select_path (int slot, const unsigned short *path, size_t pathlen)
{
  int sw, p0, p1;
  unsigned char buffer[100];
  int buflen;

  if (pathlen/2 >= sizeof buffer)
    return gpg_error (GPG_ERR_TOO_LARGE);

  for (buflen = 0; pathlen; pathlen--, path++)
    {
      buffer[buflen++] = (*path >> 8);
      buffer[buflen++] = *path;
    }

  p0 = 0x08;
  p1 = 0x0c; /* No FC return. */
  sw = apdu_send_simple (slot, 0, 0x00, CMD_SELECT_FILE,
                         p0, p1, buflen, (char*)buffer );
  return map_sw (sw);
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

  sw = apdu_send (slot, 0, 0x80, 0xAA, list_dirs? 1:2, 0, -1, NULL,
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


/* This function sends an already formatted APDU to the card.  With
   HANDLE_MORE set to true a MORE DATA status will be handled
   internally.  The return value is a gpg error code (i.e. a mapped
   status word).  This is basically the same as apdu_send_direct but
   it maps the status word and does not return it in the result
   buffer.  */
gpg_error_t
iso7816_apdu_direct (int slot, const void *apdudata, size_t apdudatalen,
                     int handle_more,
                     unsigned char **result, size_t *resultlen)
{
  int sw;

  if (!result || !resultlen)
    return gpg_error (GPG_ERR_INV_VALUE);
  *result = NULL;
  *resultlen = 0;

  sw = apdu_send_direct (slot, 0, apdudata, apdudatalen, handle_more,
                         result, resultlen);
  if (!sw)
    {
      if (*resultlen < 2)
        sw = SW_HOST_GENERAL_ERROR;
      else
        {
          sw = ((*result)[*resultlen-2] << 8) | (*result)[*resultlen-1];
          (*resultlen)--;
          (*resultlen)--;
        }
    }
  if (sw != SW_SUCCESS)
    {
      /* Make sure that pending buffers are released. */
      xfree (*result);
      *result = NULL;
      *resultlen = 0;
    }
  return map_sw (sw);
}


/* Check whether the reader supports the ISO command code COMMAND on
   the pinpad.  Returns 0 on success.  */
gpg_error_t
iso7816_check_pinpad (int slot, int command, pininfo_t *pininfo)
{
  int sw;

  sw = apdu_check_pinpad (slot, command, pininfo);
  return iso7816_map_sw (sw);
}


/* Perform a VERIFY command on SLOT using the card holder verification
   vector CHVNO.  With PININFO non-NULL the pinpad of the reader will
   be used.  Returns 0 on success. */
gpg_error_t
iso7816_verify_kp (int slot, int chvno, pininfo_t *pininfo)
{
  int sw;

  sw = apdu_pinpad_verify (slot, 0x00, CMD_VERIFY, 0, chvno, pininfo);
  return map_sw (sw);
}

/* Perform a VERIFY command on SLOT using the card holder verification
   vector CHVNO with a CHV of length CHVLEN.  Returns 0 on success. */
gpg_error_t
iso7816_verify (int slot, int chvno, const char *chv, size_t chvlen)
{
  int sw;

  sw = apdu_send_simple (slot, 0, 0x00, CMD_VERIFY, 0, chvno, chvlen, chv);
  return map_sw (sw);
}

/* Perform a CHANGE_REFERENCE_DATA command on SLOT for the card holder
   verification vector CHVNO.  With PININFO non-NULL the pinpad of the
   reader will be used.  If IS_EXCHANGE is 0, a "change reference
   data" is done, otherwise an "exchange reference data".  */
gpg_error_t
iso7816_change_reference_data_kp (int slot, int chvno, int is_exchange,
                                  pininfo_t *pininfo)
{
  int sw;

  sw = apdu_pinpad_modify (slot, 0x00, CMD_CHANGE_REFERENCE_DATA,
			   is_exchange ? 1 : 0, chvno, pininfo);
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

  sw = apdu_send_simple (slot, 0, 0x00, CMD_CHANGE_REFERENCE_DATA,
                         oldchvlen? 0 : 1, chvno, oldchvlen+newchvlen, buf);
  xfree (buf);
  return map_sw (sw);

}


gpg_error_t
iso7816_reset_retry_counter_with_rc (int slot, int chvno,
                                     const char *data, size_t datalen)
{
  int sw;

  if (!data || !datalen )
    return gpg_error (GPG_ERR_INV_VALUE);

  sw = apdu_send_simple (slot, 0, 0x00, CMD_RESET_RETRY_COUNTER,
                         0, chvno, datalen, data);
  return map_sw (sw);
}


gpg_error_t
iso7816_reset_retry_counter (int slot, int chvno,
                             const char *newchv, size_t newchvlen)
{
  int sw;

  sw = apdu_send_simple (slot, 0, 0x00, CMD_RESET_RETRY_COUNTER,
                         2, chvno, newchvlen, newchv);
  return map_sw (sw);
}



/* Perform a GET DATA command requesting TAG and storing the result in
   a newly allocated buffer at the address passed by RESULT.  Return
   the length of this data at the address of RESULTLEN. */
gpg_error_t
iso7816_get_data (int slot, int extended_mode, int tag,
                  unsigned char **result, size_t *resultlen)
{
  int sw;
  int le;

  if (!result || !resultlen)
    return gpg_error (GPG_ERR_INV_VALUE);
  *result = NULL;
  *resultlen = 0;

  if (extended_mode > 0 && extended_mode < 256)
    le = 65534; /* Not 65535 in case it is used as some special flag.  */
  else if (extended_mode > 0)
    le = extended_mode;
  else
    le = 256;

  sw = apdu_send_le (slot, extended_mode, 0x00, CMD_GET_DATA,
                     ((tag >> 8) & 0xff), (tag & 0xff), -1, NULL, le,
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
   DATALEN to TAG.  EXTENDED_MODE controls whether extended length
   headers or command chaining is used instead of single length
   bytes. */
gpg_error_t
iso7816_put_data (int slot, int extended_mode, int tag,
                  const void *data, size_t datalen)
{
  int sw;

  sw = apdu_send_simple (slot, extended_mode, 0x00, CMD_PUT_DATA,
                         ((tag >> 8) & 0xff), (tag & 0xff),
                         datalen, (const char*)data);
  return map_sw (sw);
}

/* Same as iso7816_put_data but uses an odd instruction byte.  */
gpg_error_t
iso7816_put_data_odd (int slot, int extended_mode, int tag,
                      const void *data, size_t datalen)
{
  int sw;

  sw = apdu_send_simple (slot, extended_mode, 0x00, CMD_PUT_DATA+1,
                         ((tag >> 8) & 0xff), (tag & 0xff),
                         datalen, (const char*)data);
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

  if (p1 < 0 || p1 > 255 || p2 < 0 || p2 > 255 )
    return gpg_error (GPG_ERR_INV_VALUE);

  sw = apdu_send_simple (slot, 0, 0x00, CMD_MSE, p1, p2,
                         data? datalen : -1, (const char*)data);
  return map_sw (sw);
}


/* Perform the security operation COMPUTE DIGITAL SIGANTURE.  On
   success 0 is returned and the data is availavle in a newly
   allocated buffer stored at RESULT with its length stored at
   RESULTLEN.  For LE see do_generate_keypair. */
gpg_error_t
iso7816_compute_ds (int slot, int extended_mode,
                    const unsigned char *data, size_t datalen, int le,
                    unsigned char **result, size_t *resultlen)
{
  int sw;

  if (!data || !datalen || !result || !resultlen)
    return gpg_error (GPG_ERR_INV_VALUE);
  *result = NULL;
  *resultlen = 0;

  if (!extended_mode)
    le = 256;  /* Ignore provided Le and use what apdu_send uses. */
  else if (le >= 0 && le < 256)
    le = 256;

  sw = apdu_send_le (slot, extended_mode,
                     0x00, CMD_PSO, 0x9E, 0x9A,
                     datalen, (const char*)data,
                     le,
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
   at RESULT with its length stored at RESULTLEN.  For LE see
   do_generate_keypair. */
gpg_error_t
iso7816_decipher (int slot, int extended_mode,
                  const unsigned char *data, size_t datalen, int le,
                  int padind, unsigned char **result, size_t *resultlen)
{
  int sw;
  unsigned char *buf;

  if (!data || !datalen || !result || !resultlen)
    return gpg_error (GPG_ERR_INV_VALUE);
  *result = NULL;
  *resultlen = 0;

  if (!extended_mode)
    le = 256;  /* Ignore provided Le and use what apdu_send uses. */
  else if (le >= 0 && le < 256)
    le = 256;

  if (padind >= 0)
    {
      /* We need to prepend the padding indicator. */
      buf = xtrymalloc (datalen + 1);
      if (!buf)
        return gpg_error (gpg_err_code_from_errno (errno));

      *buf = padind; /* Padding indicator. */
      memcpy (buf+1, data, datalen);
      sw = apdu_send_le (slot, extended_mode,
                         0x00, CMD_PSO, 0x80, 0x86,
                         datalen+1, (char*)buf, le,
                         result, resultlen);
      xfree (buf);
    }
  else
    {
      sw = apdu_send_le (slot, extended_mode,
                         0x00, CMD_PSO, 0x80, 0x86,
                         datalen, (const char *)data, le,
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


/*  For LE see do_generate_keypair.  */
gpg_error_t
iso7816_internal_authenticate (int slot, int extended_mode,
                               const unsigned char *data, size_t datalen,
                               int le,
                               unsigned char **result, size_t *resultlen)
{
  int sw;

  if (!data || !datalen || !result || !resultlen)
    return gpg_error (GPG_ERR_INV_VALUE);
  *result = NULL;
  *resultlen = 0;

  if (!extended_mode)
    le = 256;  /* Ignore provided Le and use what apdu_send uses. */
  else if (le >= 0 && le < 256)
    le = 256;

  sw = apdu_send_le (slot, extended_mode,
                     0x00, CMD_INTERNAL_AUTHENTICATE, 0, 0,
                     datalen, (const char*)data,
                     le,
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


/* LE is the expected return length.  This is usually 0 except if
   extended length mode is used and more than 256 byte will be
   returned.  In that case a value of -1 uses a large default
   (e.g. 4096 bytes), a value larger 256 used that value.  */
static gpg_error_t
do_generate_keypair (int slot, int extended_mode, int read_only,
                     const char *data, size_t datalen, int le,
                     unsigned char **result, size_t *resultlen)
{
  int sw;

  if (!data || !datalen || !result || !resultlen)
    return gpg_error (GPG_ERR_INV_VALUE);
  *result = NULL;
  *resultlen = 0;

  sw = apdu_send_le (slot, extended_mode,
                     0x00, CMD_GENERATE_KEYPAIR, read_only? 0x81:0x80, 0,
                     datalen, data,
                     le >= 0 && le < 256? 256:le,
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


gpg_error_t
iso7816_generate_keypair (int slot, int extended_mode,
                          const char *data, size_t datalen,
                          int le,
                          unsigned char **result, size_t *resultlen)
{
  return do_generate_keypair (slot, extended_mode, 0,
                              data, datalen, le, result, resultlen);
}


gpg_error_t
iso7816_read_public_key (int slot, int extended_mode,
                         const char *data, size_t datalen,
                         int le,
                         unsigned char **result, size_t *resultlen)
{
  return do_generate_keypair (slot, extended_mode, 1,
                              data, datalen, le, result, resultlen);
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
      sw = apdu_send_le (slot, 0,
                         0x00, CMD_GET_CHALLENGE, 0, 0, -1, NULL, n,
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
      n = read_all? 0 : nmax;
      sw = apdu_send_le (slot, 0, 0x00, CMD_READ_BINARY,
                         ((offset>>8) & 0xff), (offset & 0xff) , -1, NULL,
                         n, &buffer, &bufferlen);
      if ( SW_EXACT_LENGTH_P(sw) )
        {
          n = (sw & 0x00ff);
          sw = apdu_send_le (slot, 0, 0x00, CMD_READ_BINARY,
                             ((offset>>8) & 0xff), (offset & 0xff) , -1, NULL,
                             n, &buffer, &bufferlen);
        }

      if (*result && sw == SW_BAD_P0_P1)
        {
          /* Bad Parameter means that the offset is outside of the
             EF. When reading all data we take this as an indication
             for EOF.  */
          break;
        }

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
              gpg_error_t err = gpg_error_from_syserror ();
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
  sw = apdu_send_le (slot, 0, 0x00, CMD_READ_RECORD,
                     recno,
                     short_ef? short_ef : 0x04,
                     -1, NULL,
                     0, &buffer, &bufferlen);

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
