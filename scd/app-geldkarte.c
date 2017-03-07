/* app-geldkarte.c - The German Geldkarte application
 * Copyright (C) 2004 g10 Code GmbH
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


/* This is a read-only application to quickly dump information of a
   German Geldkarte (debit card for small amounts).  We only support
   newer Geldkarte (with the AID DF_BOERSE_NEU) issued since 2000 or
   even earlier.
*/


#include <config.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <time.h>
#include <ctype.h>

#include "scdaemon.h"

#include "../common/i18n.h"
#include "iso7816.h"
#include "app-common.h"
#include "../common/tlv.h"



/* Object with application (i.e. Geldkarte) specific data.  */
struct app_local_s
{
  char kblz[2+1+4+1];
  const char *banktype;
  char *cardno;
  char expires[7+1];
  char validfrom[10+1];
  char *country;
  char currency[3+1];
  unsigned int currency_mult100;
  unsigned char chipid;
  unsigned char osvers;
  int balance;
  int maxamount;
  int maxamount1;
};




/* Deconstructor. */
static void
do_deinit (app_t app)
{
  if (app && app->app_local)
    {
      xfree (app->app_local->cardno);
      xfree (app->app_local->country);
      xfree (app->app_local);
      app->app_local = NULL;
    }
}


static gpg_error_t
send_one_string (ctrl_t ctrl, const char *name, const char *string)
{
  if (!name || !string)
    return 0;
  send_status_info (ctrl, name, string, strlen (string), NULL, 0);
  return 0;
}

/* Implement the GETATTR command.  This is similar to the LEARN
   command but returns just one value via the status interface. */
static gpg_error_t
do_getattr (app_t app, ctrl_t ctrl, const char *name)
{
  gpg_error_t err;
  struct app_local_s *ld = app->app_local;
  char numbuf[100];

  if (!strcmp (name, "X-KBLZ"))
    err = send_one_string (ctrl, name, ld->kblz);
  else if (!strcmp (name, "X-BANKINFO"))
    err = send_one_string (ctrl, name, ld->banktype);
  else if (!strcmp (name, "X-CARDNO"))
    err = send_one_string (ctrl, name, ld->cardno);
  else if (!strcmp (name, "X-EXPIRES"))
    err = send_one_string (ctrl, name, ld->expires);
  else if (!strcmp (name, "X-VALIDFROM"))
    err = send_one_string (ctrl, name, ld->validfrom);
  else if (!strcmp (name, "X-COUNTRY"))
    err = send_one_string (ctrl, name, ld->country);
  else if (!strcmp (name, "X-CURRENCY"))
    err = send_one_string (ctrl, name, ld->currency);
  else if (!strcmp (name, "X-ZKACHIPID"))
    {
      snprintf (numbuf, sizeof numbuf, "0x%02X", ld->chipid);
      err = send_one_string (ctrl, name, numbuf);
    }
  else if (!strcmp (name, "X-OSVERSION"))
    {
      snprintf (numbuf, sizeof numbuf, "0x%02X", ld->osvers);
      err = send_one_string (ctrl, name, numbuf);
    }
  else if (!strcmp (name, "X-BALANCE"))
    {
      snprintf (numbuf, sizeof numbuf, "%.2f",
                (double)ld->balance / 100 * ld->currency_mult100);
      err = send_one_string (ctrl, name, numbuf);
    }
  else if (!strcmp (name, "X-MAXAMOUNT"))
    {
      snprintf (numbuf, sizeof numbuf, "%.2f",
                (double)ld->maxamount / 100 * ld->currency_mult100);
      err = send_one_string (ctrl, name, numbuf);
    }
  else if (!strcmp (name, "X-MAXAMOUNT1"))
    {
      snprintf (numbuf, sizeof numbuf, "%.2f",
                (double)ld->maxamount1 / 100 * ld->currency_mult100);
      err = send_one_string (ctrl, name, numbuf);
    }
  else
    err = gpg_error (GPG_ERR_INV_NAME);

  return err;
}


static gpg_error_t
do_learn_status (app_t app, ctrl_t ctrl, unsigned int flags)
{
  static const char *names[] = {
    "X-KBLZ",
    "X-BANKINFO",
    "X-CARDNO",
    "X-EXPIRES",
    "X-VALIDFROM",
    "X-COUNTRY",
    "X-CURRENCY",
    "X-ZKACHIPID",
    "X-OSVERSION",
    "X-BALANCE",
    "X-MAXAMOUNT",
    "X-MAXAMOUNT1",
    NULL
  };
  gpg_error_t err = 0;
  int idx;

  (void)flags;

  for (idx=0; names[idx] && !err; idx++)
    err = do_getattr (app, ctrl, names[idx]);
  return err;
}


static char *
copy_bcd (const unsigned char *string, size_t length)
{
  const unsigned char *s;
  size_t n;
  size_t needed;
  char *buffer, *dst;

  if (!length)
    return xtrystrdup ("");

  /* Skip leading zeroes. */
  for (; length && !*string; length--, string++)
    ;
  s = string;
  n = length;
  needed = 0;
  for (; n ; n--, s++)
    {
      if (!needed && !(*s & 0xf0))
        ; /* Skip the leading zero in the first nibble.  */
      else
        {
          if ( ((*s >> 4) & 0x0f) > 9 )
            {
              errno = EINVAL;
              return NULL;
            }
          needed++;
        }
      if ( n == 1 && (*s & 0x0f) > 9 )
        ; /* Ignore the last digit if it has the sign.  */
      else
        {
          needed++;
          if ( (*s & 0x0f) > 9 )
            {
              errno = EINVAL;
              return NULL;
            }
        }

    }
  if (!needed) /* If it is all zero, print a "0". */
    needed++;

  buffer = dst = xtrymalloc (needed+1);
  if (!buffer)
    return NULL;

  s = string;
  n = length;
  needed = 0;
  for (; n ; n--, s++)
    {
      if (!needed && !(*s & 0xf0))
        ; /* Skip the leading zero in the first nibble.  */
      else
        {
          *dst++ = '0' + ((*s >> 4) & 0x0f);
          needed++;
        }

      if ( n == 1 && (*s & 0x0f) > 9 )
        ; /* Ignore the last digit if it has the sign.  */
      else
        {
          *dst++ = '0' + (*s & 0x0f);
          needed++;
        }
    }
  if (!needed)
    *dst++ = '0';
  *dst = 0;

  return buffer;
}


/* Convert the BCD number at STING of LENGTH into an integer and store
   that at RESULT.  Return 0 on success.  */
static gpg_error_t
bcd_to_int (const unsigned char *string, size_t length, int *result)
{
  char *tmp;

  tmp = copy_bcd (string, length);
  if (!tmp)
    return gpg_error (GPG_ERR_BAD_DATA);
  *result = strtol (tmp, NULL, 10);
  xfree (tmp);
  return 0;
}


/* Select the Geldkarte application.  */
gpg_error_t
app_select_geldkarte (app_t app)
{
  static char const aid[] =
    { 0xD2, 0x76, 0x00, 0x00, 0x25, 0x45, 0x50, 0x02, 0x00 };
  gpg_error_t err;
  int slot = app->slot;
  unsigned char *result = NULL;
  size_t resultlen;
  struct app_local_s *ld;
  const char *banktype;

  err = iso7816_select_application (slot, aid, sizeof aid, 0);
  if (err)
    goto leave;

  /* Read the first record of EF_ID (SFI=0x17).  We require this
     record to be at least 24 bytes with the first byte 0x67 and a
     correct filler byte. */
  err = iso7816_read_record (slot, 1, 1, ((0x17 << 3)|4), &result, &resultlen);
  if (err)
    goto leave;  /* Oops - not a Geldkarte.  */
  if (resultlen < 24 || *result != 0x67 || result[22])
    {
      err = gpg_error (GPG_ERR_NOT_FOUND);
      goto leave;
    }

  /* The short Bankleitzahl consists of 3 bytes at offset 1.  */
  switch (result[1])
    {
    case 0x21: banktype = "Oeffentlich-rechtliche oder private Bank"; break;
    case 0x22: banktype = "Privat- oder Geschaeftsbank"; break;
    case 0x25: banktype = "Sparkasse"; break;
    case 0x26:
    case 0x29: banktype = "Genossenschaftsbank"; break;
    default:
      err = gpg_error (GPG_ERR_NOT_FOUND);
      goto leave; /* Probably not a Geldkarte. */
    }

  app->apptype = "GELDKARTE";
  app->fnc.deinit = do_deinit;

  /* If we don't have a serialno yet construct it from the EF_ID.  */
  if (!app->serialno)
    {
      app->serialno = xtrymalloc (10);
      if (!app->serialno)
        {
          err = gpg_error_from_syserror ();
          goto leave;
        }
      memcpy (app->serialno, result, 10);
      app->serialnolen = 10;
      err = app_munge_serialno (app);
      if (err)
        goto leave;
    }


  app->app_local = ld = xtrycalloc (1, sizeof *app->app_local);
  if (!app->app_local)
    {
      err = gpg_err_code_from_syserror ();
      goto leave;
    }

  snprintf (ld->kblz, sizeof ld->kblz, "%02X-%02X%02X",
            result[1], result[2], result[3]);
  ld->banktype = banktype;
  ld->cardno = copy_bcd (result+4, 5);
  if (!ld->cardno)
    {
      err = gpg_err_code_from_syserror ();
      goto leave;
    }

  snprintf (ld->expires, sizeof ld->expires, "20%02X-%02X",
            result[10], result[11]);
  snprintf (ld->validfrom, sizeof ld->validfrom, "20%02X-%02X-%02X",
            result[12], result[13], result[14]);

  ld->country = copy_bcd (result+15, 2);
  if (!ld->country)
    {
      err = gpg_err_code_from_syserror ();
      goto leave;
    }

  snprintf (ld->currency, sizeof ld->currency, "%c%c%c",
            isascii (result[17])? result[17]:' ',
            isascii (result[18])? result[18]:' ',
            isascii (result[19])? result[19]:' ');

  ld->currency_mult100 = (result[20] == 0x01? 1:
                          result[20] == 0x02? 10:
                          result[20] == 0x04? 100:
                          result[20] == 0x08? 1000:
                          result[20] == 0x10? 10000:
                          result[20] == 0x20? 100000:0);

  ld->chipid = result[21];
  ld->osvers = result[23];

  /* Read the first record of EF_BETRAG (SFI=0x18). */
  xfree (result);
  err = iso7816_read_record (slot, 1, 1, ((0x18 << 3)|4), &result, &resultlen);
  if (err)
    goto leave;  /* It does not make sense to continue.  */
  if (resultlen < 12)
    {
      err = gpg_error (GPG_ERR_NOT_FOUND);
      goto leave;
    }
  err = bcd_to_int (result+0, 3, &ld->balance);
  if (!err)
    err = bcd_to_int (result+3, 3, &ld->maxamount);
  if (!err)
    err = bcd_to_int (result+6, 3, &ld->maxamount1);
  /* The next 3 bytes are the maximum amount chargable without using a
     MAC.  This is usually 0.  */
  if (err)
    goto leave;

  /* Setup the rest of the methods.  */
  app->fnc.learn_status = do_learn_status;
  app->fnc.getattr = do_getattr;


 leave:
  xfree (result);
  if (err)
    do_deinit (app);
  return err;
}
