/* card.c - SCdaemon card functions
 *	Copyright (C) 2002 Free Software Foundation, Inc.
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
#include <time.h>

#include <opensc-pkcs15.h>

#include "scdaemon.h"



struct card_ctx_s {
  int reader;   /* used reader */
  struct sc_context *ctx;
  struct sc_card *scard;
  struct sc_pkcs15_card *p15card; /* only if there is a pkcs15 application */
  
};

/* Map the SC error codes to the GNUPG ones */
static int
map_sc_err (int rc)
{
  switch (rc)
    {
    case 0: rc = 0; break;
    case SC_ERROR_CMD_TOO_SHORT:         rc = GNUPG_Card_Error; break;
    case SC_ERROR_CMD_TOO_LONG:          rc = GNUPG_Card_Error; break;
    case SC_ERROR_NOT_SUPPORTED:         rc = GNUPG_Not_Supported; break;
    case SC_ERROR_TRANSMIT_FAILED:       rc = GNUPG_Card_Error; break;
    case SC_ERROR_FILE_NOT_FOUND:        rc = GNUPG_Card_Error; break;
    case SC_ERROR_INVALID_ARGUMENTS:     rc = GNUPG_Card_Error; break;
    case SC_ERROR_PKCS15_APP_NOT_FOUND:  rc = GNUPG_No_PKCS15_App; break;
    case SC_ERROR_REQUIRED_PARAMETER_NOT_FOUND: rc = GNUPG_Card_Error; break;
    case SC_ERROR_OUT_OF_MEMORY:         rc = GNUPG_Out_Of_Core; break;
    case SC_ERROR_NO_READERS_FOUND:      rc = GNUPG_Card_Error; break;
    case SC_ERROR_OBJECT_NOT_VALID:      rc = GNUPG_Card_Error; break;
    case SC_ERROR_ILLEGAL_RESPONSE:      rc = GNUPG_Card_Error; break;
    case SC_ERROR_PIN_CODE_INCORRECT:    rc = GNUPG_Card_Error; break;
    case SC_ERROR_SECURITY_STATUS_NOT_SATISFIED: rc = GNUPG_Card_Error; break;
    case SC_ERROR_CONNECTING_TO_RES_MGR: rc = GNUPG_Card_Error; break;
    case SC_ERROR_INVALID_ASN1_OBJECT:   rc = GNUPG_Card_Error; break;
    case SC_ERROR_BUFFER_TOO_SMALL:      rc = GNUPG_Card_Error; break;
    case SC_ERROR_CARD_NOT_PRESENT:      rc = GNUPG_Card_Not_Present; break;
    case SC_ERROR_RESOURCE_MANAGER:      rc = GNUPG_Card_Error; break;
    case SC_ERROR_CARD_REMOVED:          rc = GNUPG_Card_Removed; break;
    case SC_ERROR_INVALID_PIN_LENGTH:    rc = GNUPG_Card_Error; break;
    case SC_ERROR_UNKNOWN_SMARTCARD:     rc = GNUPG_Card_Error; break;
    case SC_ERROR_UNKNOWN_REPLY:         rc = GNUPG_Card_Error; break;
    case SC_ERROR_OBJECT_NOT_FOUND:      rc = GNUPG_Card_Error; break;
    case SC_ERROR_CARD_RESET:            rc = GNUPG_Card_Reset; break;
    case SC_ERROR_ASN1_OBJECT_NOT_FOUND: rc = GNUPG_Card_Error; break;
    case SC_ERROR_ASN1_END_OF_CONTENTS:  rc = GNUPG_Card_Error; break;
    case SC_ERROR_TOO_MANY_OBJECTS:      rc = GNUPG_Card_Error; break;
    case SC_ERROR_INVALID_CARD:          rc = GNUPG_Invalid_Card; break;
    case SC_ERROR_WRONG_LENGTH:          rc = GNUPG_Card_Error; break;
    case SC_ERROR_RECORD_NOT_FOUND:      rc = GNUPG_Card_Error; break;
    case SC_ERROR_INTERNAL:              rc = GNUPG_Card_Error; break;
    default: rc = GNUPG_Card_Error; break;
    }
  return rc;
}


/* Create a new context for the card and figures out some basic
   information of the card.  Detects whether a PKCS_15 application is
   stored.

   Common errors: GNUPG_Card_Not_Present */
int
card_open (CARD *rcard)
{
  CARD card;
  int rc;

  card = xtrycalloc (1, sizeof *card);
  if (!card)
    return GNUPG_Out_Of_Core;
  card->reader = 0;
  
  rc = sc_establish_context (&card->ctx);
  if (rc)
    {
      log_error ("failed to establish SC context: %s\n", sc_strerror (rc));
      rc = map_sc_err (rc);
      goto leave;
    }
  if (card->reader >= card->ctx->reader_count)
    {
      log_error ("no card reader available\n");
      rc = GNUPG_Card_Error;
    }
  card->ctx->error_file = log_get_stream ();
  card->ctx->debug_file = log_get_stream ();
  if (sc_detect_card (card->ctx, card->reader) != 1)
    {
      rc = GNUPG_Card_Not_Present;
      goto leave;
    }

  rc = sc_connect_card (card->ctx, card->reader, &card->scard);
  if (rc)
    {
      log_error ("failed to connect card in reader %d: %s\n",
                 card->reader, sc_strerror (rc));
      rc = map_sc_err (rc);
      goto leave;
    }
  if (opt.verbose)
    log_info ("connected to card in reader %d using driver `%s'\n",
              card->reader, card->scard->driver->name);

  rc = sc_lock (card->scard);
  if (rc)
    {
      log_error ("can't lock card in reader %d: %s\n",
                 card->reader, sc_strerror (rc));
      rc = map_sc_err (rc);
      goto leave;
    }

  rc = sc_pkcs15_bind (card->scard, &card->p15card);
  if (rc == SC_ERROR_PKCS15_APP_NOT_FOUND)
    rc = 0; /* okay */
  else if (rc)
    {
      log_error ("binding of existing PKCS-15 failed in reader %d: %s\n",
                 card->reader, sc_strerror (rc));
      rc = map_sc_err (rc);
      goto leave;
    }
    
 leave:
  if (rc)
    card_close (card);
  else
    *rcard = card;
  return rc;
}


/* Close a card and release all resources */
void
card_close (CARD card)
{
  if (card)
    {
      if (card->p15card)
        {
          sc_pkcs15_unbind (card->p15card);
          card->p15card = NULL;
        }
      if (card->scard)
        {
          sc_unlock (card->scard);
          sc_disconnect_card (card->scard);
          card->scard = NULL;
	}
      if (card->ctx)
        {
          sc_destroy_context (card->ctx);
          card->ctx = NULL;
        }
      xfree (card);
    }      
}

/* Retrieve the serial number and the time of the last update of the
   card.  The serial number is returned as a malloced string (hex
   encoded) in SERIAL and the time of update is returned in STAMP.
   If no update time is available the returned value is 0.  The serial
   is mandatory for a PKCS_15 application and an error will be
   returned if this value is not availbale.  For non-PKCS-15 cards a
   serial number is constructed by other means. Caller must free
   SERIAL unless the fucntion returns an error. */
int 
card_get_serial_and_stamp (CARD card, char **serial, time_t *stamp)
{
  char *s;

  if (!card || !serial || !stamp)
    return GNUPG_Invalid_Value;

  *serial = NULL;
  *stamp = 0; /* not available */
  if (!card->p15card)
    { /* fixme: construct a serial number */
      /* We should lookup the iso 7812-1 and 8583-3 - argh ISO practice is
         suppressing innovation - IETF rules! */
      return GNUPG_No_PKCS15_App;
    }
  s = card->p15card->serial_number;
  if (!s || !hexdigitp (s) )
    return GNUPG_Invalid_Card; /* the serial number is mandatory */
  *serial = xstrdup (s);
  if (!*serial)
    return GNUPG_Out_Of_Core;
  return 0;
}
