/* apdu.c - ISO 7816 APDU functions and low level I/O
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
#include <assert.h>

#include "scdaemon.h"
#include "apdu.h"

#define HAVE_CTAPI 1

#define MAX_READER 4 /* Number of readers we support concurrently. */
#define CARD_CONNECT_TIMEOUT 30 /* Number of seconds to wait for
                                   insertion of the card. */



/* A global table to keep track of active readers. */
static struct {
  int used;            /* True if slot is used. */
  unsigned short port; /* port number0 = unused, 1 - dev/tty */
  int status;
  unsigned char atr[33];
  size_t atrlen;
} reader_table[MAX_READER];                          


/* ct API function pointer. */
static char (*CT_init) (unsigned short ctn, unsigned short Pn);
static char (*CT_data) (unsigned short ctn, unsigned char *dad,
                        unsigned char *sad, unsigned short lc,
                        unsigned char *cmd, unsigned short *lr,
                        unsigned char *rsp);
static char (*CT_close) (unsigned short ctn);





/* 
      Helper
 */
 

/* Find an unused reader slot for PORT and put it into the reader
   table.  Return -1 on error or the index into the reader table. */
static int 
new_reader_slot (int port)    
{
  int i, reader = -1;

  if (port < 0 || port > 0xffff)
    {
      log_error ("new_reader_slot: invalid port %d requested\n", port);
      return -1;
    }

  for (i=0; i < MAX_READER; i++)
    {
      if (reader_table[i].used && reader_table[i].port == port)
        {
          log_error ("new_reader_slot: requested port %d already in use\n",
                     reader);
          return -1; 
        }
      else if (!reader_table[i].used && reader == -1)
        reader = i;
    }
  if (reader == -1)
    {
      log_error ("new_reader_slot: out of slots\n");
      return -1;
    }
  reader_table[reader].used = 1;
  reader_table[reader].port = port;
  return reader;
}


static void
dump_reader_status (int reader)
{
  log_info ("reader %d: %s\n", reader,
            reader_table[reader].status == 1? "Processor ICC present" :
            reader_table[reader].status == 0? "Memory ICC present" :
                                              "ICC not present" );
 
  if (reader_table[reader].status != -1)
    {
      log_info ("reader %d: ATR=", reader);
      log_printhex ("", reader_table[reader].atr,
                    reader_table[reader].atrlen);
    }
}



#ifdef HAVE_CTAPI
/* 
       ct API Interface 
 */

static const char *
ct_error_string (int err)
{
  switch (err)
    {
    case 0: return "okay";
    case -1: return "invalid data";
    case -8: return "ct error";
    case -10: return "transmission error";
    case -11: return "memory allocation error";
    case -128: return "HTSI error";
    default: return "unknown CT-API error";
    }
}

/* Wait for the card in READER and activate it.  Return -1 on error or
   0 on success. */
static int
ct_activate_card (int reader)
{
  int rc, count;

  for (count = 0; count < CARD_CONNECT_TIMEOUT; count++)
    {
      unsigned char dad[1], sad[1], cmd[11], buf[256];
      unsigned short buflen;

      /* Check whether card has been inserted. */
      dad[0] = 1;     /* Destination address: CT. */    
      sad[0] = 2;     /* Source address: Host. */

      cmd[0] = 0x20;  /* Class byte. */
      cmd[1] = 0x13;  /* Request status. */
      cmd[2] = 0x00;  /* From kernel. */
      cmd[3] = 0x80;  /* Return card's DO. */
      cmd[4] = 0x00;

      buflen = DIM(buf);

      rc = CT_data (reader, dad, sad, 5, cmd, &buflen, buf);
      if (rc || buflen < 2 || buf[buflen-2] != 0x90)
        {
          log_error ("ct_activate_card: can't get status of reader %d: %s\n",
                     reader, ct_error_string (rc));
          return -1;
        }

      if (buf[0] == 0x05)
        { /* Connected, now activate the card. */           
          dad[0] = 1;    /* Destination address: CT. */    
          sad[0] = 2;    /* Source address: Host. */

          cmd[0] = 0x20;  /* Class byte. */
          cmd[1] = 0x12;  /* Request ICC. */
          cmd[2] = 0x01;  /* From first interface. */
          cmd[3] = 0x01;  /* Return card's ATR. */
          cmd[4] = 0x00;

          buflen = DIM(buf);

          rc = CT_data (reader, dad, sad, 5, cmd, &buflen, buf);
          if (rc || buflen < 2 || buf[buflen-2] != 0x90)
            {
              log_error ("ct_activate_card(%d): activation failed: %s\n",
                         reader, ct_error_string (rc));
              return -1;
            }

          /* Store the type and the ATR. */
          if (buflen - 2 > DIM (reader_table[0].atr))
            {
              log_error ("ct_activate_card(%d): ATR too long\n", reader);
              return -1;
            }

          reader_table[reader].status = buf[buflen - 1];
          memcpy (reader_table[reader].atr, buf, buflen - 2);
          reader_table[reader].atrlen = buflen - 2;
          return 0;
        }

      sleep (1); /* FIXME: we should use a more reliable timer. */
    }
 
  log_info ("ct_activate_card(%d): timeout waiting for card\n", reader);
  return -1;
}


/* Open a reader and return an internal handle for it.  PORT is a
   non-negative value with the port number of the reader. USB readers
   do habe port numbers starting at 32769. */
static int
open_ct_reader (int port)
{
  int rc, reader;

  reader = new_reader_slot (port);
  if (reader == -1)
    return reader;

  rc = CT_init (reader, (unsigned short)port);
  if (rc)
    {
      log_error ("apdu_open_ct_reader failed on port %d: %s\n",
                 port, ct_error_string (rc));
      reader_table[reader].used = 0;
      return -1;
    }

  rc = ct_activate_card (reader);
  if (rc)
    {
      reader_table[reader].used = 0;
      return -1;
    }

  dump_reader_status (reader);
  return reader;
}


/* Actuall send the APDU of length APDULEN to SLOT and return a
   maximum of *BUFLEN data in BUFFER, the actual retruned size will be
   set to BUFLEN.  Returns: CT API error code. */
static int
ct_send_apdu (int slot, unsigned char *apdu, size_t apdulen,
              unsigned char *buffer, size_t *buflen)
{
  int rc;
  unsigned char dad[1], sad[1];
  unsigned short ctbuflen;
  
  dad[0] = 0;     /* Destination address: Card. */    
  sad[0] = 2;     /* Source address: Host. */
  ctbuflen = *buflen;
  if (DBG_CARD_IO)
    log_printhex ("  CT_data:", apdu, apdulen);
  rc = CT_data (slot, dad, sad, apdulen, apdu, &ctbuflen, buffer);
  *buflen = ctbuflen;

  /* FIXME: map the errorcodes to GNUPG ones, so that they can be
     shared between CTAPI and PCSC. */
  return rc;
}


#endif /*HAVE_CTAPI*/


#ifdef HAVE_PCSC
/* 
       PC/SC Interface
 */


#endif /*HAVE_PCSC*/


/* 
       Driver Access
 */

/* Open the reader and return an internal slot number or -1 on
   error. */
int
apdu_open_reader (int port)
{
  static int ct_api_loaded;

  if (!ct_api_loaded)
    {
      void *handle;

      handle = dlopen ("libtowitoko.so", RTLD_LAZY);
      if (!handle)
        {
          log_error ("apdu_open_reader: failed to open driver: %s",
                     dlerror ());
          return -1;
        }
      CT_init = dlsym (handle, "CT_init");
      CT_data = dlsym (handle, "CT_data");
      CT_close = dlsym (handle, "CT_close");
      if (!CT_init || !CT_data || !CT_close)
        {
          log_error ("apdu_open_reader: invalid driver\n");
          dlclose (handle);
          return -1;
        }
      ct_api_loaded = 1;
    }
  return open_ct_reader (port);
}


unsigned char *
apdu_get_atr (int slot, size_t *atrlen)
{
  char *buf;

  if (slot < 0 || slot >= MAX_READER || !reader_table[slot].used )
    return NULL;
  
  buf = xtrymalloc (reader_table[slot].atrlen);
  if (!buf)
    return NULL;
  memcpy (buf, reader_table[slot].atr, reader_table[slot].atrlen);
  *atrlen = reader_table[slot].atrlen;
  return buf;
}
  
    
static const char *
error_string (int slot, int rc)
{
#ifdef HAVE_CTAPI
  return ct_error_string (rc);
#elif defined(HAVE_PCSC)
  return "?";
#else
  return "?";
#endif
}


/* Dispatcher for the actual send_apdu fucntion. */
static int
send_apdu (int slot, unsigned char *apdu, size_t apdulen,
           unsigned char *buffer, size_t *buflen)
{
#ifdef HAVE_CTAPI
  return ct_send_apdu (slot, apdu, apdulen, buffer, buflen);
#elif defined(HAVE_PCSC)
  return -1;
#else
  return -1;
#endif
}

/* Send an APDU to the card in SLOT.  The APDU is created from all
   given parameters: CLASS, INS, P0, P1, LC, DATA, LE.  A value of -1
   for LC won't sent this field and the data field; in this case DATA
   must also be passed as NULL.  The return value is the status word
   or -1 for an invalid SLOT or other non card related error.  If
   RETBUF is not NULL, it will receive an allocated buffer with the
   returned data.  The length of that data will be put into
   *RETBUFLEN.  The caller is reposnible for releasing the buffer even
   in case of errors.  */
int 
apdu_send_le(int slot, int class, int ins, int p0, int p1,
             int lc, const char *data, int le,
             unsigned char **retbuf, size_t *retbuflen)
{
  unsigned char result[256+10]; /* 10 extra in case of bugs in the driver. */
  size_t resultlen = 256;
  unsigned char apdu[5+256+1];
  size_t apdulen;
  int rc, sw;

  if (DBG_CARD_IO)
    log_debug ("send apdu: c=%02X i=%02X p0=%02X p1=%02X lc=%d le=%d\n",
               class, ins, p0, p1, lc, le);

  if (lc != -1 && (lc > 255 || lc < 0))
    return SW_WRONG_LENGTH; 
  if (le != -1 && (le > 256 || le < 1))
    return SW_WRONG_LENGTH; 
  if ((!data && lc != -1) || (data && lc == -1))
    return -1;

  apdulen = 0;
  apdu[apdulen++] = class;
  apdu[apdulen++] = ins;
  apdu[apdulen++] = p0;
  apdu[apdulen++] = p1;
  if (lc != -1)
    {
      apdu[apdulen++] = lc;
      memcpy (apdu+apdulen, data, lc);
      apdulen += lc;
    }
  if (le != -1)
    apdu[apdulen++] = le; /* Truncation is okay becuase 0 means 256. */
  assert (sizeof (apdu) >= apdulen);
  /* As safeguard don't pass any garbage from the stack to the driver. */
  memset (apdu+apdulen, 0, sizeof (apdu) - apdulen);
  rc = send_apdu (slot, apdu, apdulen, result, &resultlen);
  if (rc || resultlen < 2)
    {
      log_error ("apdu_send_simple(%d) failed: %s\n",
                 slot, error_string (slot, rc));
      return -1;
    }
  sw = (result[resultlen-2] << 8) | result[resultlen-1];
  /* store away the returned data but strip the statusword. */
  resultlen -= 2;
  if (DBG_CARD_IO)
    {
      log_debug (" response: sw=%04X  datalen=%d\n", sw, resultlen);
      if ( !retbuf && (sw == SW_SUCCESS || (sw & 0xff00) == SW_MORE_DATA))
        log_printhex ("     dump: ", result, resultlen);
    }

  if (sw == SW_SUCCESS)
    {
      if (retbuf)
        {
          *retbuf = xtrymalloc (resultlen? resultlen : 1);
          if (!*retbuf)
            return -1; /* fixme: this is actually out of core. */
          *retbuflen = resultlen;
          memcpy (*retbuf, result, resultlen);
        }
    }
  else if ((sw & 0xff00) == SW_MORE_DATA)
    {
      unsigned char *p = NULL, *tmp;
      size_t bufsize = 4096;

      /* It is likely that we need to return much more data, so we
         start off with a large buffer. */
      if (retbuf)
        {
          *retbuf = p = xtrymalloc (bufsize);
          if (!*retbuf)
            return -1; /* fixme: this is actually out of core. */
          assert (resultlen < bufsize);
          memcpy (p, result, resultlen);
          p += resultlen;
        }

      do
        {
          int len = (sw & 0x00ff);
          
          log_debug ("apdu_send_simple(%d): %d more bytes available\n",
                     slot, len);
          apdulen = 0;
          apdu[apdulen++] = class;
          apdu[apdulen++] = 0xC0;
          apdu[apdulen++] = 0;
          apdu[apdulen++] = 0;
          apdu[apdulen++] = 64; /* that is 256 bytes for Le */
          memset (apdu+apdulen, 0, sizeof (apdu) - apdulen);
          rc = send_apdu (slot, apdu, apdulen, result, &resultlen);
          if (rc || resultlen < 2)
            {
              log_error ("apdu_send_simple(%d) for get response failed: %s\n",
                         slot, error_string (slot, rc));
              return -1;
            }
          sw = (result[resultlen-2] << 8) | result[resultlen-1];
          resultlen -= 2;
          if (DBG_CARD_IO)
            {
              log_debug ("     more: sw=%04X  datalen=%d\n", sw, resultlen);
              if (!retbuf && (sw==SW_SUCCESS || (sw&0xff00)==SW_MORE_DATA))
                log_printhex ("     dump: ", result, resultlen);
            }

          if ((sw & 0xff00) == SW_MORE_DATA || sw == SW_SUCCESS)
            {
              if (retbuf)
                {
                  if (p - *retbuf + resultlen > bufsize)
                    {
                      bufsize += resultlen > 4096? resultlen: 4096;
                      tmp = xtryrealloc (*retbuf, bufsize);
                      if (!tmp)
                        return -1; /* fixme: actually this is out of core */
                      p = tmp + (p - *retbuf);
                      *retbuf = tmp;
                    }
                  memcpy (p, result, resultlen);
                  p += resultlen;
                }
            }
          else
            log_info ("apdu_send_simple(%d) "
                      "got unexpected status %04X from get response\n",
                      slot, sw);
        }
      while ((sw & 0xff00) == SW_MORE_DATA);
      
      if (retbuf)
        {
          *retbuflen = p - *retbuf;
          tmp = xtryrealloc (*retbuf, *retbuflen);
          if (tmp)
            *retbuf = tmp;
        }
    }
  if (DBG_CARD_IO && retbuf && sw == SW_SUCCESS)
    log_printhex ("      dump: ", *retbuf, *retbuflen);
 
  return sw;
}

/* Send an APDU to the card in SLOT.  The APDU is created from all
   given parameters: CLASS, INS, P0, P1, LC, DATA.  A value of -1 for
   LC won't sent this field and the data field; in this case DATA must
   also be passed as NULL. The return value is the status word or -1
   for an invalid SLOT or other non card related error.  If RETBUF is
   not NULL, it will receive an allocated buffer with the returned
   data.  The length of that data will be put into *RETBUFLEN.  The
   caller is reponsible for releasing the buffer even in case of
   errors.  */
int 
apdu_send(int slot, int class, int ins, int p0, int p1,
          int lc, const char *data, unsigned char **retbuf, size_t *retbuflen)
{
  return apdu_send_le (slot, class, ins, p0, p1, lc, data, 256, 
                       retbuf, retbuflen);
}

/* Send an APDU to the card in SLOT.  The APDU is created from all
   given parameters: CLASS, INS, P0, P1, LC, DATA.  A value of -1 for
   LC won't sent this field and the data field; in this case DATA must
   also be passed as NULL. The return value is the status word or -1
   for an invalid SLOT or other non card related error.  No data will be
   returned. */
int 
apdu_send_simple (int slot, int class, int ins, int p0, int p1,
                  int lc, const char *data)
{
  return apdu_send (slot, class, ins, p0, p1, lc, data, NULL, NULL);
}
