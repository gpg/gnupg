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
#include <assert.h>
#ifdef HAVE_OPENSC
# include <opensc/opensc.h>
#endif

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
#include "cardglue.h"
#else /* GNUPG_MAJOR_VERSION != 1 */
#include "scdaemon.h"
#endif /* GNUPG_MAJOR_VERSION != 1 */

#include "apdu.h"
#include "dynload.h"
#include "ccid-driver.h"

#define MAX_READER 4 /* Number of readers we support concurrently. */
#define CARD_CONNECT_TIMEOUT 1 /* Number of seconds to wait for
                                  insertion of the card (1 = don't wait). */


#ifdef _WIN32
#define DLSTDCALL __stdcall
#else
#define DLSTDCALL
#endif


/* A structure to collect information pertaining to one reader
   slot. */
struct reader_table_s {
  int used;            /* True if slot is used. */
  unsigned short port; /* Port number:  0 = unused, 1 - dev/tty */
  int is_ccid;         /* Uses the internal CCID driver. */
  struct {
    ccid_driver_t handle;
  } ccid;
  int is_ctapi;        /* This is a ctAPI driver. */
  struct {
    unsigned long context;
    unsigned long card;
    unsigned long protocol;
  } pcsc;
#ifdef HAVE_OPENSC
  int is_osc;          /* We are using the OpenSC driver layer. */
  struct {
    struct sc_context *ctx;
    struct sc_card *scard;
  } osc;
#endif /*HAVE_OPENSC*/
  int status;
  unsigned char atr[33];
  size_t atrlen;
};
typedef struct reader_table_s *reader_table_t;

/* A global table to keep track of active readers. */
static struct reader_table_s reader_table[MAX_READER];


/* ct API function pointer. */
static char (* DLSTDCALL CT_init) (unsigned short ctn, unsigned short Pn);
static char (* DLSTDCALL CT_data) (unsigned short ctn, unsigned char *dad,
                                   unsigned char *sad, unsigned short lc,
                                   unsigned char *cmd, unsigned short *lr,
                                   unsigned char *rsp);
static char (* DLSTDCALL CT_close) (unsigned short ctn);

/* PC/SC constants and function pointer. */
#define PCSC_SCOPE_USER      0 
#define PCSC_SCOPE_TERMINAL  1 
#define PCSC_SCOPE_SYSTEM    2 
#define PCSC_SCOPE_GLOBAL    3 

#define PCSC_PROTOCOL_T0     1 
#define PCSC_PROTOCOL_T1     2 
#define PCSC_PROTOCOL_RAW    4 

#define PCSC_SHARE_EXCLUSIVE 1
#define PCSC_SHARE_SHARED    2
#define PCSC_SHARE_DIRECT    3

#define PCSC_LEAVE_CARD      0
#define PCSC_RESET_CARD      1
#define PCSC_UNPOWER_CARD    2
#define PCSC_EJECT_CARD      3

struct pcsc_io_request_s {
  unsigned long protocol; 
  unsigned long pci_len;
};

typedef struct pcsc_io_request_s *pcsc_io_request_t;

long (* DLSTDCALL pcsc_establish_context) (unsigned long scope,
                                           const void *reserved1,
                                           const void *reserved2,
                                           unsigned long *r_context);
long (* DLSTDCALL pcsc_release_context) (unsigned long context);
long (* DLSTDCALL pcsc_list_readers) (unsigned long context,
                                      const char *groups,
                                      char *readers, unsigned long*readerslen);
long (* DLSTDCALL pcsc_connect) (unsigned long context,
                                 const char *reader,
                                 unsigned long share_mode,
                                 unsigned long preferred_protocols,
                                 unsigned long *r_card,
                                 unsigned long *r_active_protocol);
long (* DLSTDCALL pcsc_disconnect) (unsigned long card,
                                    unsigned long disposition);
long (* DLSTDCALL pcsc_status) (unsigned long card,
                                char *reader, unsigned long *readerlen,
                                unsigned long *r_state,
                                unsigned long *r_protocol,
                                unsigned char *atr, unsigned long *atrlen);
long (* DLSTDCALL pcsc_begin_transaction) (unsigned long card);
long (* DLSTDCALL pcsc_end_transaction) (unsigned long card);
long (* DLSTDCALL pcsc_transmit) (unsigned long card,
                                  const pcsc_io_request_t send_pci,
                                  const unsigned char *send_buffer,
                                  unsigned long send_len,
                                  pcsc_io_request_t recv_pci,
                                  unsigned char *recv_buffer,
                                  unsigned long *recv_len);
long (* DLSTDCALL pcsc_set_timeout) (unsigned long context,
                                     unsigned long timeout);





/* 
      Helper
 */
 

/* Find an unused reader slot for PORTSTR and put it into the reader
   table.  Return -1 on error or the index into the reader table. */
static int 
new_reader_slot (void)    
{
  int i, reader = -1;

  for (i=0; i < MAX_READER; i++)
    {
      if (!reader_table[i].used && reader == -1)
        reader = i;
    }
  if (reader == -1)
    {
      log_error ("new_reader_slot: out of slots\n");
      return -1;
    }
  reader_table[reader].used = 1;
  reader_table[reader].is_ccid = 0;
  reader_table[reader].is_ctapi = 0;
#ifdef HAVE_OPENSC
  reader_table[reader].is_osc = 0;
#endif
  return reader;
}


static void
dump_reader_status (int reader)
{
  if (reader_table[reader].is_ccid)
    log_info ("reader slot %d: using ccid driver\n", reader);
  else if (reader_table[reader].is_ctapi)
    {
      log_info ("reader slot %d: %s\n", reader,
                reader_table[reader].status == 1? "Processor ICC present" :
                reader_table[reader].status == 0? "Memory ICC present" :
                "ICC not present" );
    }
  else
    {
      log_info ("reader slot %d: active protocol:", reader);
      if ((reader_table[reader].pcsc.protocol & PCSC_PROTOCOL_T0))
        log_printf (" T0");
      else if ((reader_table[reader].pcsc.protocol & PCSC_PROTOCOL_T1))
        log_printf (" T1");
      else if ((reader_table[reader].pcsc.protocol & PCSC_PROTOCOL_RAW))
        log_printf (" raw");
      log_printf ("\n");
    }

  if (reader_table[reader].status != -1)
    {
      log_info ("reader %d: ATR=", reader);
      log_printhex ("", reader_table[reader].atr,
                    reader_table[reader].atrlen);
    }
}



/* 
       ct API Interface 
 */

static const char *
ct_error_string (long err)
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

      if (count)
        ; /* FIXME: we should use a more reliable timer than sleep. */

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

      /* Connected, now activate the card. */           
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
          if (!rc)
            log_printhex ("  received data:", buf, buflen);
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
 
  log_info ("ct_activate_card(%d): timeout waiting for card\n", reader);
  return -1;
}


/* Open a reader and return an internal handle for it.  PORT is a
   non-negative value with the port number of the reader. USB readers
   do have port numbers starting at 32769. */
static int
open_ct_reader (int port)
{
  int rc, reader;

  if (port < 0 || port > 0xffff)
    {
      log_error ("open_ct_reader: invalid port %d requested\n", port);
      return -1;
    }
  reader = new_reader_slot ();
  if (reader == -1)
    return reader;
  reader_table[reader].port = port;

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

  reader_table[reader].is_ctapi = 1;
  dump_reader_status (reader);
  return reader;
}

static int
close_ct_reader (int slot)
{
  CT_close (slot);
  reader_table[slot].used = 0;
  return 0;
}


/* Actually send the APDU of length APDULEN to SLOT and return a
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



static const char *
pcsc_error_string (long err)
{
  const char *s;

  if (!err)
    return "okay";
  if ((err & 0x80100000) != 0x80100000)
    return "invalid PC/SC error code";
  err &= 0xffff;
  switch (err)
    {
    case 0x0002: s = "cancelled"; break;
    case 0x000e: s = "can't dispose"; break;
    case 0x0008: s = "insufficient buffer"; break;   
    case 0x0015: s = "invalid ATR"; break;
    case 0x0003: s = "invalid handle"; break;
    case 0x0004: s = "invalid parameter"; break; 
    case 0x0005: s = "invalid target"; break;
    case 0x0011: s = "invalid value"; break; 
    case 0x0006: s = "no memory"; break;  
    case 0x0013: s = "comm error"; break;      
    case 0x0001: s = "internal error"; break;     
    case 0x0014: s = "unknown error"; break; 
    case 0x0007: s = "waited too long"; break;  
    case 0x0009: s = "unknown reader"; break;
    case 0x000a: s = "timeout"; break; 
    case 0x000b: s = "sharing violation"; break;       
    case 0x000c: s = "no smartcard"; break;
    case 0x000d: s = "unknown card"; break;   
    case 0x000f: s = "proto mismatch"; break;          
    case 0x0010: s = "not ready"; break;               
    case 0x0012: s = "system cancelled"; break;        
    case 0x0016: s = "not transacted"; break;
    case 0x0017: s = "reader unavailable"; break; 
    case 0x0065: s = "unsupported card"; break;        
    case 0x0066: s = "unresponsive card"; break;       
    case 0x0067: s = "unpowered card"; break;          
    case 0x0068: s = "reset card"; break;              
    case 0x0069: s = "removed card"; break;            
    case 0x006a: s = "inserted card"; break;           
    case 0x001f: s = "unsupported feature"; break;     
    case 0x0019: s = "PCI too small"; break;           
    case 0x001a: s = "reader unsupported"; break;      
    case 0x001b: s = "duplicate reader"; break;        
    case 0x001c: s = "card unsupported"; break;        
    case 0x001d: s = "no service"; break;              
    case 0x001e: s = "service stopped"; break;      
    default:     s = "unknown PC/SC error code"; break;
    }
  return s;
}

/* 
       PC/SC Interface
 */

static int
open_pcsc_reader (const char *portstr)
{
  long err;
  int slot;
  char *list = NULL;
  unsigned long nreader, listlen, atrlen;
  char *p;
  unsigned long card_state, card_protocol;

  slot = new_reader_slot ();
  if (slot == -1)
    return -1;

  err = pcsc_establish_context (PCSC_SCOPE_SYSTEM, NULL, NULL,
                                &reader_table[slot].pcsc.context);
  if (err)
    {
      log_error ("pcsc_establish_context failed: %s (0x%lx)\n",
                 pcsc_error_string (err), err);
      reader_table[slot].used = 0;
      return -1;
    }
  
  err = pcsc_list_readers (reader_table[slot].pcsc.context,
                           NULL, NULL, &nreader);
  if (!err)
    {
      list = xtrymalloc (nreader+1); /* Better add 1 for safety reasons. */
      if (!list)
        {
          log_error ("error allocating memory for reader list\n");
          pcsc_release_context (reader_table[slot].pcsc.context);
          reader_table[slot].used = 0;
          return -1;
        }
      err = pcsc_list_readers (reader_table[slot].pcsc.context,
                               NULL, list, &nreader);
    }
  if (err)
    {
      log_error ("pcsc_list_readers failed: %s (0x%lx)\n",
                 pcsc_error_string (err), err);
      pcsc_release_context (reader_table[slot].pcsc.context);
      reader_table[slot].used = 0;
      xfree (list);
      return -1;
    }

  listlen = nreader;
  p = list;
  while (nreader)
    {
      if (!*p && !p[1])
        break;
      log_info ("detected reader `%s'\n", p);
      if (nreader < (strlen (p)+1))
        {
          log_error ("invalid response from pcsc_list_readers\n");
          break;
        }
      nreader -= strlen (p)+1;
      p += strlen (p) + 1;
    }

  err = pcsc_connect (reader_table[slot].pcsc.context,
                      portstr? portstr : list,
                      PCSC_SHARE_EXCLUSIVE,
                      PCSC_PROTOCOL_T0|PCSC_PROTOCOL_T1,
                      &reader_table[slot].pcsc.card,
                      &reader_table[slot].pcsc.protocol);
  if (err)
    {
      log_error ("pcsc_connect failed: %s (0x%lx)\n",
                  pcsc_error_string (err), err);
      pcsc_release_context (reader_table[slot].pcsc.context);
      reader_table[slot].used = 0;
      xfree (list);
      return -1;
    }      
  
  atrlen = 32;
  /* (We need to pass a dummy buffer.  We use LIST because it ought to
     be large enough.) */
  err = pcsc_status (reader_table[slot].pcsc.card,
                     list, &listlen,
                     &card_state, &card_protocol,
                     reader_table[slot].atr, &atrlen);
  xfree (list);
  if (err)
    {
      log_error ("pcsc_status failed: %s (0x%lx)\n",
                  pcsc_error_string (err), err);
      pcsc_release_context (reader_table[slot].pcsc.context);
      reader_table[slot].used = 0;
      return -1;
    }
  if (atrlen >= DIM (reader_table[0].atr))
    log_bug ("ATR returned by pcsc_status is too large\n");
  reader_table[slot].atrlen = atrlen;
/*   log_debug ("state    from pcsc_status: 0x%lx\n", card_state); */
/*   log_debug ("protocol from pcsc_status: 0x%lx\n", card_protocol); */

  dump_reader_status (slot); 
  return slot;
}


/* Actually send the APDU of length APDULEN to SLOT and return a
   maximum of *BUFLEN data in BUFFER, the actual returned size will be
   set to BUFLEN.  Returns: CT API error code. */
static int
pcsc_send_apdu (int slot, unsigned char *apdu, size_t apdulen,
                unsigned char *buffer, size_t *buflen)
{
  long err;
  struct pcsc_io_request_s send_pci;
  unsigned long recv_len;
  
  if (DBG_CARD_IO)
    log_printhex ("  PCSC_data:", apdu, apdulen);

  if ((reader_table[slot].pcsc.protocol & PCSC_PROTOCOL_T1))
      send_pci.protocol = PCSC_PROTOCOL_T1;
  else
      send_pci.protocol = PCSC_PROTOCOL_T0;
  send_pci.pci_len = sizeof send_pci;
  recv_len = *buflen;
  err = pcsc_transmit (reader_table[slot].pcsc.card,
                       &send_pci, apdu, apdulen,
                       NULL, buffer, &recv_len);
  *buflen = recv_len;
  if (err)
    log_error ("pcsc_transmit failed: %s (0x%lx)\n",
               pcsc_error_string (err), err);
  
  return err? -1:0; /* FIXME: Return appropriate error code. */
}

static int
close_pcsc_reader (int slot)
{
  pcsc_release_context (reader_table[slot].pcsc.context);
  reader_table[slot].used = 0;
  return 0;
}





#ifdef HAVE_LIBUSB
/* 
     Internal CCID driver interface.
 */

static const char *
get_ccid_error_string (long err)
{
  if (!err)
    return "okay";
  else
    return "unknown CCID error";
}

static int
open_ccid_reader (void)
{
  int err;
  int slot;
  reader_table_t slotp;

  slot = new_reader_slot ();
  if (slot == -1)
    return -1;
  slotp = reader_table + slot;

  err = ccid_open_reader (&slotp->ccid.handle, 0);
  if (err)
    {
      slotp->used = 0;
      return -1;
    }

  err = ccid_get_atr (slotp->ccid.handle,
                      slotp->atr, sizeof slotp->atr, &slotp->atrlen);
  if (err)
    {
      slotp->used = 0;
      return -1;
    }

  slotp->is_ccid = 1;

  dump_reader_status (slot); 
  return slot;
}

static int
close_ccid_reader (int slot)
{
  ccid_close_reader (reader_table[slot].ccid.handle);
  reader_table[slot].used = 0;
  return 0;
}                       
  


/* Actually send the APDU of length APDULEN to SLOT and return a
   maximum of *BUFLEN data in BUFFER, the actual returned size will be
   set to BUFLEN.  Returns: Internal CCID driver error code. */
static int
send_apdu_ccid (int slot, unsigned char *apdu, size_t apdulen,
                unsigned char *buffer, size_t *buflen)
{
  long err;
  size_t maxbuflen;

  if (DBG_CARD_IO)
    log_printhex ("  APDU_data:", apdu, apdulen);

  maxbuflen = *buflen;
  err = ccid_transceive (reader_table[slot].ccid.handle,
                         apdu, apdulen,
                         buffer, maxbuflen, buflen);
  if (err)
    log_error ("ccid_transceive failed: (0x%lx)\n",
               err);
  
  return err? -1:0; /* FIXME: Return appropriate error code. */
}

#endif /* HAVE_LIBUSB */



#ifdef HAVE_OPENSC
/* 
     OpenSC Interface.

     This uses the OpenSC primitives to send APDUs.  We need this
     because we can't mix OpenSC and native (i.e. ctAPI or PC/SC)
     access to a card for resource conflict reasons.
 */

static int
open_osc_reader (int portno)
{
  int err;
  int slot;
  reader_table_t slotp;

  slot = new_reader_slot ();
  if (slot == -1)
    return -1;
  slotp = reader_table + slot;

  err = sc_establish_context (&slotp->osc.ctx, "scdaemon");
  if (err)
    {
      log_error ("failed to establish SC context: %s\n", sc_strerror (err));
      slotp->used = 0;
      return -1;
    }
  if (portno < 0 || portno >= slotp->osc.ctx->reader_count)
    {
      log_error ("no card reader available\n");
      sc_release_context (slotp->osc.ctx);
      slotp->used = 0;
      return -1;
    }

  /* Redirect to our logging facility. */
  slotp->osc.ctx->error_file = log_get_stream ();
  slotp->osc.ctx->debug = opt.debug_sc;
  slotp->osc.ctx->debug_file = log_get_stream ();

  if (sc_detect_card_presence (slotp->osc.ctx->reader[portno], 0) != 1)
    {
      log_error ("no card present\n");
      sc_release_context (slotp->osc.ctx);
      slotp->used = 0;
      return -1;
    }
  
  /* We want the standard ISO driver. */
  /*FIXME: OpenSC does not like "iso7816", so we use EMV for now. */
  err = sc_set_card_driver(slotp->osc.ctx, "emv");
  if (err)
    {
      log_error ("failed to select the iso7816 driver: %s\n",
                 sc_strerror (err));
      sc_release_context (slotp->osc.ctx);
      slotp->used = 0;
      return -1;
    }

  /* Now connect the card and hope that OpenSC won't try to be too
     smart. */
  err = sc_connect_card (slotp->osc.ctx->reader[portno], 0,
                         &slotp->osc.scard);
  if (err)
    {
      log_error ("failed to connect card in reader %d: %s\n",
                 portno, sc_strerror (err));
      sc_release_context (slotp->osc.ctx);
      slotp->used = 0;
      return -1;
    }
  if (opt.verbose)
    log_info ("connected to card in opensc reader %d using driver `%s'\n",
              portno, slotp->osc.scard->driver->name);

  err = sc_lock (slotp->osc.scard);
  if (err)
    {
      log_error ("can't lock card in reader %d: %s\n",
                 portno, sc_strerror (err));
      sc_disconnect_card (slotp->osc.scard, 0);
      sc_release_context (slotp->osc.ctx);
      slotp->used = 0;
      return -1;
    }

  if (slotp->osc.scard->atr_len >= DIM (slotp->atr))
    log_bug ("ATR returned by opensc is too large\n");
  slotp->atrlen = slotp->osc.scard->atr_len;
  memcpy (slotp->atr, slotp->osc.scard->atr, slotp->atrlen);

  slotp->is_osc = 1;

  dump_reader_status (slot); 
  return slot;
}


static int
close_osc_reader (int slot)
{
  /* FIXME: Implement. */
  reader_table[slot].used = 0;
  return 0;
}



/* Actually send the APDU of length APDULEN to SLOT and return a
   maximum of *BUFLEN data in BUFFER, the actual returned size will be
   set to BUFLEN.  Returns: OpenSC error code. */
static int
osc_send_apdu (int slot, unsigned char *apdu, size_t apdulen,
                unsigned char *buffer, size_t *buflen)
{
  long err;
  struct sc_apdu a;
  unsigned char data[SC_MAX_APDU_BUFFER_SIZE];
  unsigned char result[SC_MAX_APDU_BUFFER_SIZE];

  if (DBG_CARD_IO)
    log_printhex ("  APDU_data:", apdu, apdulen);

  if (apdulen < 4)
    {
      log_error ("osc_send_apdu: APDU is too short\n");
      return SC_ERROR_CMD_TOO_SHORT;
    }

  memset(&a, 0, sizeof a);
  a.cla = *apdu++;
  a.ins = *apdu++;
  a.p1 = *apdu++;
  a.p2 = *apdu++;
  apdulen -= 4;

  if (!apdulen)
    a.cse = SC_APDU_CASE_1;
  else if (apdulen == 1) 
    {
      a.le = *apdu? *apdu : 256;
      apdu++; apdulen--;
      a.cse = SC_APDU_CASE_2_SHORT;
    }
  else
    {
      a.lc = *apdu++; apdulen--;
      if (apdulen < a.lc)
        {
          log_error ("osc_send_apdu: APDU shorter than specified in Lc\n");
          return SC_ERROR_CMD_TOO_SHORT;

        }
      memcpy(data, apdu, a.lc);
      apdu += a.lc; apdulen -= a.lc;

      a.data = data;
      a.datalen = a.lc;
      
      if (!apdulen)
        a.cse = SC_APDU_CASE_3_SHORT;
      else
        {
          a.le = *apdu? *apdu : 256;
          apdu++; apdulen--;
          if (apdulen)
            {
              log_error ("osc_send_apdu: APDU larger than specified\n");
              return SC_ERROR_CMD_TOO_LONG;
            }
          a.cse = SC_APDU_CASE_4_SHORT;
        }
    }

  a.resp = result;
  a.resplen = DIM(result);

  err = sc_transmit_apdu (reader_table[slot].osc.scard, &a);
  if (err)
    {
      log_error ("sc_apdu_transmit failed: %s\n", sc_strerror (err));
      return err;
    }

  if (*buflen < 2 || a.resplen > *buflen - 2)
    {
      log_error ("osc_send_apdu: provided buffer too short to store result\n");
      return SC_ERROR_BUFFER_TOO_SMALL;
    }
  memcpy (buffer, a.resp, a.resplen);
  buffer[a.resplen] = a.sw1;
  buffer[a.resplen+1] = a.sw2;
  *buflen = a.resplen + 2;
  return 0;
}

#endif /* HAVE_OPENSC */



/* 
       Driver Access
 */

/* Open the reader and return an internal slot number or -1 on
   error. If PORTSTR is NULL we default to a suitable port (for ctAPI:
   the first USB reader.  For PC/SC the first listed reader).  If
   OpenSC support is compiled in, we first try to use OpenSC. */
int
apdu_open_reader (const char *portstr)
{
  static int pcsc_api_loaded, ct_api_loaded;

#ifdef HAVE_LIBUSB
  if (!opt.disable_ccid)
    {
      int slot;

      slot = open_ccid_reader ();
      if (slot != -1)
        return slot; /* got one */
    }
#endif /* HAVE_LIBUSB */

#ifdef HAVE_OPENSC
  if (!opt.disable_opensc)
    {
      int port = portstr? atoi (portstr) : 0;

      return open_osc_reader (port);
    }
#endif /* HAVE_OPENSC */  


  if (opt.ctapi_driver && *opt.ctapi_driver)
    {
      int port = portstr? atoi (portstr) : 32768;

      if (!ct_api_loaded)
        {
          void *handle;
          
          handle = dlopen (opt.ctapi_driver, RTLD_LAZY);
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
              log_error ("apdu_open_reader: invalid CT-API driver\n");
              dlclose (handle);
              return -1;
            }
          ct_api_loaded = 1;
        }
      return open_ct_reader (port);
    }

  
  /* No ctAPI configured, so lets try the PC/SC API */
  if (!pcsc_api_loaded)
    {
      void *handle;

      handle = dlopen (opt.pcsc_driver, RTLD_LAZY);
      if (!handle)
        {
          log_error ("apdu_open_reader: failed to open driver `%s': %s",
                     opt.pcsc_driver, dlerror ());
          return -1;
        }

      pcsc_establish_context = dlsym (handle, "SCardEstablishContext");
      pcsc_release_context   = dlsym (handle, "SCardReleaseContext");
      pcsc_list_readers      = dlsym (handle, "SCardListReaders");
#ifdef _WIN32
      if (!pcsc_list_readers)
        pcsc_list_readers    = dlsym (handle, "SCardListReadersA");
#endif
      pcsc_connect           = dlsym (handle, "SCardConnect");
#ifdef _WIN32
      if (!pcsc_connect)
        pcsc_connect         = dlsym (handle, "SCardConnectA");
#endif
      pcsc_disconnect        = dlsym (handle, "SCardDisconnect");
      pcsc_status            = dlsym (handle, "SCardStatus");
#ifdef _WIN32
      if (!pcsc_status)
        pcsc_status          = dlsym (handle, "SCardStatusA");
#endif
      pcsc_begin_transaction = dlsym (handle, "SCardBeginTransaction");
      pcsc_end_transaction   = dlsym (handle, "SCardEndTransaction");
      pcsc_transmit          = dlsym (handle, "SCardTransmit");
      pcsc_set_timeout       = dlsym (handle, "SCardSetTimeout");

      if (!pcsc_establish_context
          || !pcsc_release_context  
          || !pcsc_list_readers     
          || !pcsc_connect          
          || !pcsc_disconnect
          || !pcsc_status
          || !pcsc_begin_transaction
          || !pcsc_end_transaction
          || !pcsc_transmit         
          /* || !pcsc_set_timeout */)
        {
          /* Note that set_timeout is currently not used and also not
             available under Windows. */
          log_error ("apdu_open_reader: invalid PC/SC driver "
                     "(%d%d%d%d%d%d%d%d%d%d)\n",
                     !!pcsc_establish_context,
                     !!pcsc_release_context,  
                     !!pcsc_list_readers,     
                     !!pcsc_connect,          
                     !!pcsc_disconnect,
                     !!pcsc_status,
                     !!pcsc_begin_transaction,
                     !!pcsc_end_transaction,
                     !!pcsc_transmit,         
                     !!pcsc_set_timeout );
          dlclose (handle);
          return -1;
        }
      pcsc_api_loaded = 1;
    }
  
  return open_pcsc_reader (portstr);
}


int
apdu_close_reader (int slot)
{
  if (slot < 0 || slot >= MAX_READER || !reader_table[slot].used )
    return SW_HOST_NO_DRIVER;
  if (reader_table[slot].is_ctapi)
    return close_ct_reader (slot);
#ifdef HAVE_LIBUSB
  else if (reader_table[slot].is_ccid)
    return close_ccid_reader (slot);
#endif
#ifdef HAVE_OPENSC
  else if (reader_table[slot].is_osc)
    return close_osc_reader (slot);
#endif
  else
    return close_pcsc_reader (slot);
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
error_string (int slot, long rc)
{
  if (slot < 0 || slot >= MAX_READER || !reader_table[slot].used )
    return "[invalid slot]";
  if (reader_table[slot].is_ctapi)
    return ct_error_string (rc);
#ifdef HAVE_LIBUSB
  else if (reader_table[slot].is_ccid)
    return get_ccid_error_string (rc);
#endif
#ifdef HAVE_OPENSC
  else if (reader_table[slot].is_osc)
    return sc_strerror (rc);
#endif
  else
    return pcsc_error_string (rc);
}


/* Dispatcher for the actual send_apdu fucntion. */
static int
send_apdu (int slot, unsigned char *apdu, size_t apdulen,
           unsigned char *buffer, size_t *buflen)
{
  if (slot < 0 || slot >= MAX_READER || !reader_table[slot].used )
    return SW_HOST_NO_DRIVER;
  if (reader_table[slot].is_ctapi)
    return ct_send_apdu (slot, apdu, apdulen, buffer, buflen);
#ifdef HAVE_LIBUSB
  else if (reader_table[slot].is_ccid)
    return send_apdu_ccid (slot, apdu, apdulen, buffer, buflen);
#endif
#ifdef HAVE_OPENSC
  else if (reader_table[slot].is_osc)
    return osc_send_apdu (slot, apdu, apdulen, buffer, buflen);
#endif
  else
    return pcsc_send_apdu (slot, apdu, apdulen, buffer, buflen);
}

/* Send an APDU to the card in SLOT.  The APDU is created from all
   given parameters: CLASS, INS, P0, P1, LC, DATA, LE.  A value of -1
   for LC won't sent this field and the data field; in this case DATA
   must also be passed as NULL.  The return value is the status word
   or -1 for an invalid SLOT or other non card related error.  If
   RETBUF is not NULL, it will receive an allocated buffer with the
   returned data.  The length of that data will be put into
   *RETBUFLEN.  The caller is reponsible for releasing the buffer even
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
  int sw;
  long rc; /* we need a long here due to PC/SC. */

  if (DBG_CARD_IO)
    log_debug ("send apdu: c=%02X i=%02X p0=%02X p1=%02X lc=%d le=%d\n",
               class, ins, p0, p1, lc, le);

  if (lc != -1 && (lc > 255 || lc < 0))
    return SW_WRONG_LENGTH; 
  if (le != -1 && (le > 256 || le < 1))
    return SW_WRONG_LENGTH; 
  if ((!data && lc != -1) || (data && lc == -1))
    return SW_HOST_INV_VALUE;

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
      return SW_HOST_INCOMPLETE_CARD_RESPONSE;
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

  if (sw == SW_SUCCESS || sw == SW_EOF_REACHED)
    {
      if (retbuf)
        {
          *retbuf = xtrymalloc (resultlen? resultlen : 1);
          if (!*retbuf)
            return SW_HOST_OUT_OF_CORE;
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
            return SW_HOST_OUT_OF_CORE;
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
          apdu[apdulen++] = len; 
          memset (apdu+apdulen, 0, sizeof (apdu) - apdulen);
          rc = send_apdu (slot, apdu, apdulen, result, &resultlen);
          if (rc || resultlen < 2)
            {
              log_error ("apdu_send_simple(%d) for get response failed: %s\n",
                         slot, error_string (slot, rc));
              return SW_HOST_INCOMPLETE_CARD_RESPONSE;
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
                        return SW_HOST_OUT_OF_CORE;
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
apdu_send (int slot, int class, int ins, int p0, int p1,
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
  return apdu_send_le (slot, class, ins, p0, p1, lc, data, -1, NULL, NULL);
}




