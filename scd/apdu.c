/* apdu.c - ISO 7816 APDU functions and low level I/O
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
 *
 * $Id$
 */

#include <config.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <signal.h>
#ifdef USE_GNU_PTH
# include <pth.h>
# include <unistd.h>
# include <fcntl.h>
#endif
#ifdef HAVE_OPENSC
# include <opensc/opensc.h>
# ifdef USE_GNU_PTH
# undef USE_GNU_PTH
# endif
#endif

/* If requested include the definitions for the remote APDU protocol
   code. */
#ifdef USE_G10CODE_RAPDU
#include "rapdu.h"
#endif /*USE_G10CODE_RAPDU*/

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


/* To to conflicting use of threading libraries we usually can't link
   against libpcsclite.   Instead we use a wrapper program.  */
#ifdef USE_GNU_PTH
#ifndef HAVE_W32_SYSTEM
#define NEED_PCSC_WRAPPER 1
#endif
#endif

 
#define MAX_READER 4 /* Number of readers we support concurrently. */


#ifdef _WIN32
#define DLSTDCALL __stdcall
#else
#define DLSTDCALL
#endif

#ifdef _POSIX_OPEN_MAX
#define MAX_OPEN_FDS _POSIX_OPEN_MAX
#else
#define MAX_OPEN_FDS 20
#endif


/* A structure to collect information pertaining to one reader
   slot. */
struct reader_table_s {
  int used;            /* True if slot is used. */
  unsigned short port; /* Port number:  0 = unused, 1 - dev/tty */

  /* Function pointers intialized to the various backends.  */
  int (*close_reader)(int);
  int (*shutdown_reader)(int);
  int (*reset_reader)(int);
  int (*get_status_reader)(int, unsigned int *);
  int (*send_apdu_reader)(int,unsigned char *,size_t,
                          unsigned char *, size_t *);
  void (*dump_status_reader)(int);

  struct {
    ccid_driver_t handle;
  } ccid;
  struct {
    unsigned long context;
    unsigned long card;
    unsigned long protocol;
#ifdef NEED_PCSC_WRAPPER
    int req_fd;
    int rsp_fd;
    pid_t pid;
#endif /*NEED_PCSC_WRAPPER*/
  } pcsc;
#ifdef HAVE_OPENSC
  struct {
    struct sc_context *ctx;
    struct sc_card *scard;
  } osc;
#endif /*HAVE_OPENSC*/
#ifdef USE_G10CODE_RAPDU
  struct {
    rapdu_t handle;
  } rapdu;
#endif /*USE_G10CODE_RAPDU*/
  char *rdrname;     /* Name of the connected reader or NULL if unknown. */
  int last_status;
  int status;
  unsigned char atr[33];
  size_t atrlen;           /* A zero length indicates that the ATR has
                              not yet been read; i.e. the card is not
                              ready for use. */
  unsigned int change_counter;
#ifdef USE_GNU_PTH
  int lock_initialized;
  pth_mutex_t lock;
#endif
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

#define PCSC_UNKNOWN    0x0001  
#define PCSC_ABSENT     0x0002  /* Card is absent.  */
#define PCSC_PRESENT    0x0004  /* Card is present.  */
#define PCSC_SWALLOWED  0x0008  /* Card is present and electrical connected. */
#define PCSC_POWERED    0x0010  /* Card is powered.  */
#define PCSC_NEGOTIABLE 0x0020  /* Card is awaiting PTS.  */
#define PCSC_SPECIFIC   0x0040  /* Card is ready for use.  */

#define PCSC_STATE_UNAWARE     0x0000  /* Want status.  */
#define PCSC_STATE_IGNORE      0x0001  /* Ignore this reader.  */
#define PCSC_STATE_CHANGED     0x0002  /* State has changed.  */
#define PCSC_STATE_UNKNOWN     0x0004  /* Reader unknown.  */
#define PCSC_STATE_UNAVAILABLE 0x0008  /* Status unavailable.  */
#define PCSC_STATE_EMPTY       0x0010  /* Card removed.  */
#define PCSC_STATE_PRESENT     0x0020  /* Card inserted.  */
#define PCSC_STATE_ATRMATCH    0x0040  /* ATR matches card. */
#define PCSC_STATE_EXCLUSIVE   0x0080  /* Exclusive Mode.  */
#define PCSC_STATE_INUSE       0x0100  /* Shared mode.  */
#define PCSC_STATE_MUTE	       0x0200  /* Unresponsive card.  */


struct pcsc_io_request_s 
{
  unsigned long protocol; 
  unsigned long pci_len;
};

typedef struct pcsc_io_request_s *pcsc_io_request_t;

struct pcsc_readerstate_s
{
  const char *reader;
  void *user_data;
  unsigned long current_state;
  unsigned long event_state;
  unsigned long atrlen;
  unsigned char atr[33];
};

typedef struct pcsc_readerstate_s *pcsc_readerstate_t;

long (* DLSTDCALL pcsc_establish_context) (unsigned long scope,
                                           const void *reserved1,
                                           const void *reserved2,
                                           unsigned long *r_context);
long (* DLSTDCALL pcsc_release_context) (unsigned long context);
long (* DLSTDCALL pcsc_list_readers) (unsigned long context,
                                      const char *groups,
                                      char *readers, unsigned long*readerslen);
long (* DLSTDCALL pcsc_get_status_change) (unsigned long context,
                                           unsigned long timeout,
                                           pcsc_readerstate_t readerstates,
                                           unsigned long nreaderstates);
long (* DLSTDCALL pcsc_connect) (unsigned long context,
                                 const char *reader,
                                 unsigned long share_mode,
                                 unsigned long preferred_protocols,
                                 unsigned long *r_card,
                                 unsigned long *r_active_protocol);
long (* DLSTDCALL pcsc_reconnect) (unsigned long card,
                                   unsigned long share_mode,
                                   unsigned long preferred_protocols,
                                   unsigned long initialization,
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
#ifdef USE_GNU_PTH
  if (!reader_table[reader].lock_initialized)
    {
      if (!pth_mutex_init (&reader_table[reader].lock))
        {
          log_error ("error initializing mutex: %s\n", strerror (errno));
          return -1;
        }
      reader_table[reader].lock_initialized = 1;
    }
#endif /*USE_GNU_PTH*/
  reader_table[reader].close_reader = NULL;
  reader_table[reader].shutdown_reader = NULL;
  reader_table[reader].reset_reader = NULL;
  reader_table[reader].get_status_reader = NULL;
  reader_table[reader].send_apdu_reader = NULL;
  reader_table[reader].dump_status_reader = NULL;

  reader_table[reader].used = 1;
  reader_table[reader].last_status = 0;
#ifdef NEED_PCSC_WRAPPER
  reader_table[reader].pcsc.req_fd = -1;
  reader_table[reader].pcsc.rsp_fd = -1;
  reader_table[reader].pcsc.pid = (pid_t)(-1);
#endif

  return reader;
}


static void
dump_reader_status (int slot)
{
  if (!opt.verbose)
    return;

  if (reader_table[slot].dump_status_reader)
    reader_table[slot].dump_status_reader (slot);

  if (reader_table[slot].status != -1
      && reader_table[slot].atrlen)
    {
      log_info ("slot %d: ATR=", slot);
      log_printhex ("", reader_table[slot].atr, reader_table[slot].atrlen);
    }
}



static const char *
host_sw_string (long err)
{
  switch (err)
    {
    case 0: return "okay";
    case SW_HOST_OUT_OF_CORE: return "out of core";
    case SW_HOST_INV_VALUE: return "invalid value";
    case SW_HOST_NO_DRIVER: return "no driver";
    case SW_HOST_NOT_SUPPORTED: return "not supported";
    case SW_HOST_LOCKING_FAILED: return "locking failed";
    case SW_HOST_BUSY: return "busy";
    case SW_HOST_NO_CARD: return "no card";
    case SW_HOST_CARD_INACTIVE: return "card inactive";
    case SW_HOST_CARD_IO_ERROR: return "card I/O error";
    case SW_HOST_GENERAL_ERROR: return "general error";
    case SW_HOST_NO_READER: return "no reader";
    case SW_HOST_ABORTED: return "aborted";
    default: return "unknown host status error";
    }
}


const char *
apdu_strerror (int rc)
{
  switch (rc)
    {
    case SW_EOF_REACHED    : return "eof reached";
    case SW_EEPROM_FAILURE : return "eeprom failure";
    case SW_WRONG_LENGTH   : return "wrong length";
    case SW_CHV_WRONG      : return "CHV wrong";
    case SW_CHV_BLOCKED    : return "CHV blocked";
    case SW_USE_CONDITIONS : return "use conditions not satisfied";
    case SW_BAD_PARAMETER  : return "bad parameter";
    case SW_NOT_SUPPORTED  : return "not supported";
    case SW_FILE_NOT_FOUND : return "file not found";
    case SW_RECORD_NOT_FOUND:return "record not found";
    case SW_REF_NOT_FOUND  : return "reference not found";
    case SW_BAD_P0_P1      : return "bad P0 or P1";
    case SW_INS_NOT_SUP    : return "instruction not supported";
    case SW_CLA_NOT_SUP    : return "class not supported";
    case SW_SUCCESS        : return "success";
    default:
      if ((rc & ~0x00ff) == SW_MORE_DATA)
        return "more data available";
      if ( (rc & 0x10000) )
        return host_sw_string (rc);
      return "unknown status error";
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


static void
ct_dump_reader_status (int slot)
{
  log_info ("reader slot %d: %s\n", slot,
            reader_table[slot].status == 1? "Processor ICC present" :
            reader_table[slot].status == 0? "Memory ICC present" :
            "ICC not present" );
}


/* Wait for the card in SLOT and activate it.  Return a status word
   error or 0 on success. */
static int
ct_activate_card (int slot)
{
  int rc;
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

  rc = CT_data (slot, dad, sad, 5, cmd, &buflen, buf);
  if (rc || buflen < 2 || buf[buflen-2] != 0x90)
    {
      log_error ("ct_activate_card: can't get status of reader %d: %s\n",
                 slot, ct_error_string (rc));
      return SW_HOST_CARD_IO_ERROR;
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

  rc = CT_data (slot, dad, sad, 5, cmd, &buflen, buf);
  if (rc || buflen < 2 || buf[buflen-2] != 0x90)
    {
      log_error ("ct_activate_card(%d): activation failed: %s\n",
                 slot, ct_error_string (rc));
      if (!rc)
        log_printhex ("  received data:", buf, buflen);
      return SW_HOST_CARD_IO_ERROR;
    }

  /* Store the type and the ATR. */
  if (buflen - 2 > DIM (reader_table[0].atr))
    {
      log_error ("ct_activate_card(%d): ATR too long\n", slot);
      return SW_HOST_CARD_IO_ERROR;
    }

  reader_table[slot].status = buf[buflen - 1];
  memcpy (reader_table[slot].atr, buf, buflen - 2);
  reader_table[slot].atrlen = buflen - 2;
  return 0;
}


static int
close_ct_reader (int slot)
{
  CT_close (slot);
  reader_table[slot].used = 0;
  return 0;
}

static int
reset_ct_reader (int slot)
{
  /* FIXME: Check is this is sufficient do do a reset. */
  return ct_activate_card (slot);
}


static int
ct_get_status (int slot, unsigned int *status)
{
  *status = 1|2|4;  /* FIXME */
  return 0;

  return SW_HOST_NOT_SUPPORTED;
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
  
  /* If we don't have an ATR, we need to reset the reader first. */
  if (!reader_table[slot].atrlen
      && (rc = reset_ct_reader (slot)))
    return rc;

  dad[0] = 0;     /* Destination address: Card. */    
  sad[0] = 2;     /* Source address: Host. */
  ctbuflen = *buflen;
  if (DBG_CARD_IO)
    log_printhex ("  CT_data:", apdu, apdulen);
  rc = CT_data (slot, dad, sad, apdulen, apdu, &ctbuflen, buffer);
  *buflen = ctbuflen;

  return rc? SW_HOST_CARD_IO_ERROR: 0;
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

  /* Only try to activate the card. */
  rc = ct_activate_card (reader);
  if (rc)
    {
      reader_table[reader].atrlen = 0;
      rc = 0;
    }

  reader_table[reader].close_reader = close_ct_reader;
  reader_table[reader].reset_reader = reset_ct_reader;
  reader_table[reader].get_status_reader = ct_get_status;
  reader_table[reader].send_apdu_reader = ct_send_apdu;
  reader_table[reader].dump_status_reader = ct_dump_reader_status;

  dump_reader_status (reader);
  return reader;
}


#ifdef NEED_PCSC_WRAPPER
static int
writen (int fd, const void *buf, size_t nbytes)
{
  size_t nleft = nbytes;
  int nwritten;

/*   log_printhex (" writen:", buf, nbytes); */

  while (nleft > 0)
    {
#ifdef USE_GNU_PTH
      nwritten = pth_write (fd, buf, nleft);
#else
      nwritten = write (fd, buf, nleft);
#endif
      if (nwritten < 0 && errno == EINTR)
        continue;
      if (nwritten < 0)
        return -1;
      nleft -= nwritten;
      buf = (const char*)buf + nwritten;
    }
  return 0;
}

/* Read up to BUFLEN bytes from FD and return the number of bytes
   actually read in NREAD.  Returns -1 on error or 0 on success. */
static int
readn (int fd, void *buf, size_t buflen, size_t *nread)
{
  size_t nleft = buflen;
  int n;
/*   void *orig_buf = buf; */

  while (nleft > 0)
    {
#ifdef USE_GNU_PTH
      n = pth_read (fd, buf, nleft);
#else
      n = read (fd, buf, nleft);
#endif
      if (n < 0 && errno == EINTR) 
        continue;
      if (n < 0)
        return -1; /* read error. */
      if (!n)
        break; /* EOF */
      nleft -= n;
      buf = (char*)buf + n;
    }
  if (nread)
    *nread = buflen - nleft;

/*   log_printhex ("  readn:", orig_buf, *nread); */
    
  return 0;
}
#endif /*NEED_PCSC_WRAPPER*/

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

static void
dump_pcsc_reader_status (int slot)
{
  log_info ("reader slot %d: active protocol:", slot);
  if ((reader_table[slot].pcsc.protocol & PCSC_PROTOCOL_T0))
    log_printf (" T0");
  else if ((reader_table[slot].pcsc.protocol & PCSC_PROTOCOL_T1))
    log_printf (" T1");
  else if ((reader_table[slot].pcsc.protocol & PCSC_PROTOCOL_RAW))
    log_printf (" raw");
  log_printf ("\n");
}


static int
reset_pcsc_reader (int slot)
{
#ifdef NEED_PCSC_WRAPPER
  long err;
  reader_table_t slotp;
  size_t len;
  int i, n;
  unsigned char msgbuf[9];

  slotp = reader_table + slot;

  if (slotp->pcsc.req_fd == -1 
      || slotp->pcsc.rsp_fd == -1 
      || slotp->pcsc.pid == (pid_t)(-1) )
    {
      log_error ("pcsc_get_status: pcsc-wrapper not running\n");
      return SW_HOST_CARD_IO_ERROR;
    }

  msgbuf[0] = 0x05; /* RESET command. */
  len = 0;
  msgbuf[1] = (len >> 24);
  msgbuf[2] = (len >> 16);
  msgbuf[3] = (len >>  8);
  msgbuf[4] = (len      );
  if ( writen (slotp->pcsc.req_fd, msgbuf, 5) )
    {
      log_error ("error sending PC/SC RESET request: %s\n",
                 strerror (errno));
      goto command_failed;
    }

  /* Read the response. */
  if ((i=readn (slotp->pcsc.rsp_fd, msgbuf, 9, &len)) || len != 9)
    {
      log_error ("error receiving PC/SC RESET response: %s\n",
                 i? strerror (errno) : "premature EOF");
      goto command_failed;
    }
  len = (msgbuf[1] << 24) | (msgbuf[2] << 16) | (msgbuf[3] << 8 ) | msgbuf[4];
  if (msgbuf[0] != 0x81 || len < 4)
    {
      log_error ("invalid response header from PC/SC received\n");
      goto command_failed;
    }
  len -= 4; /* Already read the error code. */
  if (len > DIM (slotp->atr))
    {
      log_error ("PC/SC returned a too large ATR (len=%x)\n", len);
      goto command_failed;
    }
  err = (msgbuf[5] << 24) | (msgbuf[6] << 16) | (msgbuf[7] << 8 ) | msgbuf[8];
  if (err)
    {
      log_error ("PC/SC RESET failed: %s\n", pcsc_error_string (err));
      goto command_failed;
    }

  /* The open fucntion may return a zero for the ATR length to
     indicate that no card is present.  */
  n = len;
  if (n)
    {
      if ((i=readn (slotp->pcsc.rsp_fd, slotp->atr, n, &len)) || len != n)
        {
          log_error ("error receiving PC/SC RESET response: %s\n",
                     i? strerror (errno) : "premature EOF");
          goto command_failed;
        }
    }
  slotp->atrlen = len;

  return 0;

 command_failed:
  close (slotp->pcsc.req_fd);
  close (slotp->pcsc.rsp_fd);
  slotp->pcsc.req_fd = -1;
  slotp->pcsc.rsp_fd = -1;
  kill (slotp->pcsc.pid, SIGTERM);
  slotp->pcsc.pid = (pid_t)(-1);
  slotp->used = 0;
  return -1;

#else /* !NEED_PCSC_WRAPPER */
  long err;
  char reader[250];
  unsigned long nreader, atrlen;
  unsigned long card_state, card_protocol;

  if (reader_table[slot].pcsc.card)
    {
      err = pcsc_disconnect (reader_table[slot].pcsc.card, PCSC_LEAVE_CARD);
      if (err)
        {
          log_error ("pcsc_disconnect failed: %s (0x%lx)\n",
                     pcsc_error_string (err), err);
          return SW_HOST_CARD_IO_ERROR;
        }
      reader_table[slot].pcsc.card = 0;
    }

  err = pcsc_connect (reader_table[slot].pcsc.context,
                      reader_table[slot].rdrname,
                      PCSC_SHARE_EXCLUSIVE,
                      PCSC_PROTOCOL_T0|PCSC_PROTOCOL_T1,
                      &reader_table[slot].pcsc.card,
                      &reader_table[slot].pcsc.protocol);
  if (err)
    {
      log_error ("pcsc_connect failed: %s (0x%lx)\n",
                  pcsc_error_string (err), err);
      reader_table[slot].pcsc.card = 0;
      return SW_HOST_CARD_IO_ERROR;
    }      

  
  atrlen = 33;
  nreader = sizeof reader - 1;
  err = pcsc_status (reader_table[slot].pcsc.card,
                     reader, &nreader,
                     &card_state, &card_protocol,
                     reader_table[slot].atr, &atrlen);
  if (err)
    {
      log_error ("pcsc_status failed: %s (0x%lx)\n",
                  pcsc_error_string (err), err);
      reader_table[slot].atrlen = 0;
      return SW_HOST_CARD_IO_ERROR;
    }
  if (atrlen >= DIM (reader_table[0].atr))
    log_bug ("ATR returned by pcsc_status is too large\n");
  reader_table[slot].atrlen = atrlen;

  return 0;
#endif /* !NEED_PCSC_WRAPPER */
}


static int
pcsc_get_status (int slot, unsigned int *status)
{
#ifdef NEED_PCSC_WRAPPER
  long err;
  reader_table_t slotp;
  size_t len, full_len;
  int i, n;
  unsigned char msgbuf[9];
  unsigned char buffer[12];

  slotp = reader_table + slot;

  if (slotp->pcsc.req_fd == -1 
      || slotp->pcsc.rsp_fd == -1 
      || slotp->pcsc.pid == (pid_t)(-1) )
    {
      log_error ("pcsc_get_status: pcsc-wrapper not running\n");
      return SW_HOST_CARD_IO_ERROR;
    }

  msgbuf[0] = 0x04; /* STATUS command. */
  len = 0;
  msgbuf[1] = (len >> 24);
  msgbuf[2] = (len >> 16);
  msgbuf[3] = (len >>  8);
  msgbuf[4] = (len      );
  if ( writen (slotp->pcsc.req_fd, msgbuf, 5) )
    {
      log_error ("error sending PC/SC STATUS request: %s\n",
                 strerror (errno));
      goto command_failed;
    }

  /* Read the response. */
  if ((i=readn (slotp->pcsc.rsp_fd, msgbuf, 9, &len)) || len != 9)
    {
      log_error ("error receiving PC/SC STATUS response: %s\n",
                 i? strerror (errno) : "premature EOF");
      goto command_failed;
    }
  len = (msgbuf[1] << 24) | (msgbuf[2] << 16) | (msgbuf[3] << 8 ) | msgbuf[4];
  if (msgbuf[0] != 0x81 || len < 4)
    {
      log_error ("invalid response header from PC/SC received\n");
      goto command_failed;
    }
  len -= 4; /* Already read the error code. */
  err = (msgbuf[5] << 24) | (msgbuf[6] << 16) | (msgbuf[7] << 8 ) | msgbuf[8];
  if (err)
    {
      log_error ("pcsc_status failed: %s (0x%lx)\n",
                 pcsc_error_string (err), err);
      return SW_HOST_CARD_IO_ERROR;
    }

  full_len = len;
  
  n = 8 < len ? 8 : len;
  if ((i=readn (slotp->pcsc.rsp_fd, buffer, n, &len)) || len != 8)
    {
      log_error ("error receiving PC/SC STATUS response: %s\n",
                 i? strerror (errno) : "premature EOF");
      goto command_failed;
    }

  full_len -= len;
  /* Newer versions of the wrapper might send more status bytes.
     Read them. */
  while (full_len)
    {
      unsigned char dummybuf[128];

      n = full_len < DIM (dummybuf) ? full_len : DIM (dummybuf);
      if ((i=readn (slotp->pcsc.rsp_fd, dummybuf, n, &len)) || len != n)
        {
          log_error ("error receiving PC/SC TRANSMIT response: %s\n",
                     i? strerror (errno) : "premature EOF");
          goto command_failed;
        }
      full_len -= n;
    }
   
  /* We are lucky: The wrapper already returns the data in the
     required format. */
  *status = buffer[3];

  return 0;

 command_failed:
  close (slotp->pcsc.req_fd);
  close (slotp->pcsc.rsp_fd);
  slotp->pcsc.req_fd = -1;
  slotp->pcsc.rsp_fd = -1;
  kill (slotp->pcsc.pid, SIGTERM);
  slotp->pcsc.pid = (pid_t)(-1);
  slotp->used = 0;
  return -1;

#else /*!NEED_PCSC_WRAPPER*/

  long err;
  struct pcsc_readerstate_s rdrstates[1];
  
  memset (rdrstates, 0, sizeof *rdrstates);
  rdrstates[0].reader = reader_table[slot].rdrname;
  rdrstates[0].current_state = PCSC_STATE_UNAWARE;
  err = pcsc_get_status_change (reader_table[slot].pcsc.context,
                                0,
                                rdrstates, 1);
  if (err == 0x8010000a) /* Timeout.  */
    err = 0;
  if (err)
    {
      log_error ("pcsc_get_status_change failed: %s (0x%lx)\n",
                 pcsc_error_string (err), err);
      return SW_HOST_CARD_IO_ERROR;
    }


  /*   log_debug  */
  /*     ("pcsc_get_status_change: %s%s%s%s%s%s%s%s%s%s\n", */
  /*      (rdrstates[0].event_state & PCSC_STATE_IGNORE)? " ignore":"", */
  /*      (rdrstates[0].event_state & PCSC_STATE_CHANGED)? " changed":"", */
  /*      (rdrstates[0].event_state & PCSC_STATE_UNKNOWN)? " unknown":"", */
  /*      (rdrstates[0].event_state & PCSC_STATE_UNAVAILABLE)?" unavail":"", */
  /*      (rdrstates[0].event_state & PCSC_STATE_EMPTY)? " empty":"", */
  /*      (rdrstates[0].event_state & PCSC_STATE_PRESENT)? " present":"", */
  /*      (rdrstates[0].event_state & PCSC_STATE_ATRMATCH)? " atr":"", */
  /*      (rdrstates[0].event_state & PCSC_STATE_EXCLUSIVE)? " excl":"", */
  /*      (rdrstates[0].event_state & PCSC_STATE_INUSE)? " unuse":"", */
  /*      (rdrstates[0].event_state & PCSC_STATE_MUTE)? " mute":"" ); */

  *status = 0;
  if ( (rdrstates[0].event_state & PCSC_STATE_PRESENT) )
    *status |= 2;
  if ( !(rdrstates[0].event_state & PCSC_STATE_MUTE) )
    *status |= 4;
  /* We indicate a useful card if it is not in use by another
     application.  This is because we only use exclusive access
     mode.  */
  if ( (*status & 6) == 6
       && !(rdrstates[0].event_state & PCSC_STATE_INUSE) )
    *status |= 1;
  
  return 0; 
#endif /*!NEED_PCSC_WRAPPER*/
}


/* Actually send the APDU of length APDULEN to SLOT and return a
   maximum of *BUFLEN data in BUFFER, the actual returned size will be
   set to BUFLEN.  Returns: CT API error code. */
static int
pcsc_send_apdu (int slot, unsigned char *apdu, size_t apdulen,
                unsigned char *buffer, size_t *buflen)
{
#ifdef NEED_PCSC_WRAPPER
  long err;
  reader_table_t slotp;
  size_t len, full_len;
  int i, n;
  unsigned char msgbuf[9];

  if (!reader_table[slot].atrlen
      && (err = reset_pcsc_reader (slot)))
    return err;

  if (DBG_CARD_IO)
    log_printhex ("  PCSC_data:", apdu, apdulen);

  slotp = reader_table + slot;

  if (slotp->pcsc.req_fd == -1 
      || slotp->pcsc.rsp_fd == -1 
      || slotp->pcsc.pid == (pid_t)(-1) )
    {
      log_error ("pcsc_send_apdu: pcsc-wrapper not running\n");
      return SW_HOST_CARD_IO_ERROR;
    }

  msgbuf[0] = 0x03; /* TRANSMIT command. */
  len = apdulen;
  msgbuf[1] = (len >> 24);
  msgbuf[2] = (len >> 16);
  msgbuf[3] = (len >>  8);
  msgbuf[4] = (len      );
  if ( writen (slotp->pcsc.req_fd, msgbuf, 5)
       || writen (slotp->pcsc.req_fd, apdu, len))
    {
      log_error ("error sending PC/SC TRANSMIT request: %s\n",
                 strerror (errno));
      goto command_failed;
    }

  /* Read the response. */
  if ((i=readn (slotp->pcsc.rsp_fd, msgbuf, 9, &len)) || len != 9)
    {
      log_error ("error receiving PC/SC TRANSMIT response: %s\n",
                 i? strerror (errno) : "premature EOF");
      goto command_failed;
    }
  len = (msgbuf[1] << 24) | (msgbuf[2] << 16) | (msgbuf[3] << 8 ) | msgbuf[4];
  if (msgbuf[0] != 0x81 || len < 4)
    {
      log_error ("invalid response header from PC/SC received\n");
      goto command_failed;
    }
  len -= 4; /* Already read the error code. */
  err = (msgbuf[5] << 24) | (msgbuf[6] << 16) | (msgbuf[7] << 8 ) | msgbuf[8];
  if (err)
    {
      log_error ("pcsc_transmit failed: %s (0x%lx)\n",
                 pcsc_error_string (err), err);
      return SW_HOST_CARD_IO_ERROR;
    }

   full_len = len;
   
   n = *buflen < len ? *buflen : len;
   if ((i=readn (slotp->pcsc.rsp_fd, buffer, n, &len)) || len != n)
     {
       log_error ("error receiving PC/SC TRANSMIT response: %s\n",
                  i? strerror (errno) : "premature EOF");
       goto command_failed;
     }
   *buflen = n;

   full_len -= len;
   if (full_len)
     {
       log_error ("pcsc_send_apdu: provided buffer too short - truncated\n");
       err = SW_HOST_INV_VALUE;
     }
   /* We need to read any rest of the response, to keep the
      protocol runnng. */
   while (full_len)
     {
       unsigned char dummybuf[128];

       n = full_len < DIM (dummybuf) ? full_len : DIM (dummybuf);
       if ((i=readn (slotp->pcsc.rsp_fd, dummybuf, n, &len)) || len != n)
         {
           log_error ("error receiving PC/SC TRANSMIT response: %s\n",
                      i? strerror (errno) : "premature EOF");
           goto command_failed;
         }
       full_len -= n;
     }

   return err;

 command_failed:
  close (slotp->pcsc.req_fd);
  close (slotp->pcsc.rsp_fd);
  slotp->pcsc.req_fd = -1;
  slotp->pcsc.rsp_fd = -1;
  kill (slotp->pcsc.pid, SIGTERM);
  slotp->pcsc.pid = (pid_t)(-1);
  slotp->used = 0;
  return -1;

#else /*!NEED_PCSC_WRAPPER*/

  long err;
  struct pcsc_io_request_s send_pci;
  unsigned long recv_len;
  
  if (!reader_table[slot].atrlen
      && (err = reset_pcsc_reader (slot)))
    return err;

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
  
  return err? SW_HOST_CARD_IO_ERROR:0; 
#endif /*!NEED_PCSC_WRAPPER*/
}


static int
close_pcsc_reader (int slot)
{
#ifdef NEED_PCSC_WRAPPER
  long err;
  reader_table_t slotp;
  size_t len;
  int i;
  unsigned char msgbuf[9];

  slotp = reader_table + slot;

  if (slotp->pcsc.req_fd == -1 
      || slotp->pcsc.rsp_fd == -1 
      || slotp->pcsc.pid == (pid_t)(-1) )
    {
      log_error ("close_pcsc_reader: pcsc-wrapper not running\n");
      return 0;
    }

  msgbuf[0] = 0x02; /* CLOSE command. */
  len = 0;
  msgbuf[1] = (len >> 24);
  msgbuf[2] = (len >> 16);
  msgbuf[3] = (len >>  8);
  msgbuf[4] = (len      );
  if ( writen (slotp->pcsc.req_fd, msgbuf, 5) )
    {
      log_error ("error sending PC/SC CLOSE request: %s\n",
                 strerror (errno));
      goto command_failed;
    }

  /* Read the response. */
  if ((i=readn (slotp->pcsc.rsp_fd, msgbuf, 9, &len)) || len != 9)
    {
      log_error ("error receiving PC/SC CLOSE response: %s\n",
                 i? strerror (errno) : "premature EOF");
      goto command_failed;
    }
  len = (msgbuf[1] << 24) | (msgbuf[2] << 16) | (msgbuf[3] << 8 ) | msgbuf[4];
  if (msgbuf[0] != 0x81 || len < 4)
    {
      log_error ("invalid response header from PC/SC received\n");
      goto command_failed;
    }
  len -= 4; /* Already read the error code. */
  err = (msgbuf[5] << 24) | (msgbuf[6] << 16) | (msgbuf[7] << 8 ) | msgbuf[8];
  if (err)
    log_error ("pcsc_close failed: %s (0x%lx)\n",
               pcsc_error_string (err), err);
  
  /* We will the wrapper in any case - errors are merely
     informational. */
  
 command_failed:
  close (slotp->pcsc.req_fd);
  close (slotp->pcsc.rsp_fd);
  slotp->pcsc.req_fd = -1;
  slotp->pcsc.rsp_fd = -1;
  kill (slotp->pcsc.pid, SIGTERM);
  slotp->pcsc.pid = (pid_t)(-1);
  slotp->used = 0;
  return 0;

#else /*!NEED_PCSC_WRAPPER*/

  pcsc_release_context (reader_table[slot].pcsc.context);
  xfree (reader_table[slot].rdrname);
  reader_table[slot].rdrname = NULL;
  reader_table[slot].used = 0;
  return 0;
#endif /*!NEED_PCSC_WRAPPER*/
}

static int
open_pcsc_reader (const char *portstr)
{
#ifdef NEED_PCSC_WRAPPER
/* Open the PC/SC reader using the pcsc_wrapper program.  This is
   needed to cope with different thread models and other peculiarities
   of libpcsclite. */
  int slot;
  reader_table_t slotp;
  int fd, rp[2], wp[2];
  int n, i;
  pid_t pid;
  size_t len;
  unsigned char msgbuf[9];
  int err;

  slot = new_reader_slot ();
  if (slot == -1)
    return -1;
  slotp = reader_table + slot;

  /* Fire up the pcsc wrapper.  We don't use any fork/exec code from
     the common directy but implement it direclty so that this file
     may still be source copied. */
  
  if (pipe (rp) == -1)
    {
      log_error ("error creating a pipe: %s\n", strerror (errno));
      slotp->used = 0;
      return -1;
    }
  if (pipe (wp) == -1)
    {
      log_error ("error creating a pipe: %s\n", strerror (errno));
      close (rp[0]);
      close (rp[1]);
      slotp->used = 0;
      return -1;
    }
      
  pid = fork ();
  if (pid == -1)
    {
      log_error ("error forking process: %s\n", strerror (errno));
      close (rp[0]);
      close (rp[1]);
      close (wp[0]);
      close (wp[1]);
      slotp->used = 0;
      return -1;
    }
  slotp->pcsc.pid = pid;

  if (!pid)
    { /*
         === Child ===
       */

      /* Double fork. */
      pid = fork ();
      if (pid == -1)
        _exit (31); 
      if (pid)
        _exit (0); /* Immediate exit this parent, so that the child
                      gets cleaned up by the init process. */

      /* Connect our pipes. */
      if (wp[0] != 0 && dup2 (wp[0], 0) == -1)
        log_fatal ("dup2 stdin failed: %s\n", strerror (errno));
      if (rp[1] != 1 && dup2 (rp[1], 1) == -1)
        log_fatal ("dup2 stdout failed: %s\n", strerror (errno));
      
      /* Send stderr to the bit bucket. */
      fd = open ("/dev/null", O_WRONLY);
      if (fd == -1)
        log_fatal ("can't open `/dev/null': %s", strerror (errno));
      if (fd != 2 && dup2 (fd, 2) == -1)
        log_fatal ("dup2 stderr failed: %s\n", strerror (errno));

      /* Close all other files. */
      n = sysconf (_SC_OPEN_MAX);
      if (n < 0)
        n = MAX_OPEN_FDS;
      for (i=3; i < n; i++)
        close(i);
      errno = 0;

      execl (GNUPG_LIBDIR "/pcsc-wrapper",
             "pcsc-wrapper",
             "--",
             "1", /* API version */
             opt.pcsc_driver, /* Name of the PC/SC library. */
              NULL);
      _exit (31);
    }

  /* 
     === Parent ===
   */
  close (wp[0]);
  close (rp[1]);
  slotp->pcsc.req_fd = wp[1];
  slotp->pcsc.rsp_fd = rp[0];

  /* Wait for the intermediate child to terminate. */
#ifdef USE_GNU_PTH
#define WAIT pth_waitpid 
#else
#define WAIT waitpid 
#endif
  while ( (i=WAIT (pid, NULL, 0)) == -1 && errno == EINTR)
    ;
#undef X

  /* Now send the open request. */
  msgbuf[0] = 0x01; /* OPEN command. */
  len = portstr? strlen (portstr):0;
  msgbuf[1] = (len >> 24);
  msgbuf[2] = (len >> 16);
  msgbuf[3] = (len >>  8);
  msgbuf[4] = (len      );
  if ( writen (slotp->pcsc.req_fd, msgbuf, 5)
       || (portstr && writen (slotp->pcsc.req_fd, portstr, len)))
    {
      log_error ("error sending PC/SC OPEN request: %s\n",
                 strerror (errno));
      goto command_failed;
    }
  /* Read the response. */
  if ((i=readn (slotp->pcsc.rsp_fd, msgbuf, 9, &len)) || len != 9)
    {
      log_error ("error receiving PC/SC OPEN response: %s\n",
                 i? strerror (errno) : "premature EOF");
      goto command_failed;
    }
  len = (msgbuf[1] << 24) | (msgbuf[2] << 16) | (msgbuf[3] << 8 ) | msgbuf[4];
  if (msgbuf[0] != 0x81 || len < 4)
    {
      log_error ("invalid response header from PC/SC received\n");
      goto command_failed;
    }
  len -= 4; /* Already read the error code. */
  if (len > DIM (slotp->atr))
    {
      log_error ("PC/SC returned a too large ATR (len=%x)\n", len);
      goto command_failed;
    }
  err = (msgbuf[5] << 24) | (msgbuf[6] << 16) | (msgbuf[7] << 8 ) | msgbuf[8];
  if (err)
    {
      log_error ("PC/SC OPEN failed: %s\n", pcsc_error_string (err));
      goto command_failed;
    }

  slotp->last_status = 0;

  /* The open fucntion may return a zero for the ATR length to
     indicate that no card is present.  */
  n = len;
  if (n)
    {
      if ((i=readn (slotp->pcsc.rsp_fd, slotp->atr, n, &len)) || len != n)
        {
          log_error ("error receiving PC/SC OPEN response: %s\n",
                     i? strerror (errno) : "premature EOF");
          goto command_failed;
        }
      /* If we got to here we know that a card is present
         and usable.  Thus remember this.  */
      slotp->last_status = (1|2|4| 0x8000);
    }
  slotp->atrlen = len;

  reader_table[slot].close_reader = close_pcsc_reader;
  reader_table[slot].reset_reader = reset_pcsc_reader;
  reader_table[slot].get_status_reader = pcsc_get_status;
  reader_table[slot].send_apdu_reader = pcsc_send_apdu;
  reader_table[slot].dump_status_reader = dump_pcsc_reader_status;

  dump_reader_status (slot); 
  return slot;

 command_failed:
  close (slotp->pcsc.req_fd);
  close (slotp->pcsc.rsp_fd);
  slotp->pcsc.req_fd = -1;
  slotp->pcsc.rsp_fd = -1;
  kill (slotp->pcsc.pid, SIGTERM);
  slotp->pcsc.pid = (pid_t)(-1);
  slotp->used = 0;
  return -1;
#else /*!NEED_PCSC_WRAPPER */
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
      if (*p)
        log_info ("detected reader `%s'\n", p);
      if (nreader < (strlen (p)+1))
        {
          log_error ("invalid response from pcsc_list_readers\n");
          break;
        }
      nreader -= strlen (p)+1;
      p += strlen (p) + 1;
    }

  reader_table[slot].rdrname = xtrymalloc (strlen (portstr? portstr : list)+1);
  if (!reader_table[slot].rdrname)
    {
      log_error ("error allocating memory for reader name\n");
      pcsc_release_context (reader_table[slot].pcsc.context);
      reader_table[slot].used = 0;
      return -1;
    }
  strcpy (reader_table[slot].rdrname, portstr? portstr : list);
  xfree (list);

  err = pcsc_connect (reader_table[slot].pcsc.context,
                      reader_table[slot].rdrname,
                      PCSC_SHARE_EXCLUSIVE,
                      PCSC_PROTOCOL_T0|PCSC_PROTOCOL_T1,
                      &reader_table[slot].pcsc.card,
                      &reader_table[slot].pcsc.protocol);
  if (err == 0x8010000c) /* No smartcard.  */
    reader_table[slot].pcsc.card = 0;
  else if (err)
    {
      log_error ("pcsc_connect failed: %s (0x%lx)\n",
                  pcsc_error_string (err), err);
      pcsc_release_context (reader_table[slot].pcsc.context);
      xfree (reader_table[slot].rdrname);
      reader_table[slot].rdrname = NULL;
      reader_table[slot].used = 0;
      xfree (list);
      return -1;
    }      

  reader_table[slot].atrlen = 0;
  reader_table[slot].last_status = 0;
  if (!err)
    {
      char reader[250];
      unsigned long readerlen;

      atrlen = 32;
      readerlen = sizeof reader -1 ;
      err = pcsc_status (reader_table[slot].pcsc.card,
                         reader, &readerlen,
                         &card_state, &card_protocol,
                         reader_table[slot].atr, &atrlen);
      if (err)
        log_error ("pcsc_status failed: %s (0x%lx) %lu\n",
                   pcsc_error_string (err), err, readerlen);
      else
        {
          if (atrlen >= DIM (reader_table[0].atr))
            log_bug ("ATR returned by pcsc_status is too large\n");
          reader_table[slot].atrlen = atrlen;
          /* If we got to here we know that a card is present
             and usable.  Thus remember this.  */
          reader_table[slot].last_status = (1|2|4| 0x8000);
        }
    }

  reader_table[slot].close_reader = close_pcsc_reader;
  reader_table[slot].reset_reader = reset_pcsc_reader;
  reader_table[slot].get_status_reader = pcsc_get_status;
  reader_table[slot].send_apdu_reader = pcsc_send_apdu;
  reader_table[slot].dump_status_reader = dump_pcsc_reader_status;

/*   log_debug ("state    from pcsc_status: 0x%lx\n", card_state); */
/*   log_debug ("protocol from pcsc_status: 0x%lx\n", card_protocol); */

  dump_reader_status (slot); 
  return slot;
#endif /*!NEED_PCSC_WRAPPER */
}




#ifdef HAVE_LIBUSB
/* 
     Internal CCID driver interface.
 */


static void
dump_ccid_reader_status (int slot)
{
  log_info ("reader slot %d: using ccid driver\n", slot);
}

static int
close_ccid_reader (int slot)
{
  ccid_close_reader (reader_table[slot].ccid.handle);
  reader_table[slot].used = 0;
  return 0;
}                       
  

static int
shutdown_ccid_reader (int slot)
{
  ccid_shutdown_reader (reader_table[slot].ccid.handle);
  return 0;
}                       
  

static int
reset_ccid_reader (int slot)
{
  int err;
  reader_table_t slotp = reader_table + slot;
  unsigned char atr[33];
  size_t atrlen;

  err = ccid_get_atr (slotp->ccid.handle, atr, sizeof atr, &atrlen);
  if (err)
    return err;
  /* If the reset was successful, update the ATR. */
  assert (sizeof slotp->atr >= sizeof atr);
  slotp->atrlen = atrlen;
  memcpy (slotp->atr, atr, atrlen);
  dump_reader_status (slot); 
  return 0;
}                       
  

static int
get_status_ccid (int slot, unsigned int *status)
{
  int rc;
  int bits;

  rc = ccid_slot_status (reader_table[slot].ccid.handle, &bits);
  if (rc)
    return -1;

  if (bits == 0)
    *status = 1|2|4;
  else if (bits == 1)
    *status = 2;
  else 
    *status = 0;

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

  /* If we don't have an ATR, we need to reset the reader first. */
  if (!reader_table[slot].atrlen
      && (err = reset_ccid_reader (slot)))
    return err;

  if (DBG_CARD_IO)
    log_printhex ("  APDU_data:", apdu, apdulen);

  maxbuflen = *buflen;
  err = ccid_transceive (reader_table[slot].ccid.handle,
                         apdu, apdulen,
                         buffer, maxbuflen, buflen);
  if (err)
    log_error ("ccid_transceive failed: (0x%lx)\n",
               err);
  
  return err; 
}

/* Open the reader and try to read an ATR.  */
static int
open_ccid_reader (const char *portstr)
{
  int err;
  int slot;
  reader_table_t slotp;

  slot = new_reader_slot ();
  if (slot == -1)
    return -1;
  slotp = reader_table + slot;

  err = ccid_open_reader (&slotp->ccid.handle, portstr);
  if (err)
    {
      slotp->used = 0;
      return -1;
    }

  err = ccid_get_atr (slotp->ccid.handle,
                      slotp->atr, sizeof slotp->atr, &slotp->atrlen);
  if (err)
    {
      slotp->atrlen = 0;
      err = 0;
    }
  else
    {
      /* If we got to here we know that a card is present
         and usable.  Thus remember this.  */
      reader_table[slot].last_status = (1|2|4| 0x8000);
    }

  reader_table[slot].close_reader = close_ccid_reader;
  reader_table[slot].shutdown_reader = shutdown_ccid_reader;
  reader_table[slot].reset_reader = reset_ccid_reader;
  reader_table[slot].get_status_reader = get_status_ccid;
  reader_table[slot].send_apdu_reader = send_apdu_ccid;
  reader_table[slot].dump_status_reader = dump_ccid_reader_status;

  dump_reader_status (slot); 
  return slot;
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
close_osc_reader (int slot)
{
  /* FIXME: Implement. */
  reader_table[slot].used = 0;
  return 0;
}

static int
reset_osc_reader (int slot)
{
  return SW_HOST_NOT_SUPPORTED;
}


static int
osc_get_status (int slot, unsigned int *status)
{
  return SW_HOST_NOT_SUPPORTED;
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
      return SW_HOST_INV_VALUE;
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
          return SW_HOST_INV_VALUE;

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
              return SW_HOST_INV_VALUE;
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
      return SW_HOST_CARD_IO_ERROR;
    }

  if (*buflen < 2 || a.resplen > *buflen - 2)
    {
      log_error ("osc_send_apdu: provided buffer too short to store result\n");
      return SW_HOST_INV_VALUE;
    }
  memcpy (buffer, a.resp, a.resplen);
  buffer[a.resplen] = a.sw1;
  buffer[a.resplen+1] = a.sw2;
  *buflen = a.resplen + 2;
  return 0;
}

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

  reader_table[slot].close_reader = close_osc_reader;
  reader_table[slot].reset_reader = reset_osc_reader;
  reader_table[slot].get_status_reader = osc_get_status;
  reader_table[slot].send_apdu_reader = osc_send_apdu;
  reader_table[slot].dump_status_reader = NULL;

  dump_reader_status (slot); 
  return slot;
}

#endif /* HAVE_OPENSC */



#ifdef USE_G10CODE_RAPDU
/* 
     The Remote APDU Interface.

     This uses the Remote APDU protocol to contact a reader.

     The port number is actually an index into the list of ports as
     returned via the protocol.
 */


static int
rapdu_status_to_sw (int status)
{
  int rc;

  switch (status)
    {
    case RAPDU_STATUS_SUCCESS:  rc = 0; break;

    case RAPDU_STATUS_INVCMD:  
    case RAPDU_STATUS_INVPROT:  
    case RAPDU_STATUS_INVSEQ:  
    case RAPDU_STATUS_INVCOOKIE:
    case RAPDU_STATUS_INVREADER:  rc = SW_HOST_INV_VALUE;  break;

    case RAPDU_STATUS_TIMEOUT:  rc = SW_HOST_CARD_IO_ERROR; break;
    case RAPDU_STATUS_CARDIO:   rc = SW_HOST_CARD_IO_ERROR; break;
    case RAPDU_STATUS_NOCARD:   rc = SW_HOST_NO_CARD; break;
    case RAPDU_STATUS_CARDCHG:  rc = SW_HOST_NO_CARD; break;
    case RAPDU_STATUS_BUSY:     rc = SW_HOST_BUSY; break;
    case RAPDU_STATUS_NEEDRESET: rc = SW_HOST_CARD_INACTIVE; break;

    default: rc = SW_HOST_GENERAL_ERROR; break;
    }

  return rc;
}



static int
close_rapdu_reader (int slot)
{
  rapdu_release (reader_table[slot].rapdu.handle);
  reader_table[slot].used = 0;
  return 0;
}


static int
reset_rapdu_reader (int slot)
{
  int err;
  reader_table_t slotp;
  rapdu_msg_t msg = NULL;

  slotp = reader_table + slot;

  err = rapdu_send_cmd (slotp->rapdu.handle, RAPDU_CMD_RESET);
  if (err)
    {
      log_error ("sending rapdu command RESET failed: %s\n",
                err < 0 ? strerror (errno): rapdu_strerror (err));
      rapdu_msg_release (msg);
      return rapdu_status_to_sw (err);
    }
  err = rapdu_read_msg (slotp->rapdu.handle, &msg);
  if (err)
    {
      log_error ("receiving rapdu message failed: %s\n",
                err < 0 ? strerror (errno): rapdu_strerror (err));
      rapdu_msg_release (msg);
      return rapdu_status_to_sw (err);
    }
  if (msg->cmd != RAPDU_STATUS_SUCCESS || !msg->datalen)
    {
      int sw = rapdu_status_to_sw (msg->cmd);
      log_error ("rapdu command RESET failed: %s\n",
                 rapdu_strerror (msg->cmd));
      rapdu_msg_release (msg);
      return sw;
    }
  if (msg->datalen >= DIM (slotp->atr))
    {
      log_error ("ATR returned by the RAPDU layer is too large\n");
      rapdu_msg_release (msg);
      return SW_HOST_INV_VALUE; 
    }
  slotp->atrlen = msg->datalen;
  memcpy (slotp->atr, msg->data, msg->datalen);

  rapdu_msg_release (msg);
  return 0;
}


static int
my_rapdu_get_status (int slot, unsigned int *status)
{
  int err;
  reader_table_t slotp;
  rapdu_msg_t msg = NULL;
  int oldslot;

  slotp = reader_table + slot;

  oldslot = rapdu_set_reader (slotp->rapdu.handle, slot);
  err = rapdu_send_cmd (slotp->rapdu.handle, RAPDU_CMD_GET_STATUS);
  rapdu_set_reader (slotp->rapdu.handle, oldslot);
  if (err)
    {
      log_error ("sending rapdu command GET_STATUS failed: %s\n",
                err < 0 ? strerror (errno): rapdu_strerror (err));
      return rapdu_status_to_sw (err);
    }
  err = rapdu_read_msg (slotp->rapdu.handle, &msg);
  if (err)
    {
      log_error ("receiving rapdu message failed: %s\n",
                err < 0 ? strerror (errno): rapdu_strerror (err));
      rapdu_msg_release (msg);
      return rapdu_status_to_sw (err);
    }
  if (msg->cmd != RAPDU_STATUS_SUCCESS || !msg->datalen)
    {
      int sw = rapdu_status_to_sw (msg->cmd);
      log_error ("rapdu command GET_STATUS failed: %s\n",
                 rapdu_strerror (msg->cmd));
      rapdu_msg_release (msg);
      return sw;
    }
  *status = msg->data[0];

  rapdu_msg_release (msg);
  return 0;
}


/* Actually send the APDU of length APDULEN to SLOT and return a
   maximum of *BUFLEN data in BUFFER, the actual returned size will be
   set to BUFLEN.  Returns: OpenSC error code. */
static int
my_rapdu_send_apdu (int slot, unsigned char *apdu, size_t apdulen,
                    unsigned char *buffer, size_t *buflen)
{
  int err;
  reader_table_t slotp;
  rapdu_msg_t msg = NULL;
  size_t maxlen = *buflen;

  slotp = reader_table + slot;

  *buflen = 0;
  if (DBG_CARD_IO)
    log_printhex ("  APDU_data:", apdu, apdulen);

  if (apdulen < 4)
    {
      log_error ("rapdu_send_apdu: APDU is too short\n");
      return SW_HOST_INV_VALUE;
    }

  err = rapdu_send_apdu (slotp->rapdu.handle, apdu, apdulen);
  if (err)
    {
      log_error ("sending rapdu command APDU failed: %s\n",
                err < 0 ? strerror (errno): rapdu_strerror (err));
      rapdu_msg_release (msg);
      return rapdu_status_to_sw (err);
    }
  err = rapdu_read_msg (slotp->rapdu.handle, &msg);
  if (err)
    {
      log_error ("receiving rapdu message failed: %s\n",
                err < 0 ? strerror (errno): rapdu_strerror (err));
      rapdu_msg_release (msg);
      return rapdu_status_to_sw (err);
    }
  if (msg->cmd != RAPDU_STATUS_SUCCESS || !msg->datalen)
    {
      int sw = rapdu_status_to_sw (msg->cmd);
      log_error ("rapdu command APDU failed: %s\n",
                 rapdu_strerror (msg->cmd));
      rapdu_msg_release (msg);
      return sw;
    }
  
  if (msg->datalen > maxlen)
    {
      log_error ("rapdu response apdu too large\n");
      rapdu_msg_release (msg);
      return SW_HOST_INV_VALUE; 
    }

  *buflen = msg->datalen;
  memcpy (buffer, msg->data, msg->datalen);

  rapdu_msg_release (msg);
  return 0;
}

static int
open_rapdu_reader (int portno,
                   const unsigned char *cookie, size_t length,
                   int (*readfnc) (void *opaque,
                                   void *buffer, size_t size),
                   void *readfnc_value,
                   int (*writefnc) (void *opaque,
                                    const void *buffer, size_t size),
                   void *writefnc_value,
                   void (*closefnc) (void *opaque),
                   void *closefnc_value)
{
  int err;
  int slot;
  reader_table_t slotp;
  rapdu_msg_t msg = NULL;

  slot = new_reader_slot ();
  if (slot == -1)
    return -1;
  slotp = reader_table + slot;

  slotp->rapdu.handle = rapdu_new ();
  if (!slotp->rapdu.handle)
    {
      slotp->used = 0;
      return -1;
    }


  rapdu_set_iofunc (slotp->rapdu.handle,
                    readfnc, readfnc_value,
                    writefnc, writefnc_value,
                    closefnc, closefnc_value);
  rapdu_set_cookie (slotp->rapdu.handle, cookie, length);

  /* First try to get the current ATR, but if the card is inactive
     issue a reset instead.  */
  err = rapdu_send_cmd (slotp->rapdu.handle, RAPDU_CMD_GET_ATR);
  if (err == RAPDU_STATUS_NEEDRESET)
    err = rapdu_send_cmd (slotp->rapdu.handle, RAPDU_CMD_RESET);
  if (err)
    {
      log_info ("sending rapdu command GET_ATR/RESET failed: %s\n",
                err < 0 ? strerror (errno): rapdu_strerror (err));
      goto failure;
    }
  err = rapdu_read_msg (slotp->rapdu.handle, &msg);
  if (err)
    {
      log_info ("receiving rapdu message failed: %s\n",
                err < 0 ? strerror (errno): rapdu_strerror (err));
      goto failure;
    }
  if (msg->cmd != RAPDU_STATUS_SUCCESS || !msg->datalen)
    {
      log_info ("rapdu command GET ATR failed: %s\n",
                 rapdu_strerror (msg->cmd));
      goto failure;
    }
  if (msg->datalen >= DIM (slotp->atr))
    {
      log_error ("ATR returned by the RAPDU layer is too large\n");
      goto failure;
    }
  slotp->atrlen = msg->datalen;
  memcpy (slotp->atr, msg->data, msg->datalen);

  reader_table[slot].close_reader = close_rapdu_reader;
  reader_table[slot].reset_reader = reset_rapdu_reader;
  reader_table[slot].get_status_reader = my_rapdu_get_status;
  reader_table[slot].send_apdu_reader = my_rapdu_send_apdu;
  reader_table[slot].dump_status_reader = NULL;

  dump_reader_status (slot); 
  rapdu_msg_release (msg);
  return slot;

 failure:      
  rapdu_msg_release (msg);
  rapdu_release (slotp->rapdu.handle);
  slotp->used = 0;
  return -1;
}

#endif /*USE_G10CODE_RAPDU*/



/* 
       Driver Access
 */


static int
lock_slot (int slot)
{
#ifdef USE_GNU_PTH
  if (!pth_mutex_acquire (&reader_table[slot].lock, 0, NULL))
    {
      log_error ("failed to acquire apdu lock: %s\n", strerror (errno));
      return SW_HOST_LOCKING_FAILED;
    }
#endif /*USE_GNU_PTH*/
  return 0;
}

static int
trylock_slot (int slot)
{
#ifdef USE_GNU_PTH
  if (!pth_mutex_acquire (&reader_table[slot].lock, TRUE, NULL))
    {
      if (errno == EBUSY)
        return SW_HOST_BUSY;
      log_error ("failed to acquire apdu lock: %s\n", strerror (errno));
      return SW_HOST_LOCKING_FAILED;
    }
#endif /*USE_GNU_PTH*/
  return 0;
}

static void
unlock_slot (int slot)
{
#ifdef USE_GNU_PTH
  if (!pth_mutex_release (&reader_table[slot].lock))
    log_error ("failed to release apdu lock: %s\n", strerror (errno));
#endif /*USE_GNU_PTH*/
}


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
      int slot, i;
      const char *s;

      slot = open_ccid_reader (portstr);
      if (slot != -1)
        return slot; /* got one */

      /* If a CCID reader specification has been given, the user does
         not want a fallback to other drivers. */
      if (portstr)
        for (s=portstr, i=0; *s; s++)
          if (*s == ':' && (++i == 3))
            return -1;
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
              log_error ("apdu_open_reader: failed to open driver: %s\n",
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
#ifndef NEED_PCSC_WRAPPER
      void *handle;

      handle = dlopen (opt.pcsc_driver, RTLD_LAZY);
      if (!handle)
        {
          log_error ("apdu_open_reader: failed to open driver `%s': %s\n",
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
      pcsc_get_status_change = dlsym (handle, "SCardGetStatusChange");
#ifdef _WIN32
      if (!pcsc_get_status_change)
        pcsc_get_status_change = dlsym (handle, "SCardGetStatusChangeA");
#endif
      pcsc_connect           = dlsym (handle, "SCardConnect");
#ifdef _WIN32
      if (!pcsc_connect)
        pcsc_connect         = dlsym (handle, "SCardConnectA");
#endif
      pcsc_reconnect         = dlsym (handle, "SCardReconnect");
#ifdef _WIN32
      if (!pcsc_reconnect)
        pcsc_reconnect       = dlsym (handle, "SCardReconnectA");
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
          || !pcsc_get_status_change
          || !pcsc_connect          
          || !pcsc_reconnect
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
                     "(%d%d%d%d%d%d%d%d%d%d%d%d)\n",
                     !!pcsc_establish_context,
                     !!pcsc_release_context,  
                     !!pcsc_list_readers,     
                     !!pcsc_get_status_change,     
                     !!pcsc_connect,          
                     !!pcsc_reconnect,          
                     !!pcsc_disconnect,
                     !!pcsc_status,
                     !!pcsc_begin_transaction,
                     !!pcsc_end_transaction,
                     !!pcsc_transmit,         
                     !!pcsc_set_timeout );
          dlclose (handle);
          return -1;
        }
#endif /*!NEED_PCSC_WRAPPER*/  
      pcsc_api_loaded = 1;
    }

  return open_pcsc_reader (portstr);
}


/* Open an remote reader and return an internal slot number or -1 on
   error. This function is an alternative to apdu_open_reader and used
   with remote readers only.  Note that the supplied CLOSEFNC will
   only be called once and the slot will not be valid afther this.

   If PORTSTR is NULL we default to the first availabe port.
*/  
int
apdu_open_remote_reader (const char *portstr,
                         const unsigned char *cookie, size_t length,
                         int (*readfnc) (void *opaque,
                                         void *buffer, size_t size),
                         void *readfnc_value,
                         int (*writefnc) (void *opaque,
                                          const void *buffer, size_t size),
                         void *writefnc_value,
                         void (*closefnc) (void *opaque),
                         void *closefnc_value)
{
#ifdef USE_G10CODE_RAPDU
  return open_rapdu_reader (portstr? atoi (portstr) : 0,
                            cookie, length,
                            readfnc, readfnc_value,
                            writefnc, writefnc_value,
                            closefnc, closefnc_value);
#else
#ifdef _WIN32 
  errno = ENOENT;
#else
  errno = ENOSYS;
#endif
  return -1;
#endif
}


int
apdu_close_reader (int slot)
{
  if (slot < 0 || slot >= MAX_READER || !reader_table[slot].used )
    return SW_HOST_NO_DRIVER;
  if (reader_table[slot].close_reader)
    return reader_table[slot].close_reader (slot);
  return SW_HOST_NOT_SUPPORTED;
}

/* Shutdown a reader; that is basically the same as a close but keeps
   the handle ready for later use. A apdu_reset_header should be used
   to get it active again. */
int
apdu_shutdown_reader (int slot)
{
  if (slot < 0 || slot >= MAX_READER || !reader_table[slot].used )
    return SW_HOST_NO_DRIVER;
  if (reader_table[slot].shutdown_reader)
    return reader_table[slot].shutdown_reader (slot);
  return SW_HOST_NOT_SUPPORTED;
}

/* Enumerate all readers and return information on whether this reader
   is in use.  The caller should start with SLOT set to 0 and
   increment it with each call until an error is returned. */
int
apdu_enum_reader (int slot, int *used)
{
  if (slot < 0 || slot >= MAX_READER)
    return SW_HOST_NO_DRIVER;
  *used = reader_table[slot].used;
  return 0;
}

/* Do a reset for the card in reader at SLOT. */
int
apdu_reset (int slot)
{
  int sw;

  if (slot < 0 || slot >= MAX_READER || !reader_table[slot].used )
    return SW_HOST_NO_DRIVER;
  
  if ((sw = lock_slot (slot)))
    return sw;

  reader_table[slot].last_status = 0;
  if (reader_table[slot].reset_reader)
    sw = reader_table[slot].reset_reader (slot);

  if (!sw)
    {
      /* If we got to here we know that a card is present
         and usable.  Thus remember this.  */
      reader_table[slot].last_status = (1|2|4| 0x8000);
    }

  unlock_slot (slot);
  return sw;
}


/* Activate a card if it has not yet been done.  This is a kind of
   reset-if-required.  It is useful to test for presence of a card
   before issuing a bunch of apdu commands.  It does not wait on a
   locked card. */
int
apdu_activate (int slot)
{
  int sw;
  unsigned int s;

  if (slot < 0 || slot >= MAX_READER || !reader_table[slot].used )
    return SW_HOST_NO_DRIVER;
  
  if ((sw = trylock_slot (slot)))
    return sw;

  if (reader_table[slot].get_status_reader)
    sw = reader_table[slot].get_status_reader (slot, &s);

  if (!sw)
    {
      if (!(s & 2))  /* Card not present.  */
        sw = SW_HOST_NO_CARD;
      else if ( ((s & 2) && !(s & 4))
                || !reader_table[slot].atrlen )
        {
          /* We don't have an ATR or a card is present though inactive:
             do a reset now. */
          if (reader_table[slot].reset_reader)
            {
              reader_table[slot].last_status = 0;
              sw = reader_table[slot].reset_reader (slot);
              if (!sw)
                {
                  /* If we got to here we know that a card is present
                     and usable.  Thus remember this.  */
                  reader_table[slot].last_status = (1|2|4| 0x8000);
                }
            }
        }
    }
  
  unlock_slot (slot);
  return sw;
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


    
/* Retrieve the status for SLOT. The function does only wait for the
   card to become available if HANG is set to true. On success the
   bits in STATUS will be set to

     bit 0 = card present and usable
     bit 1 = card present
     bit 2 = card active
     bit 3 = card access locked [not yet implemented]

   For must application, testing bit 0 is sufficient.

   CHANGED will receive the value of the counter tracking the number
   of card insertions.  This value may be used to detect a card
   change.
*/
int
apdu_get_status (int slot, int hang,
                 unsigned int *status, unsigned int *changed)
{
  int sw;
  unsigned int s;

  if (slot < 0 || slot >= MAX_READER || !reader_table[slot].used )
    return SW_HOST_NO_DRIVER;

  if ((sw = hang? lock_slot (slot) : trylock_slot (slot)))
    return sw;

  if (reader_table[slot].get_status_reader)
    sw = reader_table[slot].get_status_reader (slot, &s);

  unlock_slot (slot);

  if (sw)
    {
      reader_table[slot].last_status = 0;
      return sw;
    }

  /* Keep track of changes.  We use one extra bit to test whether we
     have checked the status at least once. */
  if ( s != (reader_table[slot].last_status & 0x07ff)
       || !reader_table[slot].last_status )
    {
      reader_table[slot].change_counter++;
      /* Make sure that the ATR is invalid so that a reset will be by
         activate.  */
      reader_table[slot].atrlen = 0;
    }
  reader_table[slot].last_status = (s | 0x8000);

  if (status)
    *status = s;
  if (changed)
    *changed = reader_table[slot].change_counter;
  return 0;
}


/* Dispatcher for the actual send_apdu function. Note, that this
   function should be called in locked state. */
static int
send_apdu (int slot, unsigned char *apdu, size_t apdulen,
           unsigned char *buffer, size_t *buflen)
{
  if (slot < 0 || slot >= MAX_READER || !reader_table[slot].used )
    return SW_HOST_NO_DRIVER;

  if (reader_table[slot].send_apdu_reader)
    return reader_table[slot].send_apdu_reader (slot,
                                                apdu, apdulen,
                                                buffer, buflen);
  else
    return SW_HOST_NOT_SUPPORTED;
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
#define RESULTLEN 256
  unsigned char result[RESULTLEN+10]; /* 10 extra in case of bugs in
                                         the driver. */
  size_t resultlen;
  unsigned char apdu[5+256+1];
  size_t apdulen;
  int sw;
  long rc; /* we need a long here due to PC/SC. */

  if (slot < 0 || slot >= MAX_READER || !reader_table[slot].used )
    return SW_HOST_NO_DRIVER;

  if (DBG_CARD_IO)
    log_debug ("send apdu: c=%02X i=%02X p0=%02X p1=%02X lc=%d le=%d\n",
               class, ins, p0, p1, lc, le);

  if (lc != -1 && (lc > 255 || lc < 0))
    return SW_WRONG_LENGTH; 
  if (le != -1 && (le > 256 || le < 1))
    return SW_WRONG_LENGTH; 
  if ((!data && lc != -1) || (data && lc == -1))
    return SW_HOST_INV_VALUE;

  if ((sw = lock_slot (slot)))
    return sw;

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
  resultlen = RESULTLEN;
  rc = send_apdu (slot, apdu, apdulen, result, &resultlen);
  if (rc || resultlen < 2)
    {
      log_error ("apdu_send_simple(%d) failed: %s\n",
                 slot, apdu_strerror (rc));
      unlock_slot (slot);
      return rc? rc : SW_HOST_INCOMPLETE_CARD_RESPONSE;
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
            {
              unlock_slot (slot);
              return SW_HOST_OUT_OF_CORE;
            }
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
            {
              unlock_slot (slot);
              return SW_HOST_OUT_OF_CORE;
            }
          assert (resultlen < bufsize);
          memcpy (p, result, resultlen);
          p += resultlen;
        }

      do
        {
          int len = (sw & 0x00ff);
          
          if (DBG_CARD_IO)
            log_debug ("apdu_send_simple(%d): %d more bytes available\n",
                       slot, len);
          apdulen = 0;
          apdu[apdulen++] = class;
          apdu[apdulen++] = 0xC0;
          apdu[apdulen++] = 0;
          apdu[apdulen++] = 0;
          apdu[apdulen++] = len; 
          memset (apdu+apdulen, 0, sizeof (apdu) - apdulen);
          resultlen = RESULTLEN;
          rc = send_apdu (slot, apdu, apdulen, result, &resultlen);
          if (rc || resultlen < 2)
            {
              log_error ("apdu_send_simple(%d) for get response failed: %s\n",
                         slot, apdu_strerror (rc));
              unlock_slot (slot);
              return rc? rc : SW_HOST_INCOMPLETE_CARD_RESPONSE;
            }
          sw = (result[resultlen-2] << 8) | result[resultlen-1];
          resultlen -= 2;
          if (DBG_CARD_IO)
            {
              log_debug ("     more: sw=%04X  datalen=%d\n", sw, resultlen);
              if (!retbuf && (sw==SW_SUCCESS || (sw&0xff00)==SW_MORE_DATA))
                log_printhex ("     dump: ", result, resultlen);
            }

          if ((sw & 0xff00) == SW_MORE_DATA
              || sw == SW_SUCCESS
              || sw == SW_EOF_REACHED )
            {
              if (retbuf && resultlen)
                {
                  if (p - *retbuf + resultlen > bufsize)
                    {
                      bufsize += resultlen > 4096? resultlen: 4096;
                      tmp = xtryrealloc (*retbuf, bufsize);
                      if (!tmp)
                        {
                          unlock_slot (slot);
                          return SW_HOST_OUT_OF_CORE;
                        }
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

  unlock_slot (slot);

  if (DBG_CARD_IO && retbuf && sw == SW_SUCCESS)
    log_printhex ("      dump: ", *retbuf, *retbuflen);
 
  return sw;
#undef RESULTLEN
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


/* This is a more generic version of the apdu sending routine.  It
   takes an already formatted APDU in APDUDATA or length APDUDATALEN
   and returns the with the APDU including the status word.  With
   HANDLE_MORE set to true this function will handle the MORE DATA
   status and return all APDUs concatenated with one status word at
   the end.  The function does not return a regular status word but 0
   on success.  If the slot is locked, the fucntion returns
   immediately.*/
int 
apdu_send_direct (int slot, const unsigned char *apdudata, size_t apdudatalen,
                  int handle_more,
                  unsigned char **retbuf, size_t *retbuflen)
{
#define RESULTLEN 256
  unsigned char apdu[5+256+1];
  size_t apdulen;
  unsigned char result[RESULTLEN+10]; /* 10 extra in case of bugs in
                                         the driver. */
  size_t resultlen;
  int sw;
  long rc; /* we need a long here due to PC/SC. */
  int class;

  if (slot < 0 || slot >= MAX_READER || !reader_table[slot].used )
    return SW_HOST_NO_DRIVER;

  if ((sw = trylock_slot (slot)))
    return sw;

  /* We simply trucntate a too long APDU.  */
  if (apdudatalen > sizeof apdu)
    apdudatalen = sizeof apdu;
  apdulen = apdudatalen;
  memcpy (apdu, apdudata, apdudatalen);
  class = apdulen? *apdu : 0;


  rc = send_apdu (slot, apdu, apdulen, result, &resultlen);
  if (rc || resultlen < 2)
    {
      log_error ("apdu_send_direct(%d) failed: %s\n",
                 slot, apdu_strerror (rc));
      unlock_slot (slot);
      return rc? rc : SW_HOST_INCOMPLETE_CARD_RESPONSE;
    }
  sw = (result[resultlen-2] << 8) | result[resultlen-1];
  /* Store away the returned data but strip the statusword. */
  resultlen -= 2;
  if (DBG_CARD_IO)
    {
      log_debug (" response: sw=%04X  datalen=%d\n", sw, resultlen);
      if ( !retbuf && (sw == SW_SUCCESS || (sw & 0xff00) == SW_MORE_DATA))
        log_printhex ("     dump: ", result, resultlen);
    }

  if (handle_more && (sw & 0xff00) == SW_MORE_DATA)
    {
      unsigned char *p = NULL, *tmp;
      size_t bufsize = 4096;

      /* It is likely that we need to return much more data, so we
         start off with a large buffer. */
      if (retbuf)
        {
          *retbuf = p = xtrymalloc (bufsize + 2);
          if (!*retbuf)
            {
              unlock_slot (slot);
              return SW_HOST_OUT_OF_CORE;
            }
          assert (resultlen < bufsize);
          memcpy (p, result, resultlen);
          p += resultlen;
        }

      do
        {
          int len = (sw & 0x00ff);
          
          if (DBG_CARD_IO)
            log_debug ("apdu_send_direct(%d): %d more bytes available\n",
                       slot, len);
          apdulen = 0;
          apdu[apdulen++] = class;
          apdu[apdulen++] = 0xC0;
          apdu[apdulen++] = 0;
          apdu[apdulen++] = 0;
          apdu[apdulen++] = len; 
          memset (apdu+apdulen, 0, sizeof (apdu) - apdulen);
          resultlen = RESULTLEN;
          rc = send_apdu (slot, apdu, apdulen, result, &resultlen);
          if (rc || resultlen < 2)
            {
              log_error ("apdu_send_direct(%d) for get response failed: %s\n",
                         slot, apdu_strerror (rc));
              unlock_slot (slot);
              return rc ? rc : SW_HOST_INCOMPLETE_CARD_RESPONSE;
            }
          sw = (result[resultlen-2] << 8) | result[resultlen-1];
          resultlen -= 2;
          if (DBG_CARD_IO)
            {
              log_debug ("     more: sw=%04X  datalen=%d\n", sw, resultlen);
              if (!retbuf && (sw==SW_SUCCESS || (sw&0xff00)==SW_MORE_DATA))
                log_printhex ("     dump: ", result, resultlen);
            }

          if ((sw & 0xff00) == SW_MORE_DATA
              || sw == SW_SUCCESS
              || sw == SW_EOF_REACHED )
            {
              if (retbuf && resultlen)
                {
                  if (p - *retbuf + resultlen > bufsize)
                    {
                      bufsize += resultlen > 4096? resultlen: 4096;
                      tmp = xtryrealloc (*retbuf, bufsize + 2);
                      if (!tmp)
                        {
                          unlock_slot (slot);
                          return SW_HOST_OUT_OF_CORE;
                        }
                      p = tmp + (p - *retbuf);
                      *retbuf = tmp;
                    }
                  memcpy (p, result, resultlen);
                  p += resultlen;
                }
            }
          else
            log_info ("apdu_send_sdirect(%d) "
                      "got unexpected status %04X from get response\n",
                      slot, sw);
        }
      while ((sw & 0xff00) == SW_MORE_DATA);
      
      if (retbuf)
        {
          *retbuflen = p - *retbuf;
          tmp = xtryrealloc (*retbuf, *retbuflen + 2);
          if (tmp)
            *retbuf = tmp;
        }
    }
  else
    {
      if (retbuf)
        {
          *retbuf = xtrymalloc ((resultlen? resultlen : 1)+2);
          if (!*retbuf)
            {
              unlock_slot (slot);
              return SW_HOST_OUT_OF_CORE;
            }
          *retbuflen = resultlen;
          memcpy (*retbuf, result, resultlen);
        }
    }

  unlock_slot (slot);

  /* Append the status word - we reseved the two extra bytes while
     allocating the buffer. */
  if (retbuf)
    {
      (*retbuf)[(*retbuflen)++] = (sw >> 8);
      (*retbuf)[(*retbuflen)++] = sw;
    }

  if (DBG_CARD_IO && retbuf)
    log_printhex ("      dump: ", *retbuf, *retbuflen);
 
  return 0;
#undef RESULTLEN
}


