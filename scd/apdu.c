/* apdu.c - ISO 7816 APDU functions and low level I/O
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
 * along with this program; if not, see <http://www.gnu.org/licenses/>.
 */

/* NOTE: This module is also used by other software, thus the use of
   the macro USE_GNU_PTH is mandatory.  For GnuPG this macro is
   guaranteed to be defined true. */

#include <config.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <signal.h>
#ifdef USE_GNU_PTH
# include <unistd.h>
# include <fcntl.h>
# include <pth.h>
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
#include "dynload.h"
#include "cardglue.h"
#else /* GNUPG_MAJOR_VERSION != 1 */
#include "scdaemon.h"
#include "exechelp.h"
#endif /* GNUPG_MAJOR_VERSION != 1 */

#include "iso7816.h"
#include "apdu.h"
#include "ccid-driver.h"

/* Due to conflicting use of threading libraries we usually can't link
   against libpcsclite.   Instead we use a wrapper program.  */
#ifdef USE_GNU_PTH
#if !defined(HAVE_W32_SYSTEM) && !defined(__CYGWIN__)
#define NEED_PCSC_WRAPPER 1
#endif
#endif


#define MAX_READER 4 /* Number of readers we support concurrently. */


#if defined(_WIN32) || defined(__CYGWIN__)
#define DLSTDCALL __stdcall
#else
#define DLSTDCALL
#endif

#if defined(__APPLE__) || defined(_WIN32) || defined(__CYGWIN__)
typedef unsigned int pcsc_dword_t;
#else
typedef unsigned long pcsc_dword_t;
#endif

/* A structure to collect information pertaining to one reader
   slot. */
struct reader_table_s {
  int used;            /* True if slot is used. */
  unsigned short port; /* Port number:  0 = unused, 1 - dev/tty */

  /* Function pointers intialized to the various backends.  */
  int (*connect_card)(int);
  int (*disconnect_card)(int);
  int (*close_reader)(int);
  int (*shutdown_reader)(int);
  int (*reset_reader)(int);
  int (*get_status_reader)(int, unsigned int *);
  int (*send_apdu_reader)(int,unsigned char *,size_t,
                          unsigned char *, size_t *, pininfo_t *);
  int (*check_pinpad)(int, int, pininfo_t *);
  void (*dump_status_reader)(int);
  int (*set_progress_cb)(int, gcry_handler_progress_t, void*);
  int (*pinpad_verify)(int, int, int, int, int, pininfo_t *);
  int (*pinpad_modify)(int, int, int, int, int, pininfo_t *);

  struct {
    ccid_driver_t handle;
  } ccid;
  struct {
    long context;
    long card;
    pcsc_dword_t protocol;
    pcsc_dword_t verify_ioctl;
    pcsc_dword_t modify_ioctl;
#ifdef NEED_PCSC_WRAPPER
    int req_fd;
    int rsp_fd;
    pid_t pid;
#endif /*NEED_PCSC_WRAPPER*/
  } pcsc;
#ifdef USE_G10CODE_RAPDU
  struct {
    rapdu_t handle;
  } rapdu;
#endif /*USE_G10CODE_RAPDU*/
  char *rdrname;     /* Name of the connected reader or NULL if unknown. */
  int any_status;    /* True if we have seen any status.  */
  int last_status;
  int status;
  int is_t0;         /* True if we know that we are running T=0. */
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

/* Some PC/SC error codes.  */
#define PCSC_E_CANCELLED               0x80100002
#define PCSC_E_CANT_DISPOSE            0x8010000E
#define PCSC_E_INSUFFICIENT_BUFFER     0x80100008
#define PCSC_E_INVALID_ATR             0x80100015
#define PCSC_E_INVALID_HANDLE          0x80100003
#define PCSC_E_INVALID_PARAMETER       0x80100004
#define PCSC_E_INVALID_TARGET          0x80100005
#define PCSC_E_INVALID_VALUE           0x80100011
#define PCSC_E_NO_MEMORY               0x80100006
#define PCSC_E_UNKNOWN_READER          0x80100009
#define PCSC_E_TIMEOUT                 0x8010000A
#define PCSC_E_SHARING_VIOLATION       0x8010000B
#define PCSC_E_NO_SMARTCARD            0x8010000C
#define PCSC_E_UNKNOWN_CARD            0x8010000D
#define PCSC_E_PROTO_MISMATCH          0x8010000F
#define PCSC_E_NOT_READY               0x80100010
#define PCSC_E_SYSTEM_CANCELLED        0x80100012
#define PCSC_E_NOT_TRANSACTED          0x80100016
#define PCSC_E_READER_UNAVAILABLE      0x80100017
#define PCSC_E_NO_SERVICE              0x8010001D
#define PCSC_W_REMOVED_CARD            0x80100069

#define CM_IOCTL_GET_FEATURE_REQUEST (0x42000000 + 3400)
#define FEATURE_VERIFY_PIN_DIRECT        0x06
#define FEATURE_MODIFY_PIN_DIRECT        0x07


/* The PC/SC error is defined as a long as per specs.  Due to left
   shifts bit 31 will get sign extended.  We use this mask to fix
   it. */
#define PCSC_ERR_MASK(a)  ((a) & 0xffffffff)


struct pcsc_io_request_s
{
  unsigned long protocol;
  unsigned long pci_len;
};

typedef struct pcsc_io_request_s *pcsc_io_request_t;

#ifdef __APPLE__
#pragma pack(1)
#endif

struct pcsc_readerstate_s
{
  const char *reader;
  void *user_data;
  pcsc_dword_t current_state;
  pcsc_dword_t event_state;
  pcsc_dword_t atrlen;
  unsigned char atr[33];
};

#ifdef __APPLE__
#pragma pack()
#endif

typedef struct pcsc_readerstate_s *pcsc_readerstate_t;

long (* DLSTDCALL pcsc_establish_context) (pcsc_dword_t scope,
                                           const void *reserved1,
                                           const void *reserved2,
                                           long *r_context);
long (* DLSTDCALL pcsc_release_context) (long context);
long (* DLSTDCALL pcsc_list_readers) (long context,
                                      const char *groups,
                                      char *readers, pcsc_dword_t*readerslen);
long (* DLSTDCALL pcsc_get_status_change) (long context,
                                           pcsc_dword_t timeout,
                                           pcsc_readerstate_t readerstates,
                                           pcsc_dword_t nreaderstates);
long (* DLSTDCALL pcsc_connect) (long context,
                                 const char *reader,
                                 pcsc_dword_t share_mode,
                                 pcsc_dword_t preferred_protocols,
                                 long *r_card,
                                 pcsc_dword_t *r_active_protocol);
long (* DLSTDCALL pcsc_reconnect) (long card,
                                   pcsc_dword_t share_mode,
                                   pcsc_dword_t preferred_protocols,
                                   pcsc_dword_t initialization,
                                   pcsc_dword_t *r_active_protocol);
long (* DLSTDCALL pcsc_disconnect) (long card,
                                    pcsc_dword_t disposition);
long (* DLSTDCALL pcsc_status) (long card,
                                char *reader, pcsc_dword_t *readerlen,
                                pcsc_dword_t *r_state,
                                pcsc_dword_t *r_protocol,
                                unsigned char *atr, pcsc_dword_t *atrlen);
long (* DLSTDCALL pcsc_begin_transaction) (long card);
long (* DLSTDCALL pcsc_end_transaction) (long card,
                                         pcsc_dword_t disposition);
long (* DLSTDCALL pcsc_transmit) (long card,
                                  const pcsc_io_request_t send_pci,
                                  const unsigned char *send_buffer,
                                  pcsc_dword_t send_len,
                                  pcsc_io_request_t recv_pci,
                                  unsigned char *recv_buffer,
                                  pcsc_dword_t *recv_len);
long (* DLSTDCALL pcsc_set_timeout) (long context,
                                     pcsc_dword_t timeout);
long (* DLSTDCALL pcsc_control) (long card,
                                 pcsc_dword_t control_code,
                                 const void *send_buffer,
                                 pcsc_dword_t send_len,
                                 void *recv_buffer,
                                 pcsc_dword_t recv_len,
                                 pcsc_dword_t *bytes_returned);


/*  Prototypes.  */
static int pcsc_get_status (int slot, unsigned int *status);
static int reset_pcsc_reader (int slot);
static int apdu_get_status_internal (int slot, int hang, int no_atr_reset,
                                     unsigned int *status,
                                     unsigned int *changed);
static int check_pcsc_pinpad (int slot, int command, pininfo_t *pininfo);
static int pcsc_pinpad_verify (int slot, int class, int ins, int p0, int p1,
                               pininfo_t *pininfo);
static int pcsc_pinpad_modify (int slot, int class, int ins, int p0, int p1,
                               pininfo_t *pininfo);



/*
      Helper
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


/* Find an unused reader slot for PORTSTR and put it into the reader
   table.  Return -1 on error or the index into the reader table.
   Acquire slot's lock on successful return.  Caller needs to unlock it.  */
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
  if (lock_slot (reader))
    {
      log_error ("error locking mutex: %s\n", strerror (errno));
      return -1;
    }
  reader_table[reader].connect_card = NULL;
  reader_table[reader].disconnect_card = NULL;
  reader_table[reader].close_reader = NULL;
  reader_table[reader].shutdown_reader = NULL;
  reader_table[reader].reset_reader = NULL;
  reader_table[reader].get_status_reader = NULL;
  reader_table[reader].send_apdu_reader = NULL;
  reader_table[reader].check_pinpad = check_pcsc_pinpad;
  reader_table[reader].dump_status_reader = NULL;
  reader_table[reader].set_progress_cb = NULL;
  reader_table[reader].pinpad_verify = pcsc_pinpad_verify;
  reader_table[reader].pinpad_modify = pcsc_pinpad_modify;

  reader_table[reader].used = 1;
  reader_table[reader].any_status = 0;
  reader_table[reader].last_status = 0;
  reader_table[reader].is_t0 = 1;
#ifdef NEED_PCSC_WRAPPER
  reader_table[reader].pcsc.req_fd = -1;
  reader_table[reader].pcsc.rsp_fd = -1;
  reader_table[reader].pcsc.pid = (pid_t)(-1);
#endif
  reader_table[reader].pcsc.verify_ioctl = 0;
  reader_table[reader].pcsc.modify_ioctl = 0;

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
    case SW_HOST_NO_PINPAD: return "no pinpad";
    case SW_HOST_ALREADY_CONNECTED: return "already connected";
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
    case SW_BAD_LC         : return "bad Lc";
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
  (void)slot;
  /* The status we returned is wrong but we don't care becuase ctAPI
     is not anymore required.  */
  *status = APDU_CARD_USABLE|APDU_CARD_PRESENT|APDU_CARD_ACTIVE;
  return 0;
}

/* Actually send the APDU of length APDULEN to SLOT and return a
   maximum of *BUFLEN data in BUFFER, the actual retruned size will be
   set to BUFLEN.  Returns: CT API error code. */
static int
ct_send_apdu (int slot, unsigned char *apdu, size_t apdulen,
              unsigned char *buffer, size_t *buflen, pininfo_t *pininfo)
{
  int rc;
  unsigned char dad[1], sad[1];
  unsigned short ctbuflen;

  (void)pininfo;

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
      unlock_slot (reader);
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
  reader_table[reader].check_pinpad = NULL;
  reader_table[reader].dump_status_reader = ct_dump_reader_status;
  reader_table[reader].pinpad_verify = NULL;
  reader_table[reader].pinpad_modify = NULL;

  dump_reader_status (reader);
  unlock_slot (reader);
  return reader;
}


/*
       PC/SC Interface
 */

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
# ifdef HAVE_W32_SYSTEM
#  error Cannot use pth_read here because it expects a system HANDLE.
# endif
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

/* Map PC/SC error codes to our special host status words.  */
static int
pcsc_error_to_sw (long ec)
{
  int rc;

  switch ( PCSC_ERR_MASK (ec) )
    {
    case 0:  rc = 0; break;

    case PCSC_E_CANCELLED:           rc = SW_HOST_ABORTED; break;
    case PCSC_E_NO_MEMORY:           rc = SW_HOST_OUT_OF_CORE; break;
    case PCSC_E_TIMEOUT:             rc = SW_HOST_CARD_IO_ERROR; break;
    case PCSC_E_UNKNOWN_READER:      rc = SW_HOST_NO_READER; break;
    case PCSC_E_SHARING_VIOLATION:   rc = SW_HOST_LOCKING_FAILED; break;
    case PCSC_E_NO_SMARTCARD:        rc = SW_HOST_NO_CARD; break;
    case PCSC_W_REMOVED_CARD:        rc = SW_HOST_NO_CARD; break;

    case PCSC_E_INVALID_TARGET:
    case PCSC_E_INVALID_VALUE:
    case PCSC_E_INVALID_HANDLE:
    case PCSC_E_INVALID_PARAMETER:
    case PCSC_E_INSUFFICIENT_BUFFER: rc = SW_HOST_INV_VALUE; break;

    default:  rc = SW_HOST_GENERAL_ERROR; break;
    }

  return rc;
}

static void
dump_pcsc_reader_status (int slot)
{
  if (reader_table[slot].pcsc.card)
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
  else
    log_info ("reader slot %d: not connected\n", slot);
}


#ifndef NEED_PCSC_WRAPPER
static int
pcsc_get_status_direct (int slot, unsigned int *status)
{
  long err;
  struct pcsc_readerstate_s rdrstates[1];

  memset (rdrstates, 0, sizeof *rdrstates);
  rdrstates[0].reader = reader_table[slot].rdrname;
  rdrstates[0].current_state = PCSC_STATE_UNAWARE;
  err = pcsc_get_status_change (reader_table[slot].pcsc.context,
                                0,
                                rdrstates, 1);
  if (err == PCSC_E_TIMEOUT)
    err = 0; /* Timeout is no error error here. */
  if (err)
    {
      log_error ("pcsc_get_status_change failed: %s (0x%lx)\n",
                 pcsc_error_string (err), err);
      return pcsc_error_to_sw (err);
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
    {
      *status |= APDU_CARD_PRESENT;
      if ( !(rdrstates[0].event_state & PCSC_STATE_MUTE) )
	*status |= APDU_CARD_ACTIVE;
    }
#ifndef HAVE_W32_SYSTEM
  /* We indicate a useful card if it is not in use by another
     application.  This is because we only use exclusive access
     mode.  */
  if ( (*status & (APDU_CARD_PRESENT|APDU_CARD_ACTIVE))
       == (APDU_CARD_PRESENT|APDU_CARD_ACTIVE)
       && !(rdrstates[0].event_state & PCSC_STATE_INUSE) )
    *status |= APDU_CARD_USABLE;
#else
  /* Some winscard drivers may set EXCLUSIVE and INUSE at the same
     time when we are the only user (SCM SCR335) under Windows.  */
  if ((*status & (APDU_CARD_PRESENT|APDU_CARD_ACTIVE))
      == (APDU_CARD_PRESENT|APDU_CARD_ACTIVE))
    *status |= APDU_CARD_USABLE;
#endif

  return 0;
}
#endif /*!NEED_PCSC_WRAPPER*/


#ifdef NEED_PCSC_WRAPPER
static int
pcsc_get_status_wrapped (int slot, unsigned int *status)
{
  long err;
  reader_table_t slotp;
  size_t len, full_len;
  int i, n;
  unsigned char msgbuf[9];
  unsigned char buffer[16];
  int sw = SW_HOST_CARD_IO_ERROR;

  slotp = reader_table + slot;

  if (slotp->pcsc.req_fd == -1
      || slotp->pcsc.rsp_fd == -1
      || slotp->pcsc.pid == (pid_t)(-1) )
    {
      log_error ("pcsc_get_status: pcsc-wrapper not running\n");
      return sw;
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
  err = PCSC_ERR_MASK ((msgbuf[5] << 24) | (msgbuf[6] << 16)
                       | (msgbuf[7] << 8 ) | msgbuf[8]);
  if (err)
    {
      log_error ("pcsc_status failed: %s (0x%lx)\n",
                 pcsc_error_string (err), err);
      /* This is a proper error code, so return immediately.  */
      return pcsc_error_to_sw (err);
    }

  full_len = len;

  /* The current version returns 3 words but we allow also for old
     versions returning only 2 words. */
  n = 12 < len ? 12 : len;
  if ((i=readn (slotp->pcsc.rsp_fd, buffer, n, &len))
      || (len != 8 && len != 12))
    {
      log_error ("error receiving PC/SC STATUS response: %s\n",
                 i? strerror (errno) : "premature EOF");
      goto command_failed;
    }

  slotp->is_t0 = (len == 12 && !!(buffer[11] & PCSC_PROTOCOL_T0));


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
  return sw;
}
#endif /*NEED_PCSC_WRAPPER*/


static int
pcsc_get_status (int slot, unsigned int *status)
{
#ifdef NEED_PCSC_WRAPPER
  return pcsc_get_status_wrapped (slot, status);
#else
  return pcsc_get_status_direct (slot, status);
#endif
}


#ifndef NEED_PCSC_WRAPPER
static int
pcsc_send_apdu_direct (int slot, unsigned char *apdu, size_t apdulen,
                       unsigned char *buffer, size_t *buflen,
                       pininfo_t *pininfo)
{
  long err;
  struct pcsc_io_request_s send_pci;
  pcsc_dword_t recv_len;

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

  return pcsc_error_to_sw (err);
}
#endif /*!NEED_PCSC_WRAPPER*/


#ifdef NEED_PCSC_WRAPPER
static int
pcsc_send_apdu_wrapped (int slot, unsigned char *apdu, size_t apdulen,
                        unsigned char *buffer, size_t *buflen,
                        pininfo_t *pininfo)
{
  long err;
  reader_table_t slotp;
  size_t len, full_len;
  int i, n;
  unsigned char msgbuf[9];
  int sw = SW_HOST_CARD_IO_ERROR;

  (void)pininfo;

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
      return sw;
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
  err = PCSC_ERR_MASK ((msgbuf[5] << 24) | (msgbuf[6] << 16)
                       | (msgbuf[7] << 8 ) | msgbuf[8]);
  if (err)
    {
      log_error ("pcsc_transmit failed: %s (0x%lx)\n",
                 pcsc_error_string (err), err);
      return pcsc_error_to_sw (err);
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
      protocol running.  */
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
  return sw;
}
#endif /*NEED_PCSC_WRAPPER*/


/* Send the APDU of length APDULEN to SLOT and return a maximum of
   *BUFLEN data in BUFFER, the actual returned size will be stored at
   BUFLEN.  Returns: A status word. */
static int
pcsc_send_apdu (int slot, unsigned char *apdu, size_t apdulen,
                unsigned char *buffer, size_t *buflen,
                pininfo_t *pininfo)
{
#ifdef NEED_PCSC_WRAPPER
  return pcsc_send_apdu_wrapped (slot, apdu, apdulen, buffer, buflen, pininfo);
#else
  return pcsc_send_apdu_direct (slot, apdu, apdulen, buffer, buflen, pininfo);
#endif
}


#ifndef NEED_PCSC_WRAPPER
static int
control_pcsc_direct (int slot, pcsc_dword_t ioctl_code,
                     const unsigned char *cntlbuf, size_t len,
                     unsigned char *buffer, pcsc_dword_t *buflen)
{
  long err;

  err = pcsc_control (reader_table[slot].pcsc.card, ioctl_code,
                      cntlbuf, len, buffer, *buflen, buflen);
  if (err)
    {
      log_error ("pcsc_control failed: %s (0x%lx)\n",
                 pcsc_error_string (err), err);
      return pcsc_error_to_sw (err);
    }

  return 0;
}
#endif /*!NEED_PCSC_WRAPPER*/


#ifdef NEED_PCSC_WRAPPER
static int
control_pcsc_wrapped (int slot, pcsc_dword_t ioctl_code,
                      const unsigned char *cntlbuf, size_t len,
                      unsigned char *buffer, pcsc_dword_t *buflen)
{
  long err = PCSC_E_NOT_TRANSACTED;
  reader_table_t slotp;
  unsigned char msgbuf[9];
  int i, n;
  size_t full_len;

  slotp = reader_table + slot;

  msgbuf[0] = 0x06; /* CONTROL command. */
  msgbuf[1] = ((len + 4) >> 24);
  msgbuf[2] = ((len + 4) >> 16);
  msgbuf[3] = ((len + 4) >>  8);
  msgbuf[4] = ((len + 4)      );
  msgbuf[5] = (ioctl_code >> 24);
  msgbuf[6] = (ioctl_code >> 16);
  msgbuf[7] = (ioctl_code >>  8);
  msgbuf[8] = (ioctl_code      );
  if ( writen (slotp->pcsc.req_fd, msgbuf, 9)
       || writen (slotp->pcsc.req_fd, cntlbuf, len))
    {
      log_error ("error sending PC/SC CONTROL request: %s\n",
                 strerror (errno));
      goto command_failed;
    }

  /* Read the response. */
  if ((i=readn (slotp->pcsc.rsp_fd, msgbuf, 9, &len)) || len != 9)
    {
      log_error ("error receiving PC/SC CONTROL response: %s\n",
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
  err = PCSC_ERR_MASK ((msgbuf[5] << 24) | (msgbuf[6] << 16)
                       | (msgbuf[7] << 8 ) | msgbuf[8]);
  if (err)
    {
      log_error ("pcsc_control failed: %s (0x%lx)\n",
                 pcsc_error_string (err), err);
      return pcsc_error_to_sw (err);
    }

  full_len = len;

  n = *buflen < len ? *buflen : len;
  if ((i=readn (slotp->pcsc.rsp_fd, buffer, n, &len)) || len != n)
    {
      log_error ("error receiving PC/SC CONTROL response: %s\n",
                 i? strerror (errno) : "premature EOF");
      goto command_failed;
    }
  *buflen = n;

  full_len -= len;
  if (full_len)
    {
      log_error ("pcsc_send_apdu: provided buffer too short - truncated\n");
      err = PCSC_E_INVALID_VALUE;
    }
  /* We need to read any rest of the response, to keep the
     protocol running.  */
  while (full_len)
    {
      unsigned char dummybuf[128];

      n = full_len < DIM (dummybuf) ? full_len : DIM (dummybuf);
      if ((i=readn (slotp->pcsc.rsp_fd, dummybuf, n, &len)) || len != n)
        {
          log_error ("error receiving PC/SC CONTROL response: %s\n",
                     i? strerror (errno) : "premature EOF");
          goto command_failed;
        }
      full_len -= n;
    }

  if (!err)
    return 0;

 command_failed:
  close (slotp->pcsc.req_fd);
  close (slotp->pcsc.rsp_fd);
  slotp->pcsc.req_fd = -1;
  slotp->pcsc.rsp_fd = -1;
  kill (slotp->pcsc.pid, SIGTERM);
  slotp->pcsc.pid = (pid_t)(-1);
  slotp->used = 0;
  return pcsc_error_to_sw (err);
}
#endif /*NEED_PCSC_WRAPPER*/



/* Do some control with the value of IOCTL_CODE to the card inserted
   to SLOT.  Input buffer is specified by CNTLBUF of length LEN.
   Output buffer is specified by BUFFER of length *BUFLEN, and the
   actual output size will be stored at BUFLEN.  Returns: A status word.
   This routine is used for PIN pad input support.  */
static int
control_pcsc (int slot, pcsc_dword_t ioctl_code,
              const unsigned char *cntlbuf, size_t len,
              unsigned char *buffer, pcsc_dword_t *buflen)
{
#ifdef NEED_PCSC_WRAPPER
  return control_pcsc_wrapped (slot, ioctl_code, cntlbuf, len, buffer, buflen);
#else
  return control_pcsc_direct (slot, ioctl_code, cntlbuf, len, buffer, buflen);
#endif
}


#ifndef NEED_PCSC_WRAPPER
static int
close_pcsc_reader_direct (int slot)
{
  pcsc_release_context (reader_table[slot].pcsc.context);
  xfree (reader_table[slot].rdrname);
  reader_table[slot].rdrname = NULL;
  reader_table[slot].used = 0;
  return 0;
}
#endif /*!NEED_PCSC_WRAPPER*/


#ifdef NEED_PCSC_WRAPPER
static int
close_pcsc_reader_wrapped (int slot)
{
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
  err = PCSC_ERR_MASK ((msgbuf[5] << 24) | (msgbuf[6] << 16)
                       | (msgbuf[7] << 8 ) | msgbuf[8]);
  if (err)
    log_error ("pcsc_close failed: %s (0x%lx)\n",
               pcsc_error_string (err), err);

  /* We will close the wrapper in any case - errors are merely
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
}
#endif /*NEED_PCSC_WRAPPER*/


static int
close_pcsc_reader (int slot)
{
#ifdef NEED_PCSC_WRAPPER
  return close_pcsc_reader_wrapped (slot);
#else
  return close_pcsc_reader_direct (slot);
#endif
}


/* Connect a PC/SC card.  */
#ifndef NEED_PCSC_WRAPPER
static int
connect_pcsc_card (int slot)
{
  long err;

  assert (slot >= 0 && slot < MAX_READER);

  if (reader_table[slot].pcsc.card)
    return SW_HOST_ALREADY_CONNECTED;

  reader_table[slot].atrlen = 0;
  reader_table[slot].last_status = 0;
  reader_table[slot].is_t0 = 0;

  err = pcsc_connect (reader_table[slot].pcsc.context,
                      reader_table[slot].rdrname,
                      PCSC_SHARE_EXCLUSIVE,
                      PCSC_PROTOCOL_T0|PCSC_PROTOCOL_T1,
                      &reader_table[slot].pcsc.card,
                      &reader_table[slot].pcsc.protocol);
  if (err)
    {
      reader_table[slot].pcsc.card = 0;
      if (err != PCSC_E_NO_SMARTCARD)
        log_error ("pcsc_connect failed: %s (0x%lx)\n",
                   pcsc_error_string (err), err);
    }
  else
    {
      char reader[250];
      pcsc_dword_t readerlen, atrlen;
      long card_state, card_protocol;

      atrlen = DIM (reader_table[0].atr);
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
          if (atrlen > DIM (reader_table[0].atr))
            log_bug ("ATR returned by pcsc_status is too large\n");
          reader_table[slot].atrlen = atrlen;
          /* If we got to here we know that a card is present
             and usable.  Remember this.  */
          reader_table[slot].last_status = (   APDU_CARD_USABLE
                                             | APDU_CARD_PRESENT
                                             | APDU_CARD_ACTIVE);
          reader_table[slot].is_t0 = !!(card_protocol & PCSC_PROTOCOL_T0);
        }
    }

  dump_reader_status (slot);
  return pcsc_error_to_sw (err);
}
#endif /*!NEED_PCSC_WRAPPER*/


/* Disconnect a PC/SC card.  Note that this succeeds even if the card
   is not connected.  */
#ifndef NEED_PCSC_WRAPPER
static int
disconnect_pcsc_card (int slot)
{
  long err;

  assert (slot >= 0 && slot < MAX_READER);

  if (!reader_table[slot].pcsc.card)
    return 0;

  err = pcsc_disconnect (reader_table[slot].pcsc.card, PCSC_LEAVE_CARD);
  if (err)
    {
      log_error ("pcsc_disconnect failed: %s (0x%lx)\n",
                 pcsc_error_string (err), err);
      return SW_HOST_CARD_IO_ERROR;
    }
  reader_table[slot].pcsc.card = 0;
  return 0;
}
#endif /*!NEED_PCSC_WRAPPER*/


#ifndef NEED_PCSC_WRAPPER
static int
reset_pcsc_reader_direct (int slot)
{
  int sw;

  sw = disconnect_pcsc_card (slot);
  if (!sw)
    sw = connect_pcsc_card (slot);

  return sw;
}
#endif /*NEED_PCSC_WRAPPER*/


#ifdef NEED_PCSC_WRAPPER
static int
reset_pcsc_reader_wrapped (int slot)
{
  long err;
  reader_table_t slotp;
  size_t len;
  int i, n;
  unsigned char msgbuf[9];
  unsigned int dummy_status;
  int sw = SW_HOST_CARD_IO_ERROR;

  slotp = reader_table + slot;

  if (slotp->pcsc.req_fd == -1
      || slotp->pcsc.rsp_fd == -1
      || slotp->pcsc.pid == (pid_t)(-1) )
    {
      log_error ("pcsc_get_status: pcsc-wrapper not running\n");
      return sw;
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
      log_error ("PC/SC returned a too large ATR (len=%lx)\n",
                 (unsigned long)len);
      sw = SW_HOST_GENERAL_ERROR;
      goto command_failed;
    }
  err = PCSC_ERR_MASK ((msgbuf[5] << 24) | (msgbuf[6] << 16)
                       | (msgbuf[7] << 8 ) | msgbuf[8]);
  if (err)
    {
      log_error ("PC/SC RESET failed: %s (0x%lx)\n",
                 pcsc_error_string (err), err);
      /* If the error code is no smart card, we should not considere
         this a major error and close the wrapper.  */
      sw = pcsc_error_to_sw (err);
      if (err == PCSC_E_NO_SMARTCARD)
        return sw;
      goto command_failed;
    }

  /* The open function may return a zero for the ATR length to
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

  /* Read the status so that IS_T0 will be set. */
  pcsc_get_status (slot, &dummy_status);

  return 0;

 command_failed:
  close (slotp->pcsc.req_fd);
  close (slotp->pcsc.rsp_fd);
  slotp->pcsc.req_fd = -1;
  slotp->pcsc.rsp_fd = -1;
  kill (slotp->pcsc.pid, SIGTERM);
  slotp->pcsc.pid = (pid_t)(-1);
  slotp->used = 0;
  return sw;
}
#endif /* !NEED_PCSC_WRAPPER */


/* Send an PC/SC reset command and return a status word on error or 0
   on success. */
static int
reset_pcsc_reader (int slot)
{
#ifdef NEED_PCSC_WRAPPER
  return reset_pcsc_reader_wrapped (slot);
#else
  return reset_pcsc_reader_direct (slot);
#endif
}


/* Open the PC/SC reader without using the wrapper.  Returns -1 on
   error or a slot number for the reader.  */
#ifndef NEED_PCSC_WRAPPER
static int
open_pcsc_reader_direct (const char *portstr)
{
  long err;
  int slot;
  char *list = NULL;
  pcsc_dword_t nreader, listlen;
  char *p;

  slot = new_reader_slot ();
  if (slot == -1)
    return -1;

  /* Fixme: Allocating a context for each slot is not required.  One
     global context should be sufficient.  */
  err = pcsc_establish_context (PCSC_SCOPE_SYSTEM, NULL, NULL,
                                &reader_table[slot].pcsc.context);
  if (err)
    {
      log_error ("pcsc_establish_context failed: %s (0x%lx)\n",
                 pcsc_error_string (err), err);
      reader_table[slot].used = 0;
      unlock_slot (slot);
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
	  unlock_slot (slot);
          return -1 /*SW_HOST_OUT_OF_CORE*/;
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
      unlock_slot (slot);
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
      unlock_slot (slot);
      return -1;
    }
  strcpy (reader_table[slot].rdrname, portstr? portstr : list);
  xfree (list);
  list = NULL;

  reader_table[slot].pcsc.card = 0;
  reader_table[slot].atrlen = 0;
  reader_table[slot].last_status = 0;

  reader_table[slot].connect_card = connect_pcsc_card;
  reader_table[slot].disconnect_card = disconnect_pcsc_card;
  reader_table[slot].close_reader = close_pcsc_reader;
  reader_table[slot].reset_reader = reset_pcsc_reader;
  reader_table[slot].get_status_reader = pcsc_get_status;
  reader_table[slot].send_apdu_reader = pcsc_send_apdu;
  reader_table[slot].dump_status_reader = dump_pcsc_reader_status;

  dump_reader_status (slot);
  unlock_slot (slot);
  return slot;
}
#endif /*!NEED_PCSC_WRAPPER */


/* Open the PC/SC reader using the pcsc_wrapper program.  This is
   needed to cope with different thread models and other peculiarities
   of libpcsclite. */
#ifdef NEED_PCSC_WRAPPER
static int
open_pcsc_reader_wrapped (const char *portstr)
{
  int slot;
  reader_table_t slotp;
  int fd, rp[2], wp[2];
  int n, i;
  pid_t pid;
  size_t len;
  unsigned char msgbuf[9];
  int err;
  unsigned int dummy_status;
  /*int sw = SW_HOST_CARD_IO_ERROR;*/

  /* Note that we use the constant and not the fucntion because this
     code won't be be used under Windows.  */
  const char *wrapperpgm = GNUPG_LIBEXECDIR "/gnupg-pcsc-wrapper";

  if (access (wrapperpgm, X_OK))
    {
      log_error ("can't run PC/SC access module `%s': %s\n",
                 wrapperpgm, strerror (errno));
      return -1;
    }

  slot = new_reader_slot ();
  if (slot == -1)
    return -1;
  slotp = reader_table + slot;

  /* Fire up the PC/SCc wrapper.  We don't use any fork/exec code from
     the common directy but implement it directly so that this file
     may still be source copied. */

  if (pipe (rp) == -1)
    {
      log_error ("error creating a pipe: %s\n", strerror (errno));
      slotp->used = 0;
      unlock_slot (slot);
      return -1;
    }
  if (pipe (wp) == -1)
    {
      log_error ("error creating a pipe: %s\n", strerror (errno));
      close (rp[0]);
      close (rp[1]);
      slotp->used = 0;
      unlock_slot (slot);
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
      unlock_slot (slot);
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
      close_all_fds (3, NULL);

      execl (wrapperpgm,
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
#undef WAIT

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
      log_error ("PC/SC returned a too large ATR (len=%lx)\n",
                 (unsigned long)len);
      goto command_failed;
    }
  err = PCSC_ERR_MASK ((msgbuf[5] << 24) | (msgbuf[6] << 16)
                       | (msgbuf[7] << 8 ) | msgbuf[8]);

  if (err)
    {
      log_error ("PC/SC OPEN failed: %s (0x%08x)\n",
		 pcsc_error_string (err), err);
      /*sw = pcsc_error_to_sw (err);*/
      goto command_failed;
    }

  slotp->last_status = 0;

  /* The open request may return a zero for the ATR length to
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
      slotp->last_status = (  APDU_CARD_USABLE
                            | APDU_CARD_PRESENT
                            | APDU_CARD_ACTIVE);
    }
  slotp->atrlen = len;

  reader_table[slot].close_reader = close_pcsc_reader;
  reader_table[slot].reset_reader = reset_pcsc_reader;
  reader_table[slot].get_status_reader = pcsc_get_status;
  reader_table[slot].send_apdu_reader = pcsc_send_apdu;
  reader_table[slot].dump_status_reader = dump_pcsc_reader_status;

  /* Read the status so that IS_T0 will be set. */
  pcsc_get_status (slot, &dummy_status);

  dump_reader_status (slot);
  unlock_slot (slot);
  return slot;

 command_failed:
  close (slotp->pcsc.req_fd);
  close (slotp->pcsc.rsp_fd);
  slotp->pcsc.req_fd = -1;
  slotp->pcsc.rsp_fd = -1;
  kill (slotp->pcsc.pid, SIGTERM);
  slotp->pcsc.pid = (pid_t)(-1);
  slotp->used = 0;
  unlock_slot (slot);
  /* There is no way to return SW. */
  return -1;

}
#endif /*NEED_PCSC_WRAPPER*/


static int
open_pcsc_reader (const char *portstr)
{
#ifdef NEED_PCSC_WRAPPER
  return open_pcsc_reader_wrapped (portstr);
#else
  return open_pcsc_reader_direct (portstr);
#endif
}


/* Check whether the reader supports the ISO command code COMMAND
   on the pinpad.  Return 0 on success.  */
static int
check_pcsc_pinpad (int slot, int command, pininfo_t *pininfo)
{
  unsigned char buf[256];
  pcsc_dword_t len = 256;
  int sw;

  (void)pininfo;      /* XXX: Identify reader and set pininfo->fixedlen.  */

 check_again:
  if (command == ISO7816_VERIFY)
    {
      if (reader_table[slot].pcsc.verify_ioctl == (pcsc_dword_t)-1)
        return SW_NOT_SUPPORTED;
      else if (reader_table[slot].pcsc.verify_ioctl != 0)
        return 0;                       /* Success */
    }
  else if (command == ISO7816_CHANGE_REFERENCE_DATA)
    {
      if (reader_table[slot].pcsc.modify_ioctl == (pcsc_dword_t)-1)
        return SW_NOT_SUPPORTED;
      else if (reader_table[slot].pcsc.modify_ioctl != 0)
        return 0;                       /* Success */
    }
  else
    return SW_NOT_SUPPORTED;

  reader_table[slot].pcsc.verify_ioctl = (pcsc_dword_t)-1;
  reader_table[slot].pcsc.modify_ioctl = (pcsc_dword_t)-1;

  sw = control_pcsc (slot, CM_IOCTL_GET_FEATURE_REQUEST, NULL, 0, buf, &len);
  if (sw)
    return SW_NOT_SUPPORTED;
  else
    {
      unsigned char *p = buf;

      while (p < buf + len)
        {
          unsigned char code = *p++;

          p++;                  /* Skip length */
          if (code == FEATURE_VERIFY_PIN_DIRECT)
            reader_table[slot].pcsc.verify_ioctl
              = (p[0] << 24) | (p[1] << 16) | (p[2] << 8) | p[3];
          else if (code == FEATURE_MODIFY_PIN_DIRECT)
            reader_table[slot].pcsc.modify_ioctl
              = (p[0] << 24) | (p[1] << 16) | (p[2] << 8) | p[3];
          p += 4;
        }
    }

  goto check_again;
}


#define PIN_VERIFY_STRUCTURE_SIZE 24
static int
pcsc_pinpad_verify (int slot, int class, int ins, int p0, int p1,
                    pininfo_t *pininfo)
{
  int sw;
  unsigned char *pin_verify;
  int len = PIN_VERIFY_STRUCTURE_SIZE + pininfo->fixedlen;
  unsigned char result[2];
  pcsc_dword_t resultlen = 2;

  if (!reader_table[slot].atrlen
      && (sw = reset_pcsc_reader (slot)))
    return sw;

  if (pininfo->fixedlen < 0 || pininfo->fixedlen >= 16)
    return SW_NOT_SUPPORTED;

  if (!pininfo->minlen)
    pininfo->minlen = 1;
  if (!pininfo->maxlen)
    pininfo->maxlen = 15;

  /* Note that the 25 is the maximum value the SPR532 allows.  */
  if (pininfo->minlen < 1 || pininfo->minlen > 25
      || pininfo->maxlen < 1 || pininfo->maxlen > 25
      || pininfo->minlen > pininfo->maxlen)
    return SW_HOST_INV_VALUE;

  pin_verify = xtrymalloc (len);
  if (!pin_verify)
    return SW_HOST_OUT_OF_CORE;

  pin_verify[0] = 0x00; /* bTimerOut */
  pin_verify[1] = 0x00; /* bTimerOut2 */
  pin_verify[2] = 0x82; /* bmFormatString: Byte, pos=0, left, ASCII. */
  pin_verify[3] = pininfo->fixedlen; /* bmPINBlockString */
  pin_verify[4] = 0x00; /* bmPINLengthFormat */
  pin_verify[5] = pininfo->maxlen; /* wPINMaxExtraDigit */
  pin_verify[6] = pininfo->minlen; /* wPINMaxExtraDigit */
  pin_verify[7] = 0x02; /* bEntryValidationCondition: Validation key pressed */
  if (pininfo->minlen && pininfo->maxlen && pininfo->minlen == pininfo->maxlen)
    pin_verify[7] |= 0x01; /* Max size reached.  */
  pin_verify[8] = 0xff; /* bNumberMessage: Default */
  pin_verify[9] =  0x09; /* wLangId: 0x0409: US English */
  pin_verify[10] = 0x04; /* wLangId: 0x0409: US English */
  pin_verify[11] = 0x00; /* bMsgIndex */
  pin_verify[12] = 0x00; /* bTeoPrologue[0] */
  pin_verify[13] = 0x00; /* bTeoPrologue[1] */
  pin_verify[14] = pininfo->fixedlen + 0x05; /* bTeoPrologue[2] */
  pin_verify[15] = pininfo->fixedlen + 0x05; /* ulDataLength */
  pin_verify[16] = 0x00; /* ulDataLength */
  pin_verify[17] = 0x00; /* ulDataLength */
  pin_verify[18] = 0x00; /* ulDataLength */
  pin_verify[19] = class; /* abData[0] */
  pin_verify[20] = ins; /* abData[1] */
  pin_verify[21] = p0; /* abData[2] */
  pin_verify[22] = p1; /* abData[3] */
  pin_verify[23] = pininfo->fixedlen; /* abData[4] */
  if (pininfo->fixedlen)
    memset (&pin_verify[24], 0xff, pininfo->fixedlen);

  if (DBG_CARD_IO)
    log_debug ("send secure: c=%02X i=%02X p1=%02X p2=%02X len=%d pinmax=%d\n",
	       class, ins, p0, p1, len, pininfo->maxlen);

  sw = control_pcsc (slot, reader_table[slot].pcsc.verify_ioctl,
                     pin_verify, len, result, &resultlen);
  xfree (pin_verify);
  if (sw || resultlen < 2)
    {
      log_error ("control_pcsc failed: %d\n", sw);
      return sw? sw: SW_HOST_INCOMPLETE_CARD_RESPONSE;
    }
  sw = (result[resultlen-2] << 8) | result[resultlen-1];
  if (DBG_CARD_IO)
    log_debug (" response: sw=%04X  datalen=%d\n", sw, (unsigned int)resultlen);
  return sw;
}


#define PIN_MODIFY_STRUCTURE_SIZE 29
static int
pcsc_pinpad_modify (int slot, int class, int ins, int p0, int p1,
                    pininfo_t *pininfo)
{
  int sw;
  unsigned char *pin_modify;
  int len = PIN_MODIFY_STRUCTURE_SIZE + 2 * pininfo->fixedlen;
  unsigned char result[2];
  pcsc_dword_t resultlen = 2;

  if (!reader_table[slot].atrlen
      && (sw = reset_pcsc_reader (slot)))
    return sw;

  if (pininfo->fixedlen < 0 || pininfo->fixedlen >= 16)
    return SW_NOT_SUPPORTED;

  if (!pininfo->minlen)
    pininfo->minlen = 1;
  if (!pininfo->maxlen)
    pininfo->maxlen = 15;

  /* Note that the 25 is the maximum value the SPR532 allows.  */
  if (pininfo->minlen < 1 || pininfo->minlen > 25
      || pininfo->maxlen < 1 || pininfo->maxlen > 25
      || pininfo->minlen > pininfo->maxlen)
    return SW_HOST_INV_VALUE;

  pin_modify = xtrymalloc (len);
  if (!pin_modify)
    return SW_HOST_OUT_OF_CORE;

  pin_modify[0] = 0x00; /* bTimerOut */
  pin_modify[1] = 0x00; /* bTimerOut2 */
  pin_modify[2] = 0x82; /* bmFormatString: Byte, pos=0, left, ASCII. */
  pin_modify[3] = pininfo->fixedlen; /* bmPINBlockString */
  pin_modify[4] = 0x00; /* bmPINLengthFormat */
  pin_modify[5] = 0x00; /* bInsertionOffsetOld */
  pin_modify[6] = pininfo->fixedlen; /* bInsertionOffsetNew */
  pin_modify[7] = pininfo->maxlen; /* wPINMaxExtraDigit */
  pin_modify[8] = pininfo->minlen; /* wPINMaxExtraDigit */
  pin_modify[9] = (p0 == 0 ? 0x03 : 0x01);
                  /* bConfirmPIN
                   *    0x00: new PIN once
                   *    0x01: new PIN twice (confirmation)
                   *    0x02: old PIN and new PIN once
                   *    0x03: old PIN and new PIN twice (confirmation)
                   */
  pin_modify[10] = 0x02; /* bEntryValidationCondition: Validation key pressed */
  if (pininfo->minlen && pininfo->maxlen && pininfo->minlen == pininfo->maxlen)
    pin_modify[10] |= 0x01; /* Max size reached.  */
  pin_modify[11] = 0xff; /* bNumberMessage: Default */
  pin_modify[12] =  0x09; /* wLangId: 0x0409: US English */
  pin_modify[13] = 0x04; /* wLangId: 0x0409: US English */
  pin_modify[14] = 0x00; /* bMsgIndex1 */
  pin_modify[15] = 0x00; /* bMsgIndex2 */
  pin_modify[16] = 0x00; /* bMsgIndex3 */
  pin_modify[17] = 0x00; /* bTeoPrologue[0] */
  pin_modify[18] = 0x00; /* bTeoPrologue[1] */
  pin_modify[19] = 2 * pininfo->fixedlen + 0x05; /* bTeoPrologue[2] */
  pin_modify[20] = 2 * pininfo->fixedlen + 0x05; /* ulDataLength */
  pin_modify[21] = 0x00; /* ulDataLength */
  pin_modify[22] = 0x00; /* ulDataLength */
  pin_modify[23] = 0x00; /* ulDataLength */
  pin_modify[24] = class; /* abData[0] */
  pin_modify[25] = ins; /* abData[1] */
  pin_modify[26] = p0; /* abData[2] */
  pin_modify[27] = p1; /* abData[3] */
  pin_modify[28] = 2 * pininfo->fixedlen; /* abData[4] */
  if (pininfo->fixedlen)
    memset (&pin_modify[29], 0xff, 2 * pininfo->fixedlen);

  if (DBG_CARD_IO)
    log_debug ("send secure: c=%02X i=%02X p1=%02X p2=%02X len=%d pinmax=%d\n",
	       class, ins, p0, p1, len, (int)pininfo->maxlen);

  sw = control_pcsc (slot, reader_table[slot].pcsc.modify_ioctl,
                     pin_modify, len, result, &resultlen);
  xfree (pin_modify);
  if (sw || resultlen < 2)
    {
      log_error ("control_pcsc failed: %d\n", sw);
      return sw? sw : SW_HOST_INCOMPLETE_CARD_RESPONSE;
    }
  sw = (result[resultlen-2] << 8) | result[resultlen-1];
  if (DBG_CARD_IO)
    log_debug (" response: sw=%04X  datalen=%d\n", sw, (unsigned int)resultlen);
  return sw;
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
set_progress_cb_ccid_reader (int slot, gcry_handler_progress_t cb, void *cb_arg)
{
  reader_table_t slotp = reader_table + slot;

  return ccid_set_progress_cb (slotp->ccid.handle, cb, cb_arg);
}


static int
get_status_ccid (int slot, unsigned int *status)
{
  int rc;
  int bits;

  rc = ccid_slot_status (reader_table[slot].ccid.handle, &bits);
  if (rc)
    return rc;

  if (bits == 0)
    *status = (APDU_CARD_USABLE|APDU_CARD_PRESENT|APDU_CARD_ACTIVE);
  else if (bits == 1)
    *status = APDU_CARD_PRESENT;
  else
    *status = 0;

  return 0;
}


/* Actually send the APDU of length APDULEN to SLOT and return a
   maximum of *BUFLEN data in BUFFER, the actual returned size will be
   set to BUFLEN.  Returns: Internal CCID driver error code. */
static int
send_apdu_ccid (int slot, unsigned char *apdu, size_t apdulen,
                unsigned char *buffer, size_t *buflen,
                pininfo_t *pininfo)
{
  long err;
  size_t maxbuflen;

  /* If we don't have an ATR, we need to reset the reader first. */
  if (!reader_table[slot].atrlen
      && (err = reset_ccid_reader (slot)))
    return err;

  if (DBG_CARD_IO)
    log_printhex (" raw apdu:", apdu, apdulen);

  maxbuflen = *buflen;
  if (pininfo)
    err = ccid_transceive_secure (reader_table[slot].ccid.handle,
                                  apdu, apdulen, pininfo,
                                  buffer, maxbuflen, buflen);
  else
    err = ccid_transceive (reader_table[slot].ccid.handle,
                           apdu, apdulen,
                           buffer, maxbuflen, buflen);
  if (err)
    log_error ("ccid_transceive failed: (0x%lx)\n",
               err);

  return err;
}


/* Check whether the CCID reader supports the ISO command code COMMAND
   on the pinpad.  Return 0 on success.  For a description of the pin
   parameters, see ccid-driver.c */
static int
check_ccid_pinpad (int slot, int command, pininfo_t *pininfo)
{
  unsigned char apdu[] = { 0, 0, 0, 0x81 };

  apdu[1] = command;
  return ccid_transceive_secure (reader_table[slot].ccid.handle, apdu,
				 sizeof apdu, pininfo, NULL, 0, NULL);
}


static int
ccid_pinpad_operation (int slot, int class, int ins, int p0, int p1,
		       pininfo_t *pininfo)
{
  unsigned char apdu[4];
  int err, sw;
  unsigned char result[2];
  size_t resultlen = 2;

  apdu[0] = class;
  apdu[1] = ins;
  apdu[2] = p0;
  apdu[3] = p1;
  err = ccid_transceive_secure (reader_table[slot].ccid.handle,
                                apdu, sizeof apdu, pininfo,
                                result, 2, &resultlen);
  if (err)
    return err;

  if (resultlen < 2)
    return SW_HOST_INCOMPLETE_CARD_RESPONSE;

  sw = (result[resultlen-2] << 8) | result[resultlen-1];
  return sw;
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
      unlock_slot (slot);
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
      reader_table[slot].last_status = (APDU_CARD_USABLE
                                        | APDU_CARD_PRESENT
                                        | APDU_CARD_ACTIVE);
    }

  reader_table[slot].close_reader = close_ccid_reader;
  reader_table[slot].shutdown_reader = shutdown_ccid_reader;
  reader_table[slot].reset_reader = reset_ccid_reader;
  reader_table[slot].get_status_reader = get_status_ccid;
  reader_table[slot].send_apdu_reader = send_apdu_ccid;
  reader_table[slot].check_pinpad = check_ccid_pinpad;
  reader_table[slot].dump_status_reader = dump_ccid_reader_status;
  reader_table[slot].set_progress_cb = set_progress_cb_ccid_reader;
  reader_table[slot].pinpad_verify = ccid_pinpad_operation;
  reader_table[slot].pinpad_modify = ccid_pinpad_operation;
  /* Our CCID reader code does not support T=0 at all, thus reset the
     flag.  */
  reader_table[slot].is_t0 = 0;

  dump_reader_status (slot);
  unlock_slot (slot);
  return slot;
}



#endif /* HAVE_LIBUSB */



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
  if (msg->datalen > DIM (slotp->atr))
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
   set to BUFLEN.  Returns: APDU error code. */
static int
my_rapdu_send_apdu (int slot, unsigned char *apdu, size_t apdulen,
                    unsigned char *buffer, size_t *buflen,
                    pininfo_t *pininfo)
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
      unlock_slot (slot);
      return -1;
    }

  rapdu_set_reader (slotp->rapdu.handle, portno);

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
  if (msg->datalen > DIM (slotp->atr))
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
  reader_table[slot].check_pinpad = NULL;
  reader_table[slot].dump_status_reader = NULL;
  reader_table[slot].pinpad_verify = NULL;
  reader_table[slot].pinpad_modify = NULL;

  dump_reader_status (slot);
  rapdu_msg_release (msg);
  unlock_slot (slot);
  return slot;

 failure:
  rapdu_msg_release (msg);
  rapdu_release (slotp->rapdu.handle);
  slotp->used = 0;
  unlock_slot (slot);
  return -1;
}

#endif /*USE_G10CODE_RAPDU*/



/*
       Driver Access
 */


/* Open the reader and return an internal slot number or -1 on
   error. If PORTSTR is NULL we default to a suitable port (for ctAPI:
   the first USB reader.  For PC/SC the first listed reader). */
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
#if defined(_WIN32) || defined(__CYGWIN__)
      if (!pcsc_list_readers)
        pcsc_list_readers    = dlsym (handle, "SCardListReadersA");
#endif
      pcsc_get_status_change = dlsym (handle, "SCardGetStatusChange");
#if defined(_WIN32) || defined(__CYGWIN__)
      if (!pcsc_get_status_change)
        pcsc_get_status_change = dlsym (handle, "SCardGetStatusChangeA");
#endif
      pcsc_connect           = dlsym (handle, "SCardConnect");
#if defined(_WIN32) || defined(__CYGWIN__)
      if (!pcsc_connect)
        pcsc_connect         = dlsym (handle, "SCardConnectA");
#endif
      pcsc_reconnect         = dlsym (handle, "SCardReconnect");
#if defined(_WIN32) || defined(__CYGWIN__)
      if (!pcsc_reconnect)
        pcsc_reconnect       = dlsym (handle, "SCardReconnectA");
#endif
      pcsc_disconnect        = dlsym (handle, "SCardDisconnect");
      pcsc_status            = dlsym (handle, "SCardStatus");
#if defined(_WIN32) || defined(__CYGWIN__)
      if (!pcsc_status)
        pcsc_status          = dlsym (handle, "SCardStatusA");
#endif
      pcsc_begin_transaction = dlsym (handle, "SCardBeginTransaction");
      pcsc_end_transaction   = dlsym (handle, "SCardEndTransaction");
      pcsc_transmit          = dlsym (handle, "SCardTransmit");
      pcsc_set_timeout       = dlsym (handle, "SCardSetTimeout");
      pcsc_control           = dlsym (handle, "SCardControl");

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
          || !pcsc_control
          /* || !pcsc_set_timeout */)
        {
          /* Note that set_timeout is currently not used and also not
             available under Windows. */
          log_error ("apdu_open_reader: invalid PC/SC driver "
                     "(%d%d%d%d%d%d%d%d%d%d%d%d%d)\n",
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
                     !!pcsc_set_timeout,
                     !!pcsc_control );
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
  (void)portstr;
  (void)cookie;
  (void)length;
  (void)readfnc;
  (void)readfnc_value;
  (void)writefnc;
  (void)writefnc_value;
  (void)closefnc;
  (void)closefnc_value;
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
  int sw;

  if (slot < 0 || slot >= MAX_READER || !reader_table[slot].used )
    return SW_HOST_NO_DRIVER;
  sw = apdu_disconnect (slot);
  if (sw)
    return sw;
  if (reader_table[slot].close_reader)
    return reader_table[slot].close_reader (slot);
  return SW_HOST_NOT_SUPPORTED;
}


/* Function suitable for a cleanup function to close all reader.  It
   should not be used if the reader will be opened again.  The reason
   for implementing this to properly close USB devices so that they
   will startup the next time without error. */
void
apdu_prepare_exit (void)
{
  static int sentinel;
  int slot;

  if (!sentinel)
    {
      sentinel = 1;
      for (slot = 0; slot < MAX_READER; slot++)
        if (reader_table[slot].used)
          {
            apdu_disconnect (slot);
            if (reader_table[slot].close_reader)
              reader_table[slot].close_reader (slot);
            reader_table[slot].used = 0;
          }
      sentinel = 0;
    }
}


/* Shutdown a reader; that is basically the same as a close but keeps
   the handle ready for later use. A apdu_reset_reader or apdu_connect
   should be used to get it active again. */
int
apdu_shutdown_reader (int slot)
{
  int sw;

  if (slot < 0 || slot >= MAX_READER || !reader_table[slot].used )
    return SW_HOST_NO_DRIVER;
  sw = apdu_disconnect (slot);
  if (sw)
    return sw;
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


/* Connect a card.  This is used to power up the card and make sure
   that an ATR is available.  Depending on the reader backend it may
   return an error for an inactive card or if no card is
   available.  */
int
apdu_connect (int slot)
{
  int sw;
  unsigned int status;

  if (slot < 0 || slot >= MAX_READER || !reader_table[slot].used )
    return SW_HOST_NO_DRIVER;

  /* Only if the access method provides a connect function we use it.
     If not, we expect that the card has been implicitly connected by
     apdu_open_reader.  */
  if (reader_table[slot].connect_card)
    {
      sw = lock_slot (slot);
      if (!sw)
        {
          sw = reader_table[slot].connect_card (slot);
          unlock_slot (slot);
        }
    }
  else
    sw = 0;

  /* We need to call apdu_get_status_internal, so that the last-status
     machinery gets setup properly even if a card is inserted while
     scdaemon is fired up and apdu_get_status has not yet been called.
     Without that we would force a reset of the card with the next
     call to apdu_get_status.  */
  apdu_get_status_internal (slot, 1, 1, &status, NULL);
  if (sw)
    ;
  else if (!(status & APDU_CARD_PRESENT))
    sw = SW_HOST_NO_CARD;
  else if ((status & APDU_CARD_PRESENT) && !(status & APDU_CARD_ACTIVE))
    sw = SW_HOST_CARD_INACTIVE;


  return sw;
}


int
apdu_disconnect (int slot)
{
  int sw;

  if (slot < 0 || slot >= MAX_READER || !reader_table[slot].used )
    return SW_HOST_NO_DRIVER;

  if (reader_table[slot].disconnect_card)
    {
      sw = lock_slot (slot);
      if (!sw)
        {
          sw = reader_table[slot].disconnect_card (slot);
          unlock_slot (slot);
        }
    }
  else
    sw = 0;
  return sw;
}


/* Set the progress callback of SLOT to CB and its args to CB_ARG.  If
   CB is NULL the progress callback is removed.  */
int
apdu_set_progress_cb (int slot, gcry_handler_progress_t cb, void *cb_arg)
{
  int sw;

  if (slot < 0 || slot >= MAX_READER || !reader_table[slot].used )
    return SW_HOST_NO_DRIVER;

  if (reader_table[slot].set_progress_cb)
    {
      sw = lock_slot (slot);
      if (!sw)
        {
          sw = reader_table[slot].set_progress_cb (slot, cb, cb_arg);
          unlock_slot (slot);
        }
    }
  else
    sw = 0;
  return sw;
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
      reader_table[slot].last_status = (APDU_CARD_USABLE
                                        | APDU_CARD_PRESENT
                                        | APDU_CARD_ACTIVE);
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
                  reader_table[slot].last_status = (APDU_CARD_USABLE
                                                    | APDU_CARD_PRESENT
                                                    | APDU_CARD_ACTIVE);
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
  unsigned char *buf;

  if (slot < 0 || slot >= MAX_READER || !reader_table[slot].used )
    return NULL;
  if (!reader_table[slot].atrlen)
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

     APDU_CARD_USABLE  (bit 0) = card present and usable
     APDU_CARD_PRESENT (bit 1) = card present
     APDU_CARD_ACTIVE  (bit 2) = card active
                       (bit 3) = card access locked [not yet implemented]

   For must applications, testing bit 0 is sufficient.

   CHANGED will receive the value of the counter tracking the number
   of card insertions.  This value may be used to detect a card
   change.
*/
static int
apdu_get_status_internal (int slot, int hang, int no_atr_reset,
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

  /* Keep track of changes.  */
  if (s != reader_table[slot].last_status
      || !reader_table[slot].any_status )
    {
      reader_table[slot].change_counter++;
      /* Make sure that the ATR is invalid so that a reset will be
         triggered by apdu_activate.  */
      if (!no_atr_reset)
        reader_table[slot].atrlen = 0;
    }
  reader_table[slot].any_status = 1;
  reader_table[slot].last_status = s;

  if (status)
    *status = s;
  if (changed)
    *changed = reader_table[slot].change_counter;
  return 0;
}


/* See above for a description.  */
int
apdu_get_status (int slot, int hang,
                 unsigned int *status, unsigned int *changed)
{
  return apdu_get_status_internal (slot, hang, 0, status, changed);
}


/* Check whether the reader supports the ISO command code COMMAND on
   the pinpad.  Return 0 on success.  For a description of the pin
   parameters, see ccid-driver.c */
int
apdu_check_pinpad (int slot, int command, pininfo_t *pininfo)
{
  if (slot < 0 || slot >= MAX_READER || !reader_table[slot].used )
    return SW_HOST_NO_DRIVER;

  if (opt.enable_pinpad_varlen)
    pininfo->fixedlen = 0;

  if (reader_table[slot].check_pinpad)
    {
      int sw;

      if ((sw = lock_slot (slot)))
        return sw;

      sw = reader_table[slot].check_pinpad (slot, command, pininfo);
      unlock_slot (slot);
      return sw;
    }
  else
    return SW_HOST_NOT_SUPPORTED;
}


int
apdu_pinpad_verify (int slot, int class, int ins, int p0, int p1,
		    pininfo_t *pininfo)
{
  if (slot < 0 || slot >= MAX_READER || !reader_table[slot].used )
    return SW_HOST_NO_DRIVER;

  if (reader_table[slot].pinpad_verify)
    {
      int sw;

      if ((sw = lock_slot (slot)))
        return sw;

      sw = reader_table[slot].pinpad_verify (slot, class, ins, p0, p1,
					     pininfo);
      unlock_slot (slot);
      return sw;
    }
  else
    return SW_HOST_NOT_SUPPORTED;
}


int
apdu_pinpad_modify (int slot, int class, int ins, int p0, int p1,
		    pininfo_t *pininfo)
{
  if (slot < 0 || slot >= MAX_READER || !reader_table[slot].used )
    return SW_HOST_NO_DRIVER;

  if (reader_table[slot].pinpad_modify)
    {
      int sw;

      if ((sw = lock_slot (slot)))
        return sw;

      sw = reader_table[slot].pinpad_modify (slot, class, ins, p0, p1,
                                             pininfo);
      unlock_slot (slot);
      return sw;
    }
  else
    return SW_HOST_NOT_SUPPORTED;
}


/* Dispatcher for the actual send_apdu function. Note, that this
   function should be called in locked state. */
static int
send_apdu (int slot, unsigned char *apdu, size_t apdulen,
           unsigned char *buffer, size_t *buflen, pininfo_t *pininfo)
{
  if (slot < 0 || slot >= MAX_READER || !reader_table[slot].used )
    return SW_HOST_NO_DRIVER;

  if (reader_table[slot].send_apdu_reader)
    return reader_table[slot].send_apdu_reader (slot,
                                                apdu, apdulen,
                                                buffer, buflen,
                                                pininfo);
  else
    return SW_HOST_NOT_SUPPORTED;
}


/* Core APDU tranceiver function. Parameters are described at
   apdu_send_le with the exception of PININFO which indicates pinpad
   related operations if not NULL.  If EXTENDED_MODE is not 0
   command chaining or extended length will be used according to these
   values:
       n < 0 := Use command chaining with the data part limited to -n
                in each chunk.  If -1 is used a default value is used.
      n == 0 := No extended mode or command chaining.
      n == 1 := Use extended length for input and output without a
                length limit.
       n > 1 := Use extended length with up to N bytes.

*/
static int
send_le (int slot, int class, int ins, int p0, int p1,
         int lc, const char *data, int le,
         unsigned char **retbuf, size_t *retbuflen,
         pininfo_t *pininfo, int extended_mode)
{
#define SHORT_RESULT_BUFFER_SIZE 258
  /* We allocate 8 extra bytes as a safety margin towards a driver bug.  */
  unsigned char short_result_buffer[SHORT_RESULT_BUFFER_SIZE+10];
  unsigned char *result_buffer = NULL;
  size_t result_buffer_size;
  unsigned char *result;
  size_t resultlen;
  unsigned char short_apdu_buffer[5+256+1];
  unsigned char *apdu_buffer = NULL;
  size_t apdu_buffer_size;
  unsigned char *apdu;
  size_t apdulen;
  int sw;
  long rc; /* We need a long here due to PC/SC. */
  int did_exact_length_hack = 0;
  int use_chaining = 0;
  int use_extended_length = 0;
  int lc_chunk;

  if (slot < 0 || slot >= MAX_READER || !reader_table[slot].used )
    return SW_HOST_NO_DRIVER;

  if (DBG_CARD_IO)
    log_debug ("send apdu: c=%02X i=%02X p1=%02X p2=%02X lc=%d le=%d em=%d\n",
               class, ins, p0, p1, lc, le, extended_mode);

  if (lc != -1 && (lc > 255 || lc < 0))
    {
      /* Data does not fit into an APDU.  What we do now depends on
         the EXTENDED_MODE parameter.  */
      if (!extended_mode)
        return SW_WRONG_LENGTH; /* No way to send such an APDU.  */
      else if (extended_mode > 0)
        use_extended_length = 1;
      else if (extended_mode < 0)
        {
          /* Send APDU using chaining mode.  */
          if (lc > 16384)
            return SW_WRONG_LENGTH;   /* Sanity check.  */
          if ((class&0xf0) != 0)
            return SW_HOST_INV_VALUE; /* Upper 4 bits need to be 0.  */
          use_chaining = extended_mode == -1? 255 : -extended_mode;
          use_chaining &= 0xff;
        }
      else
        return SW_HOST_INV_VALUE;
    }
  else if (lc == -1 && extended_mode > 0)
    use_extended_length = 1;

  if (le != -1 && (le > (extended_mode > 0? 255:256) || le < 0))
    {
      /* Expected Data does not fit into an APDU.  What we do now
         depends on the EXTENDED_MODE parameter.  Note that a check
         for command chaining does not make sense because we are
         looking at Le.  */
      if (!extended_mode)
        return SW_WRONG_LENGTH; /* No way to send such an APDU.  */
      else if (use_extended_length)
        ; /* We are already using extended length.  */
      else if (extended_mode > 0)
        use_extended_length = 1;
      else
        return SW_HOST_INV_VALUE;
    }

  if ((!data && lc != -1) || (data && lc == -1))
    return SW_HOST_INV_VALUE;

  if (use_extended_length)
    {
      if (reader_table[slot].is_t0)
        return SW_HOST_NOT_SUPPORTED;

      /* Space for: cls/ins/p1/p2+Z+2_byte_Lc+Lc+2_byte_Le.  */
      apdu_buffer_size = 4 + 1 + (lc >= 0? (2+lc):0) + 2;
      apdu_buffer = xtrymalloc (apdu_buffer_size + 10);
      if (!apdu_buffer)
        return SW_HOST_OUT_OF_CORE;
      apdu = apdu_buffer;
    }
  else
    {
      apdu_buffer_size = sizeof short_apdu_buffer;
      apdu = short_apdu_buffer;
    }

  if (use_extended_length && (le > 256 || le < 0))
    {
      result_buffer_size = le < 0? 4096 : le;
      result_buffer = xtrymalloc (result_buffer_size + 10);
      if (!result_buffer)
        {
          xfree (apdu_buffer);
          return SW_HOST_OUT_OF_CORE;
        }
      result = result_buffer;
    }
  else
    {
      result_buffer_size = SHORT_RESULT_BUFFER_SIZE;
      result = short_result_buffer;
    }
#undef SHORT_RESULT_BUFFER_SIZE

  if ((sw = lock_slot (slot)))
    {
      xfree (apdu_buffer);
      xfree (result_buffer);
      return sw;
    }

  do
    {
      if (use_extended_length)
        {
          use_chaining = 0;
          apdulen = 0;
          apdu[apdulen++] = class;
          apdu[apdulen++] = ins;
          apdu[apdulen++] = p0;
          apdu[apdulen++] = p1;
          apdu[apdulen++] = 0;  /* Z byte: Extended length marker.  */
          if (lc >= 0)
            {
              apdu[apdulen++] = ((lc >> 8) & 0xff);
              apdu[apdulen++] = (lc & 0xff);
              memcpy (apdu+apdulen, data, lc);
              data += lc;
              apdulen += lc;
            }
          if (le != -1)
            {
              apdu[apdulen++] = ((le >> 8) & 0xff);
              apdu[apdulen++] = (le & 0xff);
            }
        }
      else
        {
          apdulen = 0;
          apdu[apdulen] = class;
          if (use_chaining && lc > 255)
            {
              apdu[apdulen] |= 0x10;
              assert (use_chaining < 256);
              lc_chunk = use_chaining;
              lc -= use_chaining;
            }
          else
            {
              use_chaining = 0;
              lc_chunk = lc;
            }
          apdulen++;
          apdu[apdulen++] = ins;
          apdu[apdulen++] = p0;
          apdu[apdulen++] = p1;
          if (lc_chunk != -1)
            {
              apdu[apdulen++] = lc_chunk;
              memcpy (apdu+apdulen, data, lc_chunk);
              data += lc_chunk;
              apdulen += lc_chunk;
              /* T=0 does not allow the use of Lc together with Le;
                 thus disable Le in this case.  */
              if (reader_table[slot].is_t0)
                le = -1;
            }
          if (le != -1 && !use_chaining)
            apdu[apdulen++] = le; /* Truncation is okay (0 means 256). */
        }

    exact_length_hack:
      /* As a safeguard don't pass any garbage to the driver.  */
      assert (apdulen <= apdu_buffer_size);
      memset (apdu+apdulen, 0, apdu_buffer_size - apdulen);
      resultlen = result_buffer_size;
      rc = send_apdu (slot, apdu, apdulen, result, &resultlen, pininfo);
      if (rc || resultlen < 2)
        {
          log_info ("apdu_send_simple(%d) failed: %s\n",
                    slot, apdu_strerror (rc));
          unlock_slot (slot);
          xfree (apdu_buffer);
          xfree (result_buffer);
          return rc? rc : SW_HOST_INCOMPLETE_CARD_RESPONSE;
        }
      sw = (result[resultlen-2] << 8) | result[resultlen-1];
      if (!use_extended_length
          && !did_exact_length_hack && SW_EXACT_LENGTH_P (sw))
        {
          apdu[apdulen-1] = (sw & 0x00ff);
          did_exact_length_hack = 1;
          goto exact_length_hack;
        }
    }
  while (use_chaining && sw == SW_SUCCESS);

  if (apdu_buffer)
    {
      xfree (apdu_buffer);
      apdu_buffer = NULL;
      apdu_buffer_size = 0;
    }

  /* Store away the returned data but strip the statusword. */
  resultlen -= 2;
  if (DBG_CARD_IO)
    {
      log_debug (" response: sw=%04X  datalen=%d\n",
                 sw, (unsigned int)resultlen);
      if ( !retbuf && (sw == SW_SUCCESS || (sw & 0xff00) == SW_MORE_DATA))
        log_printhex ("    dump: ", result, resultlen);
    }

  if (sw == SW_SUCCESS || sw == SW_EOF_REACHED)
    {
      if (retbuf)
        {
          *retbuf = xtrymalloc (resultlen? resultlen : 1);
          if (!*retbuf)
            {
              unlock_slot (slot);
              xfree (result_buffer);
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
              xfree (result_buffer);
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
          apdu_buffer_size = sizeof short_apdu_buffer;
          apdu = short_apdu_buffer;
          apdulen = 0;
          apdu[apdulen++] = class;
          apdu[apdulen++] = 0xC0;
          apdu[apdulen++] = 0;
          apdu[apdulen++] = 0;
          apdu[apdulen++] = len;
          assert (apdulen <= apdu_buffer_size);
          memset (apdu+apdulen, 0, apdu_buffer_size - apdulen);
          resultlen = result_buffer_size;
          rc = send_apdu (slot, apdu, apdulen, result, &resultlen, NULL);
          if (rc || resultlen < 2)
            {
              log_error ("apdu_send_simple(%d) for get response failed: %s\n",
                         slot, apdu_strerror (rc));
              unlock_slot (slot);
              xfree (result_buffer);
              return rc? rc : SW_HOST_INCOMPLETE_CARD_RESPONSE;
            }
          sw = (result[resultlen-2] << 8) | result[resultlen-1];
          resultlen -= 2;
          if (DBG_CARD_IO)
            {
              log_debug ("     more: sw=%04X  datalen=%d\n",
                         sw, (unsigned int)resultlen);
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
                          xfree (result_buffer);
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
  xfree (result_buffer);

  if (DBG_CARD_IO && retbuf && sw == SW_SUCCESS)
    log_printhex ("      dump: ", *retbuf, *retbuflen);

  return sw;
}

/* Send an APDU to the card in SLOT.  The APDU is created from all
   given parameters: CLASS, INS, P0, P1, LC, DATA, LE.  A value of -1
   for LC won't sent this field and the data field; in this case DATA
   must also be passed as NULL.  If EXTENDED_MODE is not 0 command
   chaining or extended length will be used; see send_le for details.
   The return value is the status word or -1 for an invalid SLOT or
   other non card related error.  If RETBUF is not NULL, it will
   receive an allocated buffer with the returned data.  The length of
   that data will be put into *RETBUFLEN.  The caller is reponsible
   for releasing the buffer even in case of errors.  */
int
apdu_send_le(int slot, int extended_mode,
             int class, int ins, int p0, int p1,
             int lc, const char *data, int le,
             unsigned char **retbuf, size_t *retbuflen)
{
  return send_le (slot, class, ins, p0, p1,
                  lc, data, le,
                  retbuf, retbuflen,
                  NULL, extended_mode);
}


/* Send an APDU to the card in SLOT.  The APDU is created from all
   given parameters: CLASS, INS, P0, P1, LC, DATA.  A value of -1 for
   LC won't sent this field and the data field; in this case DATA must
   also be passed as NULL.  If EXTENDED_MODE is not 0 command chaining
   or extended length will be used; see send_le for details.  The
   return value is the status word or -1 for an invalid SLOT or other
   non card related error.  If RETBUF is not NULL, it will receive an
   allocated buffer with the returned data.  The length of that data
   will be put into *RETBUFLEN.  The caller is reponsible for
   releasing the buffer even in case of errors.  */
int
apdu_send (int slot, int extended_mode,
           int class, int ins, int p0, int p1,
           int lc, const char *data, unsigned char **retbuf, size_t *retbuflen)
{
  return send_le (slot, class, ins, p0, p1, lc, data, 256,
                  retbuf, retbuflen, NULL, extended_mode);
}

/* Send an APDU to the card in SLOT.  The APDU is created from all
   given parameters: CLASS, INS, P0, P1, LC, DATA.  A value of -1 for
   LC won't sent this field and the data field; in this case DATA must
   also be passed as NULL.  If EXTENDED_MODE is not 0 command chaining
   or extended length will be used; see send_le for details.  The
   return value is the status word or -1 for an invalid SLOT or other
   non card related error.  No data will be returned.  */
int
apdu_send_simple (int slot, int extended_mode,
                  int class, int ins, int p0, int p1,
                  int lc, const char *data)
{
  return send_le (slot, class, ins, p0, p1, lc, data, -1, NULL, NULL, NULL,
                  extended_mode);
}


/* This is a more generic version of the apdu sending routine.  It
   takes an already formatted APDU in APDUDATA or length APDUDATALEN
   and returns with an APDU including the status word.  With
   HANDLE_MORE set to true this function will handle the MORE DATA
   status and return all APDUs concatenated with one status word at
   the end.  If EXTENDED_LENGTH is != 0 extended lengths are allowed
   with a max. result data length of EXTENDED_LENGTH bytes.  The
   function does not return a regular status word but 0 on success.
   If the slot is locked, the function returns immediately with an
   error.  */
int
apdu_send_direct (int slot, size_t extended_length,
                  const unsigned char *apdudata, size_t apdudatalen,
                  int handle_more,
                  unsigned char **retbuf, size_t *retbuflen)
{
#define SHORT_RESULT_BUFFER_SIZE 258
  unsigned char short_result_buffer[SHORT_RESULT_BUFFER_SIZE+10];
  unsigned char *result_buffer = NULL;
  size_t result_buffer_size;
  unsigned char *result;
  size_t resultlen;
  unsigned char short_apdu_buffer[5+256+10];
  unsigned char *apdu_buffer = NULL;
  unsigned char *apdu;
  size_t apdulen;
  int sw;
  long rc; /* we need a long here due to PC/SC. */
  int class;

  if (slot < 0 || slot >= MAX_READER || !reader_table[slot].used )
    return SW_HOST_NO_DRIVER;

  if (apdudatalen > 65535)
    return SW_HOST_INV_VALUE;

  if (apdudatalen > sizeof short_apdu_buffer - 5)
    {
      apdu_buffer = xtrymalloc (apdudatalen + 5);
      if (!apdu_buffer)
        return SW_HOST_OUT_OF_CORE;
      apdu = apdu_buffer;
    }
  else
    {
      apdu = short_apdu_buffer;
    }
  apdulen = apdudatalen;
  memcpy (apdu, apdudata, apdudatalen);
  class = apdulen? *apdu : 0;

  if (extended_length >= 256 && extended_length <= 65536)
    {
      result_buffer_size = extended_length;
      result_buffer = xtrymalloc (result_buffer_size + 10);
      if (!result_buffer)
        {
          xfree (apdu_buffer);
          return SW_HOST_OUT_OF_CORE;
        }
      result = result_buffer;
    }
  else
    {
      result_buffer_size = SHORT_RESULT_BUFFER_SIZE;
      result = short_result_buffer;
    }
#undef SHORT_RESULT_BUFFER_SIZE

  if ((sw = trylock_slot (slot)))
    {
      xfree (apdu_buffer);
      xfree (result_buffer);
      return sw;
    }

  resultlen = result_buffer_size;
  rc = send_apdu (slot, apdu, apdulen, result, &resultlen, NULL);
  xfree (apdu_buffer);
  apdu_buffer = NULL;
  if (rc || resultlen < 2)
    {
      log_error ("apdu_send_direct(%d) failed: %s\n",
                 slot, apdu_strerror (rc));
      unlock_slot (slot);
      xfree (result_buffer);
      return rc? rc : SW_HOST_INCOMPLETE_CARD_RESPONSE;
    }
  sw = (result[resultlen-2] << 8) | result[resultlen-1];
  /* Store away the returned data but strip the statusword. */
  resultlen -= 2;
  if (DBG_CARD_IO)
    {
      log_debug (" response: sw=%04X  datalen=%d\n",
                 sw, (unsigned int)resultlen);
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
              xfree (result_buffer);
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
          apdu = short_apdu_buffer;
          apdulen = 0;
          apdu[apdulen++] = class;
          apdu[apdulen++] = 0xC0;
          apdu[apdulen++] = 0;
          apdu[apdulen++] = 0;
          apdu[apdulen++] = len;
          memset (apdu+apdulen, 0, sizeof (short_apdu_buffer) - apdulen);
          resultlen = result_buffer_size;
          rc = send_apdu (slot, apdu, apdulen, result, &resultlen, NULL);
          if (rc || resultlen < 2)
            {
              log_error ("apdu_send_direct(%d) for get response failed: %s\n",
                         slot, apdu_strerror (rc));
              unlock_slot (slot);
              xfree (result_buffer);
              return rc ? rc : SW_HOST_INCOMPLETE_CARD_RESPONSE;
            }
          sw = (result[resultlen-2] << 8) | result[resultlen-1];
          resultlen -= 2;
          if (DBG_CARD_IO)
            {
              log_debug ("     more: sw=%04X  datalen=%d\n",
                         sw, (unsigned int)resultlen);
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
                          xfree (result_buffer);
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
            log_info ("apdu_send_direct(%d) "
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
              xfree (result_buffer);
              return SW_HOST_OUT_OF_CORE;
            }
          *retbuflen = resultlen;
          memcpy (*retbuf, result, resultlen);
        }
    }

  unlock_slot (slot);
  xfree (result_buffer);

  /* Append the status word.  Note that we reserved the two extra
     bytes while allocating the buffer.  */
  if (retbuf)
    {
      (*retbuf)[(*retbuflen)++] = (sw >> 8);
      (*retbuf)[(*retbuflen)++] = sw;
    }

  if (DBG_CARD_IO && retbuf)
    log_printhex ("      dump: ", *retbuf, *retbuflen);

  return 0;
}
