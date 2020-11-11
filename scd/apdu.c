/* apdu.c - ISO 7816 APDU functions and low level I/O
 * Copyright (C) 2003, 2004, 2008, 2009, 2010,
 *               2011 Free Software Foundation, Inc.
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

/* NOTE: This module is also used by other software, thus the use of
   the macro USE_NPTH is mandatory.  For GnuPG this macro is
   guaranteed to be defined true. */

#include <config.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <signal.h>
#ifdef USE_NPTH
# include <unistd.h>
# include <fcntl.h>
# include <npth.h>
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
#include "../common/options.h"
#include "errors.h"
#include "memory.h"
#include "../common/util.h"
#include "../common/i18n.h"
#include "dynload.h"
#include "cardglue.h"
#else /* GNUPG_MAJOR_VERSION != 1 */
#include "scdaemon.h"
#include "../common/exechelp.h"
#endif /* GNUPG_MAJOR_VERSION != 1 */
#include "../common/host2net.h"

#include "iso7816.h"
#include "apdu.h"
#define CCID_DRIVER_INCLUDE_USB_IDS 1
#include "ccid-driver.h"

struct dev_list {
  void *table;
  const char *portstr;
  int idx;
  int idx_max;
};

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

  /* Function pointers initialized to the various backends.  */
  int (*connect_card)(int);
  int (*disconnect_card)(int);
  int (*close_reader)(int);
  int (*reset_reader)(int);
  int (*get_status_reader)(int, unsigned int *, int);
  int (*send_apdu_reader)(int,unsigned char *,size_t,
                          unsigned char *, size_t *, pininfo_t *);
  int (*check_pinpad)(int, int, pininfo_t *);
  void (*dump_status_reader)(int);
  int (*set_progress_cb)(int, gcry_handler_progress_t, void*);
  int (*set_prompt_cb)(int, void (*) (void *, int), void*);
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
    int pinmin;
    int pinmax;
    pcsc_dword_t current_state;
  } pcsc;
#ifdef USE_G10CODE_RAPDU
  struct {
    rapdu_t handle;
  } rapdu;
#endif /*USE_G10CODE_RAPDU*/
  char *rdrname;     /* Name of the connected reader or NULL if unknown. */
  unsigned int is_t0:1;     /* True if we know that we are running T=0. */
  unsigned int is_spr532:1; /* True if we know that the reader is a SPR532.  */
  unsigned int pinpad_varlen_supported:1;  /* True if we know that the reader
                                              supports variable length pinpad
                                              input.  */
  unsigned int require_get_status:1;
  unsigned char atr[33];
  size_t atrlen;           /* A zero length indicates that the ATR has
                              not yet been read; i.e. the card is not
                              ready for use. */
#ifdef USE_NPTH
  npth_mutex_t lock;
#endif
};
typedef struct reader_table_s *reader_table_t;

/* A global table to keep track of active readers. */
static struct reader_table_s reader_table[MAX_READER];

#ifdef USE_NPTH
static npth_mutex_t reader_table_lock;
#endif


/* PC/SC constants and function pointer. */
#define PCSC_SCOPE_USER      0
#define PCSC_SCOPE_TERMINAL  1
#define PCSC_SCOPE_SYSTEM    2
#define PCSC_SCOPE_GLOBAL    3

#define PCSC_PROTOCOL_T0     1
#define PCSC_PROTOCOL_T1     2
#ifdef HAVE_W32_SYSTEM
# define PCSC_PROTOCOL_RAW   0x00010000  /* The active protocol.  */
#else
# define PCSC_PROTOCOL_RAW   4
#endif

#define PCSC_SHARE_EXCLUSIVE 1
#define PCSC_SHARE_SHARED    2
#define PCSC_SHARE_DIRECT    3

#define PCSC_LEAVE_CARD      0
#define PCSC_RESET_CARD      1
#define PCSC_UNPOWER_CARD    2
#define PCSC_EJECT_CARD      3

#ifdef HAVE_W32_SYSTEM
# define PCSC_UNKNOWN    0x0000  /* The driver is not aware of the status.  */
# define PCSC_ABSENT     0x0001  /* Card is absent.  */
# define PCSC_PRESENT    0x0002  /* Card is present.  */
# define PCSC_SWALLOWED  0x0003  /* Card is present and electrical connected. */
# define PCSC_POWERED    0x0004  /* Card is powered.  */
# define PCSC_NEGOTIABLE 0x0005  /* Card is awaiting PTS.  */
# define PCSC_SPECIFIC   0x0006  /* Card is ready for use.  */
#else
# define PCSC_UNKNOWN    0x0001
# define PCSC_ABSENT     0x0002  /* Card is absent.  */
# define PCSC_PRESENT    0x0004  /* Card is present.  */
# define PCSC_SWALLOWED  0x0008  /* Card is present and electrical connected. */
# define PCSC_POWERED    0x0010  /* Card is powered.  */
# define PCSC_NEGOTIABLE 0x0020  /* Card is awaiting PTS.  */
# define PCSC_SPECIFIC   0x0040  /* Card is ready for use.  */
#endif

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
#define PCSC_STATE_MUTE        0x0200  /* Unresponsive card.  */
#ifdef HAVE_W32_SYSTEM
# define PCSC_STATE_UNPOWERED  0x0400  /* Card not powerred up.  */
#endif

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
#define PCSC_E_SERVICE_STOPPED         0x8010001E
#define PCSC_W_RESET_CARD              0x80100068
#define PCSC_W_REMOVED_CARD            0x80100069

/* Fix pcsc-lite ABI incompatibility.  */
#ifndef SCARD_CTL_CODE
#ifdef _WIN32
#include <winioctl.h>
#define SCARD_CTL_CODE(code) CTL_CODE(FILE_DEVICE_SMARTCARD, (code), \
                                      METHOD_BUFFERED, FILE_ANY_ACCESS)
#else
#define SCARD_CTL_CODE(code) (0x42000000 + (code))
#endif
#endif

#define CM_IOCTL_GET_FEATURE_REQUEST     SCARD_CTL_CODE(3400)
#define CM_IOCTL_VENDOR_IFD_EXCHANGE     SCARD_CTL_CODE(1)
#define FEATURE_VERIFY_PIN_DIRECT        0x06
#define FEATURE_MODIFY_PIN_DIRECT        0x07
#define FEATURE_GET_TLV_PROPERTIES       0x12

#define PCSCv2_PART10_PROPERTY_bEntryValidationCondition 2
#define PCSCv2_PART10_PROPERTY_bTimeOut2                 3
#define PCSCv2_PART10_PROPERTY_bMinPINSize               6
#define PCSCv2_PART10_PROPERTY_bMaxPINSize               7
#define PCSCv2_PART10_PROPERTY_wIdVendor                11
#define PCSCv2_PART10_PROPERTY_wIdProduct               12


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
static int pcsc_vendor_specific_init (int slot);
static int pcsc_get_status (int slot, unsigned int *status, int on_wire);
static int reset_pcsc_reader (int slot);
static int apdu_get_status_internal (int slot, int hang, unsigned int *status,
                                     int on_wire);
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
#ifdef USE_NPTH
  int err;

  err = npth_mutex_lock (&reader_table[slot].lock);
  if (err)
    {
      log_error ("failed to acquire apdu lock: %s\n", strerror (err));
      return SW_HOST_LOCKING_FAILED;
    }
#endif /*USE_NPTH*/
  return 0;
}

static int
trylock_slot (int slot)
{
#ifdef USE_NPTH
  int err;

  err = npth_mutex_trylock (&reader_table[slot].lock);
  if (err == EBUSY)
    return SW_HOST_BUSY;
  else if (err)
    {
      log_error ("failed to acquire apdu lock: %s\n", strerror (err));
      return SW_HOST_LOCKING_FAILED;
    }
#endif /*USE_NPTH*/
  return 0;
}

static void
unlock_slot (int slot)
{
#ifdef USE_NPTH
  int err;

  err = npth_mutex_unlock (&reader_table[slot].lock);
  if (err)
    log_error ("failed to release apdu lock: %s\n", strerror (errno));
#endif /*USE_NPTH*/
}


/* Find an unused reader slot for PORTSTR and put it into the reader
   table.  Return -1 on error or the index into the reader table.
   Acquire slot's lock on successful return.  Caller needs to unlock it.  */
static int
new_reader_slot (void)
{
  int i, reader = -1;

  for (i=0; i < MAX_READER; i++)
    if (!reader_table[i].used)
      {
        reader = i;
        reader_table[reader].used = 1;
        break;
      }

  if (reader == -1)
    {
      log_error ("new_reader_slot: out of slots\n");
      return -1;
    }

  if (lock_slot (reader))
    {
      reader_table[reader].used = 0;
      return -1;
    }

  reader_table[reader].connect_card = NULL;
  reader_table[reader].disconnect_card = NULL;
  reader_table[reader].close_reader = NULL;
  reader_table[reader].reset_reader = NULL;
  reader_table[reader].get_status_reader = NULL;
  reader_table[reader].send_apdu_reader = NULL;
  reader_table[reader].check_pinpad = check_pcsc_pinpad;
  reader_table[reader].dump_status_reader = NULL;
  reader_table[reader].set_progress_cb = NULL;
  reader_table[reader].set_prompt_cb = NULL;
  reader_table[reader].pinpad_verify = pcsc_pinpad_verify;
  reader_table[reader].pinpad_modify = pcsc_pinpad_modify;

  reader_table[reader].is_t0 = 1;
  reader_table[reader].is_spr532 = 0;
  reader_table[reader].pinpad_varlen_supported = 0;
  reader_table[reader].require_get_status = 1;
  reader_table[reader].pcsc.verify_ioctl = 0;
  reader_table[reader].pcsc.modify_ioctl = 0;
  reader_table[reader].pcsc.pinmin = -1;
  reader_table[reader].pcsc.pinmax = -1;
  reader_table[reader].pcsc.current_state = PCSC_STATE_UNAWARE;

  return reader;
}


static void
dump_reader_status (int slot)
{
  if (!opt.verbose)
    return;

  if (reader_table[slot].dump_status_reader)
    reader_table[slot].dump_status_reader (slot);

  if (reader_table[slot].atrlen)
    {
      log_info ("slot %d: ATR=", slot);
      log_printhex (reader_table[slot].atr, reader_table[slot].atrlen, "");
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
    case SW_HOST_CANCELLED: return "cancelled";
    case SW_HOST_USB_OTHER:    return "USB general error";
    case SW_HOST_USB_IO:       return "USB I/O error";
    case SW_HOST_USB_ACCESS:   return "USB permission denied";
    case SW_HOST_USB_NO_DEVICE:return "USB no device";
    case SW_HOST_USB_BUSY:     return "USB busy";
    case SW_HOST_USB_TIMEOUT:  return "USB timeout";
    case SW_HOST_USB_OVERFLOW: return "USB overflow";
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
    case SW_REF_DATA_INV   : return "referenced data invalidated";
    case SW_USE_CONDITIONS : return "use conditions not satisfied";
    case SW_BAD_PARAMETER  : return "bad parameter";
    case SW_NOT_SUPPORTED  : return "not supported";
    case SW_FILE_NOT_FOUND : return "file not found";
    case SW_RECORD_NOT_FOUND:return "record not found";
    case SW_REF_NOT_FOUND  : return "reference not found";
    case SW_NOT_ENOUGH_MEMORY: return "not enough memory space in the file";
    case SW_INCONSISTENT_LC: return "Lc inconsistent with TLV structure.";
    case SW_INCORRECT_P0_P1: return "incorrect parameters P0,P1";
    case SW_BAD_LC         : return "Lc inconsistent with P0,P1";
    case SW_BAD_P0_P1      : return "bad P0,P1";
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
       PC/SC Interface
 */

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

    case PCSC_E_CANCELLED:           rc = SW_HOST_CANCELLED; break;
    case PCSC_E_NO_MEMORY:           rc = SW_HOST_OUT_OF_CORE; break;
    case PCSC_E_TIMEOUT:             rc = SW_HOST_CARD_IO_ERROR; break;
    case PCSC_E_NO_SERVICE:
    case PCSC_E_SERVICE_STOPPED:
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


static int
pcsc_get_status (int slot, unsigned int *status, int on_wire)
{
  long err;
  struct pcsc_readerstate_s rdrstates[1];

  (void)on_wire;
  memset (rdrstates, 0, sizeof *rdrstates);
  rdrstates[0].reader = reader_table[slot].rdrname;
  rdrstates[0].current_state = reader_table[slot].pcsc.current_state;
  err = pcsc_get_status_change (reader_table[slot].pcsc.context,
                                0,
                                rdrstates, 1);
  if (err == PCSC_E_TIMEOUT)
    err = 0; /* Timeout is no error here.  */
  if (err)
    {
      log_error ("pcsc_get_status_change failed: %s (0x%lx)\n",
                 pcsc_error_string (err), err);
      return pcsc_error_to_sw (err);
    }

  if ((rdrstates[0].event_state & PCSC_STATE_CHANGED))
    reader_table[slot].pcsc.current_state =
      (rdrstates[0].event_state & ~PCSC_STATE_CHANGED);

  if (DBG_READER)
    log_debug
      ("pcsc_get_status_change: %s%s%s%s%s%s%s%s%s%s\n",
       (rdrstates[0].event_state & PCSC_STATE_IGNORE)? " ignore":"",
       (rdrstates[0].event_state & PCSC_STATE_CHANGED)? " changed":"",
       (rdrstates[0].event_state & PCSC_STATE_UNKNOWN)? " unknown":"",
       (rdrstates[0].event_state & PCSC_STATE_UNAVAILABLE)?" unavail":"",
       (rdrstates[0].event_state & PCSC_STATE_EMPTY)? " empty":"",
       (rdrstates[0].event_state & PCSC_STATE_PRESENT)? " present":"",
       (rdrstates[0].event_state & PCSC_STATE_ATRMATCH)? " atr":"",
       (rdrstates[0].event_state & PCSC_STATE_EXCLUSIVE)? " excl":"",
       (rdrstates[0].event_state & PCSC_STATE_INUSE)? " inuse":"",
       (rdrstates[0].event_state & PCSC_STATE_MUTE)? " mute":"" );

  *status = 0;
  if ( (reader_table[slot].pcsc.current_state & PCSC_STATE_PRESENT) )
    {
      *status |= APDU_CARD_PRESENT;
      if ( !(reader_table[slot].pcsc.current_state & PCSC_STATE_MUTE) )
        *status |= APDU_CARD_ACTIVE;
    }
#ifndef HAVE_W32_SYSTEM
  /* We indicate a useful card if it is not in use by another
     application.  This is because we only use exclusive access
     mode.  */
  if ( (*status & (APDU_CARD_PRESENT|APDU_CARD_ACTIVE))
       == (APDU_CARD_PRESENT|APDU_CARD_ACTIVE)
       && !(reader_table[slot].pcsc.current_state & PCSC_STATE_INUSE) )
    *status |= APDU_CARD_USABLE;
#else
  /* Some winscard drivers may set EXCLUSIVE and INUSE at the same
     time when we are the only user (SCM SCR335) under Windows.  */
  if ((*status & (APDU_CARD_PRESENT|APDU_CARD_ACTIVE))
      == (APDU_CARD_PRESENT|APDU_CARD_ACTIVE))
    *status |= APDU_CARD_USABLE;
#endif

  if (!on_wire && (rdrstates[0].event_state & PCSC_STATE_CHANGED))
    /* Event like sleep/resume occurs, which requires RESET.  */
    return SW_HOST_NO_READER;
  else
    return 0;
}


/* Send the APDU of length APDULEN to SLOT and return a maximum of
   *BUFLEN data in BUFFER, the actual returned size will be stored at
   BUFLEN.  Returns: A status word. */
static int
pcsc_send_apdu (int slot, unsigned char *apdu, size_t apdulen,
                unsigned char *buffer, size_t *buflen,
                pininfo_t *pininfo)
{
  long err;
  struct pcsc_io_request_s send_pci;
  pcsc_dword_t recv_len;

  (void)pininfo;

  if (!reader_table[slot].atrlen
      && (err = reset_pcsc_reader (slot)))
    return err;

  if (DBG_CARD_IO)
    log_printhex (apdu, apdulen, "  PCSC_data:");

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

  /* Handle fatal errors which require shutdown of reader.  */
  if (err == PCSC_E_NOT_TRANSACTED || err == PCSC_W_RESET_CARD
      || err == PCSC_W_REMOVED_CARD)
    {
      reader_table[slot].pcsc.current_state = PCSC_STATE_UNAWARE;
      scd_kick_the_loop ();
    }

  return pcsc_error_to_sw (err);
}


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
  long err;

  err = pcsc_control (reader_table[slot].pcsc.card, ioctl_code,
                      cntlbuf, len, buffer, buflen? *buflen:0, buflen);
  if (err)
    {
      log_error ("pcsc_control failed: %s (0x%lx)\n",
                 pcsc_error_string (err), err);
      return pcsc_error_to_sw (err);
    }

  return 0;
}


static int
close_pcsc_reader (int slot)
{
  pcsc_release_context (reader_table[slot].pcsc.context);
  return 0;
}


/* Connect a PC/SC card.  */
static int
connect_pcsc_card (int slot)
{
  long err;

  assert (slot >= 0 && slot < MAX_READER);

  if (reader_table[slot].pcsc.card)
    return SW_HOST_ALREADY_CONNECTED;

  reader_table[slot].atrlen = 0;
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
      pcsc_dword_t card_state, card_protocol;

      pcsc_vendor_specific_init (slot);

      atrlen = DIM (reader_table[0].atr);
      readerlen = sizeof reader -1 ;
      err = pcsc_status (reader_table[slot].pcsc.card,
                         reader, &readerlen,
                         &card_state, &card_protocol,
                         reader_table[slot].atr, &atrlen);
      if (err)
        log_error ("pcsc_status failed: %s (0x%lx) %lu\n",
                   pcsc_error_string (err), err, (long unsigned int)readerlen);
      else
        {
          if (atrlen > DIM (reader_table[0].atr))
            log_bug ("ATR returned by pcsc_status is too large\n");
          reader_table[slot].atrlen = atrlen;
          reader_table[slot].is_t0 = !!(card_protocol & PCSC_PROTOCOL_T0);
        }
    }

  dump_reader_status (slot);
  return pcsc_error_to_sw (err);
}


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


/* Send an PC/SC reset command and return a status word on error or 0
   on success. */
static int
reset_pcsc_reader (int slot)
{
  int sw;

  sw = disconnect_pcsc_card (slot);
  if (!sw)
    sw = connect_pcsc_card (slot);

  return sw;
}


/* Examine reader specific parameters and initialize.  This is mostly
   for pinpad input.  Called at opening the connection to the reader.  */
static int
pcsc_vendor_specific_init (int slot)
{
  unsigned char buf[256];
  pcsc_dword_t len;
  int sw;
  int vendor = 0;
  int product = 0;
  pcsc_dword_t get_tlv_ioctl = (pcsc_dword_t)-1;
  unsigned char *p;

  len = sizeof (buf);
  sw = control_pcsc (slot, CM_IOCTL_GET_FEATURE_REQUEST, NULL, 0, buf, &len);
  if (sw)
    {
      log_error ("pcsc_vendor_specific_init: GET_FEATURE_REQUEST failed: %d\n",
                 sw);
      return SW_NOT_SUPPORTED;
    }
  else
    {
      p = buf;
      while (p < buf + len)
        {
          unsigned char code = *p++;
          int l = *p++;
          unsigned int v = 0;

          if (l == 1)
            v = p[0];
          else if (l == 2)
            v = buf16_to_uint (p);
          else if (l == 4)
            v = buf32_to_uint (p);

          if (code == FEATURE_VERIFY_PIN_DIRECT)
            reader_table[slot].pcsc.verify_ioctl = v;
          else if (code == FEATURE_MODIFY_PIN_DIRECT)
            reader_table[slot].pcsc.modify_ioctl = v;
          else if (code == FEATURE_GET_TLV_PROPERTIES)
            get_tlv_ioctl = v;

          if (DBG_CARD_IO)
            log_debug ("feature: code=%02X, len=%d, v=%02X\n", code, l, v);

          p += l;
        }
    }

  if (get_tlv_ioctl == (pcsc_dword_t)-1)
    {
      /*
       * For system which doesn't support GET_TLV_PROPERTIES,
       * we put some heuristics here.
       */
      if (reader_table[slot].rdrname)
        {
          if (strstr (reader_table[slot].rdrname, "SPRx32"))
            {
              reader_table[slot].is_spr532 = 1;
              reader_table[slot].pinpad_varlen_supported = 1;
            }
          else if (strstr (reader_table[slot].rdrname, "ST-2xxx"))
            {
              reader_table[slot].pcsc.pinmax = 15;
              reader_table[slot].pinpad_varlen_supported = 1;
            }
          else if (strstr (reader_table[slot].rdrname, "cyberJack")
                   || strstr (reader_table[slot].rdrname, "DIGIPASS")
                   || strstr (reader_table[slot].rdrname, "Gnuk")
                   || strstr (reader_table[slot].rdrname, "KAAN")
                   || strstr (reader_table[slot].rdrname, "Trustica"))
            reader_table[slot].pinpad_varlen_supported = 1;
        }

      return 0;
    }

  len = sizeof (buf);
  sw = control_pcsc (slot, get_tlv_ioctl, NULL, 0, buf, &len);
  if (sw)
    {
      log_error ("pcsc_vendor_specific_init: GET_TLV_IOCTL failed: %d\n", sw);
      return SW_NOT_SUPPORTED;
    }

  p = buf;
  while (p < buf + len)
    {
      unsigned char tag = *p++;
      int l = *p++;
      unsigned int v = 0;

      /* Umm... here is little endian, while the encoding above is big.  */
      if (l == 1)
        v = p[0];
      else if (l == 2)
        v = (((unsigned int)p[1] << 8) | p[0]);
      else if (l == 4)
        v = (((unsigned int)p[3] << 24) | (p[2] << 16) | (p[1] << 8) | p[0]);

      if (tag == PCSCv2_PART10_PROPERTY_bMinPINSize)
        reader_table[slot].pcsc.pinmin = v;
      else if (tag == PCSCv2_PART10_PROPERTY_bMaxPINSize)
        reader_table[slot].pcsc.pinmax = v;
      else if (tag == PCSCv2_PART10_PROPERTY_wIdVendor)
        vendor = v;
      else if (tag == PCSCv2_PART10_PROPERTY_wIdProduct)
        product = v;

      if (DBG_CARD_IO)
        log_debug ("TLV properties: tag=%02X, len=%d, v=%08X\n", tag, l, v);

      p += l;
    }

  if (vendor == VENDOR_VEGA && product == VEGA_ALPHA)
    {
      /*
       * Please read the comment of ccid_vendor_specific_init in
       * ccid-driver.c.
       */
      const unsigned char cmd[] = { '\xb5', '\x01', '\x00', '\x03', '\x00' };
      sw = control_pcsc (slot, CM_IOCTL_VENDOR_IFD_EXCHANGE,
                         cmd, sizeof (cmd), NULL, 0);
      if (sw)
        return SW_NOT_SUPPORTED;
    }
  else if (vendor == VENDOR_SCM && product == SCM_SPR532) /* SCM SPR532 */
    {
      reader_table[slot].is_spr532 = 1;
      reader_table[slot].pinpad_varlen_supported = 1;
    }
  else if (vendor == 0x046a)
    {
      /* Cherry ST-2xxx (product == 0x003e) supports TPDU level
       * exchange.  Other products which only support short APDU level
       * exchange only work with shorter keys like RSA 1024.
       */
      reader_table[slot].pcsc.pinmax = 15;
      reader_table[slot].pinpad_varlen_supported = 1;
    }
  else if (vendor == 0x0c4b /* Tested with Reiner cyberJack GO */
           || vendor == 0x1a44 /* Tested with Vasco DIGIPASS 920 */
           || vendor == 0x234b /* Tested with FSIJ Gnuk Token */
           || vendor == 0x0d46 /* Tested with KAAN Advanced??? */
           || (vendor == 0x1fc9 && product == 0x81e6) /* Tested with Trustica Cryptoucan */)
    reader_table[slot].pinpad_varlen_supported = 1;

  return 0;
}


/* Open the PC/SC reader without using the wrapper.  Returns -1 on
   error or a slot number for the reader.  */
static int
open_pcsc_reader (const char *portstr)
{
  long err;
  int slot;
  char *list = NULL;
  char *rdrname = NULL;
  pcsc_dword_t nreader;
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

  p = list;
  while (nreader)
    {
      if (!*p && !p[1])
        break;
      log_info ("detected reader '%s'\n", p);
      if (nreader < (strlen (p)+1))
        {
          log_error ("invalid response from pcsc_list_readers\n");
          break;
        }
      if (!rdrname && portstr && !strncmp (p, portstr, strlen (portstr)))
        rdrname = p;
      nreader -= strlen (p)+1;
      p += strlen (p) + 1;
    }

  if (!rdrname)
    rdrname = list;

  reader_table[slot].rdrname = xtrystrdup (rdrname);
  if (!reader_table[slot].rdrname)
    {
      log_error ("error allocating memory for reader name\n");
      pcsc_release_context (reader_table[slot].pcsc.context);
      reader_table[slot].used = 0;
      unlock_slot (slot);
      return -1;
    }
  xfree (list);
  list = NULL;

  reader_table[slot].pcsc.card = 0;
  reader_table[slot].atrlen = 0;

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


/* Check whether the reader supports the ISO command code COMMAND
   on the pinpad.  Return 0 on success.  */
static int
check_pcsc_pinpad (int slot, int command, pininfo_t *pininfo)
{
  int r;

  if (reader_table[slot].pcsc.pinmin >= 0)
    pininfo->minlen = reader_table[slot].pcsc.pinmin;

  if (reader_table[slot].pcsc.pinmax >= 0)
    pininfo->maxlen = reader_table[slot].pcsc.pinmax;

  if (!pininfo->minlen)
    pininfo->minlen = 1;
  if (!pininfo->maxlen)
    pininfo->maxlen = 15;

  if ((command == ISO7816_VERIFY && reader_table[slot].pcsc.verify_ioctl != 0)
      || (command == ISO7816_CHANGE_REFERENCE_DATA
          && reader_table[slot].pcsc.modify_ioctl != 0))
    r = 0;                       /* Success */
  else
    r = SW_NOT_SUPPORTED;

  if (DBG_CARD_IO)
    log_debug ("check_pcsc_pinpad: command=%02X, r=%d\n",
               (unsigned int)command, r);

  if (reader_table[slot].pinpad_varlen_supported)
    pininfo->fixedlen = 0;

  return r;
}

#define PIN_VERIFY_STRUCTURE_SIZE 24
static int
pcsc_pinpad_verify (int slot, int class, int ins, int p0, int p1,
                    pininfo_t *pininfo)
{
  int sw;
  unsigned char *pin_verify;
  int len = PIN_VERIFY_STRUCTURE_SIZE + pininfo->fixedlen;
  /*
   * The result buffer is only expected to have two-byte result on
   * return.  However, some implementation uses this buffer for lower
   * layer too and it assumes that there is enough space for lower
   * layer communication.  Such an implementation fails for TPDU
   * readers with "insufficient buffer", as it needs header and
   * trailer.  Six is the number for header + result + trailer (TPDU).
   */
  unsigned char result[6];
  pcsc_dword_t resultlen = 6;
  int no_lc;

  if (!reader_table[slot].atrlen
      && (sw = reset_pcsc_reader (slot)))
    return sw;

  if (pininfo->fixedlen < 0 || pininfo->fixedlen >= 16)
    return SW_NOT_SUPPORTED;

  pin_verify = xtrymalloc (len);
  if (!pin_verify)
    return SW_HOST_OUT_OF_CORE;

  no_lc = (!pininfo->fixedlen && reader_table[slot].is_spr532);

  pin_verify[0] = 0x00; /* bTimeOut */
  pin_verify[1] = 0x00; /* bTimeOut2 */
  pin_verify[2] = 0x82; /* bmFormatString: Byte, pos=0, left, ASCII. */
  pin_verify[3] = pininfo->fixedlen; /* bmPINBlockString */
  pin_verify[4] = 0x00; /* bmPINLengthFormat */
  pin_verify[5] = pininfo->maxlen; /* wPINMaxExtraDigit */
  pin_verify[6] = pininfo->minlen; /* wPINMaxExtraDigit */
  pin_verify[7] = 0x02; /* bEntryValidationCondition: Validation key pressed */
  if (pininfo->minlen && pininfo->maxlen && pininfo->minlen == pininfo->maxlen)
    pin_verify[7] |= 0x01; /* Max size reached.  */
  pin_verify[8] = 0x01; /* bNumberMessage: One message */
  pin_verify[9] =  0x09; /* wLangId: 0x0409: US English */
  pin_verify[10] = 0x04; /* wLangId: 0x0409: US English */
  pin_verify[11] = 0x00; /* bMsgIndex */
  pin_verify[12] = 0x00; /* bTeoPrologue[0] */
  pin_verify[13] = 0x00; /* bTeoPrologue[1] */
  pin_verify[14] = pininfo->fixedlen + 0x05 - no_lc; /* bTeoPrologue[2] */
  pin_verify[15] = pininfo->fixedlen + 0x05 - no_lc; /* ulDataLength */
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
  else if (no_lc)
    len--;

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
  unsigned char result[6];      /* See the comment at pinpad_verify.  */
  pcsc_dword_t resultlen = 6;
  int no_lc;

  if (!reader_table[slot].atrlen
      && (sw = reset_pcsc_reader (slot)))
    return sw;

  if (pininfo->fixedlen < 0 || pininfo->fixedlen >= 16)
    return SW_NOT_SUPPORTED;

  pin_modify = xtrymalloc (len);
  if (!pin_modify)
    return SW_HOST_OUT_OF_CORE;

  no_lc = (!pininfo->fixedlen && reader_table[slot].is_spr532);

  pin_modify[0] = 0x00; /* bTimeOut */
  pin_modify[1] = 0x00; /* bTimeOut2 */
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
  pin_modify[11] = 0x03; /* bNumberMessage: Three messages */
  pin_modify[12] = 0x09; /* wLangId: 0x0409: US English */
  pin_modify[13] = 0x04; /* wLangId: 0x0409: US English */
  pin_modify[14] = 0x00; /* bMsgIndex1 */
  pin_modify[15] = 0x01; /* bMsgIndex2 */
  pin_modify[16] = 0x02; /* bMsgIndex3 */
  pin_modify[17] = 0x00; /* bTeoPrologue[0] */
  pin_modify[18] = 0x00; /* bTeoPrologue[1] */
  pin_modify[19] = 2 * pininfo->fixedlen + 0x05 - no_lc; /* bTeoPrologue[2] */
  pin_modify[20] = 2 * pininfo->fixedlen + 0x05 - no_lc; /* ulDataLength */
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
  else if (no_lc)
    len--;

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
set_prompt_cb_ccid_reader (int slot, void (*cb) (void *, int ), void *cb_arg)
{
  reader_table_t slotp = reader_table + slot;

  return ccid_set_prompt_cb (slotp->ccid.handle, cb, cb_arg);
}


static int
get_status_ccid (int slot, unsigned int *status, int on_wire)
{
  int rc;
  int bits;

  rc = ccid_slot_status (reader_table[slot].ccid.handle, &bits, on_wire);
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
    log_printhex (apdu, apdulen, " raw apdu:");

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
open_ccid_reader (struct dev_list *dl)
{
  int err;
  int slot;
  int require_get_status;
  reader_table_t slotp;

  slot = new_reader_slot ();
  if (slot == -1)
    return -1;
  slotp = reader_table + slot;

  err = ccid_open_reader (dl->portstr, dl->idx, dl->table,
                          &slotp->ccid.handle, &slotp->rdrname);
  if (!err)
    {
      err = ccid_get_atr (slotp->ccid.handle,
                          slotp->atr, sizeof slotp->atr, &slotp->atrlen);
      if (err)
        ccid_close_reader (slotp->ccid.handle);
    }

  if (err)
    {
      slotp->used = 0;
      unlock_slot (slot);
      return -1;
    }

  require_get_status = ccid_require_get_status (slotp->ccid.handle);

  reader_table[slot].close_reader = close_ccid_reader;
  reader_table[slot].reset_reader = reset_ccid_reader;
  reader_table[slot].get_status_reader = get_status_ccid;
  reader_table[slot].send_apdu_reader = send_apdu_ccid;
  reader_table[slot].check_pinpad = check_ccid_pinpad;
  reader_table[slot].dump_status_reader = dump_ccid_reader_status;
  reader_table[slot].set_progress_cb = set_progress_cb_ccid_reader;
  reader_table[slot].set_prompt_cb = set_prompt_cb_ccid_reader;
  reader_table[slot].pinpad_verify = ccid_pinpad_operation;
  reader_table[slot].pinpad_modify = ccid_pinpad_operation;
  /* Our CCID reader code does not support T=0 at all, thus reset the
     flag.  */
  reader_table[slot].is_t0 = 0;
  reader_table[slot].require_get_status = require_get_status;

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
my_rapdu_get_status (int slot, unsigned int *status, int on_wire)
{
  int err;
  reader_table_t slotp;
  rapdu_msg_t msg = NULL;
  int oldslot;

  (void)on_wire;
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
    log_printhex (apdu, apdulen, "  APDU_data:");

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
gpg_error_t
apdu_dev_list_start (const char *portstr, struct dev_list **l_p)
{
  struct dev_list *dl = xtrymalloc (sizeof (struct dev_list));

  *l_p = NULL;
  if (!dl)
    return gpg_error_from_syserror ();

  dl->portstr = portstr;
  dl->idx = 0;

  npth_mutex_lock (&reader_table_lock);

#ifdef HAVE_LIBUSB
  if (opt.disable_ccid)
    {
      dl->table = NULL;
      dl->idx_max = 1;
    }
  else
    {
      gpg_error_t err;

      err = ccid_dev_scan (&dl->idx_max, &dl->table);
      if (err)
        return err;

      if (dl->idx_max == 0)
        {
          /* If a CCID reader specification has been given, the user does
             not want a fallback to other drivers. */
          if (portstr && strlen (portstr) > 5 && portstr[4] == ':')
            {
              if (DBG_READER)
                log_debug ("leave: apdu_open_reader => slot=-1 (no ccid)\n");

              xfree (dl);
              npth_mutex_unlock (&reader_table_lock);
              return gpg_error (GPG_ERR_ENODEV);
            }
          else
            dl->idx_max = 1;
        }
    }
#else
  dl->table = NULL;
  dl->idx_max = 1;
#endif /* HAVE_LIBUSB */

  *l_p = dl;
  return 0;
}

void
apdu_dev_list_finish (struct dev_list *dl)
{
#ifdef HAVE_LIBUSB
  if (dl->table)
    ccid_dev_scan_finish (dl->table, dl->idx_max);
#endif
  xfree (dl);
  npth_mutex_unlock (&reader_table_lock);
}


/* Open the reader and return an internal slot number or -1 on
   error. If PORTSTR is NULL we default to a suitable port (for ctAPI:
   the first USB reader.  For PC/SC the first listed reader). */
static int
apdu_open_one_reader (const char *portstr)
{
  static int pcsc_api_loaded;
  int slot;

  if (DBG_READER)
    log_debug ("enter: apdu_open_reader: portstr=%s\n", portstr);

  /* Lets try the PC/SC API */
  if (!pcsc_api_loaded)
    {
      void *handle;

      handle = dlopen (opt.pcsc_driver, RTLD_LAZY);
      if (!handle)
        {
          log_error ("apdu_open_reader: failed to open driver '%s': %s\n",
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
      pcsc_api_loaded = 1;
    }

  slot = open_pcsc_reader (portstr);

  if (DBG_READER)
    log_debug ("leave: apdu_open_reader => slot=%d [pc/sc]\n", slot);
  return slot;
}

int
apdu_open_reader (struct dev_list *dl, int app_empty)
{
  int slot;

#ifdef HAVE_LIBUSB
  if (dl->table)
    { /* CCID readers.  */
      int readerno;

      /* See whether we want to use the reader ID string or a reader
         number. A readerno of -1 indicates that the reader ID string is
         to be used. */
      if (dl->portstr && strchr (dl->portstr, ':'))
        readerno = -1; /* We want to use the readerid.  */
      else if (dl->portstr)
        {
          readerno = atoi (dl->portstr);
          if (readerno < 0)
            {
              return -1;
            }
        }
      else
        readerno = 0;  /* Default. */

      if (readerno > 0)
        { /* Use single, the specific reader.  */
          if (readerno >= dl->idx_max)
            return -1;

          dl->idx = readerno;
          dl->portstr = NULL;
          slot = open_ccid_reader (dl);
          dl->idx = dl->idx_max;
          if (slot >= 0)
            return slot;
          else
            return -1;
        }

      while (dl->idx < dl->idx_max)
        {
          unsigned int bai = ccid_get_BAI (dl->idx, dl->table);

          if (DBG_READER)
            log_debug ("apdu_open_reader: BAI=%x\n", bai);

          /* Check identity by BAI against already opened HANDLEs.  */
          for (slot = 0; slot < MAX_READER; slot++)
            if (reader_table[slot].used
                && reader_table[slot].ccid.handle
                && ccid_compare_BAI (reader_table[slot].ccid.handle, bai))
              break;

          if (slot == MAX_READER)
            { /* Found a new device.  */
              if (DBG_READER)
                log_debug ("apdu_open_reader: new device=%x\n", bai);

              slot = open_ccid_reader (dl);

              dl->idx++;
              if (slot >= 0)
                return slot;
              else
                {
                  /* Skip this reader.  */
                  log_error ("ccid open error: skip\n");
                  continue;
                }
            }
          else
            dl->idx++;
        }

      /* Not found.  Try one for PC/SC, only when it's the initial scan.  */
      if (app_empty && dl->idx == dl->idx_max)
        {
          dl->idx++;
          slot = apdu_open_one_reader (dl->portstr);
        }
      else
        slot = -1;
    }
  else
#endif
    { /* PC/SC readers.  */
      if (app_empty && dl->idx == 0)
        {
          dl->idx++;
          slot = apdu_open_one_reader (dl->portstr);
        }
      else
        slot = -1;
    }

  return slot;
}


/* Open an remote reader and return an internal slot number or -1 on
   error. This function is an alternative to apdu_open_reader and used
   with remote readers only.  Note that the supplied CLOSEFNC will
   only be called once and the slot will not be valid afther this.

   If PORTSTR is NULL we default to the first available port.
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

  if (DBG_READER)
    log_debug ("enter: apdu_close_reader: slot=%d\n", slot);

  if (slot < 0 || slot >= MAX_READER || !reader_table[slot].used )
    {
      if (DBG_READER)
        log_debug ("leave: apdu_close_reader => SW_HOST_NO_DRIVER\n");
      return SW_HOST_NO_DRIVER;
    }
  sw = apdu_disconnect (slot);
  if (sw)
    {
      /*
       * When the reader/token was removed it might come here.
       * It should go through to call CLOSE_READER even if we got an error.
       */
      if (DBG_READER)
        log_debug ("apdu_close_reader => 0x%x (apdu_disconnect)\n", sw);
    }
  if (reader_table[slot].close_reader)
    {
      sw = reader_table[slot].close_reader (slot);
      reader_table[slot].used = 0;
      if (DBG_READER)
        log_debug ("leave: apdu_close_reader => 0x%x (close_reader)\n", sw);
      return sw;
    }
  xfree (reader_table[slot].rdrname);
  reader_table[slot].rdrname = NULL;
  reader_table[slot].used = 0;
  if (DBG_READER)
    log_debug ("leave: apdu_close_reader => SW_HOST_NOT_SUPPORTED\n");
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
      npth_mutex_lock (&reader_table_lock);
      for (slot = 0; slot < MAX_READER; slot++)
        if (reader_table[slot].used)
          {
            apdu_disconnect (slot);
            if (reader_table[slot].close_reader)
              reader_table[slot].close_reader (slot);
            xfree (reader_table[slot].rdrname);
            reader_table[slot].rdrname = NULL;
            reader_table[slot].used = 0;
          }
      npth_mutex_unlock (&reader_table_lock);
      sentinel = 0;
    }
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
   return an error for an inactive card or if no card is available.
   Return -1 on error.  Return 1 if reader requires get_status to
   watch card removal.  Return 0 if it's a token (always with a card),
   or it supports INTERRUPT endpoint to watch card removal.
  */
int
apdu_connect (int slot)
{
  int sw = 0;
  unsigned int status = 0;

  if (DBG_READER)
    log_debug ("enter: apdu_connect: slot=%d\n", slot);

  if (slot < 0 || slot >= MAX_READER || !reader_table[slot].used )
    {
      if (DBG_READER)
        log_debug ("leave: apdu_connect => SW_HOST_NO_DRIVER\n");
      return -1;
    }

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

  /* We need to call apdu_get_status_internal, so that the last-status
     machinery gets setup properly even if a card is inserted while
     scdaemon is fired up and apdu_get_status has not yet been called.
     Without that we would force a reset of the card with the next
     call to apdu_get_status.  */
  if (!sw)
    sw = apdu_get_status_internal (slot, 1, &status, 1);

  if (sw)
    ;
  else if (!(status & APDU_CARD_PRESENT))
    sw = SW_HOST_NO_CARD;
  else if ((status & APDU_CARD_PRESENT) && !(status & APDU_CARD_ACTIVE))
    sw = SW_HOST_CARD_INACTIVE;

  if (sw == SW_HOST_CARD_INACTIVE)
    {
      /* Try power it up again.  */
      sw = apdu_reset (slot);
    }

  if (DBG_READER)
    log_debug ("leave: apdu_connect => sw=0x%x\n", sw);

  if (sw)
    return -1;

  return reader_table[slot].require_get_status;
}


int
apdu_disconnect (int slot)
{
  int sw;

  if (DBG_READER)
    log_debug ("enter: apdu_disconnect: slot=%d\n", slot);

  if (slot < 0 || slot >= MAX_READER || !reader_table[slot].used )
    {
      if (DBG_READER)
        log_debug ("leave: apdu_disconnect => SW_HOST_NO_DRIVER\n");
      return SW_HOST_NO_DRIVER;
    }

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

  if (DBG_READER)
    log_debug ("leave: apdu_disconnect => sw=0x%x\n", sw);
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


int
apdu_set_prompt_cb (int slot, void (*cb) (void *, int), void *cb_arg)
{
  int sw;

  if (slot < 0 || slot >= MAX_READER || !reader_table[slot].used )
    return SW_HOST_NO_DRIVER;

  if (reader_table[slot].set_prompt_cb)
    {
      sw = lock_slot (slot);
      if (!sw)
        {
          sw = reader_table[slot].set_prompt_cb (slot, cb, cb_arg);
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

  if (DBG_READER)
    log_debug ("enter: apdu_reset: slot=%d\n", slot);

  if (slot < 0 || slot >= MAX_READER || !reader_table[slot].used )
    {
      if (DBG_READER)
        log_debug ("leave: apdu_reset => SW_HOST_NO_DRIVER\n");
      return SW_HOST_NO_DRIVER;
    }

  if ((sw = lock_slot (slot)))
    {
      if (DBG_READER)
        log_debug ("leave: apdu_reset => sw=0x%x (lock_slot)\n", sw);
      return sw;
    }

  if (reader_table[slot].reset_reader)
    sw = reader_table[slot].reset_reader (slot);

  unlock_slot (slot);
  if (DBG_READER)
    log_debug ("leave: apdu_reset => sw=0x%x\n", sw);
  return sw;
}


/* Return the ATR or NULL if none is available.  On success the length
   of the ATR is stored at ATRLEN.  The caller must free the returned
   value.  */
unsigned char *
apdu_get_atr (int slot, size_t *atrlen)
{
  unsigned char *buf;

  if (DBG_READER)
    log_debug ("enter: apdu_get_atr: slot=%d\n", slot);

  if (slot < 0 || slot >= MAX_READER || !reader_table[slot].used )
    {
      if (DBG_READER)
        log_debug ("leave: apdu_get_atr => NULL (bad slot)\n");
      return NULL;
    }
  if (!reader_table[slot].atrlen)
    {
      if (DBG_READER)
        log_debug ("leave: apdu_get_atr => NULL (no ATR)\n");
      return NULL;
    }

  buf = xtrymalloc (reader_table[slot].atrlen);
  if (!buf)
    {
      if (DBG_READER)
        log_debug ("leave: apdu_get_atr => NULL (out of core)\n");
      return NULL;
    }
  memcpy (buf, reader_table[slot].atr, reader_table[slot].atrlen);
  *atrlen = reader_table[slot].atrlen;
  if (DBG_READER)
    log_debug ("leave: apdu_get_atr => atrlen=%zu\n", *atrlen);
  return buf;
}



/* Retrieve the status for SLOT. The function does only wait for the
   card to become available if HANG is set to true. On success the
   bits in STATUS will be set to

     APDU_CARD_USABLE  (bit 0) = card present and usable
     APDU_CARD_PRESENT (bit 1) = card present
     APDU_CARD_ACTIVE  (bit 2) = card active
                       (bit 3) = card access locked [not yet implemented]

   For most applications, testing bit 0 is sufficient.
*/
static int
apdu_get_status_internal (int slot, int hang, unsigned int *status, int on_wire)
{
  int sw;
  unsigned int s = 0;

  if (slot < 0 || slot >= MAX_READER || !reader_table[slot].used )
    return SW_HOST_NO_DRIVER;

  if ((sw = hang? lock_slot (slot) : trylock_slot (slot)))
    return sw;

  if (reader_table[slot].get_status_reader)
    sw = reader_table[slot].get_status_reader (slot, &s, on_wire);

  unlock_slot (slot);

  if (sw)
    {
      if (on_wire)
        reader_table[slot].atrlen = 0;
      s = 0;
    }

  if (status)
    *status = s;
  return sw;
}


/* See above for a description.  */
int
apdu_get_status (int slot, int hang, unsigned int *status)
{
  int sw;

  if (DBG_READER)
    log_debug ("enter: apdu_get_status: slot=%d hang=%d\n", slot, hang);
  sw = apdu_get_status_internal (slot, hang, status, 0);
  if (DBG_READER)
    {
      if (status)
        log_debug ("leave: apdu_get_status => sw=0x%x status=%u\n",
                   sw, *status);
      else
        log_debug ("leave: apdu_get_status => sw=0x%x\n", sw);
    }
  return sw;
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
      /* Two more bytes are needed for status bytes.  */
      result_buffer_size = le < 0? 4096 : (le + 2);
      result_buffer = xtrymalloc (result_buffer_size);
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
          if (lc > 0)
            {
              apdu[apdulen++] = 0;  /* Z byte: Extended length marker.  */
              apdu[apdulen++] = ((lc >> 8) & 0xff);
              apdu[apdulen++] = (lc & 0xff);
              memcpy (apdu+apdulen, data, lc);
              data += lc;
              apdulen += lc;
            }
          if (le != -1)
            {
              if (lc <= 0)
                apdu[apdulen++] = 0;  /* Z byte: Extended length marker.  */
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
    }

  /* Store away the returned data but strip the statusword. */
  resultlen -= 2;
  if (DBG_CARD_IO)
    {
      log_debug (" response: sw=%04X  datalen=%d\n",
                 sw, (unsigned int)resultlen);
      if ( !retbuf && (sw == SW_SUCCESS || (sw & 0xff00) == SW_MORE_DATA))
        log_printhex (result, resultlen, "    dump: ");
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
                log_printhex (result, resultlen, "     dump: ");
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
    log_printhex (*retbuf, *retbuflen, "      dump: ");

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
   that data will be put into *RETBUFLEN.  The caller is responsible
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
   will be put into *RETBUFLEN.  The caller is responsible for
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
 * takes an already formatted APDU in APDUDATA or length APDUDATALEN
 * and returns with an APDU including the status word.  With
 * HANDLE_MORE set to true this function will handle the MORE DATA
 * status and return all APDUs concatenated with one status word at
 * the end.  If EXTENDED_LENGTH is != 0 extended lengths are allowed
 * with a max. result data length of EXTENDED_LENGTH bytes.  The
 * function does not return a regular status word but 0 on success.
 * If the slot is locked, the function returns immediately with an
 * error.
 *
 * Out of historical reasons the function returns 0 on success and
 * outs the status word at the end of the result to be able to get the
 * status word in the case of a not provided RETBUF, R_SW can be used
 * to store the SW.  But note that R_SW qill only be set if the
 * function returns 0. */
int
apdu_send_direct (int slot, size_t extended_length,
                  const unsigned char *apdudata, size_t apdudatalen,
                  int handle_more, unsigned int *r_sw,
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
        log_printhex (result, resultlen, "     dump: ");
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
                log_printhex (result, resultlen, "     dump: ");
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

  if (r_sw)
    *r_sw = sw;

  if (DBG_CARD_IO && retbuf)
    log_printhex (*retbuf, *retbuflen, "      dump: ");


  return 0;
}


const char *
apdu_get_reader_name (int slot)
{
  return reader_table[slot].rdrname;
}

gpg_error_t
apdu_init (void)
{
#ifdef USE_NPTH
  gpg_error_t err;
  int i;

  if (npth_mutex_init (&reader_table_lock, NULL))
    goto leave;

  for (i = 0; i < MAX_READER; i++)
    if (npth_mutex_init (&reader_table[i].lock, NULL))
      goto leave;

  /* All done well.  */
  return 0;

 leave:
  err = gpg_error_from_syserror ();
  log_error ("apdu: error initializing mutex: %s\n", gpg_strerror (err));
  return err;
#endif /*USE_NPTH*/
  return 0;
}
