/* pcsc-wrapper.c - Wrapper for accessing the PC/SC service
 *	Copyright (C) 2003, 2004 Free Software Foundation, Inc.
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

/*
  This wrapper is required to handle problems with the libpscslite
  library.  That library assumes that pthreads are used and fails
  badly if one tries to use it with a procerss using Pth.

  The operation model is pretty simple: It reads requests from stdin
  and returns the answer on stdout.  There is no direct mapping to the
  pcsc interface but to a higher level one which resembles the code
  used in scdaemon (apdu.c) when not using Pth or while running under
  Windows.

  The interface is binary consisting of a command tag and the length
  of the parameter list.  The calling process needs to pass the
  version number of the interface on the command line to make sure
  that both agree on the same interface.  For each port a separate
  instance of this process needs to be started.

*/

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif
#include <stdio.h>
#include <stdlib.h>
#include <stddef.h>
#include <string.h>
#include <errno.h>
#include <stdarg.h>
#include <assert.h>
#include <dlfcn.h>


#define PGM "pcsc-wrapper"

/* Allow for a standalone build. */
#ifdef VERSION
#define MYVERSION_LINE PGM " (GnuPG) " VERSION
#define BUGREPORT_LINE "\nReport bugs to <bug-gnupg@gnu.org>.\n"
#else
#define MYVERSION_LINE PGM
#define BUGREPORT_LINE ""
#endif

#define DEFAULT_PCSC_DRIVER "libpcsclite.so"


static int verbose;

#if defined(__APPLE__) || defined(_WIN32) || defined(__CYGWIN__)
typedef unsinged int pcsc_dword_t;
#else
typedef unsigned long pcsc_dword_t;
#endif


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

struct pcsc_io_request_s {
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


static int driver_is_open;     /* True if the PC/SC driver has been
                                  initialzied and is ready for
                                  operations.  The following variables
                                  are then valid. */
static long pcsc_context;  /* The current PC/CS context. */
static char *current_rdrname;
static long pcsc_card;
static pcsc_dword_t pcsc_protocol;
static unsigned char current_atr[33];
static size_t current_atrlen;

long (* pcsc_establish_context) (pcsc_dword_t scope,
                                 const void *reserved1,
                                 const void *reserved2,
                                 long *r_context);
long (* pcsc_release_context) (long context);
long (* pcsc_list_readers) (long context,
                            const char *groups,
                            char *readers, pcsc_dword_t *readerslen);
long (* pcsc_get_status_change) (long context,
                                 pcsc_dword_t timeout,
                                 pcsc_readerstate_t readerstates,
                                 pcsc_dword_t nreaderstates);
long (* pcsc_connect) (long context,
                       const char *reader,
                       pcsc_dword_t share_mode,
                       pcsc_dword_t preferred_protocols,
                       long *r_card,
                       pcsc_dword_t *r_active_protocol);
long (* pcsc_reconnect) (long card,
                         pcsc_dword_t share_mode,
                         pcsc_dword_t preferred_protocols,
                         pcsc_dword_t initialization,
                         pcsc_dword_t *r_active_protocol);
long (* pcsc_disconnect) (long card,
                          pcsc_dword_t disposition);
long (* pcsc_status) (long card,
                      char *reader, pcsc_dword_t *readerlen,
                      pcsc_dword_t *r_state,
                      pcsc_dword_t *r_protocol,
                      unsigned char *atr, pcsc_dword_t *atrlen);
long (* pcsc_begin_transaction) (long card);
long (* pcsc_end_transaction) (long card,
                               pcsc_dword_t disposition);
long (* pcsc_transmit) (long card,
                        const pcsc_io_request_t send_pci,
                        const unsigned char *send_buffer,
                        pcsc_dword_t send_len,
                        pcsc_io_request_t recv_pci,
                        unsigned char *recv_buffer,
                        pcsc_dword_t *recv_len);
long (* pcsc_set_timeout) (long context,
                           pcsc_dword_t timeout);
long (* pcsc_control) (long card,
                       pcsc_dword_t control_code,
                       const void *send_buffer,
                       pcsc_dword_t send_len,
                       void *recv_buffer,
                       pcsc_dword_t recv_len,
                       pcsc_dword_t *bytes_returned);



static void
bad_request (const char *type)
{
  fprintf (stderr, PGM ": bad `%s' request\n", type);
  exit (1);
}

static void
request_failed (int err)
{
  if (!err)
    err = -1;

  putchar (0x81); /* Simple error/success response. */

  putchar (0);
  putchar (0);
  putchar (0);
  putchar (4);

  putchar ((err >> 24) & 0xff);
  putchar ((err >> 16) & 0xff);
  putchar ((err >>  8) & 0xff);
  putchar ((err      ) & 0xff);

  fflush (stdout);
}


static void
request_succeeded (const void *buffer, size_t buflen)
{
  size_t len;

  putchar (0x81); /* Simple error/success response. */

  len = 4 + buflen;
  putchar ((len >> 24) & 0xff);
  putchar ((len >> 16) & 0xff);
  putchar ((len >>  8) & 0xff);
  putchar ((len      ) & 0xff);

  /* Error code. */
  putchar (0);
  putchar (0);
  putchar (0);
  putchar (0);

  /* Optional reponse string. */
  if (buffer)
    fwrite (buffer, buflen, 1, stdout);

  fflush (stdout);
}



static unsigned long
read_32 (FILE *fp)
{
  int c1, c2, c3, c4;

  c1 = getc (fp);
  c2 = getc (fp);
  c3 = getc (fp);
  c4 = getc (fp);
  if (c1 == EOF || c2 == EOF || c3 == EOF || c4 == EOF)
    {
      fprintf (stderr, PGM ": premature EOF while parsing request\n");
      exit (1);
    }
  return (c1 << 24) | (c2 << 16) | (c3 << 8) | c4;
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

static void
load_pcsc_driver (const char *libname)
{
  void *handle;

  handle = dlopen (libname, RTLD_LAZY);
  if (!handle)
    {
      fprintf (stderr, PGM ": failed to open driver `%s': %s",
               libname, dlerror ());
      exit (1);
    }

  pcsc_establish_context = dlsym (handle, "SCardEstablishContext");
  pcsc_release_context   = dlsym (handle, "SCardReleaseContext");
  pcsc_list_readers      = dlsym (handle, "SCardListReaders");
  pcsc_get_status_change = dlsym (handle, "SCardGetStatusChange");
  pcsc_connect           = dlsym (handle, "SCardConnect");
  pcsc_reconnect         = dlsym (handle, "SCardReconnect");
  pcsc_disconnect        = dlsym (handle, "SCardDisconnect");
  pcsc_status            = dlsym (handle, "SCardStatus");
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
      fprintf (stderr,
               "apdu_open_reader: invalid PC/SC driver "
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
      exit (1);
    }
}




/* Handle a open request.  The argument is expected to be a string
   with the port identification.  ARGBUF is always guaranteed to be
   terminted by a 0 which is not counted in ARGLEN.  We may modifiy
   ARGBUF. */
static void
handle_open (unsigned char *argbuf, size_t arglen)
{
  long err;
  const char * portstr;
  char *list = NULL;
  pcsc_dword_t nreader, atrlen;
  char *p;
  pcsc_dword_t card_state, card_protocol;
  unsigned char atr[33];

  /* Make sure there is only the port string */
  if (arglen != strlen ((char*)argbuf))
    bad_request ("OPEN");
  portstr = (char*)argbuf;

  if (driver_is_open)
    {
      fprintf (stderr, PGM ": PC/SC has already been opened\n");
      request_failed (-1);
      return;
    }

  err = pcsc_establish_context (PCSC_SCOPE_SYSTEM, NULL, NULL, &pcsc_context);
  if (err)
    {
      fprintf (stderr, PGM": pcsc_establish_context failed: %s (0x%lx)\n",
               pcsc_error_string (err), err);
      request_failed (err);
      return;
    }

  err = pcsc_list_readers (pcsc_context, NULL, NULL, &nreader);
  if (!err)
    {
      list = malloc (nreader+1); /* Better add 1 for safety reasons. */
      if (!list)
        {
          fprintf (stderr, PGM": error allocating memory for reader list\n");
          exit (1);
        }
      err = pcsc_list_readers (pcsc_context, NULL, list, &nreader);
    }
  if (err)
    {
      fprintf (stderr, PGM": pcsc_list_readers failed: %s (0x%lx)\n",
               pcsc_error_string (err), err);
      pcsc_release_context (pcsc_context);
      free (list);
      request_failed (err);
      return;
    }

  p = list;
  while (nreader)
    {
      if (!*p && !p[1])
        break;
      fprintf (stderr, PGM": detected reader `%s'\n", p);
      if (nreader < (strlen (p)+1))
        {
          fprintf (stderr, PGM": invalid response from pcsc_list_readers\n");
          break;
        }
      nreader -= strlen (p)+1;
      p += strlen (p) + 1;
    }

  current_rdrname = malloc (strlen (portstr && *portstr? portstr:list)+1);
  if (!current_rdrname)
    {
      fprintf (stderr, PGM": error allocating memory for reader name\n");
      exit (1);
    }
  strcpy (current_rdrname, portstr && *portstr? portstr:list);
  free (list);

  err = pcsc_connect (pcsc_context,
                      current_rdrname,
                      PCSC_SHARE_EXCLUSIVE,
                      PCSC_PROTOCOL_T0|PCSC_PROTOCOL_T1,
                      &pcsc_card,
                      &pcsc_protocol);
  if (err == 0x8010000c) /* No smartcard.  */
    {
      pcsc_card = 0;
    }
  else if (err)
    {
      fprintf (stderr, PGM": pcsc_connect failed: %s (0x%lx)\n",
               pcsc_error_string (err), err);
      pcsc_release_context (pcsc_context);
      free (current_rdrname);
      current_rdrname = NULL;
      pcsc_card = 0;
      pcsc_protocol = 0;
      request_failed (err);
      return;
    }

  current_atrlen = 0;
  if (!err)
    {
      char reader[250];
      pcsc_dword_t readerlen;

      atrlen = 33;
      readerlen = sizeof reader -1;
      err = pcsc_status (pcsc_card,
                         reader, &readerlen,
                         &card_state, &card_protocol,
                         atr, &atrlen);
      if (err)
        fprintf (stderr, PGM": pcsc_status failed: %s (0x%lx)\n",
                 pcsc_error_string (err), err);
      else
        {
          if (atrlen >= sizeof atr || atrlen >= sizeof current_atr)
            {
              fprintf (stderr, PGM": ATR returned by pcsc_status"
                       " is too large\n");
              exit (4);
            }
          memcpy (current_atr, atr, atrlen);
          current_atrlen = atrlen;
        }
    }

  driver_is_open = 1;
  request_succeeded (current_atr, current_atrlen);
}



/* Handle a close request.  We expect no arguments.  We may modifiy
   ARGBUF. */
static void
handle_close (unsigned char *argbuf, size_t arglen)
{
  (void)argbuf;
  (void)arglen;

  if (!driver_is_open)
    {
      fprintf (stderr, PGM ": PC/SC has not yet been opened\n");
      request_failed (-1);
      return;
    }

  free (current_rdrname);
  current_rdrname = NULL;
  pcsc_release_context (pcsc_context);
  pcsc_card = 0;
  pcsc_protocol = 0;

  request_succeeded (NULL, 0);
}



/* Handle a status request.  We expect no arguments.  We may modifiy
   ARGBUF. */
static void
handle_status (unsigned char *argbuf, size_t arglen)
{
  long err;
  struct pcsc_readerstate_s rdrstates[1];
  int status;
  unsigned char buf[20];

  (void)argbuf;
  (void)arglen;

  if (!driver_is_open)
    {
      fprintf (stderr, PGM ": PC/SC has not yet been opened\n");
      request_failed (-1);
      return;
    }

  memset (rdrstates, 0, sizeof *rdrstates);
  rdrstates[0].reader = current_rdrname;
  rdrstates[0].current_state = PCSC_STATE_UNAWARE;
  err = pcsc_get_status_change (pcsc_context,
                                0,
                                rdrstates, 1);
  if (err == 0x8010000a) /* Timeout.  */
    err = 0;
  if (err)
    {
      fprintf (stderr, PGM": pcsc_get_status_change failed: %s (0x%lx)\n",
               pcsc_error_string (err), err);
      request_failed (err);
      return;
    }

  status = 0;
  if ( !(rdrstates[0].event_state & PCSC_STATE_UNKNOWN) )
    {
      if ( (rdrstates[0].event_state & PCSC_STATE_PRESENT) )
	{
	  status |= 2;
	  if ( !(rdrstates[0].event_state & PCSC_STATE_MUTE) )
	    status |= 4;
	}
      /* We indicate a useful card if it is not in use by another
         application.  This is because we only use exclusive access
         mode.  */
      if ( (status & 6) == 6
           && !(rdrstates[0].event_state & PCSC_STATE_INUSE) )
        status |= 1;
    }

  /* First word is identical to the one used by apdu.c. */
  buf[0] = 0;
  buf[1] = 0;
  buf[2] = 0;
  buf[3] = status;
  /* The second word is the native PCSC state.  */
  buf[4] = (rdrstates[0].event_state >> 24);
  buf[5] = (rdrstates[0].event_state >> 16);
  buf[6] = (rdrstates[0].event_state >>  8);
  buf[7] = (rdrstates[0].event_state >>  0);
  /* The third word is the protocol. */
  buf[8]  = (pcsc_protocol >> 24);
  buf[9]  = (pcsc_protocol >> 16);
  buf[10] = (pcsc_protocol >> 8);
  buf[11] = (pcsc_protocol);

  request_succeeded (buf, 8);
}


/* Handle a reset request.  We expect no arguments.  We may modifiy
   ARGBUF. */
static void
handle_reset (unsigned char *argbuf, size_t arglen)
{
  long err;
  char reader[250];
  pcsc_dword_t nreader, atrlen;
  pcsc_dword_t card_state, card_protocol;

  (void)argbuf;
  (void)arglen;

  if (!driver_is_open)
    {
      fprintf (stderr, PGM ": PC/SC has not yet been opened\n");
      request_failed (-1);
      return;
    }

  if (pcsc_card)
    {
      err = pcsc_disconnect (pcsc_card, PCSC_LEAVE_CARD);
      if (err == 0x80100003)  /* Invalid handle.  (already disconnected) */
        err = 0;
      if (err)
        {
          fprintf (stderr, PGM": pcsc_disconnect failed: %s (0x%lx)\n",
                     pcsc_error_string (err), err);
          request_failed (err);
          return;
        }
      pcsc_card = 0;
    }

  err = pcsc_connect (pcsc_context,
                      current_rdrname,
                      PCSC_SHARE_EXCLUSIVE,
                      PCSC_PROTOCOL_T0|PCSC_PROTOCOL_T1,
                      &pcsc_card,
                      &pcsc_protocol);
  if (err)
    {
      fprintf (stderr, PGM": pcsc_connect failed: %s (0x%lx)\n",
               pcsc_error_string (err), err);
      pcsc_card = 0;
      request_failed (err);
      return;
    }


  atrlen = 33;
  nreader = sizeof reader - 1;
  err = pcsc_status (pcsc_card,
                     reader, &nreader,
                     &card_state, &card_protocol,
                     current_atr, &atrlen);
  if (err)
    {
      fprintf (stderr, PGM": pcsc_status failed: %s (0x%lx)\n",
               pcsc_error_string (err), err);
      current_atrlen = 0;
      request_failed (err);
      return;
    }

  request_succeeded (current_atr, current_atrlen);
}



/* Handle a transmit request.  The argument is expected to be a buffer
   with the APDU.  We may modifiy ARGBUF. */
static void
handle_transmit (unsigned char *argbuf, size_t arglen)
{
  long err;
  struct pcsc_io_request_s send_pci;
  pcsc_dword_t recv_len;
  unsigned char buffer[1024];

  /* The apdu should at least be one byte. */
  if (!arglen)
    bad_request ("TRANSMIT");

  if (!driver_is_open)
    {
      fprintf (stderr, PGM ": PC/SC has not yet been opened\n");
      request_failed (-1);
      return;
    }
  if ((pcsc_protocol & PCSC_PROTOCOL_T1))
    send_pci.protocol = PCSC_PROTOCOL_T1;
  else
    send_pci.protocol = PCSC_PROTOCOL_T0;
  send_pci.pci_len = sizeof send_pci;
  recv_len = sizeof (buffer);
  err = pcsc_transmit (pcsc_card, &send_pci, argbuf, arglen,
                       NULL, buffer, &recv_len);
  if (err)
    {
      if (verbose)
        fprintf (stderr, PGM": pcsc_transmit failed: %s (0x%lx)\n",
                 pcsc_error_string (err), err);
      request_failed (err);
      return;
    }
  request_succeeded (buffer, recv_len);
}


/* Handle a control request.  The argument is expected to be a buffer
   which contains CONTROL_CODE (4-byte) and INPUT_BYTES.
 */
static void
handle_control (unsigned char *argbuf, size_t arglen)
{
  long err;
  pcsc_dword_t ioctl_code;
  pcsc_dword_t recv_len = 1024;
  unsigned char buffer[1024];

  if (arglen < 4)
    bad_request ("CONTROL");

  ioctl_code = (argbuf[0] << 24) | (argbuf[1] << 16) | (argbuf[2] << 8) | argbuf[3];
  argbuf += 4;
  arglen -= 4;

  recv_len = sizeof (buffer);
  err = pcsc_control (pcsc_card, ioctl_code, argbuf, arglen,
                      buffer, recv_len, &recv_len);
  if (err)
    {
      if (verbose)
        fprintf (stderr, PGM": pcsc_control failed: %s (0x%lx)\n",
                 pcsc_error_string (err), err);
      request_failed (err);
      return;
    }
  request_succeeded (buffer, recv_len);
}


static void
print_version (int with_help)
{
  fputs (MYVERSION_LINE "\n"
         "Copyright (C) 2004 Free Software Foundation, Inc.\n"
         "This program comes with ABSOLUTELY NO WARRANTY.\n"
         "This is free software, and you are welcome to redistribute it\n"
         "under certain conditions. See the file COPYING for details.\n",
         stdout);

  if (with_help)
    fputs ("\n"
          "Usage: " PGM " [OPTIONS] API-NUMBER [LIBNAME]\n"
          "Helper to connect scdaemon to the PC/SC library\n"
          "\n"
          "  --verbose   enable extra informational output\n"
          "  --version   print version of the program and exit\n"
          "  --help      display this help and exit\n"
          BUGREPORT_LINE, stdout );

  exit (0);
}


int
main (int argc, char **argv)
{
  int last_argc = -1;
  int api_number = 0;
  int c;

  if (argc)
    {
      argc--; argv++;
    }
  while (argc && last_argc != argc )
    {
      last_argc = argc;
      if (!strcmp (*argv, "--"))
        {
          argc--; argv++;
          break;
        }
      else if (!strcmp (*argv, "--version"))
        print_version (0);
      else if (!strcmp (*argv, "--help"))
        print_version (1);
      else if (!strcmp (*argv, "--verbose"))
        {
          verbose = 1;
          argc--; argv++;
        }
    }
  if (argc != 1 && argc != 2)
    {
      fprintf (stderr, "usage: " PGM " API-NUMBER [LIBNAME]\n");
      exit (1);
    }

  api_number = atoi (*argv);
  argv++; argc--;
  if (api_number != 1)
    {
      fprintf (stderr, PGM ": api-number %d is not valid\n", api_number);
      exit (1);
    }

  load_pcsc_driver (argc? *argv : DEFAULT_PCSC_DRIVER);

  while ((c = getc (stdin)) != EOF)
    {
      size_t arglen;
      unsigned char argbuffer[2048];

      arglen = read_32 (stdin);
      if (arglen >= sizeof argbuffer - 1)
        {
          fprintf (stderr, PGM ": request too long\n");
          exit (1);
        }
      if (arglen && fread (argbuffer, arglen, 1, stdin) != 1)
        {
          fprintf (stderr, PGM ": error reading request: %s\n",
                   strerror (errno));
          exit (1);
        }
      argbuffer[arglen] = 0;
      switch (c)
        {
        case 1:
          handle_open (argbuffer, arglen);
          break;

        case 2:
          handle_close (argbuffer, arglen);
          exit (0);
          break;

        case 3:
          handle_transmit (argbuffer, arglen);
          break;

        case 4:
          handle_status (argbuffer, arglen);
          break;

        case 5:
          handle_reset (argbuffer, arglen);
          break;

        case 6:
          handle_control (argbuffer, arglen);
          break;

        default:
          fprintf (stderr, PGM ": invalid request 0x%02X\n", c);
          exit (1);
        }
    }
  return 0;
}



/*
Local Variables:
compile-command: "gcc -Wall -g -o pcsc-wrapper pcsc-wrapper.c -ldl"
End:
*/
