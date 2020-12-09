/* ccid-driver.c - USB ChipCardInterfaceDevices driver
 * Copyright (C) 2003, 2004, 2005, 2006, 2007
 *               2008, 2009, 2013  Free Software Foundation, Inc.
 * Written by Werner Koch.
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
 *
 * ALTERNATIVELY, this file may be distributed under the terms of the
 * following license, in which case the provisions of this license are
 * required INSTEAD OF the GNU General Public License. If you wish to
 * allow use of your version of this file only under the terms of the
 * GNU General Public License, and not to allow others to use your
 * version of this file under the terms of the following license,
 * indicate your decision by deleting this paragraph and the license
 * below.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, and the entire permission notice in its entirety,
 *    including the disclaimer of warranties.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. The name of the author may not be used to endorse or promote
 *    products derived from this software without specific prior
 *    written permission.
 *
 * THIS SOFTWARE IS PROVIDED "AS IS" AND ANY EXPRESS OR IMPLIED
 * WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT,
 * INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED
 * OF THE POSSIBILITY OF SUCH DAMAGE.
 */


/* CCID (ChipCardInterfaceDevices) is a specification for accessing
   smartcard via a reader connected to the USB.

   This is a limited driver allowing to use some CCID drivers directly
   without any other specila drivers. This is a fallback driver to be
   used when nothing else works or the system should be kept minimal
   for security reasons.  It makes use of the libusb library to gain
   portable access to USB.

   This driver has been tested with the SCM SCR335 and SPR532
   smartcard readers and requires that a reader implements APDU or
   TPDU level exchange and does fully automatic initialization.
*/

#ifdef HAVE_CONFIG_H
# include <config.h>
#endif

#if defined(HAVE_LIBUSB) || defined(TEST)

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <time.h>
#include <unistd.h>
#ifdef HAVE_NPTH
# include <npth.h>
#endif /*HAVE_NPTH*/

#include <libusb.h>

#include "scdaemon.h"
#include "iso7816.h"
#define CCID_DRIVER_INCLUDE_USB_IDS 1
#include "ccid-driver.h"

#define DRVNAME "ccid-driver: "

/* Max length of buffer with out CCID message header of 10-byte
   Sending: 547 for RSA-4096 key import
        APDU size = 540 (24+4+256+256)
        command + lc + le = 4 + 3 + 0
   Sending: write data object of cardholder certificate
        APDU size = 2048
        command + lc + le = 4 + 3 + 0
   Receiving: 2048 for cardholder certificate
*/
#define CCID_MAX_BUF (2048+7+10)

/* CCID command timeout.  */
#define CCID_CMD_TIMEOUT (5*1000)

/* Depending on how this source is used we either define our error
   output to go to stderr or to the GnuPG based logging functions.  We
   use the latter when GNUPG_MAJOR_VERSION or GNUPG_SCD_MAIN_HEADER
   are defined.  */
#if defined(GNUPG_MAJOR_VERSION) || defined(GNUPG_SCD_MAIN_HEADER)

#if defined(GNUPG_SCD_MAIN_HEADER)
#  include GNUPG_SCD_MAIN_HEADER
#elif GNUPG_MAJOR_VERSION == 1 /* GnuPG Version is < 1.9. */
#  include "options.h"
#  include "util.h"
#  include "memory.h"
#  include "cardglue.h"
# else /* This is the modularized GnuPG 1.9 or later. */
#  include "scdaemon.h"
#endif


# define DEBUGOUT(t)         do { if (debug_level) \
                                  log_debug (DRVNAME t); } while (0)
# define DEBUGOUT_1(t,a)     do { if (debug_level) \
                                  log_debug (DRVNAME t,(a)); } while (0)
# define DEBUGOUT_2(t,a,b)   do { if (debug_level) \
                                  log_debug (DRVNAME t,(a),(b)); } while (0)
# define DEBUGOUT_3(t,a,b,c) do { if (debug_level) \
                                  log_debug (DRVNAME t,(a),(b),(c));} while (0)
# define DEBUGOUT_4(t,a,b,c,d) do { if (debug_level) \
                              log_debug (DRVNAME t,(a),(b),(c),(d));} while (0)
# define DEBUGOUT_CONT(t)    do { if (debug_level) \
                                  log_printf (t); } while (0)
# define DEBUGOUT_CONT_1(t,a)  do { if (debug_level) \
                                  log_printf (t,(a)); } while (0)
# define DEBUGOUT_CONT_2(t,a,b)   do { if (debug_level) \
                                  log_printf (t,(a),(b)); } while (0)
# define DEBUGOUT_CONT_3(t,a,b,c) do { if (debug_level) \
                                  log_printf (t,(a),(b),(c)); } while (0)
# define DEBUGOUT_LF()       do { if (debug_level) \
                                  log_printf ("\n"); } while (0)

#else /* Other usage of this source - don't use gnupg specifics. */

# define DEBUGOUT(t)          do { if (debug_level) \
                     fprintf (stderr, DRVNAME t); } while (0)
# define DEBUGOUT_1(t,a)      do { if (debug_level) \
                     fprintf (stderr, DRVNAME t, (a)); } while (0)
# define DEBUGOUT_2(t,a,b)    do { if (debug_level) \
                     fprintf (stderr, DRVNAME t, (a), (b)); } while (0)
# define DEBUGOUT_3(t,a,b,c)  do { if (debug_level) \
                     fprintf (stderr, DRVNAME t, (a), (b), (c)); } while (0)
# define DEBUGOUT_4(t,a,b,c,d)  do { if (debug_level) \
                     fprintf (stderr, DRVNAME t, (a), (b), (c), (d));} while(0)
# define DEBUGOUT_CONT(t)     do { if (debug_level) \
                     fprintf (stderr, t); } while (0)
# define DEBUGOUT_CONT_1(t,a) do { if (debug_level) \
                     fprintf (stderr, t, (a)); } while (0)
# define DEBUGOUT_CONT_2(t,a,b) do { if (debug_level) \
                     fprintf (stderr, t, (a), (b)); } while (0)
# define DEBUGOUT_CONT_3(t,a,b,c) do { if (debug_level) \
                     fprintf (stderr, t, (a), (b), (c)); } while (0)
# define DEBUGOUT_LF()        do { if (debug_level) \
                     putc ('\n', stderr); } while (0)

#endif /* This source not used by scdaemon. */


#ifndef EAGAIN
#define EAGAIN  EWOULDBLOCK
#endif



enum {
  RDR_to_PC_NotifySlotChange= 0x50,
  RDR_to_PC_HardwareError   = 0x51,

  PC_to_RDR_SetParameters   = 0x61,
  PC_to_RDR_IccPowerOn      = 0x62,
  PC_to_RDR_IccPowerOff     = 0x63,
  PC_to_RDR_GetSlotStatus   = 0x65,
  PC_to_RDR_Secure          = 0x69,
  PC_to_RDR_T0APDU          = 0x6a,
  PC_to_RDR_Escape          = 0x6b,
  PC_to_RDR_GetParameters   = 0x6c,
  PC_to_RDR_ResetParameters = 0x6d,
  PC_to_RDR_IccClock        = 0x6e,
  PC_to_RDR_XfrBlock        = 0x6f,
  PC_to_RDR_Mechanical      = 0x71,
  PC_to_RDR_Abort           = 0x72,
  PC_to_RDR_SetDataRate     = 0x73,

  RDR_to_PC_DataBlock       = 0x80,
  RDR_to_PC_SlotStatus      = 0x81,
  RDR_to_PC_Parameters      = 0x82,
  RDR_to_PC_Escape          = 0x83,
  RDR_to_PC_DataRate        = 0x84
};


/* Two macro to detect whether a CCID command has failed and to get
   the error code.  These macros assume that we can access the
   mandatory first 10 bytes of a CCID message in BUF. */
#define CCID_COMMAND_FAILED(buf) ((buf)[7] & 0x40)
#define CCID_ERROR_CODE(buf)     (((unsigned char *)(buf))[8])


/* Store information on the driver's state.  A pointer to such a
   structure is used as handle for most functions. */
struct ccid_driver_s
{
  libusb_device_handle *idev;
  unsigned int bai;
  unsigned short id_vendor;
  unsigned short id_product;
  int ifc_no;
  int ep_bulk_out;
  int ep_bulk_in;
  int ep_intr;
  int seqno;
  unsigned char t1_ns;
  unsigned char t1_nr;
  unsigned char nonnull_nad;
  int max_ifsd;
  int max_ccid_msglen;
  int ifsc;
  unsigned char apdu_level:2;     /* Reader supports short APDU level
                                     exchange.  With a value of 2 short
                                     and extended level is supported.*/
  unsigned int auto_voltage:1;
  unsigned int auto_param:1;
  unsigned int auto_pps:1;
  unsigned int auto_ifsd:1;
  unsigned int has_pinpad:2;
  unsigned int enodev_seen:1;
  int powered_off;

  time_t last_progress; /* Last time we sent progress line.  */

  /* The progress callback and its first arg as supplied to
     ccid_set_progress_cb.  */
  void (*progress_cb)(void *, const char *, int, int, int);
  void *progress_cb_arg;

  void (*prompt_cb)(void *, int);
  void *prompt_cb_arg;

  unsigned char intr_buf[64];
  struct libusb_transfer *transfer;
};


static int initialized_usb; /* Tracks whether USB has been initialized. */
static int debug_level;     /* Flag to control the debug output.
                               0 = No debugging
                               1 = USB I/O info
                               2 = Level 1 + T=1 protocol tracing
                               3 = Level 2 + USB/I/O tracing of SlotStatus.
                              */
static int ccid_usb_thread_is_alive;


static unsigned int compute_edc (const unsigned char *data, size_t datalen,
                                 int use_crc);
static int bulk_out (ccid_driver_t handle, unsigned char *msg, size_t msglen,
                     int no_debug);
static int bulk_in (ccid_driver_t handle, unsigned char *buffer, size_t length,
                    size_t *nread, int expected_type, int seqno, int timeout,
                    int no_debug);
static int abort_cmd (ccid_driver_t handle, int seqno);
static int send_escape_cmd (ccid_driver_t handle, const unsigned char *data,
                            size_t datalen, unsigned char *result,
                            size_t resultmax, size_t *resultlen);


static int
map_libusb_error (int usberr)
{
  switch (usberr)
    {
    case 0:                     return 0;
    case LIBUSB_ERROR_IO:       return CCID_DRIVER_ERR_USB_IO;
    case LIBUSB_ERROR_ACCESS:   return CCID_DRIVER_ERR_USB_ACCESS;
    case LIBUSB_ERROR_NO_DEVICE:return CCID_DRIVER_ERR_USB_NO_DEVICE;
    case LIBUSB_ERROR_BUSY:     return CCID_DRIVER_ERR_USB_BUSY;
    case LIBUSB_ERROR_TIMEOUT:  return CCID_DRIVER_ERR_USB_TIMEOUT;
    case LIBUSB_ERROR_OVERFLOW: return CCID_DRIVER_ERR_USB_OVERFLOW;
    }
  return CCID_DRIVER_ERR_USB_OTHER;
}


/* Convert a little endian stored 4 byte value into an unsigned
   integer. */
static unsigned int
convert_le_u32 (const unsigned char *buf)
{
  return buf[0] | (buf[1] << 8) | (buf[2] << 16) | ((unsigned int)buf[3] << 24);
}


/* Convert a little endian stored 2 byte value into an unsigned
   integer. */
static unsigned int
convert_le_u16 (const unsigned char *buf)
{
  return buf[0] | (buf[1] << 8);
}

static void
set_msg_len (unsigned char *msg, unsigned int length)
{
  msg[1] = length;
  msg[2] = length >> 8;
  msg[3] = length >> 16;
  msg[4] = length >> 24;
}


static void
print_progress (ccid_driver_t handle)
{
  time_t ct = time (NULL);

  /* We don't want to print progress lines too often. */
  if (ct == handle->last_progress)
    return;

  if (handle->progress_cb)
    handle->progress_cb (handle->progress_cb_arg, "card_busy", 'w', 0, 0);

  handle->last_progress = ct;
}



/* Pint an error message for a failed CCID command including a textual
   error code.  MSG shall be the CCID message at a minimum of 10 bytes. */
static void
print_command_failed (const unsigned char *msg)
{
  const char *t;
  char buffer[100];
  int ec;

  if (!debug_level)
    return;

  ec = CCID_ERROR_CODE (msg);
  switch (ec)
    {
    case 0x00: t = "Command not supported"; break;

    case 0xE0: t = "Slot busy"; break;
    case 0xEF: t = "PIN cancelled"; break;
    case 0xF0: t = "PIN timeout"; break;

    case 0xF2: t = "Automatic sequence ongoing"; break;
    case 0xF3: t = "Deactivated Protocol"; break;
    case 0xF4: t = "Procedure byte conflict"; break;
    case 0xF5: t = "ICC class not supported"; break;
    case 0xF6: t = "ICC protocol not supported"; break;
    case 0xF7: t = "Bad checksum in ATR"; break;
    case 0xF8: t = "Bad TS in ATR"; break;

    case 0xFB: t = "An all inclusive hardware error occurred"; break;
    case 0xFC: t = "Overrun error while talking to the ICC"; break;
    case 0xFD: t = "Parity error while talking to the ICC"; break;
    case 0xFE: t = "CCID timed out while talking to the ICC"; break;
    case 0xFF: t = "Host aborted the current activity"; break;

    default:
      if (ec > 0 && ec < 128)
        sprintf (buffer, "Parameter error at offset %d", ec);
      else
        sprintf (buffer, "Error code %02X", ec);
      t = buffer;
      break;
    }
  DEBUGOUT_1 ("CCID command failed: %s\n", t);
}


static void
print_pr_data (const unsigned char *data, size_t datalen, size_t off)
{
  int any = 0;

  for (; off < datalen; off++)
    {
      if (!any || !(off % 16))
        {
          if (any)
            DEBUGOUT_LF ();
          DEBUGOUT_1 ("  [%04lu] ", (unsigned long) off);
        }
      DEBUGOUT_CONT_1 (" %02X", data[off]);
      any = 1;
    }
  if (any && (off % 16))
    DEBUGOUT_LF ();
}


static void
print_p2r_header (const char *name, const unsigned char *msg, size_t msglen)
{
  DEBUGOUT_1 ("%s:\n", name);
  if (msglen < 7)
    return;
  DEBUGOUT_1 ("  dwLength ..........: %u\n", convert_le_u32 (msg+1));
  DEBUGOUT_1 ("  bSlot .............: %u\n", msg[5]);
  DEBUGOUT_1 ("  bSeq ..............: %u\n", msg[6]);
}


static void
print_p2r_iccpoweron (const unsigned char *msg, size_t msglen)
{
  print_p2r_header ("PC_to_RDR_IccPowerOn", msg, msglen);
  if (msglen < 10)
    return;
  DEBUGOUT_2 ("  bPowerSelect ......: 0x%02x (%s)\n", msg[7],
              msg[7] == 0? "auto":
              msg[7] == 1? "5.0 V":
              msg[7] == 2? "3.0 V":
              msg[7] == 3? "1.8 V":"");
  print_pr_data (msg, msglen, 8);
}


static void
print_p2r_iccpoweroff (const unsigned char *msg, size_t msglen)
{
  print_p2r_header ("PC_to_RDR_IccPowerOff", msg, msglen);
  print_pr_data (msg, msglen, 7);
}


static void
print_p2r_getslotstatus (const unsigned char *msg, size_t msglen)
{
  print_p2r_header ("PC_to_RDR_GetSlotStatus", msg, msglen);
  print_pr_data (msg, msglen, 7);
}


static void
print_p2r_xfrblock (const unsigned char *msg, size_t msglen)
{
  unsigned int val;

  print_p2r_header ("PC_to_RDR_XfrBlock", msg, msglen);
  if (msglen < 10)
    return;
  DEBUGOUT_1 ("  bBWI ..............: 0x%02x\n", msg[7]);
  val = convert_le_u16 (msg+8);
  DEBUGOUT_2 ("  wLevelParameter ...: 0x%04x%s\n", val,
              val == 1? " (continued)":
              val == 2? " (continues+ends)":
              val == 3? " (continues+continued)":
              val == 16? " (DataBlock-expected)":"");
  print_pr_data (msg, msglen, 10);
}


static void
print_p2r_getparameters (const unsigned char *msg, size_t msglen)
{
  print_p2r_header ("PC_to_RDR_GetParameters", msg, msglen);
  print_pr_data (msg, msglen, 7);
}


static void
print_p2r_resetparameters (const unsigned char *msg, size_t msglen)
{
  print_p2r_header ("PC_to_RDR_ResetParameters", msg, msglen);
  print_pr_data (msg, msglen, 7);
}


static void
print_p2r_setparameters (const unsigned char *msg, size_t msglen)
{
  print_p2r_header ("PC_to_RDR_SetParameters", msg, msglen);
  if (msglen < 10)
    return;
  DEBUGOUT_1 ("  bProtocolNum ......: 0x%02x\n", msg[7]);
  print_pr_data (msg, msglen, 8);
}


static void
print_p2r_escape (const unsigned char *msg, size_t msglen)
{
  print_p2r_header ("PC_to_RDR_Escape", msg, msglen);
  print_pr_data (msg, msglen, 7);
}


static void
print_p2r_iccclock (const unsigned char *msg, size_t msglen)
{
  print_p2r_header ("PC_to_RDR_IccClock", msg, msglen);
  if (msglen < 10)
    return;
  DEBUGOUT_1 ("  bClockCommand .....: 0x%02x\n", msg[7]);
  print_pr_data (msg, msglen, 8);
}


static void
print_p2r_to0apdu (const unsigned char *msg, size_t msglen)
{
  print_p2r_header ("PC_to_RDR_T0APDU", msg, msglen);
  if (msglen < 10)
    return;
  DEBUGOUT_1 ("  bmChanges .........: 0x%02x\n", msg[7]);
  DEBUGOUT_1 ("  bClassGetResponse .: 0x%02x\n", msg[8]);
  DEBUGOUT_1 ("  bClassEnvelope ....: 0x%02x\n", msg[9]);
  print_pr_data (msg, msglen, 10);
}


static void
print_p2r_secure (const unsigned char *msg, size_t msglen)
{
  unsigned int val;

  print_p2r_header ("PC_to_RDR_Secure", msg, msglen);
  if (msglen < 10)
    return;
  DEBUGOUT_1 ("  bBMI ..............: 0x%02x\n", msg[7]);
  val = convert_le_u16 (msg+8);
  DEBUGOUT_2 ("  wLevelParameter ...: 0x%04x%s\n", val,
              val == 1? " (continued)":
              val == 2? " (continues+ends)":
              val == 3? " (continues+continued)":
              val == 16? " (DataBlock-expected)":"");
  print_pr_data (msg, msglen, 10);
}


static void
print_p2r_mechanical (const unsigned char *msg, size_t msglen)
{
  print_p2r_header ("PC_to_RDR_Mechanical", msg, msglen);
  if (msglen < 10)
    return;
  DEBUGOUT_1 ("  bFunction .........: 0x%02x\n", msg[7]);
  print_pr_data (msg, msglen, 8);
}


static void
print_p2r_abort (const unsigned char *msg, size_t msglen)
{
  print_p2r_header ("PC_to_RDR_Abort", msg, msglen);
  print_pr_data (msg, msglen, 7);
}


static void
print_p2r_setdatarate (const unsigned char *msg, size_t msglen)
{
  print_p2r_header ("PC_to_RDR_SetDataRate", msg, msglen);
  if (msglen < 10)
    return;
  print_pr_data (msg, msglen, 7);
}


static void
print_p2r_unknown (const unsigned char *msg, size_t msglen)
{
  print_p2r_header ("Unknown PC_to_RDR command", msg, msglen);
  if (msglen < 10)
    return;
  print_pr_data (msg, msglen, 0);
}


static void
print_r2p_header (const char *name, const unsigned char *msg, size_t msglen)
{
  DEBUGOUT_1 ("%s:\n", name);
  if (msglen < 9)
    return;
  DEBUGOUT_1 ("  dwLength ..........: %u\n", convert_le_u32 (msg+1));
  DEBUGOUT_1 ("  bSlot .............: %u\n", msg[5]);
  DEBUGOUT_1 ("  bSeq ..............: %u\n", msg[6]);
  DEBUGOUT_1 ("  bStatus ...........: %u\n", msg[7]);
  if (msg[8])
    DEBUGOUT_1 ("  bError ............: %u\n", msg[8]);
}


static void
print_r2p_datablock (const unsigned char *msg, size_t msglen)
{
  print_r2p_header ("RDR_to_PC_DataBlock", msg, msglen);
  if (msglen < 10)
    return;
  if (msg[9])
    DEBUGOUT_2 ("  bChainParameter ...: 0x%02x%s\n", msg[9],
                msg[9] == 1? " (continued)":
                msg[9] == 2? " (continues+ends)":
                msg[9] == 3? " (continues+continued)":
                msg[9] == 16? " (XferBlock-expected)":"");
  print_pr_data (msg, msglen, 10);
}


static void
print_r2p_slotstatus (const unsigned char *msg, size_t msglen)
{
  print_r2p_header ("RDR_to_PC_SlotStatus", msg, msglen);
  if (msglen < 10)
    return;
  DEBUGOUT_2 ("  bClockStatus ......: 0x%02x%s\n", msg[9],
              msg[9] == 0? " (running)":
              msg[9] == 1? " (stopped-L)":
              msg[9] == 2? " (stopped-H)":
              msg[9] == 3? " (stopped)":"");
  print_pr_data (msg, msglen, 10);
}


static void
print_r2p_parameters (const unsigned char *msg, size_t msglen)
{
  print_r2p_header ("RDR_to_PC_Parameters", msg, msglen);
  if (msglen < 10)
    return;

  DEBUGOUT_1 ("  protocol ..........: T=%d\n", msg[9]);
  if (msglen == 17 && msg[9] == 1)
    {
      /* Protocol T=1.  */
      DEBUGOUT_1 ("  bmFindexDindex ....: %02X\n", msg[10]);
      DEBUGOUT_1 ("  bmTCCKST1 .........: %02X\n", msg[11]);
      DEBUGOUT_1 ("  bGuardTimeT1 ......: %02X\n", msg[12]);
      DEBUGOUT_1 ("  bmWaitingIntegersT1: %02X\n", msg[13]);
      DEBUGOUT_1 ("  bClockStop ........: %02X\n", msg[14]);
      DEBUGOUT_1 ("  bIFSC .............: %d\n", msg[15]);
      DEBUGOUT_1 ("  bNadValue .........: %d\n", msg[16]);
    }
  else
    print_pr_data (msg, msglen, 10);
}


static void
print_r2p_escape (const unsigned char *msg, size_t msglen)
{
  print_r2p_header ("RDR_to_PC_Escape", msg, msglen);
  if (msglen < 10)
    return;
  DEBUGOUT_1 ("  buffer[9] .........: %02X\n", msg[9]);
  print_pr_data (msg, msglen, 10);
}


static void
print_r2p_datarate (const unsigned char *msg, size_t msglen)
{
  print_r2p_header ("RDR_to_PC_DataRate", msg, msglen);
  if (msglen < 10)
    return;
  if (msglen >= 18)
    {
      DEBUGOUT_1 ("  dwClockFrequency ..: %u\n", convert_le_u32 (msg+10));
      DEBUGOUT_1 ("  dwDataRate ..... ..: %u\n", convert_le_u32 (msg+14));
      print_pr_data (msg, msglen, 18);
    }
  else
    print_pr_data (msg, msglen, 10);
}


static void
print_r2p_unknown (const unsigned char *msg, size_t msglen)
{
  print_r2p_header ("Unknown RDR_to_PC command", msg, msglen);
  if (msglen < 10)
    return;
  DEBUGOUT_1 ("  bMessageType ......: %02X\n", msg[0]);
  DEBUGOUT_1 ("  buffer[9] .........: %02X\n", msg[9]);
  print_pr_data (msg, msglen, 10);
}


/* Parse a CCID descriptor, optionally print all available features
   and test whether this reader is usable by this driver.  Returns 0
   if it is usable.

   Note, that this code is based on the one in lsusb.c of the
   usb-utils package, I wrote on 2003-09-01. -wk. */
static int
parse_ccid_descriptor (ccid_driver_t handle, unsigned short bcd_device,
                       const unsigned char *buf, size_t buflen)
{
  unsigned int i;
  unsigned int us;
  int have_t1 = 0, have_tpdu=0;

  handle->nonnull_nad = 0;
  handle->auto_ifsd = 0;
  handle->max_ifsd = 32;
  handle->has_pinpad = 0;
  handle->apdu_level = 0;
  handle->auto_voltage = 0;
  handle->auto_param = 0;
  handle->auto_pps = 0;
  DEBUGOUT_3 ("idVendor: %04X  idProduct: %04X  bcdDevice: %04X\n",
              handle->id_vendor, handle->id_product, bcd_device);
  if (buflen < 54 || buf[0] < 54)
    {
      DEBUGOUT ("CCID device descriptor is too short\n");
      return -1;
    }

  DEBUGOUT   ("ChipCard Interface Descriptor:\n");
  DEBUGOUT_1 ("  bLength             %5u\n", buf[0]);
  DEBUGOUT_1 ("  bDescriptorType     %5u\n", buf[1]);
  DEBUGOUT_2 ("  bcdCCID             %2x.%02x", buf[3], buf[2]);
    if (buf[3] != 1 || buf[2] != 0)
      DEBUGOUT_CONT("  (Warning: Only accurate for version 1.0)");
  DEBUGOUT_LF ();

  DEBUGOUT_1 ("  nMaxSlotIndex       %5u\n", buf[4]);
  DEBUGOUT_2 ("  bVoltageSupport     %5u  %s\n",
              buf[5], (buf[5] == 1? "5.0V" : buf[5] == 2? "3.0V"
                       : buf[5] == 3? "1.8V":"?"));

  us = convert_le_u32 (buf+6);
  DEBUGOUT_1 ("  dwProtocols         %5u ", us);
  if ((us & 1))
    DEBUGOUT_CONT (" T=0");
  if ((us & 2))
    {
      DEBUGOUT_CONT (" T=1");
      have_t1 = 1;
    }
  if ((us & ~3))
    DEBUGOUT_CONT (" (Invalid values detected)");
  DEBUGOUT_LF ();

  us = convert_le_u32(buf+10);
  DEBUGOUT_1 ("  dwDefaultClock      %5u\n", us);
  us = convert_le_u32(buf+14);
  DEBUGOUT_1 ("  dwMaxiumumClock     %5u\n", us);
  DEBUGOUT_1 ("  bNumClockSupported  %5u\n", buf[18]);
  us = convert_le_u32(buf+19);
  DEBUGOUT_1 ("  dwDataRate        %7u bps\n", us);
  us = convert_le_u32(buf+23);
  DEBUGOUT_1 ("  dwMaxDataRate     %7u bps\n", us);
  DEBUGOUT_1 ("  bNumDataRatesSupp.  %5u\n", buf[27]);

  us = convert_le_u32(buf+28);
  DEBUGOUT_1 ("  dwMaxIFSD           %5u\n", us);
  handle->max_ifsd = us;

  us = convert_le_u32(buf+32);
  DEBUGOUT_1 ("  dwSyncProtocols  %08X ", us);
  if ((us&1))
    DEBUGOUT_CONT ( " 2-wire");
  if ((us&2))
    DEBUGOUT_CONT ( " 3-wire");
  if ((us&4))
    DEBUGOUT_CONT ( " I2C");
  DEBUGOUT_LF ();

  us = convert_le_u32(buf+36);
  DEBUGOUT_1 ("  dwMechanical     %08X ", us);
  if ((us & 1))
    DEBUGOUT_CONT (" accept");
  if ((us & 2))
    DEBUGOUT_CONT (" eject");
  if ((us & 4))
    DEBUGOUT_CONT (" capture");
  if ((us & 8))
    DEBUGOUT_CONT (" lock");
  DEBUGOUT_LF ();

  us = convert_le_u32(buf+40);
  DEBUGOUT_1 ("  dwFeatures       %08X\n", us);
  if ((us & 0x0002))
    {
      DEBUGOUT ("    Auto configuration based on ATR (assumes auto voltage)\n");
      handle->auto_voltage = 1;
    }
  if ((us & 0x0004))
    DEBUGOUT ("    Auto activation on insert\n");
  if ((us & 0x0008))
    {
      DEBUGOUT ("    Auto voltage selection\n");
      handle->auto_voltage = 1;
    }
  if ((us & 0x0010))
    DEBUGOUT ("    Auto clock change\n");
  if ((us & 0x0020))
    DEBUGOUT ("    Auto baud rate change\n");
  if ((us & 0x0040))
    {
      DEBUGOUT ("    Auto parameter negotiation made by CCID\n");
      handle->auto_param = 1;
    }
  else if ((us & 0x0080))
    {
      DEBUGOUT ("    Auto PPS made by CCID\n");
      handle->auto_pps = 1;
    }
  if ((us & (0x0040 | 0x0080)) == (0x0040 | 0x0080))
    DEBUGOUT ("    WARNING: conflicting negotiation features\n");

  if ((us & 0x0100))
    DEBUGOUT ("    CCID can set ICC in clock stop mode\n");
  if ((us & 0x0200))
    {
      DEBUGOUT ("    NAD value other than 0x00 accepted\n");
      handle->nonnull_nad = 1;
    }
  if ((us & 0x0400))
    {
      DEBUGOUT ("    Auto IFSD exchange\n");
      handle->auto_ifsd = 1;
    }

  if ((us & 0x00010000))
    {
      DEBUGOUT ("    TPDU level exchange\n");
      have_tpdu = 1;
    }
  else if ((us & 0x00020000))
    {
      DEBUGOUT ("    Short APDU level exchange\n");
      handle->apdu_level = 1;
    }
  else if ((us & 0x00040000))
    {
      DEBUGOUT ("    Short and extended APDU level exchange\n");
      handle->apdu_level = 2;
    }
  else if ((us & 0x00070000))
    DEBUGOUT ("    WARNING: conflicting exchange levels\n");

  us = convert_le_u32(buf+44);
  DEBUGOUT_1 ("  dwMaxCCIDMsgLen     %5u\n", us);
  handle->max_ccid_msglen = us;

  DEBUGOUT (  "  bClassGetResponse    ");
  if (buf[48] == 0xff)
    DEBUGOUT_CONT ("echo\n");
  else
    DEBUGOUT_CONT_1 ("  %02X\n", buf[48]);

  DEBUGOUT (  "  bClassEnvelope       ");
  if (buf[49] == 0xff)
    DEBUGOUT_CONT ("echo\n");
  else
    DEBUGOUT_CONT_1 ("  %02X\n", buf[48]);

  DEBUGOUT (  "  wlcdLayout           ");
  if (!buf[50] && !buf[51])
    DEBUGOUT_CONT ("none\n");
  else
    DEBUGOUT_CONT_2 ("%u cols %u lines\n", buf[50], buf[51]);

  DEBUGOUT_1 ("  bPINSupport         %5u ", buf[52]);
  if ((buf[52] & 1))
    {
      DEBUGOUT_CONT ( " verification");
      handle->has_pinpad |= 1;
    }
  if ((buf[52] & 2))
    {
      DEBUGOUT_CONT ( " modification");
      handle->has_pinpad |= 2;
    }
  DEBUGOUT_LF ();

  DEBUGOUT_1 ("  bMaxCCIDBusySlots   %5u\n", buf[53]);

  if (buf[0] > 54)
    {
      DEBUGOUT ("  junk             ");
      for (i=54; i < buf[0]-54; i++)
        DEBUGOUT_CONT_1 (" %02X", buf[i]);
      DEBUGOUT_LF ();
    }

  if (!have_t1 || !(have_tpdu  || handle->apdu_level))
    {
      DEBUGOUT ("this drivers requires that the reader supports T=1, "
                "TPDU or APDU level exchange - this is not available\n");
      return -1;
    }


  /* SCM drivers get stuck in their internal USB stack if they try to
     send a frame of n*wMaxPacketSize back to us.  Given that
     wMaxPacketSize is 64 for these readers we set the IFSD to a value
     lower than that:
        64 - 10 CCID header -  4 T1frame - 2 reserved = 48
     Product Ids:
         0xe001 - SCR 331
         0x5111 - SCR 331-DI
         0x5115 - SCR 335
         0xe003 - SPR 532
     The
         0x5117 - SCR 3320 USB ID-000 reader
     seems to be very slow but enabling this workaround boosts the
     performance to a more or less acceptable level (tested by David).

  */
  if (handle->id_vendor == VENDOR_SCM
      && handle->max_ifsd > 48
      && (  (handle->id_product == SCM_SCR331   && bcd_device < 0x0516)
          ||(handle->id_product == SCM_SCR331DI && bcd_device < 0x0620)
          ||(handle->id_product == SCM_SCR335   && bcd_device < 0x0514)
          ||(handle->id_product == SCM_SPR532   && bcd_device < 0x0504)
          ||(handle->id_product == SCM_SCR3320  && bcd_device < 0x0522)
          ))
    {
      DEBUGOUT ("enabling workaround for buggy SCM readers\n");
      handle->max_ifsd = 48;
    }

  if (handle->id_vendor == VENDOR_GEMPC)
    {
      DEBUGOUT ("enabling product quirk: disable non-null NAD\n");
      handle->nonnull_nad = 0;
    }

  return 0;
}


static char *
get_escaped_usb_string (libusb_device_handle *idev, int idx,
                        const char *prefix, const char *suffix)
{
  int rc;
  unsigned char buf[280];
  unsigned char *s;
  unsigned int langid;
  size_t i, n, len;
  char *result;

  if (!idx)
    return NULL;

  /* Fixme: The next line is for the current Valgrid without support
     for USB IOCTLs. */
  memset (buf, 0, sizeof buf);

  /* First get the list of supported languages and use the first one.
     If we do don't find it we try to use English.  Note that this is
     all in a 2 bute Unicode encoding using little endian. */
#ifdef USE_NPTH
  npth_unprotect ();
#endif
  rc = libusb_control_transfer (idev, LIBUSB_ENDPOINT_IN,
                                LIBUSB_REQUEST_GET_DESCRIPTOR,
                                (LIBUSB_DT_STRING << 8), 0,
                                buf, sizeof buf, 1000 /* ms timeout */);
#ifdef USE_NPTH
  npth_protect ();
#endif
  if (rc < 4)
    langid = 0x0409; /* English.  */
  else
    langid = (buf[3] << 8) | buf[2];

#ifdef USE_NPTH
  npth_unprotect ();
#endif
  rc = libusb_control_transfer (idev, LIBUSB_ENDPOINT_IN,
                                LIBUSB_REQUEST_GET_DESCRIPTOR,
                                (LIBUSB_DT_STRING << 8) + idx, langid,
                                buf, sizeof buf, 1000 /* ms timeout */);
#ifdef USE_NPTH
  npth_protect ();
#endif
  if (rc < 2 || buf[1] != LIBUSB_DT_STRING)
    return NULL; /* Error or not a string. */
  len = buf[0];
  if (len > rc)
    return NULL; /* Larger than our buffer. */

  for (s=buf+2, i=2, n=0; i+1 < len; i += 2, s += 2)
    {
      if (s[1])
        n++; /* High byte set. */
      else if (*s <= 0x20 || *s >= 0x7f || *s == '%' || *s == ':')
        n += 3 ;
      else
        n++;
    }

  result = malloc (strlen (prefix) + n + strlen (suffix) + 1);
  if (!result)
    return NULL;

  strcpy (result, prefix);
  n = strlen (prefix);
  for (s=buf+2, i=2; i+1 < len; i += 2, s += 2)
    {
      if (s[1])
        result[n++] = '\xff'; /* High byte set. */
      else if (*s <= 0x20 || *s >= 0x7f || *s == '%' || *s == ':')
        {
          sprintf (result+n, "%%%02X", *s);
          n += 3;
        }
      else
        result[n++] = *s;
    }
  strcpy (result+n, suffix);

  return result;
}

/* This function creates an reader id to be used to find the same
   physical reader after a reset.  It returns an allocated and possibly
   percent escaped string or NULL if not enough memory is available. */
static char *
make_reader_id (libusb_device_handle *idev,
                unsigned int vendor, unsigned int product,
                unsigned char serialno_index)
{
  char *rid;
  char prefix[20];

  sprintf (prefix, "%04X:%04X:", (vendor & 0xffff), (product & 0xffff));
  rid = get_escaped_usb_string (idev, serialno_index, prefix, ":0");
  if (!rid)
    {
      rid = malloc (strlen (prefix) + 3 + 1);
      if (!rid)
        return NULL;
      strcpy (rid, prefix);
      strcat (rid, "X:0");
    }
  return rid;
}


/* Helper to find the endpoint from an interface descriptor.  */
static int
find_endpoint (const struct libusb_interface_descriptor *ifcdesc, int mode)
{
  int no;
  int want_bulk_in = 0;

  if (mode == 1)
    want_bulk_in = 0x80;
  for (no=0; no < ifcdesc->bNumEndpoints; no++)
    {
      const struct libusb_endpoint_descriptor *ep = ifcdesc->endpoint + no;
      if (ep->bDescriptorType != LIBUSB_DT_ENDPOINT)
        ;
      else if (mode == 2
               && ((ep->bmAttributes & LIBUSB_TRANSFER_TYPE_MASK)
                   == LIBUSB_TRANSFER_TYPE_INTERRUPT)
               && (ep->bEndpointAddress & 0x80))
        return ep->bEndpointAddress;
      else if ((mode == 0 || mode == 1)
               && ((ep->bmAttributes & LIBUSB_TRANSFER_TYPE_MASK)
                   == LIBUSB_TRANSFER_TYPE_BULK)
               && (ep->bEndpointAddress & 0x80) == want_bulk_in)
        return ep->bEndpointAddress;
    }

  return -1;
}


/* Helper for scan_devices. This function returns true if a
   requested device has been found or the caller should stop scanning
   for other reasons. */
static void
scan_usb_device (int *count, char **rid_list, struct libusb_device *dev)
{
  int ifc_no;
  int set_no;
  const struct libusb_interface_descriptor *ifcdesc;
  char *rid;
  libusb_device_handle *idev = NULL;
  int err;
  struct libusb_config_descriptor *config;
  struct libusb_device_descriptor desc;
  char *p;

  err = libusb_get_device_descriptor (dev, &desc);
  if (err)
    return;

  err = libusb_get_active_config_descriptor (dev, &config);
  if (err)
    return;

  for (ifc_no=0; ifc_no < config->bNumInterfaces; ifc_no++)
    for (set_no=0; set_no < config->interface[ifc_no].num_altsetting; set_no++)
      {
        ifcdesc = (config->interface[ifc_no].altsetting + set_no);
        /* The second condition is for older SCM SPR 532 who did
           not know about the assigned CCID class.  The third
           condition does the same for a Cherry SmartTerminal
           ST-2000.  Instead of trying to interpret the strings
           we simply check the product ID. */
        if (ifcdesc && ifcdesc->extra
            && ((ifcdesc->bInterfaceClass == 11
                 && ifcdesc->bInterfaceSubClass == 0
                 && ifcdesc->bInterfaceProtocol == 0)
                || (ifcdesc->bInterfaceClass == 255
                    && desc.idVendor == VENDOR_SCM
                    && desc.idProduct == SCM_SPR532)
                || (ifcdesc->bInterfaceClass == 255
                    && desc.idVendor == VENDOR_CHERRY
                    && desc.idProduct == CHERRY_ST2000)))
          {
            ++*count;

            err = libusb_open (dev, &idev);
            if (err)
              {
                DEBUGOUT_1 ("usb_open failed: %s\n", libusb_error_name (err));
                continue; /* with next setting. */
              }

            rid = make_reader_id (idev, desc.idVendor, desc.idProduct,
                                  desc.iSerialNumber);
            if (!rid)
              {
                libusb_free_config_descriptor (config);
                return;
              }

            /* We are collecting infos about all available CCID
               readers.  Store them and continue.  */
            DEBUGOUT_2 ("found CCID reader %d (ID=%s)\n", *count, rid);
            p = malloc ((*rid_list? strlen (*rid_list):0) + 1
                        + strlen (rid) + 1);
            if (p)
              {
                *p = 0;
                if (*rid_list)
                  {
                    strcat (p, *rid_list);
                    free (*rid_list);
                  }
                strcat (p, rid);
                strcat (p, "\n");
                *rid_list = p;
              }
            else /* Out of memory. */
              {
                libusb_free_config_descriptor (config);
                free (rid);
                return;
              }

            free (rid);
            libusb_close (idev);
            idev = NULL;
          }
      }

  libusb_free_config_descriptor (config);
}

/* Scan all CCID devices.

   The function returns 0 if a reader has been found or when a scan
   returned without error.

   R_RID should be the address where to store the list of reader_ids
   we found.  If on return this list is empty, no CCID device has been
   found; otherwise it points to an allocated linked list of reader
   IDs.
*/
static int
scan_devices (char **r_rid)
{
  char *rid_list = NULL;
  int count = 0;
  libusb_device **dev_list = NULL;
  libusb_device *dev;
  int i;
  ssize_t n;

  /* Set return values to a default. */
  if (r_rid)
    *r_rid = NULL;

  n = libusb_get_device_list (NULL, &dev_list);

  for (i = 0; i < n; i++)
    {
      dev = dev_list[i];
      scan_usb_device (&count, &rid_list, dev);
    }

  libusb_free_device_list (dev_list, 1);

  *r_rid = rid_list;
  return 0;
}


/* Set the level of debugging to LEVEL and return the old level.  -1
   just returns the old level.  A level of 0 disables debugging, 1
   enables debugging, 2 enables additional tracing of the T=1
   protocol, 3 additionally enables debugging for GetSlotStatus, other
   values are not yet defined.

   Note that libusb may provide its own debugging feature which is
   enabled by setting the envvar USB_DEBUG.  */
int
ccid_set_debug_level (int level)
{
  int old = debug_level;
  if (level != -1)
    debug_level = level;
  return old;
}


char *
ccid_get_reader_list (void)
{
  char *reader_list;

  if (!initialized_usb)
    {
      int rc;
      if ((rc = libusb_init (NULL)))
        {
          DEBUGOUT_1 ("usb_init failed: %s.\n", libusb_error_name (rc));
          return NULL;
        }
      initialized_usb = 1;
    }

  if (scan_devices (&reader_list))
    return NULL; /* Error. */
  return reader_list;
}


/* Vendor specific custom initialization.  */
static int
ccid_vendor_specific_init (ccid_driver_t handle)
{
  int r = 0;

  if (handle->id_vendor == VENDOR_VEGA && handle->id_product == VEGA_ALPHA)
    {
      /*
       * Vega alpha has a feature to show retry counter on the pinpad
       * display.  But it assumes that the card returns the value of
       * retry counter by VERIFY with empty data (return code of
       * 63Cx).  Unfortunately, existing OpenPGP cards don't support
       * VERIFY command with empty data.  This vendor specific command
       * sequence is to disable the feature.
       */
      const unsigned char cmd[] = { '\xb5', '\x01', '\x00', '\x03', '\x00' };

      r = send_escape_cmd (handle, cmd, sizeof (cmd), NULL, 0, NULL);
    }
  else if (handle->id_vendor == VENDOR_SCM && handle->id_product == SCM_SPR532)
    {
      /*
       * It seems that SEQ may be out of sync between host and the card reader,
       * and SET_INTERFACE doesn't reset it.  Make sure it works at the init.
       */
      abort_cmd (handle, 0);
    }

  if (r != 0 && r != CCID_DRIVER_ERR_CARD_INACTIVE
      && r != CCID_DRIVER_ERR_NO_CARD)
    return r;
  else
    return 0;
}


static int
ccid_vendor_specific_setup (ccid_driver_t handle)
{
  if (handle->id_vendor == VENDOR_SCM && handle->id_product == SCM_SPR532)
    {
      DEBUGOUT ("sending escape sequence to switch to a case 1 APDU\n");
      send_escape_cmd (handle, (const unsigned char*)"\x80\x02\x00", 3,
                       NULL, 0, NULL);
      libusb_clear_halt (handle->idev, handle->ep_intr);
    }
  return 0;
}


#define MAX_DEVICE 4 /* See MAX_READER in apdu.c.  */

struct ccid_dev_table {
  int n;                        /* Index to ccid_usb_dev_list */
  int interface_number;
  int setting_number;
  unsigned char *ifcdesc_extra;
  int ep_bulk_out;
  int ep_bulk_in;
  int ep_intr;
  size_t ifcdesc_extra_len;
};

static libusb_device **ccid_usb_dev_list;
static struct ccid_dev_table ccid_dev_table[MAX_DEVICE];

gpg_error_t
ccid_dev_scan (int *idx_max_p, void **t_p)
{
  ssize_t n;
  libusb_device *dev;
  int i;
  int ifc_no;
  int set_no;
  int idx = 0;
  int err = 0;

  *idx_max_p = 0;
  *t_p = NULL;

  if (!initialized_usb)
    {
      int rc;
      if ((rc = libusb_init (NULL)))
        {
          DEBUGOUT_1 ("usb_init failed: %s.\n", libusb_error_name (rc));
          return gpg_error (GPG_ERR_ENODEV);
        }
      initialized_usb = 1;
    }

  n = libusb_get_device_list (NULL, &ccid_usb_dev_list);
  for (i = 0; i < n; i++)
    {
      struct libusb_config_descriptor *config;
      struct libusb_device_descriptor desc;

      dev = ccid_usb_dev_list[i];

      if (libusb_get_device_descriptor (dev, &desc))
        continue;

      if (libusb_get_active_config_descriptor (dev, &config))
        continue;

      for (ifc_no=0; ifc_no < config->bNumInterfaces; ifc_no++)
        for (set_no=0; set_no < config->interface[ifc_no].num_altsetting;
             set_no++)
          {
            const struct libusb_interface_descriptor *ifcdesc;

            ifcdesc = &config->interface[ifc_no].altsetting[set_no];
            /* The second condition is for older SCM SPR 532 who did
               not know about the assigned CCID class.  The third
               condition does the same for a Cherry SmartTerminal
               ST-2000.  Instead of trying to interpret the strings
               we simply check the product ID. */
            if (ifcdesc && ifcdesc->extra
                && ((ifcdesc->bInterfaceClass == 11
                     && ifcdesc->bInterfaceSubClass == 0
                     && ifcdesc->bInterfaceProtocol == 0)
                    || (ifcdesc->bInterfaceClass == 255
                        && desc.idVendor == VENDOR_SCM
                        && desc.idProduct == SCM_SPR532)
                    || (ifcdesc->bInterfaceClass == 255
                        && desc.idVendor == VENDOR_CHERRY
                        && desc.idProduct == CHERRY_ST2000)))
              {
                /* Found a reader.  */
                unsigned char *ifcdesc_extra;

                ifcdesc_extra = malloc (ifcdesc->extra_length);
                if (!ifcdesc_extra)
                  {
                    err = gpg_error_from_syserror ();
                    libusb_free_config_descriptor (config);
                    goto scan_finish;
                  }
                memcpy (ifcdesc_extra, ifcdesc->extra, ifcdesc->extra_length);

                ccid_dev_table[idx].n = i;
                ccid_dev_table[idx].interface_number = ifc_no;
                ccid_dev_table[idx].setting_number = set_no;
                ccid_dev_table[idx].ifcdesc_extra = ifcdesc_extra;
                ccid_dev_table[idx].ifcdesc_extra_len = ifcdesc->extra_length;
                ccid_dev_table[idx].ep_bulk_out = find_endpoint (ifcdesc, 0);
                ccid_dev_table[idx].ep_bulk_in = find_endpoint (ifcdesc, 1);
                ccid_dev_table[idx].ep_intr = find_endpoint (ifcdesc, 2);

                idx++;
                if (idx >= MAX_DEVICE)
                  {
                    libusb_free_config_descriptor (config);
                    err = 0;
                    goto scan_finish;
                  }
              }
          }

      libusb_free_config_descriptor (config);
    }

 scan_finish:

  if (err)
    {
      for (i = 0; i < idx; i++)
        {
          free (ccid_dev_table[idx].ifcdesc_extra);
          ccid_dev_table[idx].n = 0;
          ccid_dev_table[idx].interface_number = 0;
          ccid_dev_table[idx].setting_number = 0;
          ccid_dev_table[idx].ifcdesc_extra = NULL;
          ccid_dev_table[idx].ifcdesc_extra_len = 0;
          ccid_dev_table[idx].ep_bulk_out = 0;
          ccid_dev_table[idx].ep_bulk_in = 0;
          ccid_dev_table[idx].ep_intr = 0;
        }
      libusb_free_device_list (ccid_usb_dev_list, 1);
      ccid_usb_dev_list = NULL;
    }
  else
    {
      *idx_max_p = idx;
      if (idx)
        *t_p = ccid_dev_table;
      else
        *t_p = NULL;
    }

  return err;
}

void
ccid_dev_scan_finish (void *tbl0, int max)
{
  int i;
  struct ccid_dev_table *tbl = tbl0;

  for (i = 0; i < max; i++)
    {
      free (tbl[i].ifcdesc_extra);
      tbl[i].n = 0;
      tbl[i].interface_number = 0;
      tbl[i].setting_number = 0;
      tbl[i].ifcdesc_extra = NULL;
      tbl[i].ifcdesc_extra_len = 0;
      tbl[i].ep_bulk_out = 0;
      tbl[i].ep_bulk_in = 0;
      tbl[i].ep_intr = 0;
    }
  libusb_free_device_list (ccid_usb_dev_list, 1);
  ccid_usb_dev_list = NULL;
}

unsigned int
ccid_get_BAI (int idx, void *tbl0)
{
  int n;
  int bus, addr, intf;
  unsigned int bai;
  libusb_device *dev;
  struct ccid_dev_table *tbl = tbl0;

  n = tbl[idx].n;
  dev = ccid_usb_dev_list[n];

  bus = libusb_get_bus_number (dev);
  addr = libusb_get_device_address (dev);
  intf = tbl[idx].interface_number;
  bai = (bus << 16) | (addr << 8) | intf;

  return bai;
}

int
ccid_compare_BAI (ccid_driver_t handle, unsigned int bai)
{
  return handle->bai == bai;
}


static void
intr_cb (struct libusb_transfer *transfer)
{
  ccid_driver_t handle = transfer->user_data;

  DEBUGOUT_2 ("CCID: interrupt callback %d (%d)\n",
              transfer->status, transfer->actual_length);

  if (transfer->status == LIBUSB_TRANSFER_TIMED_OUT)
    {
      int err;

    submit_again:
      /* Submit the URB again to keep watching the INTERRUPT transfer.  */
      err = libusb_submit_transfer (transfer);
      if (err == LIBUSB_ERROR_NO_DEVICE)
        goto device_removed;

      DEBUGOUT_1 ("CCID submit transfer again %d\n", err);
    }
  else if (transfer->status == LIBUSB_TRANSFER_COMPLETED)
    {
      size_t len = transfer->actual_length;
      unsigned char *p = transfer->buffer;
      int card_removed = 0;

      while (len)
        {
          if (*p == RDR_to_PC_NotifySlotChange)
            {
              if (len < 2)
                break;

              DEBUGOUT_1 ("CCID: NotifySlotChange: %02x\n", p[1]);

              if ((p[1] & 1))
                card_removed = 0;
              else
                card_removed = 1;

              p += 2;
              len -= 2;
            }
          else if (*p == RDR_to_PC_HardwareError)
            {
              if (len < 4)
                break;

              DEBUGOUT_1 ("CCID: hardware error detected: %02x\n", p[3]);
              p += 4;
              len -= 4;
            }
          else
            {
              DEBUGOUT_1 ("CCID: unknown intr: %02x\n", p[0]);
              break;
            }
        }

      if (card_removed)
        {
          DEBUGOUT ("CCID: card removed\n");
          handle->powered_off = 1;
#if defined(GNUPG_MAJOR_VERSION)
          scd_kick_the_loop ();
#endif
        }
      else
        {
          /* Event other than card removal.  */
          goto submit_again;
        }
    }
  else if (transfer->status == LIBUSB_TRANSFER_CANCELLED)
    handle->powered_off = 1;
  else
    {
    device_removed:
      DEBUGOUT ("CCID: device removed\n");
      handle->powered_off = 1;
#if defined(GNUPG_MAJOR_VERSION)
      scd_kick_the_loop ();
#endif
    }
}

static void
ccid_setup_intr  (ccid_driver_t handle)
{
  struct libusb_transfer *transfer;
  int err;

  transfer = libusb_alloc_transfer (0);
  handle->transfer = transfer;
  libusb_fill_interrupt_transfer (transfer, handle->idev, handle->ep_intr,
                                  handle->intr_buf, sizeof (handle->intr_buf),
                                  intr_cb, handle, 0);
  err = libusb_submit_transfer (transfer);
  DEBUGOUT_2 ("CCID submit transfer (%x): %d", handle->ep_intr, err);
}


static void *
ccid_usb_thread (void *arg)
{
  libusb_context *ctx = arg;

  while (ccid_usb_thread_is_alive)
    {
#ifdef USE_NPTH
      npth_unprotect ();
#endif
      libusb_handle_events_completed (ctx, NULL);
#ifdef USE_NPTH
      npth_protect ();
#endif
    }

  return NULL;
}


static int
ccid_open_usb_reader (const char *spec_reader_name,
                      int idx, void *ccid_table0,
                      ccid_driver_t *handle, char **rdrname_p)
{
  libusb_device *dev;
  libusb_device_handle *idev = NULL;
  char *rid = NULL;
  int rc = 0;
  int ifc_no, set_no;
  struct libusb_device_descriptor desc;
  int n;
  int bus, addr;
  unsigned int bai;
  struct ccid_dev_table *ccid_table = ccid_table0;

  n = ccid_table[idx].n;
  ifc_no = ccid_table[idx].interface_number;
  set_no = ccid_table[idx].setting_number;

  dev = ccid_usb_dev_list[n];
  bus = libusb_get_bus_number (dev);
  addr = libusb_get_device_address (dev);
  bai = (bus << 16) | (addr << 8) | ifc_no;

  rc = libusb_open (dev, &idev);
  if (rc)
    {
      DEBUGOUT_1 ("usb_open failed: %s\n", libusb_error_name (rc));
      free (*handle);
      *handle = NULL;
      return map_libusb_error (rc);
    }

  if (ccid_usb_thread_is_alive++ == 0)
    {
      npth_t thread;
      npth_attr_t tattr;
      int err;

      err = npth_attr_init (&tattr);
      if (err)
        {
          DEBUGOUT_1 ("npth_attr_init failed: %s\n", strerror (err));
          free (*handle);
          *handle = NULL;
          return err;
        }

      npth_attr_setdetachstate (&tattr, NPTH_CREATE_DETACHED);
      err = npth_create (&thread, &tattr, ccid_usb_thread, NULL);
      if (err)
        {
          DEBUGOUT_1 ("npth_create failed: %s\n", strerror (err));
          free (*handle);
          *handle = NULL;
          return err;
        }

      npth_attr_destroy (&tattr);
    }

  rc = libusb_get_device_descriptor (dev, &desc);
  if (rc)
    {
      DEBUGOUT ("get_device_descripor failed\n");
      rc = map_libusb_error (rc);
      goto leave;
    }

  rid = make_reader_id (idev, desc.idVendor, desc.idProduct,
                        desc.iSerialNumber);

  /* Check to see if reader name matches the spec.  */
  if (spec_reader_name
      && strncmp (rid, spec_reader_name, strlen (spec_reader_name)))
    {
      DEBUGOUT ("device not matched\n");
      rc = CCID_DRIVER_ERR_NO_READER;
      goto leave;
    }

  (*handle)->id_vendor = desc.idVendor;
  (*handle)->id_product = desc.idProduct;
  (*handle)->idev = idev;
  (*handle)->bai = bai;
  (*handle)->ifc_no = ifc_no;
  (*handle)->ep_bulk_out = ccid_table[idx].ep_bulk_out;
  (*handle)->ep_bulk_in = ccid_table[idx].ep_bulk_in;
  (*handle)->ep_intr = ccid_table[idx].ep_intr;

  DEBUGOUT_2 ("using CCID reader %d (ID=%s)\n", idx, rid);

  if (parse_ccid_descriptor (*handle, desc.bcdDevice,
                             ccid_table[idx].ifcdesc_extra,
                             ccid_table[idx].ifcdesc_extra_len))
    {
      DEBUGOUT ("device not supported\n");
      rc = CCID_DRIVER_ERR_NO_READER;
      goto leave;
    }

  rc = libusb_claim_interface (idev, ifc_no);
  if (rc)
    {
      DEBUGOUT_1 ("usb_claim_interface failed: %d\n", rc);
      rc = map_libusb_error (rc);
      goto leave;
    }

  /* Submit SET_INTERFACE control transfer which can reset the device.  */
  rc = libusb_set_interface_alt_setting (idev, ifc_no, set_no);
  if (rc)
    {
      DEBUGOUT_1 ("usb_set_interface_alt_setting failed: %d\n", rc);
      rc = map_libusb_error (rc);
      goto leave;
    }

  rc = ccid_vendor_specific_init (*handle);

 leave:
  if (rc)
    {
      --ccid_usb_thread_is_alive;
      free (rid);
      libusb_release_interface (idev, ifc_no);
      libusb_close (idev);
      free (*handle);
      *handle = NULL;
    }
  else
    {
      if (rdrname_p)
        *rdrname_p = rid;
      else
        free (rid);
    }

  return rc;
}

/* Open the reader with the internal number READERNO and return a
   pointer to be used as handle in HANDLE.  Returns 0 on success. */
int
ccid_open_reader (const char *spec_reader_name, int idx,
                  void *ccid_table0,
                  ccid_driver_t *handle, char **rdrname_p)
{
  struct ccid_dev_table *ccid_table = ccid_table0;

  *handle = calloc (1, sizeof **handle);
  if (!*handle)
    {
      DEBUGOUT ("out of memory\n");
      return CCID_DRIVER_ERR_OUT_OF_CORE;
    }

  return ccid_open_usb_reader (spec_reader_name, idx, ccid_table,
                               handle, rdrname_p);
}


int
ccid_require_get_status (ccid_driver_t handle)
{
  /* When a card reader supports interrupt transfer to check the
     status of card, it is possible to submit only an interrupt
     transfer, and no check is required by application layer.  USB can
     detect removal of a card and can detect removal of a reader.
  */
  if (handle->ep_intr >= 0)
    {
      if (handle->id_vendor != VENDOR_SCM)
        return 0;

      /*
       * For card reader with interrupt transfer support, ideally,
       * removal is detected by intr_cb, but some card reader
       * (e.g. SPR532) has a possible case of missing report to
       * intr_cb, and another case of valid report to intr_cb.
       *
       * For such a reader, the removal should be able to be detected
       * by PC_to_RDR_GetSlotStatus, too.  Thus, calls to
       * ccid_slot_status should go on wire even if "on_wire" is not
       * requested.
       *
       */
      if (handle->transfer == NULL)
        return 0;
    }

  /* Libusb actually detects the removal of USB device in use.
     However, there is no good API to handle the removal (yet),
     cleanly and with good portability.

     There is libusb_set_pollfd_notifiers function, but it doesn't
     offer libusb_device_handle* data to its callback.  So, when it
     watches multiple devices, there is no way to know which device is
     removed.

     Once, we will have a good programming interface of libusb, we can
     list tokens (with no interrupt transfer support, but always with
     card inserted) here to return 0, so that scdaemon can submit
     minimum packet on wire.
  */
  return 1;
}

static int
send_power_off (ccid_driver_t handle)
{
  int rc;
  unsigned char msg[100];
  size_t msglen;
  unsigned char seqno;

  msg[0] = PC_to_RDR_IccPowerOff;
  msg[5] = 0; /* slot */
  msg[6] = seqno = handle->seqno++;
  msg[7] = 0; /* RFU */
  msg[8] = 0; /* RFU */
  msg[9] = 0; /* RFU */
  set_msg_len (msg, 0);
  msglen = 10;

  rc = bulk_out (handle, msg, msglen, 0);
  if (!rc)
    bulk_in (handle, msg, sizeof msg, &msglen, RDR_to_PC_SlotStatus,
             seqno, 2000, 0);
  return rc;
}

static void
do_close_reader (ccid_driver_t handle)
{
  int rc;

  if (!handle->powered_off)
    send_power_off (handle);

  if (handle->transfer)
    {
      if (!handle->powered_off)
        {
          DEBUGOUT ("libusb_cancel_transfer\n");

          rc = libusb_cancel_transfer (handle->transfer);
          if (rc != LIBUSB_ERROR_NOT_FOUND)
            while (!handle->powered_off)
              {
                DEBUGOUT ("libusb_handle_events_completed\n");
#ifdef USE_NPTH
                npth_unprotect ();
#endif
                libusb_handle_events_completed (NULL, &handle->powered_off);
#ifdef USE_NPTH
                npth_protect ();
#endif
              }
        }

      libusb_free_transfer (handle->transfer);
      handle->transfer = NULL;
    }
  libusb_release_interface (handle->idev, handle->ifc_no);
  --ccid_usb_thread_is_alive;
  libusb_close (handle->idev);
  handle->idev = NULL;
}


int
ccid_set_progress_cb (ccid_driver_t handle,
                      void (*cb)(void *, const char *, int, int, int),
                      void *cb_arg)
{
  if (!handle)
    return CCID_DRIVER_ERR_INV_VALUE;

  handle->progress_cb = cb;
  handle->progress_cb_arg = cb_arg;
  return 0;
}


int
ccid_set_prompt_cb (ccid_driver_t handle,
		    void (*cb)(void *, int), void *cb_arg)
{
  if (!handle)
    return CCID_DRIVER_ERR_INV_VALUE;

  handle->prompt_cb = cb;
  handle->prompt_cb_arg = cb_arg;
  return 0;
}


/* Close the reader HANDLE. */
int
ccid_close_reader (ccid_driver_t handle)
{
  if (!handle)
    return 0;

  do_close_reader (handle);
  free (handle);
  return 0;
}


/* Return False if a card is present and powered. */
int
ccid_check_card_presence (ccid_driver_t handle)
{
  (void)handle;  /* Not yet implemented.  */
  return -1;
}


/* Write a MSG of length MSGLEN to the designated bulk out endpoint.
   Returns 0 on success. */
static int
bulk_out (ccid_driver_t handle, unsigned char *msg, size_t msglen,
          int no_debug)
{
  int rc;
  int transferred;

  /* No need to continue and clutter the log with USB write error
     messages after we got the first ENODEV.  */
  if (handle->enodev_seen)
    return CCID_DRIVER_ERR_NO_READER;

  if (debug_level && (!no_debug || debug_level >= 3))
    {
      switch (msglen? msg[0]:0)
        {
        case PC_to_RDR_IccPowerOn:
          print_p2r_iccpoweron (msg, msglen);
          break;
        case PC_to_RDR_IccPowerOff:
          print_p2r_iccpoweroff (msg, msglen);
          break;
        case PC_to_RDR_GetSlotStatus:
          print_p2r_getslotstatus (msg, msglen);
          break;
        case PC_to_RDR_XfrBlock:
          print_p2r_xfrblock (msg, msglen);
          break;
        case PC_to_RDR_GetParameters:
          print_p2r_getparameters (msg, msglen);
          break;
        case PC_to_RDR_ResetParameters:
          print_p2r_resetparameters (msg, msglen);
          break;
        case PC_to_RDR_SetParameters:
          print_p2r_setparameters (msg, msglen);
          break;
        case PC_to_RDR_Escape:
          print_p2r_escape (msg, msglen);
          break;
        case PC_to_RDR_IccClock:
          print_p2r_iccclock (msg, msglen);
          break;
        case PC_to_RDR_T0APDU:
          print_p2r_to0apdu (msg, msglen);
          break;
        case PC_to_RDR_Secure:
          print_p2r_secure (msg, msglen);
          break;
        case PC_to_RDR_Mechanical:
          print_p2r_mechanical (msg, msglen);
          break;
        case PC_to_RDR_Abort:
          print_p2r_abort (msg, msglen);
          break;
        case PC_to_RDR_SetDataRate:
          print_p2r_setdatarate (msg, msglen);
          break;
        default:
          print_p2r_unknown (msg, msglen);
          break;
        }
    }

#ifdef USE_NPTH
  npth_unprotect ();
#endif
  rc = libusb_bulk_transfer (handle->idev, handle->ep_bulk_out,
                             msg, msglen, &transferred,
                             5000 /* ms timeout */);
#ifdef USE_NPTH
  npth_protect ();
#endif
  if (rc == 0 && transferred == msglen)
    return 0;

  if (rc)
    {
      DEBUGOUT_1 ("usb_bulk_write error: %s\n", libusb_error_name (rc));
      if (rc == LIBUSB_ERROR_NO_DEVICE)
        {
          handle->enodev_seen = 1;
          return CCID_DRIVER_ERR_NO_READER;
        }
    }

  return 0;
}


/* Read a maximum of LENGTH bytes from the bulk in endpoint into
   BUFFER and return the actual read number if bytes in NREAD. SEQNO
   is the sequence number used to send the request and EXPECTED_TYPE
   the type of message we expect. Does checks on the ccid
   header. TIMEOUT is the timeout value in ms. NO_DEBUG may be set to
   avoid debug messages in case of no error; this can be overriden
   with a glibal debug level of at least 3. Returns 0 on success. */
static int
bulk_in (ccid_driver_t handle, unsigned char *buffer, size_t length,
         size_t *nread, int expected_type, int seqno, int timeout,
         int no_debug)
{
  int rc;
  int msglen;
  int notified = 0;
  int bwi = 1;

  /* Fixme: The next line for the current Valgrind without support
     for USB IOCTLs. */
  memset (buffer, 0, length);
 retry:

#ifdef USE_NPTH
  npth_unprotect ();
#endif
  rc = libusb_bulk_transfer (handle->idev, handle->ep_bulk_in,
                             buffer, length, &msglen, bwi*timeout);
#ifdef USE_NPTH
  npth_protect ();
#endif
  if (rc)
    {
      DEBUGOUT_1 ("usb_bulk_read error: %s\n", libusb_error_name (rc));
      if (rc == LIBUSB_ERROR_NO_DEVICE)
        handle->enodev_seen = 1;

      return map_libusb_error (rc);
    }
  if (msglen < 0)
    return CCID_DRIVER_ERR_INV_VALUE;  /* Faulty libusb.  */
  *nread = msglen;

  if (msglen < 10)
    {
      DEBUGOUT_1 ("bulk-in msg too short (%u)\n", (unsigned int)msglen);
      abort_cmd (handle, seqno);
      return CCID_DRIVER_ERR_INV_VALUE;
    }
  if (buffer[5] != 0)
    {
      DEBUGOUT_1 ("unexpected bulk-in slot (%d)\n", buffer[5]);
      return CCID_DRIVER_ERR_INV_VALUE;
    }
  if (buffer[6] != seqno)
    {
      DEBUGOUT_2 ("bulk-in seqno does not match (%d/%d)\n",
                  seqno, buffer[6]);
      /* Retry until we are synced again.  */
      goto retry;
    }

  /* We need to handle the time extension request before we check that
     we got the expected message type.  This is in particular required
     for the Cherry keyboard which sends a time extension request for
     each key hit.  */
  if (!(buffer[7] & 0x03) && (buffer[7] & 0xC0) == 0x80)
    {
      /* Card present and active, time extension requested. */
      DEBUGOUT_2 ("time extension requested (%02X,%02X)\n",
                  buffer[7], buffer[8]);

      bwi = 1;
      if (buffer[8] != 0 && buffer[8] != 0xff)
        bwi = buffer[8];

      /* Gnuk enhancement to prompt user input by ack button */
      if (buffer[8] == 0xff && !notified)
        {
          notified = 1;
	  handle->prompt_cb (handle->prompt_cb_arg, 1);
        }

      goto retry;
    }

  if (notified)
    handle->prompt_cb (handle->prompt_cb_arg, 0);

  if (buffer[0] != expected_type && buffer[0] != RDR_to_PC_SlotStatus)
    {
      DEBUGOUT_1 ("unexpected bulk-in msg type (%02x)\n", buffer[0]);
      abort_cmd (handle, seqno);
      return CCID_DRIVER_ERR_INV_VALUE;
    }

  if (debug_level && (!no_debug || debug_level >= 3))
    {
      switch (buffer[0])
        {
        case RDR_to_PC_DataBlock:
          print_r2p_datablock (buffer, msglen);
          break;
        case RDR_to_PC_SlotStatus:
          print_r2p_slotstatus (buffer, msglen);
          break;
        case RDR_to_PC_Parameters:
          print_r2p_parameters (buffer, msglen);
          break;
        case RDR_to_PC_Escape:
          print_r2p_escape (buffer, msglen);
          break;
        case RDR_to_PC_DataRate:
          print_r2p_datarate (buffer, msglen);
          break;
        default:
          print_r2p_unknown (buffer, msglen);
          break;
        }
    }
  if (CCID_COMMAND_FAILED (buffer))
    print_command_failed (buffer);

  /* Check whether a card is at all available.  Note: If you add new
     error codes here, check whether they need to be ignored in
     send_escape_cmd. */
  switch ((buffer[7] & 0x03))
    {
    case 0: /* no error */ break;
    case 1: rc = CCID_DRIVER_ERR_CARD_INACTIVE; break;
    case 2: rc = CCID_DRIVER_ERR_NO_CARD; break;
    case 3: /* RFU */ break;
    }

  if (rc)
    {
      /*
       * Communication failure by device side.
       * Possibly, it was forcibly suspended and resumed.
       */
      if (handle->ep_intr < 0)
        {
          DEBUGOUT ("CCID: card inactive/removed\n");
          handle->powered_off = 1;
        }

#if defined(GNUPG_MAJOR_VERSION)
      scd_kick_the_loop ();
#endif
    }

  return rc;
}



/* Send an abort sequence and wait until everything settled.  */
static int
abort_cmd (ccid_driver_t handle, int seqno)
{
  int rc;
  unsigned char dummybuf[8];
  unsigned char msg[100];
  int msglen;

  seqno &= 0xff;
  DEBUGOUT_1 ("sending abort sequence for seqno %d\n", seqno);
  /* Send the abort command to the control pipe.  Note that we don't
     need to keep track of sent abort commands because there should
     never be another thread using the same slot concurrently.  */
#ifdef USE_NPTH
  npth_unprotect ();
#endif
  rc = libusb_control_transfer (handle->idev,
                                0x21,/* bmRequestType: host-to-device,
                                        class specific, to interface.  */
                                1,   /* ABORT */
                                (seqno << 8 | 0 /* slot */),
                                handle->ifc_no,
                                dummybuf, 0,
                                1000 /* ms timeout */);
#ifdef USE_NPTH
  npth_protect ();
#endif
  if (rc)
    {
      DEBUGOUT_1 ("usb_control_msg error: %s\n", libusb_error_name (rc));
      return map_libusb_error (rc);
    }

  /* Now send the abort command to the bulk out pipe using the same
     SEQNO and SLOT.  Do this in a loop to so that all seqno are
     tried.  */
  seqno--;  /* Adjust for next increment.  */
  do
    {
      int transferred;

      seqno++;
      msg[0] = PC_to_RDR_Abort;
      msg[5] = 0; /* slot */
      msg[6] = seqno;
      msg[7] = 0; /* RFU */
      msg[8] = 0; /* RFU */
      msg[9] = 0; /* RFU */
      msglen = 10;
      set_msg_len (msg, 0);

#ifdef USE_NPTH
      npth_unprotect ();
#endif
      rc = libusb_bulk_transfer (handle->idev, handle->ep_bulk_out,
                                 msg, msglen, &transferred,
                                 5000 /* ms timeout */);
#ifdef USE_NPTH
      npth_protect ();
#endif
      if (rc == 0 && transferred == msglen)
        rc = 0;
      else if (rc)
        DEBUGOUT_1 ("usb_bulk_write error in abort_cmd: %s\n",
                    libusb_error_name (rc));

      if (rc)
        return map_libusb_error (rc);

#ifdef USE_NPTH
      npth_unprotect ();
#endif
      rc = libusb_bulk_transfer (handle->idev, handle->ep_bulk_in,
                                 msg, sizeof msg, &msglen,
                                 5000 /*ms timeout*/);
#ifdef USE_NPTH
      npth_protect ();
#endif
      if (rc)
        {
          DEBUGOUT_1 ("usb_bulk_read error in abort_cmd: %s\n",
                      libusb_error_name (rc));
          return map_libusb_error (rc);
        }

      if (msglen < 10)
        {
          DEBUGOUT_1 ("bulk-in msg in abort_cmd too short (%u)\n",
                      (unsigned int)msglen);
          return CCID_DRIVER_ERR_INV_VALUE;
        }
      if (msg[5] != 0)
        {
          DEBUGOUT_1 ("unexpected bulk-in slot (%d) in abort_cmd\n", msg[5]);
          return CCID_DRIVER_ERR_INV_VALUE;
        }

      DEBUGOUT_3 ("status: %02X  error: %02X  octet[9]: %02X\n",
                  msg[7], msg[8], msg[9]);
      if (CCID_COMMAND_FAILED (msg))
        print_command_failed (msg);
    }
  while (msg[0] != RDR_to_PC_SlotStatus && msg[5] != 0 && msg[6] != seqno);

  handle->seqno = ((seqno + 1) & 0xff);
  DEBUGOUT ("sending abort sequence succeeded\n");

  return 0;
}


/* Note that this function won't return the error codes NO_CARD or
   CARD_INACTIVE.  IF RESULT is not NULL, the result from the
   operation will get returned in RESULT and its length in RESULTLEN.
   If the response is larger than RESULTMAX, an error is returned and
   the required buffer length returned in RESULTLEN.  */
static int
send_escape_cmd (ccid_driver_t handle,
                 const unsigned char *data, size_t datalen,
                 unsigned char *result, size_t resultmax, size_t *resultlen)
{
  int rc;
  unsigned char msg[100];
  size_t msglen;
  unsigned char seqno;

  if (resultlen)
    *resultlen = 0;

  if (datalen > sizeof msg - 10)
    return CCID_DRIVER_ERR_INV_VALUE; /* Escape data too large.  */

  msg[0] = PC_to_RDR_Escape;
  msg[5] = 0; /* slot */
  msg[6] = seqno = handle->seqno++;
  msg[7] = 0; /* RFU */
  msg[8] = 0; /* RFU */
  msg[9] = 0; /* RFU */
  memcpy (msg+10, data, datalen);
  msglen = 10 + datalen;
  set_msg_len (msg, datalen);

  rc = bulk_out (handle, msg, msglen, 0);
  if (rc)
    return rc;
  rc = bulk_in (handle, msg, sizeof msg, &msglen, RDR_to_PC_Escape,
                seqno, 5000, 0);
  if (result)
    switch (rc)
      {
        /* We need to ignore certain errorcode here. */
      case 0:
      case CCID_DRIVER_ERR_CARD_INACTIVE:
      case CCID_DRIVER_ERR_NO_CARD:
        {
          if (msglen > resultmax)
            rc = CCID_DRIVER_ERR_INV_VALUE; /* Response too large. */
          else
            {
              memcpy (result, msg, msglen);
              if (resultlen)
                *resultlen = msglen;
              rc = 0;
            }
        }
        break;
      default:
        break;
      }

  return rc;
}


int
ccid_transceive_escape (ccid_driver_t handle,
                        const unsigned char *data, size_t datalen,
                        unsigned char *resp, size_t maxresplen, size_t *nresp)
{
  return send_escape_cmd (handle, data, datalen, resp, maxresplen, nresp);
}



/* experimental */
int
ccid_poll (ccid_driver_t handle)
{
  int rc;
  unsigned char msg[10];
  int msglen;
  int i, j;

  rc = libusb_interrupt_transfer (handle->idev, handle->ep_intr,
                                  msg, sizeof msg, &msglen,
                                  0 /* ms timeout */ );
  if (rc == LIBUSB_ERROR_TIMEOUT)
    return 0;

  if (rc)
    {
      DEBUGOUT_1 ("usb_intr_read error: %s\n", libusb_error_name (rc));
      return CCID_DRIVER_ERR_CARD_IO_ERROR;
    }

  if (msglen < 1)
    {
      DEBUGOUT ("intr-in msg too short\n");
      return CCID_DRIVER_ERR_INV_VALUE;
    }

  if (msg[0] == RDR_to_PC_NotifySlotChange)
    {
      DEBUGOUT ("notify slot change:");
      for (i=1; i < msglen; i++)
        for (j=0; j < 4; j++)
          DEBUGOUT_CONT_3 (" %d:%c%c",
                           (i-1)*4+j,
                           (msg[i] & (1<<(j*2)))? 'p':'-',
                           (msg[i] & (2<<(j*2)))? '*':' ');
      DEBUGOUT_LF ();
    }
  else if (msg[0] == RDR_to_PC_HardwareError)
    {
      DEBUGOUT ("hardware error occurred\n");
    }
  else
    {
      DEBUGOUT_1 ("unknown intr-in msg of type %02X\n", msg[0]);
    }

  return 0;
}


/* Note that this function won't return the error codes NO_CARD or
   CARD_INACTIVE */
int
ccid_slot_status (ccid_driver_t handle, int *statusbits, int on_wire)
{
  int rc;
  unsigned char msg[100];
  size_t msglen;
  unsigned char seqno;
  int retries = 0;

  if (handle->powered_off)
    return CCID_DRIVER_ERR_NO_READER;

  /* If the card (with its lower-level driver) doesn't require
     GET_STATUS on wire (because it supports INTERRUPT transfer for
     status change, or it's a token which has a card always inserted),
     no need to send on wire.  */
  if (!on_wire && !ccid_require_get_status (handle))
    {
      /* Setup interrupt transfer at the initial call of slot_status
         with ON_WIRE == 0 */
      if (handle->transfer == NULL)
        ccid_setup_intr (handle);

      *statusbits = 0;
      return 0;
    }

 retry:
  msg[0] = PC_to_RDR_GetSlotStatus;
  msg[5] = 0; /* slot */
  msg[6] = seqno = handle->seqno++;
  msg[7] = 0; /* RFU */
  msg[8] = 0; /* RFU */
  msg[9] = 0; /* RFU */
  set_msg_len (msg, 0);

  rc = bulk_out (handle, msg, 10, 1);
  if (rc)
    return rc;
  /* Note that we set the NO_DEBUG flag here, so that the logs won't
     get cluttered up by a ticker function checking for the slot
     status and debugging enabled. */
  rc = bulk_in (handle, msg, sizeof msg, &msglen, RDR_to_PC_SlotStatus,
                seqno, retries? 1000 : 200, 1);
  if ((rc == CCID_DRIVER_ERR_CARD_IO_ERROR || rc == CCID_DRIVER_ERR_USB_TIMEOUT)
      && retries < 3)
    {
      if (!retries)
        {
          DEBUGOUT ("USB: CALLING USB_CLEAR_HALT\n");
#ifdef USE_NPTH
          npth_unprotect ();
#endif
          libusb_clear_halt (handle->idev, handle->ep_bulk_in);
          libusb_clear_halt (handle->idev, handle->ep_bulk_out);
#ifdef USE_NPTH
          npth_protect ();
#endif
        }
      else
          DEBUGOUT ("USB: RETRYING bulk_in AGAIN\n");
      retries++;
      goto retry;
    }
  if (rc && rc != CCID_DRIVER_ERR_NO_CARD && rc != CCID_DRIVER_ERR_CARD_INACTIVE)
    return rc;
  *statusbits = (msg[7] & 3);

  return 0;
}


/* Parse ATR string (of ATRLEN) and update parameters at PARAM.
   Calling this routine, it should prepare default values at PARAM
   beforehand.  This routine assumes that card is accessed by T=1
   protocol.  It doesn't analyze historical bytes at all.

   Returns < 0 value on error:
     -1 for parse error or integrity check error
     -2 for card doesn't support T=1 protocol
     -3 for parameters are nod explicitly defined by ATR
     -4 for this driver doesn't support CRC

   Returns >= 0 on success:
      0 for card is negotiable mode
      1 for card is specific mode (and not negotiable)
 */
static int
update_param_by_atr (unsigned char *param, unsigned char *atr, size_t atrlen)
{
  int i = -1;
  int t, y, chk;
  int historical_bytes_num, negotiable = 1;

#define NEXTBYTE() do { i++; if (atrlen <= i) return -1; } while (0)

  NEXTBYTE ();

  if (atr[i] == 0x3F)
    param[1] |= 0x02;           /* Convention is inverse.  */
  NEXTBYTE ();

  y = (atr[i] >> 4);
  historical_bytes_num = atr[i] & 0x0f;
  NEXTBYTE ();

  if ((y & 1))
    {
      param[0] = atr[i];        /* TA1 - Fi & Di */
      NEXTBYTE ();
    }

  if ((y & 2))
    NEXTBYTE ();                /* TB1 - ignore */

  if ((y & 4))
    {
      param[2] = atr[i];        /* TC1 - Guard Time */
      NEXTBYTE ();
    }

  if ((y & 8))
    {
      y = (atr[i] >> 4);        /* TD1 */
      t = atr[i] & 0x0f;
      NEXTBYTE ();

      if ((y & 1))
        {                       /* TA2 - PPS mode */
          if ((atr[i] & 0x0f) != 1)
            return -2;          /* Wrong card protocol (!= 1).  */

          if ((atr[i] & 0x10) != 0x10)
            return -3; /* Transmission parameters are implicitly defined. */

          negotiable = 0;       /* TA2 means specific mode.  */
          NEXTBYTE ();
        }

      if ((y & 2))
        NEXTBYTE ();            /* TB2 - ignore */

      if ((y & 4))
        NEXTBYTE ();            /* TC2 - ignore */

      if ((y & 8))
        {
          y = (atr[i] >> 4);    /* TD2 */
          t = atr[i] & 0x0f;
          NEXTBYTE ();
        }
      else
        y = 0;

      while (y)
        {
          if ((y & 1))
            {                   /* TAx */
              if (t == 1)
                param[5] = atr[i]; /* IFSC */
              else if (t == 15)
                /* XXX: check voltage? */
                param[4] = (atr[i] >> 6); /* ClockStop */

              NEXTBYTE ();
            }

          if ((y & 2))
            {
              if (t == 1)
                param[3] = atr[i]; /* TBx - BWI & CWI */
              NEXTBYTE ();
            }

          if ((y & 4))
            {
              if (t == 1)
                param[1] |= (atr[i] & 0x01); /* TCx - LRC/CRC */
              NEXTBYTE ();

              if (param[1] & 0x01)
                return -4;      /* CRC not supported yet.  */
            }

          if ((y & 8))
            {
              y = (atr[i] >> 4); /* TDx */
              t = atr[i] & 0x0f;
              NEXTBYTE ();
            }
          else
            y = 0;
        }
    }

  i += historical_bytes_num - 1;
  NEXTBYTE ();
  if (atrlen != i+1)
    return -1;

#undef NEXTBYTE

  chk = 0;
  do
    {
      chk ^= atr[i];
      i--;
    }
  while (i > 0);

  if (chk != 0)
    return -1;

  return negotiable;
}


/* Return the ATR of the card.  This is not a cached value and thus an
   actual reset is done.  */
int
ccid_get_atr (ccid_driver_t handle,
              unsigned char *atr, size_t maxatrlen, size_t *atrlen)
{
  int rc;
  int statusbits;
  unsigned char msg[100];
  unsigned char *tpdu;
  size_t msglen, tpdulen;
  unsigned char seqno;
  int use_crc = 0;
  unsigned int edc;
  int tried_iso = 0;
  int got_param;
  unsigned char param[7] = { /* For Protocol T=1 */
    0x11, /* bmFindexDindex */
    0x10, /* bmTCCKST1 */
    0x00, /* bGuardTimeT1 */
    0x4d, /* bmWaitingIntegersT1 */
    0x00, /* bClockStop */
    0x20, /* bIFSC */
    0x00  /* bNadValue */
  };

  /* First check whether a card is available.  */
  rc = ccid_slot_status (handle, &statusbits, 1);
  if (rc)
    return rc;
  if (statusbits == 2)
    return CCID_DRIVER_ERR_NO_CARD;

  /*
   * In the first invocation of ccid_slot_status, card reader may
   * return CCID_DRIVER_ERR_CARD_INACTIVE and handle->powered_off may
   * become 1.  Because inactive card is no problem (we are turning it
   * ON here), clear the flag.
   */
  handle->powered_off = 0;

  /* For an inactive and also for an active card, issue the PowerOn
     command to get the ATR.  */
 again:
  msg[0] = PC_to_RDR_IccPowerOn;
  msg[5] = 0; /* slot */
  msg[6] = seqno = handle->seqno++;
  /* power select (0=auto, 1=5V, 2=3V, 3=1.8V) */
  msg[7] = handle->auto_voltage ? 0 : 1;
  msg[8] = 0; /* RFU */
  msg[9] = 0; /* RFU */
  set_msg_len (msg, 0);
  msglen = 10;

  rc = bulk_out (handle, msg, msglen, 0);
  if (rc)
    return rc;
  rc = bulk_in (handle, msg, sizeof msg, &msglen, RDR_to_PC_DataBlock,
                seqno, 5000, 0);
  if (rc)
    return rc;
  if (!tried_iso && CCID_COMMAND_FAILED (msg) && CCID_ERROR_CODE (msg) == 0xbb
      && ((handle->id_vendor == VENDOR_CHERRY
           && handle->id_product == 0x0005)
          || (handle->id_vendor == VENDOR_GEMPC
              && handle->id_product == 0x4433)
          ))
    {
      tried_iso = 1;
      /* Try switching to ISO mode. */
      if (!send_escape_cmd (handle, (const unsigned char*)"\xF1\x01", 2,
                            NULL, 0, NULL))
        goto again;
    }
  else if (statusbits == 0 && CCID_COMMAND_FAILED (msg))
    {
      /* Card was active already, and something went wrong with
         PC_to_RDR_IccPowerOn command.  It may be baud-rate mismatch
         between the card and the reader.  To recover from this state,
         send PC_to_RDR_IccPowerOff command to reset the card and try
         again.
       */
      rc = send_power_off (handle);
      if (rc)
        return rc;

      statusbits = 1;
      goto again;
    }
  else if (CCID_COMMAND_FAILED (msg))
    return CCID_DRIVER_ERR_CARD_IO_ERROR;


  handle->powered_off = 0;

  if (atr)
    {
      size_t n = msglen - 10;

      if (n > maxatrlen)
        n = maxatrlen;
      memcpy (atr, msg+10, n);
      *atrlen = n;
    }

  param[6] = handle->nonnull_nad? ((1 << 4) | 0): 0;
  rc = update_param_by_atr (param, msg+10, msglen - 10);
  if (rc < 0)
    {
      DEBUGOUT_1 ("update_param_by_atr failed: %d\n", rc);
      return CCID_DRIVER_ERR_CARD_IO_ERROR;
    }

  got_param = 0;

  if (handle->auto_param)
    {
      msg[0] = PC_to_RDR_GetParameters;
      msg[5] = 0; /* slot */
      msg[6] = seqno = handle->seqno++;
      msg[7] = 0; /* RFU */
      msg[8] = 0; /* RFU */
      msg[9] = 0; /* RFU */
      set_msg_len (msg, 0);
      msglen = 10;
      rc = bulk_out (handle, msg, msglen, 0);
      if (!rc)
        rc = bulk_in (handle, msg, sizeof msg, &msglen, RDR_to_PC_Parameters,
                      seqno, 2000, 0);
      if (rc)
        DEBUGOUT ("GetParameters failed\n");
      else if (msglen == 17 && msg[9] == 1)
        got_param = 1;
    }
  else if (handle->auto_pps)
    ;
  else if (rc == 1)             /* It's negotiable, send PPS.  */
    {
      msg[0] = PC_to_RDR_XfrBlock;
      msg[5] = 0; /* slot */
      msg[6] = seqno = handle->seqno++;
      msg[7] = 0;
      msg[8] = 0;
      msg[9] = 0;
      msg[10] = 0xff;           /* PPSS */
      msg[11] = 0x11;           /* PPS0: PPS1, Protocol T=1 */
      msg[12] = param[0];       /* PPS1: Fi / Di */
      msg[13] = 0xff ^ 0x11 ^ param[0]; /* PCK */
      set_msg_len (msg, 4);
      msglen = 10 + 4;

      rc = bulk_out (handle, msg, msglen, 0);
      if (rc)
        return rc;

      rc = bulk_in (handle, msg, sizeof msg, &msglen, RDR_to_PC_DataBlock,
                    seqno, 5000, 0);
      if (rc)
        return rc;

      if (msglen != 10 + 4)
        {
          DEBUGOUT_1 ("Setting PPS failed: %zu\n", msglen);
          return CCID_DRIVER_ERR_CARD_IO_ERROR;
        }

      if (msg[10] != 0xff || msg[11] != 0x11 || msg[12] != param[0])
        {
          DEBUGOUT_1 ("Setting PPS failed: 0x%02x\n", param[0]);
          return CCID_DRIVER_ERR_CARD_IO_ERROR;
        }
    }

  /* Setup parameters to select T=1. */
  msg[0] = PC_to_RDR_SetParameters;
  msg[5] = 0; /* slot */
  msg[6] = seqno = handle->seqno++;
  msg[7] = 1; /* Select T=1. */
  msg[8] = 0; /* RFU */
  msg[9] = 0; /* RFU */

  if (!got_param)
    memcpy (&msg[10], param, 7);
  set_msg_len (msg, 7);
  msglen = 10 + 7;

  rc = bulk_out (handle, msg, msglen, 0);
  if (rc)
    return rc;
  rc = bulk_in (handle, msg, sizeof msg, &msglen, RDR_to_PC_Parameters,
                seqno, 5000, 0);
  if (rc)
    DEBUGOUT ("SetParameters failed (ignored)\n");

  if (!rc && msglen > 15 && msg[15] >= 16 && msg[15] <= 254 )
    handle->ifsc = msg[15];
  else
    handle->ifsc = 128; /* Something went wrong, assume 128 bytes.  */

  if (handle->nonnull_nad && msglen > 16 && msg[16] == 0)
    {
      DEBUGOUT ("Use Null-NAD, clearing handle->nonnull_nad.\n");
      handle->nonnull_nad = 0;
    }

  handle->t1_ns = 0;
  handle->t1_nr = 0;

  /* Send an S-Block with our maximum IFSD to the CCID.  */
  if (!handle->apdu_level && !handle->auto_ifsd)
    {
      tpdu = msg+10;
      /* NAD: DAD=1, SAD=0 */
      tpdu[0] = handle->nonnull_nad? ((1 << 4) | 0): 0;
      tpdu[1] = (0xc0 | 0 | 1); /* S-block request: change IFSD */
      tpdu[2] = 1;
      tpdu[3] = handle->max_ifsd? handle->max_ifsd : 32;
      tpdulen = 4;
      edc = compute_edc (tpdu, tpdulen, use_crc);
      if (use_crc)
        tpdu[tpdulen++] = (edc >> 8);
      tpdu[tpdulen++] = edc;

      msg[0] = PC_to_RDR_XfrBlock;
      msg[5] = 0; /* slot */
      msg[6] = seqno = handle->seqno++;
      msg[7] = 0;
      msg[8] = 0; /* RFU */
      msg[9] = 0; /* RFU */
      set_msg_len (msg, tpdulen);
      msglen = 10 + tpdulen;

      if (debug_level > 1)
        DEBUGOUT_3 ("T=1: put %c-block seq=%d%s\n",
                      ((msg[11] & 0xc0) == 0x80)? 'R' :
                                (msg[11] & 0x80)? 'S' : 'I',
                      ((msg[11] & 0x80)? !!(msg[11]& 0x10)
                                       : !!(msg[11] & 0x40)),
                    (!(msg[11] & 0x80) && (msg[11] & 0x20)? " [more]":""));

      rc = bulk_out (handle, msg, msglen, 0);
      if (rc)
        return rc;


      rc = bulk_in (handle, msg, sizeof msg, &msglen,
                    RDR_to_PC_DataBlock, seqno, 5000, 0);
      if (rc)
        return rc;

      tpdu = msg + 10;
      tpdulen = msglen - 10;

      if (tpdulen < 4)
        return CCID_DRIVER_ERR_ABORTED;

      if (debug_level > 1)
        DEBUGOUT_4 ("T=1: got %c-block seq=%d err=%d%s\n",
                    ((msg[11] & 0xc0) == 0x80)? 'R' :
                              (msg[11] & 0x80)? 'S' : 'I',
                    ((msg[11] & 0x80)? !!(msg[11]& 0x10)
                                     : !!(msg[11] & 0x40)),
                    ((msg[11] & 0xc0) == 0x80)? (msg[11] & 0x0f) : 0,
                    (!(msg[11] & 0x80) && (msg[11] & 0x20)? " [more]":""));

      if ((tpdu[1] & 0xe0) != 0xe0 || tpdu[2] != 1)
        {
          DEBUGOUT ("invalid response for S-block (Change-IFSD)\n");
          return -1;
        }
      DEBUGOUT_1 ("IFSD has been set to %d\n", tpdu[3]);
    }

  ccid_vendor_specific_setup (handle);
  return 0;
}




static unsigned int
compute_edc (const unsigned char *data, size_t datalen, int use_crc)
{
  if (use_crc)
    {
      return 0x42; /* Not yet implemented. */
    }
  else
    {
      unsigned char crc = 0;

      for (; datalen; datalen--)
        crc ^= *data++;
      return crc;
    }
}


/* Return true if APDU is an extended length one.  */
static int
is_exlen_apdu (const unsigned char *apdu, size_t apdulen)
{
  if (apdulen < 7 || apdu[4])
    return 0;  /* Too short or no Z byte.  */
  return 1;
}


/* Helper for ccid_transceive used for APDU level exchanges.  */
static int
ccid_transceive_apdu_level (ccid_driver_t handle,
                            const unsigned char *apdu_buf, size_t apdu_len,
                            unsigned char *resp, size_t maxresplen,
                            size_t *nresp)
{
  int rc;
  unsigned char msg[CCID_MAX_BUF];
  const unsigned char *apdu_p;
  size_t apdu_part_len;
  size_t msglen;
  unsigned char seqno;
  int bwi = 0;
  unsigned char chain = 0;

  if (apdu_len == 0 || apdu_len > sizeof (msg) - 10)
    return CCID_DRIVER_ERR_INV_VALUE; /* Invalid length. */

  apdu_p = apdu_buf;
  while (1)
    {
      apdu_part_len = apdu_len;
      if (apdu_part_len > handle->max_ccid_msglen - 10)
        {
          apdu_part_len = handle->max_ccid_msglen - 10;
          chain |= 0x01;
        }

      msg[0] = PC_to_RDR_XfrBlock;
      msg[5] = 0; /* slot */
      msg[6] = seqno = handle->seqno++;
      msg[7] = bwi;
      msg[8] = chain;
      msg[9] = 0;
      memcpy (msg+10, apdu_p, apdu_part_len);
      set_msg_len (msg, apdu_part_len);
      msglen = 10 + apdu_part_len;

      rc = bulk_out (handle, msg, msglen, 0);
      if (rc)
        return rc;

      apdu_p += apdu_part_len;
      apdu_len -= apdu_part_len;

      rc = bulk_in (handle, msg, sizeof msg, &msglen,
                    RDR_to_PC_DataBlock, seqno, CCID_CMD_TIMEOUT, 0);
      if (rc)
        return rc;

      if (!(chain & 0x01))
        break;

      chain = 0x02;
    }

  apdu_len = 0;
  while (1)
    {
      apdu_part_len = msglen - 10;
      if (resp && apdu_len + apdu_part_len <= maxresplen)
        memcpy (resp + apdu_len, msg+10, apdu_part_len);
      apdu_len += apdu_part_len;

      if (!(msg[9] & 0x01))
        break;

      msg[0] = PC_to_RDR_XfrBlock;
      msg[5] = 0; /* slot */
      msg[6] = seqno = handle->seqno++;
      msg[7] = bwi;
      msg[8] = 0x10;                /* Request next data block */
      msg[9] = 0;
      set_msg_len (msg, 0);
      msglen = 10;

      rc = bulk_out (handle, msg, msglen, 0);
      if (rc)
        return rc;

      rc = bulk_in (handle, msg, sizeof msg, &msglen,
                    RDR_to_PC_DataBlock, seqno, CCID_CMD_TIMEOUT, 0);
      if (rc)
        return rc;
    }

  if (resp)
    {
      if (apdu_len > maxresplen)
        {
          DEBUGOUT_2 ("provided buffer too short for received data "
                      "(%u/%u)\n",
                      (unsigned int)apdu_len, (unsigned int)maxresplen);
          return CCID_DRIVER_ERR_INV_VALUE;
        }

      *nresp = apdu_len;
    }

  return 0;
}



/*
  Protocol T=1 overview

  Block Structure:
           Prologue Field:
   1 byte     Node Address (NAD)
   1 byte     Protocol Control Byte (PCB)
   1 byte     Length (LEN)
           Information Field:
   0-254 byte APDU or Control Information (INF)
           Epilogue Field:
   1 byte     Error Detection Code (EDC)

  NAD:
   bit 7     unused
   bit 4..6  Destination Node Address (DAD)
   bit 3     unused
   bit 2..0  Source Node Address (SAD)

   If node adresses are not used, SAD and DAD should be set to 0 on
   the first block sent to the card.  If they are used they should
   have different values (0 for one is okay); that first block sets up
   the addresses of the nodes.

  PCB:
   Information Block (I-Block):
      bit 7    0
      bit 6    Sequence number (yep, that is modulo 2)
      bit 5    Chaining flag
      bit 4..0 reserved
   Received-Ready Block (R-Block):
      bit 7    1
      bit 6    0
      bit 5    0
      bit 4    Sequence number
      bit 3..0  0 = no error
                1 = EDC or parity error
                2 = other error
                other values are reserved
   Supervisory Block (S-Block):
      bit 7    1
      bit 6    1
      bit 5    clear=request,set=response
      bit 4..0  0 = resynchronization request
                1 = information field size request
                2 = abort request
                3 = extension of BWT request
                4 = VPP error
                other values are reserved

*/

int
ccid_transceive (ccid_driver_t handle,
                 const unsigned char *apdu_buf, size_t apdu_buflen,
                 unsigned char *resp, size_t maxresplen, size_t *nresp)
{
  int rc;
  /* The size of the buffer used to be 10+259.  For the via_escape
     hack we need one extra byte, thus 11+259.  */
  unsigned char send_buffer[11+259], recv_buffer[11+259];
  const unsigned char *apdu;
  size_t apdulen;
  unsigned char *msg, *tpdu, *p;
  size_t msglen, tpdulen, last_tpdulen, n;
  unsigned char seqno;
  unsigned int edc;
  int use_crc = 0;
  int hdrlen, pcboff;
  size_t dummy_nresp;
  int via_escape = 0;
  int next_chunk = 1;
  int sending = 1;
  int retries = 0;
  int resyncing = 0;
  int nad_byte;
  int wait_more = 0;

  if (!nresp)
    nresp = &dummy_nresp;
  *nresp = 0;

  /* Smarter readers allow sending APDUs directly; divert here. */
  if (handle->apdu_level)
    {
      /* We employ a hack for Omnikey readers which are able to send
         TPDUs using an escape sequence.  There is no documentation
         but the Windows driver does it this way.  Tested using a
         CM6121.  This method works also for the Cherry XX44
         keyboards; however there are problems with the
         ccid_transceive_secure which leads to a loss of sync on the
         CCID level.  If Cherry wants to make their keyboard work
         again, they should hand over some docs. */
      if ((handle->id_vendor == VENDOR_OMNIKEY)
          && handle->apdu_level < 2
          && is_exlen_apdu (apdu_buf, apdu_buflen))
        via_escape = 1;
      else
        return ccid_transceive_apdu_level (handle, apdu_buf, apdu_buflen,
                                           resp, maxresplen, nresp);
    }

  /* The other readers we support require sending TPDUs.  */

  tpdulen = 0; /* Avoid compiler warning about no initialization. */
  msg = send_buffer;
  hdrlen = via_escape? 11 : 10;

  /* NAD: DAD=1, SAD=0 */
  nad_byte = handle->nonnull_nad? ((1 << 4) | 0): 0;
  if (via_escape)
    nad_byte = 0;

  last_tpdulen = 0;  /* Avoid gcc warning (controlled by RESYNCING). */
  for (;;)
    {
      if (next_chunk)
        {
          next_chunk = 0;

          apdu = apdu_buf;
          apdulen = apdu_buflen;
          assert (apdulen);

          /* Construct an I-Block. */
          tpdu = msg + hdrlen;
          tpdu[0] = nad_byte;
          tpdu[1] = ((handle->t1_ns & 1) << 6); /* I-block */
          if (apdulen > handle->ifsc )
            {
              apdulen = handle->ifsc;
              apdu_buf += handle->ifsc;
              apdu_buflen -= handle->ifsc;
              tpdu[1] |= (1 << 5); /* Set more bit. */
            }
          tpdu[2] = apdulen;
          memcpy (tpdu+3, apdu, apdulen);
          tpdulen = 3 + apdulen;
          edc = compute_edc (tpdu, tpdulen, use_crc);
          if (use_crc)
            tpdu[tpdulen++] = (edc >> 8);
          tpdu[tpdulen++] = edc;
        }

      if (via_escape)
        {
          msg[0] = PC_to_RDR_Escape;
          msg[5] = 0; /* slot */
          msg[6] = seqno = handle->seqno++;
          msg[7] = 0; /* RFU */
          msg[8] = 0; /* RFU */
          msg[9] = 0; /* RFU */
          msg[10] = 0x1a; /* Omnikey command to send a TPDU.  */
          set_msg_len (msg, 1 + tpdulen);
        }
      else
        {
          msg[0] = PC_to_RDR_XfrBlock;
          msg[5] = 0; /* slot */
          msg[6] = seqno = handle->seqno++;
          msg[7] = (wait_more ? wait_more : 1); /* bBWI */
          msg[8] = 0; /* RFU */
          msg[9] = 0; /* RFU */
          set_msg_len (msg, tpdulen);
        }
      msglen = hdrlen + tpdulen;
      if (!resyncing)
        last_tpdulen = tpdulen;
      pcboff = hdrlen+1;

      if (debug_level > 1)
        DEBUGOUT_3 ("T=1: put %c-block seq=%d%s\n",
                    ((msg[pcboff] & 0xc0) == 0x80)? 'R' :
                    (msg[pcboff] & 0x80)? 'S' : 'I',
                    ((msg[pcboff] & 0x80)? !!(msg[pcboff]& 0x10)
                     : !!(msg[pcboff] & 0x40)),
                    (!(msg[pcboff] & 0x80) && (msg[pcboff] & 0x20)?
                     " [more]":""));

      rc = bulk_out (handle, msg, msglen, 0);
      if (rc)
        return rc;

      msg = recv_buffer;
      rc = bulk_in (handle, msg, sizeof recv_buffer, &msglen,
                    via_escape? RDR_to_PC_Escape : RDR_to_PC_DataBlock, seqno,
                    (wait_more ? wait_more : 1) * CCID_CMD_TIMEOUT, 0);
      if (rc)
        return rc;

      tpdu = msg + hdrlen;
      tpdulen = msglen - hdrlen;
      resyncing = 0;

      if (tpdulen < 4)
        {
#ifdef USE_NPTH
          npth_unprotect ();
#endif
          libusb_clear_halt (handle->idev, handle->ep_bulk_in);
#ifdef USE_NPTH
          npth_protect ();
#endif
          return CCID_DRIVER_ERR_ABORTED;
        }

      if (debug_level > 1)
        DEBUGOUT_4 ("T=1: got %c-block seq=%d err=%d%s\n",
                    ((msg[pcboff] & 0xc0) == 0x80)? 'R' :
                              (msg[pcboff] & 0x80)? 'S' : 'I',
                    ((msg[pcboff] & 0x80)? !!(msg[pcboff]& 0x10)
                     : !!(msg[pcboff] & 0x40)),
                    ((msg[pcboff] & 0xc0) == 0x80)? (msg[pcboff] & 0x0f) : 0,
                    (!(msg[pcboff] & 0x80) && (msg[pcboff] & 0x20)?
                     " [more]":""));

      wait_more = 0;
      if (!(tpdu[1] & 0x80))
        { /* This is an I-block. */
          retries = 0;
          if (sending)
            { /* last block sent was successful. */
              handle->t1_ns ^= 1;
              sending = 0;
            }

          if (!!(tpdu[1] & 0x40) != handle->t1_nr)
            { /* Response does not match our sequence number. */
              msg = send_buffer;
              tpdu = msg + hdrlen;
              tpdu[0] = nad_byte;
              tpdu[1] = (0x80 | (handle->t1_nr & 1) << 4 | 2); /* R-block */
              tpdu[2] = 0;
              tpdulen = 3;
              edc = compute_edc (tpdu, tpdulen, use_crc);
              if (use_crc)
                tpdu[tpdulen++] = (edc >> 8);
              tpdu[tpdulen++] = edc;

              continue;
            }

          handle->t1_nr ^= 1;

          p = tpdu + 3; /* Skip the prologue field. */
          n = tpdulen - 3 - 1; /* Strip the epilogue field. */
          /* fixme: verify the checksum. */
          if (resp)
            {
              if (n > maxresplen)
                {
                  DEBUGOUT_2 ("provided buffer too short for received data "
                              "(%u/%u)\n",
                              (unsigned int)n, (unsigned int)maxresplen);
                  return CCID_DRIVER_ERR_INV_VALUE;
                }

              memcpy (resp, p, n);
              resp += n;
              *nresp += n;
              maxresplen -= n;
            }

          if (!(tpdu[1] & 0x20))
            return 0; /* No chaining requested - ready. */

          msg = send_buffer;
          tpdu = msg + hdrlen;
          tpdu[0] = nad_byte;
          tpdu[1] = (0x80 | (handle->t1_nr & 1) << 4); /* R-block */
          tpdu[2] = 0;
          tpdulen = 3;
          edc = compute_edc (tpdu, tpdulen, use_crc);
          if (use_crc)
            tpdu[tpdulen++] = (edc >> 8);
          tpdu[tpdulen++] = edc;
        }
      else if ((tpdu[1] & 0xc0) == 0x80)
        { /* This is a R-block. */
          if ( (tpdu[1] & 0x0f))
            {
              retries++;
              if (via_escape && retries == 1 && (msg[pcboff] & 0x0f))
                {
                  /* Error probably due to switching to TPDU.  Send a
                     resync request.  We use the recv_buffer so that
                     we don't corrupt the send_buffer.  */
                  msg = recv_buffer;
                  tpdu = msg + hdrlen;
                  tpdu[0] = nad_byte;
                  tpdu[1] = 0xc0; /* S-block resync request. */
                  tpdu[2] = 0;
                  tpdulen = 3;
                  edc = compute_edc (tpdu, tpdulen, use_crc);
                  if (use_crc)
                    tpdu[tpdulen++] = (edc >> 8);
                  tpdu[tpdulen++] = edc;
                  resyncing = 1;
                  DEBUGOUT ("T=1: requesting resync\n");
                }
              else if (retries > 3)
                {
                  DEBUGOUT ("T=1: 3 failed retries\n");
                  return CCID_DRIVER_ERR_CARD_IO_ERROR;
                }
              else
                {
                  /* Error: repeat last block */
                  msg = send_buffer;
                  tpdulen = last_tpdulen;
                }
            }
          else if (sending && !!(tpdu[1] & 0x10) == handle->t1_ns)
            { /* Response does not match our sequence number. */
              DEBUGOUT ("R-block with wrong seqno received on more bit\n");
              return CCID_DRIVER_ERR_CARD_IO_ERROR;
            }
          else if (sending)
            { /* Send next chunk. */
              retries = 0;
              msg = send_buffer;
              next_chunk = 1;
              handle->t1_ns ^= 1;
            }
          else
            {
              DEBUGOUT ("unexpected ACK R-block received\n");
              return CCID_DRIVER_ERR_CARD_IO_ERROR;
            }
        }
      else
        { /* This is a S-block. */
          retries = 0;
          DEBUGOUT_2 ("T=1: S-block %s received cmd=%d\n",
                      (tpdu[1] & 0x20)? "response": "request",
                      (tpdu[1] & 0x1f));
          if ( !(tpdu[1] & 0x20) && (tpdu[1] & 0x1f) == 1 && tpdu[2] == 1)
            {
              /* Information field size request.  */
              unsigned char ifsc = tpdu[3];

              if (ifsc < 16 || ifsc > 254)
                return CCID_DRIVER_ERR_CARD_IO_ERROR;

              msg = send_buffer;
              tpdu = msg + hdrlen;
              tpdu[0] = nad_byte;
              tpdu[1] = (0xc0 | 0x20 | 1); /* S-block response */
              tpdu[2] = 1;
              tpdu[3] = ifsc;
              tpdulen = 4;
              edc = compute_edc (tpdu, tpdulen, use_crc);
              if (use_crc)
                tpdu[tpdulen++] = (edc >> 8);
              tpdu[tpdulen++] = edc;
              DEBUGOUT_1 ("T=1: requesting an ifsc=%d\n", ifsc);
            }
          else if ( !(tpdu[1] & 0x20) && (tpdu[1] & 0x1f) == 3 && tpdu[2])
            {
              /* Wait time extension request. */
              unsigned char bwi = tpdu[3];

	      wait_more = bwi;

              msg = send_buffer;
              tpdu = msg + hdrlen;
              tpdu[0] = nad_byte;
              tpdu[1] = (0xc0 | 0x20 | 3); /* S-block response */
              tpdu[2] = 1;
              tpdu[3] = bwi;
              tpdulen = 4;
              edc = compute_edc (tpdu, tpdulen, use_crc);
              if (use_crc)
                tpdu[tpdulen++] = (edc >> 8);
              tpdu[tpdulen++] = edc;
              DEBUGOUT_1 ("T=1: waittime extension of bwi=%d\n", bwi);
              print_progress (handle);
            }
          else if ( (tpdu[1] & 0x20) && (tpdu[1] & 0x1f) == 0 && !tpdu[2])
            {
              DEBUGOUT ("T=1: resync ack from reader\n");
              /* Repeat previous block.  */
              msg = send_buffer;
              tpdulen = last_tpdulen;
            }
          else
            return CCID_DRIVER_ERR_CARD_IO_ERROR;
        }
    } /* end T=1 protocol loop. */

  return 0;
}


/* Send the CCID Secure command to the reader.  APDU_BUF should
   contain the APDU template.  PIN_MODE defines how the pin gets
   formatted:

     1 := The PIN is ASCII encoded and of variable length.  The
          length of the PIN entered will be put into Lc by the reader.
          The APDU should me made up of 4 bytes without Lc.

   PINLEN_MIN and PINLEN_MAX define the limits for the pin length. 0
   may be used t enable reasonable defaults.

   When called with RESP and NRESP set to NULL, the function will
   merely check whether the reader supports the secure command for the
   given APDU and PIN_MODE. */
int
ccid_transceive_secure (ccid_driver_t handle,
                        const unsigned char *apdu_buf, size_t apdu_buflen,
                        pininfo_t *pininfo,
                        unsigned char *resp, size_t maxresplen, size_t *nresp)
{
  int rc;
  unsigned char send_buffer[10+259], recv_buffer[10+259];
  unsigned char *msg, *tpdu, *p;
  size_t msglen, tpdulen, n;
  unsigned char seqno;
  size_t dummy_nresp;
  int testmode;
  int cherry_mode = 0;
  int add_zero = 0;
  int enable_varlen = 0;

  testmode = !resp && !nresp;

  if (!nresp)
    nresp = &dummy_nresp;
  *nresp = 0;

  if (apdu_buflen >= 4 && apdu_buf[1] == 0x20 && (handle->has_pinpad & 1))
    ;
  else if (apdu_buflen >= 4 && apdu_buf[1] == 0x24 && (handle->has_pinpad & 2))
    ;
  else
    return CCID_DRIVER_ERR_NO_PINPAD;

  if (!pininfo->minlen)
    pininfo->minlen = 1;
  if (!pininfo->maxlen)
    pininfo->maxlen = 15;

  /* Note that the 25 is the maximum value the SPR532 allows.  */
  if (pininfo->minlen < 1 || pininfo->minlen > 25
      || pininfo->maxlen < 1 || pininfo->maxlen > 25
      || pininfo->minlen > pininfo->maxlen)
    return CCID_DRIVER_ERR_INV_VALUE;

  /* We have only tested a few readers so better don't risk anything
     and do not allow the use with other readers. */
  switch (handle->id_vendor)
    {
    case VENDOR_SCM:  /* Tested with SPR 532. */
    case VENDOR_KAAN: /* Tested with KAAN Advanced (1.02). */
    case VENDOR_FSIJ: /* Tested with Gnuk (0.21). */
      pininfo->maxlen = 25;
      enable_varlen = 1;
      break;
    case VENDOR_REINER:/* Tested with cyberJack go */
    case VENDOR_VASCO: /* Tested with DIGIPASS 920 */
      enable_varlen = 1;
      break;
    case VENDOR_CHERRY:
      pininfo->maxlen = 15;
      enable_varlen = 1;
      /* The CHERRY XX44 keyboard echos an asterisk for each entered
         character on the keyboard channel.  We use a special variant
         of PC_to_RDR_Secure which directs these characters to the
         smart card's bulk-in channel.  We also need to append a zero
         Lc byte to the APDU.  It seems that it will be replaced with
         the actual length instead of being appended before the APDU
         is send to the card. */
      add_zero = 1;
      if (handle->id_product != CHERRY_ST2000)
        cherry_mode = 1;
      break;
    case VENDOR_NXP:
      if (handle->id_product == CRYPTOUCAN){
        pininfo->maxlen = 25;
        enable_varlen = 1;
        break;
      }
      return CCID_DRIVER_ERR_NOT_SUPPORTED;
    case VENDOR_GEMPC:
      if (handle->id_product == GEMPC_PINPAD)
        {
          enable_varlen = 0;
          pininfo->minlen = 4;
          pininfo->maxlen = 8;
          break;
        }
      else if (handle->id_product == GEMPC_EZIO)
        {
          pininfo->maxlen = 25;
          enable_varlen = 1;
          break;
        }
      return CCID_DRIVER_ERR_NOT_SUPPORTED;
    default:
      if ((handle->id_vendor == VENDOR_VEGA &&
           handle->id_product == VEGA_ALPHA))
        {
          enable_varlen = 0;
          pininfo->minlen = 4;
          pininfo->maxlen = 8;
          break;
        }
     return CCID_DRIVER_ERR_NOT_SUPPORTED;
    }

  if (enable_varlen)
    pininfo->fixedlen = 0;

  if (testmode)
    return 0; /* Success */

  if (pininfo->fixedlen < 0 || pininfo->fixedlen >= 16)
    return CCID_DRIVER_ERR_NOT_SUPPORTED;

  msg = send_buffer;
  msg[0] = cherry_mode? 0x89 : PC_to_RDR_Secure;
  msg[5] = 0; /* slot */
  msg[6] = seqno = handle->seqno++;
  msg[7] = 0; /* bBWI */
  msg[8] = 0; /* RFU */
  msg[9] = 0; /* RFU */
  msg[10] = apdu_buf[1] == 0x20 ? 0 : 1;
               /* Perform PIN verification or PIN modification. */
  msg[11] = 0; /* Timeout in seconds. */
  msg[12] = 0x82; /* bmFormatString: Byte, pos=0, left, ASCII. */
  if (handle->id_vendor == VENDOR_SCM)
    {
      /* For the SPR532 the next 2 bytes need to be zero.  We do this
         for all SCM products.  Kudos to Martin Paljak for this
         hint.  */
      msg[13] = msg[14] = 0;
    }
  else
    {
      msg[13] = pininfo->fixedlen; /* bmPINBlockString:
                                      0 bits of pin length to insert.
                                      PIN block size by fixedlen.  */
      msg[14] = 0x00; /* bmPINLengthFormat:
                         Units are bytes, position is 0. */
    }

  msglen = 15;
  if (apdu_buf[1] == 0x24)
    {
      msg[msglen++] = 0;    /* bInsertionOffsetOld */
      msg[msglen++] = pininfo->fixedlen;    /* bInsertionOffsetNew */
    }

  /* The following is a little endian word. */
  msg[msglen++] = pininfo->maxlen;   /* wPINMaxExtraDigit-Maximum.  */
  msg[msglen++] = pininfo->minlen;   /* wPINMaxExtraDigit-Minimum.  */

  if (apdu_buf[1] == 0x24)
    msg[msglen++] = apdu_buf[2] == 0 ? 0x03 : 0x01;
              /* bConfirmPIN
               *    0x00: new PIN once
               *    0x01: new PIN twice (confirmation)
               *    0x02: old PIN and new PIN once
               *    0x03: old PIN and new PIN twice (confirmation)
               */

  msg[msglen] = 0x02; /* bEntryValidationCondition:
                         Validation key pressed */
  if (pininfo->minlen && pininfo->maxlen && pininfo->minlen == pininfo->maxlen)
    msg[msglen] |= 0x01; /* Max size reached.  */
  msglen++;

  if (apdu_buf[1] == 0x20)
    msg[msglen++] = 0x01; /* bNumberMessage. */
  else
    msg[msglen++] = 0x03; /* bNumberMessage. */

  msg[msglen++] = 0x09; /* wLangId-Low:  English FIXME: use the first entry. */
  msg[msglen++] = 0x04; /* wLangId-High. */

  if (apdu_buf[1] == 0x20)
    msg[msglen++] = 0;    /* bMsgIndex. */
  else
    {
      msg[msglen++] = 0;    /* bMsgIndex1. */
      msg[msglen++] = 1;    /* bMsgIndex2. */
      msg[msglen++] = 2;    /* bMsgIndex3. */
    }

  /* Calculate Lc.  */
  n = pininfo->fixedlen;
  if (apdu_buf[1] == 0x24)
    n += pininfo->fixedlen;

  /* bTeoProlog follows: */
  msg[msglen++] = handle->nonnull_nad? ((1 << 4) | 0): 0;
  msg[msglen++] = ((handle->t1_ns & 1) << 6); /* I-block */
  if (n)
    msg[msglen++] = n + 5; /* apdulen should be filled for fixed length.  */
  else
    msg[msglen++] = 0; /* The apdulen will be filled in by the reader.  */
  /* APDU follows:  */
  msg[msglen++] = apdu_buf[0]; /* CLA */
  msg[msglen++] = apdu_buf[1]; /* INS */
  msg[msglen++] = apdu_buf[2]; /* P1 */
  msg[msglen++] = apdu_buf[3]; /* P2 */
  if (add_zero)
    msg[msglen++] = 0;
  else if (pininfo->fixedlen != 0)
    {
      msg[msglen++] = n;
      memset (&msg[msglen], 0xff, n);
      msglen += n;
    }
  /* An EDC is not required. */
  set_msg_len (msg, msglen - 10);

  rc = bulk_out (handle, msg, msglen, 0);
  if (rc)
    return rc;

  msg = recv_buffer;
  rc = bulk_in (handle, msg, sizeof recv_buffer, &msglen,
                RDR_to_PC_DataBlock, seqno, 30000, 0);
  if (rc)
    return rc;

  tpdu = msg + 10;
  tpdulen = msglen - 10;

  if (handle->apdu_level)
    {
      if (resp)
        {
          if (tpdulen > maxresplen)
            {
              DEBUGOUT_2 ("provided buffer too short for received data "
                          "(%u/%u)\n",
                          (unsigned int)tpdulen, (unsigned int)maxresplen);
              return CCID_DRIVER_ERR_INV_VALUE;
            }

          memcpy (resp, tpdu, tpdulen);
          *nresp = tpdulen;
        }
      return 0;
    }

  if (tpdulen < 4)
    {
#ifdef USE_NPTH
      npth_unprotect ();
#endif
      libusb_clear_halt (handle->idev, handle->ep_bulk_in);
#ifdef USE_NPTH
      npth_protect ();
#endif
      return CCID_DRIVER_ERR_ABORTED;
    }
  if (debug_level > 1)
    DEBUGOUT_4 ("T=1: got %c-block seq=%d err=%d%s\n",
                ((msg[11] & 0xc0) == 0x80)? 'R' :
                          (msg[11] & 0x80)? 'S' : 'I',
                ((msg[11] & 0x80)? !!(msg[11]& 0x10) : !!(msg[11] & 0x40)),
                ((msg[11] & 0xc0) == 0x80)? (msg[11] & 0x0f) : 0,
                (!(msg[11] & 0x80) && (msg[11] & 0x20)? " [more]":""));

  if (!(tpdu[1] & 0x80))
    { /* This is an I-block. */
      /* Last block sent was successful. */
      handle->t1_ns ^= 1;

      if (!!(tpdu[1] & 0x40) != handle->t1_nr)
        { /* Response does not match our sequence number. */
          DEBUGOUT ("I-block with wrong seqno received\n");
          return CCID_DRIVER_ERR_CARD_IO_ERROR;
        }

      handle->t1_nr ^= 1;

      p = tpdu + 3; /* Skip the prologue field. */
      n = tpdulen - 3 - 1; /* Strip the epilogue field. */
      /* fixme: verify the checksum. */
      if (resp)
        {
          if (n > maxresplen)
            {
              DEBUGOUT_2 ("provided buffer too short for received data "
                          "(%u/%u)\n",
                          (unsigned int)n, (unsigned int)maxresplen);
              return CCID_DRIVER_ERR_INV_VALUE;
            }

          memcpy (resp, p, n);
          *nresp += n;
        }

      if (!(tpdu[1] & 0x20))
        return 0; /* No chaining requested - ready. */

      DEBUGOUT ("chaining requested but not supported for Secure operation\n");
      return CCID_DRIVER_ERR_CARD_IO_ERROR;
    }
  else if ((tpdu[1] & 0xc0) == 0x80)
    { /* This is a R-block. */
      if ( (tpdu[1] & 0x0f))
        { /* Error: repeat last block */
          DEBUGOUT ("No retries supported for Secure operation\n");
          return CCID_DRIVER_ERR_CARD_IO_ERROR;
        }
      else if (!!(tpdu[1] & 0x10) == handle->t1_ns)
        { /* Response does not match our sequence number. */
          DEBUGOUT ("R-block with wrong seqno received on more bit\n");
          return CCID_DRIVER_ERR_CARD_IO_ERROR;
        }
      else
        { /* Send next chunk. */
          DEBUGOUT ("chaining not supported on Secure operation\n");
          return CCID_DRIVER_ERR_CARD_IO_ERROR;
        }
    }
  else
    { /* This is a S-block. */
      DEBUGOUT_2 ("T=1: S-block %s received cmd=%d for Secure operation\n",
                  (tpdu[1] & 0x20)? "response": "request",
                  (tpdu[1] & 0x1f));
      return CCID_DRIVER_ERR_CARD_IO_ERROR;
    }

  return 0;
}




#ifdef TEST


static void
print_error (int err)
{
  const char *p;
  char buf[50];

  switch (err)
    {
    case 0: p = "success"; break;
    case CCID_DRIVER_ERR_OUT_OF_CORE: p = "out of core"; break;
    case CCID_DRIVER_ERR_INV_VALUE: p = "invalid value"; break;
    case CCID_DRIVER_ERR_NO_DRIVER: p = "no driver"; break;
    case CCID_DRIVER_ERR_NOT_SUPPORTED: p = "not supported"; break;
    case CCID_DRIVER_ERR_LOCKING_FAILED: p = "locking failed"; break;
    case CCID_DRIVER_ERR_BUSY: p = "busy"; break;
    case CCID_DRIVER_ERR_NO_CARD: p = "no card"; break;
    case CCID_DRIVER_ERR_CARD_INACTIVE: p = "card inactive"; break;
    case CCID_DRIVER_ERR_CARD_IO_ERROR: p = "card I/O error"; break;
    case CCID_DRIVER_ERR_GENERAL_ERROR: p = "general error"; break;
    case CCID_DRIVER_ERR_NO_READER: p = "no reader"; break;
    case CCID_DRIVER_ERR_ABORTED: p = "aborted"; break;
    default: sprintf (buf, "0x%05x", err); p = buf; break;
    }
  fprintf (stderr, "operation failed: %s\n", p);
}


static void
print_data (const unsigned char *data, size_t length)
{
  if (length >= 2)
    {
      fprintf (stderr, "operation status: %02X%02X\n",
               data[length-2], data[length-1]);
      length -= 2;
    }
  if (length)
    {
        fputs ("   returned data:", stderr);
        for (; length; length--, data++)
          fprintf (stderr, " %02X", *data);
        putc ('\n', stderr);
    }
}

static void
print_result (int rc, const unsigned char *data, size_t length)
{
  if (rc)
    print_error (rc);
  else if (data)
    print_data (data, length);
}

int
main (int argc, char **argv)
{
  gpg_error_t err;
  ccid_driver_t ccid;
  int slotstat;
  unsigned char result[512];
  size_t resultlen;
  int no_pinpad = 0;
  int verify_123456 = 0;
  int did_verify = 0;
  int no_poll = 0;
  int idx_max;
  struct ccid_dev_table *ccid_table;

  if (argc)
    {
      argc--;
      argv++;
    }

  while (argc)
    {
      if ( !strcmp (*argv, "--list"))
        {
          char *p;
          p = ccid_get_reader_list ();
          if (!p)
            return 1;
          fputs (p, stderr);
          free (p);
          return 0;
        }
      else if ( !strcmp (*argv, "--debug"))
        {
          ccid_set_debug_level (ccid_set_debug_level (-1)+1);
          argc--; argv++;
        }
      else if ( !strcmp (*argv, "--no-poll"))
        {
          no_poll = 1;
          argc--; argv++;
        }
      else if ( !strcmp (*argv, "--no-pinpad"))
        {
          no_pinpad = 1;
          argc--; argv++;
        }
      else if ( !strcmp (*argv, "--verify-123456"))
        {
          verify_123456 = 1;
          argc--; argv++;
        }
      else
        break;
    }

  err = ccid_dev_scan (&idx_max, &ccid_table);
  if (err)
    return 1;

  if (idx_max == 0)
    return 1;

  err = ccid_open_reader (argc? *argv:NULL, 0, ccid_table, &ccid, NULL);
  if (err)
    return 1;

  ccid_dev_scan_finish (ccid_table, idx_max);

  if (!no_poll)
    ccid_poll (ccid);
  fputs ("getting ATR ...\n", stderr);
  err = ccid_get_atr (ccid, NULL, 0, NULL);
  if (err)
    {
      print_error (err);
      return 1;
    }

  if (!no_poll)
    ccid_poll (ccid);
  fputs ("getting slot status ...\n", stderr);
  err = ccid_slot_status (ccid, &slotstat, 1);
  if (err)
    {
      print_error (err);
      return 1;
    }

  if (!no_poll)
    ccid_poll (ccid);

  fputs ("selecting application OpenPGP ....\n", stderr);
  {
    static unsigned char apdu[] = {
      0, 0xA4, 4, 0, 6, 0xD2, 0x76, 0x00, 0x01, 0x24, 0x01};
    err = ccid_transceive (ccid,
                           apdu, sizeof apdu,
                           result, sizeof result, &resultlen);
    print_result (err, result, resultlen);
  }


  if (!no_poll)
    ccid_poll (ccid);

  fputs ("getting OpenPGP DO 0x65 ....\n", stderr);
  {
    static unsigned char apdu[] = { 0, 0xCA, 0, 0x65, 254 };
    err = ccid_transceive (ccid, apdu, sizeof apdu,
                           result, sizeof result, &resultlen);
    print_result (err, result, resultlen);
  }

  if (!no_pinpad)
    {
    }

  if (!no_pinpad)
    {
      static unsigned char apdu[] = { 0, 0x20, 0, 0x81 };
      pininfo_t pininfo = { 0, 0, 0 };

      if (ccid_transceive_secure (ccid, apdu, sizeof apdu, &pininfo,
                                  NULL, 0, NULL))
        fputs ("can't verify using a PIN-Pad reader\n", stderr);
      else
        {
           fputs ("verifying CHV1 using the PINPad ....\n", stderr);

          err = ccid_transceive_secure (ccid, apdu, sizeof apdu, &pininfo,
                                        result, sizeof result, &resultlen);
          print_result (err, result, resultlen);
          did_verify = 1;
        }
    }

  if (verify_123456 && !did_verify)
    {
      fputs ("verifying that CHV1 is 123456....\n", stderr);
      {
        static unsigned char apdu[] = {0, 0x20, 0, 0x81,
                                       6, '1','2','3','4','5','6'};
        err = ccid_transceive (ccid, apdu, sizeof apdu,
                               result, sizeof result, &resultlen);
        print_result (err, result, resultlen);
      }
    }

  if (!err)
    {
      fputs ("getting OpenPGP DO 0x5E ....\n", stderr);
      {
        static unsigned char apdu[] = { 0, 0xCA, 0, 0x5E, 254 };
        err = ccid_transceive (ccid, apdu, sizeof apdu,
                               result, sizeof result, &resultlen);
        print_result (err, result, resultlen);
      }
    }

  ccid_close_reader (ccid);

  return 0;
}

/*
 * Local Variables:
 *  compile-command: "gcc -DTEST -DGPGRT_ENABLE_ES_MACROS -DHAVE_NPTH -DUSE_NPTH -Wall -I/usr/include/libusb-1.0 -I/usr/local/include -lusb-1.0 -g ccid-driver.c -lnpth -lgpg-error"
 * End:
 */
#endif /*TEST*/
#endif /*HAVE_LIBUSB*/
