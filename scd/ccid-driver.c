/* ccid-driver.c - USB ChipCardInterfaceDevices driver
 * Copyright (C) 2003, 2004, 2005, 2006, 2007
 *               2008, 2009  Free Software Foundation, Inc.
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
 * along with this program; if not, see <http://www.gnu.org/licenses/>.
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
 * THIS SOFTWARE IS PROVIDED ``AS IS'' AND ANY EXPRESS OR IMPLIED
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
 *
 * $Date$
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
#ifdef HAVE_PTH
# include <pth.h>
#endif /*HAVE_PTH*/

#include <usb.h>

#include "ccid-driver.h"

#define DRVNAME "ccid-driver: "


/* Depending on how this source is used we either define our error
   output to go to stderr or to the jnlib based logging functions.  We
   use the latter when GNUPG_MAJOR_VERSION is defines or when both,
   GNUPG_SCD_MAIN_HEADER and HAVE_JNLIB_LOGGING are defined.
*/
#if defined(GNUPG_MAJOR_VERSION) \
    || (defined(GNUPG_SCD_MAIN_HEADER) && defined(HAVE_JNLIB_LOGGING))

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


/* We need to know the vendor to do some hacks. */
enum {
  VENDOR_CHERRY = 0x046a,
  VENDOR_SCM    = 0x04e6,
  VENDOR_OMNIKEY= 0x076b,
  VENDOR_GEMPC  = 0x08e6,
  VENDOR_KAAN   = 0x0d46
};

/* A list and a table with special transport descriptions. */
enum {
  TRANSPORT_USB    = 0, /* Standard USB transport. */
  TRANSPORT_CM4040 = 1  /* As used by the Cardman 4040. */
};

static struct
{ 
  char *name;  /* Device name. */
  int  type;

} transports[] = {
  { "/dev/cmx0", TRANSPORT_CM4040 },  
  { "/dev/cmx1", TRANSPORT_CM4040 },  
  { NULL },
};


/* Store information on the driver's state.  A pointer to such a
   structure is used as handle for most functions. */
struct ccid_driver_s 
{
  usb_dev_handle *idev;
  char *rid;
  int dev_fd;  /* -1 for USB transport or file descriptor of the
                   transport device. */
  unsigned short id_vendor;
  unsigned short id_product;
  unsigned short bcd_device;
  int ifc_no;
  int ep_bulk_out;
  int ep_bulk_in;
  int ep_intr;
  int seqno;
  unsigned char t1_ns;
  unsigned char t1_nr;
  unsigned char nonnull_nad;
  int max_ifsd;
  int ifsd;
  int ifsc;
  unsigned char apdu_level:2;     /* Reader supports short APDU level
                                     exchange.  With a value of 2 short
                                     and extended level is supported.*/
  unsigned int auto_ifsd:1;
  unsigned int powered_off:1;
  unsigned int has_pinpad:2;
  unsigned int enodev_seen:1;

  time_t last_progress; /* Last time we sent progress line.  */

  /* The progress callback and its first arg as supplied to
     ccid_set_progress_cb.  */
  void (*progress_cb)(void *, const char *, int, int, int);
  void *progress_cb_arg;
};


static int initialized_usb; /* Tracks whether USB has been initialized. */
static int debug_level;     /* Flag to control the debug output. 
                               0 = No debugging
                               1 = USB I/O info
                               2 = Level 1 + T=1 protocol tracing
                               3 = Level 2 + USB/I/O tracing of SlotStatus.
                              */


static unsigned int compute_edc (const unsigned char *data, size_t datalen,
                                 int use_crc);
static int bulk_out (ccid_driver_t handle, unsigned char *msg, size_t msglen,
                     int no_debug);
static int bulk_in (ccid_driver_t handle, unsigned char *buffer, size_t length,
                    size_t *nread, int expected_type, int seqno, int timeout,
                    int no_debug);
static int abort_cmd (ccid_driver_t handle, int seqno);

/* Convert a little endian stored 4 byte value into an unsigned
   integer. */
static unsigned int 
convert_le_u32 (const unsigned char *buf)
{
  return buf[0] | (buf[1] << 8) | (buf[2] << 16) | (buf[3] << 24); 
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
my_sleep (int seconds)
{
#ifdef HAVE_PTH
  /* With Pth we also call the standard sleep(0) so that the process
     may give up its timeslot.  */
  if (!seconds)
    {
# ifdef HAVE_W32_SYSTEM    
      Sleep (0);
# else
      sleep (0);
# endif
    }
  pth_sleep (seconds);
#else
# ifdef HAVE_W32_SYSTEM    
  Sleep (seconds*1000);
# else
  sleep (seconds);
# endif
#endif
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


/* Given a handle used for special transport prepare it for use.  In
   particular setup all information in way that resembles what
   parse_cccid_descriptor does. */
static void
prepare_special_transport (ccid_driver_t handle)
{
  assert (!handle->id_vendor);

  handle->nonnull_nad = 0;
  handle->auto_ifsd = 0;
  handle->max_ifsd = 32;
  handle->ifsd = 0;
  handle->has_pinpad = 0;
  handle->apdu_level = 0;
  switch (handle->id_product)
    {
    case TRANSPORT_CM4040:
      DEBUGOUT ("setting up transport for CardMan 4040\n");
      handle->apdu_level = 1;
      break;

    default: assert (!"transport not defined");
    }
}

/* Parse a CCID descriptor, optionally print all available features
   and test whether this reader is usable by this driver.  Returns 0
   if it is usable.

   Note, that this code is based on the one in lsusb.c of the
   usb-utils package, I wrote on 2003-09-01. -wk. */
static int
parse_ccid_descriptor (ccid_driver_t handle,
                       const unsigned char *buf, size_t buflen)
{
  unsigned int i;
  unsigned int us;
  int have_t1 = 0, have_tpdu=0, have_auto_conf = 0;


  handle->nonnull_nad = 0;
  handle->auto_ifsd = 0;
  handle->max_ifsd = 32;
  handle->ifsd = 0;
  handle->has_pinpad = 0;
  handle->apdu_level = 0;
  DEBUGOUT_3 ("idVendor: %04X  idProduct: %04X  bcdDevice: %04X\n",
              handle->id_vendor, handle->id_product, handle->bcd_device);
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
      DEBUGOUT ("    Auto configuration based on ATR\n");
      have_auto_conf = 1;
    }
  if ((us & 0x0004))
    DEBUGOUT ("    Auto activation on insert\n");
  if ((us & 0x0008))
    DEBUGOUT ("    Auto voltage selection\n");
  if ((us & 0x0010))
    DEBUGOUT ("    Auto clock change\n");
  if ((us & 0x0020))
    DEBUGOUT ("    Auto baud rate change\n");
  if ((us & 0x0040))
    DEBUGOUT ("    Auto parameter negotiation made by CCID\n");
  else if ((us & 0x0080))
    DEBUGOUT ("    Auto PPS made by CCID\n");
  else if ((us & (0x0040 | 0x0080)))
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

  if (buf[0] > 54) {
    DEBUGOUT ("  junk             ");
    for (i=54; i < buf[0]-54; i++)
      DEBUGOUT_CONT_1 (" %02X", buf[i]);
    DEBUGOUT_LF ();
  }

  if (!have_t1 || !(have_tpdu  || handle->apdu_level) || !have_auto_conf)
    {
      DEBUGOUT ("this drivers requires that the reader supports T=1, "
                "TPDU or APDU level exchange and auto configuration - "
                "this is not available\n");
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
     performance to a a more or less acceptable level (tested by David). 
         
  */
  if (handle->id_vendor == VENDOR_SCM
      && handle->max_ifsd > 48      
      && (  (handle->id_product == 0xe001 && handle->bcd_device < 0x0516)
          ||(handle->id_product == 0x5111 && handle->bcd_device < 0x0620)
          ||(handle->id_product == 0x5115 && handle->bcd_device < 0x0514)
          ||(handle->id_product == 0xe003 && handle->bcd_device < 0x0504)
          ||(handle->id_product == 0x5117 && handle->bcd_device < 0x0522)
          ))
    {
      DEBUGOUT ("enabling workaround for buggy SCM readers\n");
      handle->max_ifsd = 48;
    }


  return 0;
}


static char *
get_escaped_usb_string (usb_dev_handle *idev, int idx,
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
  rc = usb_control_msg (idev, USB_ENDPOINT_IN, USB_REQ_GET_DESCRIPTOR,
                        (USB_DT_STRING << 8), 0, 
                        (char*)buf, sizeof buf, 1000 /* ms timeout */);
  if (rc < 4)
    langid = 0x0409; /* English.  */
  else
    langid = (buf[3] << 8) | buf[2];

  rc = usb_control_msg (idev, USB_ENDPOINT_IN, USB_REQ_GET_DESCRIPTOR,
                        (USB_DT_STRING << 8) + idx, langid,
                        (char*)buf, sizeof buf, 1000 /* ms timeout */);
  if (rc < 2 || buf[1] != USB_DT_STRING)
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
make_reader_id (usb_dev_handle *idev,
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
find_endpoint (struct usb_interface_descriptor *ifcdesc, int mode)
{
  int no;
  int want_bulk_in = 0;

  if (mode == 1)
    want_bulk_in = 0x80;
  for (no=0; no < ifcdesc->bNumEndpoints; no++)
    {
      struct usb_endpoint_descriptor *ep = ifcdesc->endpoint + no;
      if (ep->bDescriptorType != USB_DT_ENDPOINT)
        ;
      else if (mode == 2
          && ((ep->bmAttributes & USB_ENDPOINT_TYPE_MASK)
              == USB_ENDPOINT_TYPE_INTERRUPT)
          && (ep->bEndpointAddress & 0x80))
        return (ep->bEndpointAddress & 0x0f);
      else if (((ep->bmAttributes & USB_ENDPOINT_TYPE_MASK)
                == USB_ENDPOINT_TYPE_BULK)
               && (ep->bEndpointAddress & 0x80) == want_bulk_in)
        return (ep->bEndpointAddress & 0x0f);
    }
  /* Should never happen.  */
  return mode == 2? 0x83 : mode == 1? 0x82 :1;
}


/* Helper for scan_or_find_devices. This function returns true if a
   requested device has been found or the caller should stop scanning
   for other reasons. */
static int
scan_or_find_usb_device (int scan_mode,
                         int *readerno, int *count, char **rid_list,
                         const char *readerid,
                         struct usb_device *dev,
                         char **r_rid,
                         struct usb_device **r_dev,
                         usb_dev_handle **r_idev,
                         unsigned char **ifcdesc_extra,
                         size_t *ifcdesc_extra_len,
                         int *interface_number,
                         int *ep_bulk_out, int *ep_bulk_in, int *ep_intr)
{
  int cfg_no;
  int ifc_no;
  int set_no;
  struct usb_config_descriptor *config;
  struct usb_interface *interface;          
  struct usb_interface_descriptor *ifcdesc;
  char *rid;
  usb_dev_handle *idev;

  *r_idev = NULL;

  for (cfg_no=0; cfg_no < dev->descriptor.bNumConfigurations; cfg_no++)
    {
      config = dev->config + cfg_no;
      if(!config)
        continue;

      for (ifc_no=0; ifc_no < config->bNumInterfaces; ifc_no++)
        {
          interface = config->interface + ifc_no;
          if (!interface)
            continue;
                  
          for (set_no=0; set_no < interface->num_altsetting; set_no++)
            {
              ifcdesc = (interface->altsetting + set_no);
              /* The second condition is for older SCM SPR 532 who did
                 not know about the assigned CCID class.  Instead of
                 trying to interpret the strings we simply check the
                 product ID. */
              if (ifcdesc && ifcdesc->extra
                  && ((ifcdesc->bInterfaceClass == 11
                       && ifcdesc->bInterfaceSubClass == 0
                       && ifcdesc->bInterfaceProtocol == 0)
                      || (ifcdesc->bInterfaceClass == 255
                          && dev->descriptor.idVendor == VENDOR_SCM
                          && dev->descriptor.idProduct == 0xe003)))
                {
                  idev = usb_open (dev);
                  if (!idev)
                    {
                      DEBUGOUT_1 ("usb_open failed: %s\n",
                                  strerror (errno));
                      continue; /* with next setting. */
                    }
                  
                  rid = make_reader_id (idev,
                                        dev->descriptor.idVendor,
                                        dev->descriptor.idProduct,
                                        dev->descriptor.iSerialNumber);
                  if (rid)
                    {
                      if (scan_mode)
                        {
                          char *p;
                          
                          /* We are collecting infos about all
                             available CCID readers.  Store them and
                             continue. */
                          DEBUGOUT_2 ("found CCID reader %d (ID=%s)\n",
                                      *count, rid );
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
                            free (rid);
                          
                          rid = NULL;
                          ++*count;
                        }
                      else if (!*readerno
                               || (*readerno < 0
                                   && readerid
                                   && !strcmp (readerid, rid)))
                        {
                          /* We found the requested reader. */
                          if (ifcdesc_extra && ifcdesc_extra_len)
                            {
                              *ifcdesc_extra = malloc (ifcdesc
                                                       ->extralen);
                              if (!*ifcdesc_extra)
                                {
                                  usb_close (idev);
                                  free (rid);
                                  return 1; /* Out of core. */
                                }
                              memcpy (*ifcdesc_extra, ifcdesc->extra,
                                      ifcdesc->extralen);
                              *ifcdesc_extra_len = ifcdesc->extralen;
                            }

                          if (interface_number)
                            *interface_number = (ifcdesc->bInterfaceNumber);

                          if (ep_bulk_out)
                            *ep_bulk_out = find_endpoint (ifcdesc, 0);
                          if (ep_bulk_in)
                            *ep_bulk_in = find_endpoint (ifcdesc, 1);
                          if (ep_intr)
                            *ep_intr = find_endpoint (ifcdesc, 2);

                          if (r_dev)
                            *r_dev = dev;
                          if (r_rid)
                            {
                              *r_rid = rid;
                              rid = NULL;
                            }
                          else
                            free (rid);
                          
                          *r_idev = idev;
                          return 1; /* Found requested device. */
                        }
                      else
                        {
                          /* This is not yet the reader we want.
                             fixme: We should avoid the extra usb_open
                             in this case. */
                          if (*readerno >= 0)
                            --*readerno;
                        }
                      free (rid);
                    }
                  
                  usb_close (idev);
                  idev = NULL;
                  return 0;
                }
            }
        }
    }

  return 0;
}

/* Combination function to either scan all CCID devices or to find and
   open one specific device. 

   The function returns 0 if a reader has been found or when a scan
   returned without error.

   With READERNO = -1 and READERID is NULL, scan mode is used and
   R_RID should be the address where to store the list of reader_ids
   we found.  If on return this list is empty, no CCID device has been
   found; otherwise it points to an allocated linked list of reader
   IDs.  Note that in this mode the function always returns NULL.

   With READERNO >= 0 or READERID is not NULL find mode is used.  This
   uses the same algorithm as the scan mode but stops and returns at
   the entry number READERNO and return the handle for the the opened
   USB device. If R_RID is not NULL it will receive the reader ID of
   that device.  If R_DEV is not NULL it will the device pointer of
   that device.  If IFCDESC_EXTRA is NOT NULL it will receive a
   malloced copy of the interfaces "extra: data filed;
   IFCDESC_EXTRA_LEN receive the length of this field.  If there is
   no reader with number READERNO or that reader is not usable by our
   implementation NULL will be returned.  The caller must close a
   returned USB device handle and free (if not passed as NULL) the
   returned reader ID info as well as the IFCDESC_EXTRA.  On error
   NULL will get stored at R_RID, R_DEV, IFCDESC_EXTRA and
   IFCDESC_EXTRA_LEN.  With READERID being -1 the function stops if
   the READERID was found.

   If R_FD is not -1 on return the device is not using USB for
   transport but the device associated with that file descriptor.  In
   this case INTERFACE will receive the transport type and the other
   USB specific return values are not used; the return value is
   (void*)(1).

   Note that the first entry of the returned reader ID list in scan mode
   corresponds with a READERNO of 0 in find mode.
*/
static int
scan_or_find_devices (int readerno, const char *readerid,
                      char **r_rid,
                      struct usb_device **r_dev,
                      unsigned char **ifcdesc_extra,
                      size_t *ifcdesc_extra_len,
                      int *interface_number,
                      int *ep_bulk_out, int *ep_bulk_in, int *ep_intr,
                      usb_dev_handle **r_idev,
                      int *r_fd)
{
  char *rid_list = NULL;
  int count = 0;
  struct usb_bus *busses, *bus;
  struct usb_device *dev = NULL;
  usb_dev_handle *idev = NULL;
  int scan_mode = (readerno == -1 && !readerid);
  int i;

  /* Set return values to a default. */
  if (r_rid)
    *r_rid = NULL;
  if (r_dev)
    *r_dev = NULL; 
  if (ifcdesc_extra)
    *ifcdesc_extra = NULL;
  if (ifcdesc_extra_len)
    *ifcdesc_extra_len = 0;
  if (interface_number)
    *interface_number = 0;
  if (r_idev)
    *r_idev = NULL;
  if (r_fd)
    *r_fd = -1;

  /* See whether we want scan or find mode. */
  if (scan_mode) 
    {
      assert (r_rid);
    }

  usb_find_busses();
  usb_find_devices();

#ifdef HAVE_USB_GET_BUSSES
  busses = usb_get_busses();
#else
  busses = usb_busses;
#endif

  for (bus = busses; bus; bus = bus->next) 
    {
      for (dev = bus->devices; dev; dev = dev->next)
        {
          if (scan_or_find_usb_device (scan_mode, &readerno, &count, &rid_list,
                                       readerid,
                                       dev,
                                       r_rid,
                                       r_dev,
                                       &idev,
                                       ifcdesc_extra,
                                       ifcdesc_extra_len,
                                       interface_number,
                                       ep_bulk_out, ep_bulk_in, ep_intr))
            {
              /* Found requested device or out of core. */
              if (!idev)
                {
                  free (rid_list);
                  return -1; /* error */
                }
              *r_idev = idev;
              return 0; 
            }
        }
    }

  /* Now check whether there are any devices with special transport types. */
  for (i=0; transports[i].name; i++)
    {
      int fd;
      char *rid, *p;

      fd = open (transports[i].name, O_RDWR);
      if (fd == -1 && scan_mode && errno == EBUSY)
        {
          /* Ignore this error in scan mode because it indicates that
             the device exists but is already open (most likely by us)
             and thus in general suitable as a reader.  */
        }
      else if (fd == -1)
        {
          DEBUGOUT_2 ("failed to open `%s': %s\n",
                     transports[i].name, strerror (errno));
          continue;
        }

      rid = malloc (strlen (transports[i].name) + 30 + 10);
      if (!rid)
        {
          if (fd != -1)
            close (fd);
          free (rid_list);
          return -1; /* Error. */
        }
      sprintf (rid, "0000:%04X:%s:0", transports[i].type, transports[i].name);
      if (scan_mode)
        {
          DEBUGOUT_2 ("found CCID reader %d (ID=%s)\n", count, rid);
          p = malloc ((rid_list? strlen (rid_list):0) + 1 + strlen (rid) + 1);
          if (!p)
            {
              if (fd != -1)
                close (fd);
              free (rid_list);
              free (rid);
              return -1; /* Error. */
            }
          *p = 0;
          if (rid_list)
            {
              strcat (p, rid_list);
              free (rid_list);
            }
          strcat (p, rid);
          strcat (p, "\n");
          rid_list = p;
          ++count;
        }
      else if (!readerno ||
               (readerno < 0 && readerid && !strcmp (readerid, rid)))
        {
          /* Found requested device. */
          if (interface_number)
            *interface_number = transports[i].type;
          if (r_rid)
            *r_rid = rid;
          else
            free (rid);
          if (r_fd)
            *r_fd = fd;
          return 0; /* Okay, found device */
        }
      else /* This is not yet the reader we want. */
        {
          if (readerno >= 0)
            --readerno;
        }
      free (rid);
      if (fd != -1)
        close (fd);
    }

  if (scan_mode)
    {
      *r_rid = rid_list;
      return 0;
    }
  else
    return -1;
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
      usb_init ();
      initialized_usb = 1;
    }

  if (scan_or_find_devices (-1, NULL, &reader_list, NULL, NULL, NULL, NULL,
                            NULL, NULL, NULL, NULL, NULL))
    return NULL; /* Error. */
  return reader_list;
}


/* Open the reader with the internal number READERNO and return a 
   pointer to be used as handle in HANDLE.  Returns 0 on success. */
int 
ccid_open_reader (ccid_driver_t *handle, const char *readerid)
{
  int rc = 0;
  struct usb_device *dev = NULL;
  usb_dev_handle *idev = NULL;
  int dev_fd = -1;
  char *rid = NULL;
  unsigned char *ifcdesc_extra = NULL;
  size_t ifcdesc_extra_len;
  int readerno;
  int ifc_no, ep_bulk_out, ep_bulk_in, ep_intr;

  *handle = NULL;

  if (!initialized_usb)
    {
      usb_init ();
      initialized_usb = 1;
    }

  /* See whether we want to use the reader ID string or a reader
     number. A readerno of -1 indicates that the reader ID string is
     to be used. */
  if (readerid && strchr (readerid, ':'))
    readerno = -1; /* We want to use the readerid.  */
  else if (readerid)
    {
      readerno = atoi (readerid);
      if (readerno < 0)
        {
          DEBUGOUT ("no CCID readers found\n");
          rc = CCID_DRIVER_ERR_NO_READER;
          goto leave;
        }
    }
  else
    readerno = 0;  /* Default. */

  if (scan_or_find_devices (readerno, readerid, &rid, &dev,
                            &ifcdesc_extra, &ifcdesc_extra_len,
                            &ifc_no, &ep_bulk_out, &ep_bulk_in, &ep_intr,
                            &idev, &dev_fd) )
    {
      if (readerno == -1)
        DEBUGOUT_1 ("no CCID reader with ID %s\n", readerid );
      else
        DEBUGOUT_1 ("no CCID reader with number %d\n", readerno );
      rc = CCID_DRIVER_ERR_NO_READER;
      goto leave;
    }

  /* Okay, this is a CCID reader. */
  *handle = calloc (1, sizeof **handle);
  if (!*handle)
    {
      DEBUGOUT ("out of memory\n");
      rc = CCID_DRIVER_ERR_OUT_OF_CORE;
      goto leave;
    }
  (*handle)->rid = rid;
  if (idev) /* Regular USB transport. */
    {
      (*handle)->idev = idev;
      (*handle)->dev_fd = -1;
      (*handle)->id_vendor = dev->descriptor.idVendor;
      (*handle)->id_product = dev->descriptor.idProduct;
      (*handle)->bcd_device = dev->descriptor.bcdDevice;
      (*handle)->ifc_no = ifc_no;
      (*handle)->ep_bulk_out = ep_bulk_out;
      (*handle)->ep_bulk_in = ep_bulk_in;
      (*handle)->ep_intr = ep_intr;
    }
  else if (dev_fd != -1) /* Device transport. */
    {
      (*handle)->idev = NULL;
      (*handle)->dev_fd = dev_fd;
      (*handle)->id_vendor = 0;  /* Magic vendor for special transport. */
      (*handle)->id_product = ifc_no; /* Transport type */
      prepare_special_transport (*handle);
    }
  else
    {
      assert (!"no transport"); /* Bug. */
    }

  DEBUGOUT_2 ("using CCID reader %d (ID=%s)\n",  readerno, rid );

  if (idev)
    {
      if (parse_ccid_descriptor (*handle, ifcdesc_extra, ifcdesc_extra_len))
        {
          DEBUGOUT ("device not supported\n");
          rc = CCID_DRIVER_ERR_NO_READER;
          goto leave;
        }
      
      rc = usb_claim_interface (idev, ifc_no);
      if (rc)
        {
          DEBUGOUT_1 ("usb_claim_interface failed: %d\n", rc);
          rc = CCID_DRIVER_ERR_CARD_IO_ERROR;
          goto leave;
        }
    }

 leave:
  free (ifcdesc_extra);
  if (rc)
    {
      free (rid);
      if (idev)
        usb_close (idev);
      if (dev_fd != -1)
        close (dev_fd);
      free (*handle);
      *handle = NULL;
    }

  return rc;
}


static void
do_close_reader (ccid_driver_t handle)
{
  int rc;
  unsigned char msg[100];
  size_t msglen;
  unsigned char seqno;
  
  if (!handle->powered_off)
    {
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
      handle->powered_off = 1;
    }
  if (handle->idev)
    {
      usb_release_interface (handle->idev, handle->ifc_no);
      usb_close (handle->idev);
      handle->idev = NULL;
    }
  if (handle->dev_fd != -1)
    {
      close (handle->dev_fd);
      handle->dev_fd = -1;
    }
}


/* Reset a reader on HANDLE.  This is useful in case a reader has been
   plugged of and inserted at a different port.  By resetting the
   handle, the same reader will be get used.  Note, that on error the
   handle won't get released. 

   This does not return an ATR, so ccid_get_atr should be called right
   after this one.
*/
int 
ccid_shutdown_reader (ccid_driver_t handle)
{
  int rc = 0;
  struct usb_device *dev = NULL;
  usb_dev_handle *idev = NULL;
  unsigned char *ifcdesc_extra = NULL;
  size_t ifcdesc_extra_len;
  int ifc_no, ep_bulk_out, ep_bulk_in, ep_intr;

  if (!handle || !handle->rid)
    return CCID_DRIVER_ERR_INV_VALUE;

  do_close_reader (handle);

  if (scan_or_find_devices (-1, handle->rid, NULL, &dev,
                            &ifcdesc_extra, &ifcdesc_extra_len,
                            &ifc_no, &ep_bulk_out, &ep_bulk_in, &ep_intr,
                            &idev, NULL) || !idev)
    {
      DEBUGOUT_1 ("no CCID reader with ID %s\n", handle->rid);
      return CCID_DRIVER_ERR_NO_READER;
    }

  if (idev)
    {
      handle->idev = idev;
      handle->ifc_no = ifc_no;
      handle->ep_bulk_out = ep_bulk_out;
      handle->ep_bulk_in = ep_bulk_in;
      handle->ep_intr = ep_intr;

      if (parse_ccid_descriptor (handle, ifcdesc_extra, ifcdesc_extra_len))
        {
          DEBUGOUT ("device not supported\n");
          rc = CCID_DRIVER_ERR_NO_READER;
          goto leave;
        }
      
      rc = usb_claim_interface (idev, ifc_no);
      if (rc)
        {
          DEBUGOUT_1 ("usb_claim_interface failed: %d\n", rc);
          rc = CCID_DRIVER_ERR_CARD_IO_ERROR;
          goto leave;
        }
    }

 leave:
  free (ifcdesc_extra);
  if (rc)
    {
      if (handle->idev)
        usb_close (handle->idev);
      handle->idev = NULL;
      if (handle->dev_fd != -1)
        close (handle->dev_fd);
      handle->dev_fd = -1;
    }

  return rc;

}


int 
ccid_set_progress_cb (ccid_driver_t handle, 
                      void (*cb)(void *, const char *, int, int, int),
                      void *cb_arg)
{
  if (!handle || !handle->rid)
    return CCID_DRIVER_ERR_INV_VALUE;

  handle->progress_cb = cb;
  handle->progress_cb_arg = cb_arg;
  return 0;
}


/* Close the reader HANDLE. */
int 
ccid_close_reader (ccid_driver_t handle)
{
  if (!handle || (!handle->idev && handle->dev_fd == -1))
    return 0;

  do_close_reader (handle);
  free (handle->rid);
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


/* Write NBYTES of BUF to file descriptor FD. */
static int
writen (int fd, const void *buf, size_t nbytes)
{
  size_t nleft = nbytes;
  int nwritten;
  
  while (nleft > 0)
    {
      nwritten = write (fd, buf, nleft);
      if (nwritten < 0)
        {
          if (errno == EINTR)
            nwritten = 0;
          else
            return -1;
        }
      nleft -= nwritten;
      buf = (const char*)buf + nwritten;
    }
    
  return 0;
}


/* Write a MSG of length MSGLEN to the designated bulk out endpoint.
   Returns 0 on success. */
static int
bulk_out (ccid_driver_t handle, unsigned char *msg, size_t msglen,
          int no_debug)
{
  int rc;

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
  
  if (handle->idev)
    {
      rc = usb_bulk_write (handle->idev, 
                           handle->ep_bulk_out,
                           (char*)msg, msglen,
                           5000 /* ms timeout */);
      if (rc == msglen)
        return 0;
#ifdef ENODEV
      if (rc == -(ENODEV))
        {
          /* The Linux libusb returns a negative error value.  Catch
             the most important one.  */
          errno = ENODEV;
          rc = -1;
        }
#endif /*ENODEV*/

      if (rc == -1)
        {
          DEBUGOUT_1 ("usb_bulk_write error: %s\n", strerror (errno));
#ifdef ENODEV
          if (errno == ENODEV)
            {
              handle->enodev_seen = 1;
              return CCID_DRIVER_ERR_NO_READER;
            }
#endif /*ENODEV*/
        }
      else
        DEBUGOUT_1 ("usb_bulk_write failed: %d\n", rc);
    }
  else
    {
      rc = writen (handle->dev_fd, msg, msglen);
      if (!rc)
        return 0;
      DEBUGOUT_2 ("writen to %d failed: %s\n",
                  handle->dev_fd, strerror (errno));
      
    }
  return CCID_DRIVER_ERR_CARD_IO_ERROR;
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
  size_t msglen;
  int eagain_retries = 0;

  /* Fixme: The next line for the current Valgrind without support
     for USB IOCTLs. */
  memset (buffer, 0, length);
 retry:
  if (handle->idev)
    {
      rc = usb_bulk_read (handle->idev, 
                          handle->ep_bulk_in,
                          (char*)buffer, length,
                          timeout);
      if (rc < 0)
        {
          rc = errno;
          DEBUGOUT_1 ("usb_bulk_read error: %s\n", strerror (rc));
          if (rc == EAGAIN && eagain_retries++ < 3)
            {
              my_sleep (1);
              goto retry;
            }
          return CCID_DRIVER_ERR_CARD_IO_ERROR;
        }
      *nread = msglen = rc;
    }
  else
    {
      rc = read (handle->dev_fd, buffer, length);
      if (rc < 0)
        {
          rc = errno;
          DEBUGOUT_2 ("read from %d failed: %s\n",
                      handle->dev_fd, strerror (rc));
          if (rc == EAGAIN && eagain_retries++ < 5)
            {
              my_sleep (1);
              goto retry;
            }
          return CCID_DRIVER_ERR_CARD_IO_ERROR;
        }
      *nread = msglen = rc;
    }
  eagain_retries = 0;

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
  if ( !(buffer[7] & 0x03) && (buffer[7] & 0xC0) == 0x80)
    { 
      /* Card present and active, time extension requested. */
      DEBUGOUT_2 ("time extension requested (%02X,%02X)\n",
                  buffer[7], buffer[8]);
      goto retry;
    }

  if (buffer[0] != expected_type)
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
    case 1: return CCID_DRIVER_ERR_CARD_INACTIVE;
    case 2: return CCID_DRIVER_ERR_NO_CARD;
    case 3: /* RFU */ break;
    }
  return 0;
}



/* Send an abort sequence and wait until everything settled.  */
static int
abort_cmd (ccid_driver_t handle, int seqno)
{
  int rc;
  char dummybuf[8];
  unsigned char msg[100];
  size_t msglen;

  if (!handle->idev)
    {
      /* I don't know how to send an abort to non-USB devices.  */
      rc = CCID_DRIVER_ERR_NOT_SUPPORTED;
    }
  
  seqno &= 0xff;
  DEBUGOUT_1 ("sending abort sequence for seqno %d\n", seqno);
  /* Send the abort command to the control pipe.  Note that we don't
     need to keep track of sent abort commands because there should
     never be another thread using the same slot concurrently.  */
  rc = usb_control_msg (handle->idev, 
                        0x21,/* bmRequestType: host-to-device,
                                class specific, to interface.  */
                        1,   /* ABORT */
                        (seqno << 8 | 0 /* slot */),
                        handle->ifc_no,
                        dummybuf, 0,
                        1000 /* ms timeout */);
  if (rc < 0)
    {
      DEBUGOUT_1 ("usb_control_msg error: %s\n", strerror (errno));
      return CCID_DRIVER_ERR_CARD_IO_ERROR;
    }

  /* Now send the abort command to the bulk out pipe using the same
     SEQNO and SLOT.  Do this in a loop to so that all seqno are
     tried.  */
  seqno--;  /* Adjust for next increment.  */
  do
    {
      seqno++; 
      msg[0] = PC_to_RDR_Abort;
      msg[5] = 0; /* slot */
      msg[6] = seqno;
      msg[7] = 0; /* RFU */
      msg[8] = 0; /* RFU */
      msg[9] = 0; /* RFU */
      msglen = 10;
      set_msg_len (msg, 0);

      rc = usb_bulk_write (handle->idev, 
                           handle->ep_bulk_out,
                           (char*)msg, msglen,
                           5000 /* ms timeout */);
      if (rc == msglen)
        rc = 0;
      else if (rc == -1)
        DEBUGOUT_1 ("usb_bulk_write error in abort_cmd: %s\n", 
                    strerror (errno));
      else
        DEBUGOUT_1 ("usb_bulk_write failed in abort_cmd: %d\n", rc);

      if (rc)
        return rc;
      
      rc = usb_bulk_read (handle->idev, 
                          handle->ep_bulk_in,
                          (char*)msg, sizeof msg, 
                          5000 /*ms timeout*/);
      if (rc < 0)
        {
          DEBUGOUT_1 ("usb_bulk_read error in abort_cmd: %s\n",
                      strerror (errno));
          return CCID_DRIVER_ERR_CARD_IO_ERROR;
        }
      msglen = rc;

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
              *resultlen = msglen;
            }
          rc = 0;
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
  size_t msglen;
  int i, j;

  if (handle->idev)
    {
      rc = usb_bulk_read (handle->idev, 
                          handle->ep_intr,
                          (char*)msg, sizeof msg,
                          0 /* ms timeout */ );
      if (rc < 0 && errno == ETIMEDOUT)
        return 0;
    }
  else 
    return 0;

  if (rc < 0)
    {
      DEBUGOUT_1 ("usb_intr_read error: %s\n", strerror (errno));
      return CCID_DRIVER_ERR_CARD_IO_ERROR;
    }

  msglen = rc;
  rc = 0;

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
      DEBUGOUT ("hardware error occured\n");
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
ccid_slot_status (ccid_driver_t handle, int *statusbits)
{
  int rc;
  unsigned char msg[100];
  size_t msglen;
  unsigned char seqno;
  int retries = 0;

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
  if (rc == CCID_DRIVER_ERR_CARD_IO_ERROR && retries < 3)
    {
      if (!retries)
        {
          DEBUGOUT ("USB: CALLING USB_CLEAR_HALT\n");
          usb_clear_halt (handle->idev, handle->ep_bulk_in);
          usb_clear_halt (handle->idev, handle->ep_bulk_out);
        }
      else
          DEBUGOUT ("USB: RETRYING bulk_in AGAIN\n");
      retries++;
      goto retry;
    }
  if (rc && rc != CCID_DRIVER_ERR_NO_CARD
      && rc != CCID_DRIVER_ERR_CARD_INACTIVE)
    return rc;
  *statusbits = (msg[7] & 3);

  return 0;
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

  /* First check whether a card is available.  */
  rc = ccid_slot_status (handle, &statusbits);
  if (rc)
    return rc;
  if (statusbits == 2)
    return CCID_DRIVER_ERR_NO_CARD;

  /* For an inactive and also for an active card, issue the PowerOn
     command to get the ATR.  */
 again:
  msg[0] = PC_to_RDR_IccPowerOn;
  msg[5] = 0; /* slot */
  msg[6] = seqno = handle->seqno++;
  msg[7] = 0; /* power select (0=auto, 1=5V, 2=3V, 3=1.8V) */
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

  got_param = 0;
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

  /* Setup parameters to select T=1. */
  msg[0] = PC_to_RDR_SetParameters;
  msg[5] = 0; /* slot */
  msg[6] = seqno = handle->seqno++;
  msg[7] = 1; /* Select T=1. */
  msg[8] = 0; /* RFU */
  msg[9] = 0; /* RFU */

  if (!got_param)
    {
      /* FIXME: Get those values from the ATR. */
      msg[10]= 0x01; /* Fi/Di */
      msg[11]= 0x10; /* LRC, direct convention. */
      msg[12]= 0;    /* Extra guardtime. */
      msg[13]= 0x41; /* BWI/CWI */
      msg[14]= 0;    /* No clock stoppping. */
      msg[15]= 254;  /* IFSC */
      msg[16]= 0;    /* Does not support non default NAD values. */
    }
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
                            const unsigned char *apdu_buf, size_t apdu_buflen,
                            unsigned char *resp, size_t maxresplen,
                            size_t *nresp)
{
  int rc;
  unsigned char send_buffer[10+261+300], recv_buffer[10+261+300];
  const unsigned char *apdu;
  size_t apdulen;
  unsigned char *msg;
  size_t msglen;
  unsigned char seqno;
  int bwi = 4;

  msg = send_buffer;

  apdu = apdu_buf;
  apdulen = apdu_buflen;
  assert (apdulen);

  /* The maximum length for a short APDU T=1 block is 261.  For an
     extended APDU T=1 block the maximum length 65544; however
     extended APDU exchange level is not yet supported.  */
  if (apdulen > 261)
    return CCID_DRIVER_ERR_INV_VALUE; /* Invalid length. */
  
  msg[0] = PC_to_RDR_XfrBlock;
  msg[5] = 0; /* slot */
  msg[6] = seqno = handle->seqno++;
  msg[7] = bwi; /* bBWI */
  msg[8] = 0; /* RFU */
  msg[9] = 0; /* RFU */
  memcpy (msg+10, apdu, apdulen);
  set_msg_len (msg, apdulen);
  msglen = 10 + apdulen;

  rc = bulk_out (handle, msg, msglen, 0);
  if (rc)
    return rc;

  msg = recv_buffer;
  rc = bulk_in (handle, msg, sizeof recv_buffer, &msglen,
                RDR_to_PC_DataBlock, seqno, 5000, 0);
  if (rc)
    return rc;
      
  apdu = msg + 10;
  apdulen = msglen - 10;
      
  if (resp)
    {
      if (apdulen > maxresplen)
        {
          DEBUGOUT_2 ("provided buffer too short for received data "
                      "(%u/%u)\n",
                      (unsigned int)apdulen, (unsigned int)maxresplen);
          return CCID_DRIVER_ERR_INV_VALUE;
        }
      
      memcpy (resp, apdu, apdulen); 
      *nresp = apdulen;
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
      bit 4..0  0 = resyncronisation request
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

  if (!nresp)
    nresp = &dummy_nresp;
  *nresp = 0;

  /* Smarter readers allow to send APDUs directly; divert here. */
  if (handle->apdu_level)
    {
      /* We employ a hack for Omnikey readers which are able to send
         TPDUs using an escape sequence.  There is no documentation
         but the Windows driver does it this way.  Tested using a
         CM6121.  This method works also for the Cherry XX44
         keyboards; however there are problems with the
         ccid_tranceive_secure which leads to a loss of sync on the
         CCID level.  If Cherry wants to make their keyboard work
         again, they should hand over some docs. */
      if ((handle->id_vendor == VENDOR_OMNIKEY
           || (!handle->idev && handle->id_product == TRANSPORT_CM4040))
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
          msg[7] = 4; /* bBWI */
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
                    via_escape? RDR_to_PC_Escape : RDR_to_PC_DataBlock, 
                    seqno, 5000, 0);
      if (rc)
        return rc;

      tpdu = msg + hdrlen;
      tpdulen = msglen - hdrlen;
      resyncing = 0;
            
      if (tpdulen < 4) 
        {
          usb_clear_halt (handle->idev, handle->ep_bulk_in);
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

      if (!(tpdu[1] & 0x80))
        { /* This is an I-block. */
          retries = 0;
          if (sending)
            { /* last block sent was successful. */
              handle->t1_ns ^= 1;
              sending = 0;
            }

          if (!!(tpdu[1] & 0x40) != handle->t1_nr)
            { /* Reponse does not match our sequence number. */
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
   may be used t enable reasonable defaults.  PIN_PADLEN should be 0.
   
   When called with RESP and NRESP set to NULL, the function will
   merely check whether the reader supports the secure command for the
   given APDU and PIN_MODE. */
int
ccid_transceive_secure (ccid_driver_t handle,
                        const unsigned char *apdu_buf, size_t apdu_buflen,
                        int pin_mode, int pinlen_min, int pinlen_max,
                        int pin_padlen, 
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

  testmode = !resp && !nresp;

  if (!nresp)
    nresp = &dummy_nresp;
  *nresp = 0;

  if (apdu_buflen >= 4 && apdu_buf[1] == 0x20 && (handle->has_pinpad & 1))
    ;
  else if (apdu_buflen >= 4 && apdu_buf[1] == 0x24 && (handle->has_pinpad & 2))
    return CCID_DRIVER_ERR_NOT_SUPPORTED; /* Not yet by our code. */
  else
    return CCID_DRIVER_ERR_NO_KEYPAD;
    
  if (pin_mode != 1)
    return CCID_DRIVER_ERR_NOT_SUPPORTED;

  if (pin_padlen != 0)
    return CCID_DRIVER_ERR_NOT_SUPPORTED;

  if (!pinlen_min)
    pinlen_min = 1;
  if (!pinlen_max)
    pinlen_max = 25;

  /* Note that the 25 is the maximum value the SPR532 allows.  */
  if (pinlen_min < 1 || pinlen_min > 25
      || pinlen_max < 1 || pinlen_max > 25 
      || pinlen_min > pinlen_max)
    return CCID_DRIVER_ERR_INV_VALUE;

  /* We have only tested a few readers so better don't risk anything
     and do not allow the use with other readers. */
  switch (handle->id_vendor)
    {
    case VENDOR_SCM:  /* Tested with SPR 532. */
    case VENDOR_KAAN: /* Tested with KAAN Advanced (1.02). */
      break;
    case VENDOR_CHERRY:
      /* The CHERRY XX44 keyboard echos an asterisk for each entered
         character on the keyboard channel.  We use a special variant
         of PC_to_RDR_Secure which directs these characters to the
         smart card's bulk-in channel.  We also need to append a zero
         Lc byte to the APDU.  It seems that it will be replaced with
         the actual length instead of being appended before the APDU
         is send to the card. */
      cherry_mode = 1;
      break;
    default:
     return CCID_DRIVER_ERR_NOT_SUPPORTED;
    }

  if (testmode)
    return 0; /* Success */
    
  msg = send_buffer;
  if (handle->id_vendor == VENDOR_SCM)
    {
      DEBUGOUT ("sending escape sequence to switch to a case 1 APDU\n");
      rc = send_escape_cmd (handle, (const unsigned char*)"\x80\x02\x00", 3,
                            NULL, 0, NULL);
      if (rc)
        return rc;
    }

  msg[0] = cherry_mode? 0x89 : PC_to_RDR_Secure;
  msg[5] = 0; /* slot */
  msg[6] = seqno = handle->seqno++;
  msg[7] = 0; /* bBWI */
  msg[8] = 0; /* RFU */
  msg[9] = 0; /* RFU */
  msg[10] = 0; /* Perform PIN verification. */
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
      msg[13] = 0x00; /* bmPINBlockString:
                         0 bits of pin length to insert. 
                         0 bytes of PIN block size.  */
      msg[14] = 0x00; /* bmPINLengthFormat:
                         Units are bytes, position is 0. */
    }

  /* The following is a little endian word. */
  msg[15] = pinlen_max;   /* wPINMaxExtraDigit-Maximum.  */
  msg[16] = pinlen_min;   /* wPINMaxExtraDigit-Minimum.  */

  msg[17] = 0x02; /* bEntryValidationCondition:
                     Validation key pressed */
  if (pinlen_min && pinlen_max && pinlen_min == pinlen_max)
    msg[17] |= 0x01; /* Max size reached.  */
  msg[18] = 0xff; /* bNumberMessage: Default. */
  msg[19] = 0x04; /* wLangId-High. */
  msg[20] = 0x09; /* wLangId-Low:  English FIXME: use the first entry. */
  msg[21] = 0;    /* bMsgIndex. */
  /* bTeoProlog follows: */
  msg[22] = handle->nonnull_nad? ((1 << 4) | 0): 0;
  msg[23] = ((handle->t1_ns & 1) << 6); /* I-block */
  msg[24] = 0; /* The apdulen will be filled in by the reader.  */
  /* APDU follows:  */
  msg[25] = apdu_buf[0]; /* CLA */
  msg[26] = apdu_buf[1]; /* INS */
  msg[27] = apdu_buf[2]; /* P1 */
  msg[28] = apdu_buf[3]; /* P2 */
  msglen = 29;
  if (cherry_mode)
    msg[msglen++] = 0;
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
      usb_clear_halt (handle->idev, handle->ep_bulk_in);
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
        { /* Reponse does not match our sequence number. */
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
          resp += n;
          *nresp += n;
          maxresplen -= n;
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
        { /* Reponse does not match our sequence number. */
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
    case 0: p = "success";
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
  int rc;
  ccid_driver_t ccid;
  int slotstat;
  unsigned char result[512];
  size_t resultlen;
  int no_pinpad = 0;
  int verify_123456 = 0;
  int did_verify = 0;
  int no_poll = 0;

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

  rc = ccid_open_reader (&ccid, argc? *argv:NULL);
  if (rc)
    return 1;

  if (!no_poll)
    ccid_poll (ccid);
  fputs ("getting ATR ...\n", stderr);
  rc = ccid_get_atr (ccid, NULL, 0, NULL);
  if (rc)
    {
      print_error (rc);
      return 1;
    }

  if (!no_poll)
    ccid_poll (ccid);
  fputs ("getting slot status ...\n", stderr);
  rc = ccid_slot_status (ccid, &slotstat);
  if (rc)
    {
      print_error (rc);
      return 1;
    }

  if (!no_poll)
    ccid_poll (ccid);

  fputs ("selecting application OpenPGP ....\n", stderr);
  {
    static unsigned char apdu[] = {
      0, 0xA4, 4, 0, 6, 0xD2, 0x76, 0x00, 0x01, 0x24, 0x01};
    rc = ccid_transceive (ccid,
                          apdu, sizeof apdu,
                          result, sizeof result, &resultlen);
    print_result (rc, result, resultlen);
  }
  

  if (!no_poll)
    ccid_poll (ccid);

  fputs ("getting OpenPGP DO 0x65 ....\n", stderr);
  {
    static unsigned char apdu[] = { 0, 0xCA, 0, 0x65, 254 };
    rc = ccid_transceive (ccid, apdu, sizeof apdu,
                          result, sizeof result, &resultlen);
    print_result (rc, result, resultlen);
  }

  if (!no_pinpad)
    {
    }

  if (!no_pinpad)
    {
      static unsigned char apdu[] = { 0, 0x20, 0, 0x81 };

      
      if (ccid_transceive_secure (ccid,
                                  apdu, sizeof apdu,
                                  1, 0, 0, 0,
                                  NULL, 0, NULL))
        fputs ("can't verify using a PIN-Pad reader\n", stderr);
      else
        {
          fputs ("verifying CHV1 using the PINPad ....\n", stderr);
          
          rc = ccid_transceive_secure (ccid,
                                       apdu, sizeof apdu,
                                       1, 0, 0, 0,
                                       result, sizeof result, &resultlen);
          print_result (rc, result, resultlen);
          did_verify = 1;
        }
    }
  
  if (verify_123456 && !did_verify)
    {
      fputs ("verifying that CHV1 is 123456....\n", stderr);
      {
        static unsigned char apdu[] = {0, 0x20, 0, 0x81,
                                       6, '1','2','3','4','5','6'};
        rc = ccid_transceive (ccid, apdu, sizeof apdu,
                              result, sizeof result, &resultlen);
        print_result (rc, result, resultlen);
      }
    }

  if (!rc)
    {
      fputs ("getting OpenPGP DO 0x5E ....\n", stderr);
      {
        static unsigned char apdu[] = { 0, 0xCA, 0, 0x5E, 254 };
        rc = ccid_transceive (ccid, apdu, sizeof apdu,
                              result, sizeof result, &resultlen);
        print_result (rc, result, resultlen);
      }
    }

  ccid_close_reader (ccid);

  return 0;
}

/*
 * Local Variables:
 *  compile-command: "gcc -DTEST -Wall -I/usr/local/include -lusb -g ccid-driver.c"
 * End:
 */
#endif /*TEST*/
#endif /*HAVE_LIBUSB*/
