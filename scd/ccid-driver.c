/* ccid-driver.c - USB ChipCardInterfaceDevices driver
 *	Copyright (C) 2003 Free Software Foundation, Inc.
 *      Written by Werner Koch.
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
 */


/* CCID (ChipCardInterfaceDevices) is a specification for accessing
   smartcard via a reader connected to the USB.  

   This is a limited driver allowing to use some CCID drivers directly
   without any other specila drivers. This is a fallback driver to be
   used when nothing else works or the system should be kept minimal
   for security reasons.  It makes use of the libusb library to gain
   portable access to USB.

   This driver has been tested with the SCM SCR335 smartcard reader
   and requires that reader implements the TPDU level exchange and
   does fully automatic initialization.
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

/* Disable all debugging output for now. */
#undef DBG_CARD_IO
#define DBG_CARD_IO 0


# define DEBUGOUT(t)         do { if (DBG_CARD_IO) \
                                  log_debug (DRVNAME t); } while (0)
# define DEBUGOUT_1(t,a)     do { if (DBG_CARD_IO) \
                                  log_debug (DRVNAME t,(a)); } while (0)
# define DEBUGOUT_2(t,a,b)   do { if (DBG_CARD_IO) \
                                  log_debug (DRVNAME t,(a),(b)); } while (0)
# define DEBUGOUT_3(t,a,b,c) do { if (DBG_CARD_IO) \
                                  log_debug (DRVNAME t,(a),(b),(c));} while (0)
# define DEBUGOUT_CONT(t)    do { if (DBG_CARD_IO) \
                                  log_printf (t); } while (0)
# define DEBUGOUT_CONT_1(t,a)  do { if (DBG_CARD_IO) \
                                  log_printf (t,(a)); } while (0)
# define DEBUGOUT_CONT_2(t,a,b)   do { if (DBG_CARD_IO) \
                                  log_printf (t,(a),(b)); } while (0)
# define DEBUGOUT_CONT_3(t,a,b,c) do { if (DBG_CARD_IO) \
                                  log_printf (t,(a),(b),(c)); } while (0)
# define DEBUGOUT_LF()       do { if (DBG_CARD_IO) \
                                  log_printf ("\n"); } while (0)

#else /* Other usage of this source - don't use gnupg specifics. */

# define DEBUGOUT(t)          fprintf (stderr, DRVNAME t)
# define DEBUGOUT_1(t,a)      fprintf (stderr, DRVNAME t, (a))
# define DEBUGOUT_2(t,a,b)    fprintf (stderr, DRVNAME t, (a), (b))
# define DEBUGOUT_3(t,a,b,c)  fprintf (stderr, DRVNAME t, (a), (b), (c))
# define DEBUGOUT_CONT(t)     fprintf (stderr, t)
# define DEBUGOUT_CONT_1(t,a)      fprintf (stderr, t, (a))
# define DEBUGOUT_CONT_2(t,a,b)    fprintf (stderr, t, (a), (b))
# define DEBUGOUT_CONT_3(t,a,b,c)  fprintf (stderr, t, (a), (b), (c))
# define DEBUGOUT_LF()        putc ('\n', stderr)

#endif /* This source not used by scdaemon. */


/* Define to print information pertaining the T=1 protocol. */
#undef DEBUG_T1 



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


/* Store information on the driver's state.  A pointer to such a
   structure is used as handle for most functions. */
struct ccid_driver_s {
  usb_dev_handle *idev;
  int seqno;
  unsigned char t1_ns;
  unsigned char t1_nr;
};


static int bulk_out (ccid_driver_t handle, unsigned char *msg, size_t msglen);
static int bulk_in (ccid_driver_t handle, unsigned char *buffer, size_t length,
                    size_t *nread, int expected_type, int seqno);



/* Convert a little endian stored 4 byte value into an unsigned
   integer. */
static unsigned int 
convert_le_u32 (const unsigned char *buf)
{
  return buf[0] | (buf[1] << 8) | (buf[2] << 16) | (buf[3] << 24); 
}

static void
set_msg_len (unsigned char *msg, unsigned int length)
{
  msg[1] = length;
  msg[2] = length >> 8;
  msg[3] = length >> 16;
  msg[4] = length >> 24;
}




/* Parse a CCID descriptor, optionally print all available features
   and test whether this reader is usable by this driver.  Returns 0
   if it is usable.

   Note, that this code is based on the one in lsusb.c of the
   usb-utils package, I wrote on 2003-09-01. -wk. */
static int
parse_ccid_descriptor (const unsigned char *buf, size_t buflen)
{
  unsigned int i;
  unsigned int us;
  int have_t1 = 0, have_tpdu=0, have_auto_conf = 0;


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
    DEBUGOUT ("    Auto parameter negotation made by CCID\n");
  else if ((us & 0x0080))
    DEBUGOUT ("    Auto PPS made by CCID\n");
  else if ((us & (0x0040 | 0x0080)))
    DEBUGOUT ("    WARNING: conflicting negotation features\n");

  if ((us & 0x0100))
    DEBUGOUT ("    CCID can set ICC in clock stop mode\n");
  if ((us & 0x0200))
    DEBUGOUT ("    NAD value other than 0x00 accpeted\n");
  if ((us & 0x0400))
    DEBUGOUT ("    Auto IFSD exchange\n");

  if ((us & 0x00010000))
    {
      DEBUGOUT ("    TPDU level exchange\n");
      have_tpdu = 1;
    } 
  else if ((us & 0x00020000))
    DEBUGOUT ("    Short APDU level exchange\n");
  else if ((us & 0x00040000))
    DEBUGOUT ("    Short and extended APDU level exchange\n");
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
    DEBUGOUT_1 ("  %02X\n", buf[48]);

  DEBUGOUT (  "  wlcdLayout           ");
  if (!buf[50] && !buf[51])
    DEBUGOUT_CONT ("none\n");
  else
    DEBUGOUT_CONT_2 ("%u cols %u lines\n", buf[50], buf[51]);
        
  DEBUGOUT_1 ("  bPINSupport         %5u ", buf[52]);
  if ((buf[52] & 1))
    DEBUGOUT_CONT ( " verification");
  if ((buf[52] & 2))
    DEBUGOUT_CONT ( " modification");
  DEBUGOUT_LF ();
        
  DEBUGOUT_1 ("  bMaxCCIDBusySlots   %5u\n", buf[53]);

  if (buf[0] > 54) {
    DEBUGOUT ("  junk             ");
    for (i=54; i < buf[0]-54; i++)
      DEBUGOUT_CONT_1 (" %02X", buf[i]);
    DEBUGOUT_LF ();
  }

  if (!have_t1 || !have_tpdu || !have_auto_conf)
    {
      DEBUGOUT ("this drivers requires that the reader supports T=1, "
                "TPDU level exchange and auto configuration - "
                "this is not available\n");
      return -1;
    }
  else
    return 0;
}


/* Read the device information, return all required data and check
   that the device is usable for us.  Returns 0 on success or an error
   code. */
static int
read_device_info (struct usb_device *dev)
{
  int cfg_no;

  for (cfg_no=0; cfg_no < dev->descriptor->bNumConfigurations; cfg_no++)
    {
      struct usb_config_descriptor *config = dev->config + cfg_no;
      int ifc_no;

      for (ifc_no=0; ifc_no < config->bNumInterfaces; ifc_no++)
        {
          struct usb_interface *interface = config->interface + ifc_no;
          int set_no;

          for (set_no=0; set_no < interface->num_altsetting; set_no++)
            {
              struct usb_interface_descriptor *ifcdesc
                = interface->altsetting + set_no;
              
              if (ifcdesc->bInterfaceClass == 11
                  && ifcdesc->bInterfaceSubClass == 0
                  && ifcdesc->bInterfaceProtocol == 0)
                {
                  if (ifcdesc->extra)
                    {
                      if (!parse_ccid_descriptor (ifcdesc->extra,
                                                 ifcdesc->extralen))
                        return 0; /* okay. we can use it. */
                    }
                }
            }
        }
    }
  return -1; /* No suitable device found. */
}


/* Open the reader with the internal number READERNO and return a a
   pointer to be used as handle in HANDLE.  Returns 0 on success. */
int 
ccid_open_reader (ccid_driver_t *handle, int readerno)
{
  static int initialized;

  int rc;
  usb_match_handle *match = NULL;
  struct usb_device *dev = NULL;
  usb_dev_handle *idev = NULL;

  *handle = NULL;
  if (!initialized)
    {
      usb_init ();
      initialized = 1;
    }
  
  rc = usb_create_match (&match, -1, -1, 11, -1, -1);
  if (rc)
    {
      DEBUGOUT_1 ("usb_create_match failed: %d\n", rc);
      return -1;
    }

  while (usb_find_device(match, dev, &dev) >= 0) 
    {
      DEBUGOUT_3 ("%-40s %04X/%04X\n", dev->filename,
                  dev->descriptor->idVendor, dev->descriptor->idProduct);
      if (!readerno)
        {
          rc = read_device_info (dev);
          if (rc)
            {
              DEBUGOUT ("device not supported\n");
              goto leave;
            }

          rc = usb_open (dev, &idev);
          if (rc)
            {
              DEBUGOUT_1 ("usb_open failed: %d\n", rc);
              goto leave;
            }


          /* fixme: Do we need to claim and set the interface as
             determined by read_device_info ()? */
          rc = usb_claim_interface (idev, 0);
          if (rc)
            {
              DEBUGOUT_1 ("usb_claim_interface failed: %d\n", rc);
              goto leave;
            }

          *handle = calloc (1, sizeof **handle);
          if (!*handle)
            {
              DEBUGOUT ("out of memory\n");
              rc = -1;
              goto leave;
            }
          (*handle)->idev = idev;
          idev = NULL;
          /* FIXME: Do we need to get the endpoint addresses from the
             structure and store them with the handle? */

          break;
        }
      readerno--;
    }


 leave:
  if (idev)
    usb_close (idev);
  /* fixme: Do we need to release dev or is it supposed to be a
     shallow copy of the list created internally by usb_init ? */
  usb_free_match (match);

  if (!rc && !*handle)
    rc = -1; /* In case we didn't enter the while lool at all. */

  return rc;
}


/* Close the reader HANDLE. */
int 
ccid_close_reader (ccid_driver_t handle)
{
  if (!handle || !handle->idev)
    return 0;

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
   
     rc = bulk_out (handle, msg, msglen);
     if (!rc)
        bulk_in (handle, msg, sizeof msg, &msglen, RDR_to_PC_SlotStatus, seqno);
   }
   
  usb_release_interface (handle->idev, 0);
  usb_close (handle->idev);
  handle->idev = NULL;
  free (handle);
  return 0;
}


/* Return False if a card is present and powered. */
int
ccid_check_card_presence (ccid_driver_t handle)
{

  return -1;
}


/* Write a MSG of length MSGLEN to the designated bulk out endpoint.
   Returns 0 on success. */
static int
bulk_out (ccid_driver_t handle, unsigned char *msg, size_t msglen)
{
  int rc;

  rc = usb_bulk_write (handle->idev, 
                       1, /*endpoint */
                       msg, msglen,
                       1000 /* ms timeout */);
  if (rc == msglen)
    return 0;

  if (rc == -1)
    DEBUGOUT_1 ("usb_bulk_write error: %s\n", strerror (errno));
  else
    DEBUGOUT_1 ("usb_bulk_write failed: %d\n", rc);
  return -1;
}


/* Read a maximum of LENGTH bytes from the bulk in endpoint into
   BUFFER and return the actual read number if bytes in NREAD. SEQNO
   is the sequence number used to send the request and EXPECTED_TYPE
   the type of message we expect. Does checks on the ccid
   header. Returns 0 on success. */
static int
bulk_in (ccid_driver_t handle, unsigned char *buffer, size_t length,
         size_t *nread, int expected_type, int seqno)
{
  int i, rc;
  size_t msglen;

  rc = usb_bulk_read (handle->idev, 
                      0x82,
                      buffer, length,
                      10000 /* ms timeout */ );
  /* Fixme: instead of using a 10 second timeout we should better
     handle the timeout here and retry if appropriate.  */
  if (rc < 0)
    {
      DEBUGOUT_1 ("usb_bulk_read error: %s\n", strerror (errno));
      return -1;
    }

  *nread = msglen = rc;

  if (msglen < 10)
    {
      DEBUGOUT_1 ("bulk-in msg too short (%u)\n", (unsigned int)msglen);
      return -1;
    }
  if (buffer[0] != expected_type)
    {
      DEBUGOUT_1 ("unexpected bulk-in msg type (%02x)\n", buffer[0]);
      return -1;
    }
  if (buffer[5] != 0)    
    {
      DEBUGOUT_1 ("unexpected bulk-in slot (%d)\n", buffer[5]);
      return -1;
    }
  if (buffer[6] != seqno)    
    {
      DEBUGOUT_2 ("bulk-in seqno does not match (%d/%d)\n",
                  seqno, buffer[6]);
      return -1;
    }

  DEBUGOUT_3 ("status: %02X  error: %02X  octet[9]: %02X\n"
              "               data:",  buffer[7], buffer[8], buffer[9] );
  for (i=10; i < msglen; i++)
    DEBUGOUT_CONT_1 (" %02X", buffer[i]);
  DEBUGOUT_LF ();

  return 0;
}


/* experimental */
int
ccid_poll (ccid_driver_t handle)
{
  int rc;
  unsigned char msg[10];
  size_t msglen;
  int i, j;

  rc = usb_bulk_read (handle->idev, 
                      0x83,
                      msg, sizeof msg,
                      0 /* ms timeout */ );
  if (rc < 0 && errno == ETIMEDOUT)
    return 0;

  if (rc < 0)
    {
      DEBUGOUT_1 ("usb_intr_read error: %s\n", strerror (errno));
      return -1;
    }

  msglen = rc;
  rc = 0;

  if (msglen < 1)
    {
      DEBUGOUT ("intr-in msg too short\n");
      return -1;
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



int 
ccid_slot_status (ccid_driver_t handle)
{
  int rc;
  unsigned char msg[100];
  size_t msglen;
  unsigned char seqno;

  msg[0] = PC_to_RDR_GetSlotStatus;
  msg[5] = 0; /* slot */
  msg[6] = seqno = handle->seqno++;
  msg[7] = 0; /* RFU */
  msg[8] = 0; /* RFU */
  msg[9] = 0; /* RFU */
  set_msg_len (msg, 0);

  rc = bulk_out (handle, msg, 10);
  if (rc)
    return rc;
  rc = bulk_in (handle, msg, sizeof msg, &msglen, RDR_to_PC_SlotStatus, seqno);
  if (rc)
    return rc;

  return 0;
}


int 
ccid_get_atr (ccid_driver_t handle,
              unsigned char *atr, size_t maxatrlen, size_t *atrlen)
{
  int rc;
  unsigned char msg[100];
  size_t msglen;
  unsigned char seqno;

  msg[0] = PC_to_RDR_IccPowerOn;
  msg[5] = 0; /* slot */
  msg[6] = seqno = handle->seqno++;
  msg[7] = 0; /* power select (0=auto, 1=5V, 2=3V, 3=1.8V) */
  msg[8] = 0; /* RFU */
  msg[9] = 0; /* RFU */
  set_msg_len (msg, 0);
  msglen = 10;

  rc = bulk_out (handle, msg, msglen);
  if (rc)
    return rc;
  rc = bulk_in (handle, msg, sizeof msg, &msglen, RDR_to_PC_DataBlock, seqno);
  if (rc)
    return rc;
  
  if (atr)
    {
      size_t n = msglen - 10;

      if (n > maxatrlen)
        n = maxatrlen;
      memcpy (atr, msg+10, n);
      *atrlen = n;
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
  unsigned char send_buffer[10+258], recv_buffer[10+258];
  const unsigned char *apdu;
  size_t apdulen;
  unsigned char *msg, *tpdu, *p;
  size_t msglen, tpdulen, n;
  unsigned char seqno;
  int i;
  unsigned char crc;
  size_t dummy_nresp;
  int next_chunk = 1;
  int sending = 1;

  if (!nresp)
    nresp = &dummy_nresp;
  *nresp = 0;

  tpdulen = 0; /* Avoid compiler warning about no initialization. */
  msg = send_buffer;
  for (;;)
    {
      if (next_chunk)
        {
          next_chunk = 0;

          apdu = apdu_buf;
          apdulen = apdu_buflen;
          assert (apdulen);

          /* Construct an I-Block. */
          if (apdulen > 254)
            return -1; /* Invalid length. */

          tpdu = msg+10;
          tpdu[0] = ((1 << 4) | 0); /* NAD: DAD=1, SAD=0 */
          tpdu[1] = ((handle->t1_ns & 1) << 6); /* I-block */
          if (apdulen > 128 /* fixme: replace by ifsc */)
            {
              apdulen = 128;
              apdu_buf += 128;  
              apdu_buflen -= 128;
              tpdu[1] |= (1 << 5); /* Set more bit. */
            }
          tpdu[2] = apdulen;
          memcpy (tpdu+3, apdu, apdulen);
          crc = 0;
          for (i=0,p=tpdu; i < apdulen+3; i++)
            crc ^= *p++;
          tpdu[3+apdulen] = crc;
          
          tpdulen = apdulen + 4;
        }

      msg[0] = PC_to_RDR_XfrBlock;
      msg[5] = 0; /* slot */
      msg[6] = seqno = handle->seqno++;
      msg[7] = 4; /* bBWI */
      msg[8] = 0; /* RFU */
      msg[9] = 0; /* RFU */
      set_msg_len (msg, tpdulen);
      msglen = 10 + tpdulen;

      DEBUGOUT ("sending");
      for (i=0; i < msglen; i++)
        DEBUGOUT_CONT_1 (" %02X", msg[i]);
      DEBUGOUT_LF ();

#ifdef DEBUG_T1      
      fprintf (stderr, "T1: put %c-block seq=%d\n",
               ((msg[11] & 0xc0) == 0x80)? 'R' :
               (msg[11] & 0x80)? 'S' : 'I',
        ((msg[11] & 0x80)? !!(msg[11]& 0x10) : !!(msg[11] & 0x40)));
#endif  

      rc = bulk_out (handle, msg, msglen);
      if (rc)
        return rc;

      /* Fixme: The next line for the current Valgrid without support
         for USB IOCTLs. */
      memset (recv_buffer, 0, sizeof recv_buffer);

      msg = recv_buffer;
      rc = bulk_in (handle, msg, sizeof recv_buffer, &msglen,
                    RDR_to_PC_DataBlock, seqno);
      if (rc)
        return rc;
      
      tpdu = msg + 10;
      tpdulen = msglen - 10;
      
      if (tpdulen < 4) 
        {
          DEBUGOUT ("cannot yet handle short blocks!\n");
          return -1; 
        }

#ifdef DEBUG_T1
      fprintf (stderr, "T1: got %c-block seq=%d err=%d\n",
               ((msg[11] & 0xc0) == 0x80)? 'R' :
               (msg[11] & 0x80)? 'S' : 'I',
        ((msg[11] & 0x80)? !!(msg[11]& 0x10) : !!(msg[11] & 0x40)),
               ((msg[11] & 0xc0) == 0x80)? (msg[11] & 0x0f) : 0
               );
#endif

      if (!(tpdu[1] & 0x80))
        { /* This is an I-block. */
          
          if (sending)
            { /* last block sent was successful. */
              handle->t1_ns ^= 1;
              sending = 0;
            }

          if (!!(tpdu[1] & 0x40) != handle->t1_nr)
            { /* Reponse does not match our sequence number. */
              msg = send_buffer;
              tpdu = msg+10;
              tpdu[0] = ((1 << 4) | 0); /* NAD: DAD=1, SAD=0 */
              tpdu[1] = (0x80 | (handle->t1_nr & 1) << 4 | 2); /* R-block */
              tpdu[2] = 0;
              tpdulen = 3;
              for (crc=0,i=0,p=tpdu; i < tpdulen; i++)
                crc ^= *p++;
              tpdu[tpdulen++] = crc;

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
                  return -1;
                }
              
              memcpy (resp, p, n); 
              resp += n;
              *nresp += n;
              maxresplen -= n;
            }
          
          if (!(tpdu[1] & 0x20))
            return 0; /* No chaining requested - ready. */
          
          msg = send_buffer;
          tpdu = msg+10;
          tpdu[0] = ((1 << 4) | 0); /* NAD: DAD=1, SAD=0 */
          tpdu[1] = (0x80 | (handle->t1_nr & 1) << 4); /* R-block */
          tpdu[2] = 0;
          tpdulen = 3;
          for (crc=0,i=0,p=tpdu; i < tpdulen; i++)
            crc ^= *p++;
          tpdu[tpdulen++] = crc;
          
        }
      else if ((tpdu[1] & 0xc0) == 0x80)
        { /* This is a R-block. */
          if ( (tpdu[1] & 0x0f)) 
            { /* Error: repeat last block */
              msg = send_buffer;
            }
          else if (sending && !!(tpdu[1] & 0x40) == handle->t1_ns)
            { /* Reponse does not match our sequence number. */
              DEBUGOUT ("R-block with wrong seqno received on more bit\n");
              return -1;
            }
          else if (sending)
            { /* Send next chunk. */
              msg = send_buffer;
              next_chunk = 1;
              handle->t1_ns ^= 1;
            }
          else
            {
              DEBUGOUT ("unexpected ACK R-block received\n");
              return -1;
            }
        }
      else 
        { /* This is a S-block. */
          DEBUGOUT_2 ("T1 S-block %s received cmd=%d\n",
                      (tpdu[1] & 0x20)? "response": "request",
                      (tpdu[1] & 0x1f));
          if ( !(tpdu[1] & 0x20) && (tpdu[1] & 0x1f) == 3 && tpdu[2])
            { /* Wait time extension request. */
              unsigned char bwi = tpdu[3];
              msg = send_buffer;
              tpdu = msg+10;
              tpdu[0] = ((1 << 4) | 0); /* NAD: DAD=1, SAD=0 */
              tpdu[1] = (0xc0 | 0x20 | 3); /* S-block response */
              tpdu[2] = 1;
              tpdu[3] = bwi;
              tpdulen = 4;
              for (crc=0,i=0,p=tpdu; i < tpdulen; i++)
                crc ^= *p++;
              tpdu[tpdulen++] = crc;
              DEBUGOUT_1 ("T1 waittime extension of bwi=%d\n", bwi);
            }
          else
            return -1;
        }
    } /* end T=1 protocol loop. */

  return 0;
}




#ifdef TEST
int
main (int argc, char **argv)
{
  int rc;
  ccid_driver_t ccid;

  rc = ccid_open_reader (&ccid, 0);
  if (rc)
    return 1;

  ccid_poll (ccid);
  fputs ("getting ATR ...\n", stderr);
  rc = ccid_get_atr (ccid, NULL, 0, NULL);
  if (rc)
    return 1;

  ccid_poll (ccid);
  fputs ("getting slot status ...\n", stderr);
  rc = ccid_slot_status (ccid);
  if (rc)
    return 1;

  ccid_poll (ccid);

  {
    static unsigned char apdu[] = {
      0, 0xA4, 4, 0, 6, 0xD2, 0x76, 0x00, 0x01, 0x24, 0x01};
  rc = ccid_transceive (ccid,
                        apdu, sizeof apdu,
                        NULL, 0, NULL);
  }
  ccid_poll (ccid);

  {
    static unsigned char apdu[] = {
      0, 0xCA, 0, 0x65, 254 };
  rc = ccid_transceive (ccid,
                        apdu, sizeof apdu,
                        NULL, 0, NULL);
  }
  ccid_poll (ccid);


  return 0;
}

/*
 * Local Variables:
 *  compile-command: "gcc -DTEST -Wall -I/usr/local/include -lusb -g ccid-driver.c"
 * End:
 */
#endif /*TEST*/
#endif /*HAVE_LIBUSB*/
