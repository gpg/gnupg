/* ccid-driver.c - USB ChipCardInterfaceDevices driver
 *	Copyright (C) 2003, 2004 Free Software Foundation, Inc.
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

   This driver has been tested with the SCM SCR335 and SPR532
   smartcard readers and requires that a reader implements the TPDU
   level exchange and does fully automatic initialization.
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

/* Define to print information pertaining the T=1 protocol. */
#undef DEBUG_T1 


# define DEBUGOUT(t)         do { if (debug_level) \
                                  log_debug (DRVNAME t); } while (0)
# define DEBUGOUT_1(t,a)     do { if (debug_level) \
                                  log_debug (DRVNAME t,(a)); } while (0)
# define DEBUGOUT_2(t,a,b)   do { if (debug_level) \
                                  log_debug (DRVNAME t,(a),(b)); } while (0)
# define DEBUGOUT_3(t,a,b,c) do { if (debug_level) \
                                  log_debug (DRVNAME t,(a),(b),(c));} while (0)
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
struct ccid_driver_s 
{
  usb_dev_handle *idev;
  char *rid;
  int seqno;
  unsigned char t1_ns;
  unsigned char t1_nr;
  int nonnull_nad;
  int auto_ifsd;
  int max_ifsd;
  int ifsd;
  int has_pinpad;
};


static int initialized_usb; /* Tracks whether USB has been initialized. */
static int debug_level;     /* Flag to control the debug output.  */


static unsigned int compute_edc (const unsigned char *data, size_t datalen,
                                 int use_crc);
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
    DEBUGOUT ("    Auto parameter negotation made by CCID\n");
  else if ((us & 0x0080))
    DEBUGOUT ("    Auto PPS made by CCID\n");
  else if ((us & (0x0040 | 0x0080)))
    DEBUGOUT ("    WARNING: conflicting negotation features\n");

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

  /* Fixme: The next line for the current Valgrid without support
     for USB IOCTLs. */
  memset (buf, 0, sizeof buf);

  /* First get the list of supported languages and use the first one.
     If we do don't find it we try to use English.  Note that this is
     all in a 2 bute Unicode encoding using little endian. */
  rc = usb_control_msg (idev, USB_ENDPOINT_IN, USB_REQ_GET_DESCRIPTOR,
                        (USB_DT_STRING << 8), 0, 
                        buf, sizeof buf, 1000 /* ms timeout */);
  if (rc < 4)
    langid = 0x0409; /* English.  */
  else
    langid = (buf[3] << 8) | buf[2];

  rc = usb_control_msg (idev, USB_ENDPOINT_IN, USB_REQ_GET_DESCRIPTOR,
                        (USB_DT_STRING << 8) + idx, langid,
                        buf, sizeof buf, 1000 /* ms timeout */);
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

  sprintf (prefix, "%04X:%04X:", (vendor & 0xfff), (product & 0xffff));
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


/* Combination function to either scan all CCID devices or to find and
   open one specific device. 

   With READERNO = -1 and READERID is NULL, scan mode is used and
   R_RID should be the address where to store the list of reader_ids
   we found.  If on return this list is empty, no CCID device has been
   found; otherwise it points to an allocated linked list of reader
   IDs.  Note that in this mode the function always returns NULL.

   With READERNO >= 0 or READERID is not NULL find mode is used.  This
   uses the same algorithm as the scan mode but stops and returns at
   the entry number READERNO and return the handle for the the opened
   USB device. If R_ID is not NULL it will receive the reader ID of
   that device.  If R_DEV is not NULL it will the device pointer of
   that device.  If IFCDESC_EXTRA is NOT NULL it will receive a
   malloced copy of the interfaces "extra: data filed;
   IFCDESC_EXTRA_LEN receive the lengtyh of this field.  If there is
   no reader with number READERNO or that reader is not usable by our
   implementation NULL will be returned.  The caller must close a
   returned USB device handle and free (if not passed as NULL) the
   returned reader ID info as well as the IFCDESC_EXTRA.  On error
   NULL will get stored at R_RID, R_DEV, IFCDESC_EXTRA and
   IFCDESC_EXTRA_LEN.  With READERID being -1 the function stops if
   the READERID was found.

   Note that the first entry of the returned reader ID list in scan mode
   corresponds with a READERNO of 0 in find mode.
*/
static usb_dev_handle *
scan_or_find_devices (int readerno, const char *readerid,
                      char **r_rid,
                      struct usb_device **r_dev,
                      unsigned char **ifcdesc_extra,
                      size_t *ifcdesc_extra_len)
{
  char *rid_list = NULL;
  int count = 0;
  struct usb_bus *busses, *bus;
  struct usb_device *dev = NULL;
  usb_dev_handle *idev = NULL;
  int scan_mode = (readerno == -1 && !readerid);

   /* Set return values to a default. */
  if (r_rid)
    *r_rid = NULL;
  if (r_dev)
    *r_dev = NULL; 
  if (ifcdesc_extra)
    *ifcdesc_extra = NULL;
  if (ifcdesc_extra_len)
    *ifcdesc_extra_len = 0;

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
          int cfg_no;
          
          for (cfg_no=0; cfg_no < dev->descriptor.bNumConfigurations; cfg_no++)
            {
              struct usb_config_descriptor *config = dev->config + cfg_no;
              int ifc_no;

              if(!config)
                continue;

              for (ifc_no=0; ifc_no < config->bNumInterfaces; ifc_no++)
                {
                  struct usb_interface *interface
                    = config->interface + ifc_no;
                  int set_no;
                  
                  if (!interface)
                    continue;
                  
                  for (set_no=0; set_no < interface->num_altsetting; set_no++)
                    {
                      struct usb_interface_descriptor *ifcdesc
                        = interface->altsetting + set_no;
                      char *rid;
                      
                      /* The second condition is for some SCM Micro
                         SPR 532 which does not know about the
                         assigned CCID class. Instead of trying to
                         interpret the strings we simply look at the
                         product ID. */
                      if (ifcdesc && ifcdesc->extra
                          && (   (ifcdesc->bInterfaceClass == 11
                                  && ifcdesc->bInterfaceSubClass == 0
                                  && ifcdesc->bInterfaceProtocol == 0)
                              || (ifcdesc->bInterfaceClass == 255
                                  && dev->descriptor.idVendor == 0x04e6
                                  && dev->descriptor.idProduct == 0xe003
                                  && ifcdesc->bInterfaceSubClass == 1
                                  && ifcdesc->bInterfaceProtocol == 1)))
                        {
                          idev = usb_open (dev);
                          if (!idev)
                            {
                              DEBUGOUT_1 ("usb_open failed: %s\n",
                                          strerror (errno));
                              continue;
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
                                     available CCID readers.  Store
                                     them and continue. */
                                  DEBUGOUT_2 ("found CCID reader %d "
                                              "(ID=%s)\n",
                                              count, rid );
                                  if ((p = malloc ((rid_list?
                                                    strlen (rid_list):0)
                                                   + 1 + strlen (rid)
                                                   + 1)))
                                    {
                                      *p = 0;
                                      if (rid_list)
                                        {
                                          strcat (p, rid_list);
                                          free (rid_list);
                                        }
                                      strcat (p, rid);
                                      strcat (p, "\n");
                                      rid_list = p;
                                    }
                                  else /* Out of memory. */
                                    free (rid);
                                  rid = NULL;
                                  count++;
                                }
                              else if (!readerno
                                       || (readerno < 0
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
                                          return NULL; /* Out of core. */
                                        }
                                      memcpy (*ifcdesc_extra, ifcdesc->extra,
                                              ifcdesc->extralen);
                                      *ifcdesc_extra_len = ifcdesc->extralen;
                                    }

                                  if (r_dev)
                                    *r_dev = dev;
                                  if (r_rid)
                                    {
                                      *r_rid = rid;
                                      rid = NULL;
                                    }
                                  else
                                    free (rid);
                                  return idev; /* READY. */
                                }
                              else
                                {
                                  /* This is not yet the reader we
                                     want.  fixme: We could avoid the
                                     extra usb_open in this case. */
                                  if (readerno >= 0)
                                    readerno--;
                                }
                              free (rid);
                            }
                          
                          usb_close (idev);
                          idev = NULL;
                          goto next_device;
                        }
                    }
                }
            }
        next_device:
          ;
        }
    }

  if (scan_mode)
    *r_rid = rid_list;

  return NULL;
}


/* Set the level of debugging to to usea dn return the old level.  -1
   just returns the old level.  A level of 0 disables debugging, 1
   enables debugging, other values are not yet defined. */
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

  scan_or_find_devices (-1, NULL, &reader_list, NULL, NULL, NULL);
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
  char *rid = NULL;
  unsigned char *ifcdesc_extra = NULL;
  size_t ifcdesc_extra_len;
  int readerno;

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

  idev = scan_or_find_devices (readerno, readerid, &rid, &dev,
                               &ifcdesc_extra, &ifcdesc_extra_len);
  if (!idev)
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
  (*handle)->idev = idev;
  (*handle)->rid = rid;

  DEBUGOUT_2 ("using CCID reader %d (ID=%s)\n",  readerno, rid );


  if (parse_ccid_descriptor (*handle, ifcdesc_extra, ifcdesc_extra_len))
    {
      DEBUGOUT ("device not supported\n");
      rc = CCID_DRIVER_ERR_NO_READER;
      goto leave;
    }
  
  /* fixme: Do we need to claim and set the interface as
     determined above? */
  rc = usb_claim_interface (idev, 0);
  if (rc)
    {
      DEBUGOUT_1 ("usb_claim_interface failed: %d\n", rc);
      rc = CCID_DRIVER_ERR_CARD_IO_ERROR;
      goto leave;
    }
  
  /* FIXME: Do we need to get the endpoint addresses from the
     structure and store them with the handle? */
              
 leave:
  free (ifcdesc_extra);
  if (rc)
    {
      free (rid);
      if (idev)
        usb_close (idev);
      free (*handle);
      *handle = NULL;
    }

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
  free (handle->rid);
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
  return CCID_DRIVER_ERR_CARD_IO_ERROR;
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

  /* Fixme: The next line for the current Valgrind without support
     for USB IOCTLs. */
  memset (buffer, 0, length);
 retry:
  rc = usb_bulk_read (handle->idev, 
                      0x82,
                      buffer, length,
                      10000 /* ms timeout */ );
  /* Fixme: instead of using a 10 second timeout we should better
     handle the timeout here and retry if appropriate.  */
  if (rc < 0)
    {
      DEBUGOUT_1 ("usb_bulk_read error: %s\n", strerror (errno));
      return CCID_DRIVER_ERR_CARD_IO_ERROR;
    }

  *nread = msglen = rc;

  if (msglen < 10)
    {
      DEBUGOUT_1 ("bulk-in msg too short (%u)\n", (unsigned int)msglen);
      return CCID_DRIVER_ERR_INV_VALUE;
    }
  if (buffer[0] != expected_type)
    {
      DEBUGOUT_1 ("unexpected bulk-in msg type (%02x)\n", buffer[0]);
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
      return CCID_DRIVER_ERR_INV_VALUE;
    }

  if ( !(buffer[7] & 0x03) && (buffer[7] & 0xC0) == 0x80)
    { 
      /* Card present and active, time extension requested. */
      DEBUGOUT_2 ("time extension requested (%02X,%02X)\n",
                  buffer[7], buffer[8]);
      goto retry;
    }
  
  DEBUGOUT_3 ("status: %02X  error: %02X  octet[9]: %02X\n"
              "               data:",  buffer[7], buffer[8], buffer[9] );
  for (i=10; i < msglen; i++)
    DEBUGOUT_CONT_1 (" %02X", buffer[i]);
  DEBUGOUT_LF ();

  switch ((buffer[7] & 0x03))
    {
    case 0: /* no error */ break;
    case 1: return CCID_DRIVER_ERR_CARD_INACTIVE;
    case 2: return CCID_DRIVER_ERR_NO_CARD;
    case 3: /* RFU */ break;
    }
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


/* Note that this fucntion won't return the error codes NO_CARD or
   CARD_INACTIVE */
int 
ccid_slot_status (ccid_driver_t handle, int *statusbits)
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
  if (rc && rc != CCID_DRIVER_ERR_NO_CARD
      && rc != CCID_DRIVER_ERR_CARD_INACTIVE)
    return rc;
  *statusbits = (msg[7] & 3);

  return 0;
}


int 
ccid_get_atr (ccid_driver_t handle,
              unsigned char *atr, size_t maxatrlen, size_t *atrlen)
{
  int rc;
  unsigned char msg[100];
  unsigned char *tpdu;
  size_t msglen, tpdulen;
  unsigned char seqno;
  int use_crc = 0;
  unsigned int edc;
  int i;

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

  /* Setup parameters to select T=1. */
  msg[0] = PC_to_RDR_SetParameters;
  msg[5] = 0; /* slot */
  msg[6] = seqno = handle->seqno++;
  msg[7] = 1; /* Select T=1. */
  msg[8] = 0; /* RFU */
  msg[9] = 0; /* RFU */

  /* FIXME: Get those values from the ATR. */
  msg[10]= 0x01; /* Fi/Di */
  msg[11]= 0x10; /* LRC, direct convention. */
  msg[12]= 0;    /* Extra guardtime. */
  msg[13]= 0x41; /* BWI/CWI */
  msg[14]= 0;    /* No clock stoppping. */
  msg[15]= 254;  /* IFSC */
  msg[16]= 0;    /* Does not support non default NAD values. */
  set_msg_len (msg, 7);
  msglen = 10 + 7;

  DEBUGOUT ("sending");
  for (i=0; i < msglen; i++)
    DEBUGOUT_CONT_1 (" %02X", msg[i]);
  DEBUGOUT_LF ();

  rc = bulk_out (handle, msg, msglen);
  if (rc)
    return rc;
  /* Note that we ignore the error code on purpose. */
  bulk_in (handle, msg, sizeof msg, &msglen, RDR_to_PC_Parameters, seqno);


  /* Send an S-Block with our maximun IFSD to the CCID.  */
  if (!handle->auto_ifsd)
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


      rc = bulk_in (handle, msg, sizeof msg, &msglen,
                    RDR_to_PC_DataBlock, seqno);
      if (rc)
        return rc;
      
      tpdu = msg + 10;
      tpdulen = msglen - 10;
      
      if (tpdulen < 4) 
        return CCID_DRIVER_ERR_ABORTED; 

#ifdef DEBUG_T1
      fprintf (stderr, "T1: got %c-block seq=%d err=%d\n",
               ((msg[11] & 0xc0) == 0x80)? 'R' :
               (msg[11] & 0x80)? 'S' : 'I',
               ((msg[11] & 0x80)? !!(msg[11]& 0x10) : !!(msg[11] & 0x40)),
               ((msg[11] & 0xc0) == 0x80)? (msg[11] & 0x0f) : 0
               );
#endif
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
  unsigned char send_buffer[10+259], recv_buffer[10+259];
  const unsigned char *apdu;
  size_t apdulen;
  unsigned char *msg, *tpdu, *p;
  size_t msglen, tpdulen, last_tpdulen, n;
  unsigned char seqno;
  int i;
  unsigned int edc;
  int use_crc = 0;
  size_t dummy_nresp;
  int next_chunk = 1;
  int sending = 1;
  int retries = 0;

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
            return CCID_DRIVER_ERR_INV_VALUE; /* Invalid length. */

          tpdu = msg+10;
          /* NAD: DAD=1, SAD=0 */
          tpdu[0] = handle->nonnull_nad? ((1 << 4) | 0): 0;
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
          tpdulen = 3 + apdulen;
          edc = compute_edc (tpdu, tpdulen, use_crc);
          if (use_crc)
            tpdu[tpdulen++] = (edc >> 8);
          tpdu[tpdulen++] = edc;
        }

      msg[0] = PC_to_RDR_XfrBlock;
      msg[5] = 0; /* slot */
      msg[6] = seqno = handle->seqno++;
      msg[7] = 4; /* bBWI */
      msg[8] = 0; /* RFU */
      msg[9] = 0; /* RFU */
      set_msg_len (msg, tpdulen);
      msglen = 10 + tpdulen;
      last_tpdulen = tpdulen;

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

      msg = recv_buffer;
      rc = bulk_in (handle, msg, sizeof recv_buffer, &msglen,
                    RDR_to_PC_DataBlock, seqno);
      if (rc)
        return rc;
      
      tpdu = msg + 10;
      tpdulen = msglen - 10;
      
      if (tpdulen < 4) 
        {
          usb_clear_halt (handle->idev, 0x82);
          return CCID_DRIVER_ERR_ABORTED; 
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
          retries = 0;
          if (sending)
            { /* last block sent was successful. */
              handle->t1_ns ^= 1;
              sending = 0;
            }

          if (!!(tpdu[1] & 0x40) != handle->t1_nr)
            { /* Reponse does not match our sequence number. */
              msg = send_buffer;
              tpdu = msg+10;
              /* NAD: DAD=1, SAD=0 */
              tpdu[0] = handle->nonnull_nad? ((1 << 4) | 0): 0;
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
          tpdu = msg+10;
          /* NAD: DAD=1, SAD=0 */
          tpdu[0] = handle->nonnull_nad? ((1 << 4) | 0): 0;
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
            { /* Error: repeat last block */
              if (++retries > 3)
                {
                  DEBUGOUT ("3 failed retries\n");
                  return CCID_DRIVER_ERR_CARD_IO_ERROR;
                }
              msg = send_buffer;
              tpdulen = last_tpdulen;
            }
          else if (sending && !!(tpdu[1] & 0x40) == handle->t1_ns)
            { /* Reponse does not match our sequence number. */
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
          DEBUGOUT_2 ("T1 S-block %s received cmd=%d\n",
                      (tpdu[1] & 0x20)? "response": "request",
                      (tpdu[1] & 0x1f));
          if ( !(tpdu[1] & 0x20) && (tpdu[1] & 0x1f) == 3 && tpdu[2])
            { /* Wait time extension request. */
              unsigned char bwi = tpdu[3];
              msg = send_buffer;
              tpdu = msg+10;
              /* NAD: DAD=1, SAD=0 */
              tpdu[0] = handle->nonnull_nad? ((1 << 4) | 0): 0;
              tpdu[1] = (0xc0 | 0x20 | 3); /* S-block response */
              tpdu[2] = 1;
              tpdu[3] = bwi;
              tpdulen = 4;
              edc = compute_edc (tpdu, tpdulen, use_crc);
              if (use_crc)
                tpdu[tpdulen++] = (edc >> 8);
              tpdu[tpdulen++] = edc;
              DEBUGOUT_1 ("T1 waittime extension of bwi=%d\n", bwi);
            }
          else
            return CCID_DRIVER_ERR_CARD_IO_ERROR;
        }
    } /* end T=1 protocol loop. */

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
  unsigned int slotstat;
  unsigned char result[512];
  size_t resultlen;

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
          ccid_set_debug_level (1);
          argc--; argv++;
        }
      else
        break;
    }

  rc = ccid_open_reader (&ccid, argc? *argv:NULL);
  if (rc)
    return 1;

  ccid_poll (ccid);
  fputs ("getting ATR ...\n", stderr);
  rc = ccid_get_atr (ccid, NULL, 0, NULL);
  if (rc)
    {
      print_error (rc);
      return 1;
    }

  ccid_poll (ccid);
  fputs ("getting slot status ...\n", stderr);
  rc = ccid_slot_status (ccid, &slotstat);
  if (rc)
    {
      print_error (rc);
      return 1;
    }

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
  

  ccid_poll (ccid);

  fputs ("getting OpenPGP DO 0x65 ....\n", stderr);
  {
    static unsigned char apdu[] = { 0, 0xCA, 0, 0x65, 254 };
    rc = ccid_transceive (ccid, apdu, sizeof apdu,
                          result, sizeof result, &resultlen);
    print_result (rc, result, resultlen);
  }

  ccid_poll (ccid);

/*   if (!ccid->has_pinpad) */
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
/*   else */
/*     { */
/*       fputs ("verifying CHV1 using the PINPad ....\n", stderr); */
/*       { */
/*         rc = ccid_secure_transceive (ccid, */
/*                                      result, sizeof result, &resultlen); */
/*         print_result (rc, result, resultlen); */
/*       } */
/*     } */

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
