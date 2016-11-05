/* ccidmon.c - CCID monitor for use with the Linux usbmon facility.
 *	Copyright (C) 2009 Free Software Foundation, Inc.
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


/* This utility takes the output of usbmon, filters out the bulk data
   and prints the CCID messages in a human friendly way.

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
#include <unistd.h>
#include <signal.h>


#ifndef PACKAGE_VERSION
# define PACKAGE_VERSION "[build on " __DATE__ " " __TIME__ "]"
#endif
#ifndef PACKAGE_BUGREPORT
# define PACKAGE_BUGREPORT "devnull@example.org"
#endif
#define PGM "ccidmon"
#ifndef GNUPG_NAME
# define GNUPG_NAME "GnuPG"
#endif

/* Option flags. */
static int verbose;
static int debug;
static int skip_escape;
static int usb_bus, usb_dev;
static int sniffusb;


/* Error counter.  */
static int any_error;

/* Data storage.  */
struct
{
  int is_bi;
  char address[50];
  int count;
  char data[2000];
} databuffer;


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


#define digitp(p)   (*(p) >= '0' && *(p) <= '9')
#define hexdigitp(a) (digitp (a)                     \
                      || (*(a) >= 'A' && *(a) <= 'F')  \
                      || (*(a) >= 'a' && *(a) <= 'f'))
#define ascii_isspace(a) ((a)==' ' || (a)=='\n' || (a)=='\r' || (a)=='\t')
#define xtoi_1(p)   ((p) <= '9'? ((p)- '0'): \
                     (p) <= 'F'? ((p)-'A'+10):((p)-'a'+10))



/* Print diagnostic message and exit with failure. */
static void
die (const char *format, ...)
{
  va_list arg_ptr;

  fflush (stdout);
  fprintf (stderr, "%s: ", PGM);

  va_start (arg_ptr, format);
  vfprintf (stderr, format, arg_ptr);
  va_end (arg_ptr);
  putc ('\n', stderr);

  exit (1);
}


/* Print diagnostic message. */
static void
err (const char *format, ...)
{
  va_list arg_ptr;

  any_error = 1;

  fflush (stdout);
  fprintf (stderr, "%s: ", PGM);

  va_start (arg_ptr, format);
  vfprintf (stderr, format, arg_ptr);
  va_end (arg_ptr);
  putc ('\n', stderr);
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
print_pr_data (const unsigned char *data, size_t datalen, size_t off)
{
  int needlf = 0;
  int first = 1;

  for (; off < datalen; off++)
    {
      if (!(off % 16) || first)
        {
          if (needlf)
            putchar ('\n');
          printf ("  [%04lu] ", (unsigned long)off);
        }
      printf (" %02X", data[off]);
      needlf = 1;
      first = 0;
    }
  if (needlf)
    putchar ('\n');
}


static void
print_p2r_header (const char *name, const unsigned char *msg, size_t msglen)
{
  printf ("%s:\n", name);
  if (msglen < 7)
    return;
  printf ("  dwLength ..........: %u\n", convert_le_u32 (msg+1));
  printf ("  bSlot .............: %u\n", msg[5]);
  printf ("  bSeq ..............: %u\n", msg[6]);
}


static void
print_p2r_iccpoweron (const unsigned char *msg, size_t msglen)
{
  print_p2r_header ("PC_to_RDR_IccPowerOn", msg, msglen);
  if (msglen < 10)
    return;
  printf ("  bPowerSelect ......: 0x%02x (%s)\n", msg[7],
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
  printf ("  bBWI ..............: 0x%02x\n", msg[7]);
  val = convert_le_u16 (msg+8);
  printf ("  wLevelParameter ...: 0x%04x%s\n", val,
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
  printf ("  bProtocolNum ......: 0x%02x\n", msg[7]);
  print_pr_data (msg, msglen, 8);
}


static void
print_p2r_escape (const unsigned char *msg, size_t msglen)
{
  if (skip_escape)
    return;
  print_p2r_header ("PC_to_RDR_Escape", msg, msglen);
  print_pr_data (msg, msglen, 7);
}


static void
print_p2r_iccclock (const unsigned char *msg, size_t msglen)
{
  print_p2r_header ("PC_to_RDR_IccClock", msg, msglen);
  if (msglen < 10)
    return;
  printf ("  bClockCommand .....: 0x%02x\n", msg[7]);
  print_pr_data (msg, msglen, 8);
}


static void
print_p2r_to0apdu (const unsigned char *msg, size_t msglen)
{
  print_p2r_header ("PC_to_RDR_T0APDU", msg, msglen);
  if (msglen < 10)
    return;
  printf ("  bmChanges .........: 0x%02x\n", msg[7]);
  printf ("  bClassGetResponse .: 0x%02x\n", msg[8]);
  printf ("  bClassEnvelope ....: 0x%02x\n", msg[9]);
  print_pr_data (msg, msglen, 10);
}


static void
print_p2r_secure (const unsigned char *msg, size_t msglen)
{
  unsigned int val;

  print_p2r_header ("PC_to_RDR_Secure", msg, msglen);
  if (msglen < 10)
    return;
  printf ("  bBMI ..............: 0x%02x\n", msg[7]);
  val = convert_le_u16 (msg+8);
  printf ("  wLevelParameter ...: 0x%04x%s\n", val,
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
  printf ("  bFunction .........: 0x%02x\n", msg[7]);
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
  char buf[100];

  snprintf (buf, sizeof buf, "Unknown PC_to_RDR command 0x%02X",
            msglen? msg[0]:0);
  print_p2r_header (buf, msg, msglen);
  if (msglen < 10)
    return;
  print_pr_data (msg, msglen, 0);
}


static void
print_p2r (const unsigned char *msg, size_t msglen)
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


static void
print_r2p_header (const char *name, const unsigned char *msg, size_t msglen)
{
  printf ("%s:\n", name);
  if (msglen < 9)
    return;
  printf ("  dwLength ..........: %u\n", convert_le_u32 (msg+1));
  printf ("  bSlot .............: %u\n", msg[5]);
  printf ("  bSeq ..............: %u\n", msg[6]);
  printf ("  bStatus ...........: %u\n", msg[7]);
  if (msg[8])
    printf ("  bError ............: %u\n", msg[8]);
}


static void
print_r2p_datablock (const unsigned char *msg, size_t msglen)
{
  print_r2p_header ("RDR_to_PC_DataBlock", msg, msglen);
  if (msglen < 10)
    return;
  if (msg[9])
    printf ("  bChainParameter ...: 0x%02x%s\n", msg[9],
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
  printf ("  bClockStatus ......: 0x%02x%s\n", msg[9],
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

  printf ("  protocol ..........: T=%d\n", msg[9]);
  if (msglen == 17 && msg[9] == 1)
    {
      /* Protocol T=1.  */
      printf ("  bmFindexDindex ....: %02X\n", msg[10]);
      printf ("  bmTCCKST1 .........: %02X\n", msg[11]);
      printf ("  bGuardTimeT1 ......: %02X\n", msg[12]);
      printf ("  bmWaitingIntegersT1: %02X\n", msg[13]);
      printf ("  bClockStop ........: %02X\n", msg[14]);
      printf ("  bIFSC .............: %d\n", msg[15]);
      printf ("  bNadValue .........: %d\n", msg[16]);
    }
  else
    print_pr_data (msg, msglen, 10);
}


static void
print_r2p_escape (const unsigned char *msg, size_t msglen)
{
  if (skip_escape)
    return;
  print_r2p_header ("RDR_to_PC_Escape", msg, msglen);
  if (msglen < 10)
    return;
  printf ("  buffer[9] .........: %02X\n", msg[9]);
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
      printf ("  dwClockFrequency ..: %u\n", convert_le_u32 (msg+10));
      printf ("  dwDataRate ..... ..: %u\n", convert_le_u32 (msg+14));
      print_pr_data (msg, msglen, 18);
    }
  else
    print_pr_data (msg, msglen, 10);
}


static void
print_r2p_unknown (const unsigned char *msg, size_t msglen)
{
  char buf[100];

  snprintf (buf, sizeof buf, "Unknown RDR_to_PC command 0x%02X",
            msglen? msg[0]:0);
  print_r2p_header (buf, msg, msglen);
  if (msglen < 10)
    return;
  printf ("  bMessageType ......: %02X\n", msg[0]);
  printf ("  buffer[9] .........: %02X\n", msg[9]);
  print_pr_data (msg, msglen, 10);
}


static void
print_r2p (const unsigned char *msg, size_t msglen)
{
  switch (msglen? msg[0]:0)
    {
    case RDR_to_PC_DataBlock:
      print_r2p_datablock (msg, msglen);
      break;
    case RDR_to_PC_SlotStatus:
      print_r2p_slotstatus (msg, msglen);
      break;
    case RDR_to_PC_Parameters:
      print_r2p_parameters (msg, msglen);
      break;
    case RDR_to_PC_Escape:
      print_r2p_escape (msg, msglen);
      break;
    case RDR_to_PC_DataRate:
      print_r2p_datarate (msg, msglen);
      break;
    default:
      print_r2p_unknown (msg, msglen);
      break;
    }

}


static void
flush_data (void)
{
  if (!databuffer.count)
    return;

  if (verbose)
    printf ("Address: %s\n", databuffer.address);
  if (databuffer.is_bi)
    {
      print_r2p (databuffer.data, databuffer.count);
      if (verbose)
        putchar ('\n');
    }
  else
    print_p2r (databuffer.data, databuffer.count);

  databuffer.count = 0;
}

static void
collect_data (char *hexdata, const char *address, unsigned int lineno)
{
  size_t length;
  int is_bi;
  char *s;
  unsigned int value;

  is_bi = (*address && address[1] == 'i');

  if (databuffer.is_bi != is_bi || strcmp (databuffer.address, address))
    flush_data ();
  databuffer.is_bi = is_bi;
  if (strlen (address) >= sizeof databuffer.address)
    die ("address field too long");
  strcpy (databuffer.address, address);

  length = databuffer.count;
  for (s=hexdata; *s; s++ )
    {
      if (ascii_isspace (*s))
        continue;
      if (!hexdigitp (s))
        {
          err ("invalid hex digit in line %u - line skipped", lineno);
          break;
        }
      value = xtoi_1 (*s) * 16;
      s++;
      if (!hexdigitp (s))
        {
          err ("invalid hex digit in line %u - line skipped", lineno);
          break;
        }
      value += xtoi_1 (*s);

      if (length >= sizeof (databuffer.data))
        {
          err ("too much data at line %u - can handle only up to % bytes",
               lineno, sizeof (databuffer.data));
          break;
        }
      databuffer.data[length++] = value;
    }
  databuffer.count = length;
}


static void
parse_line (char *line, unsigned int lineno)
{
  char *p;
  char *event_type, *address, *data, *status, *datatag;

  if (debug)
    printf ("line[%u] ='%s'\n", lineno, line);

  p = strtok (line, " ");
  if (!p)
    die ("invalid line %d (no URB)");
  p = strtok (NULL, " ");
  if (!p)
    die ("invalid line %d (no timestamp)");
  event_type = strtok (NULL, " ");
  if (!event_type)
    die ("invalid line %d (no event type)");
  address = strtok (NULL, " ");
  if (!address)
    die ("invalid line %d (no address");
  if (usb_bus || usb_dev)
    {
      int bus, dev;

      p = strchr (address, ':');
      if (!p)
        die ("invalid line %d (invalid address");
      p++;
      bus = atoi (p);
      p = strchr (p, ':');
      if (!p)
        die ("invalid line %d (invalid address");
      p++;
      dev = atoi (p);

      if ((usb_bus && usb_bus != bus) || (usb_dev && usb_dev != dev))
        return;  /* We don't want that one.  */
    }
  if (*address != 'B' || (address[1] != 'o' && address[1] != 'i'))
    return; /* We only want block in and block out.  */
  status = strtok (NULL, " ");
  if (!status)
    return;
  if (!strchr ("-0123456789", *status))
    return; /* Setup packet.  */
  /* We don't support "Z[io]" types thus we don't need to check here.  */
  p = strtok (NULL, " ");
  if (!p)
    return; /* No data length.  */

  datatag = strtok (NULL, " ");
  if (datatag && *datatag == '=')
    {
      data = strtok (NULL, "");
      collect_data (data?data:"", address, lineno);
    }
}


static void
parse_line_sniffusb (char *line, unsigned int lineno)
{
  char *p;

  if (debug)
    printf ("line[%u] ='%s'\n", lineno, line);

  p = strtok (line, " \t");
  if (!p)
    return;
  p = strtok (NULL, " \t");
  if (!p)
    return;
  p = strtok (NULL, " \t");
  if (!p)
    return;

  if (hexdigitp (p+0) && hexdigitp (p+1)
      && hexdigitp (p+2) && hexdigitp (p+3)
      && p[4] == ':' && !p[5])
    {
      size_t length;
      unsigned int value;

      length = databuffer.count;
      while ((p=strtok (NULL, " \t")))
        {
          if (!hexdigitp (p+0) || !hexdigitp (p+1))
            {
              err ("invalid hex digit in line %u (%s)", lineno,p);
              break;
            }
          value = xtoi_1 (p[0]) * 16 + xtoi_1 (p[1]);

          if (length >= sizeof (databuffer.data))
            {
              err ("too much data at line %u - can handle only up to % bytes",
                   lineno, sizeof (databuffer.data));
              break;
            }
          databuffer.data[length++] = value;
        }
      databuffer.count = length;

    }
  else if (!strcmp (p, "TransferFlags"))
    {
      flush_data ();

      *databuffer.address = 0;
      while ((p=strtok (NULL, " \t(,)")))
        {
          if (!strcmp (p, "USBD_TRANSFER_DIRECTION_IN"))
            {
              databuffer.is_bi = 1;
              break;
            }
          else if (!strcmp (p, "USBD_TRANSFER_DIRECTION_OUT"))
            {
              databuffer.is_bi = 0;
              break;
            }
        }
    }

}


static void
parse_input (FILE *fp)
{
  char line[2000];
  size_t length;
  unsigned int lineno = 0;

  while (fgets (line, sizeof (line), fp))
    {
      lineno++;
      length = strlen (line);
      if (length && line[length - 1] == '\n')
	line[--length] = 0;
      else
        err ("line number %u too long or last line not terminated", lineno);
      if (length && line[length - 1] == '\r')
	line[--length] = 0;
      if (sniffusb)
        parse_line_sniffusb (line, lineno);
      else
        parse_line (line, lineno);
    }
  flush_data ();
  if (ferror (fp))
    err ("error reading input at line %u: %s", lineno, strerror (errno));
}


int
main (int argc, char **argv)
{
  int last_argc = -1;

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
        {
          fputs (PGM " (" GNUPG_NAME ") " PACKAGE_VERSION "\n", stdout);
          exit (0);
        }
      else if (!strcmp (*argv, "--help"))
        {
          puts ("Usage: " PGM " [BUS:DEV]\n"
                "Parse the output of usbmod assuming it is CCID compliant.\n\n"
                "  --skip-escape  do not show escape packets\n"
                "  --sniffusb     Assume output from Sniffusb.exe\n"
                "  --verbose      enable extra informational output\n"
                "  --debug        enable additional debug output\n"
                "  --help         display this help and exit\n\n"
                "Report bugs to " PACKAGE_BUGREPORT ".");
          exit (0);
        }
      else if (!strcmp (*argv, "--verbose"))
        {
          verbose = 1;
          argc--; argv++;
        }
      else if (!strcmp (*argv, "--debug"))
        {
          verbose = debug = 1;
          argc--; argv++;
        }
      else if (!strcmp (*argv, "--skip-escape"))
        {
          skip_escape = 1;
          argc--; argv++;
        }
      else if (!strcmp (*argv, "--sniffusb"))
        {
          sniffusb = 1;
          argc--; argv++;
        }
    }

  if (argc && sniffusb)
    die ("no arguments expected when using --sniffusb\n");
  else if (argc > 1)
    die ("usage: " PGM " [BUS:DEV]  (try --help for more information)\n");

  if (argc == 1)
    {
      const char *s = strchr (argv[0], ':');

      usb_bus = atoi (argv[0]);
      if (s)
        usb_dev =  atoi (s+1);
      if (usb_bus < 1 || usb_bus > 999 || usb_dev < 1 || usb_dev > 999)
        die ("invalid bus:dev specified");
    }


  signal (SIGPIPE, SIG_IGN);

  parse_input (stdin);

  return any_error? 1:0;
}


/*
Local Variables:
compile-command: "gcc -Wall -Wno-pointer-sign -g -o ccidmon ccidmon.c"
End:
*/
