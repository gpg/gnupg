/* card-yubikey.c - Yubikey specific functions.
 * Copyright (C) 2019 g10 Code GmbH
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
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

#include <config.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>

#include "../common/util.h"
#include "../common/i18n.h"
#include "../common/tlv.h"
#include "../common/ttyio.h"
#include "gpg-card.h"


/* Object to describe requested interface options.  */
struct iface_s {
  unsigned int usb:1;
  unsigned int nfc:1;
};


/* Bit flags as used by the fields in struct ykapps_s. */
#define YKAPP_USB_SUPPORTED  0x01
#define YKAPP_USB_ENABLED    0x02
#define YKAPP_NFC_SUPPORTED  0x04
#define YKAPP_NFC_ENABLED    0x08
#define YKAPP_SELECTED       0x80  /* Selected by the command.  */

/* An object to describe the applications on a Yubikey.  Each field
 * has 8 bits to hold the above flag values.  */
struct ykapps_s {
  unsigned int otp:8;
  unsigned int u2f:8;
  unsigned int opgp:8;
  unsigned int piv:8;
  unsigned int oath:8;
  unsigned int fido2:8;
};



/* Helper to parse an unsigned integer config value consisting of bit
 * flags.  TAG select the config item and MASK is the mask ORed into
 * the value for a set bit.  The function modifies YK.  */
static gpg_error_t
parse_ul_config_value (struct ykapps_s *yk,
                       const unsigned char *config, size_t configlen,
                       int tag, unsigned int mask)
{
  const unsigned char *s;
  size_t n;
  unsigned long ul = 0;
  int i;

  s = find_tlv (config, configlen, tag, &n);
  if (s && n)
    {
      if (n > sizeof ul)
        {
          log_error ("too large integer in Yubikey config tag %02x detected\n",
                     tag);
          if (opt.verbose)
            log_printhex (config, configlen, "config:");
          return gpg_error (GPG_ERR_CARD);
        }
      for (i=0; i < n; i++)
        {
          ul <<=8;
          ul |= s[i];
        }
      if (ul & 0x01)
        yk->otp |= mask;
      if (ul & 0x02)
        yk->u2f |= mask;
      if (ul & 0x08)
        yk->opgp |= mask;
      if (ul & 0x10)
        yk->piv |= mask;
      if (ul & 0x20)
        yk->oath |= mask;
      if (ul & 0x200)
        yk->fido2 |= mask;
    }
  return 0;
}


/* Create an unsigned integer config value for TAG from the data in YK
 * and store it the provided 4 byte buffer RESULT. If ENABLE is true
 * the respective APP_SELECTED bit in YK sets the corresponding bit
 * flags, it is is false that bit flag is cleared.  IF APP_SELECTED is
 * not set the bit flag is not changed.  */
static void
set_ul_config_value (struct ykapps_s *yk,
                     unsigned int bitflag, int tag, unsigned int enable,
                     unsigned char *result)
{
  unsigned long ul = 0;

  /* First set the current values.  */
  if ((yk->otp & bitflag))
    ul |= 0x01;
  if ((yk->u2f & bitflag))
    ul |= 0x02;
  if ((yk->opgp & bitflag))
    ul |= 0x08;
  if ((yk->piv & bitflag))
    ul |= 0x10;
  if ((yk->oath & bitflag))
    ul |= 0x20;
  if ((yk->fido2 & bitflag))
    ul |= 0x200;

  /* Then enable or disable the bits according to the selection flag.  */
  if (enable)
    {
      if ((yk->otp & YKAPP_SELECTED))
        ul |= 0x01;
      if ((yk->u2f & YKAPP_SELECTED))
        ul |= 0x02;
      if ((yk->opgp & YKAPP_SELECTED))
        ul |= 0x08;
      if ((yk->piv & YKAPP_SELECTED))
        ul |= 0x10;
      if ((yk->oath & YKAPP_SELECTED))
        ul |= 0x20;
      if ((yk->fido2 & YKAPP_SELECTED))
        ul |= 0x200;
    }
  else
    {
      if ((yk->otp & YKAPP_SELECTED))
        ul &= ~0x01;
      if ((yk->u2f & YKAPP_SELECTED))
        ul &= ~0x02;
      if ((yk->opgp & YKAPP_SELECTED))
        ul &= ~0x08;
      if ((yk->piv & YKAPP_SELECTED))
        ul &= ~0x10;
      if ((yk->oath & YKAPP_SELECTED))
        ul &= ~0x20;
      if ((yk->fido2 & YKAPP_SELECTED))
        ul &= ~0x200;
    }

  /* Make sure that we do not disable the CCID transport.  Without
   * CCID we won't have any way to change the configuration again.  We
   * would instead need one of the other Yubikey tools to enable an
   * application and thus its transport again.  */
  if (bitflag == YKAPP_USB_ENABLED && !(ul & (0x08|0x10|0x20)))
    {
      log_info ("Enabling PIV to have at least one CCID transport\n");
      ul |= 0x10;
    }

  result[0] = tag;
  result[1] = 2;
  result[2] = ul >> 8;
  result[3] = ul;
}


/* Print the info from YK.  */
static void
yk_list (estream_t fp, struct ykapps_s *yk)
{
  if (opt.interactive)
    tty_fprintf (fp, ("Application  USB    NFC\n"
                      "-----------------------\n"));
  tty_fprintf (fp, "OTP          %s    %s\n",
               (yk->otp & YKAPP_USB_SUPPORTED)?
               (yk->otp & YKAPP_USB_ENABLED?   "yes" : "no ") : "-  ",
               (yk->otp & YKAPP_NFC_SUPPORTED)?
               (yk->otp & YKAPP_NFC_ENABLED?   "yes" : "no ") : "-  ");
  tty_fprintf (fp, "U2F          %s    %s\n",
               (yk->otp & YKAPP_USB_SUPPORTED)?
               (yk->otp & YKAPP_USB_ENABLED?   "yes" : "no ") : "-  ",
               (yk->otp & YKAPP_NFC_SUPPORTED)?
               (yk->otp & YKAPP_NFC_ENABLED?   "yes" : "no ") : "-  ");
  tty_fprintf (fp, "OPGP         %s    %s\n",
               (yk->opgp & YKAPP_USB_SUPPORTED)?
               (yk->opgp & YKAPP_USB_ENABLED?  "yes" : "no ") : "-  ",
               (yk->opgp & YKAPP_NFC_SUPPORTED)?
               (yk->opgp & YKAPP_NFC_ENABLED?  "yes" : "no ") : "-  ");
  tty_fprintf (fp, "PIV          %s    %s\n",
               (yk->piv & YKAPP_USB_SUPPORTED)?
               (yk->piv & YKAPP_USB_ENABLED?   "yes" : "no ") : "-  ",
               (yk->piv & YKAPP_NFC_SUPPORTED)?
               (yk->piv & YKAPP_NFC_ENABLED?   "yes" : "no ") : "-  ");
  tty_fprintf (fp, "OATH         %s    %s\n",
               (yk->oath & YKAPP_USB_SUPPORTED)?
               (yk->oath & YKAPP_USB_ENABLED?  "yes" : "no ") : "-  ",
               (yk->oath & YKAPP_NFC_SUPPORTED)?
               (yk->oath & YKAPP_NFC_ENABLED?  "yes" : "no ") : "-  ");
  tty_fprintf (fp, "FIDO2        %s    %s\n",
               (yk->fido2 & YKAPP_USB_SUPPORTED)?
               (yk->fido2 & YKAPP_USB_ENABLED? "yes" : "no ") : "-  ",
               (yk->fido2 & YKAPP_NFC_SUPPORTED)?
               (yk->fido2 & YKAPP_NFC_ENABLED? "yes" : "no ") : "-  ");
}


/* Enable disable the apps as marked in YK with flag YKAPP_SELECTED.  */
static gpg_error_t
yk_enable_disable (struct ykapps_s *yk, struct iface_s *iface,
                   const unsigned char *config, size_t configlen, int enable)
{
  gpg_error_t err = 0;
  unsigned char apdu[100];
  unsigned int apdulen;
  /* const unsigned char *s; */
  /* size_t n; */
  char *hexapdu = NULL;

  apdulen = 0;
  apdu[apdulen++] = 0x00;
  apdu[apdulen++] = 0x1c;  /* Write Config instruction.  */
  apdu[apdulen++] = 0x00;
  apdu[apdulen++] = 0x00;
  apdu[apdulen++] = 0x00;  /* Lc will be fixed up later.  */
  apdu[apdulen++] = 0x00;  /* Length of data will also be fixed up later.  */

  /* The ykman tool has no way to set NFC and USB flags in one go.
   * Reasoning about the Yubikey's firmware it seems plausible that
   * combining should work.  Let's try it here if the user called for
   * setting both interfaces.  */
  if (iface->nfc)
    {
      set_ul_config_value (yk, YKAPP_NFC_ENABLED, 0x0e, enable, apdu+apdulen);
      apdulen += 4;
    }
  if (iface->usb)
    {
      set_ul_config_value (yk, YKAPP_USB_ENABLED, 0x03, enable, apdu+apdulen);
      apdulen += 4;
      /* Yubikey's ykman copies parts of the config data when writing
       * the config for USB.  Below is a commented example on how that
       * can be done.  */
      (void)config;
      (void)configlen;
      /* Copy the device flags.  */
      /* s = find_tlv (config, configlen, 0x08, &n); */
      /* if (s && n) */
      /*   { */
      /*     s -= 2; */
      /*     n += 2; */
      /*     if (apdulen + n > sizeof apdu) */
      /*       { */
      /*         err = gpg_error (GPG_ERR_BUFFER_TOO_SHORT); */
      /*         goto leave; */
      /*       } */
      /*     memcpy (apdu+apdulen, s, n); */
      /*     apdulen += n; */
      /*   } */
    }
  if (iface->nfc || iface->usb)
    {
      if (apdulen + 2 > sizeof apdu)
        {
          err = gpg_error (GPG_ERR_BUFFER_TOO_SHORT);
          goto leave;
        }
      /* Disable the next two lines to let the card reboot.  Not doing
       * this is however more convenient for this tool because further
       * commands don't end up with an error.  It seems to be better
       * that a "reset" command from gpg-card-tool is run at the
       * user's discretion.  */
      /* apdu[apdulen++] = 0x0c;  /\* Reboot tag *\/ */
      /* apdu[apdulen++] = 0;     /\* No data for reboot.  *\/ */
      /* Fixup the lngth bytes.  */
      apdu[4] = apdulen - 6 + 1;
      apdu[5] = apdulen - 6;

      hexapdu = bin2hex (apdu, apdulen, NULL);
      if (!hexapdu)
        err = gpg_error_from_syserror ();
      else
        err = send_apdu (hexapdu, "YK.write_config", 0, NULL, NULL);
    }

 leave:
  xfree (hexapdu);
  return err;
}


/* Implementation part of cmd_yubikey.  ARGV is an array of size ARGc
 * with the argumets given to the yubikey command.  Note that ARGV has
 * no terminating NULL so that ARGC must be considered.  FP is the
 * stream to output information.  This function must only be called on
 * Yubikeys. */
gpg_error_t
yubikey_commands (card_info_t info, estream_t fp, int argc, const char *argv[])
{
  gpg_error_t err;
  enum {ykLIST, ykENABLE, ykDISABLE } cmd;
  struct iface_s iface = {0,0};
  struct ykapps_s ykapps = {0};
  unsigned char *config = NULL;
  size_t configlen;
  int i;

  if (!argc)
    return gpg_error (GPG_ERR_SYNTAX);

  /* Parse command.  */
  if (!ascii_strcasecmp (argv[0], "list"))
    cmd = ykLIST;
  else if (!ascii_strcasecmp (argv[0], "enable"))
    cmd = ykENABLE;
  else if (!ascii_strcasecmp (argv[0], "disable"))
    cmd = ykDISABLE;
  else
    {
      log_info ("Please use \"%s\" to list the available sub-commands\n",
                "help yubikey");
      err = gpg_error (GPG_ERR_UNKNOWN_COMMAND);
      goto leave;
    }

  if (info->cardversion < 0x050000 && cmd != ykLIST)
    {
      log_info ("Sub-command '%s' is only support by Yubikey-5 and later\n",
                argv[0]);
      err = gpg_error (GPG_ERR_NOT_SUPPORTED);
      goto leave;
    }

  /* Parse interface if needed.  */
  if (cmd == ykLIST)
    iface.usb = iface.nfc = 1;
  else if (argc < 2)
    {
      err = gpg_error (GPG_ERR_SYNTAX);
      goto leave;
    }
  else if (!ascii_strcasecmp (argv[1], "usb"))
    iface.usb = 1;
  else if (!ascii_strcasecmp (argv[1], "nfc"))
    iface.nfc = 1;
  else if (!ascii_strcasecmp (argv[1], "all") || !strcmp (argv[1], "*"))
    iface.usb = iface.nfc = 1;
  else
    {
      err = gpg_error (GPG_ERR_SYNTAX);
      goto leave;
    }

  /* Parse list of applications.  */
  for (i=2; i < argc; i++)
    {
      if (!ascii_strcasecmp (argv[i], "otp"))
        ykapps.otp = 0x80;
      else if (!ascii_strcasecmp (argv[i], "u2f"))
        ykapps.u2f = 0x80;
      else if (!ascii_strcasecmp (argv[i], "opgp")
               ||!ascii_strcasecmp (argv[i], "openpgp"))
        ykapps.opgp = 0x80;
      else if (!ascii_strcasecmp (argv[i], "piv"))
        ykapps.piv = 0x80;
      else if (!ascii_strcasecmp (argv[i], "oath")
               || !ascii_strcasecmp (argv[i], "oauth"))
        ykapps.oath = 0x80;
      else if (!ascii_strcasecmp (argv[i], "fido2"))
        ykapps.fido2 = 0x80;
      else if (!ascii_strcasecmp (argv[i], "all")|| !strcmp (argv[i], "*"))
        {
          ykapps.otp = ykapps.u2f = ykapps.opgp = ykapps.piv = ykapps.oath
            = ykapps.fido2 = 0x80;
        }
      else
        {
          err = gpg_error (GPG_ERR_SYNTAX);
          goto leave;
        }
    }

  /* Select the Yubikey Manager application.  */
  err = send_apdu ("00A4040008a000000527471117", "Select.YK-Manager", 0,
                   NULL, NULL);
  if (err)
    goto leave;
  /* Send the read config command.  */
  err = send_apdu ("001D000000", "YK.read_config", 0, &config, &configlen);
  if (err)
    goto leave;
  if (!configlen || *config > configlen - 1)
    {
      /* The length byte is shorter than the actual length. */
      log_error ("Yubikey returned improper config data\n");
      log_printhex (config, configlen, "config:");
      err = gpg_error (GPG_ERR_CARD);
      goto leave;
    }
  if (configlen-1 > *config)
    {
      log_info ("Extra config data ignored\n");
      log_printhex (config, configlen, "config:");
    }
  configlen = *config;

  err = parse_ul_config_value (&ykapps, config+1, configlen,
                               0x01, YKAPP_USB_SUPPORTED);
  if (!err)
    err = parse_ul_config_value (&ykapps, config+1, configlen,
                                 0x03, YKAPP_USB_ENABLED);
  if (!err)
    err = parse_ul_config_value (&ykapps, config+1, configlen,
                                 0x0d, YKAPP_NFC_SUPPORTED);
  if (!err)
    err = parse_ul_config_value (&ykapps, config+1, configlen,
                                 0x0e, YKAPP_NFC_ENABLED);
  if (err)
    goto leave;

  switch (cmd)
    {
    case ykLIST: yk_list (fp, &ykapps); break;
    case ykENABLE: err = yk_enable_disable (&ykapps, &iface,
                                            config+1, configlen, 1); break;
    case ykDISABLE: err = yk_enable_disable (&ykapps, &iface,
                                             config+1, configlen, 0); break;
    }

 leave:
  xfree (config);
  return err;
}
