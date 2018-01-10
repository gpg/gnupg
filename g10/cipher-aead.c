/* cipher-aead.c - Enciphering filter for AEAD modes
 * Copyright (C) 2018 Werner koch
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
 * SPDX-License-Identifier: GPL-3.0+
 */

#include <config.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>

#include "gpg.h"
#include "../common/status.h"
#include "../common/iobuf.h"
#include "../common/util.h"
#include "filter.h"
#include "packet.h"
#include "options.h"
#include "main.h"


/*
 * This filter is used to encipher data with an AEAD algorithm
 */
int
cipher_filter_aead (void *opaque, int control,
                   iobuf_t a, byte *buf, size_t *ret_len)
{
  cipher_filter_context_t *cfx = opaque;
  size_t size = *ret_len;
  int rc = 0;

  if (control == IOBUFCTRL_UNDERFLOW) /* decrypt */
    {
      rc = -1; /* not yet used */
    }
  else if (control == IOBUFCTRL_FLUSH) /* encrypt */
    {
      log_assert (a);
      rc = GPG_ERR_NOT_IMPLEMENTED;
    }
  else if (control == IOBUFCTRL_FREE)
    {
      gcry_cipher_close (cfx->cipher_hd);
    }
  else if (control == IOBUFCTRL_DESC)
    {
      mem2str (buf, "cipher_filter_aead", *ret_len);
    }

  return rc;
}
