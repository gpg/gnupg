/* openpgp-s2ks.c - OpenPGP S2K helper functions
 * Copyright (C) 1998, 1999, 2000, 2001, 2002, 2003, 2004,
 *               2005, 2006 Free Software Foundation, Inc.
 * Copyright (C) 2010, 2019 g10 Code GmbH
 *
 * This file is part of GnuPG.
 *
 * This file is free software; you can redistribute it and/or modify
 * it under the terms of either
 *
 *   - the GNU Lesser General Public License as published by the Free
 *     Software Foundation; either version 3 of the License, or (at
 *     your option) any later version.
 *
 * or
 *
 *   - the GNU General Public License as published by the Free
 *     Software Foundation; either version 2 of the License, or (at
 *     your option) any later version.
 *
 * or both in parallel, as here.
 *
 * This file is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, see <https://www.gnu.org/licenses/>.
 */

#include <config.h>
#include <stdlib.h>
#include <errno.h>
#include <ctype.h>
#include <assert.h>

#include "util.h"
#include "openpgpdefs.h"


/* Pack an s2k iteration count into the form specified in RFC-4880.
 * If we're in between valid values, round up.  */
unsigned char
encode_s2k_iterations (int iterations)
{
  unsigned char c=0;
  unsigned char result;
  unsigned int count;

  if (iterations <= 1024)
    return 0;  /* Command line arg compatibility.  */

  if (iterations >= 65011712)
    return 255;

  /* Need count to be in the range 16-31 */
  for (count=iterations>>6; count>=32; count>>=1)
    c++;

  result = (c<<4)|(count-16);

  if (S2K_DECODE_COUNT(result) < iterations)
    result++;

  return result;
}
