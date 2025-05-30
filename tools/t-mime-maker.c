/* t-mime-maker.c - Module test for mime-maker.c
 * Copyright (C) 2025 g10 Code GmbH
 *
 * This file is part of GnuPG.
 *
 * This file is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as
 * published by the Free Software Foundation; either version 2.1 of
 * the License, or (at your option) any later version.
 *
 * This file is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with this program; if not, see <https://www.gnu.org/licenses/>.
 * SPDX-License-Identifier: LGPL-2.1-or-later
 */

#include <config.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>

#include "../common/util.h"
#include "../common/init.h"
#include "mime-maker.h"


static int verbose;



static void
test_qp_encode (void)
{
  static struct
  {
    const char *plain;
    const char *encoded;
  } samples[] =
    {
      { "",
        ""
      },{
        "From someone\n"
        " I received this mail\n",
        "=46rom someone\n"
        " I received this mail\n"
      },{
        " From someone\n",
        " From someone\n"
      },{
        "Foo\n"
        ".\n",
        "Foo\n"
        "=2E\n"
      },{
        "Foo\n"
        ".",
        "Foo\n"
        "=2E"
      },{
        "Hello ÄÖÜ§äöüß my dear umlauts",
        "Hello =C3=84=C3=96=C3=9C=C2=A7=C3=A4=C3=B6=C3=BC=C3=9F "
        "my dear umlauts"
      },{
        "👀\tⒶ",
        "=F0=9F=91=80\t=E2=92=B6"
      }
    };
  int idx;
  char *result;
  int oops = 0;

  for (idx=0; idx < DIM (samples); idx++)
    {
      result = mime_maker_qp_encode (samples[idx].plain);
      if (!result)
        {
          log_error ("%s:test %d: error: %s\n",
                     __func__, idx, strerror (errno));
          exit (1);
        }
      if (strcmp (samples[idx].encoded, result))
        {
          log_error ("%s:test %d: error\nwant ===>%s<===\n got ===>%s<===\n",
                     __func__, idx, samples[idx].plain, result);
          oops = 1;
        }
    }

  if (oops)
    exit (1);
}


int
main (int argc, char **argv)
{
  log_set_prefix ("t-mime-maker", GPGRT_LOG_WITH_PREFIX);
  init_common_subsystems (&argc, &argv);

  if (argc)
    { argc--; argv++; }
  if (argc && !strcmp (argv[0], "--verbose"))
    {
      verbose = 1;
      argc--; argv++;
    }

  test_qp_encode ();

  return 0;
}
