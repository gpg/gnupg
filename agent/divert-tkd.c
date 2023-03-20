/* divert-tkd.c - divert operations to the tkdaemon
 *	Copyright (C) 2002, 2003, 2009 Free Software Foundation, Inc.
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

#include <config.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <assert.h>
#include <unistd.h>
#include <sys/stat.h>

#include "agent.h"
#include "../common/i18n.h"
#include "../common/sexp-parse.h"

int
divert_tkd_pksign (ctrl_t ctrl, const unsigned char *digest, size_t digestlen,
                   unsigned char **r_sig, size_t *r_siglen)
{
  return agent_tkd_pksign (ctrl, digest, digestlen, r_sig, r_siglen);
}

int
divert_tkd_cmd (ctrl_t ctrl, const char *cmdline)
{
  return agent_tkd_cmd (ctrl, cmdline);
}
