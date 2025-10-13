/* argparse.h - Wrapper for the new argparse in gpgrt
 * Copyright (C) 2020 g10 Code GmbH
 *
 * This file is part of GnuPG.
 *
 * GnuPG is free software; you can redistribute and/or modify this
 * part of GnuPG under the terms of either
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
 * GnuPG is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copies of the GNU General Public License
 * and the GNU Lesser General Public License along with this program;
 * if not, see <https://www.gnu.org/licenses/>.
 */

#ifndef GNUPG_COMMON_ARGPARSE_H
#define GNUPG_COMMON_ARGPARSE_H

#include <stdio.h>
#include <gpgrt.h>

#define GNUPG_CONFDIR_USER GPGRT_CONFDIR_USER
#define GNUPG_CONFDIR_SYS  GPGRT_CONFDIR_SYS

typedef gpgrt_argparse_t gnupg_argparse_t;
typedef gpgrt_opt_t      gnupg_opt_t;
typedef gpgrt_argparse_t ARGPARSE_ARGS;
typedef gpgrt_opt_t      ARGPARSE_OPTS;

#define gnupg_argparse(a,b,c)            gpgrt_argparse ((a),(b),(c))
#define gnupg_argparser(a,b,c)           gpgrt_argparser ((a),(b),(c))
#define strusage(a)                      gpgrt_strusage (a)
#define set_strusage(a)                  gpgrt_set_strusage (a)
#define gnupg_set_usage_outfnc(a)        gpgrt_set_usage_outfnc ((a))
#define gnupg_set_fixed_string_mapper(a) gpgrt_set_fixed_string_mapper ((a))
#define gnupg_set_confdir(a,b)           gpgrt_set_confdir ((a),(b))

void usage (int level);

#endif /*GNUPG_COMMON_ARGPARSE_H*/
