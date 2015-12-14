/* sh-exectool.h - Utility functions to execute a helper tool
 * Copyright (C) 2015 g10 Code GmbH
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
 * along with this program; if not, see <http://www.gnu.org/licenses/>.
 */

#ifndef GNUPG_COMMON_EXECTOOL_H
#define GNUPG_COMMON_EXECTOOL_H

#include <gpg-error.h>

/* Run the program PGMNAME with the command line arguments given in
   the NULL terminates array ARGV.  If INPUT_STRING is not NULL it
   will be fed to stdin of the process.  stderr is logged using
   log_info and the process' stdout is returned in a newly malloced
   buffer RESULT with the length stored at RESULTLEN if not given as
   NULL.  A hidden Nul is appended to the output.  On error NULL is
   stored at RESULT, a diagnostic is printed, and an error code
   returned.  */
gpg_error_t gnupg_exec_tool (const char *pgmname, const char *argv[],
                             const char *input_string,
                             char **result, size_t *resultlen);

/* Run the program PGMNAME with the command line arguments given in
   the NULL terminates array ARGV.  If INPUT is not NULL it will be
   fed to stdin of the process.  stderr is logged using log_info and
   the process' stdout is written to OUTPUT.  On error a diagnostic is
   printed, and an error code returned.  */
gpg_error_t gnupg_exec_tool_stream (const char *pgmname, const char *argv[],
				 estream_t input,
				 estream_t output);

#endif /* GNUPG_COMMON_EXECTOOL_H */
