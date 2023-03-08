/* ksba-io-support.h - Supporting functions for ksba reader and writer
 * Copyright (C) 2017  Werner Koch
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
 * SPDX-License-Identifier: (LGPL-3.0-or-later OR GPL-2.0-or-later)
 */

#ifndef GNUPG_KSBA_IO_SUPPORT_H
#define GNUPG_KSBA_IO_SUPPORT_H

/* Flags used with gnupg_ksba_create_reader and
 * gnupg_ksba_create_writer.  */
#define GNUPG_KSBA_IO_PEM         1  /* X.509 PEM format.  */
#define GNUPG_KSBA_IO_BASE64      2  /* Plain Base64 format.  */
#define GNUPG_KSBA_IO_AUTODETECT  4  /* Try to autodetect the format.  */
#define GNUPG_KSBA_IO_MULTIPEM    8  /* Allow more than one PEM chunk.  */
#define GNUPG_KSBA_IO_STRIP      16  /* Strip off zero padding.         */


/* Context object.  */
typedef struct gnupg_ksba_io_s *gnupg_ksba_io_t;

/* Progress callback type.  */
typedef gpg_error_t (*gnupg_ksba_progress_cb_t)(ctrl_t ctrl,
                                                uint64_t current,
                                                uint64_t total);


gpg_error_t gnupg_ksba_create_reader (gnupg_ksba_io_t *ctx,
                                      unsigned int flags,
                                      estream_t fp,
                                      ksba_reader_t *r_reader);

int gnupg_ksba_reader_eof_seen (gnupg_ksba_io_t ctx);
void gnupg_ksba_destroy_reader (gnupg_ksba_io_t ctx);

gpg_error_t gnupg_ksba_create_writer (gnupg_ksba_io_t *ctx,
                                      unsigned int flags,
                                      const char *pem_name,
                                      estream_t stream,
                                      ksba_writer_t *r_writer);
gpg_error_t gnupg_ksba_finish_writer (gnupg_ksba_io_t ctx);
void gnupg_ksba_destroy_writer (gnupg_ksba_io_t ctx);

void gnupg_ksba_set_progress_cb (gnupg_ksba_io_t ctx,
                                 gnupg_ksba_progress_cb_t cb, ctrl_t ctrl);
void gnupg_ksba_set_total (gnupg_ksba_io_t ctx, uint64_t total);




#endif /*GNUPG_KSBA_IO_SUPPORT_H*/
