/* mime-maker.h - Create MIME structures
 * Copyright (C) 2016 g10 Code GmbH
 * Copyright (C) 2016 Bundesamt für Sicherheit in der Informationstechnik
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
 */

#ifndef GNUPG_MIME_MAKER_H
#define GNUPG_MIME_MAKER_H

struct mime_maker_context_s;
typedef struct mime_maker_context_s *mime_maker_t;

gpg_error_t mime_maker_new (mime_maker_t *r_ctx, void *cookie);
void        mime_maker_release (mime_maker_t ctx);

void mime_maker_set_verbose (mime_maker_t ctx, int level);

void mime_maker_dump_tree (mime_maker_t ctx);

gpg_error_t mime_maker_add_header (mime_maker_t ctx,
                                   const char *name, const char *value);
gpg_error_t mime_maker_add_body (mime_maker_t ctx, const char *string);
gpg_error_t mime_maker_add_body_data (mime_maker_t ctx,
                                      const void *data, size_t datalen);
gpg_error_t mime_maker_add_stream (mime_maker_t ctx, estream_t *stream_addr);
gpg_error_t mime_maker_add_container (mime_maker_t ctx);
gpg_error_t mime_maker_end_container (mime_maker_t ctx);
unsigned int mime_maker_get_partid (mime_maker_t ctx);

gpg_error_t mime_maker_make (mime_maker_t ctx, estream_t fp);
gpg_error_t mime_maker_get_part (mime_maker_t ctx, unsigned int partid,
                                 estream_t *r_stream);



#endif /*GNUPG_MIME_MAKER_H*/
