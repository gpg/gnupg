/* mime-parser.h - Parse MIME structures (high level rfc822 parser).
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

#ifndef GNUPG_MIME_PARSER_H
#define GNUPG_MIME_PARSER_H

#include "rfc822parse.h"

struct mime_parser_context_s;
typedef struct mime_parser_context_s *mime_parser_t;

gpg_error_t mime_parser_new (mime_parser_t *r_ctx, void *cookie);
void        mime_parser_release (mime_parser_t ctx);

void mime_parser_set_verbose (mime_parser_t ctx, int level);
void mime_parser_set_t2body (mime_parser_t ctx,
                             gpg_error_t (*fnc) (void *cookie, int level));
void mime_parser_set_new_part (mime_parser_t ctx,
                               gpg_error_t (*fnc) (void *cookie,
                                                   const char *mediatype,
                                                   const char *mediasubtype));
void mime_parser_set_part_data (mime_parser_t ctx,
                                gpg_error_t (*fnc) (void *cookie,
                                                    const void *data,
                                                    size_t datalen));
void mime_parser_set_collect_encrypted (mime_parser_t ctx,
                                        gpg_error_t (*fnc) (void *cookie,
                                                            const char *data));
void mime_parser_set_collect_signeddata (mime_parser_t ctx,
                                         gpg_error_t (*fnc) (void *cookie,
                                                             const char *data));
void mime_parser_set_collect_signature (mime_parser_t ctx,
                                        gpg_error_t (*fnc) (void *cookie,
                                                            const char *data));

gpg_error_t mime_parser_parse (mime_parser_t ctx, estream_t fp);


rfc822parse_t mime_parser_rfc822parser (mime_parser_t ctx);



#endif /*GNUPG_MIME_PARSER_H*/
