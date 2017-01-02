/* packet-functions.h - Accessor functions for in-core representations.
 * Copyright (C) 2017 g10 Code GmbH
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

#ifndef G10_PACKET_FUNCTIONS_H
#define G10_PACKET_FUNCTIONS_H

#include "../common/logging.h"

static inline u32
kb_pk_set_expiredate (PKT_public_key *pk, u32 value)
{
  pk->expiredate = value;
  pk->flags.valid_expiredate = 1;
  return value;
}

static inline void
kb_pk_invalidate_expiredate (PKT_public_key *pk)
{
  pk->expiredate = 0;
  pk->flags.valid_expiredate = 0;
}

static inline int
kb_pk_valid_expiredate (PKT_public_key *pk)
{
  return pk->flags.valid_expiredate;
}

#define kb_pk_expiredate(PK)					\
  (log_assert ((PK)->flags.valid_expiredate), (PK)->expiredate)

#endif /*G10_PACKET_FUNCTIONS_H*/
