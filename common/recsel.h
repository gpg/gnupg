/* recsel.c - Record selection
 * Copyright (C) 2016 Werner Koch
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
#ifndef GNUPG_COMMON_RECSEL_H
#define GNUPG_COMMON_RECSEL_H

struct recsel_expr_s;
typedef struct recsel_expr_s *recsel_expr_t;

gpg_error_t recsel_parse_expr (recsel_expr_t *selector, const char *expr);
void recsel_release (recsel_expr_t a);
void recsel_dump (recsel_expr_t selector);
int recsel_select (recsel_expr_t selector,
                   const char *(*getval)(void *cookie, const char *propname),
                   void *cookie);


#endif /*GNUPG_COMMON_RECSEL_H*/
