/* pref.h
 *	Copyright (C) 1998 Free Software Foundation, Inc.
 *
 * This file is part of GNUPG.
 *
 * GNUPG is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * GNUPG is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA
 */

#ifndef G10_PREF_H
#define G10_PREF_H 1

/* a structure to hold information abopu preferred algorithms */
typedef struct pref_list_s *PREF_LIST;
#ifndef DEFINES_PREF_LIST
struct pref_list_s { char preference_stuff[1]; };
#endif


PREF_LIST new_pref_list(void);
void release_pref_list( PREF_LIST pref );









#endif /*G10_PREF_H*/
