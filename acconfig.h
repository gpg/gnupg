/* acconfig.h - used by autoheader to make config.h.in
 *	Copyright (c) 1997 by Werner Koch (dd9jn)
 *
 * This file is part of G10.
 *
 * G10 is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * G10 is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA
 */
#ifndef G10_CONFIG_H
#define G10_CONFIG_H


@TOP@

#undef M_DEBUG
#undef VERSION
#undef PACKAGE

#undef BIG_ENDIAN_HOST
#undef LITTLE_ENDIAN_HOST

#undef HAVE_BYTE_TYPEDEF
#undef HAVE_USHORT_TYPEDEF
#undef HAVE_ULONG_TYPEDEF
#undef HAVE_U16_TYPEDEF
#undef HAVE_U32_TYPEDEF


/* RSA is only compiled in if you have these files. You can use
 * RSA without any restrictions, if your not in the U.S. or
 * wait until sep 20, 2000
 */
#undef HAVE_RSA_CIPHER


@BOTTOM@


#endif /*G10_CONFIG_H*/
