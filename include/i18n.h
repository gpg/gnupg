/* i18n.h
 *	Copyright (C) 1998, 1999, 2000, 2001 Free Software Foundation, Inc.
 *
 * This file is part of GNUPG.
 *
 * GNUPG is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 *
 * GNUPG is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, see <http://www.gnu.org/licenses/>.
 */

#ifndef G10_I18N_H
#define G10_I18N_H

#ifdef USE_SIMPLE_GETTEXT
int set_gettext_file( const char *filename, const char *regkey );
const char *gettext( const char *msgid );

#define _(a) gettext (a)
#define N_(a) (a)

#else
#ifdef HAVE_LOCALE_H
#include <locale.h>	/* suggested by Ernst Molitor */
#endif

#ifdef ENABLE_NLS
#ifndef __riscos__
#include <libintl.h>
#else
#include "libgettext.h"
#endif /* __riscos__ */
#define _(a) gettext (a)
#ifdef gettext_noop
#define N_(a) gettext_noop (a)
#else
#define N_(a) (a)
#endif
#else
#define _(a) (a)
#define N_(a) (a)
#endif
#endif /* !USE_SIMPLE_GETTEXT */

#endif /*G10_I18N_H*/
