/* w32reg.c -  MS-Windows Registry access
 *	Copyright (C) 1999 Free Software Foundation, Inc.
 *
 * This file is part of GnuPG.
 *
 * GnuPG is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * GnuPG is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA
 */

#include <config.h>
#ifdef __MINGW32__  /* This module is only used in this environment */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <windows.h>
#include "util.h"
#include "memory.h"


/****************
 * Return a string from the Win32 Registry or NULL in case of
 * error.  Caller must release the return value.   A NUKK for root
 * is an alias fro HKEY_CURRENT_USER
 * NOTE: The value is allocated with a plain malloc() - use free() and not
 * the usual m_free()!!!
 */
char *
read_w32_registry_string( const char *root, const char *dir, const char *name )
{
    HKEY root_key, key_handle;
    DWORD n1, nbytes;
    char *result = NULL;

    if( !root )
	root_key = HKEY_CURRENT_USER;
    else if( !strcmp( root, "HKEY_CLASSES_ROOT" ) )
	root_key = HKEY_CLASSES_ROOT;
    else if( !strcmp( root, "HKEY_CURRENT_USER" ) )
	root_key = HKEY_CURRENT_USER;
    else if( !strcmp( root, "HKEY_LOCAL_MACHINE" ) )
	root_key = HKEY_LOCAL_MACHINE;
    else if( !strcmp( root, "HKEY_USERS" ) )
	root_key = HKEY_USERS;
    else if( !strcmp( root, "HKEY_PERFORMANCE_DATA" ) )
	root_key = HKEY_PERFORMANCE_DATA;
    else if( !strcmp( root, "HKEY_CURRENT_CONFIG" ) )
	root_key = HKEY_CURRENT_CONFIG;
    else
	return NULL;

    if( RegOpenKeyEx( root_key, dir, 0, KEY_READ, &key_handle ) )
	return NULL; /* no need for a RegClose, so return direct */

    nbytes = 1;
    if( RegQueryValueEx( key_handle, name, 0, NULL, NULL, &nbytes ) )
	goto leave;
    result = malloc( (n1=nbytes+1) );
    if( !result )
	goto leave;
    if( RegQueryValueEx( key_handle, name, 0, NULL, result, &n1 ) ) {
	free(result); result = NULL;
	goto leave;
    }
    result[nbytes] = 0; /* make sure it is really a string  */

  leave:
    RegCloseKey( key_handle );
    return result;
}





#endif /* __MINGW32__ */
