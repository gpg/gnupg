/* rndriscos.c  -  raw random number for RISC OS
 *	Copyright (C) 2001 Free Software Foundation, Inc.
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

#ifdef USE_RNDRISCOS

#include <string.h>
#include <kernel.h>
#include <swis.h>
#include "util.h"

static int init_device(void);

#define CryptRandom_Byte 0x51980

static const char * const path[] = {
    "GnuPG:CryptRandom",
    "GnuPG:CryptRand",
    "System:Modules.CryptRandom"
    "System:Modules.CryptRand",
    NULL
};

/****************
 * Used to load the CryptRandom module if it isn't already loaded
 */
static int
init_device(void)
{
    int i;

    /* Is CryptRandom already loaded? */
    if (!_swix(OS_Module, _INR(0,1), 18, "CryptRandom"))
        return 1;

    /* Check all the places where the module could be located */
    for (i=0; path[i]; ++i)
        if (!_swix(OS_Module, _INR(0,1), 1, path[i]))
            return 1;

    /* Can't find CryptRandom in the default locations */
    g10_log_fatal("Can't load module CryptRandom.\n");

    return 0; /* never reached, but don't throw a warning */
}


/****************
 * Get the random bytes from module
 */
int
rndriscos_gather_random(void (*add)(const void*, size_t, int), int requester,
	                size_t length, int level)
{
    static int initialized = 0;
    int n;
    byte buffer[768];

    if (!initialized)
        initialized = init_device();

    while (length) {
        int nbytes = length < sizeof(buffer) ? length : sizeof(buffer);

        for (n = 0; n < nbytes; ++n)
            if (_swix(CryptRandom_Byte, _OUT(0), &buffer[n]))
                g10_log_fatal("CryptRandom module isn't working as expected!\n");

	(*add)(buffer, n, requester);
	length -= n;
    }
    wipememory(buffer, sizeof(buffer));

    return 0; /* success */
}

#endif /*USE_RNDRISCOS */
