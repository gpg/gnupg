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

#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <kernel.h>
#include <swis.h>
#include "util.h"
#include "algorithms.h"

static int init_device(void);

#define CryptRandom_Byte 0x51980

/****************
 * Used to load the CryptRandom module if it isn't already loaded
 */
static int
init_device(void)
{
    _kernel_swi_regs r;

    /* Is CryptRandom already loaded? */
    r.r[0] = 18;
    r.r[1] = (int) "CryptRandom";
    if (!_kernel_swi(OS_Module, &r, &r))
        return 1;

    /* Is it named CryptRand and inside GnuPG$Path? */
    r.r[0] = 1;
    r.r[1] = (int) "GnuPG:CryptRand";
    if (!_kernel_swi(OS_Module, &r, &r))
        return 1;

    /* Is it named CryptRandom and inside GnuPG$Path? */
    r.r[0] = 1;
    r.r[1] = (int) "GnuPG:CryptRandom";
    if (!_kernel_swi(OS_Module, &r, &r))
        return 1;

    /* Can't find CryptRandom in the default locations */
    g10_log_fatal("Can't load module CryptRandom.\n");
}


/****************
 */
int
rndriscos_gather_random(void (*add)(const void*, size_t, int), int requester,
	                size_t length, int level)
{
    static int initialized = 0;
    int n;
    byte buffer[768];
    _kernel_swi_regs r;
    _kernel_oserror *e;

    if (!initialized)
        initialized = init_device();

    while (length) {
        int nbytes = length < sizeof(buffer) ? length : sizeof(buffer);

        for (n = 0; n < nbytes; n++) {
            if (e = _kernel_swi(CryptRandom_Byte, &r, &r))
                g10_log_fatal("CryptRandom module isn't working as expected!\n");
            buffer[n] = (byte) r.r[0];
        }

	(*add)(buffer, n, requester);
	length -= n;
    }
    memset(buffer, 0, sizeof(buffer));

    return 0; /* success */
}

#endif /*USE_RNDRISCOS */
