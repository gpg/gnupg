/* construct.c  -  RISC OS constructors for cipher algorithms
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

void rndriscos_constructor(void);
void sha1_constructor(void);
void rmd160_constructor(void);
void md5_constructor(void);

void
cipher_modules_constructor(void)
{
    static int done = 0;
    if( done )
        return;
    done = 1;

   rndriscos_constructor();
   sha1_constructor();
   rmd160_constructor();
   md5_constructor();
}
