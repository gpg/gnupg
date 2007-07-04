/* w32main.h - W32 main entry point and support functions
 * Copyright (C) 2007 Free Software Foundation, Inc.
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
 * along with this program; if not, see <http://www.gnu.org/licenses/>.
 */

#ifndef AGENT_W32MAIN_H
#define AGENT_W32MAIN_H

/* This is the actual entry point as called by w32main.c.  */
int w32_main (int argc, char **argv );

/* Fire up the icon for the taskbar.  */
int w32_setup_taskbar (void);

void w32_poll_events (void);


#endif /*AGENT_W32MAIN_H*/
