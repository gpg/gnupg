/* status.h
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
#ifndef G10_STATUS_H
#define G10_STATUS_H


#define STATUS_ENTER	 1
#define STATUS_LEAVE	 2
#define STATUS_ABORT	 3

#define STATUS_GOODSIG	 4
#define STATUS_BADSIG	 5
#define STATUS_ERRSIG	 6


#define STATUS_BADARMOR  7



/*-- status.c --*/
void set_status_fd( int fd );
void write_status( int no );


#endif /*G10_STATUS_H*/
