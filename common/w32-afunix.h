/* w32-afunix.h - AF_UNIX emulation for Windows
 *	Copyright (C) 2004, 2006 g10 Code GmbH
 *
 * This file is part of GnuPG.
 *
 * GnuPG is free software; you can redistribute it and/or modify it
 * under the terms of either
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
 * GnuPG is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copies of the GNU General Public License
 * and the GNU Lesser General Public License along with this program;
 * if not, see <http://www.gnu.org/licenses/>.
 */

#ifdef _WIN32
#ifndef W32AFUNIX_DEFS_H
#define W32AFUNIX_DEFS_H

#include <sys/types.h>
#include <windows.h>
#include <ws2tcpip.h>
#include <unistd.h>

/* We can easiliy replace this code by the socket wrappers from libassuan.  */
#warning Remove this code; it is only used on w32 by symcryptrun.

#define DIRSEP_C '\\'

#define AF_LOCAL AF_UNIX
/* We need to prefix the structure with a sockaddr_in header so we can
   use it later for sendto and recvfrom. */
struct sockaddr_un
{
  short          sun_family;
  unsigned short sun_port;
  struct         in_addr sun_addr;
  char           sun_path[108-2-4]; /* Path name.  */
};


int _w32_close (int fd);
int _w32_sock_new (int domain, int type, int proto);
int _w32_sock_connect (int sockfd, struct sockaddr *addr, int addrlen);


#endif /*W32AFUNIX_DEFS_H*/
#endif /*_WIN32*/
