/* assuan-socket.c
 * Copyright (C) 2004 Free Software Foundation, Inc.
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

/* Please note that this is a stripped down and modified version of
   the orginal Assuan code from libassuan. */

#include <config.h>
#include <stdio.h>
#ifdef HAVE_W32_SYSTEM
#include <windows.h>
#include <io.h>
#else
#include <sys/types.h>
#include <sys/socket.h>
#endif
#include "assuan-defs.h"

int
_assuan_close (int fd)
{
#ifndef HAVE_W32_SYSTEM
  return close (fd);
#else
  int rc = closesocket (fd);
  if (rc && WSAGetLastError () == WSAENOTSOCK)
      rc = close (fd);
  return rc;
#endif
}


int
_assuan_sock_new (int domain, int type, int proto)
{
#ifndef HAVE_W32_SYSTEM
  return socket (domain, type, proto);
#else
  if (domain == AF_UNIX || domain == AF_LOCAL)
    domain = AF_INET;
  return socket (domain, type, proto);
#endif
}


int
_assuan_sock_connect (int sockfd, struct sockaddr * addr, int addrlen)
{
#ifndef HAVE_W32_SYSTEM
  return connect (sockfd, addr, addrlen);
#else
  struct sockaddr_in myaddr;
  struct sockaddr_un * unaddr;
  FILE * fp;
  int port = 0;
  
  unaddr = (struct sockaddr_un *)addr;
  fp = fopen (unaddr->sun_path, "rb");
  if (!fp)
      return -1;
  fscanf (fp, "%d", &port);
  fclose (fp);
  /* XXX: set errno in this case */
  if (port < 0 || port > 65535)
      return -1;
  
  myaddr.sin_family = AF_INET;
  myaddr.sin_port = port; 
  myaddr.sin_addr.s_addr = htonl (INADDR_LOOPBACK);

  /* we need this later. */
  unaddr->sun_family = myaddr.sin_family;
  unaddr->sun_port = myaddr.sin_port;
  unaddr->sun_addr.s_addr = myaddr.sin_addr.s_addr;
  
  return connect (sockfd, (struct sockaddr *)&myaddr, sizeof myaddr);
#endif
}


