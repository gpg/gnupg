/* w32-afunix.c
 * Copyright (C) 2004 g10 Code GmbH
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
#ifdef _WIN32
#include <stdio.h>
#include <windows.h>
#include <io.h>

#include "w32-afunix.h"

int
_w32_close (int fd)
{
  int rc = closesocket (fd);
  if (rc && WSAGetLastError () == WSAENOTSOCK)
      rc = close (fd);
  return rc;
}


int
_w32_sock_new (int domain, int type, int proto)
{
  if (domain == AF_UNIX || domain == AF_LOCAL)
    domain = AF_INET;
  return socket (domain, type, proto);
}


int
_w32_sock_connect (int sockfd, struct sockaddr * addr, int addrlen)
{
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
}


int
_w32_sock_bind (int sockfd, struct sockaddr * addr, int addrlen)
{
  if (addr->sa_family == AF_LOCAL || addr->sa_family == AF_UNIX)
    {
      struct sockaddr_in myaddr;
      struct sockaddr_un * unaddr;
      FILE * fp;
      int len = sizeof myaddr;
      int rc;

      myaddr.sin_port = 0;
      myaddr.sin_family = AF_INET;
      myaddr.sin_addr.s_addr = htonl (INADDR_LOOPBACK);

      rc = bind (sockfd, (struct sockaddr *)&myaddr, len);
      if (rc)
        return rc;
      rc = getsockname (sockfd, (struct sockaddr *)&myaddr, &len);
      if (rc)
        return rc;
      unaddr = (struct sockaddr_un *)addr;
      fp = fopen (unaddr->sun_path, "wb");
      if (!fp)
        return -1;
      fprintf (fp, "%d", myaddr.sin_port);
      fclose (fp);

      /* we need this later. */
      unaddr->sun_family = myaddr.sin_family;
      unaddr->sun_port = myaddr.sin_port;
      unaddr->sun_addr.s_addr = myaddr.sin_addr.s_addr;
      
      return 0;
    }
  return bind (sockfd, addr, addrlen);
}

#endif /*_WIN32*/
