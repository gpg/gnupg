/* stream.c - Stream I/O/ layer
   Copyright (C) 2004 g10 Code GmbH

   This file is part of libgpg-stream.
 
   libgpg-stream is free software; you can redistribute it and/or
   modify it under the terms of the GNU General Public License as
   published by the Free Software Foundation; either version 2 of the
   License, or (at your option) any later version.
 
   libgpg-stream is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
   Lesser General Public License for more details.
 
   You should have received a copy of the GNU General Public License
   along with libgpg-stream; if not, write to the Free Software
   Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA
   02111-1307, USA.  */

#ifndef GPG_STREAM_CONFIG_H
#define GPG_STREAM_CONFIG_H

#define USE_PTH

#ifdef USE_PTH
#include <pth.h>

#define READ  pth_read
#define WRITE pth_write

#else

#include <unistd.h>

#define READ  read
#define WRITE write

#endif

#endif
