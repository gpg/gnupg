# Assuan Makefile for test purposes
# Copyright (C) 2001 Free Software Foundation, Inc.
#
# This file is part of GnuPG.
#
# GnuPG is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
# 
# GnuPG is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
# 
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA

## Process this file with automake to produce Makefile.in

EXTRA_DIST = mkerrors
INCLUDES = -I.. -I$(top_srcdir)/include
BUILT_SOURCES = assuan-errors.c

noinst_LIBRARIES = libassuan.a


#libassuan_a_LDFLAGS =
libassuan_a_SOURCES = \
	assuan.h \
	assuan-defs.h \
	assuan-util.c \
	assuan-errors.c \
	assuan-buffer.c \
	assuan-handler.c \
	assuan-inquire.c \
	assuan-listen.c \
	assuan-connect.c \
	assuan-client.c \
	assuan-pipe-server.c 


assuan-errors.c : assuan.h
	$(srcdir)/mkerrors < $(srcdir)/assuan.h > assuan-errors.c
