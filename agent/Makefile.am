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

bin_PROGRAMS = gpg-agent

INCLUDES = -I$(top_srcdir)/common -I$(top_srcdir)/intl
LDFLAGS = @LDFLAGS@ 

gpg_agent_SOURCES = \
	gpg-agent.c agent.h \
	command.c \
	pksign.c 

gpg_agent_LDADD = ../jnlib/libjnlib.a ../assuan/libassuan.a  \
              ../../libgcrypt/src/.libs/libgcrypt.so.1 



