/* memory.h - memory allocation
 *	Copyright (c) 1997 by Werner Koch (dd9jn)
 *
 * This file is part of G10.
 *
 * G10 is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * G10 is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA
 */

#ifndef G10_MEMORY_H
#define G10_MEMORY_H

#ifdef M_DEBUG
#ifndef STR
  #define STR(v) #v
#endif
#define M_DBGINFO(a)	    __FUNCTION__ "["__FILE__ ":"  STR(a) "]"
#define m_alloc(n)		m_debug_alloc((n), M_DBGINFO( __LINE__ ) )
#define m_alloc_clear(n)	m_debug_alloc_clear((n), M_DBGINFO(__LINE__) )
#define m_alloc_secure(n)	m_debug_alloc((n), M_DBGINFO(__LINE__) )
#define m_alloc_secure_clear(n) m_debug_alloc((n), M_DBGINFO(__LINE__) )
#define m_realloc(n,m)		m_debug_realloc((n),(m), M_DBGINFO(__LINE__) )
#define m_free(n)		m_debug_free((n), M_DBGINFO(__LINE__) )
#define m_check(n)		m_debug_check((n), M_DBGINFO(__LINE__) )

void *m_debug_alloc( size_t n, const char *info );
void *m_debug_alloc_clear( size_t n, const char *info  );
void *m_debug_alloc_secure( size_t n, const char *info	);
void *m_debug_alloc_secure_clear( size_t n, const char *info  );
void *m_debug_realloc( void *a, size_t n, const char *info  );
void m_debug_free( void *p, const char *info  );
void m_debug_check( const void *a, const char *info );

#else
void *m_alloc( size_t n );
void *m_alloc_clear( size_t n );
void *m_alloc_secure( size_t n );
void *m_alloc_secure_clear( size_t n );
void *m_realloc( void *a, size_t n );
void m_free( void *p );
void m_check( const void *a );
#endif


size_t m_size( const void *a );
int m_is_secure( const void *p );

#define DBG_MEMORY    memory_debug_mode
#define DBG_MEMSTAT   memory_stat_debug_mode
int memory_debug_mode;
int memory_stat_debug_mode;

#endif /*G10_MEMORY_H*/
