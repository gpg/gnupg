/* mpi-add.c  -  MPI functions
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

#include <config.h>
#include <stdio.h>
#include <stdlib.h>

#include "mpi-internal.h"


/****************
 * Add the unsigned integer V to the mpi-integer U and store the
 * result in W. U and V may be the same.
 */
void
mpi_add_ui(MPI w, MPI u, unsigned long v )
{
    mpi_ptr_t wp, up;
    mpi_size_t usize, wsize;
    int usign, wsign;

    usize = u->nlimbs;
    usign = u->sign;
    wsign = 0;

    /* If not space for W (and possible carry), increase space.  */
    wsize = usize + 1;
    if( w->alloced < wsize )
	mpi_resize(w, wsize);

    /* These must be after realloc (U may be the same as W).  */
    up = u->d;
    wp = w->d;

    if( !usize ) {  /* simple */
	wp[0] = v;
	wsize = v? 1:0;
    }
    else if( !usign ) {  /* mpi is not negative */
	mpi_limb_t cy;
	cy = mpihelp_add_1(wp, up, usize, v);
	wp[usize] = cy;
	wsize = usize + cy;
    }
    else {  /* The signs are different.  Need exact comparison to determine
	     * which operand to subtract from which.  */
	if( usize == 1 && up[0] < v ) {
	    wp[0] = v - up[0];
	    wsize = 1;
	}
	else {
	    mpihelp_sub_1(wp, up, usize, v);
	    /* Size can decrease with at most one limb. */
	    wsize = (usize - (wp[usize-1]? 0:1));
	    wsign = 1;
	}
    }

    w->nlimbs = wsize;
    w->sign   = wsign;
}


void
mpi_add(MPI w, MPI u, MPI v)
{
    mpi_ptr_t wp, up, vp;
    mpi_size_t usize, vsize, wsize;
    int usign, vsign, wsign;

    usize = u->nlimbs;
    vsize = v->nlimbs;
    usign = u->sign;
    vsign = v->sign;

    if( usize < vsize ) { /* Swap U and V. */
	{ MPI t; t = u; u = v; v = t; }
	{ mpi_size_t t = usize; usize = vsize; vsize = t; }
	{ int t = usign; usign = vsign; vsign = t; }
    }

    /* If not space for w (and possible carry), increase space.  */
    wsize = usize + 1;
    if( w->alloced < wsize )
	mpi_resize(w, wsize);
    wsign = 0;

    /* These must be after realloc (u or v may be the same as w).  */
    up = u->d;
    vp = v->d;
    wp = w->d;

    if( !vsize ) {  /* simple */
	MPN_COPY(wp, up, usize );
	wsize = usize;
	wsign = usign;
    }
    else if( usign != vsign ) { /* different sign */
	/* This test is right since USIZE >= VSIZE */
	if( usize != vsize ) {
	    mpihelp_sub(wp, up, usize, vp, vsize);
	    wsize = usize;
	    MPN_NORMALIZE(wp, wsize);
	    wsign = usign;
	}
	else if( mpihelp_cmp(up, vp, usize) < 0 ) {
	    mpihelp_sub_n(wp, vp, up, usize);
	    wsize = usize;
	    MPN_NORMALIZE(wp, wsize);
	    if( !usign )
		wsign = 1;
	}
	else {
	    mpihelp_sub_n(wp, up, vp, usize);
	    wsize = usize;
	    MPN_NORMALIZE(wp, wsize);
	    if( usign )
		wsign = 1;
	}
    }
    else { /* U and V have same sign. Add them. */
	mpi_limb_t cy = mpihelp_add(wp, up, usize, vp, vsize);
	wp[usize] = cy;
	wsize = usize + cy;
	if( usign )
	    wsize = 1;
    }

    w->nlimbs = wsize;
    w->sign = wsign;
}


/****************
 * Subtract the unsigned integer V from the mpi-integer U and store the
 * result in W.
 */
void
mpi_sub_ui(MPI w, MPI u, unsigned long v )
{
    mpi_ptr_t wp, up;
    mpi_size_t usize, wsize;
    int usign, wsign;

    usize = u->nlimbs;
    usign = u->sign;
    wsign = 0;

    /* If not space for W (and possible carry), increase space.  */
    wsize = usize + 1;
    if( w->alloced < wsize )
	mpi_resize(w, wsize);

    /* These must be after realloc (U may be the same as W).  */
    up = u->d;
    wp = w->d;

    if( !usize ) {  /* simple */
	wp[0] = v;
	wsize = v? 1:0;
	wsign = 1;
    }
    else if( usign ) {	/* mpi and v are negative */
	mpi_limb_t cy;
	cy = mpihelp_add_1(wp, up, usize, v);
	wp[usize] = cy;
	wsize = usize + cy;
    }
    else {  /* The signs are different.  Need exact comparison to determine
	     * which operand to subtract from which.  */
	if( usize == 1 && up[0] < v ) {
	    wp[0] = v - up[0];
	    wsize = 1;
	    wsign = 1;
	}
	else {
	    mpihelp_sub_1(wp, up, usize, v);
	    /* Size can decrease with at most one limb. */
	    wsize = (usize - (wp[usize-1]? 1:0));
	}
    }

    w->nlimbs = wsize;
    w->sign   = wsign;
}

void
mpi_sub(MPI w, MPI u, MPI v)
{
    if( w == v ) {
	MPI vv = mpi_copy(v);
	vv->sign = !vv->sign;
	mpi_add( w, u, vv );
	m_free(vv);
    }
    else {
	/* fixme: this is not thread-save (we temp. modify v) */
	v->sign = !v->sign;
	mpi_add( w, u, v );
	v->sign = !v->sign;
    }
}


