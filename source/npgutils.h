/* ================================================================================ **
/*             
/*  Network Packet Generator (http://www.wikistc.org/wiki/Network_packet_generator)
/*                                                                     
/*  Copyright (C) 2006 by Jason Todd  email://jasontodd@wikistc.org
/*                                                                                 
/*  This program is free software; you can redistribute it and/or 
/*  modify it under the terms of the GNU Library General Public
/*  License as published by the Free Software Foundation; either
/*  version 2 of the License, or (at your option) any later version.
/* 
/*  This program is distributed in the hope that it will be useful,
/*  but WITHOUT ANY WARRANTY; without even the implied warranty of
/*  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
/*  Library General Public License for more details.
/*
/*  You should have received a copy of the GNU Library General Public
/*  License along with this library; if not, write to the Free
/*  Software Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA. 
/*
/*  Bug reports, comments, suggestions 
/*  can be made @ http://www.wikistc.org/wiki/Talk:Network_packet_generator
/*  or email npg@wikistc.org
/* 
/* ================================================================================ **/
#ifndef _NPGUTILS_H_
#define _NPGUTLIS_H_

#include <pcap.h>

#define bzero(X,Y)  memset((X),0,(Y))

char ValidateRT(char *RCount, char *Time);
u_int32_t Chars2Hex(char *chex, char cHexLength);
void *MAlloc(u_int32_t size);
void *Free(void *Ptr);

#endif