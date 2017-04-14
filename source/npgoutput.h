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
#ifndef _NPGOUTPUT_H_
#define _NPGOUTPUT_H_

// How much information we are going to spam to the console
#define VERBOSE           2
#define VERYVERBOSE       3
#define VERYVERYVERBOSE   4


#define SYNTAX_ERROR         1
#define FILE_READ_ERROR      2
#define ARGUMENT_ERROR       3
#define FATAL_ERROR          4
#define WARNING_MESSAGE      5


void Verbose(int Level, char *Message, ...);
void PrintError(int EType, char *Message, ...);

#endif