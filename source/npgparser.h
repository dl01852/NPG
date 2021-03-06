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
#ifndef _NPGPARSER_H_
#define _NPGPARSER_H_

#include "npginjector.h"
#include "npgfile.h"

char **ParseToken(char *line, char StopChar, char Delimiter, int MaxTokens, int *TokCount, int *Advanced);
char *ParsePacketID(char *line, int *Advanced);
void FreeTokens(char ***theArray, int TokCount);
u_char *ProcessArgumentPacket(char *APacket, int *WhichHByte);

#endif