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
#include "npgoutput.h"
#include "npgfile.h"
#include "npg.h"

/* 
 * =-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-= **
 *
 *
 * =-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-= **
 */
void Verbose(int Level, char *Message, ...) {

va_list VList;

  // Only display messages that are at or above our current verbose setting
  if (ArgVerbose >= Level) {
   va_start( VList, Message );
   vprintf( Message, VList );
   va_end( VList );
  }
}

/* 
 * =-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-= **
 *
 *
 * =-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-= **
 */
void PrintError(int EType, char *Message, ...) {

va_list VList;


	switch (EType) {

	case SYNTAX_ERROR : {
	    printf("\nSYNTAX ERROR in %s line %d Position %d : ",PacketFileName, LineCounter, CharPosition);
                         break;
						}
	case FILE_READ_ERROR : {
        printf("\nFILE READ ERROR in %s line %d : ",PacketFileName,LineCounter);
                            break;
						   }
	case ARGUMENT_ERROR : {
        printf("\nSYNTAX ERROR in argument : ");
                            break;
						   }
	case FATAL_ERROR : {
        printf("\nFATAL ERROR in npg.exe : ");
                            break;
						   }
	case WARNING_MESSAGE : {
        printf("\nWARNING in %s line %d Position %d: ",PacketFileName,LineCounter, CharPosition);
                            break;
						   }
	}

  va_start( VList, Message );
  vprintf( Message, VList );
  va_end( VList );

}
