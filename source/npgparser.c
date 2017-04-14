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
#include "npgparser.h"
#include "npgutils.h"
#include "npgoutput.h"

/* 
 * =-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-= **
 *
 *
 * =-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-= **
 */
char **ParseToken(char *line, char StopChar, char Delimiter, int MaxTokens, int *TokCount, int *Advanced) {

char   *WorkingString = NULL;
char   *EndofWorkingString = NULL;
char   **ReturnString = NULL;
char   *StopCharPtr   = NULL;
int    StringSize     = 0;
int    TokenSize      = 0;
int    ArrayIndex     = 0;
int    Start          = 0;
int    i;


  *Advanced = 0;
  // Pointer to where *StopChar is located in *line
  StopCharPtr = strchr(line,StopChar);

  // Validate we have a *StopChar in *line
  if ( StopCharPtr == NULL) {
	 CharPosition = strlen(line);
	 PrintError(SYNTAX_ERROR,"Missing %c\n",StopChar);
   return 0;
  }

  StringSize = (StopCharPtr-line)+1;

  ReturnString = (char **) MAlloc((MaxTokens+1) * sizeof(char **) );
  WorkingString = (char *) MAlloc(sizeof(char)*StringSize);
  // When we copy  StringSize-1 is to remove the trailing StopChar
  memcpy(WorkingString,line,StringSize-1);

  for (i=0;i<StringSize;i++) {

	if (ArrayIndex > MaxTokens ) {
	   CharPosition += i;
       PrintError(SYNTAX_ERROR,"Exceeded maximum argument count\n");
     return 0;
	}

    if (WorkingString[i] == Delimiter) {

	  TokenSize = (i-Start);
     *Advanced += TokenSize;

	  ReturnString[ArrayIndex] = (char *) MAlloc(TokenSize);
	  memcpy(ReturnString[ArrayIndex],WorkingString+Start+1,TokenSize-1);

  Verbose(VERYVERYVERBOSE,"Token[%d] (%s)\n",ArrayIndex,ReturnString[ArrayIndex]);

      Start = i;
	  ArrayIndex++;
	}
  }

  TokenSize = (strlen(WorkingString)-Start);

  // Parse out the last token left in *WorkingString
  ReturnString[ArrayIndex] = (char *) MAlloc(TokenSize);
  memcpy(ReturnString[ArrayIndex],(WorkingString+Start+1),(TokenSize-1));

  Verbose(VERYVERYVERBOSE,"Token[%d] (%s)\n",ArrayIndex,ReturnString[ArrayIndex]);

  // Set the size of the returned token array
  *TokCount = ArrayIndex;

  WorkingString = Free(WorkingString);

  // Advance the reading position
  CharPosition += (StringSize-1);
  *Advanced += TokenSize;

 return ReturnString;
}

/*
 * =-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-= **
 *
 *
 * =-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-= **
 */
char *ParsePacketID(char *line, int *Advanced) {

int     StringSize      = 0;
char   *PktID           = NULL;
char   *WorkingPacketID = NULL;
char   *StopCharPtr     = NULL;
char   *StartCharPtr    = NULL;
int     AppendSize      = 0;
int     RemovedCount    = 1; // This count tracks the removed > count from >> parsing
int     PktIDSize       = 0;

 // Mark the last > found in *line. This may or may not be the end marker to the current packetid
 // In the case of multiple packets declared on the same line this would grab the position of the
 // last seen > in the line.
 StopCharPtr = strrchr(line,'>');

   // Validate we have a possible complete bracket containing atleast one >
   if (  StopCharPtr == NULL) {
	  CharPosition += strlen(line);
      PrintError(SYNTAX_ERROR,"Missing >\n");
    return NULL;
   }

  *Advanced = 0;
  StartCharPtr = line;

  while ( line <= StopCharPtr ) {

	  if ( *line == '>' ) {

        line++;
		CharPosition++;

		    AppendSize = (line-StartCharPtr);

			if (*line == '>') RemovedCount++;

			if (PktID == NULL) {
              PktID = MAlloc(sizeof(char*)*AppendSize);
			  // +1 to remove < and -2 to remove last char and >
			  memcpy(PktID,StartCharPtr+1,AppendSize-2);

			  *Advanced += AppendSize; // Return of how far to advance the read point in the line
			  StartCharPtr = line; // Our new starting point
			}
			else {
		      AppendSize = (line-StartCharPtr);

			  PktIDSize = strlen(PktID);

              WorkingPacketID = MAlloc(sizeof(char*)*(PktIDSize+AppendSize));
              memcpy(WorkingPacketID,PktID,PktIDSize);

			  if (*line == '>') {
                memcpy(WorkingPacketID+PktIDSize,StartCharPtr,AppendSize);
			    *Advanced += AppendSize+2;
			  }
			  else {
                memcpy(WorkingPacketID+PktIDSize,StartCharPtr,AppendSize-1);
			    *Advanced += AppendSize+1;
			  }

              PktID = Free(PktID);
			  PktID = MAlloc(sizeof(char*)*strlen(WorkingPacketID));
			  memcpy(PktID,WorkingPacketID,strlen(WorkingPacketID));

			  WorkingPacketID = Free(WorkingPacketID);

              StartCharPtr = line;
			  StartCharPtr++;
			} 

		   // Return our parsed PktID when we reach a final closing >
		   if (*line != '>') {
             *Advanced -= RemovedCount;
		    return PktID;
		   }

	  } // End if ( *line == '>' )

   line++;
   CharPosition++;
  } // End while ( line <= StopCharPtr )

 // If we are here then we never found a final closing >
 PrintError(SYNTAX_ERROR,"Missing final closing >\n");
 return NULL;
}

/* 
 * =-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-= **
 *
 *
 * =-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-= **
 */
void FreeTokens(char ***theArray, int TokCount) {
int      i;
char     **DeleteIndex;


  DeleteIndex = *theArray;

  for (i=0;i<TokCount;i++) {

	 if (DeleteIndex[i] != NULL) 
	   DeleteIndex[i] = Free(DeleteIndex[i]);
  }

  DeleteIndex = Free(DeleteIndex);
  *theArray = NULL;
}

/* 
 * =-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-= **
 *
 *
 * =-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-= **
 */
u_char *ProcessArgumentPacket(char *APacket, int *WhichHByte) {

u_char *Packet;
int     LineLength = 0;
int     i;

char    HByte[1];
//char    WhichHByte = 0;

u_char  ReturnByte;
int     PacketIndex = 0;


   Packet = MAlloc(strlen(APacket)/2);
   bzero(Packet,strlen(APacket)/2);
   LineLength = strlen(APacket);
   bzero(HByte,2); 

   for (i=0;i<LineLength;i++) {

	  // Only HEX characters are valid inside a packet block { }
      if ( ((APacket[i] < 48)  || (APacket[i] > 57)) && 
	       ((APacket[i] < 65)  || (APacket[i] > 70)) &&
		   ((APacket[i] < 97)  || (APacket[i] > 102)) )
	  {
        PrintError(ARGUMENT_ERROR,"Invalid HEX value %c\n",APacket[i]);
       exit(1);
	  }


	 // Parse out single read characters into a single u_char value
     if (*WhichHByte == 0)
	 {
      HByte[0] = APacket[i];
	  *WhichHByte = 1;
	 }
	 else
	 {
      HByte[1] = APacket[i];

	  ReturnByte = (u_char) Chars2Hex(HByte,2);

      memcpy(Packet+PacketIndex,&ReturnByte,sizeof(u_char));

	  PacketIndex++;

      bzero(HByte,2);
      *WhichHByte = 0;
	 }

   }

 return Packet;
}
