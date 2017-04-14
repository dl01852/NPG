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
#include "npgutils.h"
#include "npgfile.h"

/* 
 * =-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-= **
 *
 *
 * =-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-= **
 */
char ValidateRT(char *RCount, char *Time) {

int i;
long RLength = 0;
long TLength = 0;

RLength = strlen(RCount);
TLength = strlen(Time);

    // Check for NULL values
    if (RLength == 0) {
      printf("\nSYNTAX ERROR in %s line %d : Repeat count cannot be NULL\nUse 0 to ignore repeat\n",PacketFileName, LineCounter);
     return -1;
    }
    else if (TLength == 0) {
      printf("\nSYNTAX ERROR in %s line %d : Time value cannot be NULL\nUse 0 to ignore time interval\n",PacketFileName, LineCounter);
     return -2;
    }

    // Validate max number range
	if (RLength > 8 ) {
      printf("\nSYNTAX ERROR in %s line %d : Repeat count value %s invalid or to large\n",PacketFileName, LineCounter, RCount);
     return -1;
	}
	else if (TLength > 8 ) 
	{
     printf("\nSYNTAX ERROR in %s line %d : Time value %s invalid or to large\n",PacketFileName, LineCounter, Time);
	 return -2;
	}

    // Loop through looking for non numeric digit values
	for (i=0;i<RLength;i++) {

	   if ( !isdigit(RCount[i]) ) {
          printf("\nSYNTAX ERROR in %s line %d character %c : Invalid repeat count value %s\n",PacketFileName, LineCounter, RCount[i], RCount);
	    return -3;
	   }
	}

    // Loop through looking for non numeric digit values
	for (i=0;i<TLength;i++) {

	   if ( !isdigit(Time[i]) ) {
          printf("\nSYNTAX ERROR in %s line %d character %c : Invalid time value %s\n",PacketFileName, LineCounter, Time[i], Time);
	    return -4;
	   }
	}

 return 0;
}

/* 
 * =-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-= **
 *
 *
 * =-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-= **
 */
u_int32_t Chars2Hex(char *chex, char cHexLength) {

char  i;
u_int32_t  m;
u_int32_t  Digit[7];
u_int32_t  ReturnInt = 0;


  for (i = 0; i < cHexLength; i++)
  {
   if ( chex[i] > 0x29  && chex[i] < 0x40 ) Digit[i] = chex[i] & 0x0f; //if 0 to 9
   else if (chex[i] >='a' && chex[i] <= 'f') Digit[i] = (chex[i] & 0x0f) + 9; //if a to f
   else if (chex[i] >='A' && chex[i] <= 'F') Digit[i] = (chex[i] & 0x0f) + 9;//if A to F
  }

  m = cHexLength - 1;
  for(i = 0; i < cHexLength; i++) 
  {
   ReturnInt = ReturnInt | (Digit[i] << (m << 2));
   m--;   // adjust the position to set
  }

 return ReturnInt;
}


/* 
 * =-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-= **
 *
 *
 * =-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-= **
 */
void *MAlloc(u_int32_t size) {

void *Ptr;

  if ( (Ptr = (void *) malloc(size) ) == NULL) {
   printf("FATAL ERROR: Unable to allocate memory for internal structure\n");
   exit(1);
  }

  bzero(Ptr,size); // Pass back a NULL(0) CLEANED MEMORY BUFFER

 return Ptr;
}

/* 
 * =-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-= **
 *
 *
 * =-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-= **
 */
void *Free(void *Ptr) {

 if (Ptr != NULL) free(Ptr);

 return NULL;
}