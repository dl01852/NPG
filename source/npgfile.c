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
#include "npgfile.h"
#include "npgoutput.h"
#include "npgutils.h"
#include "npgdevice.h"
#include "npgparser.h"
#include "npg.h"

u_char  *PacketBlock = NULL;
char     HexByte[1]; // Storage for validation and conversion into single char byte

/* 
 * =-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-= **
 *
 *
 * =-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-= **
 */
void AppendPacketBlock(int *workingindex, int *psize, u_char workingline[FILEREADBUFFER]) {

u_char  *WorkingRAWPacket = NULL;

   if (PacketBlock == NULL) {
     PacketBlock = MAlloc(*workingindex);
     memcpy(PacketBlock,workingline,*workingindex);
     *psize = *workingindex;
	}
    else {
	 WorkingRAWPacket = MAlloc(*psize+*workingindex);
	 memcpy(WorkingRAWPacket,PacketBlock,*psize);
	  
	 PacketBlock = Free(PacketBlock);

	 memcpy(WorkingRAWPacket+*psize,workingline,*workingindex);

	 PacketBlock = MAlloc(*psize+*workingindex);

     memcpy(PacketBlock,WorkingRAWPacket,*psize+*workingindex);

     WorkingRAWPacket = Free(WorkingRAWPacket);
     WorkingRAWPacket = NULL;
     *psize += *workingindex;
	}

   *workingindex = 0;
   bzero(workingline,FILEREADBUFFER);
}

/* 
 * =-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-= **
 *
 *
 * =-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-= **
 */
FILE *InteractiveFileName(char *FName, char *DefaultFile, char *Mode) {

char       FileName[255];     // Interactive mode entered file name holder
FILE      *fp;                // File handle pointer
BOOLEAN    FoundFile = FALSE;


  if (FName != NULL) {
   /* Sanity check the file here for existance, and access */
   if ((fp = fopen(FName, Mode)) == NULL) printf("Could not locate the packet file %s\n",FName);
   else FoundFile = TRUE;
  }

   bzero(FileName,255); 

   printf("\n");
   while ( FoundFile == FALSE) 
   {
    printf("Enter the name of the packets file [%s]: ",DefaultFile);

    fgets(FileName,255,stdin);

    // If we have a CR use default value
    if ( FileName[0] == 0x0a) FName = DefaultFile;
	else {
	  FileName[strlen(FileName)-1] = 0x00; // trim off CR
	  FName = FileName;
	}

    /* Sanity check the file here for existance, and access */
    if ((fp = fopen(FName, Mode)) == NULL) printf("Could not locate the packet file %s\n",FName);
	else FoundFile = TRUE;

    fflush(stdin); 
   }

  Verbose(VERYVERYVERBOSE,"Successfully opened file %s as read only\n",FName);

  PacketFileName = MAlloc(strlen(FName)+1);
  memcpy(PacketFileName,FName,strlen(FName));

 return fp;
}

/* 
 * =-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-= **
 *
 *
 * =-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-= **
 */
char ParsePacketFile(char *location) {

char         ReadBuffer[FILEREADBUFFER]; // char buffer from file read
char        *WorkingReadBuffer = NULL;   // Pointer to line read in from file
char        *EndofLineBuffer= NULL;      // End of the line buffer
u_char       WorkingLine[FILEREADBUFFER];// Working buffer for the current read in file line
int          WorkingIndex  = 0;          // Position index of WorkingLine

float        CPUTime         = 0;   // Elapsed time counter
int          PacketCount     = 0;   // Packets processed counter
int          PacketBlockSize = 0;   // Current Size of PacketBlock
int          WhichByte       = 0;   // Marker for HexByte for 2 character byte read in from file
int          AdvanceIndex    = 0;   // Tracker of how far to advance *WorkingReadBuffer after processing
int          TokenCount      = 0;   // Amount of tokens stored in ParsedTokens
char         **ParsedTokens  = NULL;// Parsed Tokens

FILE         *FPtr = NULL;              // File pointer

BOOLEAN      ProcessingBlock  = FALSE;  // Signal flag that a packet block is being processed
BOOLEAN      DeclaredDevice   = FALSE;  // Signal flag that a device bracket has already been declared on the current packet
BOOLEAN      DeclaredTime     = FALSE;  // Signal flag that a timing bracket has already been declared on the current packet
BOOLEAN      DeclaredPacketID = FALSE;  // Signal flag that a PacketID bracket has already been declared on the current packet

int          RepeatCount    = 0;        // Repeat count of the current packet
long         Timing         = 0;        // Time interval of the current packet
DeviceList   *theDeviceList = NULL;     // List of devices that will inject the current packet
char         *PacketID      = NULL;     // Message to be displayed when the packet is injected

char         *TrimmedTime   = NULL;
char         *TrimmedRepeat = NULL;


  FPtr = InteractiveFileName(location,"packets.txt","r");

  // Start elapsed time counter
  CPUTime = (float) clock();

  while( ((fgets(ReadBuffer, FILEREADBUFFER, FPtr)) != NULL) )
  {
   LineCounter++;
   CharPosition = 0;
   WorkingReadBuffer = ReadBuffer;
   EndofLineBuffer = WorkingReadBuffer + strlen(WorkingReadBuffer);   

   // Validate the line read in was not bigger then FILEREADBUFFER
   if ( strrchr(WorkingReadBuffer,'\n') == 0 ) {
       
	   if ( !feof(FPtr) ) {
         PrintError(FILE_READ_ERROR,"Exceeded max file line length\nMaximum file line length is %d\n",FILEREADBUFFER);
	    return -1;
	   }
   }

   Verbose(VERYVERYVERBOSE,"Processing line %d: %s",LineCounter,WorkingReadBuffer);

   // remove whitespaces and tabs at beginning of the line
   while (*WorkingReadBuffer == ' ' || *WorkingReadBuffer == '\t') { 
	   WorkingReadBuffer++;
	   CharPosition++;
   }
   // skip over comment delimeter, <CR>, or blank line 
   if ( (*WorkingReadBuffer == '#' ) || (*WorkingReadBuffer == 0x0a) || (WorkingReadBuffer == NULL) ) continue;
   // This is a catch for a line that had all spaces/tabs and got parsed to nothing
   if ( strlen(WorkingReadBuffer) == 0 ) continue;

   // Process the line
   while ( WorkingReadBuffer < EndofLineBuffer ) {

	// Skip spaces and tabs
	if ( (*WorkingReadBuffer == ' ') || (*WorkingReadBuffer == '\t') ) {
	  CharPosition++;
	  WorkingReadBuffer++;
      continue;
	}
	// Stop processing this line when a comment delimiter is found or EOL
    else if ( (*WorkingReadBuffer == '#') || (*WorkingReadBuffer == 0x0a) ) 
	{
	 CharPosition = 0;
	 WorkingReadBuffer = EndofLineBuffer;
	 continue;
	}
//** REPEAT COUNT & TIME INTERVAL ** ---------------------------------------------- **
	else if ( *WorkingReadBuffer == '[' ) {

       if (DeclaredTime == TRUE) {
	     PrintError(SYNTAX_ERROR,"Multiple Repeat/Time interval declarations on the same packet\n");
	    return -1;
	   }

	   // Parse out and declarations between [ and ] seperatred by ,
	   if ( (ParsedTokens = ParseToken(WorkingReadBuffer,']',',',MAX_TIMING_TOKENS,&TokenCount,&AdvanceIndex)) == NULL) 
		 return -1;

	   // Make sure we grabbed both a RepeatCount and Timing
       if (TokenCount != 1) {
	     PrintError(SYNTAX_ERROR,"[] bracket must contain both a Repeat count and a time interval\nSyntax:[RepeatCount,Time interval]\n");
	    return -1;
	   }


	   TrimmedRepeat = strtok(ParsedTokens[0]," \t");

       if ( strtok(NULL," \t") != NULL) {
	     PrintError(SYNTAX_ERROR,"Improperly formatted repeat count\n");
		return -1;
	   }

	   TrimmedTime = strtok(ParsedTokens[1]," \t");

       if ( strtok(NULL," \t") != NULL) {
	     PrintError(SYNTAX_ERROR,"Improperly formatted time interval\n");
		return -1;
	   }

       // Validate each declaration to make sure it is within range
       if (ValidateRT(TrimmedRepeat,TrimmedTime) != 0) return -1; 

	   RepeatCount = atol(TrimmedRepeat);
	   Timing      = atol(TrimmedTime);

	   if (Timing != 0) UseTimeIntervals = TRUE;

     Verbose(VERYVERYVERBOSE,"Repeat Count: %d\nTime Interval: %d\n",RepeatCount,Timing);

      FreeTokens(&ParsedTokens, TokenCount);

     WorkingReadBuffer += AdvanceIndex;
	 DeclaredTime = TRUE;
	}
//** PACKET ID ** ----------------------------------------------------------------- **
	else if ( *WorkingReadBuffer == '<' ) {

       if (DeclaredPacketID == TRUE) {
	     PrintError(SYNTAX_ERROR,"Multiple packet ID declarations on the same packet\n");
	    return -1;
	   }

	   if ( (PacketID = ParsePacketID(WorkingReadBuffer,&AdvanceIndex)) == NULL) return -1;

     Verbose(VERYVERYVERBOSE,"PacketID: %s\n",PacketID);

     WorkingReadBuffer += AdvanceIndex;

     DeclaredPacketID = TRUE;
	}
//** DEVICE ** -------------------------------------------------------------------- **
	else if ( *WorkingReadBuffer == '(' ) {

       if (DeclaredDevice == TRUE) {
	     PrintError(SYNTAX_ERROR,"Multiple device declarations on the same packet\n");
	    return -1;
	   }

	   // Parse out and declarations between [ and ] seperatred by ,
	   if ( (ParsedTokens = ParseToken(WorkingReadBuffer,')',',',MAX_DEVICE_TOKENS,&TokenCount,&AdvanceIndex)) == NULL) 
		 return -1;

       // Process our device listing
	   if ( (theDeviceList = ProcessDeviceList(ParsedTokens,TokenCount)) == NULL) return -1;

      FreeTokens(&ParsedTokens, TokenCount);

      WorkingReadBuffer += AdvanceIndex;
	  DeclaredDevice = TRUE;
	}
//** PACKET BLOCK ** -------------------------------------------------------------- **
	else if (*WorkingReadBuffer == '{') {

  Verbose(VERYVERYVERBOSE,"Found {\n");

		if (ProcessingBlock == TRUE) {
          PrintError(SYNTAX_ERROR,"Found { was expecting }\n");
         return -1;
		}

	  ProcessingBlock = TRUE;
	}
	else if ( (ProcessingBlock == TRUE) && (*WorkingReadBuffer != '}') ) {

	  // Only HEX characters are valid inside a packet block { }
      if ( ((*WorkingReadBuffer < 48)  || (*WorkingReadBuffer > 57)) && 
	       ((*WorkingReadBuffer < 65)  || (*WorkingReadBuffer > 70)) &&
		   ((*WorkingReadBuffer < 97)  || (*WorkingReadBuffer > 102)) )
	  {
        PrintError(SYNTAX_ERROR,"Invalid HEX value %c\n",*WorkingReadBuffer);
       return -1;
	  }

	 // Parse out single read characters into a single u_char value
     if (WhichByte == 0)
	 {
      HexByte[0] = *WorkingReadBuffer;
	  WhichByte = 1;
	 }
	 else
	 {
      HexByte[1] = *WorkingReadBuffer;

      WorkingLine[WorkingIndex] = (u_char) Chars2Hex(HexByte,2);

 Verbose(VERYVERYVERBOSE,"Validated : %.2X\n",WorkingLine[WorkingIndex]);

      bzero(HexByte,2);
      WhichByte = 0;
      WorkingIndex++;
	 }

	}
	else if (*WorkingReadBuffer == '}') {

  Verbose(VERYVERYVERBOSE,"Found }\n");

       // If we found a } on the same line as packet data we need to append it here
	  if (WorkingIndex != 0) {
        AppendPacketBlock(&WorkingIndex,&PacketBlockSize,WorkingLine);
	  }

	  PacketCount++;

      // Verify that each 2 character byte (00-FF) was found and not a single character byte
      if ( WhichByte == 1 ) {
	     PrintError(FATAL_ERROR,"Corrupted packet stream.\nSingle character found on double chacter byte in packet #%d\n",PacketCount);
	   exit(1);
	  }

      QueuePacket(Timing, PacketBlockSize, PacketBlock, PacketID, RepeatCount, theDeviceList);

	  // Re initialize variables for the next packet to process
	  ProcessingBlock  = FALSE;
	  DeclaredTime     = FALSE;
	  DeclaredPacketID = FALSE;
	  DeclaredDevice   = FALSE;

	  theDeviceList    = NULL;

	  RepeatCount      = 0;
	  Timing           = 0;

	  PacketBlockSize  = 0;
	  WorkingIndex     = 0;

	  PacketBlock      = Free(PacketBlock);
	  PacketID         = Free(PacketID);
	}
//** INVALID CHARACTERS ** -------------------------------------------------------- **
	else {
      PrintError(SYNTAX_ERROR,"Invalid value %c\n",*WorkingReadBuffer);
     return -1;
	}

    CharPosition++;
    WorkingReadBuffer++;
   } // End while ( WorkingReadBuffer <= EndofLineBuffer )

   // If we are processing a packet block append WorkingLine to PacketBlock
   if (ProcessingBlock == TRUE) {
	 // if we have no packet data stored the skip the appending (Happens with single line { )
	 if (WorkingIndex == 0) continue;

     AppendPacketBlock(&WorkingIndex,&PacketBlockSize,WorkingLine);
   }

  } // End while( ((fgets(buf, READ_IN_BUFFER_SIZE, fp)) != NULL) )

  fclose(FPtr);
  Verbose(VERYVERYVERBOSE,"Closed file %s\n",PacketFileName);

  CPUTime = (clock() - CPUTime) / CLK_TCK;

  Verbose(VERBOSE,"Successfully processed %d packets in %s \n",PacketCount, PacketFileName);
  Verbose(VERBOSE,"Elapsed time : %5.3f\n",CPUTime);
 
 return 0;
}

/* 
 * =-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-= **
 *
 *
 * =-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-= **
 */
char ParseLibpcapFile(char *location) {

char       SourceStr[PCAP_BUF_SIZE];
char       ErrorBuffer[PCAP_ERRBUF_SIZE];
pcap_t     *CaptureFile;
FILE       *FPtr;


   FPtr = InteractiveFileName(location,"packets.cap","rb");

   fseek(FPtr,0,SEEK_END);	
   LibpcapQueueSize = ftell(FPtr) - sizeof(struct pcap_file_header);
   fclose(FPtr);

   // Create a source string
   if ( pcap_createsrcstr( SourceStr,
                           PCAP_SRC_FILE,
						   NULL,
						   NULL,
						   PacketFileName,
						   ErrorBuffer) != 0) {
	  printf("!FATAL ERROR: %s\n",ErrorBuffer);

	 return -1;
	}

    // Attempt to open the capture file
    if ( (CaptureFile = pcap_open( SourceStr,
		                           PACKET_CAPTURE_SIZE,
		                           PCAP_OPENFLAG_PROMISCUOUS,
		                           PACKET_READ_TIMEOUT,
                                   NULL,
							       ErrorBuffer) ) == NULL) {
      printf("Device: %s\n", SourceStr);
      printf("FATAL ERROR in ParseLibpcapFile file %s %s\n", PacketFileName, ErrorBuffer);

	 return -1;
	}

    QueueLibpcapPacket(CaptureFile);

    LibpcapFileDataLink = pcap_datalink(CaptureFile);

	pcap_close(CaptureFile); // Close the input file

 return 0;
}