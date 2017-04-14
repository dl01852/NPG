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

#include "npg.h"
#include "npgdevice.h"
#include "npgoutput.h"
#include "npgutils.h"
#include "npgparser.h"

/* 
 * =-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-= **
 *
 *
 * =-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-= **
 */
void InitializeGlobals() {

  FirstProcessingQueue = NULL;
  FirstOpenDevice      = NULL; // maybe local
  DefaultDevice        = NULL;
  DefaultDeviceName    = NULL;
  PcapSendQueue        = NULL;
  PacketFileName       = NULL;

  ArgVerbose           = 1; // Default to non verbose mode
  WinPcapSyncPackets   = 0; // Ignore time intervals by deafult
  LibpcapQueueSize     = 0;
  LibpcapFileDataLink  = 0;
  LibpcapPacketCount   = 0;
  LineCounter          = 0;   
  CharPosition         = 0;

  UseLibpcapFile       = FALSE;
  NeedDefaultDevice    = FALSE; 
  UseArgumentPacket    = FALSE;
  UseTimeIntervals     = FALSE;
}

/* 
 * =-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-= **
 *
 *
 * =-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-= **
 */
void npgCleanUp() {

  DestroyOpenDevice();

  PacketFileName = Free(PacketFileName);
}

/* 
 * =-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-= **
 *
 *
 * =-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-= **
 */
void DisplayNPGInfo() {

 printf("Network Packet Generator %s\n",NPGVERSION);                                                                         
 printf("Copyright (C) 2006 Jason Todd\n");
 printf("WikiSTC - http://www.wikistc.org/\n\n");
}

/* 
 * =-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-= **
 *
 *
 * =-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-= **
 */
void DisplayLicense() {

 printf("This program is free software; you can redistribute it and/or\n");
 printf("modify it under the terms of the GNU Library General Public\n");
 printf("License as published by the Free Software Foundation; either\n");
 printf("version 2 of the License, or (at your option) any later version.\n\n");

 printf("This program is distributed in the hope that it will be useful,\n");
 printf("but WITHOUT ANY WARRANTY; without even the implied warranty of\n");
 printf("MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU\n");
 printf("Library General Public License for more details.\n\n");

 printf("You should have received a copy of the GNU Library General Public\n");
 printf("License along with this library; if not, write to the Free\n");
 printf("Software Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.\n\n");
}

/* 
 * =-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-= **
 *
 *
 * =-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-= **
 */
void DisplayArguments() {

 printf("USAGE:\n");
 printf("   npg\n");
 printf("   npg [-?hlw]\n");
 printf("   npg [-vvvw] -fF <packet file name> -d <device interface>\n");
 printf("   npg [-rtvvv] -p <packet stream> -d <device interface>\n\n\n");

 printf("OPTIONS:\n\n");

 printf("-d <interface device>\n");
 printf("  Specifies a single device that will be used as a default device for any\n");
 printf("  packets that do not explicitly define a device or devices to be injected\n");
 printf("  through.\n\n");

 printf("-f <npg packet file name>\n");
 printf("  Npg formatted packet file that defines the packets to be injected, and\n");
 printf("  optionally their repeat count, time interval, device list, and PacketID\n\n");

 printf("-F <Libpcap compatible packet file name>\n");
 printf("  Libpcap compatible packet file that will have its contents injected.\n\n");

 printf("-l\n");
 printf("  Displays a list of usable interfaces in a format compatible with the\n");
 printf("  -d switch.\n\n");

 printf("-p <packet stream>\n");
 printf("  Specifies a single packet stream to be injected. This stream cannot contain\n");
 printf("  any spaces and must be formatted in two character hex value byte. 00 - FF\n\n");

 printf("-r <repeat count>\n");
 printf("  Numeric count of how many times to re inject the current packet. If time\n");
 printf("  intervals are defined it will wait the specified time before re injecting\n");
 printf("  each packet. This switch is only viable when used in conjunction with\n");
 printf("  the -p switch.\n\n");

 printf("-s\n");
 printf("  Synchronize the injected packets according to the time stamps specified in a \n");
 printf("  Libpcap compatible file. This switch is only viable when used in conjunction\n");
 printf("  with the -F switch or Libpcap compatible file.\n\n");

 printf("-t <time interval>\n");
 printf("  Specifies the time interval in milliseconds to wait before the packet is \n");
 printf("  injected. This switch is only viable when used in conjunction with \n");
 printf("  the -p switch.\n\n");

 printf("-v, -vv, -vvv\n");
 printf("  Verbose, Very Verbose, and Very Very Verbose. Determines how much status npg\n");
 printf("  will display during operation. Verbose displaying minimum progress messages,\n");
 printf("  Very Verbose displaying large amounts of status messages, and\n");
 printf("  Very Very Very Verbose spamming incredible amounts of messages.\n\n");

 printf("-w\n");
 printf("  Displays the current version of WinPcap installed.\n\n");

 printf("-?, -h\n");
 printf("   Displays copyright information and list of command line arguments.\n");

}

/* 
 * =-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-= **
 *
 *
 * =-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-= **
 */
char InteractiveFile() {

char    ReturnSelection = 0;
char    ReadChar[3];


  printf("\nPacket file type:\n\n");

  printf("[1] npg standard packet file format\n");
  printf("[2] Libpcap binary dump format\n\n");

  while ( ReturnSelection == 0 ) {
   printf("Selection [1]:");

   fgets(ReadChar,3,stdin);

   ReturnSelection = atoi(ReadChar);

   // If we have a CR use default value
   if ( ReadChar[0] == 0x0a) ReturnSelection = 1;

   fflush(stdin); 

   // Make sure our selection is in range
   if ( (ReturnSelection > 2) || (ReturnSelection <= 0) ) ReturnSelection = 0;
  }

 return ReturnSelection;
}

/* 
 * =-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-= **
 *
 *
 * =-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-= **
 */
char InteractiveVerbose() {

char    ReturnSelection = 0;
char    ReadChar[3];

  printf("No arguments detected, using interactive mode. Use npg -h for arugments.\n\n");

  printf("Output information level:\n\n");
  printf("[1] None\n");
  printf("[2] Verbose\n");
  printf("[3] Very Verbose\n");
  printf("[4] Very Very Verbose\n\n");

  while ( ReturnSelection == 0 ) {
   printf("Selection [3]:");

   fgets(ReadChar,3,stdin);

   ReturnSelection = atoi(ReadChar);

   // If we have a CR use default value
   if ( ReadChar[0] == 0x0a) ReturnSelection = 3;

   fflush(stdin); 

   // Make sure our selection is in range
   if ( (ReturnSelection > 4) || (ReturnSelection <= 0) ) ReturnSelection = 0;
  }

 return ReturnSelection;
}

/* 
 * =-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-= **
 *
 *
 * =-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-= **
 */
char InteractiveTiming() {

char    ReturnSelection = 0;
char    ReadChar[3];

  printf("\nUse time intervals defined in %s:\n\n",PacketFileName);

  printf("[1] Yes\n");
  printf("[2] No\n\n");

  while ( ReturnSelection == 0 ) {
   printf("Selection [2]:");

   fgets(ReadChar,3,stdin);

   ReturnSelection = atoi(ReadChar);

   // If we have a CR use default value
   if ( ReadChar[0] == 0x0a) ReturnSelection = 2;

   fflush(stdin); 

   // Make sure our selection is in range
   if ( (ReturnSelection > 2) || (ReturnSelection <= 0) ) ReturnSelection = 0;
  }

 return ReturnSelection;
}

/* 
 * =-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-= **
 *
 *
 * =-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-= **
 */
void InteractiveMode() {

  DisplayNPGInfo();

  ArgVerbose = InteractiveVerbose();

  // Get the file type of the packet file
  if (InteractiveFile() == 1) {
   UseLibpcapFile = FALSE;

   if (ParsePacketFile(NULL) != 0) {
	PrintError(FATAL_ERROR,"Exiting\n");
    exit(1);
   }

  }
  else {
	UseLibpcapFile    = TRUE;
    NeedDefaultDevice = TRUE;

    ParseLibpcapFile(NULL);

   WinPcapSyncPackets = InteractiveTiming();

  }

  // Only go interactive if not every packet contained a device specification 
  if ( NeedDefaultDevice == TRUE) {
   if ( (DefaultDevice = QueryOpenDevice(NULL)) == NULL) {
      PrintError(FATAL_ERROR,"Exiting\n");
    exit(1);
   }

   /* If we selected a default device and are not using LibpcapFile type make sure every 
      packet that needs it is bound to it */
   if (UseLibpcapFile != TRUE) PropogateDefaultDevice();
  }

}

/* 
 * =-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-= **
 *
 *
 * =-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-= **
 */
void CheckSwitchParameter(char *Switch, char *SwitchData) {

  if ( SwitchData == NULL ) {
    PrintError(FATAL_ERROR,"%s switch requires a paramter\n",Switch);
   exit(1);
  }

}

/* 
 * =-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-= **
 *
 *
 * =-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-= **
 */
void CheckForFileName(char *FName, char *ErrorType) {

  if (FName != NULL) {
	printf("FATAL ERROR in npg.exe: %s\n",ErrorType);
   exit(1);
  }

}

/* 
 * =-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-= **
 *
 *
 * =-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-= **
 */
int main(int argc, char **argv) {

char     ArgCounter = 0;
char    *DeviceName = NULL;
char    *FileName = NULL;
int      RepeatCount = 0;
long     Time = 0;
u_char  *ArgPacket = NULL;
int      ArgPacketSize = 0;

int      WByte = 0;

BOOLEAN  UseArgumentTiming = FALSE;
BOOLEAN  UseArgumentRepeat = FALSE;

 InitializeGlobals();
 
 // If we have no command line arguments go fully interactive
 if ( argc <= 1 ) InteractiveMode();
 else {
//** INTERPRET COMMAND LINE ARGUMENTS ** ------------------------------------------ **
  DisplayNPGInfo();

  for (ArgCounter = 1; ArgCounter < argc; ArgCounter++) {

//** -? -h SWITCH ** -------------------------------------------------------------- **
	if ( (strcmp(argv[ArgCounter],"-?") == 0) || (strcmp(argv[ArgCounter],"-h") == 0) ) {                                                                                
     DisplayLicense();

	 DisplayArguments();

     exit(0);
	}
//** -l SWITCH ** ----------------------------------------------------------------- **
	else if ( strcmp(argv[ArgCounter],"-l") == 0)   ListDeviceDetails();
	else if ( strcmp(argv[ArgCounter],"-v") == 0)   ArgVerbose = VERBOSE;
	else if ( strcmp(argv[ArgCounter],"-vv") == 0)  ArgVerbose = VERYVERBOSE;
	else if ( strcmp(argv[ArgCounter],"-vvv") == 0) ArgVerbose = VERYVERYVERBOSE;
	else if ( strcmp(argv[ArgCounter],"-s") == 0)   WinPcapSyncPackets = 1;
//** -w SWITCH ** ----------------------------------------------------------------- **
	else if ( strcmp(argv[ArgCounter],"-w") == 0) {
	  printf("%s\n",pcap_lib_version());
	  exit(0);
	}
//** -p SWITCH ** ----------------------------------------------------------------- **
	else if ( strcmp(argv[ArgCounter],"-p") == 0) {

		   CheckSwitchParameter(argv[ArgCounter],argv[ArgCounter+1]);

		   // If we already have declared a -p switch then error on the second
		   if (UseArgumentPacket == TRUE) {
		     printf("SYNTAX ERROR: Redeclaration of -p argument\n");
            exit(1);
		   }
		   else
			 UseArgumentPacket = TRUE;

		   // Make sure we have not already seen a -f or -F switch
		   CheckForFileName(FileName,"-p switch is not compatible with -fF switch");
    
		   // Processes our packet stream
           ArgPacket = ProcessArgumentPacket(argv[ArgCounter+1],&WByte);

           // Verify that each 2 character byte (00-FF) was found and not a single character byte
		   if ( WByte == 1 ) {
	         PrintError(FATAL_ERROR,"Corrupted packet stream.\nSingle character found on double chacter byte\n");
			exit(1);
		   }

           ArgPacketSize = strlen(argv[ArgCounter+1])/2;

           // -p switch set a manditory default device
	       NeedDefaultDevice = TRUE;

     ArgCounter++;
	}
//** -r SWITCH ** ----------------------------------------------------------------- **
	else if ( strcmp(argv[ArgCounter],"-r") == 0) {

		   CheckSwitchParameter(argv[ArgCounter],argv[ArgCounter+1]);

		   if (UseArgumentRepeat == TRUE) {
		     PrintError(ARGUMENT_ERROR,"Redeclaration of -r argument\n");
            exit(1);
		   }
           else
             UseArgumentRepeat = TRUE;

		   // Validate our repeat value
	       if (ValidateRT(argv[ArgCounter+1],"0") != 0) exit(1);

           RepeatCount = atol(argv[ArgCounter+1]);

      ArgCounter++;
	}
//** -t SWITCH ** ----------------------------------------------------------------- **
	else if ( strcmp(argv[ArgCounter],"-t") == 0) {

		   CheckSwitchParameter(argv[ArgCounter],argv[ArgCounter+1]);

		   if (UseArgumentTiming == TRUE) {
		     PrintError(ARGUMENT_ERROR,"Redeclaration of -t argument\n");
            exit(1);
		   }
           else
            UseArgumentTiming = TRUE;

		   // Validate our time interval
	       if (ValidateRT("0",argv[ArgCounter+1]) != 0) exit(1);

           Time = atol(argv[ArgCounter+1]);

      ArgCounter++;
	}
//** -d SWITCH ** ----------------------------------------------------------------- **
	else if ( strcmp(argv[ArgCounter],"-d") == 0) {

		   CheckSwitchParameter(argv[ArgCounter],argv[ArgCounter+1]);

           if ( DeviceName != NULL ) {
             PrintError(ARGUMENT_ERROR,"Redeclaration of -d argument\n");
            exit(1);
		   }

	       DeviceName = malloc(sizeof(char)*strlen(argv[ArgCounter+1])+1);
	       memcpy(DeviceName,argv[ArgCounter+1],sizeof(char)*strlen(argv[ArgCounter+1])+1);

      ArgCounter++;
	}
//** -f SWITCH ** ----------------------------------------------------------------- **
	else if ( strcmp(argv[ArgCounter],"-f") == 0) {

		   CheckSwitchParameter(argv[ArgCounter],argv[ArgCounter+1]);

		   // Make sure we have not already seen a -f or -F switch
		   CheckForFileName(FileName,"Multiple file declaration");

		   if (UseArgumentPacket == TRUE) {
		     printf("SYNTAX ERROR: -p switch not compatible with -fF argument\n");
            exit(1);
		   }

	      FileName = malloc(sizeof(char)*strlen(argv[ArgCounter+1])+1);
	      memcpy(FileName,argv[ArgCounter+1],sizeof(char)*strlen(argv[ArgCounter+1])+1);

      ArgCounter++;
	}
//** -F SWITCH ** ----------------------------------------------------------------- **
	else if ( strcmp(argv[ArgCounter],"-F") == 0) {

		   CheckSwitchParameter(argv[ArgCounter],argv[ArgCounter+1]);

		   // Make sure we have not already seen a -f or -F switch
		   CheckForFileName(FileName,"Multiple file declaration");

		   if (UseArgumentPacket == TRUE) {
		     printf("SYNTAX ERROR: -p switch not compatible with -fF argument\n");
            exit(1);
		   }

	       FileName = malloc(sizeof(char)*strlen(argv[ArgCounter+1])+1);
	       memcpy(FileName,argv[ArgCounter+1],sizeof(char)*strlen(argv[ArgCounter+1])+1);

           UseLibpcapFile = TRUE;

      ArgCounter++;
	}
//** UNKNOWN SWITCH ** ------------------------------------------------------------ **
	else {
	 printf("FATAL ERROR in npg.exe, unknown argument %s\n\n",argv[ArgCounter]);
	 DisplayArguments();
	 exit(1);
	 break;
	}

  } // for (ArgCounter = 1; ArgCounter < argc; ArgCounter++)


//** COMMAND LINE PACKET INJETION ** ---------------------------------------------- **
  // Make sure we have a valid combination of arugments
  if ( ((UseArgumentRepeat == TRUE ) || (UseArgumentTiming == TRUE)) && (UseArgumentPacket != TRUE)) {
    printf("SYNTAX ERROR: Arguments -r and/or -t are only valid in conjection with -p");
   exit(1);
  }

  // If we had a -p argument then we need to queue the packet
  if ( UseArgumentPacket == TRUE ) {
    if ( (UseArgumentTiming != TRUE) && (WinPcapSyncPackets == 1) ) {
      printf("WARNING: -s argument used in conjunction with  -p and no -t <time interval> defined. Time interval defaulted to 0\n");
	}

   QueuePacket(Time, ArgPacketSize, ArgPacket, NULL, RepeatCount, NULL);

   ArgPacket = Free(ArgPacket);

  }
//** PACKET FILE INJECTION ** ----------------------------------------------------- **
  else {

    // If neither -f or -F was used go interactive
    if (FileName == NULL) {
	  if (InteractiveFile() == 1) UseLibpcapFile = FALSE;
	  else UseLibpcapFile = TRUE;
	}

    // Depending on the results of the interactive questions or arguments open the appropriate file type
    if (UseLibpcapFile == FALSE) {

	   if (WinPcapSyncPackets != 0) {
         printf("WARNING: -s is only valid with a Libpcap file type or -F switch.\n");
	   }

	   if (ParsePacketFile(FileName) != 0) {
	     PrintError(FATAL_ERROR,"Processing %s\n",PacketFileName);
	    exit(1);
	   }
	}
	// Use Libpcap compatible file
    else if ( UseLibpcapFile == TRUE ) {
      UseLibpcapFile    = TRUE;
      NeedDefaultDevice = TRUE;

      if (ParseLibpcapFile(FileName) != 0) exit(1);

	  // If no -s switch was specified go interactive
      if ( WinPcapSyncPackets == 0 ) WinPcapSyncPackets = InteractiveTiming();

	} 

   // We have no need for this past this point
   FileName = Free(FileName);

  } // End UseArgumentPacket else

//** DEVICE(S) FOR INJECTION ** --------------------------------------------------- **

  /* DefaultDevice needs to be set under any of the following conditions:

      -d switch was used
	  -f switch used with not all packets in the file specifying a device
	  -F used and a default device needs to be selected for the packets in the file

     If NeedDefaultDevice == TRUE and no DeviceName has been specified we will drop into
	 interactive mode to select our DefaultDevice */
  if ( NeedDefaultDevice == TRUE ) {
    if ( (DefaultDevice = QueryOpenDevice(DeviceName)) == NULL) {
	  PrintError(FATAL_ERROR,"DetectDeviceAdapater exiting\n");
     exit(1);
    }

  // We have no need for this past this point
  DeviceName  = Free(DeviceName);

   /* If we are using a npg packet file and not all packets specified devices then we
      need to propogate all unspecified packets with the DefaultDevice  */
   if ( UseLibpcapFile == FALSE ) PropogateDefaultDevice();
  }

 } // if ( argc <= 1 )

//** INJECT PACKETS ** ------------------------------------------------------------ **
  if ( UseLibpcapFile == TRUE ) {
    InjectPacketLibpcapFile();// Start injecting packets stored in the Winpcap queue
    DestroyLibpcapQueue();// Tear down the LibpcapQueue
  }
  else if ( UseLibpcapFile == FALSE ) {
    InjectPacketQueue();// Start injecting the packets stored in the npg queue
    DestroyProcessingQueue();// Tear down the ProcessingQueue
  }
  else {
   exit(1);
  }

//** CLEANUP ** ------------------------------------------------------------------- **
 npgCleanUp();

}