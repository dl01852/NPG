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
#include "npgdevice.h"
#include "npgoutput.h"
#include "npgutils.h"
#include "npg.h"

/* 
 * =-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-= **
 *
 *
 * =-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-= **
 */
void ListDeviceDetails() {

pcap_if_t   *AllDevices;
pcap_if_t   *CurrentDevice;
pcap_if_t   *ExampleDevice;
char        ErrorBuffer[PCAP_ERRBUF_SIZE];
//int         DeviceCount = 0;


  printf("Attemping to auto detect network devices - ");
  if( pcap_findalldevs_ex( PCAP_SRC_IF_STRING,
		                   NULL, 
						   &AllDevices, 
						   ErrorBuffer) == -1) {
     printf("Failure\n");
     printf("Error in pcap_findalldevs_ex: %s\n", ErrorBuffer);
     exit(1);
  }
    printf("Success.\n\n");

	printf("List of available devices:\n\n");
    /* Traverse list of devices found */
	for (CurrentDevice = AllDevices; CurrentDevice; CurrentDevice = CurrentDevice->next) {
      /* Print Winpcap list of the devices found */
	  printf("%s\n", CurrentDevice->name);

	  if (CurrentDevice != NULL) ExampleDevice = CurrentDevice;
    }

 printf("\n\nExample usage:\nnpg -d %s\n",ExampleDevice->name);

 exit(0); // Exit npg, this only a display mode
}

/* 
 * =-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-= **
 *
 *
 * =-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-= **
 */
void AddOpenDevice(pcap_t *Device, char *Name, char *Description) {

OpenDeviceList    *WorkingOpenDevice;
OpenDeviceList    *CurrentOpenDevice; 



  WorkingOpenDevice = MAlloc(sizeof(struct OpenDeviceList));
  WorkingOpenDevice->DeviceInstace = Device;
  WorkingOpenDevice->next          = NULL;

  if (Name == NULL) WorkingOpenDevice->Name = NULL;
  else {
   WorkingOpenDevice->Name = MAlloc(strlen(Name)+1);
   memcpy(WorkingOpenDevice->Name,Name,strlen(Name)+1);
  }

  if (Description == NULL) WorkingOpenDevice->Description = NULL;
  else {
   WorkingOpenDevice->Description = MAlloc(strlen(Description)+1);
   memcpy(WorkingOpenDevice->Description,Description,strlen(Description)+1);
  }

   // Add our packet to the list
   if ( FirstOpenDevice == NULL) FirstOpenDevice = WorkingOpenDevice;
   else {
    for ( CurrentOpenDevice = FirstOpenDevice;
          CurrentOpenDevice->next != NULL;
          CurrentOpenDevice = CurrentOpenDevice->next);

         CurrentOpenDevice->next = WorkingOpenDevice;
   }
}

/* 
 * =-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-= **
 *
 *
 * =-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-= **
 */
OpenDeviceList *FindOpenDevice(char *DevName) {

OpenDeviceList  *CurrentOpenDevice;  // Tracking pointer for processing linked list

  // Check list to see if the device is already open
  for( CurrentOpenDevice = FirstOpenDevice;
       CurrentOpenDevice != NULL;
       CurrentOpenDevice = CurrentOpenDevice->next) {

	if ( strcmp(CurrentOpenDevice->Name,DevName) == 0) {

    Verbose(VERYVERYVERBOSE,"Found device in cache: %s\n", CurrentOpenDevice->Name);

   	 return CurrentOpenDevice;
	}
  }

 return NULL;
}

/* 
 * =-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-= **
 *
 *
 * =-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-= **
 */
pcap_t *QueryOpenDevice(char *DeviceName) {

pcap_if_t       *AllDevices = NULL;
pcap_if_t       *CurrentDevice = NULL;
char             ErrorBuffer[PCAP_ERRBUF_SIZE];
int              SelectedDevice = 0;
int              DeviceCount = 0;
char             ReadChar[3];
int              i = 0;
pcap_t          *WorkingDevice = NULL;
OpenDeviceList  *ReturnDevice = NULL;
  

  // We need the information in ALLDevices in either mode so we grab it now
  if (pcap_findalldevs_ex( PCAP_SRC_IF_STRING,
	                       NULL, 
                           &AllDevices, 
                           ErrorBuffer) == -1) {
     printf("%s\n", ErrorBuffer);
     return NULL;
  }

  // Interactive mode
  if (DeviceName == NULL) {

	if (UseLibpcapFile == TRUE) {
	  printf("An output device must be selected for injecting the packets\n\n");
	}
	else {

	   if (UseArgumentPacket == TRUE) {
		 printf("WARNING: No device specified with the -d switch in conjunction with -p switch\n");
         printf("You must select a device for the packet\n\n");
	   }
	   else {
	     printf("\nWARNING: One or more packets in the packet file and did not specify a device\n");
         printf("You must select a default device for those packets\n\n");
	   }
	}

    printf("Available devices:\n\n");

    // Traverse list of devices found
	for (CurrentDevice = AllDevices; CurrentDevice; CurrentDevice = CurrentDevice->next) {
      /* Print a human readable list of the devices found */
	  if (CurrentDevice->description) printf("[%d] %s \n", ++DeviceCount, CurrentDevice->description);
      else printf("[%d] %s \n", ++DeviceCount, CurrentDevice->name);
    }

    printf("\n");
    while ( SelectedDevice == 0) {
     printf("Select default device (1-%d):",DeviceCount);

     fgets(ReadChar,3,stdin);
     SelectedDevice = atoi(ReadChar);
     fflush(stdin); 

     if ( (SelectedDevice < 1) || (SelectedDevice > DeviceCount) ) SelectedDevice = 0;
    }

    // Jump to the selected adapter
    for (CurrentDevice=AllDevices, i=0; i < SelectedDevice-1; CurrentDevice=CurrentDevice->next, i++);

	DeviceName = CurrentDevice->name;

  } // End interactive mode

    // Check to see if the selected default device is already in the cache from the same device
    // being defined in the packet file
    ReturnDevice = FindOpenDevice(DeviceName);
    // If we have found a device in the cache return it
	if (ReturnDevice != NULL) {
	  // If we needed a default device set the name for it here, the return will set DefaultDevice
	  if (NeedDefaultDevice == TRUE) {
	    DefaultDeviceName = ReturnDevice->Name;
	  }

   	 return ReturnDevice->DeviceInstace;
	}

  // If not found in the cache attempt to open the argument passed device 
  if ( (WorkingDevice = pcap_open( DeviceName,
		                           PACKET_CAPTURE_SIZE,
		                           PCAP_OPENFLAG_PROMISCUOUS,
		                           PACKET_READ_TIMEOUT,
                                   NULL,
							       ErrorBuffer) ) == NULL) {
     printf("Device: %s\n", DeviceName);
     printf("%s\n", ErrorBuffer);
   return NULL;
  }


  // Search the returned device list for our device
  for (CurrentDevice = AllDevices; CurrentDevice; CurrentDevice = CurrentDevice->next) {
     // Stop when we find the device that matches the one we opened
	 if ( strcmp(CurrentDevice->name,DeviceName) == 0) {
       AddOpenDevice(WorkingDevice,CurrentDevice->name,CurrentDevice->description);

    Verbose(VERYVERYVERBOSE,"\nUsing device: %s\n", CurrentDevice->name);
    Verbose(VERYVERYVERBOSE,"Data Link: %s\n",pcap_datalink_val_to_description( pcap_datalink(WorkingDevice) ) );

	 // If we have 0 devices defined in the packet file then we will not have triggered the 
	 // default device set when searching the device cache above. So we must set it here
     if ( (NeedDefaultDevice == TRUE) && (DefaultDeviceName == NULL)  /*&& (SelectedDevice > 0)*/ ) {
		// We need to grab the device name from the allocated memory pointer that was created
		// by AddOpenDevice above
        ReturnDevice = FindOpenDevice(DeviceName);
		DefaultDeviceName = ReturnDevice->Name;
	 }

  	  // At this point, we don't need any more the device list. Free it
      pcap_freealldevs(AllDevices);

	  return WorkingDevice;
	 }
  }

  /* At if we are here then we have had a failure and the program is about to exit
     so clean up the best we can */
  pcap_freealldevs(AllDevices);

 return NULL;
}
/* 
 * =-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-= **
 *
 *
 * =-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-= **
 */
void DestroyOpenDevice() {

OpenDeviceList  *WorkingOpenDevice;
OpenDeviceList  *DeleteOpenDevice;


  WorkingOpenDevice = FirstOpenDevice;

  // Loop through the entire OpenDevice lsit and free each entry
  while (WorkingOpenDevice != NULL) {


   DeleteOpenDevice = WorkingOpenDevice;
   WorkingOpenDevice = WorkingOpenDevice->next;

  Verbose(VERYVERYVERBOSE,"Closing device: %s\n", DeleteOpenDevice->Name);

   DeleteOpenDevice->Description = Free(DeleteOpenDevice->Description);
   DeleteOpenDevice->Name = Free(DeleteOpenDevice->Name);

   // Close the open device
   pcap_close(DeleteOpenDevice->DeviceInstace);

   DeleteOpenDevice = Free(DeleteOpenDevice);
  }

}

/* 
 * =-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-= **
 *
 *
 * =-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-= **
 */
void PropogateDefaultDevice() {

int                CurrentPacketNumber = 0;
ProcessingQueue   *CurrentProcessingQueue; // Tracking pointer for processing linked list


  for ( CurrentProcessingQueue = FirstProcessingQueue;
        CurrentProcessingQueue != NULL;
        CurrentProcessingQueue = CurrentProcessingQueue->next ) {

	// If we have a packet with no device defined, then attach the default device
	if ( CurrentProcessingQueue->FirstDevice == NULL ) {

     Verbose(VERYVERYVERBOSE,"No device specified on packet #%d using DefaultDevice: %s\n",CurrentPacketNumber,DefaultDeviceName);

     CurrentProcessingQueue->FirstDevice = MAlloc(sizeof(struct DeviceList));

	 CurrentProcessingQueue->FirstDevice->DeviceInstance = DefaultDevice;
     CurrentProcessingQueue->FirstDevice->Name           = DefaultDeviceName;
	 CurrentProcessingQueue->FirstDevice->next           = NULL; 

	}
   CurrentPacketNumber++;
  }
}


/* 
 * =-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-= **
 *
 *
 * =-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-= **
 */
BOOLEAN SearchDeviceList(DeviceList *theDevice, char *newDeviceName) {

DeviceList  *CurrentDeviceList;

  // If there is no device to search for then just exit
  if (theDevice == NULL) return FALSE;

    for ( CurrentDeviceList = theDevice;
          CurrentDeviceList != NULL;
          CurrentDeviceList = CurrentDeviceList->next) {

		if ( strcmp(CurrentDeviceList->Name,newDeviceName) == 0) return TRUE; 
	}

 return FALSE;
}
/* 
 * =-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-= **
 *
 *
 * =-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-= **
 */
DeviceList *ProcessDeviceList(char **Tokens, int TCount) {

DeviceList  *WorkingDeviceList;
DeviceList  *CurrentDeviceList;
DeviceList  *FirstDevice = NULL;
int          i;
int          DeviceNameSize = 0;
char        *TrimmedDeviceName = NULL;

   // Add each tokenized device to the list
   for ( i=0;i<=TCount;i++ ) {
 
      // Make sure this device is not already defined
	  if (SearchDeviceList(FirstDevice,Tokens[i]) == TRUE) {
        PrintError(WARNING_MESSAGE,"Identical device declaration on a single packet\nDuplicate device : %s\n",Tokens[i]);
       continue;
	  }

	   // Remove leading and trailing blank spaces
       TrimmedDeviceName = strtok(Tokens[i]," \t");
	   DeviceNameSize = strlen(TrimmedDeviceName)+1;

       WorkingDeviceList = MAlloc(sizeof(struct DeviceList));
       WorkingDeviceList->next = NULL;

       WorkingDeviceList->Name = MAlloc(DeviceNameSize);
	   memcpy(WorkingDeviceList->Name,TrimmedDeviceName,DeviceNameSize);

     Verbose(VERYVERYVERBOSE,"Adding Device: %s",WorkingDeviceList->Name);

       WorkingDeviceList->DeviceInstance = QueryOpenDevice(WorkingDeviceList->Name);

	   // Catch any errors returned by QueryOpenDevice
       if (WorkingDeviceList->DeviceInstance == NULL) {
         PrintError(SYNTAX_ERROR,"Error in processing the device\n");
		return NULL;
	   }

	   // If there was a problem opening the device report an error
	   if ( WorkingDeviceList->DeviceInstance == NULL ) return NULL;

       if ( FirstDevice == NULL ) FirstDevice = WorkingDeviceList;
       else {
         for ( CurrentDeviceList = FirstDevice;
               CurrentDeviceList->next != NULL;
               CurrentDeviceList = CurrentDeviceList->next);

            CurrentDeviceList->next = WorkingDeviceList;
		 }
   }

 // We return the first pointer in the device list back to be attached to the packet
 return FirstDevice;
}
