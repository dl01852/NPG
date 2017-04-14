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
#include "npginjector.h"
#include "npgdevice.h"
#include "npgoutput.h"
#include "npgutils.h"
#include "npgfile.h"
#include "npg.h"

/* 
 * =-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-= **
 *
 *
 * =-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-= **
 */
void InjectPacketLibpcapFile() {

float         CPUTime;
u_int         BytesSent;
int           Sync;
BOOLEAN       FailedPacket = FALSE;


  // Make sure the output device datalink layer matches the capture file datalink layer
  if ( LibpcapFileDataLink != pcap_datalink(DefaultDevice) ) {
    PrintError(FATAL_ERROR,"Datalink layer mismatch\n");
	exit(1);
  }

  // Check if this is a time interval injection
  if (WinPcapSyncPackets == 2 ) {
    Sync = 0;
    Verbose(VERBOSE,"Injecting packet queue ignoring time intervals\n\n");
   }
  else {
	Sync = 1;

    Verbose(VERBOSE,"Injecting packet queue obeying time intervals\n");
    Verbose(VERBOSE,"During this process there will be no visual feedback until the queue is emtpy\n\n");
  }

  CPUTime = (float) clock();

  if ( (BytesSent = pcap_sendqueue_transmit(DefaultDevice, PcapSendQueue, Sync) ) < PcapSendQueue->len) {
	printf("WARNING: %s. Only %d bytes were sent\n", pcap_geterr(DefaultDevice), BytesSent);
	FailedPacket = TRUE;
  }

  CPUTime = (clock() - CPUTime)/CLK_TCK;

   Verbose(VERBOSE,"Elapsed time : %5.3f\n",CPUTime);
  if (FailedPacket != TRUE) Verbose(VERBOSE,"%d packets successfully injected\n",LibpcapPacketCount);
   Verbose(VERBOSE,"%d bytes sent\n",BytesSent);
}

/* 
 * =-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-= **
 *
 *
 * =-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-= **
 */
void InjectPacketQueue() {

int                TotalPacketCounter = 0;
int                UniquePacketCounter = 0;
float              CPUTime;
int                RepeatCount;
DeviceList        *CurrentDevice;
ProcessingQueue   *CurrentProcessingQueue; // Tracking pointer for processing linked list

  if (UseTimeIntervals == FALSE ) Verbose(VERBOSE,"Injecting packet queue ignoring time intervals\n\n");
  else Verbose(VERBOSE,"Injecting packet queue obeying time intervals\n\n");
  
  // Start elapsed time counter
  CPUTime = (float) clock();

  // Loop through our ProcessingQueue and add each packet to the pcap queue
  for ( CurrentProcessingQueue = FirstProcessingQueue;
        CurrentProcessingQueue != NULL;
        CurrentProcessingQueue = CurrentProcessingQueue->next ) {
     UniquePacketCounter++;

     // Loop through our repeat count at the specified time interval
     for (RepeatCount=0;RepeatCount<=CurrentProcessingQueue->RepeatCount;RepeatCount++) {		   

	    // If we are using timing intervals then wait the appropriate time
        if (UseTimeIntervals == TRUE) {
          Verbose(VERYVERBOSE,"Waiting approximately %d milliseconds\n",CurrentProcessingQueue->TimeInterval);

         Sleep(CurrentProcessingQueue->TimeInterval);
		}

	    // Loop through each device and inject the packet
	    for ( CurrentDevice = CurrentProcessingQueue->FirstDevice;
	          CurrentDevice != NULL;
		      CurrentDevice = CurrentDevice->next ) {
           TotalPacketCounter++;

    Verbose(VERYVERBOSE,"Injecting Packet #%d\nDevice: %s\nPacket ID: %s\nRepeat count: %d\n\n",UniquePacketCounter,CurrentDevice->Name,CurrentProcessingQueue->PacketID,RepeatCount);

            pcap_sendpacket( CurrentDevice->DeviceInstance,
	                         CurrentProcessingQueue->thePacket,
                             CurrentProcessingQueue->PacketSize);
	    }

	 } // End for (RepeatCount=0;RepeatCount<=CurrentProcessingQueue->RepeatCount;RepeatCount++)
   } // End for ( CurrentProcessingQueue = FirstProcessingQueue;

  CPUTime = (clock() - CPUTime) / CLK_TCK;
  Verbose(VERBOSE,"\nA total of %d packets successfully injected\n",TotalPacketCounter);
  Verbose(VERBOSE,"%d of the %d were uniquely defined packets\n",UniquePacketCounter,TotalPacketCounter);
  Verbose(VERBOSE,"Elapsed time : %5.3f\n",CPUTime);
}

/* 
 * =-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-= **
 *
 *
 * =-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-= **
 */
void QueuePacket(u_int32_t TInterval, int PktSize, u_char *thePkt, char *PktID, int RCount, DeviceList *DevList) {

ProcessingQueue   *WorkingProcessingQueue;
ProcessingQueue   *CurrentProcessingQueue; // Tracking pointer for processing linked list
int                PktIDSize = 0;


   WorkingProcessingQueue = malloc(sizeof(ProcessingQueue));

   WorkingProcessingQueue->thePacket = malloc(sizeof(u_char)*PktSize);
   memcpy(WorkingProcessingQueue->thePacket,thePkt,sizeof(u_char)*PktSize);

   WorkingProcessingQueue->PacketSize     = PktSize;
   WorkingProcessingQueue->TimeInterval   = TInterval;
   WorkingProcessingQueue->RepeatCount    = RCount;
   WorkingProcessingQueue->next           = NULL;

   // If any single packet without a device specified is found we default to interactive mode
   if (DevList == NULL) {
	 WorkingProcessingQueue->FirstDevice = NULL;
	 NeedDefaultDevice = TRUE; 
   }
   else {
	 WorkingProcessingQueue->FirstDevice = MAlloc(sizeof(struct DeviceList));
     memcpy(WorkingProcessingQueue->FirstDevice,DevList,sizeof(struct DeviceList));
   }

   // If a packetID was defined attach it
   if (PktID != NULL) {
     PktIDSize = strlen(PktID)+1;

     WorkingProcessingQueue->PacketID = MAlloc(PktIDSize);
 	 memcpy(WorkingProcessingQueue->PacketID,PktID,PktIDSize);
   }
   else WorkingProcessingQueue->PacketID = NULL;

   // Add our packet to the list
   if ( FirstProcessingQueue == NULL) FirstProcessingQueue = WorkingProcessingQueue;
   else {
    for( CurrentProcessingQueue = FirstProcessingQueue;
         CurrentProcessingQueue->next != NULL;
         CurrentProcessingQueue = CurrentProcessingQueue->next);

         CurrentProcessingQueue->next = WorkingProcessingQueue;
   }

}

/* 
 * =-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-= **
 *
 *
 * =-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-= **
 */
char QueueLibpcapPacket(pcap_t *CFile) {

int                   Error;
struct pcap_pkthdr   *pktheader;
u_char               *pktdata;
float                 CPUTime = 0;


  CPUTime = (float) clock();

  // Allocate the pcap queue
  PcapSendQueue = pcap_sendqueue_alloc(LibpcapQueueSize);

  // Fill the queue with the packets from the file
  while ((Error = pcap_next_ex( CFile, &pktheader, &pktdata)) == 1) {
	   if (pcap_sendqueue_queue(PcapSendQueue, pktheader, pktdata) == -1) {
		 printf("WARNING: packet buffer too small, not all the packets will be sent.\n");
		 break;
	   }

   LibpcapPacketCount++;
  }

  // Error check loading the queue
  if (Error == -1){
    printf("Corrupted input file.\n");
    pcap_sendqueue_destroy(PcapSendQueue);

   return -1;
  }

  // End file processing time
  CPUTime = (clock() - CPUTime) / CLK_TCK;

 Verbose(VERBOSE,"\nSuccessfully processed %d packets in %s\n",LibpcapPacketCount,PacketFileName);
 Verbose(VERBOSE,"%d bytes allocated in packet queue to be sent\n",LibpcapQueueSize);
 Verbose(VERBOSE,"Elapsed time : %5.3f\n\n",CPUTime);

 return 0;
}

/* 
 * =-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-= **
 *
 *
 * =-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-= **
 */
void DestroyProcessingQueue() {

ProcessingQueue   *DeleteProcessingQueue;
DeviceList        *DeleteDeviceList;
DeviceList        *CurrentDeviceList;
ProcessingQueue   *CurrentProcessingQueue; // Tracking pointer for processing linked list

  CurrentProcessingQueue = FirstProcessingQueue;

  // Loop through the entire ProcessingQueue and free each entry
  while ( CurrentProcessingQueue != NULL ) {

     DeleteProcessingQueue  = CurrentProcessingQueue;
     CurrentProcessingQueue = CurrentProcessingQueue->next;

     CurrentDeviceList = DeleteProcessingQueue->FirstDevice;

     while ( CurrentDeviceList != NULL ) {

        DeleteDeviceList  = CurrentDeviceList;
        CurrentDeviceList = CurrentDeviceList->next;

     /* This is so we can use one memory location for all packets using the default device name 
        without allocating memory for the name on each packet. Caveat being we can only free it
        once and need to make sure we don't attempt to more than once */
        if ( (DefaultDeviceName != NULL) && 
		     (strcmp(DeleteDeviceList->Name,DefaultDeviceName) != 0) ) {

    Verbose(VERYVERYVERBOSE,"Releasing %d bytes used for DefaultDeviceName\n", strlen(DeleteDeviceList->Name));

          DeleteDeviceList->Name = Free(DeleteDeviceList->Name);
          DefaultDeviceName = NULL;
        }

      DeleteDeviceList = Free(DeleteDeviceList);
	 } // End while ( CurrentDeviceList != NULL )


     DeleteProcessingQueue->thePacket = Free(DeleteProcessingQueue->thePacket);
     DeleteProcessingQueue->PacketID  = Free(DeleteProcessingQueue->PacketID);
     DeleteProcessingQueue            = Free(DeleteProcessingQueue);
  } // End while ( CurrentProcessingQueue != NULL )

}

/* 
 * =-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-= **
 *
 *
 * =-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-= **
 */
void DestroyLibpcapQueue() {

 Verbose(VERYVERBOSE,"Releasing %d bytes used for LibpcapQueue\n",LibpcapQueueSize);

 pcap_sendqueue_destroy(PcapSendQueue); // Free the queue
}