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
#ifndef _NPGINJECTOR_H_
#define _NPGINJECTOR_H_

#include <pcap.h>
#include <remote-ext.h>

#define PACKETBUFFER 2048 // Size of our temporary processing packet array


typedef struct DeviceList {

        pcap_t              *DeviceInstance; // Which DeviceInstance to send the packet out of
		char                *Name;           // -d name of the device used

        struct DeviceList   *next;
} DeviceList;

// This structure contains any relevant information about the packet we are injecting
typedef struct ProcessingQueue {

        DeviceList     *FirstDevice; // List of all devices this packet will be sent out on

	    long            TimeInterval;// wait time before injection
		int             RepeatCount; // how many times do we repeat injection of this packet

		int             PacketSize;  // Size of the packet in bytes
		char           *PacketID;    // User defined console message displayed when packet is sent

        u_char         *thePacket;   // Raw packet stream

        struct ProcessingQueue   *next;

} ProcessingQueue;

ProcessingQueue   *FirstProcessingQueue;   // Root pointer for beginning of linked list
pcap_send_queue   *PcapSendQueue;          // Wimpcap variable for injceting libpcap compatible files


void InjectPacketLibpcapFile();
void InjectPacketQueue();
char QueueLibpcapPacket(pcap_t *CFile);
void QueuePacket(u_int32_t TInterval, int PktSize, u_char *thePkt, char *Msg,int RCount, DeviceList *DevList);
void DestroyProcessingQueue();
void DestroyLibpcapQueue();

#endif