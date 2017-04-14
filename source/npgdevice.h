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
#ifndef _NPGDEVICE_H_
#define _NPGDEVICE_H_

#include <pcap.h>
#include <remote-ext.h>
#include "npginjector.h"


#define PACKET_READ_TIMEOUT  1000
#define PACKET_CAPTURE_SIZE  65536

typedef struct OpenDeviceList {

    pcap_t   *DeviceInstace;  // WinPcap instanced device pointer

	char     *Name;           // Name compatible with WinPcap functions
	char     *Description;    // Human readable description

	struct  OpenDeviceList  *next;

} OpenDeviceList;

pcap_t          *DefaultDevice;      // Default device to use when not specified in packet file
char            *DefaultDeviceName;  // String name of the default device used

BOOLEAN          NeedDefaultDevice;  // Interactive marker if not all packets specified devices in the packet file

OpenDeviceList  *FirstOpenDevice;    // Root pointer for beginning of linked list

int              LibpcapQueueSize;    // Memory usage tracking variable
int              LibpcapPacketCount;  // Total packet count in a libpcap compatible file
int              LibpcapFileDataLink; // DataLink layer type reported by libpcap compatible file

void ListDeviceDetails();
pcap_t *OpenLibpcapFileDevice(char *Device, char *PacketFile);
void AddOpenDevice(pcap_t *Device, char *Name, char *Description);
pcap_t *QueryOpenDevice(char *Description);
void DestroyOpenDevice();
void PropogateDefaultDevice();
DeviceList *ProcessDeviceList(char **Tokens, int TCount);

#endif