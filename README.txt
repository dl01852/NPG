NAME

npg - Network Packet Generator

DESCRIPTION

Network Packet Generator (npg) is a free GNU GPL Windows packet injector (generator) that utilizes WinPcap to send specific packets out a single or multiple network interfaces. These packets and other extended options can be defined on the command line, in a packet file, or combination of the two. A packet file can be either a Libpcap compatible capture dump or an npg formatted file that generates packets from raw byte streams providing the ability to create any packet type regardless of header, payload, or data link.


SYNOPSIS

npg
    [-?hlw]
    [-vvvw] -fF <packet file name> -d <device interface>
    [-rtvvv] -p <packet stream> -d <device interface>


OPTIONS

-d <interface device>
  Specifies a single device that will be used as a default device for any packets 
  that do not explicitly define a device or devices to be injected through.

-f <npg packet file name>
  Npg formatted packet file that defines the packets to be injected, and 
  optionally their repeat count, time interval, device list, and PacketID

-F <Libpcap compatible packet file name>
  Libpcap compatible packet file that will have its contents injected.

-l
  Displays a list of usable interfaces in a format compatible with the -d switch.

-p <packet stream>
  Specifies a single packet stream to be injected. This stream cannot contain 
  any spaces and must be formatted in two character hex value byte. 00 - FF

-r <repeat count>
  Numeric count of how many times to re inject the current packet. If time 
  intervals are defined it will wait the specified time before re injecting 
  each packet. This switch is only viable when used in conjunction with 
  the -p switch.

-s
  Synchronize the injected packets according to the time stamps specified in a 
  Libpcap compatible file. This switch is only viable when used in conjunction 
  with the -F switch or Libpcap compatible file.

-t <time interval>
  Specifies the time interval in milliseconds to wait before the packet is injected.
  This switch is only viable when used in conjunction with the -p switch.

-v, -vv, -vvv
  Verbose, Very Verbose, and Very Very Verbose. Determines how much status npg will 
  display during operation. Verbose displaying minimum progress messages, 
  Very Verbose displaying large amounts of status messages, and 
  Very Very Very Verbose spamming incredible amounts of messages.

-w
  Displays the current version of WinPcap installed.

-?, -h
   Displays copyright information and list of command line switches.


*If no options are specified then npg will run in interactive mode and use prompt menus for operation.


WRITING A NPG PACKET FILE

A packet file consists of a mandatory packet block accompanied with optional injection rate, device list, and packet ID identifiers. 


 Packet Block

A packet block is a stream of 4 bit hex value identifiers between a starting { and ending }. Each hex number is formatted as a two character byte expressed as a value between 00 and FF. This collection of numbers make up a raw packet stream where all headers and payloads must be defined by the user. Any spaces, tabs, or comments inside a packet block will be ignored by the npg file parser.

Example: { 01 02 03 04 05 06 06 05 04 03 02 01 08 00 }
Example: { 01 02 03 04 05 06
           06 05 04 03 02 01
           08 00 }
Example: {0102030405060605040302010800}
Example: {
          0
          1
          0
          2
          0
          3
         }

 Injection rate bracket

A single injection rate bracket may be defined before each packet block to inform the injector of how many times to inject the packet and how long to wait before each injection. 

Declaring a rate bracket is done anywhere before the packet block with an opening [ and finished with a closing ]. The first numeric value inside this bracket will define the repeat count followed by a , delimiter and then another numeric value defining a milliseconds wait time interval.

Example: [0,1000]
Example: [3,0]
Example: [ 2 , 3000 ]


 Packet ID bracket

Each packet can be tagged with a string value identifier between < and > brackets that will be displayed each time the packet is injected. In order to display a > character within a packet ID bracket you would declare it as >>.

Example: <This is an example of displaying a >> character within a packet ID bracket>
Example: <This is an example packet id message>
Example: < Multiple use of >> characters >> in a >> packetID >


 Device bracket

Each individual packet can specify a single or multiple network device interfaces from witch it will be injected. To obtain a list of valid interface devices on the system npg can be run with the -l switch. When using an npg packet file if any packets are found without at least one assigned interface device an interactive menu will be triggered to assign a single default device to all unassigned packets. A libpcap compatible file does not store device information limiting it to single device injection and will always trigger an interactive default device selection menu.

Example: (rpcap://\Device\NPF_{AB070CF2-8017-V021-B007-19300C0F301C})
Example: (    rpcap://\Device\NPF_{AB070CF2-8017-V021-B007-19300C0F301C} )
Example: (rpcap://\Device\NPF_{AB070CF2-8017-V021-B007-19300C0F301C} ,rpcap://\Device\NPF_{AC0700F2-1A10-V011-BG07-19A300C0F301C})


 Comments

Comments can be added anywhere in the packet file using the # delimiter with anything past the delimiter to the EOL being ignored by the parser.

Example: {
          # Ethernet HEADER -----

          01 02 03 04 05 06  # Destination MAC
          06 05 04 03 02 01  # Source MAC
          08 00              # Protocol 
         }
Example: [1,1]<Ping Packet>#From this point on till EOL is ignored by the parser
Example: # This entire line has been commented 


BUG REPORTS, COMMENTS, SUGGESTIONS

The talk page for the live npg documentation is the preferred method:
http://www.wikistc.org/wiki/Talk:Network_packet_generator

or email:
npg@wikistc.org

Live documentation @ http://www.wikistc.org/wiki/Network_packet_generator