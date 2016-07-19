/*
 * Copyright (c) 1999 - 2005 NetGroup, Politecnico di Torino (Italy)
 * Copyright (c) 2005 - 2006 CACE Technologies, Davis (California)
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 * notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 * notice, this list of conditions and the following disclaimer in the
 * documentation and/or other materials provided with the distribution.
 * 3. Neither the name of the Politecnico di Torino, CACE Technologies
 * nor the names of its contributors may be used to endorse or promote
 * products derived from this software without specific prior written
 * permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 */

#ifdef _MSC_VER
/*
 * we do not want the warnings about the old deprecated and unsecure CRT functions
 * since these examples can be compiled under *nix as well
 */
#define _CRT_SECURE_NO_WARNINGS
#endif


#include "pcap.h"
#include "packetparser.h"
#include <time.h>


/* prototype of the packet handler */
void packet_handler(u_char *param, const struct pcap_pkthdr *header, const u_char *pkt_data);


int main()
{
    pcap_if_t *alldevs;
    pcap_if_t *d;
    int inum;
    int i=0;
    pcap_t *adhandle;
    char errbuf[PCAP_ERRBUF_SIZE];
    u_int netmask;
    char packet_filter[] = "tcp";
                           //"tcp or udp";
    struct bpf_program fcode;

    /* Retrieve the device list */
    if(pcap_findalldevs(&alldevs, errbuf) == -1)
    {
        fprintf(stderr,"Error in pcap_findalldevs: %s\n", errbuf);
        return 1;
    }

    /* Print the list */
    for(d=alldevs; d; d=d->next)
    {
        printf("%d. %s", ++i, d->name);
        if (d->description)
            printf(" (%s)\n", d->description);
        else
            printf(" (No description available)\n");
    }

    if(i==0)
    {
        printf("\nNo interfaces found! Make sure WinPcap is installed.\n");
        return -1;
    }

    printf("Enter the interface number (1-%d):",i);
    scanf("%d", &inum);

    /* Check if the user specified a valid adapter */
    if(inum < 1 || inum > i)
    {
        printf("\nAdapter number out of range.\n");

        /* Free the device list */
        pcap_freealldevs(alldevs);
        return -1;
    }


    /* Jump to the selected adapter */
    for(d=alldevs, i=0; i< inum-1 ;d=d->next, i++);

    /* Open the adapter */
    if ((adhandle= pcap_open_live(d->name,	// name of the device
                             65536,			// portion of the packet to capture.
                                            // 65536 grants that the whole packet will be captured on all the MACs.
                             1,				// promiscuous mode (nonzero means promiscuous)
                             1000,			// read timeout
                             errbuf			// error buffer
                             )) == NULL)
    {
        fprintf(stderr,"\nUnable to open the adapter. is not supported by WinPcap\n");
        /* Free the device list */
        pcap_freealldevs(alldevs);
        return -1;
    }



    /* Check the link layer. We support only Ethernet for simplicity. */
    if(pcap_datalink(adhandle) != DLT_EN10MB)
    {
        fprintf(stderr,"\nThis program works only on Ethernet networks.\n");
        /* Free the device list */
        pcap_freealldevs(alldevs);
        return -1;
    }


    if(d->addresses != NULL)
    {
        /* Retrieve the mask of the first address of the interface */
        if(d->addresses->netmask)
        {
#ifdef WIN32
            netmask=((struct sockaddr_in *)(d->addresses->netmask))->sin_addr.S_un.S_addr;
#else
            netmask=((struct sockaddr_in *)(d->addresses->netmask))->sin_addr.s_addr;
#endif
            printf("netmask set\n");
        }
        else
        {
            netmask=0xffffff;
            printf("netmask error\n");
        }
    }
    else
    {
        /* If the interface is without addresses we suppose to be in a C class network */
        netmask=0xffffff;
        printf("netmask error\n");
    }


    //compile the filter
#ifdef WIN32
    if (pcap_compile(adhandle, &fcode, packet_filter, 1, netmask) <0 )
#else
    if (pcap_compile(adhandle, &fcode, packet_filter, 0, netmask) <0 )
#endif
    {
        fprintf(stderr,"\nUnable to compile the packet filter. Check the syntax.\n");
        /* Free the device list */
        pcap_freealldevs(alldevs);
        return -1;
    }


    //set the filter
    if (pcap_setfilter(adhandle, &fcode)<0)
    {
        fprintf(stderr,"\nError setting the filter.\n");
        printf("\nError setting the filter.\n");
        /* Free the device list */
        pcap_freealldevs(alldevs);
        return -1;
    }

    printf("\nlistening on %s...\n", d->description);

    /* At this point, we don't need any more the device list. Free it */
    pcap_freealldevs(alldevs);

    /* start the capture */
    pcap_loop(adhandle, 0, packet_handler, NULL);

    printf("loop terminated\n");
    return 0;
}

/* Callback function invoked by libpcap for every incoming packet */
void packet_handler(u_char *param, const struct pcap_pkthdr *header, const u_char *pkt_data)
{
    struct tm *ltime;
    char timestr[16];    
    time_t local_tv_sec;
    Ethernet_Parser ethernetInformation(pkt_data,header->len);
    IP_Parser* ipInformation;
    UDP_Parser* udpInformation;
    TCP_Parser* tcpInformation;

    /*
     * unused parameter
     */
    (void)(param);

    /* convert the timestamp to readable format */
    local_tv_sec = header->ts.tv_sec;
    ltime=localtime(&local_tv_sec);
    strftime( timestr, sizeof timestr, "%H:%M:%S", ltime);

    /* print timestamp and length of the packet */
    //printf("%s.%.6d len:%d ", timestr, header->ts.tv_usec, header->len);

    char* src,* dst;
    src=ethernetInformation.getSourceAddressAsString();
    dst=ethernetInformation.getDestinationAddressAsString();
    printf("Ethernet %s to %s \n",src,dst);
    delete[] src;
    delete[] dst;
    switch(ethernetInformation.getProtocol())
    {
    case ETHERTYPE_IP:
        ipInformation=ethernetInformation.getIPInformation();

        src=ipInformation->getSourceAddressAsString();
        dst=ipInformation->getDestinationAddressAsString();
        printf("IPv%d %s to %s (data len : %llu)\n",
               ipInformation->getVersion(), src, dst, ipInformation->getLength());
        delete[] src;
        delete[] dst;

        switch(ipInformation->getProtocol())
        {
        case IPPROTO_TCP:
            tcpInformation=ipInformation->getTCP();
            src=tcpInformation->getSourceAddressAsString();
            dst=tcpInformation->getDestinationAddressAsString();
            printf("TCP Port %s to Port %s (data len : %llu)\n",src,dst,tcpInformation->getDataLength());
            delete[] src;
            delete[] dst;
            delete tcpInformation;
            break;
        case IPPROTO_UDP:
            udpInformation=ipInformation->getUDP();
            src=udpInformation->getSourceAddressAsString();
            dst=udpInformation->getDestinationAddressAsString();
            printf("UDP Port %s to Port %s (data len : %llu)\n",src,dst,udpInformation->getDataLength());
            delete[] src;
            delete[] dst;
            delete udpInformation;
            break;
        }
        delete ipInformation;
        break;
    default:
        printf("not IP\n");
    }
    printf("\n");

}
