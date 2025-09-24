#include <pcap.h> // libpcap declarations (pcap_findalldevs, pcap_if_t,  PCAP_ERRBUF_SIZE, etc.)
#include <stdio.h>

int main(void) {
    char errbuf[PCAP_ERRBUF_SIZE]; // buffer for human-readable error messages from libpcap
    pcap_if_t *alldevs = NULL;     // will point to the head of a linked list of interfaces

    // Ask libpcap to enumerate capture and write the linked list address into 'alldevs'.
    // Return: 0 on success, -1 on error (with 'errbuf' filled).
    if (pcap_findalldevs(&alldevs, errbuf) == -1) {
        fprintf(stderr, "pcap_findalldevs failed: %s\n", errbuf);
        return 1; // non-zero = error exit
    }

    int i = 0;
    // iterate the singly-linked list: each node is a 'pcap_if_t'; points to the next node
    for (pcap_if_t *d = alldevs; d != NULL; d = d->next) {
        // d->name is the OS interface name (e.g., "eth0", "wlan0", "lo").
        // The ternary guards against NULL names
        printf("%d) %s", ++i, d->name ? d-> name : "(no-name)");

        // Some platforms provide a human-readable description; print it if present.
        if (d->description) {
            printf("  -  %s", d->description);
        }
        printf("\n");
    }

    if(i == 0) {
        printf("No devices found.\n");
    }

    // Free the allocated list to avoid memory leak
    pcap_freealldevs(alldevs);
    return 0;

}