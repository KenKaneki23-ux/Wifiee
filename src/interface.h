#ifndef INTERFACE_H
#define INTERFACE_H

#include <linux/if.h>

// Maximum number of interfaces to scan
#define MAX_INTERFACES 16

// Structure to hold interface information
struct interface_info {
    char name[IFNAMSIZ];   // Interface name (e.g., wlan0)
    char path[64];         // Sysfs path
    int  is_wireless;      // 1 if wireless, 0 if not
    int  is_monitor;       // 1 if already in monitor mode
};

// Auto-detect WiFi interfaces
// Returns number of interfaces found, fills iface_list
int detect_interfaces(struct interface_info *iface_list, int max_count);

// Select interface (first found or by name)
// Returns index in iface_list, or -1 if not found
int select_interface(struct interface_info *iface_list, int count, const char *name);

// Print detected interfaces
void print_interfaces(struct interface_info *iface_list, int count);

#endif // INTERFACE_H
