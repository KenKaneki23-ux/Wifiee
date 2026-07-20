#ifndef INTERFACE_H
#define INTERFACE_H

#include <net/if.h>

#define MAX_INTERFACES 16

struct interface_info {
    char name[IFNAMSIZ];
    char path[128];
    int  is_wireless;
    int  is_monitor;
};

int detect_interfaces(struct interface_info *iface_list, int max_count);
int select_interface(struct interface_info *iface_list, int count, const char *name);
void print_interfaces(struct interface_info *iface_list, int count);

#endif // INTERFACE_H
