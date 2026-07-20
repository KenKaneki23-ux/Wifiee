#ifndef MONITOR_H
#define MONITOR_H

#include <linux/if.h>

// Put interface into monitor mode
// Returns 0 on success, -1 on failure
int enable_monitor_mode(const char *iface_name);

// Restore interface to managed mode
// Returns 0 on success, -1 on failure
int disable_monitor_mode(const char *iface_name);

// Get current interface mode
// Returns mode string (e.g., "monitor", "managed")
const char* get_interface_mode(const char *iface_name);

#endif // MONITOR_H
