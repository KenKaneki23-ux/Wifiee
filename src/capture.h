#ifndef CAPTURE_H
#define CAPTURE_H

#include <stdint.h>
#include <linux/if_ether.h>

// Maximum packet size
#define MAX_PACKET_SIZE 2048

// Capture handle structure
struct capture_handle {
    int fd;                     // Raw socket file descriptor
    char iface[16];             // Interface name
    int channel;                // Current channel
};

// Initialize capture handle
// Returns 0 on success, -1 on failure
int capture_init(struct capture_handle *handle, const char *iface_name);

// Close capture handle
void capture_close(struct capture_handle *handle);

// Set channel (1-14)
// Returns 0 on success, -1 on failure
int capture_set_channel(struct capture_handle *handle, int channel);

// Get current channel
int capture_get_channel(struct capture_handle *handle);

// Channel hop loop (for scanning)
// Calls callback for each packet received
// Returns 0 on success, -1 on failure
typedef void (*packet_callback)(const uint8_t *packet, int length, void *user_data);
int capture_channel_hop(struct capture_handle *handle, int channels[], int num_channels,
                        int dwell_time_ms, packet_callback callback, void *user_data);

// Capture single packet (blocking)
// Returns packet length, 0 on timeout, -1 on error
int capture_packet(struct capture_handle *handle, uint8_t *buffer, int bufsize, int timeout_ms);

#endif // CAPTURE_H
