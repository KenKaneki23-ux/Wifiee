#include "capture.h"
#include "utils.h"
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <linux/wireless.h>

int capture_init(struct capture_handle *handle, const char *iface_name) {
    struct sockaddr_ll sll;
    struct ifreq ifr;
    int optval = 1;

    memset(handle, 0, sizeof(*handle));
    strncpy(handle->iface, iface_name, sizeof(handle->iface) - 1);

    // Create raw socket
    handle->fd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (handle->fd < 0) {
        log_error("Failed to create raw socket (are you root?)");
        return -1;
    }

    // Get interface index
    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, iface_name, IFNAMSIZ - 1);
    if (ioctl(handle->fd, SIOCGIFINDEX, &ifr) < 0) {
        log_error("Failed to get interface index for %s", iface_name);
        close(handle->fd);
        return -1;
    }

    // Bind to interface
    memset(&sll, 0, sizeof(sll));
    sll.sll_family = AF_PACKET;
    sll.sll_ifindex = ifr.ifr_ifindex;
    sll.sll_protocol = htons(ETH_P_ALL);

    if (bind(handle->fd, (struct sockaddr *)&sll, sizeof(sll)) < 0) {
        log_error("Failed to bind to interface %s", iface_name);
        close(handle->fd);
        return -1;
    }

    // Set promiscuous mode
    ifr.ifr_flags |= IFF_PROMISC;
    if (ioctl(handle->fd, SIOCGIFFLAGS, &ifr) < 0) {
        log_warning("Failed to set promiscuous mode");
    }

    // Set socket buffer size
    int bufsize = 2 * 1024 * 1024; // 2MB
    setsockopt(handle->fd, SOL_SOCKET, SO_RCVBUF, &bufsize, sizeof(bufsize));

    // Enable timestamp
    int timestamp = 1;
    setsockopt(handle->fd, SOL_SOCKET, SO_TIMESTAMP, &timestamp, sizeof(timestamp));

    log_success("Capture initialized on %s", iface_name);
    return 0;
}

void capture_close(struct capture_handle *handle) {
    if (handle->fd >= 0) {
        close(handle->fd);
        handle->fd = -1;
    }
}

int capture_set_channel(struct capture_handle *handle, int channel) {
    struct iwreq wrq;

    if (channel < 1 || channel > 14) {
        log_error("Invalid channel: %d (must be 1-14)", channel);
        return -1;
    }

    memset(&wrq, 0, sizeof(wrq));
    strncpy(wrq.ifr_name, handle->iface, IFNAMSIZ - 1);

    // Set frequency (channel to frequency conversion)
    // channels 1-13: 2407 + (channel * 5)
    // channel 14: 2484
    int freq;
    if (channel == 14) {
        freq = 2484;
    } else {
        freq = 2407 + (channel * 5);
    }

    wrq.u.freq.m = freq;
    wrq.u.freq.e = 6; // MHz

    if (ioctl(handle->fd, SIOCSIWFREQ, &wrq) < 0) {
        log_error("Failed to set channel %d", channel);
        return -1;
    }

    handle->channel = channel;
    return 0;
}

int capture_get_channel(struct capture_handle *handle) {
    return handle->channel;
}

int capture_channel_hop(struct capture_handle *handle, int channels[], int num_channels,
                        int dwell_time_ms, packet_callback callback, void *user_data) {
    uint8_t buffer[MAX_PACKET_SIZE];
    int packet_len;
    int current_channel = 0;

    log_info("Starting channel hopping (dwell time: %d ms)...", dwell_time_ms);

    while (1) {
        // Set channel
        if (capture_set_channel(handle, channels[current_channel]) < 0) {
            log_error("Failed to set channel %d, skipping...", channels[current_channel]);
            current_channel = (current_channel + 1) % num_channels;
            continue;
        }

        // Wait for packets on this channel
        struct timeval start, now;
        gettimeofday(&start, NULL);

        do {
            packet_len = capture_packet(handle, buffer, sizeof(buffer), 100);
            if (packet_len > 0 && callback) {
                callback(buffer, packet_len, user_data);
            }
            gettimeofday(&now, NULL);
        } while (((now.tv_sec - start.tv_sec) * 1000 +
                  (now.tv_usec - start.tv_usec) / 1000) < dwell_time_ms);

        // Move to next channel
        current_channel = (current_channel + 1) % num_channels;
    }

    return 0;
}

int capture_packet(struct capture_handle *handle, uint8_t *buffer, int bufsize, int timeout_ms) {
    struct timeval tv;
    fd_set readfds;
    int ret;

    tv.tv_sec = timeout_ms / 1000;
    tv.tv_usec = (timeout_ms % 1000) * 1000;

    FD_ZERO(&readfds);
    FD_SET(handle->fd, &readfds);

    ret = select(handle->fd + 1, &readfds, NULL, NULL, &tv);
    if (ret < 0) {
        return -1;
    }
    if (ret == 0) {
        return 0; // Timeout
    }

    return recv(handle->fd, buffer, bufsize, 0);
}
