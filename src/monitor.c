#include "monitor.h"
#include "utils.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <linux/wireless.h>

// Execute shell command and return status
static int exec_cmd(const char *cmd) {
    int ret = system(cmd);
    if (ret != 0) {
        log_error("Command failed: %s", cmd);
    }
    return ret;
}

// Set interface down
static int set_interface_down(const char *iface_name) {
    char cmd[128];
    snprintf(cmd, sizeof(cmd), "ip link set %s down 2>/dev/null", iface_name);
    return exec_cmd(cmd);
}

// Set interface up
static int set_interface_up(const char *iface_name) {
    char cmd[128];
    snprintf(cmd, sizeof(cmd), "ip link set %s up 2>/dev/null", iface_name);
    return exec_cmd(cmd);
}

// Set monitor mode using iw
static int set_monitor_mode_iw(const char *iface_name) {
    char cmd[128];
    snprintf(cmd, sizeof(cmd), "iw %s set monitor control 2>/dev/null", iface_name);
    return exec_cmd(cmd);
}

// Alternative: Set monitor mode using iwconfig (legacy)
static int set_monitor_mode_iwconfig(const char *iface_name) {
    char cmd[128];
    snprintf(cmd, sizeof(cmd), "iwconfig %s mode monitor 2>/dev/null", iface_name);
    return exec_cmd(cmd);
}

// Kill interfering processes (NetworkManager, wpa_supplicant, etc.)
static void kill_interfering_processes(void) {
    log_info("Killing interfering processes...");
    exec_cmd("systemctl stop NetworkManager 2>/dev/null");
    exec_cmd("killall -9 NetworkManager 2>/dev/null");
    exec_cmd("killall -9 wpa_supplicant 2>/dev/null");
    exec_cmd("killall -9 dhclient 2>/dev/null");
    exec_cmd("killall -9 dhcpcd 2>/dev/null");
    exec_cmd("killall -9 hostapd 2>/dev/null");
    exec_cmd("killall -9 avahi-daemon 2>/dev/null");
    usleep(500000);
}

int enable_monitor_mode(const char *iface_name) {
    log_info("Putting %s into monitor mode...", iface_name);

    // Check if already in monitor mode
    const char *current_mode = get_interface_mode(iface_name);
    if (strcmp(current_mode, "monitor") == 0) {
        log_warning("Interface %s is already in monitor mode", iface_name);
        return 0;
    }

    // Kill interfering processes
    kill_interfering_processes();

    // Bring interface down
    log_info("Bringing interface down...");
    if (set_interface_down(iface_name) != 0) {
        char cmd[128];
        snprintf(cmd, sizeof(cmd), "ifconfig %s down 2>/dev/null", iface_name);
        exec_cmd(cmd);
    }

    usleep(200000);

    // Set monitor mode with iw (preferred)
    log_info("Setting monitor mode...");
    if (set_monitor_mode_iw(iface_name) != 0) {
        log_warning("iw failed, trying iwconfig...");
        if (set_monitor_mode_iwconfig(iface_name) != 0) {
            log_error("Failed to set monitor mode");
            return -1;
        }
    }

    // Bring interface back up
    log_info("Bringing interface up...");
    if (set_interface_up(iface_name) != 0) {
        char cmd[128];
        snprintf(cmd, sizeof(cmd), "ifconfig %s up 2>/dev/null", iface_name);
        exec_cmd(cmd);
    }

    usleep(200000);

    // Verify mode
    const char *new_mode = get_interface_mode(iface_name);
    if (strcmp(new_mode, "monitor") == 0) {
        log_success("Interface %s is now in monitor mode", iface_name);
        return 0;
    }

    log_error("Failed to verify monitor mode");
    return -1;
}

int disable_monitor_mode(const char *iface_name) {
    log_info("Restoring %s to managed mode...", iface_name);

    set_interface_down(iface_name);
    usleep(200000);

    // Try iw first
    char cmd[128];
    snprintf(cmd, sizeof(cmd), "iw %s set type managed 2>&1", iface_name);
    int ret = system(cmd);

    if (ret != 0) {
        // Fallback: iwconfig
        snprintf(cmd, sizeof(cmd), "iwconfig %s mode managed 2>&1", iface_name);
        system(cmd);
    }

    set_interface_up(iface_name);
    usleep(200000);

    // Verify
    const char *mode = get_interface_mode(iface_name);
    if (strcmp(mode, "managed") == 0) {
        log_success("Interface %s restored to managed mode", iface_name);
    } else {
        log_warning("Interface mode is '%s' (expected 'managed')", mode);
    }
    return 0;
}

const char* get_interface_mode(const char *iface_name) {
    static char mode[32] = {0};
    char cmd[128];
    FILE *fp;

    snprintf(cmd, sizeof(cmd), "iw %s info 2>/dev/null | grep type | awk '{print $2}'", iface_name);
    fp = popen(cmd, "r");
    if (fp) {
        if (fgets(mode, sizeof(mode), fp)) {
            strip_newline(mode);
            pclose(fp);
            if (strlen(mode) > 0) {
                return mode;
            }
        }
        pclose(fp);
    }

    strncpy(mode, "unknown", sizeof(mode) - 1);
    return mode;
}

int ensure_monitor_mode(const char *iface_name) {
    const char *mode = get_interface_mode(iface_name);
    if (strcmp(mode, "monitor") == 0) {
        return 0;
    }
    log_warning("Interface dropped out of monitor mode (now: %s), re-enabling...", mode);
    return enable_monitor_mode(iface_name);
}
