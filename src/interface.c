#include "interface.h"
#include "utils.h"
#include <stdio.h>
#include <string.h>
#include <dirent.h>
#include <sys/stat.h>

// Check if interface is wireless by examining sysfs
static int is_wireless_interface(const char *iface_name) {
    char path[128];
    struct stat st;

    // Check /sys/class/net/{iface}/wireless exists
    snprintf(path, sizeof(path), "/sys/class/net/%s/wireless", iface_name);
    if (stat(path, &st) == 0) {
        return 1;
    }

    // Alternative: check /sys/class/net/{iface}/phy80211
    snprintf(path, sizeof(path), "/sys/class/net/%s/phy80211", iface_name);
    if (stat(path, &st) == 0) {
        return 1;
    }

    return 0;
}

// Check if interface is in monitor mode
static int is_monitor_mode(const char *iface_name) {
    char path[128];
    char mode[32] = {0};
    FILE *fp;

    // Read from /sys/class/net/{iface}/type or use ioctl
    // For simplicity, we'll check via /sys/class/net/{iface}/wireless
    snprintf(path, sizeof(path), "/sys/class/net/%s/type", iface_name);
    fp = fopen(path, "r");
    if (fp) {
        if (fgets(mode, sizeof(mode), fp)) {
            strip_newline(mode);
            // Type 803 = monitor mode (simplified check)
            if (strcmp(mode, "803") == 0) {
                fclose(fp);
                return 1;
            }
        }
        fclose(fp);
    }
    return 0;
}

int detect_interfaces(struct interface_info *iface_list, int max_count) {
    DIR *dir;
    struct dirent *entry;
    int count = 0;

    dir = opendir("/sys/class/net/");
    if (!dir) {
        log_error("Failed to open /sys/class/net/");
        return -1;
    }

    while ((entry = readdir(dir)) != NULL && count < max_count) {
        // Skip . and .. and non-wireless entries
        if (entry->d_name[0] == '.') {
            continue;
        }

        // Skip loopback and common non-wireless interfaces
        if (strcmp(entry->d_name, "lo") == 0 ||
            strcmp(entry->d_name, "eth0") == 0 ||
            strncmp(entry->d_name, "docker", 6) == 0 ||
            strncmp(entry->d_name, "veth", 4) == 0 ||
            strncmp(entry->d_name, "br-", 3) == 0) {
            continue;
        }

        if (is_wireless_interface(entry->d_name)) {
            strncpy(iface_list[count].name, entry->d_name, IFNAMSIZ - 1);
            iface_list[count].name[IFNAMSIZ - 1] = '\0';
            snprintf(iface_list[count].path, sizeof(iface_list[count].path),
                     "/sys/class/net/%s", entry->d_name);
            iface_list[count].is_wireless = 1;
            iface_list[count].is_monitor = is_monitor_mode(entry->d_name);
            count++;
        }
    }

    closedir(dir);
    return count;
}

int select_interface(struct interface_info *iface_list, int count, const char *name) {
    if (name == NULL) {
        // Auto-select first interface
        if (count > 0) {
            return 0;
        }
        return -1;
    }

    // Find by name
    for (int i = 0; i < count; i++) {
        if (strcmp(iface_list[i].name, name) == 0) {
            return i;
        }
    }

    return -1;
}

void print_interfaces(struct interface_info *iface_list, int count) {
    if (count == 0) {
        log_warning("No wireless interfaces found!");
        return;
    }

    log_info("Detected wireless interfaces:");
    for (int i = 0; i < count; i++) {
        printf("  [%d] %s", i, iface_list[i].name);
        if (iface_list[i].is_monitor) {
            printf(" (monitor mode)");
        }
        printf("\n");
    }
}
