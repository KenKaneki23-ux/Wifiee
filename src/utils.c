#include "utils.h"
#include <stdarg.h>
#include <string.h>
#include <unistd.h>
#include <ctype.h>

void log_info(const char *fmt, ...) {
    va_list args;
    printf("[*] ");
    va_start(args, fmt);
    vprintf(fmt, args);
    va_end(args);
    printf("\n");
}

void log_success(const char *fmt, ...) {
    va_list args;
    printf("[+] ");
    va_start(args, fmt);
    vprintf(fmt, args);
    va_end(args);
    printf("\n");
}

void log_warning(const char *fmt, ...) {
    va_list args;
    printf("[-] ");
    va_start(args, fmt);
    vprintf(fmt, args);
    va_end(args);
    printf("\n");
}

void log_error(const char *fmt, ...) {
    va_list args;
    fprintf(stderr, "[!] ERROR: ");
    va_start(args, fmt);
    vfprintf(stderr, fmt, args);
    va_end(args);
    fprintf(stderr, "\n");
}

void mac_to_str(const uint8_t *mac, char *str) {
    sprintf(str, "%02X:%02X:%02X:%02X:%02X:%02X",
            mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
}

int str_to_mac(const char *str, uint8_t *mac) {
    unsigned int values[6];
    if (sscanf(str, "%02X:%02X:%02X:%02X:%02X:%02X",
               &values[0], &values[1], &values[2],
               &values[3], &values[4], &values[5]) != 6) {
        return -1;
    }
    for (int i = 0; i < 6; i++) {
        mac[i] = (uint8_t)values[i];
    }
    return 0;
}

int is_root(void) {
    return geteuid() == 0;
}

void strip_newline(char *str) {
    int len = strlen(str);
    while (len > 0 && (str[len - 1] == '\n' || str[len - 1] == '\r')) {
        str[--len] = '\0';
    }
}
