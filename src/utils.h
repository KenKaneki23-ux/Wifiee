#ifndef UTILS_H
#define UTILS_H

#include <stdint.h>
#include <stdio.h>

// MAC address string length (AA:BB:CC:DD:EE:FF + null)
#define MAC_STR_LEN 18

// Colors for terminal output
#define COLOR_RED     "\033[31m"
#define COLOR_GREEN   "\033[32m"
#define COLOR_YELLOW  "\033[33m"
#define COLOR_BLUE    "\033[34m"
#define COLOR_RESET   "\033[0m"

// Log messages
void log_info(const char *fmt, ...);
void log_success(const char *fmt, ...);
void log_warning(const char *fmt, ...);
void log_error(const char *fmt, ...);

// MAC address formatting
void mac_to_str(const uint8_t *mac, char *str);
int str_to_mac(const char *str, uint8_t *mac);

// Check if running as root
int is_root(void);

// Strip newline from string
void strip_newline(char *str);

#endif // UTILS_H
