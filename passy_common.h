#pragma once

#include <mbedtls/des.h>
#include <furi.h>
#include <toolbox/bit_buffer.h>

typedef enum {
    PassyReadNone = 0,
    PassyReadDG1,
    PassyReadDG2,
    PassyReadDG7,
} PassyReadType;

void passy_log_bitbuffer(char* tag, char* prefix, BitBuffer* buffer);
void passy_log_buffer(char* tag, char* prefix, uint8_t* buffer, size_t buffer_len);
void passy_mac(uint8_t* key, uint8_t* data, size_t data_length, uint8_t* mac, bool prepadded);
char passy_checksum(char* str);
int print_struct_callback(const void* buffer, size_t size, void* app_key);
