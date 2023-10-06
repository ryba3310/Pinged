#include <stdio.h>
#include "helpers.h"
#include <string.h>
#include <stdarg.h>     // vla and macros for va_list type


int vflag = 0;        // All possible b64chars characters
const char b64chars[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

void set_verbose(int value)
{
    vflag = value;
}

int verbose(const char *restrict format, ...)
{
    if(!vflag)
        return 0;
    va_list arguments;
    va_start(arguments, format);
    int printed = vprintf(format, arguments);
    va_end(arguments);
    return printed;
}

// Encoding takes 3 bytes and encodes it into 4 bytes
static int encoded_b64_len(int input_len)
{
    int encoded_len = input_len;
    if (encoded_len % 3 != 0)
    {
        encoded_len += 3 - (input_len % 3);      // ensuring extra padding in case of input length not being multiple of 3 bytes
    }
    encoded_len /= 3;
    return encoded_len *= 4;
}


char *encode_b64(const unsigned char *input, int input_len)
{
    if (input == NULL || input_len == 0)
    {
        return NULL;
    }
    unsigned int value, encoded_len;
    encoded_len = encoded_b64_len(input_len);
    char *output = malloc(encoded_len + 1);     // Add extra NUL char at end of encoded string
    output[encoded_len] = '\0';

    for (int i = 0, j = 0; i < input_len; i += 3, j += 4) {
        // First store all 3 bytes into 32 bit uint
        value = input[i];
        value = i + 1 < input_len ? (value << 8) | input[i + 1] : value << 8;
        value = i + 2 < input_len ? (value << 8) | input[i + 2] : value << 8;
        // Second divided it into 6 bit long units and for each get it one of corresponding 64 values from the b64 array
        output[j] = b64chars[(value >> 18) & 0x3F];
        output[j + 1] = b64chars[(value >> 12) & 0x3F];
        output[j + 2] = i + 1 < input_len ? b64chars[(value >> 6) & 0x3F] : '=';
        output[j + 3] = i + 2 < input_len ? b64chars[value & 0x3F] : '=';
    }
    return output;
}


void usage()
{
    printf("Usage: pinged [-f path] [-b] [destiantion ip]\n");
}
