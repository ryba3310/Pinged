
void set_verbose(int value);

int verbose(const char *restrict format, ...);

char *encode_b64(const char *input, int input_len);

void usage();

unsigned short checksum(void *buffer, int length);
