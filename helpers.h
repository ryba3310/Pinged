
void usage();
void set_verbose(int value);
int verbose(const char *restrict format, ...);
char *encode_b64(const unsigned char *input, int input_len);
