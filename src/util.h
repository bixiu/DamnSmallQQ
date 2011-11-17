/*
 * util.h
 *
 *  Created on: Mar 17, 2009
 *  	Author: Phoebus Veiz <phoebusveiz@gmail.com>
 */

#ifndef UTIL_H_
#define UTIL_H_

#ifdef SAFE_STR
char* strncpy_s(char* dest, const char *src, size_t n);
#endif

void log_error(const char* e);

/*
 *convert a uint8_t array to hex string.
 *hex string format example:"AF B0 80 7D"
 */
char* bytes_to_hex_string(const unsigned char* in, size_t size);

/*
 * convert a hex string to a uint8_t array.
 * hex string format example:"AF B0 80 7D"
 */
size_t hex_string_to_bytes(const char* str, unsigned char** p);

/*
 * download the file,
 * save it
 */
int download(const char* url, const char* local_file);


#endif /* UTIL_H_ */

