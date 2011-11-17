#ifndef TEA_H_
#define TEA_H_

#include "tea.h"
#include "util.h"

class TEA
{
public:
	bool qq_decrypt_8_bytes(uint8_t* in, size_t size);
	int qq_decrypt(uint8_t* in, size_t size, uint8_t** out);
	void qq_encrypt_8_bytes();
	static uint8_t tea_rand();
	size_t qq_encrypt(uint8_t* in, size_t size, uint8_t** out);
	TEA(const uint8_t* key, int round = 16, bool is_net_bytes = true);
	TEA(const TEA& rhs);
	~TEA();
	TEA& operator=(const TEA& rhs);
	void encrypt(const uint8_t* in, uint8_t* out);
	void decrypt(const uint8_t* in, uint8_t* out);
private:
	void encrypt(const uint32_t* in, uint32_t* out);
	void decrypt(const uint32_t* in, uint32_t* out);
	uint32_t ntoh(uint32_t net_len)
	{
		return _is_net_byte ? ntohl(net_len) : net_len;
	}
	uint32_t hton(uint32_t host_len)
	{
		return _is_net_byte ? htonl(host_len) : host_len;
	}
private:
	int _round;		// iteration round to encrypt or decrypt
	bool _is_net_byte;	// whether input uint8_ts come from network
	uint8_t _key[16];	// encrypt or decrypt key

	uint8_t _plain[8];
	uint8_t _pre_plain[8];
	uint8_t* _out;
	int _pos;
	int _crypt, _pre_crypt;
	int _pading;
	bool _header;
	size_t _context_start;	

	pthread_mutex_t mtx;	
};

#endif /* TEA_H_ */

