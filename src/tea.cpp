#include <cstring>
#include <ctime>
#include <cstdlib>
#include "def.h"
#include "tea.h"

TEA::TEA(const uint8_t* key, int round /*= 32*/, bool is_net_byte /*= false*/) : _round(round),
	_is_net_byte(is_net_byte)
{
	pthread_mutex_init(&mtx, NULL);

	if (key != 0)
		memcpy(_key, key, 16);
	else
		memset(_key, 0, 16);

	memset((uint8_t*)_plain, 0, 8);
	memset((uint8_t*)_pre_plain, 0, 8);
	_out = NULL;
}

TEA::TEA(const TEA& rhs) : _round(rhs._round), _is_net_byte(rhs._is_net_byte)
{
	pthread_mutex_init(&mtx, NULL);

	memcpy(_key, rhs._key, 16);
	memset((uint8_t*)_plain, 0, 8);
	memset((uint8_t*)_pre_plain, 0, 8);
	_out = NULL;
}

TEA::~TEA()
{
	pthread_mutex_destroy(&mtx);
}

TEA& TEA::operator=(const TEA& rhs)
{
	if (&rhs != this)
	{
		_round = rhs._round;
		_is_net_byte = rhs._is_net_byte;
		memcpy(_key, rhs._key, 16);
		memset((uint8_t*)_plain, 0, 8);
		memset((uint8_t*)_pre_plain, 0, 8);
		_out = NULL;
	}
	return *this;
}

void TEA::encrypt(const uint8_t* in, uint8_t* out)
{
	encrypt((const uint32_t *) in, (uint32_t *) out);
}

void TEA::decrypt(const uint8_t* in, uint8_t* out)
{
	decrypt((const uint32_t *) in, (uint32_t *) out);
}

void TEA::encrypt(const uint32_t* in, uint32_t* out)
{
	uint32_t* k = (uint32_t*) _key;
	register uint32_t y = ntoh(in[0]);
	register uint32_t z = ntoh(in[1]);
	register uint32_t a = ntoh(k[0]);
	register uint32_t b = ntoh(k[1]);
	register uint32_t c = ntoh(k[2]);
	register uint32_t d = ntoh(k[3]);
	register uint32_t delta = 0x9E3779B9; /* (sqrt(5)-1)/2*2^32 */
	register int round = _round;
	register uint32_t sum = 0;

	while (round--)
	{
		/* basic cycle start */
		sum += delta;
		y += ((z << 4) + a) ^ (z + sum) ^ ((z >> 5) + b);
		z += ((y << 4) + c) ^ (y + sum) ^ ((y >> 5) + d);
	}    /* end cycle */
	out[0] = ntoh(y);
	out[1] = ntoh(z);
}

void TEA::decrypt(const uint32_t* in, uint32_t* out)
{
	uint32_t* k = (uint32_t*) _key;
	register uint32_t y = ntoh(in[0]);
	register uint32_t z = ntoh(in[1]);
	register uint32_t a = ntoh(k[0]);
	register uint32_t b = ntoh(k[1]);
	register uint32_t c = ntoh(k[2]);
	register uint32_t d = ntoh(k[3]);
	register uint32_t delta = 0x9E3779B9; /* (sqrt(5)-1)/2*2^32 */
	register int round = _round;
	register uint32_t sum = 0;

	if (round == 32)
		sum = 0xC6EF3720; /* delta << 5*/
	else if (round == 16)
		sum = 0xE3779B90; /* delta << 4*/
	else
		sum = 0;

	while (round--)
	{
		/* basic cycle start */
		z -= ((y << 4) + c) ^ (y + sum) ^ ((y >> 5) + d);
		y -= ((z << 4) + a) ^ (z + sum) ^ ((z >> 5) + b);
		sum -= delta;
	}    /* end cycle */
	out[0] = ntoh(y);
	out[1] = ntoh(z);
}


uint8_t TEA::tea_rand()
{
	uint8_t ret = (uint8_t) (rand() % 0x100);
	return ret;
}


// QQ Encrypt

void TEA::qq_encrypt_8_bytes()
{
	int i = 0;
	uint8_t* crypted = new uint8_t[8];
	for (_pos = 0; _pos <= 7; _pos++)
	{
		if (this->_header == true)
		{
			_plain[_pos] = (uint8_t) (_plain[_pos] ^ _pre_plain[_pos]);
		}
		else
		{
			_plain[_pos] = (uint8_t) (_plain[_pos] ^ _out[_pre_crypt + _pos]);
		}
	}

	encrypt(_plain, crypted);
	for (i = 0; i < 8; i++)
	{
		_out[_crypt + i] = (uint8_t) crypted[i];
	}

	for (_pos = 0; _pos < 8; _pos++)
	{
		_out[_crypt + _pos] = (uint8_t)
			(_out[_crypt + _pos] ^ _pre_plain[_pos]);
	}

	memcpy((uint8_t*)_pre_plain, (uint8_t*)_plain, 8);
	_pre_crypt = _crypt;
	_crypt = _crypt + 8;
	_pos = 0;
	_header = false;
	delete[] crypted;
}


size_t TEA::qq_encrypt(uint8_t* in, size_t size, uint8_t** out)
{
	memset((uint8_t*)_plain, 0, 8);
	memset((uint8_t*)_pre_plain, 0, 8);
	_pading = 1;
	_pos = 2;
	_crypt = 0;
	_pre_crypt = 0;
	_header = true;

	int l = 0;
	int i = 0;
	_pos = (size + 10) % 8;
	if (_pos != 0)
		_pos = 8 - _pos;

	size_t outsize = size + _pos + 10;
	if (_out != NULL)
	{
		delete _out;
	}
	_out = new uint8_t[outsize];

	_plain[0] = (uint8_t) ((tea_rand() & 0xf8) | _pos);

	for (i = 1; i <= _pos; i++)
	{
		_plain[i] = (uint8_t) (tea_rand() & 0xff);
	}
	_pos++;

	while (_pading < 3)
	{
		if (_pos < 8)
		{
			_plain[_pos] = (uint8_t) (tea_rand() & 0xff);
			_pading++;
			_pos++;
		}
		else if (_pos == 8)
		{
			this->qq_encrypt_8_bytes();
		}
	}

	int index = 0;

	l = size;
	while (l > 0)
	{
		if (_pos < 8)
		{
			_plain[_pos] = in[index];
			index++;
			_pos++;
			l--;
		}
		else if (_pos == 8)
		{
			this->qq_encrypt_8_bytes();
		}
	}

	_pading = 1;
	while (_pading < 9)
	{
		if (_pos < 8)
		{
			_plain[_pos] = 0;
			_pos++;
			_pading++;
		}
		else if (_pos == 8)
		{
			this->qq_encrypt_8_bytes();
		}
	}

	*out = new uint8_t[outsize] ;
	memcpy(*out, _out, outsize);
	delete[] _out;
	_out = NULL;
	return outsize;
}



int TEA::qq_decrypt(uint8_t* in, size_t size, uint8_t** out)
{
	pthread_mutex_lock(&mtx);

	int ret = 0;
	uint8_t* m = NULL;
	size_t outsize = 0;
	int index = 0;
	int count = 0;

	if (size < 16 || size % 8 != 0)
	{
		ret = -1;
		goto out;
	}

	m = new uint8_t[size];
	memset(m, 0, size);

	memset((uint8_t*)_plain, 0, 8);
	memset((uint8_t*)_pre_plain, 0, 8);
	_crypt = _pre_crypt = 0;
	this->decrypt(in, _pre_plain);
	_pos = _pre_plain[0] & 7;

	outsize = size - _pos - 10;
	if (_out != NULL)
	{
		delete _out;
	}
	_out = new uint8_t[outsize];
	memset(_out, 0, outsize);
	_pre_crypt = 0;
	_crypt = 8;
	this->_context_start = 8;
	_pos++;
	_pading = 1;

	while (_pading < 3)
	{
		if (_pos < 8)
		{
			_pos++;
			_pading++;
		}
		else if (_pos == 8)
		{
			memcpy(m, in, size);
			if (this->qq_decrypt_8_bytes(in, size) == false)
			{
				ret = -1;
				goto out;
			}
		}
	}

	index = 0;
	count = outsize;

	while (count != 0)
	{
		if (_pos < 8)
		{
			_out[index] = (uint8_t) (m[_pre_crypt + _pos] ^ _pre_plain[_pos]);
			index++;
			count--;
			_pos++;
		}
		else if (_pos == 8)
		{
			memcpy(m, in, size);
			_pre_crypt = _crypt - 8;
			if (this->qq_decrypt_8_bytes(in, size) == false)
			{
				ret = -1;
				goto out;
			}
		}
	}

	for (_pading = 1; _pading <= 7; _pading++)
	{
		if (_pos < 8)
		{
			_pos++;
		}
		else if (_pos == 8)
		{
			_pre_crypt = _crypt;
			if (this->qq_decrypt_8_bytes(in, size) == false)
			{
				ret = -1;
				goto out;
			}
		}
	}

	*out = new uint8_t[outsize] ;
	memcpy(*out, _out, outsize);
	delete[] _out;
	delete[] m;
	_out = NULL;

	ret = outsize;

out:
	pthread_mutex_unlock(&mtx);
	return ret;
}

bool TEA::qq_decrypt_8_bytes(uint8_t* in, size_t size)
{
	for (_pos = 0; _pos <= 7; _pos++)
	{
		if (this->_context_start + _pos > size - 1)
		{
			return true;
		}
		_pre_plain[_pos] = (uint8_t) (_pre_plain[_pos] ^ in[_crypt + _pos]);
	}
	try
	{
		uint8_t* temp = new uint8_t[8];
		memset(temp, 0, 8);
		this->decrypt(_pre_plain, temp);
		memcpy((uint8_t*)_pre_plain, temp, 8);
		delete[] temp;
	}
	catch (...)
	{
		return false;
	}

	_context_start += 8;
	_crypt += 8;
	_pos = 0;
	return true;
}

