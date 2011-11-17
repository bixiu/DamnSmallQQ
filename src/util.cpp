/*
 * util.cpp
 *
 *  Created on: Mar 17, 2009
 *  	Author: Phoebus Veiz <phoebusveiz@gmail.com>
 */

#include <fstream>
#include <cstring>
#include <cstdio>
#include <ctime>
#include "def.h"
#include "util.h"

using namespace std;

#ifdef SAFE_STR
/*
* strncpy that copies n bytes and then write zero to n-th byte
* use this when you want to copy less than n bytes
*/
char* strncpy_s(char* dest, const char *src, size_t n)
{
	char* ret = strncpy(dest, src, n);
	ret[n-1] = 0;
	return ret;
}

#endif

void log_error(const char* e)
{
	struct tm* tm_ptr;
	char str_time[16];
	time_t t = time(NULL);

	tm_ptr = localtime(&t);
	memset(str_time, 0, sizeof(str_time));
	sprintf((char *) str_time, "%02d:%02d:%02d", tm_ptr->tm_hour,
		tm_ptr->tm_min, tm_ptr->tm_sec);

	ofstream os;
	os.open("qq.log", ios::out | ios::app);
	os << e << "\t" << "[" << str_time << "]" << "\r\n";	
	os.close();
}


char* bytes_to_hex_string(const unsigned char* in, size_t size)
{
	char* hex_str = new char[size * 2 + 1];
	memset(hex_str, 0, size * 2 + 1);
	size_t i = 0;
	for (i = 0; i < size; i++)
	{
		char pt[10];
		memset(pt, 0, 10);
		if ((in[i] & 0xff) < 0x10)
			sprintf(pt, "0%x", in[i] & 0xff);
		else
			sprintf(pt, "%2x", in[i] & 0xff);
		strcat(hex_str, pt);
	}

	return hex_str;	// Remember to free hex_str!
}


size_t hex_string_to_bytes(const char* str, unsigned char** p)
{
	unsigned int len = strlen(str);
	unsigned char * str_bytes = NULL;
	char* tmp_str = NULL;

	try
	{
		str_bytes = new unsigned char[len >> 1];
		tmp_str = new char[len + 1];
	}
	catch (exception e)
	{
		log_error(e.what());
		return 0;
	}

	if (tmp_str == NULL)
		return 0;

	strcpy(tmp_str, str);
	strlwr(tmp_str);

	unsigned char c;
	unsigned  int i = 0, temp = 0, val = 0, index = 0;
	for (i = 0; i < len; i++)
	{
		c = *(tmp_str + i);
		if ((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f'))
		{
			if (c >= '0' && c <= '9')
				temp = c - '0';  
			if (c >= 'a' && c <= 'f')
				temp = c - 'a' + 0xa;    
			if ((index % 2) == 1)
			{
				val = val * 0x10 + temp;
				str_bytes[index >> 1] = (unsigned char) val;
			}
			else
				val = temp;
			index++;
		}
	}
	if (tmp_str != NULL)
		delete[] tmp_str;
	*p = str_bytes;
	return len >> 1;
}

int download(const char* url, const char* local_file)
{
	const unsigned short port = 80;
	char domain[32];
	char file[128];

	if (url == NULL)
		return 0;

	memset(domain, 0, sizeof(domain));
	memset(file, 0, sizeof(file));

	size_t url_len = strlen(url);

	size_t i = 0;
	size_t offset = 0;
	if (!strncmp(url, "http://", 7))
		offset = 7;
	
	for (i = 0 ; i < url_len; i++)
	{
		if (url[i + offset] == '/' || i == sizeof(domain))
			break;
		domain[i] = url[i + offset];
	}
	if (i + offset >= url_len || i >= sizeof(domain))
		return -4;
	strncpy((char*)file, url + i + offset, sizeof(file));

	init_socket();

	socket_t sockfd;
	sockfd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	if (sockfd == -1)
		return -1;

	hostent* hp;
	uint32_t addr;	

	if (inet_addr(domain) == INADDR_NONE)
	{
		hp = gethostbyname(domain);
	}
	else
	{
		addr = inet_addr(domain);
		hp = gethostbyaddr((char *) &addr, sizeof(addr), AF_INET);
	}
	if (hp == NULL)
	{
		closesocket(sockfd);
		return -1;
	}

	struct sockaddr_in clisa;
	clisa.sin_addr.s_addr = *((uint32_t *) hp->h_addr);
	clisa.sin_family = AF_INET;
	clisa.sin_port = htons(port);

	if (connect(sockfd, (struct sockaddr *) &clisa, sizeof(clisa)))
	{
		closesocket(sockfd);
		return -1;
	}

	const uint32_t BUFFER_SIZE = 8192;
	char recvbuf[BUFFER_SIZE] = {0};

	sprintf(recvbuf,
		"GET %s HTTP/1.1\r\nHost:%s\r\nUser-Agent:Mozilla\r\n\r\n", file,
		domain);

	int sent = send(sockfd, recvbuf, (uint32_t) strlen(recvbuf), 0);
	if (sent == -1)
	{
		return -1;
	}	

	uint32_t received = recv(sockfd, recvbuf, sizeof(recvbuf), 0);

	if (received > 9 && recvbuf[9] != '2')
	{
		// if not HTTP/1.x 2xx , quit
		closesocket(sockfd);
#ifdef WIN32
		WSACleanup();
#endif
		return -3;
	}

	ofstream outfile(local_file, ios::out | ios::binary); 

	// Remove the header
	string filestart(recvbuf);
	filestart = filestart.substr(filestart.find("\r\n\r\n") + 4);
	outfile.seekp(0);
	outfile.write(filestart.c_str(), filestart.size());

	for (; ;)
	{
		received = recv(sockfd, recvbuf, sizeof(recvbuf), 0);
		if (received <= 0)
			break;
		outfile.write(recvbuf, received);
	}	

	closesocket(sockfd);	

#ifdef WIN32
	WSACleanup();
#endif
	outfile.close();
	PRINTF("File downloaded.\n");
	return 0;
};

