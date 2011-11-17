/*
 * def.h
 *
 *  Created on: Mar 17, 2009
 *  	Author: Phoebus Veiz <phoebusveiz@gmail.com>
 */

#ifndef DEF_H_
#define DEF_H_

#define DEBUG_MODE

#ifdef DEBUG_MODE
#define PRINTF	printf
#define check_crash()	printf("%s\t%d\n", __FUNCTION__, __LINE__)
#endif

#define IPADDR_LEN 16

#ifdef WIN32
#include <windows.h>
#include <winsock.h>
#include <process.h>
#pragma comment (lib,"ws2_32.lib")
#pragma warning(disable:4996)

typedef unsigned int uint32_t;
typedef unsigned short uint16_t;
typedef unsigned char uint8_t;

#define sleep				delay
#define socklen_t			int
#define socket_t			SOCKET

#define pthread_t			HANDLE
#define pthread_cancel(x)		TerminateThread((x), 0)
#define pthread_exit(x)			_endthread
#define pthread_join(x, NULL)		WaitForSingleObject((x), INFINITE)

#define pthread_mutex_t			CRITICAL_SECTION
#define pthread_mutex_init(x, NULL)	InitializeCriticalSection(x)
#define pthread_mutex_lock(x)		EnterCriticalSection(x)
#define pthread_mutex_unlock(x)		LeaveCriticalSection(x)
#define pthread_mutex_destroy(x)	DeleteCriticalSection(x)

#define s_addr	S_un.S_addr

#define delay(x)	Sleep(x)

inline int init_socket()
{
	WORD wVersionRequested = MAKEWORD(2, 2);
	WSADATA wsaData;

	int err = WSAStartup(wVersionRequested, &wsaData);
	if (err != 0)
	{
		return -1;
	}

	if (LOBYTE(wsaData.wVersion) != 2 || HIBYTE(wsaData.wVersion) != 2)
	{
		WSACleanup();
		return -1;
	}

	return 0;
}

#else

#include <sys/types.h>
#include <unistd.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <netinet/in.h>
#include <errno.h>
#include <pthread.h>
#include <cctype>
#include <cstdio>

using namespace std;

#define closesocket	close
#define socket_t	int

#define delay(x)	usleep((x) * 1000)

inline char* itoa(int value, char* str, int radix)
{
	sprintf(str, "%d", value);
	return str;
}

inline char* strlwr(char* str)
{
	char* orig = str;
	for (; *str != '\0'; str++)
		*str = tolower(*str);
	return orig;
}

inline int init_socket()
{
	return 0;
}

#endif /* WIN32 */

#define KEEP_ALIVE_TIME	60000

#endif /* DEF_H_ */

