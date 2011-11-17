/*
 * msgr.h
 *
 *  Created on: Mar 17, 2009
 *  	Author: Phoebus Veiz <phoebusveiz@gmail.com>
 */

#ifndef MSGR_H_
#define MSGR_H_

#include <queue>
#include "def.h"

using namespace std;


struct msg_t
{
	unsigned char* msg;
	char ip[IPADDR_LEN]; 
	unsigned short port;
	int len;
};


class messenger
{
public:
	messenger();
	virtual ~messenger();
public:
	queue<struct msg_t*> incoming_msg_queue;
	queue<struct msg_t*> outgoing_msg_queue;

public:
	enum queue_type
	{
		INCOMING,
		OUTGOING,
	};

	int write_msg_queue(queue_type type, struct msg_t* message);
	int read_msg_queue(queue_type type, char* msg, char* ip, uint16_t& port, int& len);

	size_t get_incoming_msg_queue_size();
	void clean_up();
	int send_msg();
	void recv_msg();

	const char* srv_ip[5];
	unsigned short srv_port;
	unsigned short cli_port;

	socket_t sock;
	static const size_t BUF_SIZE	= 2048;
	
private:
	pthread_mutex_t	in_mtx;
	pthread_mutex_t	out_mtx;
	
};

#endif /* MSGR_H_ */

