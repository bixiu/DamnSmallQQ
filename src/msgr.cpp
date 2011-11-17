/*
 * msgr.cpp
 *
 *  Created on: Mar 17, 2009
 *  	Author: Phoebus Veiz <phoebusveiz@gmail.com>
 */

#ifndef MESSAGE_CPP_
#define MESSAGE_CPP_

#include <iostream>
#include <cstring>

#include "msgr.h"
#include "qq.h"
#include "util.h"

messenger::messenger()
{
	pthread_mutex_init(&in_mtx, NULL);
	pthread_mutex_init(&out_mtx, NULL);

	srv_ip[0] = "58.61.33.253";
	srv_ip[1] = "119.147.78.29";
	// srv_ip[0] = "219.133.60.234";
	// srv_ip[1] = "219.133.49.76";
	srv_ip[2] = "219.133.48.87";
	srv_ip[3] = "58.60.14.42";
	srv_ip[4] = "219.133.48.87";
	srv_port = 8000;
	cli_port = 4000;

	if (init_socket() == -1)
		return;

	sock = socket(AF_INET, SOCK_DGRAM, 0);

	if (sock < 0)
	{
		cout << "Create socket failed!" << endl;
	}

	sockaddr_in srv_addr;
	srv_addr.sin_addr.s_addr = htonl(INADDR_ANY);
	srv_addr.sin_family = AF_INET;

	while (srv_addr.sin_port = htons(cli_port),bind(sock, (sockaddr *) &srv_addr, sizeof(sockaddr)) == -1)
	{
		cli_port += 1;
	}
}


messenger::~messenger()
{
	pthread_mutex_destroy(&in_mtx);
	pthread_mutex_destroy(&out_mtx);

	if (sock < 0)
		clean_up();
}

size_t messenger::get_incoming_msg_queue_size()
{
	size_t ret = 0;

	pthread_mutex_lock(&in_mtx);
	ret = this->incoming_msg_queue.size();
	pthread_mutex_unlock(&in_mtx);

	return ret;
}

int messenger::write_msg_queue(queue_type type, struct msg_t* message)
{
	if (type == OUTGOING)
	{
		pthread_mutex_lock(&out_mtx);
		outgoing_msg_queue.push(message);
		pthread_mutex_unlock(&out_mtx);
	}
	else if (type == INCOMING)
	{
		pthread_mutex_lock(&in_mtx);
		incoming_msg_queue.push(message);
		pthread_mutex_unlock(&in_mtx);
	}
	else
	{
		return -1;
	}

	return 0;
}

int messenger::read_msg_queue(queue_type type, char* msg, char* ip, uint16_t& port, int& len)
{
	int ret = 0;
	struct msg_t* m = NULL;
	queue<struct msg_t*> *msg_queue = NULL;

	if (msg == NULL || ip == NULL)
	{
		ret = -1;
		goto out;
	}	

	if (type == INCOMING)
	{
		pthread_mutex_lock(&in_mtx);
		msg_queue = &incoming_msg_queue;
	}
	else if (type == OUTGOING)
	{
		pthread_mutex_lock(&out_mtx);
		msg_queue = &outgoing_msg_queue;
	}

	if (msg_queue->empty())
	{
		ret = 0;
		goto out;
	}

	m = msg_queue->front();
	
	if (m == NULL)
	{
		ret = -2;
		goto out;
	}

	memset(ip, 0, IPADDR_LEN);

	if (m->ip != NULL)
		memcpy(ip, m->ip, IPADDR_LEN);

	memset(msg, 0, BUF_SIZE);

	if (m->msg != NULL)
		memcpy(msg, m->msg, m->len);

	port = m->port;
	len = m->len;

 	if (m->msg != NULL)
 	{
 		delete[] m->msg;
 		m->msg = NULL;
 	}

 	delete m;
 	m = NULL;
 
 	msg_queue->pop(); 
	ret = len;

out:
	if (type == INCOMING)
		pthread_mutex_unlock(&in_mtx);	
	else if (type == OUTGOING)
		pthread_mutex_unlock(&out_mtx);

	return ret;
}

void messenger::recv_msg()
{
	if (sock < 0)
	{
		cout << "sock < 0" << endl;
		return;
	}

	sockaddr_in srv_addr;
	socklen_t socklen = sizeof(sockaddr);

	char buf[BUF_SIZE] = {0};

	memset((char*)buf, 0, BUF_SIZE);
	int received = ::recvfrom(sock, (char*)buf, BUF_SIZE, 0, (sockaddr*) &srv_addr,
					&socklen);

	printf("received %d bytes.\n", received);

	if (received > 0)
	{
		unsigned char * message = new unsigned char[received];
		memcpy(message, (char*)buf, received);

		unsigned short srv_port = ntohs(srv_addr.sin_port);

		unsigned int ip_int = ntohl(srv_addr.sin_addr.s_addr);

		char ip_str[IPADDR_LEN];
		memset(ip_str, 0, IPADDR_LEN);

		sprintf(ip_str, "%d.%d.%d.%d", (ip_int >> 24) % 0x100,
			(ip_int >> 16) % 0x100, (ip_int >> 8) % 0x100, ip_int % 0x100);

		struct msg_t* msg = new msg_t;
		memcpy(msg->ip, ip_str, IPADDR_LEN);
		msg->len = received;
		msg->port = srv_port;
		msg->msg = (unsigned char *) message;

		write_msg_queue(INCOMING, msg);
	}	
}

int messenger::send_msg()
{
	uint8_t msg[BUF_SIZE] = {0};
	char ip[IPADDR_LEN] = {0};
	uint16_t port = 0;
	int len = 0;

	if (sock < 0)
	{
		cout << "socket error" << endl;
		return -2;
	}
	
	if (read_msg_queue(OUTGOING, (char*)msg, (char*)ip, port, len) <= 0)
	{		
		return 1;
	}

	sockaddr_in sa;
	sa.sin_addr.s_addr = inet_addr(ip);
	sa.sin_family = AF_INET;
	sa.sin_port = htons(port);

	int sent = sendto(sock, (const char*) msg, len, 0,
				(sockaddr*) &sa, sizeof(sockaddr));
	printf("sent %d (%d) bytes\n", sent, len);

	if (sent < 0)
	{
		log_error("send failed.");
	}

	return sent;
}


void messenger::clean_up()
{
	if (sock < 0)
		return;
	closesocket(sock);
#ifdef WIN32
	WSACleanup();
#endif

	pthread_mutex_lock(&in_mtx);
	while (!incoming_msg_queue.empty())
		incoming_msg_queue.pop();
	pthread_mutex_unlock(&in_mtx);

	pthread_mutex_lock(&out_mtx);
	while (!outgoing_msg_queue.empty())
		outgoing_msg_queue.pop();
	pthread_mutex_unlock(&out_mtx);
}

#endif /* MESSAGE_CPP_ */

