/*
 * main.cpp
 *
 *  Created on: Mar 17, 2009
 *  	Author: Phoebus Veiz <phoebusveiz@gmail.com>
 */

#include <iostream>
#include <cstdlib>
#include "qq.h"
#include "util.h"
#include "parser.h"
#include "md5.h"

using namespace std;

#ifdef WIN32
static DWORD WINAPI work_thread(LPVOID lpParameter);
#else
static void* work_thread(void* arg);
#endif

QQ* qq;
pthread_t signin_thread;

int your_id;
int my_id;
string my_password;
string send_msg;
string history_msg; 

void get_md5_2(const char* password)
{
	uint8_t * pwhash2 = new uint8_t[16];
	memcpy(pwhash2, MD5((void *) MD5(password).digest(), 16).digest(), 16); 
	char* md5_2 = bytes_to_hex_string(pwhash2, 16);
	cout << md5_2 << endl;
	delete[] md5_2;
	delete[] pwhash2;
}

void init()
{
	my_id = 71949551;
	my_password = "25d1f91a425cdfc684451433b4ad9358";

	send_msg = "";
	history_msg = "";
	your_id = 91005370;
	qq = new QQ(); 
}

void create_process()
{
	if (my_id < 10000 || my_password.length() == 0)
	{
		cout << "please input qq id and password again." << endl;
		return;
	}
#ifdef WIN32
	CloseHandle(CreateThread(NULL, 0, work_thread, NULL, 0, NULL));
#else
	int ret = pthread_create(&signin_thread, (const pthread_attr_t*) NULL,
				work_thread, (void*) NULL);
	if (ret != 0)
		cout << "Create work thread failed!" << endl;
	delay(8000);
#endif
}

#ifdef WIN32
DWORD WINAPI work_thread(LPVOID lpParameter)
#else
void* work_thread(void* arg)
#endif
{
	QQ* q = qq;
	q->set_qq_id_n_pw(my_id, my_password.c_str());

	q->run();
	return 0;
}

void send_message(uint32_t buddy_id, const string& message)
{
	if (qq == NULL || qq->get_state() != qq->QQ_ONLINE)
	{
		cout << "QQ is offline, cannot send message!" << endl;
		return;
	}
	if (send_msg.length() < 0)
	{
		cout << "message length error!" << endl;
		return;
	}
	if (your_id < 10000)
	{
		cout << "friend ID is out of range!" << endl;
		return;
	}

	qq->send_msg(your_id, message.c_str()); 
	send_msg.clear();
}

void do_command(const string& command)
{
	string cmd;
	string arg;
	string::size_type idx = command.find(' ');

	cout << "\a";
	if (idx == string::npos)
		cmd = command;
	else
	{
		cmd = command.substr(0, idx);
		arg = command.substr(idx + 1);
	}

	if (cmd == "q" || cmd == "exit")
	{
		delete qq;
		exit(0);
	}
	else if (cmd == "destroy")
		qq->destroy();
	else if (cmd == "passwd")
		get_md5_2(arg.c_str());
	else
		cout << "Bad command." << endl;
}

int main()
{
	cout << "DamnSmallQQ v0.1 Build " << __TIME__ << " " << __DATE__ << "\n\n";

	init();
	create_process();
;
	for (; ;)
	{
		delay(2000);
		if (qq != NULL && qq->get_state() == qq->QQ_ONLINE)
		{
			cout << "-----------------------------------------------" << endl;
			cout << "WARNNING:" << endl;
			cout << "Be wary of prize announcements and cash offers." << endl;
			cout << "Don't call phone numbers you do not recognize." << endl;
			cout << "-----------------------------------------------" << endl;
			break;
		}
		else
		{
			// Do nothing
		}
	}
	string send_str;
	while (getline(cin, send_str))
	{
		if (send_str[0] == ':')
			do_command(send_str.substr(1));
		else
			send_message(your_id, send_str.c_str());
	}
#ifndef WIN32
	pause();
#endif
	cout << "exit!\n";
	return 0;
}

