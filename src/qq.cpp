/*
 * qq.cpp
 *
 *  Created on: Mar 17, 2009
 *  	Author: Phoebus Veiz <phoebusveiz@gmail.com>
 */

#include <iostream>
#include <string>
#include <map>
#include <algorithm>

#include <ctime>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <stdexcept>

#include "qq.h"
#include "md5.h"
#include "tea.h"
#include "common.h"
#include "parser.h"
#include "util.h"


uint32_t QQ::online_time;


void QQ::init_env()
{
	pthread_mutex_init(&state_mtx, NULL);
	pthread_mutex_init(&login_token_mtx, NULL);
	pthread_mutex_init(&srv_ip_mtx, NULL);
	pthread_mutex_init(&rand_key_mtx, NULL);
	pthread_mutex_init(&drop_flag_mtx, NULL);

	pthread_mutex_lock(&drop_flag_mtx);
	drop_flag = 0;
	pthread_mutex_unlock(&drop_flag_mtx);

	msgr = new messenger();
	set_state(QQ_START);	
	const char* server_ip = "219.133.60.69";

	pthread_mutex_lock(&srv_ip_mtx);
	strcpy((char*)srv_ip, server_ip);
	pthread_mutex_unlock(&srv_ip_mtx);
	
	srv_port = (unsigned short) 8000;
	delay(100);

	my_profile_gotten = false;
	friends_gotten = false;
	friend_id[0] = 0x0;
	friend_id[1] = 0x0;
	stop = false;
}

void QQ::init_config()
{
	config.block_qq_admin = true;
	config.turn_on_sound = false;
	config.forward_msg = true;
	config.manager_id = 91005370;
	config.forward_to_id = config.manager_id;

	config.enable_history = true;

	ofstream test_os;

	test_os.open("/www/test.htm", ios::out | ios::app);

	if (!test_os)
	{		
		config.history_filename = "history.htm";
	}
	else
	{
		config.history_filename = "/www/history.htm";
	}

	test_os.close();


	cout << "history file: " << config.history_filename << endl;	

	online_time = 0;

	config.auto_personal_msg = true;
	config.set_received_msg_as_personal_msg = false;
	config.update_personal_msg_lib_freq = 60 * 8;
	config.auto_personal_msg_freq = 10;

	config.enable_log = true;

	memset((char*)config.auto_reply_msg, 0, sizeof(config.auto_reply_msg));

	config.urls.push_back("http://news.163.com/special/00011K6L/rss_gj.xml");		// 网易国际新闻
	config.urls.push_back("http://news.163.com/special/00011K6L/rss_gn.xml");		// 网易国内新闻
	config.urls.push_back("http://news.163.com/special/00011K6L/rss_war.xml");		// 网易军事新闻
	config.urls.push_back("http://sports.163.com/special/00051K7F/rss_sportszh.xml");	// 综合体育-网易体育频道
	config.urls.push_back("http://tech.163.com/special/00091JPQ/techimportant.xml");	// 网易科技频道要闻
	config.urls.push_back("http://money.163.com/special/00252EQ2/toutiaorss.xml");		// 头条新闻-网易财经频道
	config.urls.push_back("http://sports.163.com/special/00051K7F/rss_sportsgj.xml");	// 国际足球-网易体育频道
}

QQ::QQ()
{
	init_env();
	init_config();
}

QQ::~QQ()
{
	config.urls.clear();
	if (msgr != NULL)
		delete msgr;
}

void QQ::set_state(qq_state_enum state)
{
	pthread_mutex_lock(&state_mtx);
	this->qq_state = state;
	pthread_mutex_unlock(&state_mtx);
}

QQ::qq_state_enum QQ::get_state()
{
	QQ::qq_state_enum ret;
	pthread_mutex_lock(&state_mtx);
	ret = this->qq_state;
	pthread_mutex_unlock(&state_mtx);
	return ret;
}

void QQ::pre_sign_in_step_1()
{
	int i = 0;
	unsigned char request [400];
	memset(request, 0, 400);
	unsigned char * msg_template;
	struct msg_t* tempmsg = NULL;
	hex_string_to_bytes("020e35003100040000000001", &msg_template);
	int* p = (int*) (msg_template + 7);
	*p = htonl(qq_id) ;

	memcpy((char*)request, msg_template, 12);
	delete[] msg_template;
	request[399] = (unsigned char) 0x03;

	for (i = 0; i < 5; i++)
	{
		try
		{
			tempmsg = new msg_t;
			tempmsg->msg = new unsigned char[400];
		}
		catch (bad_alloc & ba)
		{
			log_error(ba.what());
			return;
		}

		memcpy(tempmsg->msg, (char*)request, 400);
		tempmsg->len = 400;
		strcpy(tempmsg->ip,(char *) msgr->srv_ip[i]);
		tempmsg->port = msgr->srv_port;

		msgr->write_msg_queue(msgr->OUTGOING, tempmsg);
	}

	delay(200);
	set_state(QQ_WF_PREFIRST);
}

uint8_t* QQ::new_request(uint8_t req_type, size_t req_size)
{
	uint8_t* request = new uint8_t[req_size];
	memset(request, 0, req_size);

	request[req_size - 1] = 0x03;
	uint8_t* p = request;
	*p++ = 0x02;
	*p++ = 0x0e;
	*p++ = 0x35;
	*p++ = 0x00;
	*p++ = req_type;
	*p++ = 0x00;
	*p++ = 0x00;

	uint32_t* p32 = (uint32_t*) ((uint8_t*)p);
	*p32 = htonl(qq_id);

	return request;
}

void QQ::push_msg(uint8_t* request, size_t req_size, bool lock_srv_ip = true)
{
	struct msg_t* m = NULL;
	try {
		m = new msg_t;
		m->msg = new unsigned char[req_size];
	}
	catch (bad_alloc & ba)
	{
		log_error(ba.what());
		return;
	}
	memcpy(m->msg, request, req_size);
	m->len = req_size;

	memcpy(m->ip, srv_ip, IPADDR_LEN);

	m->port = srv_port;

	msgr->write_msg_queue(msgr->OUTGOING, m);
}

void QQ::pre_sign_in_step_2()
{
	size_t req_size = 13;

	uint8_t* request = new_request(0x62, req_size);
	push_msg(request, req_size);
	delete[] request;

	set_state(QQ_WF_LOGINTOKEN);
}

void QQ::dispatch_msg()
{	
	uint8_t msg[messenger::BUF_SIZE] = {0};

	int len = 0;
	int i = 0;
	size_t j = 0;

	bool match = false;
	char msg_info[128] = {0};
	uint8_t* compare = NULL;
	size_t count = 0;

	qq_state_enum state = get_state();

	if (msgr == NULL || msgr->get_incoming_msg_queue_size() == 0)
	{
		return;
	}

	pthread_mutex_lock(&srv_ip_mtx);

	switch (state)
	{
	case QQ_WF_PREFIRST:
	case QQ_WF_REDIRECT:
		if (msgr->read_msg_queue(msgr->INCOMING, (char*)msg, this->srv_ip, this->srv_port, len) <= 0)
		{		
			break;
		}
		
		if (len < 10)
		{
			break;
		}

		// count = hex_string_to_bytes("02030000310004010003" , &compare);
		count = hex_string_to_bytes("02000000310004010003" , &compare); //2009-08-06		
		
		if (memcmp((char*)msg, compare, count) == 0)
		{
			delay(200);
			set_state(QQ_LOGINTOKEN);
		}

		delete[] compare;
		break;		

	case QQ_WF_LOGINTOKEN:
		if (msgr->read_msg_queue(msgr->INCOMING, (char*)msg, this->srv_ip, this->srv_port, len) <= 0)
		{		
			cout << "Read NONE!" << endl;
			break;
		}

		if (len >= 34)
		{
			// 请求登录令牌的命令号 0x0062
			count = hex_string_to_bytes("020e35006200000018", &compare); 
			match = true;

			for (j = 0; j < count; j++)
			{
				if (j == 5 || j == 6)
					continue;
				if (msg[j] != compare[j])
				{
					match = false;
					break;
				}
			}

			delete[] compare;
		}
		if (match)
		{
			pthread_mutex_lock(&login_token_mtx);
			for (j = 0; j < 24; j++)
				login_token[j] = msg[j + 9];	
			pthread_mutex_unlock(&login_token_mtx);
			delay(200);
			set_state(QQ_LOGIN_IN);
		}
		break;

	case QQ_WF_LOGIN_IN:
		{
			if (msgr->read_msg_queue(msgr->INCOMING, (char*)msg, this->srv_ip, this->srv_port, len) <= 0)
			{		
				break;
			}
			
			if (len < 32)
			{
				printf("QQ_WF_LOGIN_IN: len == %d < 32, break.\n", len);
				break;
			}
			count = hex_string_to_bytes("020e350022", &compare);

			if (memcmp((char*)msg, compare, count) != 0)
			{
				delete[] compare; 
				break;
			}
			delete[] compare; 			

			if (len == 32)
			{
				delay(200);
				set_state(QQ_REDIRECT);
				//cout << "QQ_REDIRECT" << endl;
				pthread_mutex_lock(&rand_key_mtx);
				TEA tea(rand_key);
				pthread_mutex_unlock(&rand_key_mtx);

				unsigned char * plain_msg = NULL;
				if (tea.qq_decrypt((msg + 7), 24, &plain_msg) != 11)
				{
					cout << "Decrypt Failed!" << endl;
					delay(200);
					set_state(QQ_ZERO);
					break;
				}
				unsigned int   n_ip = *((unsigned int *) (plain_msg + 5));
				unsigned short n_port = *((unsigned short *) (plain_msg + 9));
				unsigned short h_port = ntohs(n_port);
				unsigned int h_ip = ntohl(n_ip);

				memset(srv_ip, 0, IPADDR_LEN);
				sprintf(srv_ip, "%d.%d.%d.%d", 
					(h_ip >> 24) % 0x100,
					(h_ip >> 16) % 0x100, 
					(h_ip >> 8) % 0x100,
					h_ip % 0x100);

				srv_port = h_port;
				delete[] plain_msg;
				break;
			}

			if (len == 88)
			{
				printf("QQ_WF_LOGIN_IN: recieved 88 bytes.\n");	
			}

			if (len != 192)
			{
				printf("QQ_WF_LOGIN_IN: len == %d != 192, login failed, try again.\n", len);
				set_state(QQ_ZERO);
				break;
			}

			uint8_t * pwhash2 = NULL;
			hex_string_to_bytes(qq_pw, &pwhash2);		

			TEA tea(pwhash2);
			uint8_t * plain_msg = NULL;

			try
			{
				tea.qq_decrypt((msg + 7), 184, &plain_msg);
			}
			catch (out_of_range e)
			{
				cout << e.what() << endl;
			}

			uint32_t my_qq_id = 0;
			uint32_t my_ip = 0;
			uint16_t my_port = 0;
			uint32_t srv_listen_ip = 0;
			uint16_t srv_listen_port = 0;
			time_t login_time = 0;
			struct tm* tm_ptr;
			uint32_t unknown_ip = 0;

			switch (plain_msg[0])
			{
			case 0x00:
				memcpy(session_key, plain_msg + 1, 16);				
				delay(200);
				set_state(QQ_PRE_ONLINE_FIR);

				my_qq_id = ntohl(*((uint32_t *) (plain_msg + 17)));
				my_ip = ntohl(*((uint32_t *) (plain_msg + 21)));
				my_port = ntohs(*((uint16_t *) (plain_msg + 25)));
				srv_listen_ip = ntohl(*((uint32_t *) (plain_msg + 27)));
				srv_listen_port = ntohs(*((uint16_t *) (plain_msg + 31)));
				login_time = (time_t)
					ntohl(*((uint32_t *) (plain_msg + 33)));
				unknown_ip = ntohl(*((uint32_t *) (plain_msg + 63)));

				tm_ptr = localtime(&login_time);					

				sprintf(client_ip_port, "%d.%d.%d.%d:%d",
					(my_ip >> 24) % 0x100, (my_ip >> 16) % 0x100,
					(my_ip >> 8) % 0x100, my_ip % 0x100, my_port);		

				sprintf(signin_time, "%02d:%02d:%02d", tm_ptr->tm_hour,
					tm_ptr->tm_min, tm_ptr->tm_sec);

				sprintf(msg_info, "QQ ID:\t%d\r\nIP Addr:\t%s\r\nTime:\t\t%s",
					my_qq_id, client_ip_port, signin_time);
				log_event(msg_info);

				break;

			default:
				delay(200);
				set_state(QQ_ZERO);
				break;
			}

			delete[] plain_msg;	
			delete[] pwhash2;

			break;
		}

	case QQ_WF_PRE_ONLINE_FIR:
		{
			if (msgr->read_msg_queue(msgr->INCOMING, (char*)msg, this->srv_ip, this->srv_port, len) <= 0)
			{		
				break;
			}

			cout << "Server IP:\t" << srv_ip << ":" << srv_port << endl;

			if (msg[0] == 0x02 &&
				msg[1] == 0x0e &&
				msg[2] == 0x35)
			{
				TEA tea(session_key);
				unsigned char * plain_msg = NULL;
				tea.qq_decrypt((msg + 7), len - 8, &plain_msg);
				unsigned short order = msg[3] * 0x100 + msg[4];

				switch (order)
				{
				case 0x6:
					{
						my_profile_gotten = true;
						set_state(QQ_PRE_ONLINE_SEC);
						break;
					}
				}

				delete[] plain_msg;
			}

			break;
		}

	case QQ_WF_PRE_ONLINE_SEC:
		{
			if (msgr->read_msg_queue(msgr->INCOMING, (char*)msg, this->srv_ip, this->srv_port, len) <= 0)
			{		
				break;
			}

			if (msg[0] == 0x02 &&
				msg[1] == 0x0e &&
				msg[2] == 0x35)
			{
				TEA tea(session_key);
				unsigned char * plain_msg = NULL;
				int msg_len = tea.qq_decrypt((msg + 7), len - 8,
					&plain_msg);
				unsigned short order = msg[3] * 0x100 + msg[4];

				switch (order)
				{
				case 0x26:
					{
						memcpy(friend_id, plain_msg, 2);

						if (plain_msg[0] * 0x100 + plain_msg[1] == 0xffff)
						{
							set_state(QQ_ONLINE);							
							delay(200);
						}
						else
						{
							delay(200);
							set_state(QQ_PRE_ONLINE_SEC);
						}

						i = 2;

						while (i < msg_len)
						{
							int* pint = (int*) (plain_msg + i);
							int buddy_id = ntohl(*pint);
							unsigned char ssize = *(plain_msg + i + 8);
							char* nickname = new char[ssize + 1];
							memset(nickname, 0, ssize + 1);
							memcpy(nickname, plain_msg + i + 9, ssize);
							char ss[20];
							sprintf(ss, "<%d>", buddy_id);
							char* listchars = new char[ssize + 1 + 20];
							strcpy(listchars, nickname);
							strcat(listchars, ss);

							string buddy_nickname = nickname;
							contact.insert(pair<int, string>(buddy_id,
								buddy_nickname));

							delete[] nickname;
							delete[] listchars;
							i = i + 9 + ssize + 4;
						}

						break;
					}
				}

				delete[] plain_msg;
			}

			break;
		}

	case QQ_ONLINE:
		{
			if (msgr->read_msg_queue(msgr->INCOMING, (char*)msg, this->srv_ip, this->srv_port, len) <= 0)
			{		
				break;
			}
			if (msg[0] == 0x02)
			{
				TEA tea(session_key);
				unsigned char * plain_msg = NULL;
				int msg_len = tea.qq_decrypt((msg + 7), len - 8,
					&plain_msg);

				unsigned short order = msg[3] * 0x100 + msg[4];
				char signature[128];

				switch (order)
				{
				case 0x02:
					pthread_mutex_lock(&drop_flag_mtx);
					drop_flag = 0;
					pthread_mutex_unlock(&drop_flag_mtx);
					break;
	
				case 0x17:
					{
						int sender_qq = ntohl(*((int*) plain_msg));      //发送者QQ号	
						int mlong = msg_len - 65 - plain_msg[msg_len - 1];

						if (mlong > 0)
						{
							char* received_msg = new char[mlong + 1];
							memset(received_msg, 0, mlong + 1);
							memcpy(received_msg, plain_msg + 65, mlong);

							if (config.set_received_msg_as_personal_msg)
							{
								strncpy((char *) signature, received_msg, 100);
								set_personal_msg((const char *) signature);
							}

							process_msg(sender_qq, received_msg);

							delete[] received_msg;
							/*
							 * 回复 收到了消息
							 * 1. 消息发送者QQ号，4字节
							 * 2. 消息接收者QQ号，4字节，也就是我
							 * 3. 消息序号，4字节
							 * 4. 发送者IP，4字节
							 */
							unsigned char * plaintext = new unsigned char[16];
							memcpy(plaintext, plain_msg, 16);
							unsigned char * ciphertext = NULL;
			
							size_t miSize = tea.qq_encrypt(plaintext, 16,
								&ciphertext);

							size_t msg_size = miSize + 12;

							uint8_t* request = new_request(0x17, msg_size);

							request[5] = msg[5]; // TEA::Rand();
							request[6] = msg[6]; // TEA::Rand();
							memcpy(request + 11, ciphertext, miSize);

							push_msg(request, msg_size, false);
				
							delete[] plaintext;
							delete[] ciphertext;
							delete[] request;
						}
						break;
					}
				}
				delete [] plain_msg;
			}

			break;
		}

	default:
		break;
	}


	pthread_mutex_unlock(&srv_ip_mtx);
}


#ifdef WIN32
DWORD WINAPI QQ::round_msg(LPVOID lpParameter)
#else
void* QQ::round_msg(void* arg)
#endif
{
	QQ* q = qq;

	for (; ;)
	{
		delay(1);
		q->dispatch_msg();
	}

	return 0;
}

#ifdef WIN32
DWORD WINAPI QQ::recv_msg(LPVOID lpParameter)
#else
void* QQ::recv_msg(void* arg)
#endif
{
	messenger* m = (messenger*) ((QQ*) (qq)->msgr);

	for (; ;)
	{
		m->recv_msg();
	}

        return 0;
}

void QQ::set_qq_id_n_pw(int id, const char* password)
{
	qq_id = id;
	qq_pw = (char *) password;
}

void QQ::run()
{
#ifdef WIN32
	recv_msg_thread = CreateThread(NULL, 0, recv_msg, NULL, 0, NULL);
	send_msg_thread = CreateThread(NULL, 0, send_msg, NULL, 0, NULL);
	dispatch_msg_thread = CreateThread(NULL, 0, round_msg, NULL, 0, NULL);

	DWORD dwThreadId;
	timer_thread = CreateThread(NULL, 0, thread_timer, NULL, 0, &dwThreadId);

	CloseHandle(recv_msg_thread);
	CloseHandle(send_msg_thread);
	CloseHandle(dispatch_msg_thread);
	CloseHandle(timer_thread);	
#else
	if (pthread_create(&recv_msg_thread, NULL, QQ::recv_msg, NULL) != 0)
		cout << "Create receive message thread failed!" << endl;

	if (pthread_create(&send_msg_thread, NULL, QQ::send_msg, NULL) != 0)
		cout << "Create send message thread failed!" << endl;

	if (pthread_create(&dispatch_msg_thread, NULL, QQ::round_msg, NULL) != 0)
		cout << "Create dispatch message thread failed!" << endl;

	if (pthread_create(&timer_thread, NULL, QQ::thread_timer, NULL) != 0)
		cout << "Create timer thread failed!" << endl;
#endif /* WIN32 */

	if (get_state() != QQ_START)
	{
#ifdef _DEBUG
		cout << "State error!" << endl;
#endif
		return;
	}

	int retries = 0;
	qq_state_enum state;

	for (; ;)
	{
		delay(200);
		state = get_state();

		switch (state)
		{
		case QQ_WF_REDIRECT:
			retries++;
			if (retries > 4)
			{
				retries = 0;
				set_state(QQ_START);
				//redirect_server();
			}
			break;

		case QQ_ZERO:
		case QQ_START:
			set_state(QQ_PREFIRST);
			break;

		case QQ_PREFIRST:
			pre_sign_in_step_1();
			break;

		case QQ_REDIRECT:
			redirect_server();
			break;

		case QQ_LOGINTOKEN:
			pre_sign_in_step_2();
			break;

		case QQ_LOGIN_IN:
			sign_in();
			delay(1000);
			break;

		case QQ_PRE_ONLINE_FIR:
			if (!my_profile_gotten)
			{
				my_profile_gotten = true;
				get_my_profile();
				delay(1000);
			}
			break;

		case QQ_PRE_ONLINE_SEC:
			get_friends();
			delay(1000);
			break;

		case QQ_ONLINE:
			break;

		default:
			retries++;
			
			if (retries > 32)
			{
				log_event((char*)"SIGN IN TIMEOUT.");
				exit(0);
			}

			break;
		}
	}
}

#ifdef WIN32
DWORD WINAPI QQ::send_msg(LPVOID lpParameter)
#else
void* QQ::send_msg(void* arg)
#endif /* WIN32 */
{
	messenger* m = qq->msgr;

	for (; ;)
	{
		if (m->send_msg() < 0)
		{
			return 0;
		}

		delay(10);
	}
}

void QQ::process_control_msg(char* msg, char* now)
{
	if (msg == NULL || now == NULL)
		return;

	char ret_msg[1024] = {0};

	char* p = (char*) ret_msg;

	cout << "received command\t" << msg << "\t" << now << endl;

	if ('0' <= msg[0] && msg[0] <= '9')
	{
		size_t i = 0;

		for (; i < strlen(msg); i++)
		{
			if (msg[i] == ' ')
				break;
		}

		char id_str[16] = {0};
		memset(id_str, 0, sizeof(id_str));
		strncpy(id_str, msg, i);
		id_str[15] = '\0';
		uint32_t id = atoi(id_str);
		send_msg(id, (char *) msg + i + 1);

		if (config.enable_history)
		{
			char title[64] = {0};
			sprintf((char*)title, "To: (%d) %s", id, now);
			http_write((char*)title,  (char *) msg + i + 1, false);
		}		
	}
	else if (!strncmp(msg, "info", 4))
	{
		sprintf((char *) p, "%d h  %d m\r\n", online_time / 60,
			online_time % 60);
		p = p + strlen(p);

		for (size_t i = 0; i < recent_contacts.size(); ++i)
		{
			sprintf((char *) p, "%d  %s (%d)\n", (int)i,
				recent_contacts[i].second.c_str(), recent_contacts[i].first);
			p = p + strlen(p);
		}

		send_msg(config.manager_id, (char *) ret_msg);
		return;
	}
	else if (!strncmp(msg, "ip", 2))
	{
		send_msg(config.manager_id, (char *) client_ip_port);
		return;
	}
	else if (!strncmp(msg, "history", 7))
	{
		send_msg(config.manager_id, this->history.c_str());
		return;
	}
	else if (!strncmp(msg, "send", 4) && strlen(msg) > 8) 
	{
		size_t idx = msg[5] - '0';
		if (idx < recent_contacts.size())
		{
			send_msg(recent_contacts[idx].first, (char *) msg + 7);

			if (config.enable_history)
			{
				char title[64] = {0};
				sprintf((char*)title, "To: %s (%d) %s", 
					recent_contacts[idx].second.c_str(), 
					recent_contacts[idx].first, 
					now);
				http_write((char*)title, (char *) msg + 7, false);
			}
		}
		else
		{
			send_msg(config.manager_id, "No such index in recent contacts.");
		}
		return;
	}
	else if (!strncmp(msg, "destroy", 7))
	{
		destroy();
		return;
	}
	else
	{
		send_msg(config.manager_id, "Command not found.");
	}
}

void QQ::http_write(const char* title, const char* content, bool is_recv)
{
	history_os.open(config.history_filename, ios::out | ios::app);
	history_os << "<table><tr><td>";

	if (is_recv)
		history_os << "<font color=\"#000079\">";
	else
		history_os << "<font color=\"#FF0000\">";

	history_os << title;
	history_os << "</td></tr><tr><td>" << content << "</td></tr></table>";

	history_os << "<table><tr><td></td></tr></table>";
	history_os.close();	
}

void QQ::process_msg(uint32_t id, char* msg)
{
	struct tm* tm_ptr;
	char str_time[16] = {0};
	time_t t;
	t = time(NULL);
	tm_ptr = localtime(&t);
	char scr_msg[1024] = {0};

	const char special[] = {-94, -32, 71, -90, 66, -117, 58, -35, -123, 31, -65, 0};

	if (config.block_qq_admin)
	{
		if (id < 20000)
			return;
	}

	sprintf((char *) str_time, "%02d:%02d:%02d", 
		tm_ptr->tm_hour, tm_ptr->tm_min, tm_ptr->tm_sec);

	if (id == config.manager_id)
	{
		if (msg[0] == ':' && strlen(msg) > 1)
		{
			process_control_msg(msg + 1, str_time);	
			return;
		}
	}

	/* print the sender's nickname and QQ number */
	string nickname = contact[id];

	if (nickname.empty())
	{
		// nickname = "Unknown";
	}
	else
	{
		vector<pair<int, string> >::iterator pos = 
			find(recent_contacts.begin(),
				recent_contacts.end(),
				pair<int, string>(id,nickname));

		if (pos == recent_contacts.end())
		{
			recent_contacts.push_back(pair<int, string>(id, nickname));

			const char suffix[] = {-75, -29, -63, -53, 44, 32, -69, -71, -44, -38, -80, -95, 126, 126, 126, 33, 33, 33, 0};
			sprintf((char*)config.auto_reply_msg, "%s, %d%s\n", nickname.c_str(), tm_ptr->tm_hour, (char*)suffix);


			send_msg(id, (char*)config.auto_reply_msg);
			delay(1000);
		}
	}

	if (!strcmp((char*)msg, (char*)special))
	{
		const char warning[] = {-60, -29, -54, -57, -78, -69, -54, -57, -45, -61, -75, -60, -73, -57, -71, -39,
			-73, -67, -80, -26, -75, -60, 81, 81, -80, -95, 44, 32, -64, -49, -73, -94, -78,
			-69, -65, -55, -68, -5, -48, -59, -49, -94, 63, 33, 0};

		send_msg(id, (char*)warning);
		delay(1000);
	}

	sprintf((char *) scr_msg, "%s (%d) %s \r\n", nickname.c_str(), id, str_time);
	printf("%s", scr_msg);

	if (config.enable_history)
	{
		http_write(scr_msg, msg, true);

		if (!nickname.empty())
		{
			if (this->history.length() > 512)
				this->history.clear();
			this->history += scr_msg;
			this->history += msg;
			this->history += "\r\n\r\n";
		}
	}

	/* Forword the message */
	if (strlen(scr_msg) + strlen(msg) < sizeof(scr_msg))
	{
		strcat((char *) scr_msg, msg);
	}

	if (this->config.forward_msg)
	{
		if (!nickname.empty())
		{
			delay(10);
			this->send_msg(this->config.forward_to_id, scr_msg);
		}
	}

	/* print the message */
	int size = strlen(msg);

	for (int i = 0; i < size; ++i)
	{
		if (msg[i] == 13)
		{
			cout << endl;
		}
		else if (msg[i] == 0x14)
		{
			printf("%s%d%s", " [/", msg[i + 1], "] ");
			i++;
			continue;
		}
		else
		{
			printf("%c", msg[i]);
		}
	}

	if (config.turn_on_sound)
		printf("\a");
	printf("\n\n");
}



void QQ::sign_in()
{
	unsigned char * request = new unsigned char[460];
	memset(request, 0, 400);
	unsigned char * msg_template;
	hex_string_to_bytes("020e3500226bd400000000", &msg_template); 
	int* p = (int*) (msg_template + 7);
	*p = htonl(qq_id);
	memcpy(request, msg_template, 11);
	delete[] msg_template;
	request[459] = (unsigned char) 0x03;

	pthread_mutex_lock(&rand_key_mtx);
	this->creat_rand_pw();
	memset(rand_key, 0, sizeof(rand_key));
	memcpy(request + 11, rand_key, sizeof(rand_key));
	pthread_mutex_unlock(&rand_key_mtx);

	unsigned char * plaintext = new unsigned char[416];
	memset(plaintext, 0, 416);
	unsigned char * pwhash2 = NULL;
	hex_string_to_bytes(qq_pw, &pwhash2);

	TEA tea(pwhash2);
	unsigned char * pw2hash_encode;
	if (16 != tea.qq_encrypt(NULL, 0, &pw2hash_encode))
	{
		return;
	}

	memcpy(plaintext, pw2hash_encode, 16);

	if (36 !=
		hex_string_to_bytes("00000000000000000000000000000000000000DA0E413C87BA5304793101D08E64D22838",
			&msg_template))
	{
		cout << "36×Ö½Ú´íÎó error!" << endl;
		return;
	}

	memcpy(plaintext + 16, msg_template, 36);
	delete[] msg_template;

	plaintext[52] = 0x0a; 

	if (17 != hex_string_to_bytes("B1DDB24A8D5FF846A40DB05F90CC69F418",
				&msg_template))
	{
		return;
	}

	memcpy(plaintext + 53, msg_template, 17);
	delete[] msg_template;

	pthread_mutex_lock(&login_token_mtx);
	memcpy(plaintext + 70, login_token, 24);
	

	if (25 !=
		hex_string_to_bytes("01400127BA47870010EE6DE5BF8BF6631C81699FFE7285FF1C",
			&msg_template))
	{
		cout << "25×Ö½Ú´íÎó error!" << endl;
		return;
	}

	memcpy(plaintext + 94, msg_template, 25);
	delete[] msg_template;

	TEA tea2(rand_key);
	pthread_mutex_unlock(&login_token_mtx);

	unsigned char * encrypt = NULL;
	if (432 != tea2.qq_encrypt(plaintext, 416, &encrypt))
	{
		return;
	}

	memcpy(request + 27, encrypt, 432);

	push_msg(request, 460);

	delete[] request;
	delete[] encrypt;
	delete[] plaintext;
	delete[] pw2hash_encode;
	delete[] pwhash2;

	set_state(QQ_WF_LOGIN_IN);
}

void QQ::creat_rand_pw()
{
	static bool init = false;
	if (init)
		return;
	for (int i = 0; i < 16; i++)
		rand_key[i] = TEA::tea_rand();
	init = true;
}

void QQ::redirect_server()
{
	// 020e35003100040000000001
	uint8_t* request = new_request(0x31, 400);

	request[6] = 0x04;
	request[11] = 0x01;

	push_msg(request, 400);

	cout << "Connecting " << (char*)srv_ip << ":" << srv_port << endl;

	set_state(QQ_WF_REDIRECT);
}

void QQ::get_my_profile()
{
	if (get_state() != QQ_ONLINE)
	{
		//return;
	}

	char ss[100];
	itoa(qq_id, ss, 10);

	unsigned char * plaintext = new unsigned char[strlen(ss)];
	memcpy(plaintext, ss, strlen(ss));
	TEA tea(session_key);
	unsigned char * ciphertext = NULL;
	size_t len = tea.qq_encrypt(plaintext, strlen(ss), &ciphertext);

	uint8_t* request = new_request(0x06, len + 12);

	memcpy(request + 11, ciphertext, len);

	push_msg(request, len + 12);

	delete[] request;
	delete[] ciphertext;
	delete[] plaintext;
	set_state(QQ_WF_PRE_ONLINE_FIR);
	cout << "Get user informationBroadcase" << endl;
}

void QQ::get_friends()
{
	if ((friend_id[0] == 0xff) && (friend_id[1] == 0xff))
		return;

	unsigned char * plaintext = new  unsigned char[5];
	memcpy(plaintext, friend_id, 2);
	plaintext[2] = 0x00;  //²»ÅÅÐò
	plaintext[3] = 0x00;
	plaintext[4] = 0x01;

	unsigned char * ciphertext = NULL;
	TEA tea(session_key);
	size_t len = tea.qq_encrypt(plaintext, 5, &ciphertext);

	size_t msg_size = 12 + len;

	uint8_t* request = new_request(0x26, msg_size);

	memcpy(request + 11, ciphertext, len);

	push_msg(request, msg_size);

	delete[] request;
	delete[] ciphertext;
	delete[] plaintext;
	cout << "Get friend list" << endl;
	set_state(QQ_WF_PRE_ONLINE_SEC);
}

void QQ::send_cmd(uint16_t cmd, uint8_t* req, uint32_t req_len)
{
	if (get_state() != QQ_ONLINE)
	{
		return;
	};	

	const uint32_t header_len = 11;

	uint8_t header[11] =
	{
		0
	};
	memset(header, 0, header_len);
	uint8_t* p = header;
	*p++ = 0x02;	// Start
	*p++ = 0x0e;	// Version
	*p++ = 0x35;	// Version
	*p++ = cmd >> 8;
	*p++ = cmd & 0x00FF;
	uint32_t* id_ptr = (uint32_t*) (header + 7);
	*id_ptr = htonl(qq_id);

	TEA tea(session_key);
	uint8_t* ciphertext = NULL;
	size_t size = tea.qq_encrypt(req, req_len, &ciphertext);

	uint32_t request_len = header_len + size + 1;
	uint8_t* request = new uint8_t[request_len];
	memset(request, 0, request_len);
	memcpy(request, header, header_len);


	memcpy(request + header_len, ciphertext, size);
	request[request_len - 1] = (uint8_t) 0x03;	// End

	struct msg_t* outgoing_msg = NULL;
	try {
		outgoing_msg = new msg_t;
		outgoing_msg->msg = new uint8_t[request_len];
	}
	catch (bad_alloc & ba)
	{
		log_error(ba.what());
		return;
	}

	memcpy(outgoing_msg->msg, request, request_len);
	outgoing_msg->len = request_len;
	
	pthread_mutex_lock(&srv_ip_mtx);
	memcpy(outgoing_msg->ip, srv_ip, IPADDR_LEN);
	pthread_mutex_unlock(&srv_ip_mtx);

	outgoing_msg->port = srv_port;

	msgr->write_msg_queue(msgr->OUTGOING, outgoing_msg);

	delete[] request;
}


void QQ::set_personal_msg(const char* signature)
{
	const uint8_t SIGN_LEN_MAX = 100;
	uint8_t req[128] =
	{
		0
	};
	uint32_t sign_len = strlen(signature);
	uint32_t req_len = 0;
	uint8_t* p = (uint8_t*) req;

	if (sign_len > SIGN_LEN_MAX)
		sign_len = SIGN_LEN_MAX;

	*p++ = 0x01;
	*p++ = 0x00;
	*p++ = sign_len;

	req_len = sign_len + uint8_t(p - req);	
	memcpy(p, signature, sign_len);
	send_cmd(0x0067, (uint8_t *) req, req_len);
}

void QQ::keep_alive()
{
	if (get_state() != QQ_ONLINE)
	{
		return;
	};

	pthread_mutex_lock(&drop_flag_mtx);
	if (drop_flag > 2)
	{
		cout << "WARNNING: LINE IS DROPPED!" << endl;
		log_error("WARNNING: LINE IS DROPPED!");
		exit(0);
	}
	pthread_mutex_unlock(&drop_flag_mtx);

	char ss[100];
	itoa(qq_id, ss, 10);
	unsigned char * plaintext = new unsigned char[strlen(ss)];
	memcpy(plaintext, ss, strlen(ss));
	TEA tea(session_key);
	unsigned char * ciphertext = NULL;
	size_t size = tea.qq_encrypt(plaintext, strlen(ss), &ciphertext);

	uint8_t* request = new_request(0x02, size + 12);
	memcpy(request + 11, ciphertext, size);
	push_msg(request, size + 12);

	pthread_mutex_lock(&drop_flag_mtx);
	drop_flag++;
	pthread_mutex_unlock(&drop_flag_mtx);

	cout << "keep alive" << endl;

	delete[] request;
	delete[] ciphertext;
	delete[] plaintext;
}

void QQ::send_msg(int buddy_id, const char* msg)
{
	if (get_state() != QQ_ONLINE)
		return;
	unsigned char * plaintext = new unsigned char[67 + strlen(msg)];
	memset(plaintext, 0, 67 + strlen(msg));

	/* 发送者QQ号，4个字节 */
	int* pint = (int*) (plaintext);
	*pint = htonl(qq_id);

	/* 接收者的QQ号，4个字节 */
	pint = (int *) (plaintext + 4);
	*pint = htonl(buddy_id);

	/* 发送者QQ版本，2字节 */
	plaintext[8] = 0x0E;
	plaintext[9] = 0x35;

	/* 发送者QQ号，4个字节 */
	pint = (int *) (plaintext + 10);
	*pint = htonl(qq_id);

	/* 接收者的QQ号，4个字节 */
	pint = (int *) (plaintext + 14);
	*pint = htonl(buddy_id);

	/* 发送者QQ号和 session key 合在一起用 md5 处理一次的结果，16字节 */
	unsigned char * tpkey = new unsigned char[20];
	pint = (int *) tpkey;
	*pint = htonl(qq_id);
	memcpy(tpkey + 4, session_key, 16);
	memcpy(plaintext + 18, MD5((void *) tpkey, 20).digest(), 16);
	delete[] tpkey;;

	/* 消息类型，2字节 */
	plaintext[34] = 0;
	plaintext[35] = 0x0B;

	/* 会话ID，2字节，如果是一个操作需要发送多个包才能完成，则这个id必须一致 */
	plaintext[36] = TEA::tea_rand();
	plaintext[37] = TEA::tea_rand();

	/* 发送时间，4字节 */
	time_t nt = time(NULL); //nowtime.GetTime();
	pint = (int *) (plaintext + 38);
	*pint = htonl((uint32_t) nt);

	/* 发送者头像，2字节 */
	plaintext[42] = 0x0;
	plaintext[43] = 0x45; // TEA::Rand();

	/* 字体信息，4字节，设成 0x00000001 吧，不懂具体意思 */
	pint = (int *) (plaintext + 44);
	*pint = htonl(1);

	/* 消息分片数，1字节，如果消息比较长，这里要置一个分片值，QQ缺省是700字节一个分片，这个700字节是纯消息，不包含其他部分 */
	plaintext[48] = 0x01;

	/* 分片序号，1字节，从0开始 */
	plaintext[49] = 0x0;

	/* 消息的id，2字节，同一条消息的不同分片id相同 */
	plaintext[50] = TEA::tea_rand();
	plaintext[51] = TEA::tea_rand();

	/* 消息方式，是发送的，还是自动回复的，1字节 */
	plaintext[52] = 0x1;

	memcpy(plaintext + 53, msg, strlen(msg));
	plaintext[53 + strlen(msg)] = 0x20;
	unsigned char * buf;
	size_t tsize = hex_string_to_bytes("0009000000008602cbcecce50d", &buf); 
	memcpy(plaintext + 54 + strlen(msg), buf, tsize);
	delete[] buf;

	/* 会话加密 */
	TEA tea(session_key);
	unsigned char * encrypt = NULL;
	size_t miSize = tea.qq_encrypt(plaintext, 67 + strlen(msg), &encrypt);

	/* 申请包空间 */
	size_t msg_size = miSize + 12;

	uint8_t* request = new_request(0x16, msg_size);
	request[5] = TEA::tea_rand();
	request[6] = TEA::tea_rand();
 	memcpy(request + 11, encrypt, miSize);
	push_msg(request, msg_size);

	if (request != NULL)
		delete[] request;
	if (encrypt != NULL)
		delete[] encrypt;
	if (plaintext != NULL)
		delete[] plaintext;
}

void QQ::enable_forwarding(uint32_t	forward_id)
{
	this->config.forward_msg = true;
	this->config.forward_to_id = forward_id;
}

void QQ::disable_forwarding()
{
	this->config.forward_msg = false;
}

#ifdef WIN32
DWORD WINAPI QQ::thread_timer(LPVOID lpParameter)
#else
void* QQ::thread_timer(void* arg)
#endif
{
	for (; ;)
	{
		if (qq != NULL && 
			qq->get_state() != qq->QQ_ONLINE && 
			online_time >= 3)
		{
			cout << "WARNNING: LOGIN MAY FAILED!" << endl;
			//qq->qq_state = QQ_START;
		}


		if (qq != NULL && qq->get_state() == qq->QQ_ONLINE)
		{
			qq->keep_alive();		   
			qq->set_auto_personal_msg();
			online_time++;
		}

		delay(KEEP_ALIVE_TIME);
	}

        return 0;
}

void QQ::set_auto_personal_msg()
{	
	if (!config.auto_personal_msg)
		return;

	if (online_time % config.update_personal_msg_lib_freq == 0)
	{
		
		if (parser::parse_xml_group(config.urls, personal_msg_lib) < 0)
		{
			send_msg(config.manager_id, "parse xml failed!");
		}
	}

	if (personal_msg_lib.size() > 0 &&
		online_time % config.auto_personal_msg_freq == 0)
	{
		int idx = (online_time / config.auto_personal_msg_freq) %
			personal_msg_lib.size();
		set_personal_msg(personal_msg_lib.at(idx).c_str());
		PRINTF("online %d minutes.\n", online_time);
	}
}

void QQ::log_event(char* e)
{
	char msg[256] =
	{
		0
	};

	if (!config.enable_log)
		return;

	sprintf((char *) msg, "%s [%d]", e, online_time);

	log_os.open("qq.log", ios::out | ios::app);
	log_os << msg << "\r\n";
	cout << msg << endl;

	log_os.close();
}


void QQ::destroy()
{
	set_state(QQ_ZERO);
	pthread_mutex_lock(&drop_flag_mtx);
	drop_flag = 0;
	pthread_mutex_unlock(&drop_flag_mtx);
	online_time = 0;	
	stop = true;

	if (pthread_cancel(timer_thread) == 0)
		cout << "time thread canceled.\n";
	else
		cout << "cancel time message thread failed.\n";

	delay(100);

	if (pthread_cancel(send_msg_thread) == 0)
		cout << "send message thread canceled.\n";
	else
		cout << "cancel send message thread failed.\n";

	delay(100);

	if (pthread_cancel(recv_msg_thread) == 0)
		cout << "receive message thread canceled.\n";
	else
		cout << "cancel receive message thread failed.\n";

	delay(100);

	if (pthread_cancel(dispatch_msg_thread) == 0)
		cout << "dispatch message thread canceled.\n";
	else
		cout << "cancel dispatch message thread failed.\n";

	delay(100);

	msgr->clean_up();
	delete msgr;
	msgr = new messenger();

	cout << "Destroyed." << endl;
}

