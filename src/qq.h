/*
 * qq.h
 *
 *  Created on: Mar 17, 2009
 *  	Author: Phoebus Veiz <phoebusveiz@gmail.com>
 */

#ifndef QQ_H_
#define QQ_H_

#include <map>
#include <string>
#include <fstream>
#include "def.h"
#include "msgr.h"

using namespace std;

class QQ
{
public:
	QQ();
	virtual ~QQ();
	void pre_sign_in_step_1();
	void pre_sign_in_step_2();
	void run();
	void destroy();
	void set_qq_id_n_pw(int id, const char* password);
	void dispatch_msg();
#ifdef WIN32
	static DWORD WINAPI thread_timer(LPVOID lpParameter);
	static DWORD WINAPI send_msg(LPVOID lpParameter);
	static DWORD WINAPI recv_msg(LPVOID lpParameter);
	static DWORD WINAPI round_msg(LPVOID lpParameter);
#else
	static void* thread_timer(void*);
	static void* send_msg(void*);
	static void* recv_msg(void*);
	static void* round_msg(void*);
#endif

public:
	bool friends_gotten;
	bool stop;
	int drop_flag;

	void send_cmd(uint16_t cmd, uint8_t* req, uint32_t req_len);
	void send_msg(int buddy_id, const char* msg);
	void process_msg(uint32_t buddy_id, char* buddy_msg);
	void process_control_msg(char* msg, char* now);
	void keep_alive();	
	void get_friends();	
	void get_my_profile();
	void redirect_server();
	void creat_rand_pw();
	void sign_in();
	void set_personal_msg(const char* signature);
	void enable_forwarding(uint32_t	forward_id);
	void disable_forwarding();
	void init_env();
	void init_config();
	void set_auto_personal_msg();
	void log_event(char* e);
	void http_write(const char* title, const char* content, bool is_recv);
	uint8_t* new_request(uint8_t req_type, size_t req_size);
	void push_msg(uint8_t* request, size_t req_size, bool lock_srv_ip);
	

	typedef struct _QQ_MSG_HEADER
	{
		unsigned char header;
		unsigned short version;
		unsigned short order;
		unsigned short session_id;
	} QQ_MSG_HEADER, * QQ_MSG_HEADER_PTR;

	messenger* msgr;

	enum  qq_state_enum
	{
		QQ_ZERO,
		/* 0  */
		QQ_START,
		/* 1 */
		QQ_PREFIRST,
		/* 2 send login request */
		QQ_WF_PREFIRST,
		/* 3 wait for server to respond the login request */
		QQ_REDIRECT,
		/* 4  */
		QQ_WF_REDIRECT,
		/* 5  */
		QQ_LOGINTOKEN,
		/* 6 */
		QQ_WF_LOGINTOKEN,
		/* 7  */
		QQ_LOGIN_IN,
		/* 8 */
		QQ_WF_LOGIN_IN,
		/* 9 等待系统返回处理的登陆服务器  */
		QQ_PRE_ONLINE_FIR,
		/* 10 */
		QQ_WF_PRE_ONLINE_FIR,
		/* 11*/
		QQ_PRE_ONLINE_SEC,
		/* 12*/
		QQ_WF_PRE_ONLINE_SEC,
		/* 13 */
		QQ_ONLINE
		/* 14 */
	} qq_state;

	void set_state(qq_state_enum state);
	qq_state_enum get_state();

	int qq_id;  	
	char* qq_pw;

	pthread_t recv_msg_thread; 
	pthread_t send_msg_thread;
	pthread_t dispatch_msg_thread;
	pthread_t timer_thread ;

	pthread_mutex_t state_mtx;
	pthread_mutex_t login_token_mtx;
	pthread_mutex_t srv_ip_mtx;
	pthread_mutex_t rand_key_mtx;
	pthread_mutex_t drop_flag_mtx;

	char srv_ip[IPADDR_LEN];
	unsigned short srv_port;
	unsigned char login_token[24];
	unsigned char rand_key[16];
	unsigned char session_key[16];
	unsigned char friend_id[2];

	static uint32_t online_time;

	char client_ip_port[32];
	char server_ip_port[32];
	char signin_time[16];
	string history;

	ofstream history_os;
	ofstream log_os;
	map<int, string> contact;
	vector<pair<int, string> > recent_contacts;
	vector<string> personal_msg_lib;
	bool my_profile_gotten;

	struct config_t
	{
		bool turn_on_sound;
		bool block_qq_admin;
		bool forward_msg;
		bool enable_history;	
		bool auto_personal_msg;
		bool set_received_msg_as_personal_msg;
		bool enable_log;
		bool __none_;
		char auto_reply_msg[64];
		uint32_t manager_id;
		uint32_t forward_to_id;				
		uint32_t update_personal_msg_lib_freq;
		uint32_t auto_personal_msg_freq;
		const char* history_filename;
		vector<string> urls;
	} config;
};

#endif /* QQ_H_ */

