/*
 * Author: rossano at gmail dot com
 * This file is part of the PAM-telegram-2fa distribution 
 * (https://gitlab.com/rossanx/pam-2fa.git or 
 *  https://github.com/rossanx/pam-2fa.git).
 * Copyright (c) Rossano Pablo Pinto, 2019.
 * 
 * This program is free software: you can redistribute it and/or modify  
 * it under the terms of the GNU General Public License as published by  
 * the Free Software Foundation, version 3.
 *
 * This program is distributed in the hope that it will be useful, but 
 * WITHOUT ANY WARRANTY; without even the implied warranty of 
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU 
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License 
 * along with this program. If not, see <http://www.gnu.org/licenses/>.
 */
 

/**********************************************************************************************
 * This is a toy 2-Factor-Authentication PAM module that uses Telegram's API to send a
 * verfication code to a Telegram BOT. It's described as a toy because it was neither tested 
 * in a production environment nor with GUI display managers like lightdm, GNOME, etc..
 * It works well in a non-gui local login terminal as well as with SSH.
 **********************************************************************************************/

/*
 * TODO:
 *    - User provided safe codes in case Internet is not available. ALMOST DONE !!!!
 *    - Delete code after user typed it (send message to chatbot to delete it).
 *      https://core.telegram.org/method/messages/.deleteMessages
 */


#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <security/pam_modules.h>
#include <security/pam_ext.h>
#include <time.h>
#include <pwd.h>
#include <fcntl.h>
#include <unistd.h>
#include <curl/curl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <errno.h>


/*
 *  - MAXIMUM NUMBER OF DIGITS OF THE CODE TO BE SENT TO TELEGRAM
 *
 *  - MAXIMUM NUMBER OF SAFE CODES THAT CAN BE LOADED FROM FILE 
 *    (DEFINES THE SIZE OF THE ARRAY TO HOLD SAFE CODES)
 */
#define MAX_CODE_LENGTH 5
#define MAX_SAFE_CODES 32

/*
 * ENSURE SOME ENTERED/COPIED INFORMATION DOES NOT EXCEED SOME SIZE
 */
#define MAX_PROVIDED_INFORMATION_SIZE 128
#define MAX_POST_SIZE 1024
#define MAX_PARAM_SIZE 1024
#define CRED_BUF_SIZE 4096

/*
 * ERROR CODES
 */
#define CACHE_ERROR -1
#define CACHE_EXPIRED 1
#define CACHE_VALID 2

/*
 * TELEGRAM RELATED DEFINES
 */
#define	TELEGRAM_URL  "https://api.telegram.org/bot%s/sendMessage"
#define TELEGRAM_POST "chat_id=%s&text=%i"
#define MAX_TELEGRAM_BOTKEY_LEN 128
#define MAX_TELEGRAM_ID_LEN 128

/* 
 * FAKE CURL WRITE FUNCTION 
 *  - disable echoing the return msg to the screen.
 */
size_t fake_curl_write(void *p, size_t s, size_t nmemb, void *d) 
{
	//printf("\n\n\n\nDEBUG fake_curl_write: %s\n\n\n\n",p);
	return s * nmemb;
}

/*
 * REMOVE '\n' FROM STRING
 */
int trim_string(char * str) 
{
	int index=0;
	int len = 0;
	
	if (str != NULL) {
		len = strlen(str);
		while(str[index] != '\0' || index<len) {
			if (str[index] == '\n') {
				str[index]='\0';
				break;
			}
			++index;
		}
	}
	return 0;
}
 
/*
 *  COLLECT INFORMATION USING PAM 
 *    - USED TO ASK PROXY INFO
 */
int collect_information(pam_handle_t *pamh, const char * message, int msg_style, char * result)
{
	/* 
	 * PAM VARIABLES 
	 */
	struct pam_response *resp;	
	struct pam_conv *conv;
	struct pam_message msg[1], *pmsg[1];
	pmsg[0] = &msg[0];
	msg[0].msg_style = msg_style;
	msg[0].msg = message;
    
    
	/* 
	 * ASK USER TO TYPE THE REQUESTED INFORMATION 
	 */
	int rval = pam_get_item(pamh, PAM_CONV, (const void **) &conv);
	if ( rval == PAM_SUCCESS) {
		rval = conv->conv(1, (const struct pam_message **)pmsg, &resp, conv->appdata_ptr);
		strncpy(result, resp[0].resp, MAX_PROVIDED_INFORMATION_SIZE);
	}
    
	return rval;
}



/*
 * AUTHENTICATES USER TO ACCESS THE INTERNET 
 * - Ex.: Captive portal (I'll call it proxy)
 * 
 * It's possible to provide the credentials using a user provided file with the following
 * content:
 *
 *      proxy_username=<username> 
 *      proxy_password=<password>
 *
 * The provided file must be the same file used to inform telegram chatid and botkey.
 *  
 * If the user provides the file but only parameter USERNAME, PAM will ask for the
 * password.
 *
 * In order to enable this function, you should provide the module parameters:
 *
 *     proxy_url=
 *     proxy_post_string=
 *
 * RETURNS:
 *    0 - Connection to proxy OK
 *   -1 - Connection to proxy FAILED
 */
int internet_access_authentication(char url[1024], 
				   char post_str_format[MAX_POST_SIZE], 
				   char *p_user_name, 
				   char * p_pwd,
				   pam_handle_t *pamh) 
{

	char proxy_username[MAX_PROVIDED_INFORMATION_SIZE]="";
	char * proxy_password;
	char post[MAX_POST_SIZE];


	if (p_user_name == NULL || strcmp(p_user_name,"!") == 0) {
		collect_information(pamh, "PROXY USER: ", PAM_PROMPT_ECHO_ON, proxy_username);
		
	} else {
		strncpy(proxy_username, p_user_name, MAX_PROVIDED_INFORMATION_SIZE);
	}


	if (p_pwd == NULL || strcmp(p_pwd,"!") == 0) {
		proxy_password=(char *) malloc(MAX_PROVIDED_INFORMATION_SIZE);		
		collect_information(pamh, "PROXY PASSWORD: ", PAM_PROMPT_ECHO_OFF, proxy_password);
	} else {
		proxy_password=(char *) malloc(MAX_PROVIDED_INFORMATION_SIZE);
		strncpy(proxy_password, p_pwd, MAX_PROVIDED_INFORMATION_SIZE);
	}


	snprintf(post,MAX_POST_SIZE,post_str_format, proxy_username, proxy_password);
	free(proxy_password);

	CURL *curl;
	CURLcode response;

	curl_global_init(CURL_GLOBAL_ALL);
	curl = curl_easy_init();
	if (curl) {
		curl_easy_setopt(curl, CURLOPT_URL, url);
		curl_easy_setopt(curl, CURLOPT_POSTFIELDS, post);
		curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, fake_curl_write);
		//curl_easy_setopt(curl, CURLOPT_VERBOSE, 1L);
		response = curl_easy_perform(curl);
		if (response != CURLE_OK) {
			curl_easy_cleanup(curl);
			return -1;
		}
		curl_easy_cleanup(curl);
	}
	curl_global_cleanup();
	
	return 0;

}


/* 
 * PARSE MODULE PARAMS
 */
int parse_module_params(int argc, 
			const char ** argv, 
			char * fname, 
			char * p_url, 
			char * p_post_string, 
			int *cache_timeout,
			int *enable_safe_codes) 
{
	char *line;
	char *token;
	char param[MAX_PARAM_SIZE];

	fname[0]='\0';
	p_url[0]='\0';
	p_post_string[0]='\0';

	for (int i=0; i<argc; i++) {
		strncpy(param, argv[i], MAX_PARAM_SIZE); // bkp

		line=strtok((char *) argv[i], "=");

		if (strcmp(line,"dir") == 0) {			
			line = strtok(NULL, "=");
			strcpy(fname, line);
			
		}
		else if (strcmp(line,"proxy_url") == 0) {			
			line = strtok(NULL, "=");
			strcpy(p_url, line);
			
		}
		else if (strcmp(line,"proxy_post_string") == 0) {
			int size=strlen(param);
			int j=0;
			for (j=0; j<size; j++)
				p_post_string[j]=param[j+18];
			p_post_string[j]='\0';
			
		}
		else if (strcmp(line, "cache_timeout") == 0) {
			line = strtok(NULL, "=");
			*cache_timeout = atoi(line);
			
		}
		else if (strcmp(line, "enable_safe_codes") == 0) {
			line = strtok(NULL, "=");
			*enable_safe_codes = atoi(line);
			if (*enable_safe_codes > MAX_SAFE_CODES)
				*enable_safe_codes = MAX_SAFE_CODES;
			
		}
	}


	return 0;
}


/*
 * READ USER CONFIGURATION FILE 
 */
int read_user_configuration_file(const char * uname, 
				 char * dname, 
				 char * id, 
				 char * bkey, 
				 char * p_uname,
				 char * p_pwd,
				 int nsc,
				 char safe_codes[MAX_SAFE_CODES][MAX_CODE_LENGTH+1]) 
{
	char path[512];
	char cred[CRED_BUF_SIZE];
	struct passwd *pwd;
	pwd = getpwnam(uname);
	snprintf(path, 512, "%s/%s/credentials",pwd->pw_dir,dname);
	

	FILE *fdx;
	fdx=fopen(path, "r");

	/* 
	 * IF FILE NOT PRESENT, DISABLE TWO FACTOR AUTHENTICATION 
	 *
	 *      - e.g.: ~/.pam_telegram_2fa/credentials
	 */
	if (fdx == NULL)
		return -1;

	int counter=0;
	while(1) {
		cred[counter++] = fgetc(fdx);
		if ( feof(fdx) || counter >= CRED_BUF_SIZE)
			break;
	};


	/* 
	 * PARSE ITEMS 
	 */
	char *line;
	int i=0;
	char *token;
	char *sp1, *sp2;
	int index_safe_codes=0;

	/* 
	 * READ LINE BY LINE 
	 */
	line=strtok_r(cred, "\n", &sp1);
	while ( line != NULL) {
		/* 
		 * READ FIELD BY FIELD 
		 */
		token = strtok_r(line, "=", &sp2);
		if (strcmp(token,"id") == 0) {			
			token = strtok_r(NULL, "=", &sp2);
			strncpy(id, token, MAX_TELEGRAM_ID_LEN);
		}
		else if (strcmp(token,"botkey") == 0) {			
			token = strtok_r(NULL, "=", &sp2);
			strncpy(bkey, token, MAX_TELEGRAM_BOTKEY_LEN);
		}
		else if (strcmp(token,"proxy_username") == 0) {
			token = strtok_r(NULL, "=", &sp2);
			strncpy(p_uname, token, MAX_PROVIDED_INFORMATION_SIZE);
			trim_string(p_uname);
		}
		else if (strcmp(token,"proxy_password") == 0) {
			token = strtok_r(NULL, "=", &sp2);
			strncpy(p_pwd, token, MAX_PROVIDED_INFORMATION_SIZE);
			trim_string(p_pwd);
							
		}
		else if (strcmp(token,"safe_code") == 0) {
			token = strtok_r(NULL, "=", &sp2);
			strncpy(safe_codes[index_safe_codes], token, MAX_CODE_LENGTH);
			trim_string(safe_codes[index_safe_codes]);
			++index_safe_codes;
							
		}
		line=strtok_r(NULL, "\n", &sp1);
	}

	return 0;
}

/*
 * CHECK IF CACHE EXPIRED
 * RETURNS:
 * 	-1 : CACHE_ERROR
 *       1 : CACHE_VALID
 * 	 2 : CACHE_EXPIRED
 */
int check_cache(char * dname, const char * uname, int period, unsigned long *timestamp) 
{
	char path[512];
	char dirpath[512];
	int fd=0;
	char buf[80];
	unsigned long lasttime=0;
	unsigned long currenttime=0;
	struct timeval totd;

	gettimeofday(&totd, NULL);
	currenttime = totd.tv_sec;
	*timestamp = currenttime;

	sprintf(dirpath, "/tmp/%s/",dname);
	sprintf(path, "/tmp/%s/ts_%s",dname,uname);

	fd = open(dirpath, O_RDONLY);
	if (errno == ENOENT) {
		mkdir(dirpath, 0700);
	}
	close(fd);

	fd = open(path, O_RDWR | O_CREAT);

	if ( fd >= 0) {
		int size = read(fd, buf, 80);
		close(fd);
		if (size > 0)
			lasttime=atol(buf);
		else
			return CACHE_EXPIRED;		
	}
	else {
		return CACHE_ERROR;		

	}

	/*
	 * CHECK IF CACHE EXPIRED          
	 */
	unsigned int elapsedtime = currenttime - lasttime;
	if ( elapsedtime < period )
		return CACHE_VALID;
	else
		return CACHE_EXPIRED;

	return 0;
}

/*
 * WRITE TIMESTAMP INTO CACHE FILE
 */ 
int write_cache(char * dname, const char * uname, unsigned long timestamp) 
{
	char path[512];
	char dirpath[512];
	int fd=0;
	char buf[80];

	sprintf(dirpath, "/tmp/%s/",dname);
	sprintf(path, "/tmp/%s/ts_%s",dname,uname);

	fd = open(dirpath, O_RDONLY);
	if (errno == ENOENT) {
		mkdir(dirpath, 0700);
	}
	close(fd);

	fd = open(path, O_RDWR | O_CREAT);

	snprintf(buf,80,"%lu",timestamp);
	write(fd,buf,strlen(buf));
	close(fd);

	return 0;
}



/*
 * GENERATE AND SEND CODE TO TELEGRAM
 *
 * RETURNS
 *  0 - Everything OK
 * -1 - Error
 */
int send_code(char * chatid, 
	      char * botkey, 
	      int *code, 
	      char proxy_url[1024], 
	      char proxy_post_string[MAX_POST_SIZE], 
	      char *proxy_username, 
	      char *proxy_password,
	      pam_handle_t *pamh)
{

#ifdef __DEBUG__
	printf("DEBUG: (%s) (%s) (%i) (%s) (%s) (%s) (%s)\n", chatid, botkey, *code, proxy_url, proxy_post_string,proxy_username, proxy_password);
	sleep(2);
#endif


	/* 
	 * GENERATE CODE 
	 */
	int exponent = MAX_CODE_LENGTH;
	int base=10;
	long long intermediary_result = 1;
	while (exponent != 0) {
		intermediary_result *= base;
		--exponent;
	}
	int divisor = intermediary_result / 2;

	time_t _t;
	srand((unsigned) time(&_t));
	int temp_code = rand() % divisor; 

	/* 
	 * RETURN CODE TO CALLER - THE CALLER USES IT TO VERIFY IF USER PROVIDED THE RIGHT CODE 
	 */
	*code = temp_code; 

	/* 
	 * SEND CODE 
	 */
	char url[1024] = "";
	char __post[MAX_POST_SIZE] = "";
	snprintf(url,1024,TELEGRAM_URL,botkey); 
	snprintf(__post,MAX_POST_SIZE,TELEGRAM_POST, chatid, temp_code);
	
	CURL *curl;
	CURLcode response;



	int npass=0;

 try_again:
	
	curl_global_init(CURL_GLOBAL_ALL);
	curl = curl_easy_init();
	if (curl) {
		curl_easy_setopt(curl, CURLOPT_URL, url);
		curl_easy_setopt(curl, CURLOPT_POSTFIELDS, __post);
		curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, fake_curl_write);
		response = curl_easy_perform(curl);
		if (response != CURLE_OK) {
			curl_easy_cleanup(curl);
			/*
			 * TRY TO AUTHENTICATE
			 */ 
			int rval = internet_access_authentication(proxy_url, proxy_post_string, proxy_username, proxy_password, pamh);
			if (rval != 0) {
				return -1;
			}

			++npass;
			if (npass > 1) {
				return -1;
			}
			else
				goto try_again;
		}
		curl_easy_cleanup(curl);
	}
	curl_global_cleanup();

	return 0;	
}




PAM_EXTERN int pam_sm_setcred( pam_handle_t *pamh, int flags, int argc, const char **argv ) 
{
	return PAM_SUCCESS;
}


PAM_EXTERN int pam_sm_authenticate( pam_handle_t *pamh, int flags,int argc, const char **argv ) 
{
	int rval;
	const char* username;

	/* 
	 * MODULE PARAMETERS 
	 */
	char dir[256];
	char proxy_url[512];
	char proxy_post_string[512];
	int cache_timeout=0;
	int enable_safe_codes=0;


	/* 
	 * USER PROVIDED INFO 
	 */
	char proxy_username[MAX_PROVIDED_INFORMATION_SIZE]="!";
	char proxy_password[MAX_PROVIDED_INFORMATION_SIZE]="!";
	char chatid[MAX_PROVIDED_INFORMATION_SIZE];
	char botkey[MAX_TELEGRAM_BOTKEY_LEN];
	char safe_codes[MAX_SAFE_CODES][MAX_CODE_LENGTH+1]; /* +1 to hold '\0' */


	/* 
	 * AUXILIARY VARS 
	 */
	char* code;
	unsigned long timestamp;


	/* 
	 * PAM VARIABLES 
	 */
	struct pam_response *resp;	
	struct pam_conv *conv;
	struct pam_message msg[1], *pmsg[1];
	pmsg[0] = &msg[0];
	msg[0].msg_style = PAM_PROMPT_ECHO_ON;
	msg[0].msg = "CODE: ";

		
	/*  PARSE MODULE PARAMS
	 *
	 *     proxy_url=
	 *     proxy_post_string=
	 *
	 *     dir=~/.pam_telegram_2fa
	 *
	 *        Indicates which dir the user must create to insert it's credentials.
	 *        The example indicates the user must create dir ~/.pam_telegram_2fa
	 *
	 */
	parse_module_params(argc,
			    argv,
			    dir,
			    proxy_url,
			    proxy_post_string,
			    &cache_timeout,
			    &enable_safe_codes);


	rval = pam_get_user(pamh, &username, "Username: ");
	
	if (rval != PAM_SUCCESS) {
		return rval;
	}


	/* 
	 * DO NOT SEND CODE FOR ROOT USER - AT LEAST FOR NOW - WE DON'T WANT TO LOCK ROOT OUT 
	 */
	if (strcmp("root",username) == 0)
		return PAM_SUCCESS;


	/* 
	 * READ USER CONFIGURATION FILE 
	 */
	rval = read_user_configuration_file(username, 
					    dir, 
					    chatid, 
					    botkey, 
					    proxy_username,
					    proxy_password,
					    enable_safe_codes,
					    safe_codes); 

	/* 
	 * IF read_user_configuration RETURNED -1, 
	 * DISABLE TWO FACTOR AUTHENTICATION 
	 */
	if (rval == -1) {
		return PAM_SUCCESS;
	}


	/*
	 * CHECK IF PREVIOUSLY ENTERED CODE IS STILL VALID
	 */
	int sent_code;
	int do_i_need_a_safe_code=0;
	if (check_cache(dir, username, cache_timeout, &timestamp) != 2) {
		/* 
		 * IF NOT, GENERATE AND SEND CODE TO TELEGRAM 
		 */
		rval = send_code(chatid,
				 botkey,
				 &sent_code,
				 proxy_url,
				 proxy_post_string,
				 proxy_username,
				 proxy_password,
				 pamh);

		/*
		 * IF SEND_CODE() FAILED, ASK FOR SAFE CODES (SET VARIABLE TO FLAG IT)
		 */
		if (rval != 0) {
			do_i_need_a_safe_code=1;
		}
	}
	else {
		return PAM_SUCCESS;
	}	

	/* 
	 * ASK USER TO TYPE THE RECEIVED CODE 
	 */
	rval = pam_get_item(pamh, PAM_CONV, (const void **) &conv);
	if ( rval == PAM_SUCCESS) {
		rval = conv->conv(1, (const struct pam_message **)pmsg, &resp, conv->appdata_ptr);
	}

	/* 
	 * CHECK IF USER TYPED THE CORRECT CODE 
	 */
	if (resp) {

		/*
		 * ASK FOR SAFE CODE WHEN NEEDED
		 */
		if (do_i_need_a_safe_code)
			sent_code=atoi(safe_codes[0]); // TODO: remove this fixed index thing

		code = resp[0].resp;
		resp[0].resp = NULL;
		if (atoi(code) == sent_code) {
			/*
			 * WRITE CODE CACHE IF SUCESSFUL
			 */
			write_cache(dir,username,timestamp);
			return PAM_SUCCESS;
		}
		else {
			return PAM_AUTH_ERR;	
		}
	}
	else {
		return PAM_CONV_ERR;
	}

	return PAM_AUTH_ERR;
}
