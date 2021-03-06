#include <sys/types.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/time.h>
#include <netinet/in.h>
#include <stdlib.h>
#include <stdio.h>
#include <ctype.h>
#include <unistd.h>
#include <signal.h>
#include <fcntl.h>
#include <errno.h>
#include <string.h>
#include <grp.h>
#include <netdb.h>
#include <pwd.h>
#include <grp.h>
#include <termios.h>
#include <stdarg.h>
#include <semaphore.h>

//int myfd;
int gextsocket;

#define SERVER_PORT 2001 
#define FMUTEX "/tmp/sw_cmd_instance"
#define HEAD_SIZE 9

unsigned char cmd_in_buff[256];

void usage()
{
		  // For public //
		  printf("Version OpenNSL\n");
		  printf("acc_sw \"SW_Command\"\r\n");
}

void sigdeath(int sig)
{
		  printf("dead like beef....\r\n");
		  close(gextsocket);
		  exit(0);
}

int main (int argc, char *argv[])
{
	fd_set readfds;
	fd_set readset;
	struct sockaddr_un a;
	struct sockaddr_un b;
	struct timeval tv;
	int CSBYTE = 4;

	int countn	  = 1;
	int udelay        = 0;
	int cudelay       = 0;
	char ReIP[128]     = {0};

	FILE * input_fd = fopen("ecconfig", "r");
	sprintf(ReIP, "%s", "127.0.0.1");	

	if( input_fd > 0)
	{
		char * ptr = NULL;
		printf("read ecconfig\r\n");
		int count = 1 ;
		int retn = 0;
		size_t size = 0;

		while((retn = getline(&ptr, &size ,input_fd)) > 0)
		{
			if(count==1)
			{
				//1st read is total count //
				countn = atoi(ptr);
				printf("countn=[%d]\r\n", countn);
				count++;
			}
			else if(count==2)
			{
				count++;
			}
			else if(count==3)
			{
				//3rd read is cmd udelay	  //	
				cudelay = atoi(ptr);
				printf("cudelay=[%d]\r\n", cudelay);
				count++;
			}
			else if(count==4)
			{
				//4th read is remote IP address //	
				sprintf(ReIP, "%s", ptr);	
				printf("Remote IP addr[%s]\r\n", ReIP);
				count++;

			}
			else
				break;
		}
		free(ptr);
		fclose(input_fd);
	}

	memset(cmd_in_buff, 0x0, sizeof(cmd_in_buff));

	if(argc == 1)
	{
		usage();
		return 0;
	}

	struct sigaction sigact = {0};
	sigset_t sigmask ={0};
	memset(&sigact,0,sizeof sigact);
	sigact.sa_handler = sigdeath;
	sigact.sa_mask = sigmask;

	sigaction(SIGHUP,&sigact,NULL);
	sigaction(SIGINT,&sigact,NULL);
	sigaction(SIGQUIT,&sigact, NULL);
	sigaction(SIGPIPE,&sigact,NULL);
	sigaction(SIGTERM,&sigact,NULL);
	sigaction(SIGKILL,&sigact,NULL);
	sigaction(SIGSEGV,&sigact,NULL);

	int count = countn;
	int enable = 1;
	tv.tv_sec = 0;

	if(udelay == 0)
		udelay = 50;

	tv.tv_usec = udelay;
	struct sockaddr_in dest;
	unsigned char buf[256] = {0};
	int nread = 0 , resultlen=0;
	unsigned char * result=0;
	unsigned char * tmp_ptr=0;

	gextsocket = socket(AF_INET, SOCK_STREAM, 0);
	setsockopt(gextsocket, SOL_SOCKET, SO_RCVTIMEO, (char *)&tv, sizeof(struct timeval));
	setsockopt(gextsocket, SOL_SOCKET, SO_REUSEADDR, &enable , sizeof(enable));
	bzero(&dest, sizeof(dest));
	dest.sin_family = AF_INET;
	dest.sin_port   = htons(SERVER_PORT);
	dest.sin_addr.s_addr = inet_addr(ReIP);

	connect(gextsocket,(struct sockaddr *)&dest, sizeof(dest) );
	sprintf(cmd_in_buff,"%s\r\n", argv[1]);
	send( gextsocket , cmd_in_buff , strlen(cmd_in_buff), 0);
	memset(buf, 0x0, sizeof(buf));

	nread = recv(gextsocket, buf, sizeof(buf), 0);	

	while(nread != 0)
	{
		if(nread > 0)
		{
			resultlen += nread;	
			if(result != 0)
			{
				tmp_ptr = realloc (result, resultlen); 
				if(tmp_ptr !=0)
				{
					result = tmp_ptr;
					memcpy(result + (resultlen-nread), buf, nread);
				}
				else
				{
					printf("ERROR\r\n"); 
					printf("error!!!!\r\n"); 
					free(result);
					close(gextsocket);
					return 0;
				}
			}
			else
			{
				result = malloc(resultlen ); 
				memcpy(result, buf, resultlen);
			}
		}
		else
		{
			unsigned char * p_result = 0;
			unsigned char * p_end = 0;

			if(strstr(result, "ERROR"))
			{
				printf("ERROR\r\n"); 
				break;
			}
			else
			{
				//p_end = strstr(result, "BCM.0>");
				p_end = strstr(result, "drivshell>");

				if(p_end != 0)
				{
					*p_end = '\0';
					printf("[%s]\r\n", result + HEAD_SIZE + strlen(argv[1])); 
					if(result != 0)
					{
						free(result);
						result=0;
					}
					break;
				}
			}
		}
		nread = recv(gextsocket, buf, sizeof(buf), 0);	
	}
	close(gextsocket);
}


