#include <iostream>
#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <strings.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>
#include <string>
#include <cstring>
#include <pthread.h>
#include <sstream>
#include <sys/ipc.h>
#include <sys/shm.h>
#include <sys/wait.h>
#include <sys/time.h>
#include <stdint.h>
#include <cassert>
#include <fcntl.h>
#include <string>
#include <cstring>
#include <exception>
#include <fstream>

#define PORT 8888
#define MAXLINE 192000
#define SIZE 19200000

using namespace std;


int main(int argc, char *argv[])
{
    srand(time(NULL));
    int listenfd, udpfd, connfd, nready, maxfdp1 = 0, listenfd1;
    char buffer[MAXLINE];
    pid_t childpid;
    fd_set rset;
    socklen_t len;
    struct sockaddr_in cliaddr, servaddr;

    if(argc != 2){
        cerr << "Please give: port" << endl;
        exit(0);
    }
    int port = atoi(argv[1]);


    //create listening TCP socket
    listenfd = socket(AF_INET, SOCK_STREAM, 0); //blocking
    bzero(&servaddr, sizeof(servaddr));
    int opt = 1; 
    if( setsockopt(listenfd, SOL_SOCKET, SO_REUSEADDR, (char *)&opt, sizeof(opt)) < 0 ){  
        perror("setsockopt");  
        exit(EXIT_FAILURE);  
    } 
    servaddr.sin_family = AF_INET;
    servaddr.sin_addr.s_addr = htonl(INADDR_ANY);
    servaddr.sin_port = htons(port);

    // binding server addr structure to listenfd
    bind(listenfd, (struct sockaddr*)&servaddr, sizeof(servaddr));
    listen(listenfd, 100);
    cout<<"TCP server is running"<<endl;

    connfd = accept(listenfd, (struct sockaddr*)&cliaddr, &len); //accept tcp connection
    cout<<"New connection"<<endl;

    // len = sizeof(cliaddr);
    // memset(&buffer, 0, sizeof(buffer));
    // recv(connfd, (char*)&buffer, sizeof(buffer), 0);
    // cout<<buffer<<endl;
        
    recv(connfd, (char*)&buffer, sizeof(buffer), 0);
    stringstream fs; fs << buffer;
    ofstream fout(fs.str());
    bzero(buffer, sizeof(buffer));
    recv(connfd, (char*)&buffer, sizeof(buffer), 0);
    fout << buffer;

    

}
        
