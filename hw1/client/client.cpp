// TCP Client program
#include <iostream>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <string>
#include <sstream>
#include <cassert>
#include <fcntl.h>
#include <fstream>

#define PORT 8888
#define MAXLINE 192000
using namespace std;

int main(int argc, char *argv[])
{
    if(argc != 3){
        cerr << "Usage: ip_address port" << endl; exit(0); 
    } 
    char *serverIp = argv[1]; int port = atoi(argv[2]); 

    int sockfd;
    char buffer[MAXLINE];
    string s = "Hello Server";
    char * message = new char[s.size()+1];
    copy(s.begin(), s.end(), message);
    message[s.size()] = '\0';
    struct sockaddr_in servaddr;
    int n;
    socklen_t* len;
    if ((sockfd = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
        printf("socket creation failed");
        exit(0);
    }
    memset(&servaddr, 0, sizeof(servaddr));

    servaddr.sin_family = AF_INET;
    servaddr.sin_port = htons(port);
    servaddr.sin_addr.s_addr = inet_addr(serverIp);
    if (connect(sockfd, (struct sockaddr*)&servaddr,
                            sizeof(servaddr)) < 0) {
        printf("\n Error : tcp Connect Failed \n");
    }
    

    string S = "sample.txt";
    // sendto(sockfd, S.c_str(), strlen(S.c_str()),0, (const struct sockaddr*)&servaddr,sizeof(sockfd));

    sendto(sockfd, S.c_str(), strlen(S.c_str()),0, (const struct sockaddr*)&servaddr,sizeof(sockfd));
    bzero(buffer, sizeof(buffer));
    stringstream ts; ts << "sample_file.txt";
    ifstream fin(ts.str());
    stringstream ssf;
    ssf << fin.rdbuf();
    string content = ssf.str();
    sendto(sockfd, content.c_str(), strlen(content.c_str()),0, (const struct sockaddr*)&servaddr,sizeof(sockfd));



    
    
}