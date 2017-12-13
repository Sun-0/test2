#include <stdio.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <strings.h>
#include <string.h>
#include <stdlib.h>

int main(void)
{
    struct sockaddr_in server_addr, client_addr;
    char recvbuf[4096] = "Anmoaly= IP_Proto_Misuse;sub_type= IP Flooding;ID=500001;Status=start;device_key=3133222142;classification=medium;start=2015-04-24 15:35:24 ; update=2015-04-24 15:36:24;dst=1.1.1.1;dport=80;zone_name=test;";
    socklen_t client_len;
    int sockfd;
    int ret = 0, n, num = 0, i = 0;

    //sendto
    bzero(&client_addr, sizeof(client_addr));
    client_addr.sin_family = AF_INET;
    client_addr.sin_addr.s_addr = inet_addr("127.0.0.1");
    client_addr.sin_port = htons(514);

    sockfd = socket(PF_INET, SOCK_DGRAM, 0);
    if (sockfd < 0) {
        perror("Create Socket Failed:");
        exit(1);
    }

    //异或加密
    i = 0;
    while (recvbuf[i]) {
        recvbuf[i] = (char)(recvbuf[i]^0xa6);
        i++;
    }

    while (1) {
        printf("recvbuf2 = %s\n", recvbuf);
        sendto(sockfd, recvbuf, strlen(recvbuf), 0, (struct sockaddr*)&client_addr, sizeof(client_addr));
        sleep(1);
    }

    close(sockfd);

    return 0;
}

