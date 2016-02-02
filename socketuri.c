#include "socketuri.h"

int send_message(char* message)
{

      int sock;
      struct sockaddr_un server;


      sock = socket(AF_UNIX, SOCK_STREAM, 0);

      if (sock < 0) {
          perror("opening stream socket");
          exit(1);
      }
      server.sun_family = AF_UNIX;
      strcpy(server.sun_path, "localhost");


      if (connect(sock, (struct sockaddr *) &server, sizeof(struct sockaddr_un)) < 0) {
          close(sock);
          perror("connecting stream socket");
          exit(1);
      }
      if (write(sock, message, strlen(message)) < 0)
          perror("writing on stream socket");
      else
        return 0;


      close(sock);
      return 0;
  }

