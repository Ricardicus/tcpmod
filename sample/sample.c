/*
* A little monitor program.
*
* Given a file handled by
* the tcpmod driver it 
* polls and checks for incoming
* messages, and prints information
* about them once they arrive. 
*/
#include <stdio.h>
#include <unistd.h>

#include "sample.h"

static void usage(const char * const argv0)
{
	printf("Usage: %s tcpmod-file\n", argv0);
}

static void check(const char *file)
{
	fd_set rfds;
	struct timeval tv;
	int retval;
	inet_message_t msg;
	int fd;

	if ( fd < 0 ) {
		fprintf(stderr, "Failed to open file: %s\n", file);
		exit(1);
	}

	while ( 1 ) {

		/* Wait up to five seconds. */
		tv.tv_sec = 5;
		tv.tv_usec = 0;

		fd = open(file, O_RDONLY);

		if ( fd < 0 ) {
			fprintf(stderr, "Failed to open file: %s\n", file);
			exit(1);
		}

		FD_ZERO(&rfds);
		FD_SET(fd, &rfds);

		// Poll fd
		retval = select(fd+1, &rfds, NULL, NULL, &tv);

		if ( retval == -1 ) {
			fprintf(stderr, "Failed to poll file\n");
			exit(1);
		} else if ( retval ) {
			// Data available!
			char time_buffer[30];
			struct tm *tm_info;

			ioctl(fd, RD_MESSAGE, &msg);

			tm_info = localtime(&msg.time.tv_sec);

			memset(time_buffer,0,sizeof(time_buffer));

			strftime(time_buffer, 26, "%Y-%m-%d %H:%M:%S", tm_info);

			printf("%s (%lu.%lu.%lu.%lu:%d): %s\n", 
				time_buffer, 
				(msg.ip & 0x000000FF),
				(msg.ip & 0x0000FF00) >> 8,
				(msg.ip & 0x00FF0000) >> 16,
				(msg.ip & 0xFF000000) >> 24,
				msg.port, msg.data);
		} else {
			printf("No messages..\n");
		}

		close(fd);

	}

}

int main(int argc, char *argv[])
{
	FILE *fp;
	const char *file;

	if ( argc < 2 ) {
		usage(argv[0]);
		return 1;
	}

	file = argv[1];

	if ( access(file, F_OK) != 0 ) {
		usage(argv[0]);
		return 1;
	}

	check(file);
}