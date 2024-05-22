#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <stdlib.h>
#include <fcntl.h>
#include <errno.h>
#include <stdint.h>
#include <sys/poll.h>

struct client_struc {
	int fd;
	char *filename;
	FILE *fp;
};

static const uint64_t filesize_mb = 10;
static uint64_t filesize_in_bytes = filesize_mb * 1024 * 1024;

#define MSG_BUF_SIZE               16384

static int is_end (uint8_t *b, ssize_t len)
{
	b += len - 4;

	if (*(b + 2) == 0x0d && *(b + 3) == 0x0a) {
		if (*(b + 0) == 0x0d && *(b + 1) == 0x0a)
			return 0;

		return 1;
	}

	return 0;
}

static size_t handle (int fd, int64_t size)
{
	uint8_t buf[MSG_BUF_SIZE];
	uint64_t ret = 0;
	for (;;) {
		ssize_t len = read (fd, buf, MSG_BUF_SIZE);
		if (len == -1) {
			perror ("read");
			exit (EXIT_FAILURE);
		}
		buf[len] = 0;
		int end = is_end (buf, len);

		if (len <= 0) {
			break;
		}

		ssize_t l = len;
		if ((size - len) < 0) {
			l = size - len;
			size -= l;
		} 

		memcpy (m, buf, l);

		m += l;
		ret += l;

		if (size == 0L)
			break;
		if (end)
			break;
	}

	mem[ret] = 0;
	return ret;
}

int main (int argc, char **argv)
{
	int sock = socket (AF_INET, SOCK_STREAM, 0);
	if (sock == -1) {
		perror ("socket");
		exit (EXIT_FAILURE);
	}

	int opt = 1;
	setsockopt (sock, SOL_SOCKET, SO_REUSEPORT, &opt, sizeof (opt));

	struct sockaddr_in s;
	s.sin_family = AF_INET;
	s.sin_port = htons (8080);
	inet_aton ("0.0.0.0", &s.sin_addr);

	int ret = bind (sock, (const struct sockaddr *) &s, sizeof (s));
	if (ret == -1) {
		perror ("bind");
		exit (EXIT_FAILURE);
	}

	listen (sock, 0);

	struct sockaddr_in c;
	socklen_t sc = sizeof (c);

	int n = 0;
	char filename[512];
	while (1) {
		int client = accept (sock, (struct sockaddr *) &c, &sc);

		struct pollfd fds[1];
		nfds_t nfds = 1;
		fds[0].fd = client;
		fds[0].events = POLLIN;

		struct client_struc *cs = malloc (sizeof (struct client_struc));
		cs->fd = client;

		while (1) {
			int poll_num = poll (fds, nfds, -1);
			if (poll_num == -1) {
				if (errno == EINTR)
					continue;

				perror ("poll");
				exit (EXIT_FAILURE);
			}

			if (poll_num > 0) {
				if (fds[0].revents & POLLIN) {
					size_t len = handle (client);
					if (len == 0)
						continue;

					printf ("readed: %lu\n", len);
					snprintf (filename, 512, "%d.txt", n++);
					FILE *fp = fopen (filename, "w");
					fwrite (mem, len, 1, fp);
					fclose (fp);
				}
			}


		}
		close (client);
	}
}
