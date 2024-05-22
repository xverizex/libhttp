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

static void handle (struct client_struc *cs)
{
	uint8_t buf[MSG_BUF_SIZE];
	uint64_t ret = 0;
	for (;;) {
		ssize_t len = read (cs->fd, buf, MSG_BUF_SIZE);
		if (len == -1) {
			perror ("read");
			exit (EXIT_FAILURE);
		}
		buf[len] = 0;
		int end = is_end (buf, len);

		if (len <= 0) {
			break;
		}

		if (end)
			break;
	}
}

static void *malloc_and_set (uint64_t size, uint8_t byte)
{
	void *data = malloc (size);
	memset (data, byte, size);
	return data;
}
static uint32_t listen_free_get_index (uint32_t *listen_free, int max_available_clients)
{
	for (int i = 0; i < max_available_clients; i++) {
		if (listen_free[i])
			return i;
	}

	return UINT32_MAX;
}

struct pool_client_struc {
	int max;
	struct client_struc *cs;
};

static void close_client (struct pool_client_struc *pool_cs, int indx)
{
	struct client_struc *deletable_cs = &pool_cs->cs[indx];

	int max = pool_cs->max;

	for (int i = 0; i < max; i++) {
		struct client_struc *cs = &pool_cs->cs[i];

		if (cs == deletable_cs) {
			close (cs->fd);
			if (cs->filename)
				free (cs->filename);
			if (cs->fp)
				fclose (cs->fp);

			int left = max - i;
			int all_left_size = left * sizeof (struct client_struc);

			if ((i + 1) == max)
				break;

			uint8_t *bytes = malloc (all_left_size);
			memcpy (bytes, &pool_cs->cs[i + 1], all_left_size);
			memcpy (&pool_cs->cs[i], bytes, all_left_size);
			free (bytes);
			break;
		}
	}

	max--;
	memset (&pool_cs->cs[max], 0, sizeof (struct client_struc));
	pool_cs->max = max;
}

static void restructure_fds (struct pollfd *fds, nfds_t *nfds, struct pool_client_struc *pool_cs)
{
	int max = pool_cs->max;
	*nfds = max;
	for (int i = 0; i < max; i++) {
		fds[i].fd = pool_cs->cs[i].fd;
		fds[i].events = POLLIN;
	}
}

struct http_struc {
	int server_fd;
	int max_avail;
};

struct http_struc *libhttp_init_struct (const char *ip, uint16_t port, int max_avail)
{
	int ret;
	int sock = ret = socket (AF_INET, SOCK_STREAM, 0);
	if (ret == -1) {
		return NULL;
	}

	int opt = 1;
	setsockopt (sock, SOL_SOCKET, SO_REUSEPORT, &opt, sizeof (opt));
	setsockopt (sock, SOL_SOCKET, SO_KEEPALIVE, &opt, sizeof (opt));

	struct sockaddr_in s;
	s.sin_family = AF_INET;
	s.sin_port = htons (port);
	inet_aton (ip, &s.sin_addr);

	ret = bind (sock, (const struct sockaddr *) &s, sizeof (s));
	if (ret == -1) {
		close (sock);
		return NULL;
	}

	ret = listen (sock, max_avail);
	if (ret == -1) {
		close (sock);
		return NULL;
	}

	struct http_struc *http = malloc_and_set (sizeof (struct http_struc), 0);
	http->server_fd = sock;
	http->max_avail = max_avail;

	return http;
}


int main (int argc, char **argv)
{

	struct http_struc *http = libhttp_init_struct ("0.0.0.0", 8080, 5);

	struct sockaddr_in c;
	socklen_t sc = sizeof (c);

	struct pollfd fds[http->max_avail];
	nfds_t nfds = 0;

	uint32_t *listen_free = malloc_and_set (sizeof (uint32_t) * http->max_avail, 0);

	struct pool_client_struc *pool_cs = malloc_and_set (sizeof (struct pool_client_struc), 0);
	pool_cs->cs = malloc_and_set (sizeof (struct client_struc) * http->max_avail, 0);

	while (1) {
		int client = accept (http->server_fd, (struct sockaddr *) &c, &sc);
		nfds++;

		int indx = listen_free_get_index (listen_free, http->max_avail);

		fds[indx].fd = client;
		fds[indx].events = POLLIN;

		struct client_struc *cs = &pool_cs->cs[indx];
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
				for (int i = 0; i < nfds; i++) {

					struct client_struc *cs = &pool_cs->cs[i];

					if (fds[i].revents & POLLIN) {
						handle (cs);
					}
					if (fds[i].revents & POLLNVAL) {
						close_client (pool_cs, i);
						restructure_fds (fds, &nfds, pool_cs);
					}
				}
			}
		}
	}
}
