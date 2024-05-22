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
#include <pthread.h>

#define MSG_BUF_SIZE               16384
#define LENGTH_FILENAME             4096
#define PATTERN_GLOBAL_NUM      "files/%lu.data"

struct htx_pool_http {
	int max;
	struct htx_http_struc **http;
};

struct htx_http_struc {
	int server_fd;
	int max_avail;
	pthread_t thread;
	struct htx_pool_client_struc *pool_cs;
	uint32_t *listen_free;
};

struct htx_client_struc {
	int fd;
	struct sockaddr_in c;
	socklen_t sc;
};

struct htx_pool_client_struc {
	int max;
	struct htx_client_struc *cs;
};

struct htx_com_file {
	int fd;
	char filename[LENGTH_FILENAME];
};

struct htx_client_com {
	int fd;
	struct char *filename[LENGTH_FILENAME];
	int max;
};

static uint64_t global_file_number;

static const uint64_t filesize_mb = 10;
static uint64_t filesize_in_bytes = filesize_mb * 1024 * 1024;


static void *htx_malloc_and_set (uint64_t size, uint8_t byte)
{
	void *data = malloc (size);
	memset (data, byte, size);
	return data;
}

static int is_end (uint8_t *b, ssize_t len)
{
	b += len - 2;

	if (*(b + 0) == 0x0d && *(b + 1) == 0x0a) {
		return 1;
	}

	return 0;
}

static void handle (struct htx_client_struc *cs, struct htx_com_file **hpf)
{
	*hpf = NULL;

	char filename[4096];
	snprintf (filename, 4096, PATTERN_GLOBAL_NUM, global_file_number++);

	uint8_t buf[MSG_BUF_SIZE];
	uint64_t ret = 0;

	FILE *fp = fopen (filename, "w");

	struct htx_com_file *hp = htx_malloc_and_set (sizeof (struct htx_com_file), 0);

	for (;;) {
		ssize_t len = read (cs->fd, buf, MSG_BUF_SIZE);
		if (len == -1) {
			free (hp);
			perror ("read");
			exit (EXIT_FAILURE);
		}
		buf[len] = 0;
		int end = is_end (buf, len);

		if (len < 0) {
			break;
		}

		fwrite (buf, len, 1, fp);

		if (end)
			break;
	}

	fclose (fp);

	size_t ln_filename = strlen (filename);
	memcpy (hp->filename, filename, ln_filename + 1);
	hp->fd = cs->fd;
	
	*hpf = hp;
}

static uint32_t listen_free_get_index (uint32_t *listen_free, int max_available_clients)
{
	for (int i = 0; i < max_available_clients; i++) {
		if (listen_free[i])
			return i;
	}

	return UINT32_MAX;
}


static void close_client (struct htx_pool_client_struc *pool_cs, int indx)
{
	struct htx_client_struc *deletable_cs = &pool_cs->cs[indx];

	int max = pool_cs->max;

	for (int i = 0; i < max; i++) {
		struct htx_client_struc *cs = &pool_cs->cs[i];

		if (cs == deletable_cs) {
			close (cs->fd);

			int left = max - i;
			int all_left_size = left * sizeof (struct htx_client_struc);

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
	memset (&pool_cs->cs[max], 0, sizeof (struct htx_client_struc));
	pool_cs->max = max;
}

static void restructure_fds (struct pollfd *fds, nfds_t *nfds, struct htx_pool_client_struc *pool_cs)
{
	int max = pool_cs->max;
	*nfds = max;
	for (int i = 0; i < max; i++) {
		fds[i].fd = pool_cs->cs[i].fd;
		fds[i].events = POLLIN;
	}
}


struct htx_http_struc *htx_init_struct (const char *ip, uint16_t port, int max_avail)
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

	struct htx_http_struc *http = htx_malloc_and_set (sizeof (struct htx_http_struc), 0);
	http->server_fd = sock;
	http->max_avail = max_avail;

	return http;
}


int htx_pool_http_add (struct htx_pool_http *ph, struct htx_http_struc *http)
{
	int max = ph->max;
	int indx = max++;
	struct htx_http_struc **ht = realloc (ph->http, sizeof (struct htx_http_struc) * max);
	if (!ht) {
		return 1;
	}

	ht[indx] = http;
	ph->http = ht;
	ph->max;

	return 0;
}

static void free_http (struct htx_http_struc *http)
{
	close (http->server_fd);
	free (http);
}

void htx_pool_http_free (struct htx_pool_http *ph)
{
	for (int i = 0; i < ph->max; i++) {
		free_http (ph->http[i]);
	}

	free (ph);
}

static void init_http (struct htx_http_struc *http)
{


	http->listen_free = htx_malloc_and_set (sizeof (uint32_t) * http->max_avail, 0);

	http->pool_cs = htx_malloc_and_set (sizeof (struct htx_pool_client_struc), 0);
	http->pool_cs->cs = htx_malloc_and_set (sizeof (struct htx_client_struc) * http->max_avail, 0);
}

static void *worker_http (void *_data)
{
	struct htx_http_struc *http = (struct htx_http_struc *) _data;

	struct pollfd fds[http->max_avail];
	nfds_t nfds = 0;

	socklen_t sc = sizeof (struct sockaddr_in);

	while (1) {
		int indx = listen_free_get_index (http->listen_free, http->max_avail);
		struct htx_client_struc *cs = &http->pool_cs->cs[indx];

		int client = accept (http->server_fd, (struct sockaddr *) &cs->c, &cs->sc);
		nfds++;

		fds[indx].fd = client;
		fds[indx].events = POLLIN;

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

					struct htx_client_struc *cs = &http->pool_cs->cs[i];

					struct htx_com_file *com_file = NULL;

					if (fds[i].revents & POLLIN) {
						handle (cs, &com_file);
					}
					if (fds[i].revents & POLLNVAL) {
						close_client (http->pool_cs, i);
						restructure_fds (fds, &nfds, http->pool_cs);
					}
				}
			}
		}
	}
}

void htx_pool_http_make_srv (struct htx_pool_http *ph)
{
	for (int i = 0; i < ph->max; i++) {
		init_http (ph->http[i]);
		pthread_create (&ph->http[i]->thread, NULL, worker_http, ph->http[i]);
	}


}


int main (int argc, char **argv)
{

	struct htx_pool_http *ph = htx_malloc_and_set (sizeof (struct htx_pool_http), 0);

	struct htx_http_struc *http0 = htx_init_struct ("0.0.0.0", 8080, 5);
	struct htx_http_struc *http1 = htx_init_struct ("0.0.0.0", 8090, 5);

	int ret_pool = 0;
	ret_pool += htx_pool_http_add (ph, http0);
	ret_pool += htx_pool_http_add (ph, http1);

	if (ret_pool > 0) {
		htx_pool_http_free (ph);
		exit (EXIT_FAILURE);
	}

	htx_pool_http_make_srv (ph);

	struct htx_pool_com_files pcf;
}
