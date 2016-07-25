#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <pthread.h>
#include <unistd.h>
#include <time.h>
#include <dirent.h>
#include <ctype.h>

#include "ae.h"
#include "server.h"
#include "anet.h"
#include "http_parser.h"
#include "hash.h"
#include "tmpl.h"


struct server g_svr;

/* Put event loop in the global scope, so it can be explicitly stopped */
void *accept_worker(void *arg) {
    int fd = anetTcpServer(NULL, g_svr.cfg.port, NULL, 127);
    anetNonBlock(NULL, fd);
    
    aeEventLoop *loop = aeCreateEventLoop(1024);
    
    if (aeCreateFileEvent(loop, fd, AE_READABLE, accept_proc, NULL) == AE_ERR) {
        fprintf(stderr, "Can not create event loop service.\n");
        exit(1);
    }
    if (aeCreateTimeEvent(loop, 1, server_cron, NULL, NULL) == AE_ERR) {
        fprintf(stderr, "Can not create event loop timers.\n");
        exit(1);
    }

    aeSetBeforeSleepProc(loop, before_sleep);
    aeMain(loop);
    
    aeDeleteEventLoop(loop);
    pthread_exit(NULL);
}

void *task_worker(void *arg) {
    aeEventLoop *loop;
    
    pthread_detach(pthread_self());
    loop = aeCreateEventLoop(64);
    if (!loop) {
        fprintf(stderr, "create ae event loop failed\n");
        pthread_exit(NULL);
    }
    if (aeCreateTimeEvent(loop, 1, task_cron, NULL, NULL) == AE_ERR) {
        fprintf(stderr, "Can not create event loop timers.\n");
        exit(1);
    }
    
    aeMain(loop);
    
    aeDeleteEventLoop(loop);
    pthread_exit(NULL);
}

void *worker(void *arg) {
    struct thrd *thread = arg;
    aeEventLoop *loop;
    
    
    pthread_detach(pthread_self());
    
    loop = aeCreateEventLoop(1024);
    if (!loop) {
        fprintf(stderr, "create ae event loop failed\n");
        pthread_exit(NULL);
    }
    thread->loop = loop;
    
    aeMain(loop);
    
    pthread_exit(NULL);
}

static int cfg_def_init(struct cfg *cfg) 
{
    cfg->port = 8189;
    cfg->dir = "./www";
    cfg->thrd_nr = 1;
    return 0;
}


static int parse_cmd_args(int argc, char **argv)
{
    int c, thrd_nr;
    long int port;
    
    DIR *d;

    opterr = 0;

    while ((c = getopt(argc, argv, "p:d:t:?")) != -1) {
        switch (c) {
            case 'p':
                port = strtol(optarg, NULL, 10);
                if (port > 65535 || port < 80) {
                    fprintf(stderr, "port is 80-65535.\n");
                    abort();
                }

                g_svr.cfg.port = (uint16_t)port;
                break;
            case 't':
                thrd_nr = strtol(optarg, NULL, 10);
                if (thrd_nr > 128 || thrd_nr < 1) {
                    fprintf(stderr, "thread number is 1-128.\n");
                    abort();
                }
                g_svr.cfg.thrd_nr = (uint8_t)thrd_nr;
                break;
            case 'd':
                d = opendir(optarg);
                if (!d) {
                    fprintf(stderr, "Not a valid dir.\n");
                    abort();
                }
                closedir(d);
                g_svr.cfg.dir = optarg;
                break;
            case '?':
                if (optopt == 'p')
                    fprintf(stderr, "Specify port(80-65535) with -p <port>.\n");
                else if (optopt == 'd')
                    fprintf(stderr, "Specify root dir with -d <dir>.\n");
                else if (isprint(optopt))
                    fprintf(stderr, "Unknown option `-%c`.\n", optopt);
                else
                    fprintf(stderr, "Unknown option `\\x%x`.\n", optopt);
                return 1;
            default:
                fprintf(stderr, "params: -p <port> -d <dir> -t <threads>.\n");
                abort();
        }
    }
    return 0;
}

static int svr_init(void)
{
    memset(&g_svr, 0, sizeof(g_svr));
    cfg_def_init(&g_svr.cfg);

    g_svr.running = 1;
    pthread_mutex_init(&g_svr.mtx, 0);
    
    g_svr.parser_settings.on_url = url_callback; 
    
    g_svr.threads = calloc(g_svr.cfg.thrd_nr, sizeof(struct thrd));
    if (!g_svr.threads) {
        fprintf(stderr, "failed to alloc memory.\n");
        abort();
    }
    
    mime_tables_init();
    g_svr.cache = hash_str_new(free, string_free);
    g_svr.blogs = malloc(sizeof(struct list_head));
    list_head_init(g_svr.blogs);

    refresh_index_page();
    return 0;
}   

static int svr_fini(void)
{
    // clean threads.
    if (g_svr.threads) {
        free(g_svr.threads);
        g_svr.threads = NULL;
    }
    pthread_mutex_destroy(&g_svr.mtx);
 
    free_blogs_list(g_svr.blogs);
    hash_free(g_svr.cache);
    mime_tables_shutdown();
    return 0;
}

static void sig_handler(int signum)
{
    g_svr.running = 0;
    fprintf(stderr, "\n[%d] server exiting...\n", signum);
}



int main (int argc, char **argv) {
    pthread_t accept_thrd, task_thrd;
    void *res;

    
    svr_init();
    parse_cmd_args(argc, argv);
    if (signal(SIGINT, sig_handler) == SIG_ERR
            || signal(SIGTERM, sig_handler) == SIG_ERR) {
        fprintf(stderr, "failed to bind signal handler.\n");
        abort();
    }

    signal(SIGPIPE, SIG_IGN);
    
    const struct url_map aehttpd_url_map[] = {
        { .prefix = "/blogs/", .handler = blogs },
        { .prefix = "/", .handler = static_files },
        { .prefix = NULL }
    };
    
    http_set_url_map(&g_svr, aehttpd_url_map);
    
    
    
    pthread_create(&accept_thrd, NULL, &accept_worker, NULL);
    pthread_create(&task_thrd, NULL, &task_worker, NULL);
    
    int i;
    for (i = 0; i < g_svr.cfg.thrd_nr; i++) {
        pthread_create(&g_svr.threads[i].self, NULL, &worker, &g_svr.threads[i]);
    }
    
leave:    
    pthread_join(accept_thrd, &res);

    svr_fini();
    printf("aehttpd exited\n");
    
    
    return 0;
}

