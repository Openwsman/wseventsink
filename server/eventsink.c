/*******************************************************************************
 * Copyright (C) 2004-2006 Intel Corp. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 *  - Redistributions of source code must retain the above copyright notice,
 *    this list of conditions and the following disclaimer.
 *
 *  - Redistributions in binary form must reproduce the above copyright notice,
 *    this list of conditions and the following disclaimer in the documentation
 *    and/or other materials provided with the distribution.
 *
 *  - Neither the name of Intel Corp. nor the names of its
 *    contributors may be used to endorse or promote products derived from this
 *    software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS ``AS IS''
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL Intel Corp. OR THE CONTRIBUTORS
 * BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 *******************************************************************************/

/**
 * @author Anas Nashif
 * @author Liang Hou
 */

#include <sys/types.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include "eventlistener.h"

static int port = 80;
static char *servicepath = "/eventsink";
static int debug = 0;
static int log_pid = 0;
static char *output_file = NULL;

static void usage(void)
{
	printf("\n\neventsink [-p port] [-r service_path] [-d] [-o output_file]\n\n");
}

static void
debug_message_handler(const char *str,
		      debug_level_e level, void *user_data)
{
	if (log_pid == 0)
		log_pid = getpid();

	if ( debug > 0) {
		struct tm *tm;
		time_t now;
		char timestr[128];
		char *log_msg;
		int p;

		time(&now);
		tm = localtime(&now);
		strftime(timestr, 128, "%b %e %T", tm);

		log_msg = u_strdup_printf("%s [%d] %s\n",
					  timestr, log_pid, str);
		if ((p =
		     write(STDERR_FILENO, log_msg, strlen(log_msg))) < 0)
			fprintf(stderr, "Failed writing to log file\n");
		fsync(STDERR_FILENO);

		u_free(log_msg);
	}
}


static void initialize_logging(void)
{
	debug_add_handler(debug_message_handler, -1, NULL);

}	

static int print_events(WsXmlDocH indoc, void *data)
{
	FILE *f = stdout;
        const char *filename = output_file;
	struct tm *tm;
        time_t now;
        char timestr[128];
        char *log_msg;
        time(&now);
        tm = localtime(&now);
        strftime(timestr, 128, "%b %e %T", tm);
	if (filename) {
		f = fopen(filename, "a+");
		if (f == NULL) {
			error("Could not open file for writing");
			return -1;
                }
        }
	if(f == stdout)
        	log_msg = u_strdup_printf("\t\t\033[22;32mAt %s received:\033[m \n\n",timestr);
	else
		log_msg = u_strdup_printf("At %s received:\n\n", timestr);
        fprintf(f, "%s", log_msg);
	ws_xml_dump_node_tree(f, ws_xml_get_doc_root(indoc));
	fflush(f);
	if (f != stdout) {
		fclose(f);
        }
        u_free(log_msg);
	return 0;
}

int main(int argc, char *argv[])
{
	int ch;
	if(argc > 1 && strcasecmp(argv[1], "help") == 0) {
		usage();
		exit(0);
	}
	while(argc > 1 && (ch = getopt(argc, argv, "p:r:o:d"))!= -1) {
		switch(ch) {
			case 'p':
				port = atoi(optarg);
				break;
			case 'r':
				servicepath = optarg;
				break;
			case 'd':
				debug = 1;
				break;
			case 'o':
				output_file = optarg;
				break;
			default:
				printf("Unrecognized option!\n");
				exit(0);
		}
	}
	initialize_logging();
	if(eventlistener_init(port, servicepath, 1, debug))
		exit(-1);
	eventlistener_register_event_processor(print_events, NULL);
	eventlistener_start();
	return 0;
}
