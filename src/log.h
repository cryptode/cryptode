/*
 * Copyright (c) 2017, [Ribose Inc](https://www.cryptode.com).
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * ``AS IS'' AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#ifndef __CRYPTODED_LOG_H__
#define __CRYPTODED_LOG_H__

#define COD_LOG_FILE_NAME            "cryptoded.log"

#define COD_MAX_LOG_FSIZE            30 * 1024 * 1024

/* macro definition of debug functions */
#define COD_DEBUG_MSG(...)           cod_debug_log(LOG_TYPE_MSG, __FILE__, __LINE__, __VA_ARGS__);
#define COD_DEBUG_ERR(...)           cod_debug_log(LOG_TYPE_ERR, __FILE__, __LINE__, __VA_ARGS__);
#define COD_DEBUG_WARN(...)          cod_debug_log(LOG_TYPE_WARN, __FILE__, __LINE__, __VA_ARGS__);

/* debug types */
enum LOG_TYPE {
	LOG_TYPE_MSG = 0,
	LOG_TYPE_ERR,
	LOG_TYPE_WARN
};

/* cryptoded log functions */
int cod_log_init(const char *log_dir_path);
void cod_log_finalize(void);

void cod_debug_log(enum LOG_TYPE log_type, const char *file_name, int file_line, const char *format, ...);

#endif /* __CRYPTODED_LOG_H__ */
