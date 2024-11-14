/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   woody.h                                            :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: mbucci <mbucci@student.s19.be>             +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2023/11/07 13:06:21 by mbucci            #+#    #+#             */
/*   Updated: 2023/11/07 15:04:21 by mbucci           ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#pragma once

/* INCLUDES */
#include <stdint.h>

/* CONSTANTS */
#ifndef PATCH
# define PATCH "patched"
#endif

/* PAYLOADS */
#define HANDLER_ELF64_PATH "./payloads/handler_elf64.bin"
#define HANDLER_ELF32_PATH "./payloads/handler_elf32.bin"

/* ERRORS */
#define USAGE_ERR "usage: ./infector <path/to/binary>"
#define LOAD_ERR "no loadable segment found"
#define PADD_ERR "can't inject payload: padding too small"
#define CORRUPT_ERR "file is corrupted"
#define ELF_ERR "not an elf file"
#define FORMAT_ERR "file format is not supported"
#define ELFEXEC_ERR "not an elf executable"

typedef struct s_target
{
	const char	*filename;
	uint64_t	filesz;
	void		*base;
}	t_target;

/* elf64.c */
int infect_elf64(t_target *);

/* elf32.c */
int infect_elf32(t_target *);

/* utils.c */
int write_error(const char *, const char *);
void *read_file(const char *, uint64_t *);
void patch_payload_addr32(char *, uint64_t, int32_t, int32_t);
void patch_payload_addr64(char *, uint64_t, int64_t, int64_t);
