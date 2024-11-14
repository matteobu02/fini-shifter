/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   main.c                                             :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: jdecorte42 <jdecorte42@student.42.fr>      +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2023/11/07 12:38:28 by mbucci            #+#    #+#             */
/*   Updated: 2023/11/20 16:37:40 by mbucci           ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include <elf.h>
#include <stdlib.h>
#include "infector.h"

static int check_arg(const char *filename)
{
    t_target target = {filename, 0, NULL};

    int err = 1;

    if (!(target.base = read_file(filename, &target.filesz)))
        return err;

    // check architecture
    Elf64_Ehdr *elf = target.base;
    const unsigned char *f_ident = elf->e_ident;
    if (f_ident[EI_MAG0] != ELFMAG0
            || f_ident[EI_MAG1] != ELFMAG1
            || f_ident[EI_MAG2] != ELFMAG2
            || f_ident[EI_MAG3] != ELFMAG3
       )
        write_error(filename, ELF_ERR);

    // check file class
    else if (f_ident[EI_CLASS] != ELFCLASS64 && f_ident[EI_CLASS] != ELFCLASS32)
        write_error(filename, FORMAT_ERR);

    // check file type
    else if (elf->e_type != ET_EXEC && elf->e_type != ET_DYN)
        write_error(filename, ELFEXEC_ERR);

    else // do the thing
    {
        if (f_ident[EI_CLASS] == ELFCLASS64)
            err = infect_elf64(&target);
        //else if (f_ident[EI_CLASS] == ELFCLASS32)
        //    err = infect_elf32(&target);
    }

    free(target.base);

    return err;
}

int main(int ac, char **av)
{
    if (ac != 2)
        return write_error(NULL, USAGE_ERR);

    return check_arg(av[1]);
}
