#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <stdint.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>

int write_error(const char *filename, const char *custmsg)
{
    fprintf(stderr, "Error: ");
    if (filename)
        fprintf(stderr, "%s: ", filename);
    if (custmsg)
        fprintf(stderr, "%s", custmsg);
    else
    {
        const char *errmsg = strerror(errno);
        fprintf(stderr, "%s", errmsg);
    }
    fprintf(stderr, "\n");

    return 1;
}

void *read_file(const char *path, uint64_t *fsize)
{
    int fd = -1;
    if ((fd = open(path, O_RDONLY)) == -1)
    {
        write_error(path, NULL);
        return NULL;
    }

    int64_t bytes;
    bytes = lseek(fd, 0, SEEK_END);
    if (bytes == -1)
    {
        write_error(path, NULL);
        close(fd);
        return NULL;
    }

    *fsize = bytes;
    void *file = malloc(sizeof(char) * (*fsize));
    if (file)
    {
        lseek(fd, 0, SEEK_SET);
        bytes = read(fd, file, *fsize);
        if (bytes == -1)
        {
            write_error(path, NULL);
            free(file);
            file = NULL;
        }
    }
    else
        write_error(NULL, NULL);

    close(fd);

    return file;
}

void patch_payload_addr32(char *bytes, uint64_t size, int32_t target, int32_t repl)
{
    for (uint32_t i = 0; i < size; ++i)
    {
        int32_t chunk = *(int32_t *)(bytes + i);
        if (!(chunk ^ target))
        {
            *(int32_t *)(bytes + i) = repl;
            return;
        }
    }
}

void patch_payload_addr64(char *bytes, uint64_t size, int64_t target, int64_t repl)
{
    for (uint64_t i = 0; i < size; ++i)
    {
        int64_t chunk = *(int64_t *)(bytes + i);
        if (!(chunk ^ target))
        {
            *(int64_t *)(bytes + i) = repl;
            return;
        }
    }
}
