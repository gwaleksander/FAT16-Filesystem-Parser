#ifndef DOBRYSYSTEMPLIKOW_H
#define DOBRYSYSTEMPLIKOW_H

#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <ctype.h>
#include <errno.h>

#define SECTOR_SIZE 512
#define FAT_ATTR_READONLY  0x01
#define FAT_ATTR_HIDDEN    0x02
#define FAT_ATTR_VOLUME    0x08
#define FAT_ATTR_DIRECTORY 0x10
#define FAT_ATTR_ARCHIVE   0x20

struct boot_sec {
    char unused[3];
    char name[8];
    uint16_t bytes_per_sector;
    uint8_t sectors_per_clusters;
    uint16_t size_of_reserved_area;
    uint8_t number_of_fats;
    uint16_t maximum_number_of_files;
    uint16_t number_of_sectors;
    uint8_t media_type;
    uint16_t size_of_fat;
    uint16_t sectors_per_track;
    uint16_t number_of_heads;
    uint32_t number_of_sectors_before_partition;
    uint32_t number_of_sectors_in_filesystem;
    uint8_t drive_number;
    uint8_t unused_1;
    uint8_t boot_signature;
    uint32_t serial_number;
    char label[11];
    char type[8];
    uint8_t unused_2[448];
    uint16_t signature;
} __attribute__((__packed__));


struct disk_t {
    FILE * file;
};

struct file_t {
    char name[9];
    char ext[4];
    uint16_t * cluster_list;
    uint16_t cluster_count;
    uint32_t size;
    int32_t position;
    struct volume_t * volume;
};

struct dir_entry_t {
    char name[9];
    char ext[4];
    uint8_t attr;
    uint16_t first_cluster;
    uint32_t size;

    uint8_t is_archived;
    uint8_t is_readonly;
    uint8_t is_system;
    uint8_t is_hidden;
    uint8_t is_directory;
};

struct volume_t {
    struct disk_t * disk;
    uint16_t * fat;
    struct dir_entry_t * root_entries;
    struct boot_sec boot_sec;
    size_t offset;
};

struct disk_t* disk_open_from_file(const char* volume_file_name);
int disk_read(struct disk_t* pdisk, int32_t first_sector, void* buffer, int32_t sectors_to_read);
int disk_close(struct disk_t* pdisk);

uint16_t fat_get_next_cluster(struct volume_t* volume, uint16_t current_cluster);

struct volume_t * fat_open(struct disk_t * disk,uint32_t firstSector);
struct file_t* file_open(struct volume_t* pvolume, const char* file_name);
int file_close(struct file_t* stream);
size_t file_read(void *ptr, size_t size, size_t nmemb, struct file_t *stream);
int32_t file_seek(struct file_t* stream, int32_t offset, int whence);
int fat_close(struct volume_t* pvolume);

struct dir_t {
    int entries_count;
    int index;
    struct dir_entry_t * entries;
};
struct dir_t* dir_open(struct volume_t* pvolume, const char* dir_path);
int dir_read(struct dir_t* pdir, struct dir_entry_t* pentry);
int dir_close(struct dir_t* pdir);

#endif
