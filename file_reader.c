#include "file_reader.h"

int is_entry_valid(const struct dir_entry_t* e) {
    return !((uint8_t)e->name[0] == 0x00 || (uint8_t)e->name[0] == 0xE5);
}

struct disk_t* disk_open_from_file(const char* volume_file_name) {
    if(!volume_file_name) {
        errno = EFAULT;
        return NULL;
    }

    FILE * file = fopen(volume_file_name, "rb");
    if(!file) {
        errno =ENOENT;
        return NULL;
    }

    fseek(file, 0, SEEK_END);
    long  file_size = ftell(file);
    if(file_size <= 0) {
        fclose(file);
        errno = EFAULT;                         //may be bad
        return NULL;
    }

    struct disk_t * disk = calloc(1, sizeof(struct disk_t));
    if(!disk) {
        fclose(file);
        errno = ENOMEM;
        return NULL;
    }

    fseek(file, 0, SEEK_SET);

    disk->file = file;

    return disk;
}

int disk_read(struct disk_t *pdisk, int32_t first_sector, void *buffer, int32_t sectors_to_read) {
    if (!pdisk|| first_sector < 0 || !buffer  || sectors_to_read <= 0)  return -1;

    fseek(pdisk->file, first_sector * SECTOR_SIZE, SEEK_SET);

    if ((int32_t)fread(buffer, SECTOR_SIZE, sectors_to_read, pdisk->file) != sectors_to_read)   return -1;

    return sectors_to_read;
}

uint16_t fat_get_next_cluster(struct volume_t* volume, uint16_t current_cluster) {
    if (!volume) {
        errno = EFAULT;
        return 0xFFFF; // invlid
    }

    const uint32_t offset = current_cluster * sizeof(uint16_t);
    const uint32_t fat_sector = volume->boot_sec.size_of_reserved_area + (offset / volume->boot_sec.bytes_per_sector);
    const uint32_t sector_offset = offset % volume->boot_sec.bytes_per_sector;

    uint8_t sector_buf[SECTOR_SIZE];
    if (disk_read(volume->disk, (int32_t)fat_sector, sector_buf, 1) != 1) {
        errno = EIO;
        return 0xFFFF;
    }

    uint16_t next_cluster = *(uint16_t*)(sector_buf + sector_offset);
    return next_cluster;
}

int disk_close(struct disk_t* pdisk) {
    if(!pdisk) {
        errno =EFAULT;
        return -1;
    }
    fclose(pdisk->file);
    free(pdisk);
    return 0;
}

struct volume_t* fat_open(struct disk_t* pdisk, uint32_t initial_sector) {
    if (!pdisk) {
        errno = EFAULT;
        return NULL;
    }

    struct volume_t* vol_info = calloc(1, sizeof(struct volume_t));
    if (!vol_info) {
        errno = ENOMEM;
        return NULL;
    }
    vol_info->disk = pdisk;

    struct boot_sec bootSec;

    if (disk_read(pdisk, (int32_t)initial_sector, &bootSec, 1) != 1) {
        free(vol_info);
        errno = EINVAL;
        return NULL;
    }


    if (!bootSec.bytes_per_sector || !bootSec.number_of_fats || !bootSec.size_of_reserved_area) {
        free(vol_info);
        errno = EINVAL;
        return NULL;
    }

    uint32_t fat_size_bytes = bootSec.size_of_fat * bootSec.bytes_per_sector;
    uint32_t fat_entry_count = fat_size_bytes / sizeof(uint16_t);

    uint16_t* fat = malloc(fat_size_bytes);
    if (!fat) {
        free(vol_info);
        errno = ENOMEM;
        return NULL;
    }

    uint32_t fat1_sector = bootSec.size_of_reserved_area;
    uint32_t fat2_sector = fat1_sector + bootSec.size_of_fat;

    if (disk_read(pdisk, (int32_t)fat1_sector, fat, bootSec.size_of_fat) != bootSec.size_of_fat) {
        free(fat);
        free(vol_info);
        errno = EINVAL;
        return NULL;
    }

    uint16_t buffer[SECTOR_SIZE / sizeof(uint16_t)];
    uint32_t entries_per_buffer = SECTOR_SIZE / sizeof(uint16_t);

    for (uint32_t offset = 0; offset < fat_size_bytes; offset += SECTOR_SIZE) {
        uint32_t sector_offset = offset / bootSec.bytes_per_sector;
        uint32_t entries_to_check = (offset + SECTOR_SIZE <= fat_size_bytes) ? entries_per_buffer : (fat_size_bytes - offset) / sizeof(uint16_t);

        uint32_t sectors_to_read = (entries_to_check * sizeof(uint16_t) + bootSec.bytes_per_sector - 1) / bootSec.bytes_per_sector;

        if (disk_read(pdisk, (int32_t)(fat2_sector + sector_offset), buffer, (int32_t)sectors_to_read) != (int)sectors_to_read) {
            free(fat);
            free(vol_info);
            errno = EINVAL;
            return NULL;
        }
        for (uint32_t i = 0; i < entries_to_check; i++) {
            uint32_t fat_index = offset / sizeof(uint16_t) + i;
            if (fat_index < fat_entry_count && fat[fat_index] != buffer[i]) {
                free(fat);
                free(vol_info);
                errno = EINVAL;
                return NULL;
            }
        }
    }

    vol_info->fat = fat;

    uint32_t root_dir_entries = bootSec.maximum_number_of_files;
    uint32_t entry_size = 32;
    uint32_t root_dir_size = root_dir_entries * entry_size;
    uint32_t root_dir_sectors = (root_dir_size + bootSec.bytes_per_sector - 1) / bootSec.bytes_per_sector;
    uint32_t root_dir_sector = fat2_sector + bootSec.size_of_fat;

    uint8_t* raw_data = malloc(root_dir_size);
    if (!raw_data) {
        free(fat);
        free(vol_info);
        errno = ENOMEM;
        return NULL;
    }

    if (disk_read(pdisk, (int32_t)root_dir_sector, raw_data, (int32_t)root_dir_sectors) != (int)root_dir_sectors) {
        free(raw_data);
        free(fat);
        free(vol_info);
        errno = EINVAL;
        return NULL;
    }

    struct dir_entry_t* root_entries = calloc(root_dir_entries, sizeof(struct dir_entry_t));
    if (!root_entries) {
        free(raw_data);
        free(fat);
        free(vol_info);
        errno = ENOMEM;
        return NULL;
    }

    for (uint32_t i = 0; i < root_dir_entries; i++) {
        uint8_t* entry = raw_data + (i * entry_size);

        uint8_t name_length = 0;
        for (uint8_t j = 0; j < 8 && entry[j] != ' '; j++) {
            root_entries[i].name[name_length++] = (char)entry[j];
        }
        root_entries[i].name[name_length] = '\0';

        uint8_t ext_length = 0;
        for (uint8_t j = 0; j < 3 && entry[8 + j] != ' '; j++) {
            root_entries[i].ext[ext_length++] = (char)entry[8 + j];
        }
        root_entries[i].ext[ext_length] = '\0';

        root_entries[i].attr = entry[11];
        root_entries[i].first_cluster = *(uint32_t*)&entry[26];
        root_entries[i].size = *(uint32_t*)&entry[28];
    }

    free(raw_data);
    vol_info->root_entries = root_entries;

    vol_info->offset = (root_dir_sector + root_dir_sectors) * bootSec.bytes_per_sector;

    vol_info->boot_sec = bootSec;
    return vol_info;
}

int fat_close(struct volume_t *pvolume) {
    if (!pvolume) {
        errno = EFAULT;
        return -1;
    }
    free(pvolume->root_entries);
    free(pvolume->fat);
    free(pvolume);
    return 0;
}

int32_t file_seek(struct file_t *stream, int32_t offset, int whence) {
    if (!stream) {
        errno = EFAULT;
        return -1;
    }

    if(whence == SEEK_CUR) {
        if (stream->position + offset > (int)stream->size) {
            errno = ENXIO;
            return -1;
        }
        stream->position += offset;
    } else if (whence == SEEK_SET) {
        if (offset > (int)stream->size) {
            errno = ENXIO;
            return -1;
        }
        stream->position = offset;
    } else if (whence == SEEK_END) {
        if ((int)stream->size + offset < 0 || offset > 0) {
            errno = ENXIO;
            return -1;
        }
        stream->position = (int)stream->size + offset;
    } else {errno = EINVAL; return -1;}

    return stream->position;
}

struct file_t *file_open(struct volume_t *volume, const char *filename) {
    if (!volume || !filename || filename[0] == '\0') {
        errno = EFAULT;
        return NULL;
    }

    struct file_t * file = NULL;
    uint16_t * clusters = NULL;
    struct dir_entry_t *found = NULL;

    for (int i = 0; i < volume->boot_sec.maximum_number_of_files; i++) {
        struct dir_entry_t *entry = &volume->root_entries[i];

        if(!is_entry_valid(entry)) continue;

        char name_buf[13] = {0};
        strcpy(name_buf, entry->name);

        if (entry->ext[0] && entry->ext[0] != ' ') {
            strcat(name_buf, ".");
            strcat(name_buf, entry->ext);
        }

        char name_buf_lower[13], filename_lower[13];
        for (int j = 0; j < 13; j++) {
            name_buf_lower[j] = (char)tolower((unsigned char)name_buf[j]);
            filename_lower[j] = (char)tolower((unsigned char)filename[j]);
        }

        if (strcmp(name_buf_lower, filename_lower) == 0) {
            if (entry->attr & FAT_ATTR_DIRECTORY || entry->attr & FAT_ATTR_VOLUME) {
                errno = EISDIR;
                return NULL;
            }
            found = entry;
            break;
        }
    }

    if (!found) {
        errno = ENOENT;
        return NULL;
    }

    uint16_t first_cluster = found->first_cluster;
    uint16_t next = first_cluster;
    int count = 0;

    while (next < 0xFFF8) {
        count++;
        next = fat_get_next_cluster(volume, next);
    }

    clusters = calloc(count, sizeof(uint16_t));
    if (!clusters) {
        errno = ENOMEM;
        return NULL;
    }

    next = first_cluster;
    uint32_t base_sector = volume->offset / volume->boot_sec.bytes_per_sector;
    uint8_t sectors_per_cluster = volume->boot_sec.sectors_per_clusters;

    for (int i = 0; i < count; i++) {
        clusters[i] = base_sector + (next - 2) * sectors_per_cluster;
        next = fat_get_next_cluster(volume, next);
    }

    file = calloc(1, sizeof(struct file_t));
    if (!file) {
        free(clusters);
        errno = ENOMEM;
        return NULL;
    }

    file->cluster_list = clusters;
    file->volume = volume;
    file->position = 0;
    file->cluster_count = count;
    file->size = found->size;

    strcpy(file->name, found->name);
    strcpy(file->ext, found->ext);

    return file;
}

size_t file_read(void *ptr, size_t size, size_t nmemb, struct file_t *stream) {
    if (!ptr || !stream) {
        errno = EFAULT;
        return -1;
    }

    if (stream->position >= (int32_t)stream->size)   return 0;

    const size_t total_requested = size * nmemb;
    const size_t remaining_file_bytes = stream->size - stream->position;
    const size_t bytes_to_read = total_requested < remaining_file_bytes ? total_requested : remaining_file_bytes;

    if (bytes_to_read == 0) return 0;

    const uint32_t sector_size = stream->volume->boot_sec.bytes_per_sector;
    const uint32_t sectors_per_cluster = stream->volume->boot_sec.sectors_per_clusters;
    const uint32_t cluster_size = sector_size * sectors_per_cluster;

    uint32_t current_cluster = stream->position / cluster_size;
    if (current_cluster >= stream->cluster_count)   return 0;

    uint8_t *output_buffer = (uint8_t *)ptr;
    size_t bytes_remaining = bytes_to_read;
    size_t total_bytes_read = 0;
    uint8_t sector_buffer[SECTOR_SIZE];

    while (bytes_remaining > 0 && current_cluster < stream->cluster_count) {
        uint32_t cluster_offset = stream->position % cluster_size;
        uint32_t sector_in_cluster = cluster_offset / sector_size;
        uint32_t byte_in_sector = cluster_offset % sector_size;
        uint32_t sector_remaining = sector_size - byte_in_sector;
        uint32_t read_size = bytes_remaining < sector_remaining ? bytes_remaining : sector_remaining;

        uint32_t sector_number = stream->cluster_list[current_cluster] + sector_in_cluster;

        if (disk_read(stream->volume->disk, (int)sector_number, sector_buffer, 1) != 1) {
            errno = ERANGE;
            return total_bytes_read > 0 ? total_bytes_read / size : 1;
        }

        memcpy(output_buffer, sector_buffer + byte_in_sector, read_size);

        output_buffer += read_size;
        total_bytes_read += read_size;
        bytes_remaining -= read_size;
        stream->position += (int)read_size;

        if ((stream->position % cluster_size) == 0)  current_cluster++;
    }

    return total_bytes_read / size;
}

int file_close(struct file_t *stream) {
    if (!stream) {
        errno = EFAULT;
        return -1;
    }

    free(stream->cluster_list);
    free(stream);

    return 0;
}

struct dir_t *dir_open(struct volume_t *volume, const char *path) {
    if (!volume || !path) {
        errno = EFAULT;
        return NULL;
    }
    if (path[0] != '\\' || path[1] != '\0') {
        errno = ENOENT;
        return NULL;
    }

    struct dir_t * dir = calloc(1, sizeof(*dir));
    if (!dir) {
        errno = ENOMEM;
        return NULL;
    }

    struct dir_entry_t * entries = NULL;
    int count = 0;

    for (int i = 0; i < volume->boot_sec.maximum_number_of_files; ++i) {
        struct dir_entry_t *entry = &volume->root_entries[i];

        if(!is_entry_valid(entry)) continue;

        struct dir_entry_t * tmp = realloc(entries, (count + 1) * sizeof(*entries));
        if (!tmp) {
            free(entries);
            free(dir);
            errno = ENOMEM;
            return NULL;
        }
        entries = tmp;

        char * tempname = entries[count].name;
        unsigned long n = strlen(entry->name);
        memcpy(tempname, entry->name, n);
        tempname[n] = '\0';
        if (entry->ext[0] != ' ' && entry->ext[0] != '\0') {
            size_t len = n;
            tempname[len++] = '.';
            memcpy(tempname + len, entry->ext, strnlen(entry->ext, 3));
            tempname[len + strnlen(entry->ext, 3)] = '\0';
        }

        entries[count].size = entry->size;
        entries[count].is_directory = (entry->attr & FAT_ATTR_DIRECTORY) != 0;
        entries[count].is_hidden = (entry->attr & FAT_ATTR_HIDDEN) != 0;
        entries[count].is_readonly = (entry->attr & FAT_ATTR_READONLY) != 0;
        entries[count].is_archived = (entry->attr & FAT_ATTR_ARCHIVE) != 0;

        count++;
    }

    dir->entries = entries;
    dir->entries_count = count;
    dir->index = 0;
    return dir;
}

int dir_read(struct dir_t *pdir, struct dir_entry_t *pentry) {
    if(!pdir || !pentry) {
        errno = EFAULT;
        return -1;
    }
    if(pdir->entries_count == pdir->index)    return 1;

    struct dir_entry_t * entry = pdir->entries + pdir->index;
    pentry->is_readonly = entry->is_readonly;
    pentry->is_hidden = entry->is_hidden;
    pentry->is_archived = entry->is_archived;
    pentry->is_system = entry->is_system;
    pentry->is_directory = entry->is_directory;

    strcpy(pentry->name,entry->name);
    pentry->size = entry->size;

    pdir->index += 1;
    return 0;
}

int dir_close(struct dir_t * pdir) {
    if(!pdir) {
        errno = EFAULT;
        return -1;
    }

    free(pdir->entries);
    free(pdir);

    return 0;
}

int main(void) {
    return 0;
}
