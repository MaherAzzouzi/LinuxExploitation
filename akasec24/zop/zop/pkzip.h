#ifndef PKZIP_H
#define PKZIP_H

#include <stdint.h>
#include <stdio.h>
#include <fcntl.h>
#include <string.h>
#include <stdbool.h>
#include <strings.h>
#include <unistd.h>
#include <stdlib.h>
#include <err.h>
#include <sys/types.h>
#include <sys/stat.h>

typedef struct ZIP_CFH{			// central directory file header
	uint16_t	version;
	uint16_t	version_needed;
	uint16_t	flags;
	uint16_t	compression;
	uint16_t	mod_time;
	uint16_t	mod_date;
	uint32_t	crc_checksum_32;
	uint32_t	compressed_size;
	uint32_t	uncompressed_size;
	uint16_t	fname_len;			// filename_len
	uint16_t	extra_feild_len;
	uint16_t	file_comm_len;			// comment length
	uint16_t	disk_start;
	uint16_t	internal_attrs;
	uint32_t	external_attrs;
	uint32_t	local_header;
	char		*filename;
	char		*extra_feild;
	char		*file_comment;
}ZIP_CFH;


typedef struct ZIP_CDR {
	uint16_t	disk_num;
	uint16_t	cd_start;
	uint16_t	disk_ent;
	uint16_t	tot_ent;
	uint32_t	cent_dir_size;
	uint32_t	cd_offset;
	uint16_t	comm_len;
	char		*zip_comment;
}ZIP_CDR;

// local file header
typedef struct ZIP_LFH{
	uint16_t	version;
	uint16_t	flags;
	uint16_t	compression;
	uint16_t	mod_time;
	uint16_t	mod_date;
	uint32_t	crc_checksum_32;
	uint32_t	compressed_size;
	uint32_t	uncompressed_size;
	uint16_t	fname_len;			// filename_len
	uint16_t	extra_feild_len;
	char		*filename;
	char		*extra_feild;
}ZIP_LFH;

typedef struct ZIP_DD {
	uint32_t crc_32;
	uint32_t compressed_size;
	uint32_t uncompressed_size;
} ZIP_DD;

char **extract_zip(char *zip_data, uint64_t data_len);
char* base64_decode(char* cipher, size_t *len);


#endif
