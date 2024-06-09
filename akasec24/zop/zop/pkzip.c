#include "pkzip.h"

uint64_t	extract_bytes(char *src, int size){
	uint64_t dst = 0;
	if (size > 8 || size < 1)
		return (0);
	memcpy(&dst, src, size);
	return (dst);
}

char *parse_lfh(char *local_file_header, ZIP_LFH *lfh){
	uint32_t *ptrs[10] = {
		(uint32_t *)&lfh->version, (uint32_t *)&lfh->flags,(uint32_t *) &lfh->compression,
		(uint32_t *)&lfh->mod_time, (uint32_t *)&lfh->mod_date, (uint32_t *)&lfh->crc_checksum_32,
		(uint32_t *)&lfh->compressed_size, (uint32_t *)&lfh->uncompressed_size,
		(uint32_t *)&lfh->fname_len, (uint32_t *)&lfh->extra_feild_len
	};
	uint8_t ptr_sizes[10] = {
		2, 2, 2, 2, 2, 4, 4, 4, 2, 2
	};
	char **str_ptrs[2] = {
		&lfh->filename, &lfh->extra_feild
	};

	int i = -1;

	while (++i < 10){
		bzero(ptrs[i], ptr_sizes[i]);
		memcpy(ptrs[i], local_file_header, ptr_sizes[i]);
		local_file_header += ptr_sizes[i];
	}
	uint32_t str_sizes[2] = {
		lfh->fname_len, lfh->extra_feild_len
	};
	i = -1;
	while (++i < 2){
		*str_ptrs[i] = NULL;
		if (str_sizes[i] > 1) {
			*str_ptrs[i] = (char *) malloc(str_sizes[i]);
			bzero(*str_ptrs[i], str_sizes[i]);
			strlcpy(*str_ptrs[i], local_file_header, str_sizes[i] + 1);
			local_file_header += str_sizes[i];
		}
	}
	return (local_file_header);
}

char *parse_dd(char *data_desc, ZIP_DD *dd) {
	int		i = -1;
	uint32_t	*ptrs[10] = {
		&dd->crc_32, &dd->compressed_size, &dd->uncompressed_size
	};
	while (++i < 10){
		memcpy(ptrs[i], data_desc, 4);
		data_desc += 4;
	}
	return (data_desc);
}

char *parse_cdr(char *central_directory_record, ZIP_CDR *cdr){
	uint32_t *ptrs[8] = {
		(uint32_t *)&cdr->disk_num, (uint32_t *)&cdr->cd_start, (uint32_t *)&cdr->disk_ent, (uint32_t *)&cdr->tot_ent,
		(uint32_t *)&cdr->cent_dir_size, (uint32_t *)&cdr->cd_offset, (uint32_t *)&cdr->comm_len, (uint32_t *)&cdr->zip_comment
	};
	uint8_t sizes[8] = {
		2, 2, 2, 2, 4, 4, 2
	};
	int i = -1;
	while (++i < 8){
		memcpy(ptrs[i], central_directory_record, sizes[i]);
		central_directory_record += sizes[i];
	}
	if (cdr->comm_len > 0) {
		cdr->zip_comment = (char *) malloc(cdr->comm_len + 1);
		central_directory_record += cdr->comm_len;
	}
	return (central_directory_record);
}

char *parse_cfh(char *central_file_header, ZIP_CFH *cfh){
	uint32_t *ptrs[16] = {
		(uint32_t *)&cfh->version,(uint32_t *) &cfh->version_needed,(uint32_t *) &cfh->flags,(uint32_t *) &cfh->compression,
		(uint32_t *)&cfh->mod_time, (uint32_t *)&cfh->mod_date,(uint32_t *) &cfh->crc_checksum_32,
		(uint32_t *)&cfh->compressed_size, &cfh->uncompressed_size,
		(uint32_t *)&cfh->fname_len,(uint32_t *) &cfh->extra_feild_len, (uint32_t *)&cfh->file_comm_len,
		(uint32_t *)&cfh->disk_start, (uint32_t *)&cfh->internal_attrs, &cfh->external_attrs,
		&cfh->local_header,
	};
	uint8_t ptr_sizes[16] = {
		2, 2, 2, 2, 2, 2, 4, 4, 4, 2, 2, 2, 2, 2, 4, 4
	};

	int i = -1;

	while (++i < 16){
		memcpy(ptrs[i], central_file_header, ptr_sizes[i]);
		central_file_header += ptr_sizes[i];
	}

	char **str_ptrs[3] = {
		&cfh->filename, &cfh->extra_feild, &cfh->file_comment
	};
	uint32_t str_sizes[3] = {
		cfh->fname_len, cfh->extra_feild_len, cfh->file_comm_len
	};

	i = -1;
	while (++i < 3){
		if (str_sizes[i] < 1) {
			continue;
		}
		*(str_ptrs[i]) = (char *) malloc(str_sizes[i] + 1);
		bzero(*(str_ptrs[i]), str_sizes[i]);
		strlcpy(*(str_ptrs[i]), central_file_header, str_sizes[i] + 1);
		central_file_header += str_sizes[i];
	}
	return (central_file_header);
}

// returns the filename back
char *write_file(ZIP_LFH *lfh, char *content){
	char	*filename;
	int	fd;

	filename = malloc(strlen("content/") + lfh->fname_len + 1);
	memcpy(filename, "content/", strlen("content/") + 1);
	memcpy(filename + strlen("content/"), lfh->filename, strlen(lfh->filename));
	fd = open(filename, O_WRONLY | O_CREAT, 0644);
	if (fd < 0){
		printf("%s :%m\n", lfh->filename);
		return (NULL);
	} else {
		write(fd, content, lfh->uncompressed_size);
		close(fd);
	}
	return (filename);
}

void write_symbol(ZIP_CFH *cfh){
	char	*filename;
	char	*symbol_name;
	int	fd;

	filename = malloc(strlen("content/") + cfh->fname_len + 1);
	memcpy(filename, "content/", strlen("content/") + 1);
	memcpy(filename + strlen("content/"), cfh->filename, strlen(cfh->filename));
	if ((cfh->external_attrs | 0xa0000000) == cfh->external_attrs){
		fd = open(filename, O_RDONLY);
		if (fd < 0)
			return;
		symbol_name = malloc(cfh->uncompressed_size + 1);
		read(fd, symbol_name, cfh->uncompressed_size);
		close(fd);
		remove(filename);
		symlink(symbol_name, filename);
		free(symbol_name);
	}
	if ((cfh->external_attrs >> 16 & 0xFFF) != 0) {
		chmod(filename, (cfh->external_attrs >> 16 & 0xFFF));
	}
	free(filename);
}

char **extract_zip(char *zip_data, uint64_t data_len){
	ZIP_LFH		*lfh = (ZIP_LFH *) malloc(sizeof(ZIP_LFH));
	ZIP_CFH		*cfh = (ZIP_CFH *) malloc(sizeof(ZIP_CFH));
	ZIP_DD		*dd = (ZIP_DD *) malloc(sizeof(ZIP_DD));
	ZIP_CDR		*cdr = (ZIP_CDR *) malloc(sizeof(ZIP_CDR));
	char		**files = (char **) malloc(sizeof(char *) * 30);
	int		files_iter = 0;
	uint32_t	signature;
	int		fd;
	char		*zip_ptr = zip_data ;

	bzero(files, sizeof(char *) * 30);
	while (zip_ptr < zip_data + data_len){
		memcpy(&signature, zip_ptr, 4);
		zip_ptr += 4;

		if (signature == 67324752){
			bzero(lfh, sizeof(ZIP_LFH));
			zip_ptr = parse_lfh(zip_ptr, lfh);
			if (files_iter < 30 && lfh->fname_len > 0){
				if (lfh->compression == 0)
					files[files_iter] = write_file(lfh, zip_ptr);
				if (files[files_iter] != NULL)
					files_iter++;
				zip_ptr += lfh->uncompressed_size;
			}
		} else if (signature == 33639248){
			bzero(cfh, sizeof(ZIP_CFH));
			zip_ptr = parse_cfh(zip_ptr, cfh);
			write_symbol(cfh);
			
		} else if (signature == 101010256){
			zip_ptr = parse_cdr(zip_ptr, cdr);
		}
		else {
			errx(1, "Corrupted header byte %zu\n",
					zip_ptr - zip_data);
			exit(EXIT_FAILURE);
		}
	}
	return (files);
}
