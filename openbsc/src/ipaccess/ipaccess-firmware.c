/* Routines for parsing an ipacces SDP firmware file */

/* (C) 2009 by Holger Hans Peter Freyther <zecke@selfish.org>
 * All Rights Reserved
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 *
 */

#include <openbsc/debug.h>
#include <openbsc/ipaccess.h>
#include <openbsc/talloc.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define PART_LENGTH 138

static_assert(sizeof(struct sdp_header_entry) == 138, right_entry);
static_assert(sizeof(struct sdp_firmware) == 160, _right_header_length);

/* more magic, the second "int" in the header */
static char more_magic[] = { 0x10, 0x02 };

int ipaccess_analyze_file(int fd, const unsigned int st_size, const unsigned int base_offset, struct llist_head *list)
{
	struct sdp_firmware *firmware_header = 0;
	struct sdp_header *header;
	char buf[4096];
	int rc, i;

	rc = read(fd, buf, sizeof(*firmware_header));
	if (rc < 0) {
		perror("Can not read header start.");
		return -1;
	}

	firmware_header = (struct sdp_firmware *) &buf[0];
	if (strncmp(firmware_header->magic, " SDP", 4) != 0) {
		fprintf(stderr, "Wrong magic.\n");
		return -1;
	}

	if (memcmp(firmware_header->more_magic, more_magic, 2) != 0) {
		fprintf(stderr, "Wrong more magic. Got: 0x%x %x %x %x\n",
			firmware_header->more_magic[0] & 0xff, firmware_header->more_magic[1] & 0xff,
			firmware_header->more_magic[2] & 0xff, firmware_header->more_magic[3] & 0xff);
		return -1;
	}


	if (!firmware_header)
		return -1;

	if (ntohl(firmware_header->file_length) != st_size) {
		fprintf(stderr, "The filesize and the header do not match.\n");
		return -1;
	}

	/* add the firmware */
	header = talloc_zero(list, struct sdp_header);
	header->firmware_info = *firmware_header;
	INIT_LLIST_HEAD(&header->header_list);
	llist_add(&header->entry, list);

	/* this semantic appears to be only the case for 0x0000 */
	if (firmware_header->more_more_magic != 0)
		return -1;

	if (ntohs(firmware_header->part_length) % PART_LENGTH != 0) {
		fprintf(stderr, "The part length seems to be wrong.\n");
		return -1;
	}

	/* look into each firmware now */
	for (i = 0; i < ntohs(firmware_header->part_length) / PART_LENGTH; ++i) {
		struct sdp_header_entry entry;
		struct sdp_header_item *header_entry;
		unsigned int offset = base_offset + sizeof(struct sdp_firmware);
		offset += i * 138;

		if (lseek(fd, offset, SEEK_SET) != offset) {
			fprintf(stderr, "Can not seek to the offset: %u.\n", offset);
			return -1;
		}

		rc = read(fd, &entry, sizeof(entry));
		if (rc != sizeof(entry)) {
			fprintf(stderr, "Can not read the header entry.\n");
			return -1;
		}

		/* now we need to find the SDP file... */
		offset = ntohl(entry.start) + 4 + base_offset;
		if (lseek(fd, offset, SEEK_SET) != offset) {
			perror("can't seek to sdp");
			return -1;
		}

		header_entry = talloc_zero(header,  struct sdp_header_item);
		header_entry->header_entry = entry;
		llist_add(&header_entry->entry, &header->header_list);

		ipaccess_analyze_file(fd, ntohl(entry.length), offset, list);
	}

	return 0;
}

