/*  Copyright 2021-2023 Peter Hyman, pete@peterhyman.com

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <https://www.gnu.org/licenses/>.
*/

/* ps2lrz - poke size to byte offset 6 of lrzip lrz files
   Will check first if encrypted. Can't poke size there.
   Will check if there is a size there. If so, stop unless -f is used.

   Why? Because if lrzip gets input from STDIN or writes to STDOUT
   it does not store uncompressed file size. It will store a zero.
   When performing lrzip -i, compression ratios cannot be computed.
   By poking file size post compression, usable info is attainable.

   ps2lrz -s uncompressed file size -f force overwrite -i show info file \

   Get uncompressed file size from command line.
   convert it to little endian
   write 8 bytes starting at offset 6
   done
 */

#define _GNU_SOURCE
#define OLD_MAGIC_LEN 24
#define MAGICLEN8 18
#define MAGICLEN 20
#define MAGIC_HEADER 6
#define SIZESTART 6
#define SIZELEN   8
#define LRZVERMAJ 4
#define LRZVERMIN 5
#define FILTEROFF 1
#define ENCRYPT  22
#define ENCRYPT8 15
#define COMMENT_LENGTH 64

/* from Lzma2Dec.c, decode dictionary */
#define LZMA2_DIC_SIZE_FROM_PROP(p)	(p == 40 ? 0xFFFFFFFF : (((u_int32_t)2 | ((p) & 1)) << ((p) / 2 + 11)))
/* bzip3, return actual block size */
#define BZIP3_BLOCK_SIZE_FROM_PROP(p)	(p == 8 ? 0x1FFFFFFF : (((u_int32_t)2 | ((p) & 1)) << ((p) / 2 + 24)))
const char * hashes[] = {
	"CRC",
	"MD5",
	"RIPEMD",
	"SHA 256",
	"SHA 384",
	"SHA 512",
	"SHA3 256",
	"SHA3 512",
	"SHAKE128_16",
	"SHAKE 128_32",
	"SHAKE 128_64",
	"SHAKE 256_8",
	"SHAKE 256_32",
	"SHAKE 256_64",
};
const char * encryption[] = {
	"NONE",
	"AES 128",
	"AES 256",
};

/* lrzip-next magic header 8 the same for first 14 bytes
 * byte 15 is hash type 
 * byte 16 is encrypt 1-2
 * byte 17 is filter
 * byte 18 is lzma2 dictionary encoded
 */


#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <endian.h>
#include <unistd.h>
#include <stdbool.h>
#include <locale.h>
#include <inttypes.h>

void usage()
{
	fprintf(stdout,"Usage: ps2lrz [-s] [-f] [-i] filename\n");
	fprintf(stdout,"       ps2lrz [-h | -?]\n");
	fprintf(stdout,"  -s   size in bytes.\n");
	fprintf(stdout,"  -f   force overwrite of file size. CAUTION!!\n");
	fprintf(stdout,"  -i   show file info and exit. -i is optional if only filename given.\n");
	fprintf(stdout,"  -h|? show this message\n");
}

char *filterstring(unsigned char magic, int *deltaval)
{

	unsigned char filt = magic & 7;
	switch (filt)
	{
		case 0: return "None";
			break;;
		case 1: return "x86";
			break;;
		case 2: return "ARM";
			break;;
		case 3: return "ARMT";
			break;;
		case 4: return "PPC";
			break;;
		case 5: return "SPARC";
			break;
		case 6: return "IA64";
			break;
		case 7: *deltaval = magic >> 3;
			if (*deltaval <= 16)
				*deltaval+=1;
			else
				(*deltaval-16+1)*16;
			return "Delta";
			break;
		default:
			return "WTF?";
			break;
	}
}

static bool read_magic(FILE *fd, char *magic, char *comment)
{
	int bytes_to_read;			// simplify reading of magic
	int br;

	memset(magic, 0, OLD_MAGIC_LEN);
	memset(comment, 0, COMMENT_LENGTH+1);
	/* Initially read only file type and version */
	br=fread(&magic[0], 1, MAGIC_HEADER, fd);
	if (br != MAGIC_HEADER) {
		fprintf(stderr, "Failed to read initial magic header\n");
		return false;
	}

	if (strncmp(magic, "LRZI", 4)) {
		fprintf(stderr, "Not an lrzip file\n");
		return false;
	}

	if (magic[4] == 0) {
		if (magic[5] < 8)		/* old magic */
			bytes_to_read = OLD_MAGIC_LEN;
		else if (magic[5] == 8) 	/* 0.8 file */
			bytes_to_read = MAGICLEN8;
		else				/* ASSUME current version */
			bytes_to_read = MAGICLEN;

		br=fread(&magic[6], 1, bytes_to_read - MAGIC_HEADER, fd);
		if (br != bytes_to_read - MAGIC_HEADER) { 
			fprintf(stderr, "Failed to read magic header\n");
			return false;
		}
		if (magic[5] >=9 && magic[19]) {	/* get comment if any */
			br=fread(&comment[0], 1, magic[19], fd);
			if (br != magic[19]) {
				fprintf(stderr, "Error reading comment\n");
				return false;
			}
		}

	}

	return true;
}

int main( int argc, char *argv[])
{

	unsigned char magic[OLD_MAGIC_LEN+1];
	u_int64_t le_filesize, exp_filesize=0, stored_filesize;
	FILE *fp=NULL;
	char *endptr, *filename=NULL, o_mode[3]={'\0','\0','\0'};	/* filename for readability */
	int opt, filter_offset, i, exitcode=0, major, minor;
	bool isencrypt, force, info, changesize;
	char filter[7];
	char comment[COMMENT_LENGTH+1];
	int deltaval=0;

	isencrypt=force=info=changesize=false;

	setlocale(LC_ALL,"");

	while ((opt=getopt(argc, argv, "s:fi:")) != -1)
	{
		switch(opt)
		{
			case 'i':
				info=true;
				filename=optarg;
				if (!filename) {
					fprintf(stderr,"No filename provided\n");
					exitcode=1;
				}
				break;;
			case 'f':
				force=true;
				break;;
			case 's':
				changesize=true;
				exp_filesize=strtoull(optarg,&endptr,10);
				if (exp_filesize==0)
				{
					fprintf(stderr,"Invalid filesize. Exiting...\n");
					exitcode=2;
				}
				break;;
			case 'h':
			case '?':
			default :
				usage();
				exitcode=-1;
				break;;
		}
	}

	if (argc==1) {
		fprintf(stderr, "Must enter [option] filename. Exiting...\n");
		usage();
		exitcode=-1;
	}

	if (force==true && changesize==false) {
		fprintf(stderr, "Cannot use -f without -s. Exiting...\n");
		usage();
		exitcode=-1;
	}

	if (exitcode)
		goto exitprg;

	if (optind == 1)
		info=true;

	/* open file, seek to beginning, get magic header */
	if (!filename)
		filename = argv[optind];
	/* if in info mode, open read only which will work regardless of user rights */
	o_mode[0]='r';
	if (!info)
		o_mode[1]='+';

	if (!(fp = fopen(filename,o_mode)))
	{
		fprintf(stderr,"File %s cannot be opened. Exiting...\n", filename);
		exitcode=4;
		goto exitprg;
	}

	
	if (fseek(fp,0L,SEEK_SET))
	{
		fprintf(stderr,"Error seeking to BOF of %s. Exiting...\n", filename);
		exitcode=5;
		goto exitprg;
	}

	if (!read_magic(fp, magic, comment)) {
		exitcode=6;
		goto exitprg;
	}
		
	major=(magic[LRZVERMAJ]);
	minor=(magic[LRZVERMIN]);

	unsigned char d, lc, lp, pb;
	u_int32_t ds, *dsptr;

	/* filter offset is for lrzip version 7. version 6 has no filtering */
	switch (minor)
	{
		case 6:
			isencrypt=magic[ENCRYPT];
			filter_offset = 0;
			break;;
		case 7: isencrypt=magic[ENCRYPT+1];
			filter_offset = 1;
			break;;
		case 8: 
		case 9:
		case 10:
			isencrypt=magic[ENCRYPT8];
			break;;
	}

	/* get stored filesize */
	if (!isencrypt)
		memcpy(&stored_filesize, &magic[SIZESTART], SIZELEN);
	else
		stored_filesize=0;

	if (info==true)
	{
		// common header elements
		fprintf(stdout,"%s is an lrzip version %d.%d file\n",filename,major,minor);
		if (!isencrypt)
			fprintf(stdout,"%s is not encrypted\n",filename);
		else
			fprintf(stdout,"%s is %s encrypted\n",filename, encryption[isencrypt]);

		fprintf(stdout,"%s uncompressed file size is ",filename);
		if (!isencrypt)
			fprintf(stdout,"%'"PRIu64" bytes\n", stored_filesize);
		else
			fprintf(stdout,"not known because file is encrypted\n");
		fprintf(stdout,"Dumping magic header %d bytes\n", (minor<8?OLD_MAGIC_LEN:
				       (minor==8?MAGICLEN8:MAGICLEN)));
		fprintf(stdout,"Byte Offset      Description/Content\n");
		fprintf(stdout,"===========      ===================\n");
		fprintf(stdout,"Magic Bytes 0-3: ");
		for (i=0;i<4;i++)
			fprintf(stdout,"%02hhX ",magic[i]);
		for (i=0;i<4;i++)
			fprintf(stdout,"%c",magic[i]);
		fprintf(stdout,"\n");
		fprintf(stdout,"Bytes 4-5:       LRZIP Major, Minor version: %02hhX, %02hhx\n",magic[4],magic[5]);
		int j=SIZESTART;	// for encryption offsets
		if (!isencrypt)
			fprintf(stdout,"Bytes 6-13:      LRZIP Uncompressed Size bytes: ");
		else
		{
			fprintf(stdout,"Bytes 6-7:       Encryption Hash Loops: %02hhX %02hhX = %llu\n",
					magic[6], magic[7], ((u_int64_t) magic[7] << (u_int64_t) magic[6]));
			fprintf(stdout,"Bytes 8-13,      Encryption Salt: ");
			j+=2;
		}
		for (i=j;i<SIZESTART+SIZELEN;i++)
			fprintf(stdout,"%02hhX ",magic[i]);
		fprintf(stdout,"\n");
		if (minor < 8)
		{
			fprintf(stdout,"Bytes 14 and 15: unused\n");
			if (minor==7)
			{
				strcpy(filter,filterstring(magic[16], &deltaval));
				fprintf(stdout,"Byte  16:        LRZIP Filter %hhX - %s", magic[16], filter);
				if (deltaval)
					fprintf(stdout," Offset = %d", deltaval);
				fprintf(stdout,"\n");
			}

			if (magic[16+filter_offset])
			{
				// decode lzma
				fprintf(stdout,"Bytes %2d-%2d:     LZMA Properties Bytes; ",16+filter_offset,20+filter_offset);
				for (i=0;i<5;i++)
					fprintf(stdout,"%02hhX ",magic[16+i+filter_offset]);
				/* from LzmaDec.c Igor Pavlov */
				d=magic[16+filter_offset];
				lc=(unsigned char) (d % 9);
				d /= 9;
				pb=(unsigned char) (d / 5);
				lp=(unsigned char) (d % 5);
				dsptr=(u_int32_t *) &magic[17+filter_offset];
				ds=le32toh(*dsptr);
				fprintf(stdout,"lc=%d, lp=%d, pb=%d, Dictionary Size=%'"PRIu32"", lc,lp,pb,ds);
			}
			else
				fprintf(stdout,"Bytes %2d-%2d:     unused. Not an LZMA compressed archive",16+filter_offset, 20+filter_offset);
			fprintf(stdout,"\n");
			fprintf(stdout,"Byte  %d:        Hash Sum at EOF: %s\n",21+filter_offset,hashes[magic[21+filter_offset]]);
			fprintf(stdout,"Byte  %d:        File is encrypted: %s\n",ENCRYPT+filter_offset,encryption[magic[ENCRYPT+filter_offset]]);
			if (major==0 && minor==6)
				fprintf(stdout,"Byte  23:        unused\n");
			exitcode=0;
		}
		else
		{
			/* lrzip-mext 8 or 9+ */
			fprintf(stdout,"Byte  14:        Hash Sum at EOF: %s\n",hashes[magic[14]]);
			fprintf(stdout,"Byte  15:        File is encrypted: %s\n",encryption[magic[ENCRYPT8]]);
			strcpy(filter,filterstring(magic[16], &deltaval));
			fprintf(stdout,"Byte  16:        LRZIP Filter %hhX - %s", magic[16], filter);
			if (deltaval)
				fprintf(stdout," Offset = %d", deltaval);
			fprintf(stdout,"\n");
			if (magic[17] > 0 && magic[17] <= 40)
			{
				// decode lzma
				ds=LZMA2_DIC_SIZE_FROM_PROP(magic[17]);
				fprintf(stdout,"Byte  17:        LZMA Dictionary Size Byte %02X ", magic[17]);
				/* from LzmaDec.c Igor Pavlov */
				fprintf(stdout,"lc=%d, lp=%d, pb=%d, Dictionary Size=%'"PRIu32"\n", 3, 0, 2,ds);
			}
			else if ((magic[17] & 0b11110000) == 0b11110000)	// bzip3
			{
				int b3bs;
				u_int32_t abs;
				b3bs = (magic[17] & 0b00001111);
				abs = BZIP3_BLOCK_SIZE_FROM_PROP(b3bs);
				fprintf(stdout,"Byte  17:        BZIP3 Compression and Block Size Size Byte 0x%02hhX -- BZIP3 Block Size: %d, %'"PRIu32"\n", magic[17], b3bs, abs);
			}
			else if (magic[17] & 0b10000000)	// zpaq
			{
				int cl, bs;
				bs = magic[17] & 0b00001111;	// low order bits are block size
				cl = (magic[17] & 0b01110000) >> 4;		// divide by 16
				fprintf(stdout,"Byte  17:        ZPAQ Compression and Block Size Size Byte 0x%02hhX -- ZPAQ Level: %d, Block Size: %d\n", magic[17], cl, bs);
			}
			else
				fprintf(stdout,"Byte  17:        unused. Not an LZMA, BZIP3, or ZPAQ  compressed archive\n");
			if (minor > 8) {
				/* print compression and comment for version 0.9+ */
				int lrzc, rzipc;
				lrzc = magic[18] & 0b00001111;
				rzipc = magic[18] >> 4;
				fprintf(stdout,"Byte  18:        Rzip / Lrzip-next Compression Levels %d / %d\n", rzipc, lrzc);
				if (magic[19])			// show archive comment or not
					fprintf(stdout,"Byte  19:        Archive Comment: Length: %d, %s\n", magic[19], comment);
				else
					fprintf(stdout,"Byte  19:        No Archive Comment stored\n");
			}

			exitcode=0;
		}
		goto exitprg;
	}

	/* is encrypted? can't process because encryption has is in place of file size (for now) */
	if (isencrypt)
	{
		fprintf(stderr,"File is encrypted. Cannot poke size. Exiting...\n");
		exitcode=7;
		goto exitprg;
	}

	/* now set _filesize from argv in little endian */
	le_filesize=htole64(exp_filesize);

	/* are we trying to set same size as stored? */
	if (stored_filesize == le_filesize)
	{
		fprintf(stderr,"Expected filesize %'"PRIu64" already stored in file %s. Exiting...\n",exp_filesize,filename);
		exitcode=8;
		goto exitprg;
	}

	/* is any size already stored? */
	if(stored_filesize)
	{
		/* size is stored in little endian */
		fprintf(stderr,"File size %'"PRIu64" already stored. ",le64toh(stored_filesize));
		if (force == false)
		{
			fprintf(stderr,"Exiting...\n");
			exitcode=9;
			goto exitprg;
		}
		else	/* are we forcing an overwrite? CAREFUL!! */
			fprintf(stderr,"-f selected so will overwrite with %llu. CAUTION!!\n",exp_filesize);
	}

	/* and write the 8 bytes to file header[6] */
	if (fseek(fp,SIZESTART,SEEK_SET))
	{
		fprintf(stderr,"Error seeking to %d in %s. Exiting...\n",SIZESTART,filename);
		exitcode=10;
	}

	if (!fwrite((void *) &le_filesize,SIZELEN,1,fp))
	{
		fprintf(stderr,"Fatal Error writing _filesize bytes. File may be corrupted. Exiting...\n");
		exitcode=11;
	}

	fprintf(stdout,"New file size is %llu. Magic file size set to: ",exp_filesize);
	unsigned char *p = (u_char *) &le_filesize;	/* for readability */
	for (i=0; i<SIZELEN; i++)
		fprintf(stdout,"%02hhx ",*(p+i));
	fprintf(stdout,"\n");

exitprg:
	if (fp) fclose(fp);
	exit(exitcode);
}
