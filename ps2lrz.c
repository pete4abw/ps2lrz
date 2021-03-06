/*  Copyright 2021 Peter Hyman, pete@peterhyman.com

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
#define MAGICLEN 24
#define SIZESTART 6
#define SIZELEN   8
#define LRZVERMAJ 4
#define LRZVERMIN 5
#define FILTEROFF 1
#define ENCRYPT  22
#define MAGICLEN8 18
#define ENCRYPT8 15
/* from Lzma2Dec.c, decode dictionary */
#define LZMA2_DIC_SIZE_FROM_PROP(p) (p == 40 ? 0xFFFFFFFF : (((unsigned int)2 | ((p) & 1)) << ((p) / 2 + 11)))

/* lrzip-next magic header 8 the same for first 14 bytes
 * byte 15 is md5 flag
 * byte 16 is encrypt flag
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

void usage()
{
	fprintf(stdout,"Usage: ps2lrz -s [-f] [-i] filename\n");
	fprintf(stdout,"       ps2lrz [-h | -?]\n");
	fprintf(stdout,"  -s   size in bytes.\n");
	fprintf(stdout,"  -f   force overwrite of file size. CAUTION!!\n");
	fprintf(stdout,"  -i   show file info and exit.\n");
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


int main( int argc, char *argv[])
{
	unsigned char magic[MAGICLEN+1];
	u_int64_t le_filesize, exp_filesize, stored_filesize;
	FILE *fp=NULL;
	char *endptr, *filename, o_mode[3]={'\0','\0','\0'};	/* filename for readability */
	int opt, filter_offset, i, exitcode=0, major, minor;
	bool isencrypt=false, force=false, info=false;
	char filter[7];
	int deltaval=0;

	while ((opt=getopt(argc, argv, "s:fi")) != -1)
	{
		switch(opt)
		{
			case 'i':
				info=true;
				if (argc == 3)
					fprintf(stdout,"Showing file info only\n");
				else
				{
					fprintf(stderr,"Info option cannot be used with other options. Exiting...\n");
					exitcode=1;
				}
				break;;
			case 'f':
				force=true;
				break;;
			case 's':
				exp_filesize=strtoull(optarg,&endptr,10);
				if (exp_filesize==0)
				{
					fprintf(stderr,"Invalid filesize. Exiting...\n");
					exitcode=2;
				}
				break;;
			case 'h':
			case '?':
				usage();
				exitcode=-1;
				break;;
			default:
				usage();
				exitcode=3;
				break;;
		}
	}
	/* no options */
	if (argc==1)
	{
		usage();
		exitcode=-1;
	}

	if (exitcode)
		goto exitprg;

	/* open file, seek to beginning, get magic header */
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

	// Read old magic length even if future version. We will still only write to size position
	if (!fgets(&magic[0],MAGICLEN+1,fp))
	{
		fprintf(stderr,"Error reading magic. Exiting...\n");
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
		case 8: isencrypt=magic[ENCRYPT8];
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
		fprintf(stdout,"%s %s encrypted\n",filename,(isencrypt==0?"is not":"is"));
		fprintf(stdout,"%s uncompressed file size is ",filename);
		if (!isencrypt)
			fprintf(stdout,"%llu bytes\n", stored_filesize);
		else
			fprintf(stdout,"not known because file is encrypted\n");
		fprintf(stdout,"Dumping magic header %d bytes\n", minor<8?MAGICLEN: MAGICLEN8);
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
				fprintf(stdout,"lc=%d, lp=%d, pb=%d, Dictionary Size=%lu", lc,lp,pb,ds);
			}
			else
				fprintf(stdout,"Bytes %2d-%2d:     unused. Not an LZMA compressed archive",16+filter_offset, 20+filter_offset);
			fprintf(stdout,"\n");
			fprintf(stdout,"Byte  %d:        MD5 Sum at EOF: %s\n",21+filter_offset,(magic[21+filter_offset]==1?"yes":"no"));
			fprintf(stdout,"Byte  %d:        File is encrypted: %s\n",ENCRYPT+filter_offset,(magic[ENCRYPT+filter_offset]==1?"yes":"no"));
			if (major==0 && minor==6)
				fprintf(stdout,"Byte  23:        unused\n");
			exitcode=0;
		}
		else
		{
			/* lrzip-mext8 */
			fprintf(stdout,"Byte  14:        MD5 Sum at EOF: %s\n",(magic[14]>=1?"yes":"no"));
			fprintf(stdout,"Byte  15:        File is encrypted: %s\n",(magic[ENCRYPT8]==1?"yes":"no"));
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
				fprintf(stdout,"lc=%d, lp=%d, pb=%d, Dictionary Size=%lu", 3, 0, 2,ds);
			}
			else if (magic[17] & 0b10000000)	// zpaq
			{
				int cl, bs;
				bs = magic[17] & 0b00001111;	// low order bits are block size
				cl = (magic[17] & 0b01110000) >> 4;		// divide by 16
				fprintf(stdout,"Byte  17:        ZPAQ Compression and Block Size Size Byte %02X -- ZPAQ Level: %d, Block Size: %d\n", magic[17], cl, bs);
			}
			else
				fprintf(stdout,"Byte  17:        unused. Not an LZMA compressed archive");
			fprintf(stdout,"\n");
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
		fprintf(stderr,"Expected filesize %llu already stored in file %s. Exiting...\n",exp_filesize,filename);
		exitcode=8;
		goto exitprg;
	}

	/* is any size already stored? */
	if(stored_filesize)
	{
		/* size is stored in little endian */
		fprintf(stderr,"File size %llu already stored. ",le64toh(stored_filesize));
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
