#define TEST_RNDTEST
//#define DEBUG_RNDTEST

#include <stdio.h>
#include <string.h>
#include <gd.h>
#include <gdfontmb.h>
#include <fcntl.h>
#include <errno.h>

#ifdef DEBUG_RNDTEST
#define DPRINTF(fmt, ...) \
do { fprintf(stderr, "rndtest: " fmt , ## __VA_ARGS__); } while (0)
#else
#define DPRINTF(fmt, ...) \
do {} while(0)
#endif

int readFromFile(char *filename, unsigned char *freq)
{
	int             fd, rc, i;
        unsigned char   buf[4096] = { 0 };

        fd = open(filename, O_RDONLY);
        if (fd < 0) {
                DPRINTF("Read from file error %d (%s)\n", errno, strerror(errno));
                return 0;
        }

	while ((rc = read(fd, buf, sizeof(buf)) > 0)) {
		for (i = 0; i < sizeof(buf); i++)
			freq[ buf[i] ]++;
	}

	close(fd);
	return 256;
}

int readData(unsigned char *cfreq)
{
	char in[256];
	int c, freq, num = 0;

	while (!feof(stdin)) {
		fgets(in, sizeof(in), stdin);

		sscanf(in, "data[%d] => %d\n", &c, &freq);
		cfreq[c] = freq;
		num++;
		memset(in, 0, sizeof(in));
	}

	return num - 1;
}

int generateGraphFromValues(char *filename, unsigned char *freq, int num, int showLegend, int varColors)
{
	int i, ii, col, red, ni;
	int maxVal = 0, len = 0, imageX;
	float percent;
	int startX = 30;
	int legendX = 33;
	gdImagePtr im;
	FILE *fp;

	for (i = 0; i < num; i++) {
		if (freq[i] > maxVal)
			maxVal = freq[i];
	}

	if (showLegend)
		imageX = 1024 + startX + legendX;
	else {
		startX = 0;
		legendX = 0;
		imageX = 1024;
	}

	im = gdImageCreateTrueColor(imageX, 256);

	red = gdImageColorAllocate(im, 255, 0, 0);
	if (showLegend) {
		for (i = 0; i < 100; i += 10) {
			char s[16];
			len = 255 * ((float)(100 - i) / 100);
			gdImageLine(im, 0, len, imageX, len, red);
			gdImageLine(im, startX - 2, 0, startX - 2, 255, red);
			snprintf(s, 16, "%2d%%", i);
			gdImageString(im, gdFontMediumBold, 5, len - 12, s, red);
		}
	}

	ni = startX;
	for (i = 0; i < num; i++) {
		percent = freq[i] / ((float)maxVal / 100);
		len = 256 * ((100 - percent) / 100);
		DPRINTF("Data[%d] freq = %d (%.2f%%, len = %d)\n", i, freq[i], percent, len);

		if (varColors) {
			if (percent > 90.0)
				col = gdImageColorAllocate(im, 0, 0, 255);
			else
			if (percent > 50.0)
				col = gdImageColorAllocate(im, 0, 255, 255);
			else
			if (percent > 25.0)
				col = gdImageColorAllocate(im, 255, 255, 0);
			else
				col = gdImageColorAllocate(im, 255, 0, 0);
		}
		else
			//col = gdImageColorAllocate(im, 256 - i, 0, i);
			col = gdImageColorAllocate(im, 255 - i, 255 - i, i);

		if ((i % 10 == 0) && (showLegend)) {
			char s[16];

			gdImageLine(im, ni + ii, 0, ni + ii, 255, red);
			snprintf(s, 16, "%2d", i);
			gdImageString(im, gdFontMediumBold, ni + ii + 1, 240, s, gdImageColorAllocate(im, 255, 255, 255));
			ni++;
		}

		for (ii = 0; ii < (imageX / 256); ii++) {
			gdImageLine(im, ni + ii, len, ni + ii, 255, col);
			ni++;
		}
	}

	fp = fopen(filename, "w");
	gdImagePng(im, fp);
	fclose(fp);
	gdImageDestroy(im);

	return 0;
}

#ifdef TEST_RNDTEST
int main(int argc, char *argv[])
{
	int num = 0;
	unsigned char freq[256] = { 0 };

	if (argc < 3) {
		printf("Syntax: %s filename outputFileName\n", argv[0]);
		return 1;
	}

	num = readFromFile(argv[1], freq);
	if (generateGraphFromValues(argv[2], freq, num, 1, 0) == 0)
		printf("File %s generated\n", argv[2]);
	return 0;
}
#endif
