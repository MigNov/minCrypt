#define BUFFER_SIZE		(1 << 16)
#define O_LARGEFILE			0x0200000

#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <inttypes.h>
#include <fcntl.h>

float relevance_test(char *filename1, char *filename2, int skip1, int skip2)
{
	unsigned char buf[BUFFER_SIZE] = { 0 }, buf2[BUFFER_SIZE] = { 0 };
	int fd, fd2, rc, rc2;
	uint64_t i = 0, rel = 0, pos = 0, pos2 = 0;
	float relf;

	fd = open(filename1, O_RDONLY | O_LARGEFILE);
	if (fd < 0)
		return 0.0;

	fd2 = open(filename2, O_RDONLY | O_LARGEFILE);
	if (fd2 < 0)
		return 0.0;

	rel = 0;
	while ((rc = read(fd, buf, sizeof(buf))) > 0) {
		rc2 = read(fd2, buf2, sizeof(buf2));

		for (i = 0; i < sizeof(buf); i++)
			if ((rc2 >= i) && (buf[i] == buf2[i]))
				rel++;

		if (skip1 > 0)
			read(fd, buf, skip1);
		if (skip2 > 0)
			read(fd2, buf, skip2);

		memset(buf2, 0, sizeof(buf2));
		memset(buf, 0, sizeof(buf));
	}

	pos = lseek(fd, 0, SEEK_CUR);
	pos2 = lseek(fd2, 0, SEEK_CUR);
	close(fd2);
	close(fd);

	if (pos != pos2)
		fprintf(stderr, "Warning: %s size (0x%"PRIx64" bytes) != %s (0x%"PRIx64" bytes)\n", filename1, pos, filename2, pos2);

	if (pos2 > pos)
		pos = pos2;

	relf = (float)rel / (pos / 100);
	fprintf(stderr, "Relevance between %s and %s: %.4f%% (0x%"PRIx64" of 0x%"PRIx64" bytes are relevant)\n",
				filename1, filename2, relf, rel, pos);

	return relf;
}

void usage(char *name)
{
	printf("Syntax: %s file1 file2 [skip1-bytes] [skip2-bytes]\n", name);
	exit(1);
}

int main(int argc, char *argv[])
{
	int sk1 = 0, sk2 = 0;

	if (argc < 3)
		usage(argv[0]);

	if (argc > 3)
		sk1 = atoi(argv[3]);

	if (argc > 4)
		sk1 = atoi(argv[4]);

	relevance_test(argv[1], argv[2], sk1, sk2);

	return 0;
}

