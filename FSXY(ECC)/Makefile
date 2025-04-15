CC = gcc
CFLAGS = -Wall -g -I/usr/local/include -L/usr/local/lib

#TARGET = testake
SOURCES = utils.c gcwr-ake.c fips202.c
HEADERS = utils.h gcwr-ake.h fips202.h


#all: $(TARGET)
#all: test_ake
all: test_ake test_speed_ake

test_speed_ake: $(SOURCES) $(HEADERS) ds_benchmark.h system_info.h system_info.c test_speed_ake.c 
	$(CC) $(CFLAGS) $(SOURCES) ds_benchmark.h system_info.c test_speed_ake.c -o test_speed_ake -lcrypto

test_ake: $(SOURCES) $(HEADERS) test-gcwr-ake.c 
	$(CC) $(CFLAGS) $(SOURCES) test-gcwr-ake.c -o test_ake -lcrypto

%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	-$(RM) -f *.gcno *.gcda *.lcov *.o *.so
	-$(RM) -f test_ake
	-$(RM) -f test_speed_ake