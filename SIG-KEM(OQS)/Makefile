CC = gcc
CFLAGS = -Wall -g -I/usr/local/include -L/usr/local/lib

#TARGET = testake
SOURCES = ake.c fips202.c
HEADERS = api.h ake.h fips202.h 


#all: $(TARGET)
#all: test_ake
all: test_ake test_speed

test_speed: $(SOURCES) $(HEADERS) ds_benchmark.h cpucycles.h cpucycles.c speed_print.h speed_print.c test_speed.c 
	$(CC) $(CFLAGS) $(SOURCES) ds_benchmark.h cpucycles.c speed_print.c test_speed.c -o test_speed -loqs

test_ake: $(SOURCES) $(HEADERS) test_ake.c 
	$(CC) $(CFLAGS) $(SOURCES) test_ake.c -o test_ake -loqs

%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	-$(RM) -f *.gcno *.gcda *.lcov *.o *.so
	-$(RM) -f test_ake
	-$(RM) -f test_speed