target:= simpletun
all: $target

simpletun:simpletun.c
	$CC -Wall $< -o $@

clean:
	rm -f *.o $target
