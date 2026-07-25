CC = gcc
CFLAGS = -Wall -Wextra
LIBS = -lcurl -lcjson
TARGET = pkgscan

all: $(TARGET)

$(TARGET): main.c hook.c
	$(CC) $(CFLAGS) -o $(TARGET) main.c hook.c $(LIBS)

install: all
	install -m 755 $(TARGET) /usr/local/bin/$(TARGET)

uninstall:
	@if [ -f /usr/local/bin/$(TARGET) ]; then \
		echo "Run 'sudo pkgscan --hook disable' to remove ALPM pacman hook"; \
	fi
	rm -f /usr/local/bin/$(TARGET)
clean:
	rm -f $(TARGET)
