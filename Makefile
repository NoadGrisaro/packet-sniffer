CC = gcc
CFLAGS = -Wall -Wextra -pthread -Iinclude

TARGET = bin/packet_sniffer
SRCS = main.c \
       nic_sniffer.c \
       ring_buffer.c \
       sniffer_presentation.c \
       layer_2/layer2_parser.c \
       layer_2/layer2_presentation.c \
       layer_3/layer3_parser.c \
       layer_3/layer3_presentation.c \
       layer_4/layer4_parser.c \
       layer_4/layer4_presentation.c \
       layer_5_7/layer5_7_parser.c \
       layer_5_7/layer5_7_presentation.c

all: $(TARGET)

$(TARGET): $(SRCS)
	@mkdir -p bin
	$(CC) $(CFLAGS) -o $@ $^

clean:
	rm -f $(TARGET)