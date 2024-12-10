PROJDIR := $(shell readlink -f ..)
TOP_DIR := .
CUR_DIR := $(shell pwd)
PREFIX := /usr/local
TARGET_DIR := target
BIN_NAME := tee-kms
TOOL_NAME := client

DEBUG ?=
DESTDIR ?= $(PREFIX)/bin

ifdef DEBUG
    release :=
    TARGET_DIR := $(TARGET_DIR)/debug
else
    release := --release
    TARGET_DIR := $(TARGET_DIR)/release
endif

build:
	cargo build --bin $(BIN_NAME) $(release)
    cargo build --bin $(TOOL_NAME) $(release)

install:
	install -D -m0755 $(TARGET_DIR)/$(BIN_NAME) $(DESTDIR)
    install -D -m0755 $(TARGET_DIR)/$(TOOL_NAME) $(DESTDIR)

clean:
	cargo clean
