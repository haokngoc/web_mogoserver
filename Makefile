PROG ?= example                   # Tên chương trình cần xây dựng
DELETE = rm -rf                   # Lệnh để xóa các tệp
OUT ?= -o $(PROG)                 # Đối số biên dịch cho tệp đầu ra
SOURCES = main.c mongoose.c       # Các tệp mã nguồn
CFLAGS = -W -Wall -Wextra -g -I.  # Tùy chọn biên dịch
LDLIBS = -ljson-c                 # Thư viện cần liên kết

# Các tùy chọn biên dịch cho Mongoose. Xem https://mongoose.ws/documentation/#build-options
CFLAGS_MONGOOSE += -DMG_HTTP_DIRLIST_TIME_FMT="%Y/%m/%d %H:%M:%S"
CFLAGS_MONGOOSE += -DMG_ENABLE_LINES=1 -DMG_ENABLE_IPV6=1 -DMG_ENABLE_SSI=1

ifeq ($(OS),Windows_NT)   # Cài đặt cho Windows. Giả sử sử dụng trình biên dịch MinGW. Để sử dụng VC: make CC=cl CFLAGS=/MD OUT=/Feprog.exe
  PROG ?= example.exe           # Sử dụng đuôi .exe cho tệp nhị phân
  CC = gcc                      # Sử dụng trình biên dịch gcc của MinGW
  CFLAGS += -lws2_32            # Liên kết với thư viện Winsock
  DELETE = cmd /C del /Q /F /S  # Lệnh trong dấu nhắc lệnh để xóa các tệp
  OUT ?= -o $(PROG)             # Tên tệp đầu ra khi xây dựng
endif

all: $(PROG)              # Mục tiêu mặc định. Xây dựng và chạy chương trình
	$(RUN) ./$(PROG) $(ARGS)
  
$(PROG): $(SOURCES)       # Xây dựng chương trình từ các mã nguồn
	$(CC) $(SOURCES) $(CFLAGS) $(CFLAGS_MONGOOSE) $(CFLAGS_EXTRA) $(OUT) $(LDLIBS)

clean:                    # Dọn dẹp. Xóa chương trình đã xây dựng và tất cả các tệp biên dịch
	$(DELETE) $(PROG) *.o *.obj *.exe *.dSYM
