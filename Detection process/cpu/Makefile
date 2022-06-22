TARGET = ${notdir $(CURDIR)}

SRC_DIR = .
SRC_SUBDIR += . 
INCLUDE_DIR += .
OBJ_DIR = .
MNN_ROOT=../MNN
CC = g++
C_FLAGS = -Og -g  -Wall  -DLITTLE_ENDIAN_BITFIELD  -std=c++11 -fpermissive -DSET_SOCKET_BUFFER_LEN

LD = $(CC)
INCLUDES += -I$(INCLUDE_DIR) \
		 -I$(MNN_ROOT)/include \
		 -I$(MNN_ROOT)/include/MNN \
		 -DEO_USE_MNN
LD_FLAFS += 
LD_LIBS =  -lpthread -L$(MNN_ROOT)/build -lMNN

ifeq ($(CC), g++)
	TYPE = cpp
else
	TYPE = c
endif

SRCS += ${foreach subdir, $(SRC_SUBDIR), ${wildcard $(SRC_DIR)/$(subdir)/*.$(TYPE)}}
OBJS += ${foreach src, $(notdir $(SRCS)), ${patsubst %.$(TYPE), $(OBJ_DIR)/%.o, $(src)}}

vpath %.$(TYPE) $(sort $(dir $(SRCS)))

all : $(TARGET)
	@echo "Builded target:" $^
	@echo "Done"

$(TARGET) : $(OBJS)
	@mkdir -p $(@D)
	@echo "Linking" $@ "from" $^ "..."
	$(LD) -o $@ $^ $(LD_FLAGS) $(LD_LIBS)
	@echo "Link finished\n"

$(OBJS) : $(OBJ_DIR)/%.o:%.$(TYPE)
	@mkdir -p $(@D)
	@echo "Compiling" $@ "from" $< "..."
	$(CC) -c -o $@ $< $(C_FLAGS) $(INCLUDES)
	@echo "Compile finished\n"

.PHONY : clean cleanobj
clean : cleanobj
	@echo "Remove all executable files"
	rm -f $(TARGET)
cleanobj :
	@echo "Remove object files"
	rm -rf $(OBJ_DIR)/*.o