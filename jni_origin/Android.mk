LOCAL_PATH := $(call my-dir)

include $(CLEAR_VARS)
LOCAL_CFLAGS := -std=c99
LOCAL_MODULE := extract_keymaster
LOCAL_LDLIBS := -llog
LOCAL_SRC_FILES := main.c QSEEComAPI.c vuln.c widevine_commands.c exploit_utilities.c keymaster_commands.c tzbsp_exploit.c
include $(BUILD_EXECUTABLE)
