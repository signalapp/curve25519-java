LOCAL_PATH:= $(call my-dir)

include $(CLEAR_VARS)

LOCAL_MODULE    := libcurve25519-donna
LOCAL_SRC_FILES := curve25519-donna.c

include $(BUILD_STATIC_LIBRARY)

include $(CLEAR_VARS)

LOCAL_MODULE     := libcurve25519-ref10
LOCAL_SRC_FILES  := $(wildcard ed25519/*.c) $(wildcard ed25519/additions/*.c) \
                    $(wildcard ed25519/additions/generalized/*.c) $(wildcard ed25519/nacl_sha512/*.c) \
		    ed25519/tests/internal_fast_tests.c

LOCAL_C_INCLUDES := ed25519/nacl_includes ed25519/additions ed25519/additions/generalized ed25519/tests ed25519/sha512 ed25519

include $(BUILD_STATIC_LIBRARY)

include $(CLEAR_VARS)

LOCAL_MODULE     := libcurve25519
LOCAL_SRC_FILES  := curve25519-jni.c
LOCAL_C_INCLUDES := ed25519/additions ed25519/additions/generalized ed25519/tests

LOCAL_STATIC_LIBRARIES := libcurve25519-donna libcurve25519-ref10

include $(BUILD_SHARED_LIBRARY)

