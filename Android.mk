LOCAL_PATH:= $(call my-dir)

common_COPY_HEADERS_TO := .
common_COPY_HEADERS := $(shell cd $(LOCAL_PATH) ; find -L openbsd-compat -name "*.h" -and -not -name ".*")

###################### libssh ######################
include $(CLEAR_VARS)

LOCAL_MODULE_TAGS := optional

LOCAL_SRC_FILES := \
    ssherr.c sshbuf.c sshkey.c sshbuf-getput-basic.c \
    sshbuf-misc.c sshbuf-getput-crypto.c \
    authfd.c authfile.c bufaux.c bufbn.c buffer.c \
    canohost.c channels.c cipher.c cipher-aes.c \
    cipher-bf1.c cipher-ctr.c cipher-3des1.c cleanup.c \
    compat.c compress.c crc32.c deattack.c fatal.c hostfile.c \
    log.c match.c md-sha256.c moduli.c nchan.c packet.c roaming_common.c \
    roaming_serv.c readpass.c rsa.c ttymodes.c xmalloc.c addrmatch.c \
    atomicio.c key.c dispatch.c kex.c mac.c uidswap.c uuencode.c misc.c \
    monitor_fdpass.c rijndael.c ssh-dss.c ssh-ecdsa.c ssh-rsa.c dh.c \
    kexdh.c kexgex.c kexdhc.c kexgexc.c bufec.c kexecdh.c kexecdhc.c \
    msg.c progressmeter.c dns.c entropy.c gss-genr.c umac.c umac128.c \
    ssh-pkcs11.c krl.c smult_curve25519_ref.c \
    kexc25519.c kexc25519c.c poly1305.c chacha.c cipher-chachapoly.c \
    ssh-ed25519.c digest-openssl.c hmac.c \
    sc25519.c ge25519.c fe25519.c ed25519.c verify.c hash.c blocks.c \
    openbsd-compat/base64.c openbsd-compat/basename.c \
    openbsd-compat/bcrypt_pbkdf.c openbsd-compat/bindresvport.c \
    openbsd-compat/blowfish.c openbsd-compat/daemon.c \
    openbsd-compat/dirname.c openbsd-compat/fmt_scaled.c \
    openbsd-compat/getcwd.c openbsd-compat/port-tun.c \
    openbsd-compat/getopt_long.c openbsd-compat/glob.c \
    openbsd-compat/inet_aton.c openbsd-compat/inet_ntoa.c \
    openbsd-compat/inet_ntop.c openbsd-compat/mktemp.c \
    openbsd-compat/pwcache.c openbsd-compat/readpassphrase.c \
    openbsd-compat/realpath.c openbsd-compat/rresvport.c \
    openbsd-compat/setenv.c openbsd-compat/setproctitle.c \
    openbsd-compat/sha2.c openbsd-compat/sigact.c \
    openbsd-compat/strlcat.c openbsd-compat/strlcpy.c \
    openbsd-compat/strmode.c openbsd-compat/strnlen.c \
    openbsd-compat/strptime.c openbsd-compat/strsep.c \
    openbsd-compat/strtonum.c openbsd-compat/strtoll.c \
    openbsd-compat/strtoul.c openbsd-compat/strtoull.c \
    openbsd-compat/timingsafe_bcmp.c openbsd-compat/vis.c \
    openbsd-compat/explicit_bzero.c openbsd-compat/arc4random.c \
    openbsd-compat/bsd-asprintf.c openbsd-compat/bsd-closefrom.c \
    openbsd-compat/bsd-cray.c openbsd-compat/bsd-cygwin_util.c \
    openbsd-compat/bsd-getpeereid.c openbsd-compat/getrrsetbyname-ldns.c \
    openbsd-compat/bsd-misc.c openbsd-compat/bsd-nextstep.c \
    openbsd-compat/bsd-openpty.c openbsd-compat/bsd-poll.c \
    openbsd-compat/bsd-setres_id.c openbsd-compat/bsd-snprintf.c \
    openbsd-compat/bsd-waitpid.c openbsd-compat/port-linux.c \
    openbsd-compat/fake-rfc2553.c openbsd-compat/openssl-compat.c \
    openbsd-compat/xmmap.c openbsd-compat/kludge-fd_set.c

# openbsd-compat/getrrsetbyname.c
# openbsd-compat/xcrypt.c

LOCAL_C_INCLUDES := external/openssl/include external/zlib
LOCAL_COPY_HEADERS_TO := $(common_COPY_HEADERS_TO)
LOCAL_COPY_HEADERS := $(common_COPY_HEADERS)

LOCAL_SHARED_LIBRARIES += libssl libcrypto libdl libz

LOCAL_MODULE := libssh

LOCAL_CFLAGS += -O3 -include bionic/libc/upstream-openbsd/android/include/openbsd-compat.h

include $(BUILD_SHARED_LIBRARY)

###################### ssh ######################

include $(CLEAR_VARS)

LOCAL_MODULE_TAGS := optional

LOCAL_SRC_FILES := \
    ssh.c readconf.c clientloop.c sshtty.c \
    sshconnect.c sshconnect1.c sshconnect2.c mux.c \
    roaming_common.c roaming_client.c

LOCAL_MODULE := ssh

LOCAL_C_INCLUDES := external/openssl/include
LOCAL_COPY_HEADERS_TO := $(common_COPY_HEADERS_TO)
LOCAL_COPY_HEADERS := $(common_COPY_HEADERS)

LOCAL_SHARED_LIBRARIES += libssh libssl libcrypto libdl libz

LOCAL_CFLAGS += -include bionic/libc/upstream-openbsd/android/include/openbsd-compat.h

include $(BUILD_EXECUTABLE)

###################### sftp ######################

include $(CLEAR_VARS)

LOCAL_MODULE_TAGS := optional

LOCAL_SRC_FILES := \
    sftp.c sftp-client.c sftp-common.c sftp-glob.c progressmeter.c

LOCAL_MODULE := sftp

LOCAL_C_INCLUDES := external/openssl/include
LOCAL_COPY_HEADERS_TO := $(common_COPY_HEADERS_TO)
LOCAL_COPY_HEADERS := $(common_COPY_HEADERS)

LOCAL_SHARED_LIBRARIES += libssh libssl libcrypto libdl libz

LOCAL_CFLAGS += -include bionic/libc/upstream-openbsd/android/include/openbsd-compat.h

include $(BUILD_EXECUTABLE)

###################### scp ######################

include $(CLEAR_VARS)

LOCAL_MODULE_TAGS := optional

LOCAL_SRC_FILES := \
    scp.c progressmeter.c bufaux.c

LOCAL_MODULE := scp

LOCAL_C_INCLUDES := external/openssl/include
LOCAL_COPY_HEADERS_TO := $(common_COPY_HEADERS_TO)
LOCAL_COPY_HEADERS := $(common_COPY_HEADERS)

LOCAL_SHARED_LIBRARIES += libssh libssl libcrypto libdl libz

LOCAL_CFLAGS += -include bionic/libc/upstream-openbsd/android/include/openbsd-compat.h

include $(BUILD_EXECUTABLE)

###################### sshd ######################

include $(CLEAR_VARS)

LOCAL_MODULE_TAGS := optional

LOCAL_SRC_FILES := \
    sshd.c auth-rhosts.c auth-rsa.c auth-rh-rsa.c \
    audit.c audit-bsm.c audit-linux.c platform.c \
    sshpty.c sshlogin.c servconf.c serverloop.c \
    auth.c auth1.c auth2.c auth-options.c session.c \
    auth-chall.c auth2-chall.c groupaccess.c \
    auth-skey.c auth-bsdauth.c auth2-hostbased.c auth2-kbdint.c \
    auth2-none.c auth2-passwd.c auth2-pubkey.c \
    monitor_mm.c monitor.c monitor_wrap.c kexdhs.c kexgexs.c kexecdhs.c \
    kexc25519s.c auth-krb5.c \
    auth2-gss.c gss-serv.c gss-serv-krb5.c \
    loginrec.c auth-pam.c auth-shadow.c auth-sia.c md5crypt.c \
    sftp-server.c sftp-common.c \
    roaming_common.c roaming_serv.c \
    sandbox-null.c sandbox-rlimit.c sandbox-systrace.c sandbox-darwin.c \
    sandbox-seccomp-filter.c sandbox-capsicum.c

# auth-passwd.c

LOCAL_MODULE := sshd

LOCAL_C_INCLUDES := external/openssl/include external/zlib
LOCAL_COPY_HEADERS_TO := $(common_COPY_HEADERS_TO)
LOCAL_COPY_HEADERS := $(common_COPY_HEADERS)

LOCAL_SHARED_LIBRARIES += libssh libssl libcrypto libdl libz

LOCAL_CFLAGS += -include bionic/libc/upstream-openbsd/android/include/openbsd-compat.h

include $(BUILD_EXECUTABLE)

###################### sftp-server ######################

include $(CLEAR_VARS)

LOCAL_MODULE_TAGS := optional

LOCAL_SRC_FILES := \
       sftp-server.c sftp-common.c sftp-server-main.c

LOCAL_MODULE := sftp-server

LOCAL_C_INCLUDES := external/openssl/include
LOCAL_COPY_HEADERS_TO := $(common_COPY_HEADERS_TO)
LOCAL_COPY_HEADERS := $(common_COPY_HEADERS)

LOCAL_SHARED_LIBRARIES += libssh libssl libcrypto libdl libz

LOCAL_CFLAGS += -include bionic/libc/upstream-openbsd/android/include/openbsd-compat.h

include $(BUILD_EXECUTABLE)

###################### ssh-keygen ######################

include $(CLEAR_VARS)

LOCAL_MODULE_TAGS := optional

LOCAL_SRC_FILES := \
    ssh-keygen.c

LOCAL_MODULE := ssh-keygen

LOCAL_C_INCLUDES := external/openssl/include
LOCAL_COPY_HEADERS_TO := $(common_COPY_HEADERS_TO)
LOCAL_COPY_HEADERS := $(common_COPY_HEADERS)

LOCAL_SHARED_LIBRARIES += libssh libssl libcrypto libdl libz

LOCAL_CFLAGS += -include bionic/libc/upstream-openbsd/android/include/openbsd-compat.h

include $(BUILD_EXECUTABLE)

###################### sshd_config ######################

include $(CLEAR_VARS)
LOCAL_MODULE_TAGS := optional
LOCAL_MODULE := sshd_config
LOCAL_MODULE_CLASS := ETC
LOCAL_MODULE_PATH := $(TARGET_OUT_ETC)/ssh
LOCAL_SRC_FILES := sshd_config.android
include $(BUILD_PREBUILT)

###################### start-ssh ######################

include $(CLEAR_VARS)
LOCAL_MODULE_TAGS := optional
LOCAL_MODULE := start-ssh
LOCAL_MODULE_CLASS := EXECUTABLES
LOCAL_SRC_FILES := start-ssh
include $(BUILD_PREBUILT)
