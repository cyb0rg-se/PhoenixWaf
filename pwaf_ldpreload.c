/*
 * ═══════════════════════════════════════════════════════════════════════
 *  PhoenixWAF LD_PRELOAD Protection v3
 *  Hooks: execve, unlink, rename, chmod
 * ═══════════════════════════════════════════════════════════════════════
 *
 *  编译环境要求:
 *    - Linux (x86_64 / aarch64 / armv7l)
 *    - GCC >= 4.8 或 musl-gcc
 *    - glibc-devel / musl-dev (提供 dlfcn.h)
 *
 *  ─── 编译命令 ──────────────────────────────────────────────────────────
 *
 *  ★ x86_64 (绝大多数比赛靶机):
 *    gcc -shared -fPIC -O2 -s -o waf_x86_64.so pwaf_ldpreload.c -ldl
 *
 *  ★ aarch64 (ARM64):
 *    gcc -shared -fPIC -O2 -s -o waf_aarch64.so pwaf_ldpreload.c -ldl
 *    或交叉编译:
 *    aarch64-linux-gnu-gcc -shared -fPIC -O2 -s -o waf_aarch64.so pwaf_ldpreload.c -ldl
 *
 *  ★ armv7l (ARM32, 少见):
 *    arm-linux-gnueabihf-gcc -shared -fPIC -O2 -s -o waf_armv7l.so pwaf_ldpreload.c -ldl
 *
 *  ★ 静态链接 musl (兼容性最好，无 glibc 依赖):
 *    musl-gcc -shared -fPIC -O2 -s -o waf_x86_64_musl.so pwaf_ldpreload.c -ldl
 *
 *  编译参数说明:
 *    -shared   生成共享库 (.so)
 *    -fPIC     位置无关代码 (Position Independent Code)
 *    -O2       优化等级
 *    -s        strip 符号表，减小体积 (通常 < 20KB)
 *    -ldl      链接 libdl (dlsym 需要)
 *
 *  ─── 部署方式 ──────────────────────────────────────────────────────────
 *
 *  方法 A: 通过 php.ini / .user.ini 注入 (推荐)
 *    将编译好的 waf.so 放到网站根目录，然后:
 *    echo 'LD_PRELOAD=/var/www/html/waf.so' >> /etc/environment
 *    或在 PHP-FPM pool 配置中:
 *    env[LD_PRELOAD] = /var/www/html/waf.so
 *
 *  方法 B: 通过 Apache .htaccess:
 *    SetEnv LD_PRELOAD /var/www/html/waf.so
 *
 *  方法 C: PhoenixWAF 自动部署 (install 时自动完成)
 *
 *  ─── 自定义路径 ─────────────────────────────────────────────────────────
 *
 *  编译时可通过 -D 参数自定义日志路径和网站根目录:
 *    gcc -shared -fPIC -O2 -s \
 *        -DPWAF_LOG_PATH='"/var/www/html/.pwaf_log"' \
 *        -DPWAF_WEBROOT='"/var/www/html"' \
 *        -o waf.so pwaf_ldpreload.c -ldl
 *
 *  如不指定，默认值:
 *    LOG_PATH = /var/www/html/.pwaf_log
 *    WEBROOT  = /var/www/html
 *
 *  ─── 编译后嵌入 waf.php ────────────────────────────────────────────────
 *
 *  编译完成后，将 .so 转为 base64 硬编码到 waf.php:
 *    base64 -w0 waf_x86_64.so     → 粘贴到 waf.php 中 LDPRELOAD_X86_64 常量
 *    base64 -w0 waf_aarch64.so    → 粘贴到 waf.php 中 LDPRELOAD_AARCH64 常量
 *
 *  或者直接将 base64 写入配置:
 *    php -r "echo base64_encode(file_get_contents('waf_x86_64.so'));" > waf_x86_64.b64
 *
 * ═══════════════════════════════════════════════════════════════════════
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <dlfcn.h>
#include <time.h>
#include <errno.h>

/* ── 可配置路径 (编译时 -D 覆盖) ── */

#ifndef PWAF_LOG_PATH
#define PWAF_LOG_PATH "/var/www/html/.pwaf_log"
#endif

#ifndef PWAF_WEBROOT
#define PWAF_WEBROOT "/var/www/html"
#endif

static const char *LOG_PATH = PWAF_LOG_PATH;
static const char *WEBROOT  = PWAF_WEBROOT;

/* ── execve 拦截关键词 ── */
static const char *exec_blocked[] = {
    "flag",
    "LD_PRELOAD",
    "waf.so",
    "waf.php",
    ".pwaf",
    "/dev/tcp/",
    "nc -e",
    "nc -lp",
    "ncat -e",
    "mkfifo",
    "/etc/shadow",
    "/etc/passwd",
    "base64.*decode",
    "python -c",
    "python3 -c",
    "perl -e",
    "ruby -e",
    "php -r",
    NULL
};

/* ── 受保护文件名 (禁止 unlink/rename/chmod) ── */
static const char *protected_names[] = {
    "waf.php",
    ".pwaf.php",
    ".pwaf_bak.php",
    ".htaccess",
    ".user.ini",
    "waf.so",
    ".pwaf_watcher.sh",
    ".pwaf_watcher.pid",
    ".pwaf_log",
    ".pwaf_int",
    ".pwaf_rate",
    NULL
};

/* ═══════════════════════════════════════════════════════════════════════
 *  日志记录
 * ═══════════════════════════════════════════════════════════════════════ */
static void pwaf_log(const char *hook, const char *target) {
    FILE *f = fopen(LOG_PATH, "a");
    if (!f) return;
    time_t now = time(NULL);
    struct tm *t = localtime(&now);
    char ts[32];
    strftime(ts, sizeof(ts), "%Y-%m-%d %H:%M:%S", t);
    fprintf(f,
        "{\"ts\":%ld,\"dt\":\"%s\",\"ip\":\"LDPRELOAD\",\"method\":\"%s\","
        "\"uri\":\"%.200s\",\"rule\":\"ldpreload_%s\","
        "\"payload\":\"%.200s\",\"param\":\"syscall\",\"ua\":\"\","
        "\"action\":\"blocked\"}\n",
        (long)now, ts, hook, target, hook, target);
    fclose(f);
}

/* ═══════════════════════════════════════════════════════════════════════
 *  路径保护检查
 * ═══════════════════════════════════════════════════════════════════════ */
static int is_protected(const char *path) {
    if (!path) return 0;

    /* 提取文件名 (basename) */
    const char *bn = strrchr(path, '/');
    bn = bn ? bn + 1 : path;

    /* 精确匹配保护文件名 */
    for (int i = 0; protected_names[i]; i++) {
        if (strcmp(bn, protected_names[i]) == 0) return 1;
    }

    /* 模糊匹配: 任何包含 .pwaf 的路径 */
    if (strstr(path, ".pwaf") != NULL) return 1;

    return 0;
}

/* ═══════════════════════════════════════════════════════════════════════
 *  Hook: execve — 拦截危险命令执行
 * ═══════════════════════════════════════════════════════════════════════ */
typedef int (*real_execve_t)(const char *, char *const[], char *const[]);

int execve(const char *filename, char *const argv[], char *const envp[]) {
    real_execve_t real_execve = (real_execve_t)dlsym(RTLD_NEXT, "execve");
    if (!real_execve) { errno = EACCES; return -1; }

    /* 拼接完整命令行用于关键词匹配 */
    char cmdline[2048] = {0};
    if (argv) {
        for (int i = 0; argv[i] && i < 64; i++) {
            if (i > 0) strncat(cmdline, " ", sizeof(cmdline) - strlen(cmdline) - 1);
            strncat(cmdline, argv[i], sizeof(cmdline) - strlen(cmdline) - 1);
        }
    }

    /* 检查关键词黑名单 */
    for (int j = 0; exec_blocked[j]; j++) {
        if (strstr(cmdline, exec_blocked[j]) != NULL ||
            (filename && strstr(filename, exec_blocked[j]) != NULL)) {
            pwaf_log("execve", cmdline);
            errno = EACCES;
            return -1;
        }
    }

    /* 检测 env -i 绕过尝试 (清空环境变量以移除 LD_PRELOAD) */
    if (argv) {
        for (int i = 0; argv[i]; i++) {
            if (strstr(argv[i], "env") && argv[i+1] && strstr(argv[i+1], "-i")) {
                pwaf_log("execve", "env -i bypass attempt");
                errno = EACCES;
                return -1;
            }
        }
    }

    /* 检测通过 envp 卸载 LD_PRELOAD */
    if (envp) {
        for (int i = 0; envp[i]; i++) {
            if (strncmp(envp[i], "LD_PRELOAD=", 11) == 0 &&
                strstr(envp[i], "waf.so") == NULL) {
                pwaf_log("execve", "LD_PRELOAD override attempt");
                errno = EACCES;
                return -1;
            }
        }
    }

    return real_execve(filename, argv, envp);
}

/* ═══════════════════════════════════════════════════════════════════════
 *  Hook: unlink — 禁止删除受保护文件
 * ═══════════════════════════════════════════════════════════════════════ */
typedef int (*real_unlink_t)(const char *);

int unlink(const char *pathname) {
    real_unlink_t real_unlink = (real_unlink_t)dlsym(RTLD_NEXT, "unlink");
    if (!real_unlink) { errno = EACCES; return -1; }
    if (is_protected(pathname)) {
        pwaf_log("unlink", pathname);
        errno = EPERM;
        return -1;
    }
    return real_unlink(pathname);
}

/* ═══════════════════════════════════════════════════════════════════════
 *  Hook: rename — 禁止重命名受保护文件
 * ═══════════════════════════════════════════════════════════════════════ */
typedef int (*real_rename_t)(const char *, const char *);

int rename(const char *oldpath, const char *newpath) {
    real_rename_t real_rename = (real_rename_t)dlsym(RTLD_NEXT, "rename");
    if (!real_rename) { errno = EACCES; return -1; }
    if (is_protected(oldpath)) {
        pwaf_log("rename", oldpath);
        errno = EPERM;
        return -1;
    }
    return real_rename(oldpath, newpath);
}

/* ═══════════════════════════════════════════════════════════════════════
 *  Hook: chmod — 禁止修改受保护文件权限
 * ═══════════════════════════════════════════════════════════════════════ */
typedef int (*real_chmod_t)(const char *, unsigned int);

int chmod(const char *pathname, unsigned int mode) {
    real_chmod_t real_chmod = (real_chmod_t)dlsym(RTLD_NEXT, "chmod");
    if (!real_chmod) { errno = EACCES; return -1; }
    if (is_protected(pathname)) {
        pwaf_log("chmod", pathname);
        errno = EPERM;
        return -1;
    }
    return real_chmod(pathname, mode);
}

/* ═══════════════════════════════════════════════════════════════════════
 *  Hook: remove — 禁止 remove() 删除受保护文件
 * ═══════════════════════════════════════════════════════════════════════ */
typedef int (*real_remove_t)(const char *);

int remove(const char *pathname) {
    real_remove_t real_remove = (real_remove_t)dlsym(RTLD_NEXT, "remove");
    if (!real_remove) { errno = EACCES; return -1; }
    if (is_protected(pathname)) {
        pwaf_log("remove", pathname);
        errno = EPERM;
        return -1;
    }
    return real_remove(pathname);
}

/* ═══════════════════════════════════════════════════════════════════════
 *  Hook: truncate — 禁止截断受保护文件
 * ═══════════════════════════════════════════════════════════════════════ */
typedef int (*real_truncate_t)(const char *, long);

int truncate(const char *path, long length) {
    real_truncate_t real_truncate = (real_truncate_t)dlsym(RTLD_NEXT, "truncate");
    if (!real_truncate) { errno = EACCES; return -1; }
    if (is_protected(path) && length == 0) {
        pwaf_log("truncate", path);
        errno = EPERM;
        return -1;
    }
    return real_truncate(path, length);
}

/* ═══════════════════════════════════════════════════════════════════════
 *  Constructor — .so 加载时自动执行
 * ═══════════════════════════════════════════════════════════════════════ */
__attribute__((constructor))
static void pwaf_init(void) {
    setenv("PWAF_ACTIVE", "1", 1);
}
