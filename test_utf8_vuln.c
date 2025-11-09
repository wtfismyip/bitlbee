/*
 * Standalone test program for UTF-8 nickname vulnerability
 * Compile: gcc -g -fsanitize=address -o test_utf8_vuln test_utf8_vuln.c `pkg-config --cflags --libs glib-2.0`
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <glib.h>

/* From nick.c */
static char *nick_lc_chars = "0123456789abcdefghijklmnopqrstuvwxyz{}^`-_|";
static char *nick_uc_chars = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ[]~`-_\\";

#define IRC_UTF8_NICKS 0x0001
#define MAX_NICK_LENGTH 24

/* Minimal irc_t structure for testing */
typedef struct {
    guint32 status;
    void *b;  /* We won't use this in testing */
} irc_t;

/* Simplified nick_strip() - exact copy from nick.c:292-333 */
void nick_strip(irc_t *irc, char *nick)
{
    int len = 0;
    gboolean nick_underscores = FALSE;  /* Simplified for testing */

    if (irc && (irc->status & IRC_UTF8_NICKS)) {
        gunichar c;
        char *p = nick, *n, tmp[strlen(nick) + 1];

        printf("[DEBUG] Processing nick with UTF-8 mode enabled\n");
        printf("[DEBUG] Initial nick: ");
        for (int i = 0; nick[i]; i++) {
            printf("%02x ", (unsigned char)nick[i]);
        }
        printf("\n");

        while (p && *p) {
            c = g_utf8_get_char_validated(p, -1);
            n = g_utf8_find_next_char(p, NULL);

            printf("[DEBUG] At position %ld: c=%08x, n=%p, p=%p\n",
                   p - nick, (unsigned int)c, (void*)n, (void*)p);

            if (nick_underscores && c == ' ') {
                *p = '_';
                p = n;
            } else if ((c < 0x7f && !(strchr(nick_lc_chars, c) ||
                                      strchr(nick_uc_chars, c))) ||
                       !g_unichar_isgraph(c)) {
                printf("[DEBUG] Removing character at position %ld\n", p - nick);
                printf("[DEBUG] About to strcpy(tmp, n=%p)\n", (void*)n);

                /* VULNERABLE CODE */
                strcpy(tmp, n);
                strcpy(p, tmp);

                printf("[DEBUG] strcpy completed\n");
            } else {
                p = n;
            }
        }
        if (p) {
            len = p - nick;
        }
    } else {
        int i;
        printf("[DEBUG] Processing nick without UTF-8 mode\n");

        for (i = len = 0; nick[i] && len < MAX_NICK_LENGTH; i++) {
            if (nick_underscores && nick[i] == ' ') {
                nick[len] = '_';
                len++;
            } else if (strchr(nick_lc_chars, nick[i]) ||
                       strchr(nick_uc_chars, nick[i])) {
                nick[len] = nick[i];
                len++;
            }
        }
    }

    /* Truncate if too long */
    if (strlen(nick) > MAX_NICK_LENGTH) {
        nick[MAX_NICK_LENGTH] = '\0';
    }
}

/* Test case structure */
typedef struct {
    const char *name;
    const unsigned char *nickname;
    size_t nick_len;
    const char *description;
} test_case_t;

#define TEST_CASE(name, bytes, desc) \
    { name, (const unsigned char*)bytes, sizeof(bytes) - 1, desc }

int main(int argc, char **argv)
{
    printf("BitlBee UTF-8 Nickname Vulnerability Test\n");
    printf("==========================================\n\n");

    /* Test cases with invalid UTF-8 - using byte arrays to avoid escape warnings */
    unsigned char test1[] = {'t', 'e', 's', 't', 0xc3, 0x28, 'u', 's', 'e', 'r', 0};
    unsigned char test2[] = {'a', 'd', 'm', 'i', 'n', 0xc0, 0x80, 't', 'e', 's', 't', 0};
    unsigned char test3[] = {'u', 's', 'e', 'r', 0xe2, 0x82, 0};
    unsigned char test4[] = {'t', 'e', 's', 't', 0xed, 0xa0, 0x80, 'u', 's', 'e', 'r', 0};
    unsigned char test5[] = {'a', 0xc3, 0x28, 'b', 0xc3, 0x28, 'c', 0xc3, 0x28, 0};
    unsigned char test6[] = {0xf0, 0x28, 0x8c, 0xbc, 0xf0, 0x28, 0x8c, 0xbc, 0};
    unsigned char test7[] = {'a', 'd', 'm', 'i', 'n', 0xc3, 0x28, 0xc3, 0x28, 0xc3, 0x28, 0xc3, 0x28, 0xc3, 0x28, 'x', 'y', 'z', 0};
    unsigned char test8[] = {0xfe, 0xff, 0xfe, 0xff, 0};

    test_case_t tests[] = {
        { "Test 1", test1, sizeof(test1) - 1, "Incomplete 2-byte UTF-8 sequence" },
        { "Test 2", test2, sizeof(test2) - 1, "Overlong NULL encoding" },
        { "Test 3", test3, sizeof(test3) - 1, "Truncated 3-byte sequence" },
        { "Test 4", test4, sizeof(test4) - 1, "High surrogate (invalid in UTF-8)" },
        { "Test 5", test5, sizeof(test5) - 1, "Repeated invalid sequences" },
        { "Test 6", test6, sizeof(test6) - 1, "Multiple invalid 4-byte sequences" },
        { "Test 7", test7, sizeof(test7) - 1, "Many invalid sequences" },
        { "Test 8", test8, sizeof(test8) - 1, "Invalid UTF-8 bytes (never valid)" },
    };

    int num_tests = sizeof(tests) / sizeof(tests[0]);
    int passed = 0;
    int failed = 0;

    /* Setup minimal irc_t structure */
    irc_t irc;
    irc.status = IRC_UTF8_NICKS;
    irc.b = NULL;

    for (int i = 0; i < num_tests; i++) {
        printf("\n[TEST %d] %s\n", i + 1, tests[i].name);
        printf("Description: %s\n", tests[i].description);
        printf("Input bytes: ");

        for (size_t j = 0; j < tests[i].nick_len; j++) {
            printf("%02x ", tests[i].nickname[j]);
        }
        printf("\n");

        /* Allocate buffer for nickname */
        char *nick = malloc(tests[i].nick_len + 1);
        memcpy(nick, tests[i].nickname, tests[i].nick_len);
        nick[tests[i].nick_len] = '\0';

        printf("Calling nick_strip()...\n");
        fflush(stdout);

        /* This should crash or trigger AddressSanitizer if vulnerable */
        nick_strip(&irc, nick);

        printf("Result: %s\n", nick);
        printf("Output bytes: ");
        for (int j = 0; nick[j]; j++) {
            printf("%02x ", (unsigned char)nick[j]);
        }
        printf("\n");
        printf("[PASS] No crash detected\n");
        passed++;

        free(nick);
    }

    printf("\n==========================================\n");
    printf("Tests completed: %d passed, %d failed\n", passed, failed);
    printf("\nNOTE: If AddressSanitizer is enabled and the code is vulnerable,\n");
    printf("you should see error messages above about buffer overflows.\n");

    return 0;
}
