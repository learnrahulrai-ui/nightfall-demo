/*
 * classify.c — userspace content classifier for the Nightfall DLP agent.
 *
 * This is the "what is worth protecting" half of the system. The kernel does
 * not read file contents (that would be expensive and fragile); instead this
 * classifier runs in userspace, decides a sensitivity level for a buffer, and
 * the loader registers the file's {major, minor, inode} identity with the
 * kernel so the LSM hooks can enforce the boundary cheaply.
 */
#define _GNU_SOURCE
#include <string.h>
#include "classify.h"

/*
 * luhn() — return non-zero if the `n`-digit run starting at `digits` is all
 * ASCII digits AND satisfies the Luhn (mod-10) checksum used by every major
 * credit-card issuer. Walking right-to-left, every second digit is doubled
 * (subtract 9 if the result exceeds 9); a valid PAN sums to a multiple of 10.
 * Any non-digit byte disqualifies the run immediately.
 */
static int luhn(const char *digits, int n)
{
    int sum = 0;
    int alternate = 0;
    for (int i = n - 1; i >= 0; i--) {
        if (digits[i] < '0' || digits[i] > '9')
            return 0;
        int value = digits[i] - '0';
        if (alternate) {
            value *= 2;
            if (value > 9)
                value -= 9;
        }
        sum += value;
        alternate = !alternate;
    }
    return (sum % 10) == 0;
}

int classify(const char *bytes, int n)
{
    int level = 0;

    /* Level 3 — AWS access-key IDs always start with the literal "AKIA". */
    if (memmem(bytes, n, "AKIA", 4))
        level = 3;

    /* Level 2 — any window of 16 consecutive bytes that passes Luhn is a PAN.
     * Only raises the level (never lowers a level-3 AWS match). */
    for (int i = 0; i + 16 <= n; i++) {
        if (luhn(bytes + i, 16)) {
            if (level < 2)
                level = 2;
            break;
        }
    }

    /* Level 1 — US SSN pattern: 3 digits, '-', 2 digits, '-', 4 digits.
     * Checked byte-by-byte so we never require a NUL-terminated buffer. */
    for (int i = 0; i + 11 <= n; i++) {
        if (bytes[i + 0] >= '0' && bytes[i + 0] <= '9' &&
            bytes[i + 1] >= '0' && bytes[i + 1] <= '9' &&
            bytes[i + 2] >= '0' && bytes[i + 2] <= '9' &&
            bytes[i + 3] == '-' &&
            bytes[i + 4] >= '0' && bytes[i + 4] <= '9' &&
            bytes[i + 5] >= '0' && bytes[i + 5] <= '9' &&
            bytes[i + 6] == '-' &&
            bytes[i + 7] >= '0' && bytes[i + 7] <= '9' &&
            bytes[i + 8] >= '0' && bytes[i + 8] <= '9' &&
            bytes[i + 9] >= '0' && bytes[i + 9] <= '9' &&
            bytes[i + 10] >= '0' && bytes[i + 10] <= '9') {
            if (level < 1)
                level = 1;
            break;
        }
    }

    return level;
}
