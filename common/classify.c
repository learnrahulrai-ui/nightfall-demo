#define _GNU_SOURCE
#include <string.h>
#include "classify.h"

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
    if (memmem(bytes, n, "AKIA", 4))
        level = 3;
    for (int i = 0; i + 16 <= n; i++) {
        if (luhn(bytes + i, 16)) {
            if (level < 2)
                level = 2;
            break;
        }
    }
    for (int i = 0; i + 11 <= n; i++) {
        if (bytes[i+0] >= '0' && bytes[i+0] <= '9' && bytes[i+1] >= '0' && bytes[i+1] <= '9' && bytes[i+2] >= '0' && bytes[i+2] <= '9' && bytes[i+3] == '-' && bytes[i+4] >= '0' && bytes[i+4] <= '9' && bytes[i+5] >= '0' && bytes[i+5] <= '9' && bytes[i+6] == '-' && bytes[i+7] >= '0' && bytes[i+7] <= '9' && bytes[i+8] >= '0' && bytes[i+8] <= '9' && bytes[i+9] >= '0' && bytes[i+9] <= '9' && bytes[i+10] >= '0' && bytes[i+10] <= '9') {
            if (level < 1)
                level = 1;
            break;
        }
    }
    return level;
}
