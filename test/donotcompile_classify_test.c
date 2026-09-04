/*
 * classify_test.c — unit tests for the content classifier.
 *
 * Covers all four sensitivity levels with representative inputs. Uses only
 * plain assert(); a zero exit status means every case passed. Test data is
 * synthetic (documentation/example values), never real secrets.
 */
#include <assert.h>
#include <string.h>
#include <stdio.h>
#include "../src/classify.h"

/* Helper: classify a NUL-terminated C string over its full length. */
static int cls(const char *s)
{
    return classify(s, (int)strlen(s));
}

int main(void)
{
    /* Level 1 — US SSN pattern. */
    assert(cls("SSN 123-45-6789") == 1);

    /* Level 2 — 16-digit card number that passes the Luhn checksum
     * (4242 4242 4242 4242 is the canonical Luhn-valid test PAN). */
    assert(cls("card 4242424242424242 exp") == 2);

    /* Level 3 — AWS access-key ID (AKIA prefix, documentation example). */
    assert(cls("AKIAIOSFODNN7EXAMPLE") == 3);

    /* Level 0 — nothing sensitive. */
    assert(cls("hello") == 0);

    printf("classify_test: 4/4 passed\n");
    printf("  [PASS] level 1  SSN  \"SSN 123-45-6789\"\n");
    printf("  [PASS] level 2  PAN  \"4242424242424242\" (Luhn-valid)\n");
    printf("  [PASS] level 3  AWS  \"AKIAIOSFODNN7EXAMPLE\"\n");
    printf("  [PASS] level 0  clean \"hello\"\n");
    return 0;
}
