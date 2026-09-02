#ifndef CLASSIFY_H
#define CLASSIFY_H

/*
 * classify() — scan a byte buffer for regulated content and return a
 * sensitivity level:
 *
 *   0  clean          — nothing sensitive found
 *   1  SSN            — US Social Security Number pattern (ddd-dd-dddd)
 *   2  PAN            — 16-digit card number that passes the Luhn checksum
 *   3  AWS access key — literal "AKIA" prefix
 *
 * Higher-severity matches win: an AWS key (3) outranks a PAN (2) outranks an
 * SSN (1). The scan is over a raw buffer (not a C string), so `n` is the
 * number of bytes to inspect — the buffer need not be NUL-terminated.
 */
int classify(const char *bytes, int n);

#endif /* CLASSIFY_H */
