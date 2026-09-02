/*
 * clipboard_watch.c — userspace DLP source #3: an X11 clipboard watcher.
 *
 * The kernel LSM hooks catch data leaving via files and sockets. The clipboard
 * is a third exfiltration channel that lives entirely in userspace (the X
 * server), so it needs a userspace sensor. This watcher uses the XFixes
 * extension to subscribe to CLIPBOARD selection-owner changes and fires every
 * time the clipboard contents are replaced — the hook point at which a full
 * agent would fetch the new selection and run it through classify().
 *
 * Scope note: this demonstrates the *detection* path (owner-change events).
 * Actually pulling the pasted bytes means a TARGETS -> UTF8_STRING/STRING
 * negotiation plus INCR handling for large payloads; that content-extraction
 * step is left as future work and is called out in LIMITS.md.
 *
 * Build:  gcc -O2 -Wall -o build/clipboard_watch clipboard/clipboard_watch.c -lX11 -lXfixes
 * Run:    ./build/clipboard_watch      (needs an X11 DISPLAY; not root)
 */
#include <X11/Xlib.h>
#include <X11/extensions/Xfixes.h>
#include <stdio.h>

int main(void)
{
    Display *d = XOpenDisplay(NULL);
    if (!d)
        return 1;

    Atom clip = XInternAtom(d, "CLIPBOARD", False);

    int ev_base = 0, err_base = 0;
    if (!XFixesQueryExtension(d, &ev_base, &err_base))
        return 2;

    /* Ask the X server to notify us whenever the CLIPBOARD owner changes. */
    XFixesSelectSelectionInput(d, DefaultRootWindow(d), clip,
                               XFixesSetSelectionOwnerNotifyMask);

    printf("clipboard watcher active\n");
    fflush(stdout);

    for (;;)
    {
        XEvent e;
        XNextEvent(d, &e);
        if (e.type == ev_base + XFixesSelectionNotify)
        {
            /* Clipboard contents were just replaced. A full agent would fetch
             * the new selection here and classify() it before allowing it to
             * be pasted elsewhere. */
            printf("clipboard changed\n");
            fflush(stdout);
        }
    }
    return 0;
}
