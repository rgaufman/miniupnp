#ifndef MACOS_FIXES_H
#define MACOS_FIXES_H

/* On macOS, daemon() is deprecated, so we redefine USE_DAEMON to be off */
#ifdef __APPLE__
#ifdef USE_DAEMON
#undef USE_DAEMON
#endif
#endif

#endif /* MACOS_FIXES_H */