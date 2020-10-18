**Important: WindTerm is a partial open source project, and the source will be gradually opened.**

**All released source codes (except thirdparty directory) are provided under the terms of Apache-2.0 license.**

# Components

Below is a list of (some) WindTerm components in alphabetical order, along with a brief description of each.

## Onigmo

An improved version based on Onigmo 5.13.5. In particular, **the addition of iterator makes it possible to match gap buffer or nonadjacent memory blocks.** Please refer to the sample files for how to use.

## Pty

An improved version based on [ptyqt](https://github.com/kafeg/ptyqt). **Almost all the code was rewritten to make the pty more robust and stable.**

## Protocol/TelentProtocol.h/cpp

An implementation of Telnet protocol.

## Utility/CircularBuffer.h

A quick circular buffer template class.

## Utility/Cryptographic.h/cpp

A very safe encryption class using the PBKDF2-algorithm as defined in RFC 8018. WindTerm uses this class together with the user's master password to protect user data, including passwords, private keys and so on.

## Utility/ScopeGuard.h

A class of which the sole purpose is to run the function f in its destructor. This is useful for guaranteeing your cleanup code is executed.

## Utility/Spin.h

A high-performance spin mutex and locker.

## Utility/ThreadLocal.h/cpp

A high-performance thread local storage.

## Widgets/PopupWidget.h/cpp

A popup widget.

## Widgets/Scrollbar.h/cpp

A scrollbar supports 64-bit ranges.

## Widgets/Splitter.h/cpp

A convenient splitter for showing and hiding widgets.