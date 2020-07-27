**All source codes (except thirdparty directory) are provided under the terms of Apache-2.0 license.**

# Components

Below is a list of (some) WindTerm components in alphabetical order, along with a brief description of each.

## CircularBuffer.h

A quick circular buffer template class.

## Onigmo

An improved version based on Onigmo 5.13.5. In particular, **the addition of iterator makes it possible to match gap buffer or nonadjacent memory blocks.** Please refer to the sample files for how to use.

## ScopeGuard.h

A class of which the sole purpose is to run the function f in its destructor. This is useful for guaranteeing your cleanup code is executed.

## Spin.h

A high-performance spin mutex and locker.