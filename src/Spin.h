 /*
 * Copyright 2020, WindTerm.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef SPIN_H
#define SPIN_H

#pragma once

#include <atomic>
#include <thread>

class SpinMutex {
public:
	SpinMutex() {
		unlock();
	}

	void yield(size_t nCount) {
		if (nCount < 2) {
		} else if (nCount < 16) {
			std::this_thread::yield();
		} else if (nCount < 32) {
			std::this_thread::sleep_for(std::chrono::nanoseconds(100));
		} else {
			std::this_thread::sleep_for(std::chrono::microseconds(10));
		}
	}

	void lock() {
		for (size_t i = 0; !try_lock(); i++) {
			yield(i);
		}
	}

	void unlock() {
		flag.clear(std::memory_order_release);
	}

	bool try_lock() {
		return flag.test_and_set(std::memory_order_acquire) == false;
	}

private:
	SpinMutex(const SpinMutex &) = delete;
	SpinMutex &operator=(const SpinMutex &) = delete;

	std::atomic_flag flag;
};

template <typename LockType>
class ThreadLocker {
public:
	ThreadLocker(LockType& m_, bool bLock_ = true) : m(m_), bLock(bLock_) {
		if (bLock) m.lock();
	}

	~ThreadLocker() {
		if (bLock) m.unlock();
	}

private:
	LockType& m;
	bool bLock;
};

#endif // SPIN_H