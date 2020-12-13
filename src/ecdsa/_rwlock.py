# Copyright Mateusz Kobos, (c) 2011
# Copyright Hubert Kario, (c) 2020
# https://code.activestate.com/recipes/577803-reader-writer-lock-with-priority-for-writers/
# released under the MIT licence

import signal
import threading


__author__ = "Mateusz Kobos"


class RWLock:
    """
    Read-Write locking primitive

    Synchronization object used in a solution of so-called second
    readers-writers problem. In this problem, many readers can simultaneously
    access a share, and a writer has an exclusive access to this share.
    Additionally, the following constraints should be met:
    1) no reader should be kept waiting if the share is currently opened for
       reading unless a writer is also waiting for the share,
    2) no writer should be kept waiting for the share longer than absolutely
       necessary.
    3) even when the process receives KeyboardInterrupt during lock acquisition
       or release the object is left in consistent state

    The implementation is based on [1, secs. 4.2.2, 4.2.6, 4.2.7]
    with a modification -- adding an additional lock (C{self.__readers_queue})
    -- in accordance with [2].

    Note: because of requirement 3 above, the handling of SIGINT
    (KeyboardInterrupt) is delayed until after *_release() or context
    manager exit. I.e. critical section won't get interrupted with
    KeyboardInterrupt.

    Sources:
    [1] A.B. Downey: "The little book of semaphores", Version 2.1.5, 2008
    [2] P.J. Courtois, F. Heymans, D.L. Parnas:
        "Concurrent Control with 'Readers' and 'Writers'",
        Communications of the ACM, 1971 (via [3])
    [3] http://en.wikipedia.org/wiki/Readers-writers_problem
    """

    def __init__(self):
        """
        A lock giving an even higher priority to the writer in certain
        cases (see [2] for a discussion).
        """
        self.__read_switch = _LightSwitch()
        self.__write_switch = _LightSwitch()
        self.__no_readers = threading.Lock()
        self.__no_writers = threading.Lock()
        self.__readers_queue = threading.Lock()
        self._signal_received = False
        self._old_handler = None

    @property
    def as_reader(self):
        class _reader(object):
            def __init__(self, rwlock):
                self._rwlock = rwlock

            def __enter__(self):
                self._rwlock.reader_acquire()

            def __exit__(self, exc_type, exc_value, trackeback):
                self._rwlock.reader_release()

        return _reader(self)

    @property
    def as_writer(self):
        class _writer(object):
            def __init__(self, rwlock):
                self._rwlock = rwlock

            def __enter__(self):
                self._rwlock.writer_acquire()

            def __exit__(self, exc_type, exc_value, trackeback):
                self._rwlock.writer_release()

        return _writer(self)

    def _signal_handler_start(self):
        if threading.current_thread().__class__.__name__ == "_MainThread":
            # signal handlers can be changed only in the MainThread
            self._signal_received = False
            self._old_handler = signal.signal(signal.SIGINT, self._handler)

    def _signal_handler_end(self):
        if threading.current_thread().__class__.__name__ == "_MainThread":
            signal.signal(signal.SIGINT, self._old_handler)
            if self._signal_received:
                self._old_handler(*self._signal_received)

    def _handler(self, sig, frame):
        self._signal_received = (sig, frame)

    def reader_acquire(self):
        self._signal_handler_start()

        with self.__readers_queue:
            with self.__no_readers:
                self.__read_switch.acquire(self.__no_writers)

    def reader_release(self):
        self.__read_switch.release(self.__no_writers)

        self._signal_handler_end()

    def writer_acquire(self):
        self._signal_handler_start()

        self.__write_switch.acquire(self.__no_readers)
        self.__no_writers.acquire()

    def writer_release(self):
        self.__no_writers.release()
        self.__write_switch.release(self.__no_readers)

        self._signal_handler_end()


class _LightSwitch:
    """An auxiliary "light switch"-like object. The first thread turns on the
    "switch", the last one turns it off (see [1, sec. 4.2.2] for details)."""

    def __init__(self):
        self.__counter = 0
        self.__mutex = threading.Lock()

    def acquire(self, lock):
        with self.__mutex:
            self.__counter += 1
            if self.__counter == 1:
                lock.acquire()

    def release(self, lock):
        with self.__mutex:
            self.__counter -= 1
            if self.__counter == 0:
                lock.release()
