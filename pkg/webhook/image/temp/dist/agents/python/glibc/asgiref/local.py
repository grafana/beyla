import asyncio
import contextlib
import contextvars
import threading
from typing import Any, Union


class _Storage:
    """Thread-tagged storage for a non-thread-critical ``Local``.

    The data is tagged with the identity of the thread that owns it. This lets
    ``_CVar`` ignore data that leaked into an unrelated thread.

    Python 3.14 added ``sys.flags.thread_inherit_context``, which is enabled by
    default on free-threaded builds. When set, a new thread starts with a copy
    of the spawning thread's context instead of an empty one, so the contextvar
    backing a ``Local`` would otherwise be visible in any thread spawned from
    one that had set it -- breaking the documented "thread-local in sync
    threads" behaviour. asgiref re-homes the storage to the current thread at
    the points where it *intentionally* moves work between threads (see
    ``asgiref.sync._restore_context``); data merely inherited by an unrelated
    thread is never re-homed and so stays isolated.
    """

    __slots__ = ("thread_id", "data")

    def __init__(self, thread_id: int, data: dict[str, Any]) -> None:
        self.thread_id = thread_id
        self.data = data


def _rehome(storage: "_Storage") -> "_Storage":
    """Return a copy of *storage* owned by the current thread."""
    return _Storage(threading.get_ident(), storage.data)


class _CVar:
    """Storage utility for Local."""

    def __init__(self) -> None:
        self._data: "contextvars.ContextVar[_Storage]" = contextvars.ContextVar(
            "asgiref.local"
        )

    def _storage(self) -> "_Storage":
        # Only return storage that belongs to the current thread. Storage with
        # a different thread id was inherited by this thread (rather than
        # intentionally moved here by asgiref) and must not be visible.
        storage = self._data.get(None)
        if storage is None or storage.thread_id != threading.get_ident():
            return _Storage(threading.get_ident(), {})
        return storage

    def __getattr__(self, key):
        try:
            return self._storage().data[key]
        except KeyError:
            raise AttributeError(f"{self!r} object has no attribute {key!r}")

    def __setattr__(self, key: str, value: Any) -> None:
        if key == "_data":
            return super().__setattr__(key, value)

        data = self._storage().data.copy()
        data[key] = value
        self._data.set(_Storage(threading.get_ident(), data))

    def __delattr__(self, key: str) -> None:
        data = self._storage().data.copy()
        if key in data:
            del data[key]
            self._data.set(_Storage(threading.get_ident(), data))
        else:
            raise AttributeError(f"{self!r} object has no attribute {key!r}")


class Local:
    """Local storage for async tasks.

    This is a namespace object (similar to `threading.local`) where data is
    also local to the current async task (if there is one).

    In async threads, local means in the same sense as the `contextvars`
    module - i.e. a value set in an async frame will be visible:

    - to other async code `await`-ed from this frame.
    - to tasks spawned using `asyncio` utilities (`create_task`, `wait_for`,
      `gather` and probably others).
    - to code scheduled in a sync thread using `sync_to_async`

    In "sync" threads (a thread with no async event loop running), the
    data is thread-local, but additionally shared with async code executed
    via the `async_to_sync` utility, which schedules async code in a new thread
    and copies context across to that thread.

    If `thread_critical` is True, then the local will only be visible per-thread,
    behaving exactly like `threading.local` if the thread is sync, and as
    `contextvars` if the thread is async. This allows genuinely thread-sensitive
    code (such as DB handles) to be kept strictly to their initial thread and
    disable the sharing across `sync_to_async` and `async_to_sync` wrapped calls.

    Unlike plain `contextvars` objects, this utility is threadsafe.
    """

    def __init__(self, thread_critical: bool = False) -> None:
        self._thread_critical = thread_critical
        self._thread_lock = threading.RLock()

        self._storage: "Union[threading.local, _CVar]"

        if thread_critical:
            # Thread-local storage
            self._storage = threading.local()
        else:
            # Contextvar storage
            self._storage = _CVar()

    @contextlib.contextmanager
    def _lock_storage(self):
        # Thread safe access to storage
        if self._thread_critical:
            is_async = True
            try:
                # this is a test for are we in a async or sync
                # thread - will raise RuntimeError if there is
                # no current loop
                asyncio.get_running_loop()
            except RuntimeError:
                is_async = False
            if not is_async:
                # We are in a sync thread, the storage is
                # just the plain thread local (i.e, "global within
                # this thread" - it doesn't matter where you are
                # in a call stack you see the same storage)
                yield self._storage
            else:
                # We are in an async thread - storage is still
                # local to this thread, but additionally should
                # behave like a context var (is only visible with
                # the same async call stack)

                # Ensure context exists in the current thread
                if not hasattr(self._storage, "cvar"):
                    self._storage.cvar = _CVar()

                # self._storage is a thread local, so the members
                # can't be accessed in another thread (we don't
                # need any locks)
                yield self._storage.cvar
        else:
            # Lock for thread_critical=False as other threads
            # can access the exact same storage object
            with self._thread_lock:
                yield self._storage

    def __getattr__(self, key):
        with self._lock_storage() as storage:
            return getattr(storage, key)

    def __setattr__(self, key, value):
        if key in ("_local", "_storage", "_thread_critical", "_thread_lock"):
            return super().__setattr__(key, value)
        with self._lock_storage() as storage:
            setattr(storage, key, value)

    def __delattr__(self, key):
        with self._lock_storage() as storage:
            delattr(storage, key)
