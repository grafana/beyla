# Copyright The OpenTelemetry Authors
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""
SQLite instrumentation supporting `sqlite3`_, it can be enabled by
using ``SQLite3Instrumentor``. At this time, cursor objects must
be explicitly initialized as shown below to support tracing.

.. _sqlite3: https://docs.python.org/3/library/sqlite3.html

Usage
-----

.. code:: python

    import sqlite3
    from opentelemetry.instrumentation.sqlite3 import SQLite3Instrumentor

    # Call instrument() to wrap all database connections
    SQLite3Instrumentor().instrument()

    cnx = sqlite3.connect(':memory:')
    cursor = cnx.cursor()
    cursor.execute("CREATE TABLE IF NOT EXISTS test (testField INTEGER)")
    cursor.execute("INSERT INTO test (testField) VALUES (123)")
    cursor.close()
    cnx.close()

.. code:: python

    import sqlite3
    from opentelemetry.instrumentation.sqlite3 import SQLite3Instrumentor

    # Alternatively, use instrument_connection for an individual connection
    conn = sqlite3.connect(":memory:")
    instrumented_connection = SQLite3Instrumentor().instrument_connection(conn)
    cursor = instrumented_connection.cursor()
    cursor.execute("CREATE TABLE IF NOT EXISTS test (testField INTEGER)")
    cursor.execute("INSERT INTO test (testField) VALUES (123)")
    cursor.execute("SELECT * FROM test")
    cursor.close()
    instrumented_connection.close()

API
---
"""

from __future__ import annotations

import sqlite3
from sqlite3 import dbapi2
from typing import Any, Collection, TypeVar, Union

from opentelemetry.instrumentation import dbapi
from opentelemetry.instrumentation.instrumentor import BaseInstrumentor
from opentelemetry.instrumentation.sqlite3.package import _instruments
from opentelemetry.instrumentation.sqlite3.version import __version__
from opentelemetry.trace import TracerProvider

# No useful attributes of sqlite3 connection object
_CONNECTION_ATTRIBUTES = {}

_DATABASE_SYSTEM = "sqlite"

SQLite3Connection = TypeVar(  # pylint: disable=invalid-name
    "SQLite3Connection", bound=Union[sqlite3.Connection, None]
)


class SQLite3Instrumentor(BaseInstrumentor):
    _TO_WRAP = [sqlite3, dbapi2]

    def instrumentation_dependencies(self) -> Collection[str]:
        return _instruments

    def _instrument(self, **kwargs: Any) -> None:
        """Integrate with SQLite3 Python library.
        https://docs.python.org/3/library/sqlite3.html
        """
        tracer_provider = kwargs.get("tracer_provider")

        for module in self._TO_WRAP:
            dbapi.wrap_connect(
                __name__,
                module,
                "connect",
                _DATABASE_SYSTEM,
                _CONNECTION_ATTRIBUTES,
                version=__version__,
                tracer_provider=tracer_provider,
            )

    def _uninstrument(self, **kwargs: Any) -> None:
        """ "Disable SQLite3 instrumentation"""
        for module in self._TO_WRAP:
            dbapi.unwrap_connect(module, "connect")

    @staticmethod
    def instrument_connection(
        connection: SQLite3Connection,
        tracer_provider: TracerProvider | None = None,
    ) -> SQLite3Connection:
        """Enable instrumentation in a SQLite connection.

        Args:
            connection: The connection to instrument.
            tracer_provider: The optional tracer provider to use. If omitted
                the current globally configured one is used.

        Returns:
            An instrumented SQLite connection that supports
            telemetry for tracing database operations.

        """
        return dbapi.instrument_connection(
            __name__,
            connection,
            _DATABASE_SYSTEM,
            _CONNECTION_ATTRIBUTES,
            version=__version__,
            tracer_provider=tracer_provider,
        )

    @staticmethod
    def uninstrument_connection(
        connection: SQLite3Connection,
    ) -> SQLite3Connection:
        """Disable instrumentation in a SQLite connection.

        Args:
            connection: The connection to uninstrument.

        Returns:
            An uninstrumented connection.
        """
        return dbapi.uninstrument_connection(connection)
