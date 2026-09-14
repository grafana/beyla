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
The integration with PostgreSQL supports the `Psycopg`_ library. It can be enabled by
using ``PsycopgInstrumentor``.

.. _Psycopg: https://www.psycopg.org/psycopg3/docs/

Usage
-----

.. code-block:: python

    import psycopg
    from opentelemetry.instrumentation.psycopg import PsycopgInstrumentor

    # Call instrument() to wrap all database connections
    PsycopgInstrumentor().instrument()

    cnx = psycopg.connect(database='Database')

    cursor = cnx.cursor()
    cursor.execute("CREATE TABLE IF NOT EXISTS test (testField INTEGER)")
    cursor.execute("INSERT INTO test (testField) VALUES (123)")
    cursor.close()
    cnx.close()

.. code-block:: python

    import psycopg
    from opentelemetry.instrumentation.psycopg import PsycopgInstrumentor

    # Alternatively, use instrument_connection for an individual connection
    cnx = psycopg.connect(database='Database')
    instrumented_cnx = PsycopgInstrumentor().instrument_connection(cnx)
    cursor = instrumented_cnx.cursor()
    cursor.execute("CREATE TABLE IF NOT EXISTS test (testField INTEGER)")
    cursor.execute("INSERT INTO test (testField) VALUES (123)")
    cursor.close()
    instrumented_cnx.close()


Configuration
-------------

SQLCommenter
************
You can optionally configure Psycopg instrumentation to enable sqlcommenter which enriches
the query with contextual information. Queries made after setting up trace integration with
sqlcommenter enabled will have configurable key-value pairs appended to them, e.g.
``"select * from auth_users; /*traceparent=00-01234567-abcd-01*/"``. This supports context
propagation between database client and server when database log records are enabled.
For more information, see:

* `Semantic Conventions - Database Spans <https://github.com/open-telemetry/semantic-conventions/blob/main/docs/db/database-spans.md#sql-commenter>`_
* `sqlcommenter <https://google.github.io/sqlcommenter/>`_

.. code:: python

    from opentelemetry.instrumentation.psycopg import PsycopgInstrumentor

    PsycopgInstrumentor().instrument(enable_commenter=True)


SQLCommenter with commenter_options
***********************************
The key-value pairs appended to the query can be configured using
``commenter_options``. When sqlcommenter is enabled, all available KVs/tags
are calculated by default. ``commenter_options`` supports *opting out*
of specific KVs.

.. code:: python

    from opentelemetry.instrumentation.psycopg import PsycopgInstrumentor

    # Opts into sqlcomment for Psycopg trace integration.
    # Opts out of tags for libpq_version, db_driver.
    PsycopgInstrumentor().instrument(
        enable_commenter=True,
        commenter_options={
            "libpq_version": False,
            "db_driver": False,
        }
    )

Available commenter_options
###########################

The following sqlcomment key-values can be opted out of through ``commenter_options``:

+---------------------------+-----------------------------------------------------------+---------------------------------------------------------------------------+
| Commenter Option          | Description                                               | Example                                                                   |
+===========================+===========================================================+===========================================================================+
| ``db_driver``             | Database driver name with version.                        | ``psycopg='3.1.9'``                                                       |
+---------------------------+-----------------------------------------------------------+---------------------------------------------------------------------------+
| ``dbapi_threadsafety``    | DB-API threadsafety value: 0-3 or unknown.                | ``dbapi_threadsafety=2``                                                  |
+---------------------------+-----------------------------------------------------------+---------------------------------------------------------------------------+
| ``dbapi_level``           | DB-API API level: 1.0, 2.0, or unknown.                   | ``dbapi_level='2.0'``                                                     |
+---------------------------+-----------------------------------------------------------+---------------------------------------------------------------------------+
| ``driver_paramstyle``     | DB-API paramstyle for SQL statement parameter.            | ``driver_paramstyle='pyformat'``                                          |
+---------------------------+-----------------------------------------------------------+---------------------------------------------------------------------------+
| ``libpq_version``         | PostgreSQL libpq version                                  | ``libpq_version=140001``                                                  |
+---------------------------+-----------------------------------------------------------+---------------------------------------------------------------------------+
| ``opentelemetry_values``  | OpenTelemetry context as traceparent at time of query.    | ``traceparent='00-03afa25236b8cd948fa853d67038ac79-405ff022e8247c46-01'`` |
+---------------------------+-----------------------------------------------------------+---------------------------------------------------------------------------+

SQLComment in span attribute
****************************
If sqlcommenter is enabled, you can opt into the inclusion of sqlcomment in
the query span ``db.statement`` attribute for your needs. If ``commenter_options``
have been set, the span attribute comment will also be configured by this
setting.

.. code:: python

    from opentelemetry.instrumentation.psycopg import PsycopgInstrumentor

    # Opts into sqlcomment for Psycopg trace integration.
    # Opts into sqlcomment for `db.statement` span attribute.
    PsycopgInstrumentor().instrument(
        enable_commenter=True,
        enable_attribute_commenter=True,
    )

Warning:
    Capture of sqlcomment in ``db.statement`` may have high cardinality without platform normalization. See `Semantic Conventions for database spans <https://opentelemetry.io/docs/specs/semconv/database/database-spans/#generating-a-summary-of-the-query-text>`_ for more information.

API
---
"""

from __future__ import annotations

import logging
from typing import Any, Callable, Collection, TypeVar

import psycopg  # pylint: disable=import-self
from psycopg.sql import Composable  # pylint: disable=no-name-in-module

from opentelemetry.instrumentation import dbapi
from opentelemetry.instrumentation.instrumentor import BaseInstrumentor
from opentelemetry.instrumentation.psycopg.package import _instruments
from opentelemetry.instrumentation.psycopg.version import __version__
from opentelemetry.trace import TracerProvider

_logger = logging.getLogger(__name__)
_OTEL_CURSOR_FACTORY_KEY = "_otel_orig_cursor_factory"

ConnectionT = TypeVar(
    "ConnectionT", psycopg.Connection, psycopg.AsyncConnection
)
CursorT = TypeVar("CursorT", psycopg.Cursor, psycopg.AsyncCursor)


class PsycopgInstrumentor(BaseInstrumentor):
    _CONNECTION_ATTRIBUTES = {
        "database": "info.dbname",
        "port": "info.port",
        "host": "info.host",
        "user": "info.user",
    }

    _DATABASE_SYSTEM = "postgresql"

    def instrumentation_dependencies(self) -> Collection[str]:
        return _instruments

    def _instrument(self, **kwargs: Any):
        """Integrate with PostgreSQL Psycopg library.
        Psycopg: http://initd.org/psycopg/
        """
        tracer_provider = kwargs.get("tracer_provider")
        enable_sqlcommenter = kwargs.get("enable_commenter", False)
        commenter_options = kwargs.get("commenter_options", {})
        enable_attribute_commenter = kwargs.get(
            "enable_attribute_commenter", False
        )
        capture_parameters = kwargs.get("capture_parameters", False)
        dbapi.wrap_connect(
            __name__,
            psycopg,
            "connect",
            self._DATABASE_SYSTEM,
            self._CONNECTION_ATTRIBUTES,
            version=__version__,
            tracer_provider=tracer_provider,
            db_api_integration_factory=DatabaseApiIntegration,
            enable_commenter=enable_sqlcommenter,
            commenter_options=commenter_options,
            enable_attribute_commenter=enable_attribute_commenter,
            capture_parameters=capture_parameters,
        )

        dbapi.wrap_connect(
            __name__,
            psycopg.Connection,  # pylint: disable=no-member
            "connect",
            self._DATABASE_SYSTEM,
            self._CONNECTION_ATTRIBUTES,
            version=__version__,
            tracer_provider=tracer_provider,
            db_api_integration_factory=DatabaseApiIntegration,
            enable_commenter=enable_sqlcommenter,
            commenter_options=commenter_options,
            enable_attribute_commenter=enable_attribute_commenter,
            capture_parameters=capture_parameters,
        )
        dbapi.wrap_connect(
            __name__,
            psycopg.AsyncConnection,  # pylint: disable=no-member
            "connect",
            self._DATABASE_SYSTEM,
            self._CONNECTION_ATTRIBUTES,
            version=__version__,
            tracer_provider=tracer_provider,
            db_api_integration_factory=DatabaseApiAsyncIntegration,
            enable_commenter=enable_sqlcommenter,
            commenter_options=commenter_options,
            enable_attribute_commenter=enable_attribute_commenter,
            capture_parameters=capture_parameters,
        )

    def _uninstrument(self, **kwargs: Any):
        """ "Disable Psycopg instrumentation"""
        dbapi.unwrap_connect(psycopg, "connect")  # pylint: disable=no-member
        dbapi.unwrap_connect(
            psycopg.Connection,
            "connect",  # pylint: disable=no-member
        )
        dbapi.unwrap_connect(
            psycopg.AsyncConnection,
            "connect",  # pylint: disable=no-member
        )

    # TODO(owais): check if core dbapi can do this for all dbapi implementations e.g, pymysql and mysql
    @staticmethod
    def instrument_connection(
        connection: ConnectionT, tracer_provider: TracerProvider | None = None
    ) -> ConnectionT:
        """Enable instrumentation in a psycopg connection.

        Args:
            connection: psycopg.Connection
                The psycopg connection object to be instrumented.
            tracer_provider: opentelemetry.trace.TracerProvider, optional
                The TracerProvider to use for instrumentation. If not provided,
                the global TracerProvider will be used.

        Returns:
            An instrumented psycopg connection object.
        """
        if not hasattr(connection, "_is_instrumented_by_opentelemetry"):
            connection._is_instrumented_by_opentelemetry = False

        if not connection._is_instrumented_by_opentelemetry:
            setattr(
                connection, _OTEL_CURSOR_FACTORY_KEY, connection.cursor_factory
            )
            if isinstance(connection, psycopg.AsyncConnection):
                connection.cursor_factory = _new_cursor_async_factory(
                    tracer_provider=tracer_provider
                )
            else:
                connection.cursor_factory = _new_cursor_factory(
                    tracer_provider=tracer_provider
                )
            connection._is_instrumented_by_opentelemetry = True
        else:
            _logger.warning(
                "Attempting to instrument Psycopg connection while already instrumented"
            )
        return connection

    # TODO(owais): check if core dbapi can do this for all dbapi implementations e.g, pymysql and mysql
    @staticmethod
    def uninstrument_connection(connection: ConnectionT) -> ConnectionT:
        connection.cursor_factory = getattr(
            connection, _OTEL_CURSOR_FACTORY_KEY, None
        )

        return connection


# TODO(owais): check if core dbapi can do this for all dbapi implementations e.g, pymysql and mysql
class DatabaseApiIntegration(dbapi.DatabaseApiIntegration):
    def wrapped_connection(
        self,
        connect_method: Callable[..., Any],
        args: tuple[Any, Any],
        kwargs: dict[Any, Any],
    ):
        """Add object proxy to connection object."""
        base_cursor_factory = kwargs.pop("cursor_factory", None)
        new_factory_kwargs = {"db_api": self}
        if base_cursor_factory:
            new_factory_kwargs["base_factory"] = base_cursor_factory
        kwargs["cursor_factory"] = _new_cursor_factory(**new_factory_kwargs)
        connection = connect_method(*args, **kwargs)
        self.get_connection_attributes(connection)
        return connection


class DatabaseApiAsyncIntegration(dbapi.DatabaseApiIntegration):
    async def wrapped_connection(
        self,
        connect_method: Callable[..., Any],
        args: tuple[Any, Any],
        kwargs: dict[Any, Any],
    ):
        """Add object proxy to connection object."""
        base_cursor_factory = kwargs.pop("cursor_factory", None)
        new_factory_kwargs = {"db_api": self}
        if base_cursor_factory:
            new_factory_kwargs["base_factory"] = base_cursor_factory
        kwargs["cursor_factory"] = _new_cursor_async_factory(
            **new_factory_kwargs
        )
        connection = await connect_method(*args, **kwargs)
        self.get_connection_attributes(connection)
        return connection


class CursorTracer(dbapi.CursorTracer):
    def get_operation_name(self, cursor: CursorT, args: list[Any]) -> str:
        if not args:
            return ""

        statement = args[0]
        if isinstance(statement, Composable):
            statement = statement.as_string(cursor)

        # `statement` can be empty string. See #2643
        if statement and isinstance(statement, str):
            # Strip leading comments so we get the operation name.
            return self._leading_comment_remover.sub("", statement).split()[0]

        return ""

    def get_statement(self, cursor: CursorT, args: list[Any]) -> str:
        if not args:
            return ""

        statement = args[0]
        if isinstance(statement, Composable):
            statement = statement.as_string(cursor)
        return statement


def _new_cursor_factory(
    db_api: DatabaseApiIntegration | None = None,
    base_factory: type[psycopg.Cursor] | None = None,
    tracer_provider: TracerProvider | None = None,
):
    if not db_api:
        db_api = DatabaseApiIntegration(
            __name__,
            PsycopgInstrumentor._DATABASE_SYSTEM,
            connection_attributes=PsycopgInstrumentor._CONNECTION_ATTRIBUTES,
            version=__version__,
            tracer_provider=tracer_provider,
        )

    base_factory = base_factory or psycopg.Cursor
    _cursor_tracer = CursorTracer(db_api)

    class TracedCursorFactory(base_factory):
        def execute(self, *args: Any, **kwargs: Any):
            return _cursor_tracer.traced_execution(
                self, super().execute, *args, **kwargs
            )

        def executemany(self, *args: Any, **kwargs: Any):
            return _cursor_tracer.traced_execution(
                self, super().executemany, *args, **kwargs
            )

        def callproc(self, *args: Any, **kwargs: Any):
            return _cursor_tracer.traced_execution(
                self, super().callproc, *args, **kwargs
            )

    return TracedCursorFactory


def _new_cursor_async_factory(
    db_api: DatabaseApiAsyncIntegration | None = None,
    base_factory: type[psycopg.AsyncCursor] | None = None,
    tracer_provider: TracerProvider | None = None,
):
    if not db_api:
        db_api = DatabaseApiAsyncIntegration(
            __name__,
            PsycopgInstrumentor._DATABASE_SYSTEM,
            connection_attributes=PsycopgInstrumentor._CONNECTION_ATTRIBUTES,
            version=__version__,
            tracer_provider=tracer_provider,
        )
    base_factory = base_factory or psycopg.AsyncCursor
    _cursor_tracer = CursorTracer(db_api)

    class TracedCursorAsyncFactory(base_factory):
        async def execute(self, *args: Any, **kwargs: Any):
            return await _cursor_tracer.traced_execution_async(
                self, super().execute, *args, **kwargs
            )

        async def executemany(self, *args: Any, **kwargs: Any):
            return await _cursor_tracer.traced_execution_async(
                self, super().executemany, *args, **kwargs
            )

        async def callproc(self, *args: Any, **kwargs: Any):
            return await _cursor_tracer.traced_execution_async(
                self, super().callproc, *args, **kwargs
            )

    return TracedCursorAsyncFactory
