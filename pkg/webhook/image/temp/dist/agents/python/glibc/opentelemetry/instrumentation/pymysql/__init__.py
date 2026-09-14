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
The integration with PyMySQL supports the `PyMySQL`_ library and can be enabled
by using ``PyMySQLInstrumentor``.

.. _PyMySQL: https://pypi.org/project/PyMySQL/

Usage
-----

.. code:: python

    import pymysql
    from opentelemetry.instrumentation.pymysql import PyMySQLInstrumentor

    # Call instrument() to wrap all database connections
    PyMySQLInstrumentor().instrument()

    cnx = pymysql.connect(database="MySQL_Database")
    cursor = cnx.cursor()
    cursor.execute("CREATE TABLE IF NOT EXISTS test (testField INTEGER)")
    cursor.execute("INSERT INTO test (testField) VALUES (123)")
    cnx.commit()
    cursor.close()
    cnx.close()

.. code:: python

    import pymysql
    from opentelemetry.instrumentation.pymysql import PyMySQLInstrumentor

    # Alternatively, use instrument_connection for an individual connection
    cnx = pymysql.connect(database="MySQL_Database")
    instrumented_cnx = PyMySQLInstrumentor().instrument_connection(
        cnx,
        enable_commenter=True,
        commenter_options={
            "db_driver": True,
            "mysql_client_version": True
        }
    )
    cursor = instrumented_cnx.cursor()
    cursor.execute("CREATE TABLE IF NOT EXISTS test (testField INTEGER)")
    cursor.execute("INSERT INTO test (testField) VALUES (123)")
    instrumented_cnx.commit()
    cursor.close()
    instrumented_cnx.close()

Configuration
-------------

SQLCommenter
************
You can optionally enable sqlcommenter which enriches the query with contextual
information. Queries made after setting up trace integration with sqlcommenter
enabled will have configurable key-value pairs appended to them, e.g.
``"select * from auth_users; /*traceparent=00-01234567-abcd-01*/"``. This
supports context propagation between database client and server when database log
records are enabled. For more information, see:

* `Semantic Conventions - Database Spans <https://github.com/open-telemetry/semantic-conventions/blob/main/docs/db/database-spans.md#sql-commenter>`_
* `sqlcommenter <https://google.github.io/sqlcommenter/>`_

.. code:: python

    import pymysql
    from opentelemetry.instrumentation.pymysql import PyMySQLInstrumentor

    PyMySQLInstrumentor().instrument(enable_commenter=True)

    cnx = pymysql.connect(database="MySQL_Database")
    cursor = cnx.cursor()
    cursor.execute("CREATE TABLE IF NOT EXISTS test (testField INTEGER)")
    cursor.execute("INSERT INTO test (testField) VALUES (123)")
    cnx.commit()
    cursor.close()
    cnx.close()

SQLCommenter with commenter_options
***********************************
The key-value pairs appended to the query can be configured using
``commenter_options``. When sqlcommenter is enabled, all available KVs/tags
are calculated by default. ``commenter_options`` supports *opting out*
of specific KVs.

.. code:: python

    import pymysql
    from opentelemetry.instrumentation.pymysql import PyMySQLInstrumentor

    # Opts into sqlcomment for PyMySQL trace integration.
    # Opts out of tags for mysql_client_version, db_driver.
    PyMySQLInstrumentor().instrument(
        enable_commenter=True,
        commenter_options={
            "mysql_client_version": False,
            "db_driver": False,
        }
    )

Available commenter_options
###########################

The following sqlcomment key-values can be opted out of through ``commenter_options``:

+---------------------------+-----------------------------------------------------------+---------------------------------------------------------------------------+
| Commenter Option          | Description                                               | Example                                                                   |
+===========================+===========================================================+===========================================================================+
| ``db_driver``             | Database driver name with version.                        | ``pymysql='1.2.3'``                                                       |
+---------------------------+-----------------------------------------------------------+---------------------------------------------------------------------------+
| ``dbapi_threadsafety``    | DB-API threadsafety value: 0-3 or unknown.                | ``dbapi_threadsafety=2``                                                  |
+---------------------------+-----------------------------------------------------------+---------------------------------------------------------------------------+
| ``dbapi_level``           | DB-API API level: 1.0, 2.0, or unknown.                   | ``dbapi_level='2.0'``                                                     |
+---------------------------+-----------------------------------------------------------+---------------------------------------------------------------------------+
| ``driver_paramstyle``     | DB-API paramstyle for SQL statement parameter.            | ``driver_paramstyle='pyformat'``                                          |
+---------------------------+-----------------------------------------------------------+---------------------------------------------------------------------------+
| ``mysql_client_version``  | MySQL client version.                                     | ``mysql_client_version='123'``                                            |
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

    from opentelemetry.instrumentation.pymysql import PyMySQLInstrumentor

    # Opts into sqlcomment for PyMySQL trace integration.
    # Opts into sqlcomment for `db.statement` span attribute.
    PyMySQLInstrumentor().instrument(
        enable_commenter=True,
        enable_attribute_commenter=True,
    )

Warning:
    Capture of sqlcomment in ``db.statement`` may have high cardinality without platform normalization. See `Semantic Conventions for database spans <https://opentelemetry.io/docs/specs/semconv/database/database-spans/#generating-a-summary-of-the-query-text>`_ for more information.

API
---
"""

from typing import Collection

import pymysql

from opentelemetry.instrumentation import dbapi
from opentelemetry.instrumentation.instrumentor import BaseInstrumentor
from opentelemetry.instrumentation.pymysql.package import _instruments
from opentelemetry.instrumentation.pymysql.version import __version__

_CONNECTION_ATTRIBUTES = {
    "database": "db",
    "port": "port",
    "host": "host",
    "user": "user",
}
_DATABASE_SYSTEM = "mysql"


class PyMySQLInstrumentor(BaseInstrumentor):
    def instrumentation_dependencies(self) -> Collection[str]:  # pylint: disable=no-self-use
        return _instruments

    def _instrument(self, **kwargs):  # pylint: disable=no-self-use
        """Integrate with the PyMySQL library.
        https://github.com/PyMySQL/PyMySQL/
        """
        tracer_provider = kwargs.get("tracer_provider")
        enable_sqlcommenter = kwargs.get("enable_commenter", False)
        commenter_options = kwargs.get("commenter_options", {})
        enable_attribute_commenter = kwargs.get(
            "enable_attribute_commenter", False
        )

        dbapi.wrap_connect(
            __name__,
            pymysql,
            "connect",
            _DATABASE_SYSTEM,
            _CONNECTION_ATTRIBUTES,
            version=__version__,
            tracer_provider=tracer_provider,
            enable_commenter=enable_sqlcommenter,
            commenter_options=commenter_options,
            enable_attribute_commenter=enable_attribute_commenter,
        )

    def _uninstrument(self, **kwargs):  # pylint: disable=no-self-use
        """ "Disable PyMySQL instrumentation"""
        dbapi.unwrap_connect(pymysql, "connect")

    @staticmethod
    def instrument_connection(
        connection,
        tracer_provider=None,
        enable_commenter=None,
        commenter_options=None,
        enable_attribute_commenter=None,
    ):
        """Enable instrumentation in a PyMySQL connection.

        Args:
            connection:
                The existing PyMySQL connection instance that needs to be instrumented.
                This connection was typically created using `pymysql.connect()` and is wrapped with OpenTelemetry tracing.
            tracer_provider:
                An optional `TracerProvider` instance that specifies which tracer provider should be used.
                If not provided, the globally configured OpenTelemetry tracer provider is automatically applied.
            enable_commenter:
                A flag to enable the SQL Commenter feature. If `True`, query logs will be enriched with additional
                contextual metadata (e.g., database version, traceparent IDs, driver information).
            commenter_options:
                A dictionary containing configuration options for the SQL Commenter feature.
                You can specify various options, such as enabling driver information, database version logging,
                traceparent propagation, and other customizable metadata enhancements.
                See *SQLCommenter Configurations* above for more information.
        Returns:
            An instrumented connection.
        """

        return dbapi.instrument_connection(
            __name__,
            connection,
            _DATABASE_SYSTEM,
            _CONNECTION_ATTRIBUTES,
            version=__version__,
            tracer_provider=tracer_provider,
            enable_commenter=enable_commenter,
            commenter_options=commenter_options,
            connect_module=pymysql,
            enable_attribute_commenter=enable_attribute_commenter,
        )

    @staticmethod
    def uninstrument_connection(connection):
        """Disable instrumentation in a PyMySQL connection.

        Args:
            connection: The connection to uninstrument.

        Returns:
            An uninstrumented connection.
        """
        return dbapi.uninstrument_connection(connection)
