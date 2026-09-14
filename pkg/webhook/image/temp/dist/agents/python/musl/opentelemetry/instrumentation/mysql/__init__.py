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
MySQL instrumentation supporting `mysql-connector`_, it can be enabled by
using ``MySQLInstrumentor``.

.. _mysql-connector: https://pypi.org/project/mysql-connector/

Usage
-----

.. code:: python

    import mysql.connector
    from opentelemetry.instrumentation.mysql import MySQLInstrumentor

    # Call instrument() to wrap all database connections
    MySQLInstrumentor().instrument()

    cnx = mysql.connector.connect(database="MySQL_Database")
    cursor = cnx.cursor()
    cursor.execute("CREATE TABLE IF NOT EXISTS test (testField INTEGER)")
    cursor.execute("INSERT INTO test (testField) VALUES (123)")
    cursor.close()
    cnx.close()

.. code:: python

    import mysql.connector
    from opentelemetry.instrumentation.mysql import MySQLInstrumentor

    # Alternatively, use instrument_connection for an individual connection
    cnx = mysql.connector.connect(database="MySQL_Database")
    instrumented_cnx = MySQLInstrumentor().instrument_connection(cnx)
    cursor = instrumented_cnx.cursor()
    cursor.execute("CREATE TABLE IF NOT EXISTS test (testField INTEGER)")
    cursor.execute("INSERT INTO test (testField) VALUES (123)")
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

    import mysql.connector
    from opentelemetry.instrumentation.mysql import MySQLInstrumentor

    MySQLInstrumentor().instrument(enable_commenter=True)

    cnx = mysql.connector.connect(database="MySQL_Database")
    cursor = cnx.cursor()
    cursor.execute("INSERT INTO test (testField) VALUES (123)")
    cursor.close()
    cnx.close()

Warning:
    sqlcommenter for mysql-connector instrumentation should NOT be used if your application initializes cursors with ``prepared=True``, which will natively prepare and execute MySQL statements. Adding sqlcommenting will introduce a severe performance penalty by repeating ``Prepare`` of statements by mysql-connector that are made unique by traceparent in sqlcomment. The penalty does not happen if cursor ``prepared=False`` (default) and instrumentor ``enable_commenter=True``.

SQLCommenter with commenter_options
***********************************
The key-value pairs appended to the query can be configured using
``commenter_options``. When sqlcommenter is enabled, all available KVs/tags
are calculated by default. ``commenter_options`` supports *opting out*
of specific KVs.

.. code:: python

    import mysql.connector
    from opentelemetry.instrumentation.mysql import MySQLInstrumentor

    # Opts into sqlcomment for mysql-connector trace integration.
    # Opts out of tags for mysql_client_version, db_driver.
    MySQLInstrumentor().instrument(
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
| ``db_driver``             | Database driver name with version (URL encoded).          | ``mysql.connector%%%%3A2.2.9``                                            |
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

    from opentelemetry.instrumentation.mysql import MySQLInstrumentor

    # Opts into sqlcomment for mysql-connector trace integration.
    # Opts into sqlcomment for `db.statement` span attribute.
    MySQLInstrumentor().instrument(
        enable_commenter=True,
        enable_attribute_commenter=True,
    )

Warning:
    Capture of sqlcomment in ``db.statement`` may have high cardinality without platform normalization. See `Semantic Conventions for database spans <https://opentelemetry.io/docs/specs/semconv/database/database-spans/#generating-a-summary-of-the-query-text>`_ for more information.

API
---
"""

from typing import Collection

import mysql.connector

from opentelemetry.instrumentation import dbapi
from opentelemetry.instrumentation.instrumentor import BaseInstrumentor
from opentelemetry.instrumentation.mysql.package import _instruments
from opentelemetry.instrumentation.mysql.version import __version__


class MySQLInstrumentor(BaseInstrumentor):
    _CONNECTION_ATTRIBUTES = {
        "database": "database",
        "port": "server_port",
        "host": "server_host",
        "user": "user",
    }

    _DATABASE_SYSTEM = "mysql"

    def instrumentation_dependencies(self) -> Collection[str]:
        return _instruments

    def _instrument(self, **kwargs):
        """Integrate with MySQL Connector/Python library.
        https://dev.mysql.com/doc/connector-python/en/
        """
        tracer_provider = kwargs.get("tracer_provider")
        enable_sqlcommenter = kwargs.get("enable_commenter", False)
        commenter_options = kwargs.get("commenter_options", {})
        enable_attribute_commenter = kwargs.get(
            "enable_attribute_commenter", False
        )

        dbapi.wrap_connect(
            __name__,
            mysql.connector,
            "connect",
            self._DATABASE_SYSTEM,
            self._CONNECTION_ATTRIBUTES,
            version=__version__,
            tracer_provider=tracer_provider,
            enable_commenter=enable_sqlcommenter,
            commenter_options=commenter_options,
            enable_attribute_commenter=enable_attribute_commenter,
        )

    def _uninstrument(self, **kwargs):
        """ "Disable MySQL instrumentation"""
        dbapi.unwrap_connect(mysql.connector, "connect")

    # pylint:disable=no-self-use
    def instrument_connection(
        self,
        connection,
        tracer_provider=None,
        enable_commenter=None,
        commenter_options=None,
        enable_attribute_commenter=None,
    ):
        """Enable instrumentation in a MySQL connection.

        Args:
            connection:
                The existing MySQL connection instance to instrument. This connection is typically
                obtained through `mysql.connector.connect()` and is instrumented to collect telemetry
                data about database interactions.
            tracer_provider:
                An optional `TracerProvider` instance to use for tracing. If not provided, the globally
                configured tracer provider will be automatically used.
            enable_commenter:
                Optional flag to enable/disable sqlcommenter (default False).
            commenter_options:
                Optional configurations for tags to be appended at the sql query.
            enable_attribute_commenter:
                Optional flag to enable/disable addition of sqlcomment to span attribute (default False). Requires enable_commenter=True.

        Returns:
            An instrumented MySQL connection with OpenTelemetry tracing enabled.
        """
        return dbapi.instrument_connection(
            __name__,
            connection,
            self._DATABASE_SYSTEM,
            self._CONNECTION_ATTRIBUTES,
            version=__version__,
            tracer_provider=tracer_provider,
            enable_commenter=enable_commenter,
            commenter_options=commenter_options,
            connect_module=mysql.connector,
            enable_attribute_commenter=enable_attribute_commenter,
        )

    def uninstrument_connection(self, connection):
        """Disable instrumentation in a MySQL connection.

        Args:
            connection: The connection to uninstrument.

        Returns:
            An uninstrumented connection.
        """
        return dbapi.uninstrument_connection(connection)
