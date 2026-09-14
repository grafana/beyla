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
The integration with MySQLClient supports the `MySQLClient`_ library and can be enabled
by using ``MySQLClientInstrumentor``.

.. _MySQLClient: https://pypi.org/project/MySQLClient/

Usage
-----

.. code:: python

    import MySQLdb
    from opentelemetry.instrumentation.mysqlclient import MySQLClientInstrumentor

    MySQLClientInstrumentor().instrument()

    cnx = MySQLdb.connect(database="MySQL_Database")
    cursor = cnx.cursor()
    cursor.execute("CREATE TABLE IF NOT EXISTS test (testField INTEGER)")
    cursor.execute("INSERT INTO test (testField) VALUES (123)")
    cnx.commit()
    cursor.close()
    cnx.close()

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

    import MySQLdb
    from opentelemetry.instrumentation.mysqlclient import MySQLClientInstrumentor

    MySQLClientInstrumentor().instrument(enable_commenter=True)

    cnx = MySQLdb.connect(database="MySQL_Database")
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

    import MySQLdb
    from opentelemetry.instrumentation.mysqlclient import MySQLClientInstrumentor

    # Opts into sqlcomment for MySQLClient trace integration.
    # Opts out of tags for mysql_client_version, db_driver.
    MySQLClientInstrumentor().instrument(
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
| ``db_driver``             | Database driver name with version (URL encoded).          | ``MySQLdb%%%%3A1.2.3``                                                    |
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

    from opentelemetry.instrumentation.mysqlclient import MySQLClientInstrumentor

    # Opts into sqlcomment for mysqlclient trace integration.
    # Opts into sqlcomment for `db.statement` span attribute.
    MySQLClientInstrumentor().instrument(
        enable_commenter=True,
        enable_attribute_commenter=True,
    )

Warning:
    Capture of sqlcomment in ``db.statement`` may have high cardinality without platform normalization. See `Semantic Conventions for database spans <https://opentelemetry.io/docs/specs/semconv/database/database-spans/#generating-a-summary-of-the-query-text>`_ for more information.

API
---
"""

from typing import Collection

import MySQLdb

from opentelemetry.instrumentation import dbapi
from opentelemetry.instrumentation.instrumentor import BaseInstrumentor
from opentelemetry.instrumentation.mysqlclient.package import _instruments
from opentelemetry.instrumentation.mysqlclient.version import __version__

_CONNECTION_ATTRIBUTES = {
    "database": "db",
    "port": "port",
    "host": "host",
    "user": "user",
}
_DATABASE_SYSTEM = "mysql"


class MySQLClientInstrumentor(BaseInstrumentor):
    def instrumentation_dependencies(self) -> Collection[str]:  # pylint: disable=no-self-use
        return _instruments

    def _instrument(self, **kwargs):  # pylint: disable=no-self-use
        """Integrate with the mysqlclient library.
        https://github.com/PyMySQL/mysqlclient/
        """
        tracer_provider = kwargs.get("tracer_provider")
        enable_sqlcommenter = kwargs.get("enable_commenter", False)
        commenter_options = kwargs.get("commenter_options", {})
        enable_attribute_commenter = kwargs.get(
            "enable_attribute_commenter", False
        )

        dbapi.wrap_connect(
            __name__,
            MySQLdb,
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
        """ "Disable mysqlclient instrumentation"""
        dbapi.unwrap_connect(MySQLdb, "connect")

    @staticmethod
    def instrument_connection(
        connection,
        tracer_provider=None,
        enable_commenter=None,
        commenter_options=None,
        enable_attribute_commenter=None,
    ):
        """Enable instrumentation in a mysqlclient connection.

        Args:
            connection:
                The MySQL connection instance to instrument. This connection is typically
                created using `MySQLdb.connect()` and needs to be wrapped to collect telemetry.
            tracer_provider:
                A custom `TracerProvider` instance to be used for tracing. If not specified,
                the globally configured tracer provider will be used.
            enable_commenter:
                A flag to enable the OpenTelemetry SQLCommenter feature. If set to `True`,
                SQL queries will be enriched with contextual information (e.g., database client details).
                Default is `None`.
            commenter_options:
                A dictionary of configuration options for SQLCommenter. All options are enabled (True) by default.
                This allows you to customize metadata appended to queries. Possible options include:

                    - `db_driver`: Adds the database driver name and version.
                    - `dbapi_threadsafety`: Adds threadsafety information.
                    - `dbapi_level`: Adds the DB-API version.
                    - `mysql_client_version`: Adds the MySQL client version.
                    - `driver_paramstyle`: Adds the parameter style.
                    - `opentelemetry_values`: Includes traceparent values.
        Returns:
            An instrumented MySQL connection with OpenTelemetry support enabled.
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
            connect_module=MySQLdb,
            enable_attribute_commenter=enable_attribute_commenter,
        )

    @staticmethod
    def uninstrument_connection(connection):
        """Disable instrumentation in a mysqlclient connection.

        Args:
            connection: The connection to uninstrument.

        Returns:
            An uninstrumented connection.
        """
        return dbapi.uninstrument_connection(connection)
