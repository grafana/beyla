// Copyright Sam Xie
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package otelsql

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"errors"
	"strconv"
	"sync"

	"go.opentelemetry.io/otel/metric"
)

var registerLock sync.Mutex

var maxDriverSlot = 1000

// Register initializes and registers OTel wrapped database driver
// identified by its driverName, using provided Option.
// It is possible to register multiple wrappers for the same database driver if
// needing different Option for different connections.
func Register(driverName string, options ...Option) (string, error) {
	// Retrieve the driver implementation we need to wrap with instrumentation
	db, err := sql.Open(driverName, "")
	if err != nil {
		return "", err
	}

	dri := db.Driver()

	if err = db.Close(); err != nil {
		return "", err
	}

	registerLock.Lock()
	defer registerLock.Unlock()

	// Since we might want to register multiple OTel drivers to have different
	// configurations, but potentially the same underlying database driver, we
	// cycle through to find available driver names.
	driverName += "-otelsql-"

	for i := range maxDriverSlot {
		var (
			found   = false
			regName = driverName + strconv.FormatInt(int64(i), 10)
		)

		for _, name := range sql.Drivers() {
			if name == regName {
				found = true
			}
		}

		if !found {
			sql.Register(regName, newDriver(dri, newConfig(options...)))
			return regName, nil
		}
	}

	return "", errors.New("unable to register driver, all slots have been taken")
}

// WrapDriver takes a SQL driver and wraps it with OTel instrumentation.
func WrapDriver(dri driver.Driver, options ...Option) driver.Driver {
	return newDriver(dri, newConfig(options...))
}

// Open is a wrapper over sql.Open with OTel instrumentation.
func Open(driverName, dataSourceName string, options ...Option) (*sql.DB, error) {
	// Retrieve the driver implementation we need to wrap with instrumentation.
	// The dataSourceName is used to bypass the driver's Open method, as some
	// drivers validate the data source name first before actually opening
	// connections.
	// Any connection opened here (usually no connection will be opened) is not
	// used, and it will be closed immediately to prevent leaking connections.
	// Usually, no connection will be opened here if the driver implements
	// the driver.DriverContext interface.
	db, err := sql.Open(driverName, dataSourceName)
	if err != nil {
		return nil, err
	}

	d := db.Driver()

	if err = db.Close(); err != nil {
		return nil, err
	}

	otDriver := newOtDriver(d, newConfig(options...))

	if _, ok := d.(driver.DriverContext); ok {
		connector, err := otDriver.OpenConnector(dataSourceName)
		if err != nil {
			return nil, err
		}

		return sql.OpenDB(connector), nil
	}

	return sql.OpenDB(dsnConnector{dsn: dataSourceName, driver: otDriver}), nil
}

// OpenDB is a wrapper over sql.OpenDB with OTel instrumentation.
func OpenDB(c driver.Connector, options ...Option) *sql.DB {
	d := newOtDriver(c.Driver(), newConfig(options...))
	connector := newConnector(c, d)

	return sql.OpenDB(connector)
}

// RegisterDBStatsMetrics registers sql.DBStats metrics with OTel instrumentation.
// Call Unregister on the returned Registration when the db is no longer used.
func RegisterDBStatsMetrics(db *sql.DB, opts ...Option) (metric.Registration, error) {
	cfg := newConfig(opts...)
	meter := cfg.Meter

	instruments, err := newDBStatsInstruments(meter)
	if err != nil {
		return nil, err
	}

	reg, err := meter.RegisterCallback(func(_ context.Context, observer metric.Observer) error {
		dbStats := db.Stats()

		recordDBStatsMetrics(dbStats, instruments, cfg, observer)

		return nil
	}, instruments.connectionMaxOpen,
		instruments.connectionOpen,
		instruments.connectionWaitTotal,
		instruments.connectionWaitDurationTotal,
		instruments.connectionClosedMaxIdleTotal,
		instruments.connectionClosedMaxIdleTimeTotal,
		instruments.connectionClosedMaxLifetimeTotal)
	if err != nil {
		return nil, err
	}

	return reg, nil
}

func recordDBStatsMetrics(
	dbStats sql.DBStats, instruments *dbStatsInstruments, cfg config, observer metric.Observer,
) {
	observer.ObserveInt64(instruments.connectionMaxOpen,
		int64(dbStats.MaxOpenConnections),
		metric.WithAttributes(cfg.Attributes...),
	)

	// TODO: optimize slice allocation.
	observer.ObserveInt64(instruments.connectionOpen,
		int64(dbStats.InUse),
		metric.WithAttributes(append(cfg.Attributes, connectionStatusKey.String("inuse"))...),
	)
	observer.ObserveInt64(instruments.connectionOpen,
		int64(dbStats.Idle),
		metric.WithAttributes(append(cfg.Attributes, connectionStatusKey.String("idle"))...),
	)

	observer.ObserveInt64(instruments.connectionWaitTotal,
		dbStats.WaitCount,
		metric.WithAttributes(cfg.Attributes...),
	)
	observer.ObserveFloat64(instruments.connectionWaitDurationTotal,
		float64(dbStats.WaitDuration.Nanoseconds())/1e6,
		metric.WithAttributes(cfg.Attributes...),
	)
	observer.ObserveInt64(instruments.connectionClosedMaxIdleTotal,
		dbStats.MaxIdleClosed,
		metric.WithAttributes(cfg.Attributes...),
	)
	observer.ObserveInt64(instruments.connectionClosedMaxIdleTimeTotal,
		dbStats.MaxIdleTimeClosed,
		metric.WithAttributes(cfg.Attributes...),
	)
	observer.ObserveInt64(instruments.connectionClosedMaxLifetimeTotal,
		dbStats.MaxLifetimeClosed,
		metric.WithAttributes(cfg.Attributes...),
	)
}
