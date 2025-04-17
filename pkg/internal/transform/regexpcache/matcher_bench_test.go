package regexpcache

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"
)

var (
	postgresTablePatterns = []string{
		`^users$`,
		`^user_[0-9]+_profiles$`,
		`^logs_[0-9]{4}_[0-9]{2}$`, // logs_YYYY_MM
		`^transactions_[a-z]+$`,
		`^temp_.+$`,
		`^archive_.*$`,
		`^[a-z]+_history$`,
		`^[a-z_]+_backup$`,
		`^data_[0-9]{8}$`,          // data_YYYYMMDD
		`^[a-z]+_[0-9]{6}_[a-z]+$`, // prefix_YYMMDD_suffix
	}

	matchingTableNames = []string{
		"users",
		"user_123_profiles",
		"logs_2023_10",
		"transactions_orders",
		"temp_session_data",
		"archive_2022",
		"price_history",
		"customer_backup",
		"data_20231015",
		"report_231015_summary",
	}

	nonMatchingTableNames = []string{
		"invalid_table",
		"123numbers",
		"UPPERCASE",
		"no_match_here",
		"system$tables",
	}

	defaultCtx = context.Background()
)

func BenchmarkMatch_SingleThread_WithoutCache(b *testing.B) {
	m, err := NewMatcher(Config{
		ParallelMatches: 1,
		CacheSize:       1,
	}, postgresTablePatterns)
	require.NoError(b, err)

	tableNames := append(matchingTableNames, nonMatchingTableNames...)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		name := tableNames[i%len(tableNames)]
		m.Match(defaultCtx, name)
	}
}

func BenchmarkMatch_SingleThread_WithCache(b *testing.B) {
	m, err := NewMatcher(Config{
		ParallelMatches: 1,
		CacheSize:       10,
	}, postgresTablePatterns)
	require.NoError(b, err)

	tableNames := append(matchingTableNames, nonMatchingTableNames...)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		name := tableNames[i%len(tableNames)]
		m.Match(defaultCtx, name)
	}
}

func BenchmarkMatch_MultiThread_WithoutCache(b *testing.B) {
	m, err := NewMatcher(Config{
		ParallelMatches: 5,
		CacheSize:       1,
	}, postgresTablePatterns)
	require.NoError(b, err)

	tableNames := append(matchingTableNames, nonMatchingTableNames...)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		name := tableNames[i%len(tableNames)]
		m.Match(defaultCtx, name)
	}
}

func BenchmarkMatch_MultiThread_WithCache(b *testing.B) {
	m, err := NewMatcher(Config{
		ParallelMatches: 5,
		CacheSize:       10,
	}, postgresTablePatterns)
	require.NoError(b, err)

	tableNames := append(matchingTableNames, nonMatchingTableNames...)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		name := tableNames[i%len(tableNames)]
		m.Match(defaultCtx, name)
	}
}

func BenchmarkMatch_MultiThread_WithBigCache(b *testing.B) {
	m, err := NewMatcher(Config{
		ParallelMatches: 5,
		CacheSize:       20,
	}, postgresTablePatterns)
	require.NoError(b, err)

	tableNames := append(matchingTableNames, nonMatchingTableNames...)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		name := tableNames[i%len(tableNames)]
		m.Match(defaultCtx, name)
	}
}

func BenchmarkMatch_NoMatches(b *testing.B) {
	m, err := NewMatcher(Config{
		ParallelMatches: 3,
		CacheSize:       2,
	}, postgresTablePatterns)
	require.NoError(b, err)

	tableNames := nonMatchingTableNames

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		name := tableNames[i%len(tableNames)]
		m.Match(defaultCtx, name)
	}
}
