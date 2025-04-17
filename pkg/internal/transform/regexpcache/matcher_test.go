package regexpcache

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestNewMatcher(t *testing.T) {
	t.Parallel()

	var (
		validPatterns   = []string{`^users$`, `^temp_.+$`}
		invalidPatterns = []string{`^users$`, `**`}
	)

	type args struct {
		config   Config
		patterns []string
	}

	testcases := []struct {
		name     string
		args     args
		checkRes func(r *require.Assertions, m *matcher)
		checkErr func(r *require.Assertions, err error)
	}{
		{
			name: "successfully created a matcher",
			args: args{
				config: Config{
					ParallelMatches: 5,
					CacheSize:       100,
				},
				patterns: validPatterns,
			},
			checkRes: func(r *require.Assertions, m *matcher) {
				r.NotNil(m)
			},
			checkErr: func(r *require.Assertions, err error) {
				r.NoError(err)
			},
		},
		{
			name: "error with negative parallel matches",
			args: args{
				config: Config{
					ParallelMatches: -1,
					CacheSize:       100,
				},
				patterns: validPatterns,
			},
			checkRes: func(r *require.Assertions, m *matcher) {
				r.Nil(m)
			},
			checkErr: func(r *require.Assertions, err error) {
				r.ErrorIs(err, errNegativeParallelMatches)
			},
		},
		{
			name: "error with negative cache size",
			args: args{
				config: Config{
					ParallelMatches: 5,
					CacheSize:       -1,
				},
				patterns: validPatterns,
			},
			checkRes: func(r *require.Assertions, m *matcher) {
				r.Nil(m)
			},
			checkErr: func(r *require.Assertions, err error) {
				r.ErrorIs(err, errInvalidCacheSize)
			},
		},
		{
			name: "error with zero cache size",
			args: args{
				config: Config{
					ParallelMatches: 5,
					CacheSize:       0,
				},
				patterns: validPatterns,
			},
			checkRes: func(r *require.Assertions, m *matcher) {
				r.Nil(m)
			},
			checkErr: func(r *require.Assertions, err error) {
				r.ErrorIs(err, errInvalidCacheSize)
			},
		},
		{
			name: "error with invalid patterns",
			args: args{
				config: Config{
					ParallelMatches: 5,
					CacheSize:       100,
				},
				patterns: invalidPatterns,
			},
			checkRes: func(r *require.Assertions, m *matcher) {
				r.Nil(m)
			},
			checkErr: func(r *require.Assertions, err error) {
				r.Error(err)
				r.ErrorContains(err, "failed to compile pattern **")
			},
		},
	}

	for _, tt := range testcases {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			r := require.New(t)

			m, err := NewMatcher(tt.args.config, tt.args.patterns)
			tt.checkRes(r, m)
			tt.checkErr(r, err)
		})
	}
}

func TestMatch(t *testing.T) {
	t.Parallel()

	var (
		defaultCtx   = context.Background()
		cancelledCtx = func() context.Context {
			ctx, cancel := context.WithCancel(defaultCtx)
			cancel()
			return ctx
		}
		validPatterns = []string{
			`^[a-z]+_[0-9]{4}$`,            // word_YYYY
			`^[a-z]{2,10}-[0-9]{1,5}$`,     // alpha-num
			`^[A-Z][a-z]+_[A-Z]{2,4}$`,     // CamelCase_ABC
			`^[0-9]{3}-[a-z]{3}-[0-9]{3}$`, // 123-abc-456
			`^[a-z]+_[a-z]+_[0-9]{8}$`,     // table_part_YYYYMMDD
			`^[a-z]+_v[0-9]{1,2}$`,         // table_v1
			`^[a-z]+_bk_[0-9]{12}$`,        // backup tables
			`^[a-z]+_arch_[0-9]{6}$`,       // archive tables
		}
	)

	type args struct {
		ctx      context.Context
		input    string
		config   Config
		patterns []string
	}

	testcases := []struct {
		name     string
		args     args
		expected bool
	}{
		{
			name: "successfully matched pattern",
			args: args{
				ctx:   defaultCtx,
				input: "events_2023",
				config: Config{
					ParallelMatches: 3,
					CacheSize:       3,
				},
				patterns: validPatterns,
			},
			expected: true,
		},
		{
			name: "no match",
			args: args{
				ctx:   defaultCtx,
				input: "invalid_table",
				config: Config{
					ParallelMatches: 3,
					CacheSize:       3,
				},
				patterns: validPatterns,
			},
			expected: false,
		},
		{
			name: "cancelled ctx",
			args: args{
				ctx:   cancelledCtx(),
				input: "users",
				config: Config{
					ParallelMatches: 3,
					CacheSize:       3,
				},
				patterns: validPatterns,
			},
			expected: false,
		},
	}

	for _, tt := range testcases {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			r := require.New(t)

			m, err := NewMatcher(tt.args.config, tt.args.patterns)
			r.NoError(err)

			actual := m.Match(tt.args.ctx, tt.args.input)
			r.Equal(tt.expected, actual)
		})
	}
}
