package config

import (
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"testing"
)

func TestConvert(t *testing.T) {
	t.Run("same basic type", func(t *testing.T) {
		d := 0
		require.NoError(t, Convert(1, &d, nil))
		assert.Equal(t, 1, d)
	})
	t.Run("convertible basic type", func(t *testing.T) {
		d := uint16(0)
		require.NoError(t, Convert(uint8(3), &d, nil))
		assert.Equal(t, uint16(3), d)
	})
	t.Run("string", func(t *testing.T) {
		d := ""
		require.NoError(t, Convert("foo", &d, nil))
		assert.Equal(t, "foo", d)
	})
	t.Run("same struct type", func(t *testing.T) {
		d := Foo{}
		require.NoError(t, Convert(Foo{Str: "foo", Num: 1, OtherNum: 2}, &d, nil))
		assert.Equal(t, Foo{Str: "foo", Num: 1, OtherNum: 2}, d)
	})
	t.Run("different struct type with equivalent fields", func(t *testing.T) {
		d := Bar{}
		require.NoError(t, Convert(Foo{Str: "foo", Num: 1, OtherNum: 2}, &d, nil))
		assert.Equal(t, Bar{Str: "foo", Num: 1, OtherNum: 2}, d)
	})
	t.Run("inner struct type", func(t *testing.T) {
		d := TheFoo{}
		require.NoError(t, Convert(TheFoo{
			Hiya: true, Foo: Foo{Str: "foo", Num: 1, OtherNum: 2},
		}, &d, nil))
		assert.Equal(t, TheFoo{
			Hiya: true, Foo: Foo{Str: "foo", Num: 1, OtherNum: 2},
		}, d)
	})
	t.Run("different struct type with invoker hints", func(t *testing.T) {
		d := TheBae{}
		require.NoError(t, Convert(TheFoo{
			Hiya: true, Foo: Foo{Str: "foo", Num: 1, OtherNum: 2},
		}, &d, map[string]string{
			".Hello": "Hiya",
			".Foo.AnotherNum": "OtherNum",
			".Foo.AStr": "Str",
		}))
		assert.Equal(t, TheBae{
			Hello: true, Foo: Bae{Num: 1, AnotherNum: 2, AStr: "foo"},
		}, d)
	})
	t.Run("different struct type with invoker hints and nillable pointers", func(t *testing.T) {
		d := ThePtrBae{}
		require.NoError(t, Convert(ThePtrFoo{
			Hiya: true, Foo: &Foo{Str: "foo", Num: 1, OtherNum: 2},
		}, &d, map[string]string{
			".Hello": "Hiya",
			".Bae": "Foo",
			".Bae.AnotherNum": "OtherNum",
			".Bae.AStr": "Str",
		}))
		assert.Equal(t, ThePtrBae{
			Hello: true, Bae: &Bae{Num: 1, AnotherNum: 2, AStr: "foo"},
		}, d)
	})
}

func TestError(t *testing.T) {
	t.Run("different struct type without all the invoker hints", func(t *testing.T) {
		d := TheBae{}
		require.Error(t, Convert(TheFoo{
			Hiya: true, Foo: Foo{Str: "foo", Num: 1, OtherNum: 2},
		}, &d, map[string]string{
			".Hello": "Hiya",
			".Foo.AStr": "Str",
		}))
	})
}

type Foo struct {
	Str      string
	Num      int
	OtherNum int8
}

type Bar struct {
	Num      int
	OtherNum int
	Str      string
}

type Bae struct {
	Num        int
	AnotherNum int32
	AStr       string
}

type TheFoo struct {
	Hiya bool
	Foo  Foo
}

type TheBae struct {
	Hello bool
	Foo   Bae
}

type ThePtrFoo struct {
	Hiya bool
	Foo  *Foo
}

type ThePtrBae struct {
	Hello bool
	Bae   *Bae
}