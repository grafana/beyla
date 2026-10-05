// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

/*
Package winmd implements a parser for Windows Metadata (WinMD).
The reference document is ECMA-335 6th edition,
which can be located at https://www.ecma-international.org/wp-content/uploads/ECMA-335_6th_edition_june_2012.pdf.

Documentation and comments referencing an ECMA-335 section are prefixed with the symbol §.
*/
package winmd

// Flag, attribute, and enum String methods use locally generated, checked-in
// lookup tables.

//go:generate go run ./internal/genlayout
//go:generate go run ./internal/genflags
