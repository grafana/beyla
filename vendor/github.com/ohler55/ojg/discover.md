# OjG Discover

The `discover` package and **oj** application option will scan a
stream or file for text that could be a JSON or SEN array or object
(map) embedded in the input. The JSON or SEN document must be an array
or object (map). The approach taken is to first look for a starting
character of `{` or `[` and then use a simplified SEN scanner to
determine if the bytes that follow could be part of a SEN document. If
the scan determines all bytes up to a matching closing `}` or `]` then
an attempt is made to parse the bytes as either SEN or JSON. If that
fails the scanner backs up to the starting `{` or `[` and moves
forward one byte and continues scanning for a start byte. This process
continues until the end of the stream or file.

## `discover` package

The discover package includes access to the basic scanner with the
`discover.Find` and `discover.Read` functions. These function takes a
callback that is called for each potential match. The callback can
then determine what to do with the candidate bytes. If it is
determined the text is not parseable as JSON or SEN or for what ever
other reason the callback can return a flag indicating the scanner
should backup to one after the start of the candidate bytes and
continue with the discovery process.

Making use of the basic scanner, `discover.SEN` and `discover.ReadSEN`
attempt to parse any discovered bytes with the `sen` package
parser. On success the callback provided is called. Similarly,
`discover.JSON` and `discover.ReadJSON` attempt to use the `oj`
package parser on the candidate bytes.

## **oj** application

The **oj** application has a `-discover` option that will use the
`discover` package to seearch for candidates and then use then
appropriate parser depending on the whether then `-lazy` option wa
specified.

## Use Cases

Some use cases for the discovery option include working with messaging
tools and markdown text.

### Messaging

My go-to messaging engine is [NATS
JetStream](https://docs.nats.io/nats-concepts/jetstream). JetStream
includes an inspection tool that allows viewing of messages in a
stream. It provides information about each message as well as the
contents of the message. If JSON is being used as the message content
then viewing a stream might look like:

```
> nats stream view quux
[205456] Subject: quux.example Received: 2025-11-11 17:03:44

  Nats-Expected-Stream: quux
{"name":"user-1","level":3,"status":"active"}


[205457] Subject: quux.example Received: 2025-11-11 17:05:04

  Nats-Expected-Stream: quux
{"name":"user-2","level":2,"status":"inactive"}


18:21:48 Reached apparent end of data
```

There is JSON in the output that might be useful to extract and use. By
using **oj** (or the discover package) the JSON is easily extracted.

```
> oj -discover -p 120.4 quux-view.txt
[205456]
{"level": 3, "name": "user-1", "status": "active"}
[205457]
{"level": 2, "name": "user-2", "status": "inactive"}
```

### Markdown

Some markdown or really any text document sometimes include JSON or
Javascript data. With the discover package or option those elements can be
extracted. SEN handles Javascript and other pseudo JSON data fairly
well which opens up some possibilities. As an example use **oj** to
extract the JSON elements in this markdown.

```
> oj -discover -p 120.4 discover.md
```

The results should be then same as for the JetStream example but doubled.

### Summary

The discover feature was created so to aid in processing data from
JetStream and MongoDB dumps. It is also mentioned in discussion
https://github.com/ohler55/ojg/discussions/78.
