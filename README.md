# HashidsCore

This is a fork of [hashids](https://github.com/ullmark/hashids.net) ported to .NetStandard, original version was developed by Markus Ullmark.

A small .NET package to generate YouTube-like hashes from one or many numbers. 
Use hashids when you do not want to expose your database ids to the user.

[http://www.hashids.org/net/](http://www.hashids.org/net/)

## What is it?

hashids (Hash ID's) creates short, unique, decryptable hashes from unsigned integers.

_(NOTE: This is **NOT** a true cryptographic hash, since it is reversible)_

It was designed for websites to use in URL shortening, tracking stuff, or 
making pages private (or at least unguessable).

This algorithm tries to satisfy the following requirements:

1. Hashes must be unique and decryptable.
2. They should be able to contain more than one integer (so you can use them in complex or clustered systems).
3. You should be able to specify minimum hash length.
4. Hashes should not contain basic English curse words (since they are meant to appear in public places - like the URL).

Instead of showing items as `1`, `2`, or `3`, you could show them as `U6dc`, `u87U`, and `HMou`.
You don't have to store these hashes in the database, but can encrypt + decrypt on the fly.

All integers need to be greater than or equal to zero.

## Installation
Install the package with [NuGet][]

    Install-Package hashidscore.net

## Usage

### Import namespace

```C#
using HashidsNet;
```

### Encoding one number

You can pass a unique salt value so your hashes differ from everyone else's. I use "**this is my salt**" as an example.

```C#
var hashids = new Hashids("this is my salt");
var hash = hashids.Encode(12345);
```

`hash` is now going to be:

    NkK9

If your id is stored as a `Int64` you need to use "EncodeLong".

```C#
var hashids = new Hashids("this is my salt");
var hash = hashids.EncodeLong(666555444333222L);
```

`hash` is now going to be:

    KVO9yy1oO5j

### Decoding

Notice during decoding, same salt value is used:

```C#
var hashids = new Hashids("this is my salt");
numbers = hashids.Decode("NkK9");
```

`numbers` is now going to be:

    [ 12345 ]

```C#
var hashids = new Hashids("this is my salt");
numbers = hashids.DecodeLong("KVO9yy1oO5j");
```

`numbers` is now going to be:

    [ 666555444333222L ]

### Decoding with different salt

Decoding will not work if salt is changed:

```C#
var hashids = new Hashids("this is my pepper");
numbers = hashids.Decode("NkK9");
```

`numbers` is now going to be:

    []

### Encoding several numbers

```C#
var hashids = new Hashids("this is my salt");
var hash = hashids.Encode(683, 94108, 123, 5);
```

`hash` is now going to be:

    aBMswoO2UB3Sj

### Decoding is done the same way

```C#
var hashids = new Hashids("this is my salt");
var numbers = hashids.Decode("aBMswoO2UB3Sj")
```

`numbers` is now going to be:

    [ 683, 94108, 123, 5 ]

### Encoding and specifying minimum hash length

Here we encode integer 1, and set the minimum hash length to **8** (by default it's **0** -- meaning hashes will be the shortest possible length).

```C#
var hashids = new Hashids("this is my salt", 8);
var hash = hashids.Encode(1);
```

`hash` is now going to be:

    gB0NV05e

### Decoding 

```C#
var hashids = new Hashids("this is my salt", 8);
var numbers = hashids.Decode("gB0NV05e");
```

`numbers` is now going to be:

    [ 1 ]

### Specifying custom hash alphabet

Here we set the alphabet to consist of: "abcdefghijkABCDEFGHIJK12345"

```C#
var hashids = new Hashids("this is my salt", 0, "abcdefghijkABCDEFGHIJK12345")
var hash = hashids.Encode(1, 2, 3, 4, 5)
```

`hash` is now going to be:

    Ec4iEHeF3

## Randomness

The primary purpose of hashids is to obfuscate ids. It's not meant or tested to be used for security purposes or compression.
Having said that, this algorithm does try to make these hashes unguessable and unpredictable:

### Repeating numbers

```C#
var hashids = new Hashids("this is my salt");
var hash = hashids.Encode(5, 5, 5, 5);
```

You don't see any repeating patterns that might show there's 4 identical numbers in the hash:

    1Wc8cwcE

Same with incremented numbers:

```C#
var hashids = new Hashids("this is my salt");
var hash = hashids.Encode(1, 2, 3, 4, 5, 6, 7, 8, 9, 10)
```

`hash` will be :

    kRHnurhptKcjIDTWC3sx

### Incrementing number hashes:

```C#
var hashids = new Hashids("this is my salt");

hashids.Encode(1); // => NV
hashids.Encode(2); // => 6m
hashids.Encode(3); // => yD
hashids.Encode(4); // => 2l
hashids.Encode(5); // => rD
```

### Encoding using a HEX string

```C#
var hashids = new Hashids("this is my salt");
var hash = hashids.EncodeHex("DEADBEEF");
```

`hash` is now going to be: 

    kRNrpKlJ

### Decoding to a HEX string

```C#
var hashids = new Hashids("this is my salt");
var hex = hashids.DecodeHex("kRNrpKlJ");
```

`hex` is now going to be:

    DEADBEEF
