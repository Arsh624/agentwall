# fastcache

A tiny in-memory cache for Go with TTL support.

## Install

    go get example.com/fastcache

## Usage

    c := fastcache.New(time.Minute)
    c.Set("user:1", "alice")
    v, ok := c.Get("user:1")

## Contributing

Open an issue before large changes. Run `make test` and `make lint` before sending a pull request. Licensed under MIT.
