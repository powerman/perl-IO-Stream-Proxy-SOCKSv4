[![Build Status](https://travis-ci.org/powerman/perl-IO-Stream-Proxy-SOCKSv4.svg?branch=master)](https://travis-ci.org/powerman/perl-IO-Stream-Proxy-SOCKSv4)
[![Coverage Status](https://coveralls.io/repos/powerman/perl-IO-Stream-Proxy-SOCKSv4/badge.svg?branch=master)](https://coveralls.io/r/powerman/perl-IO-Stream-Proxy-SOCKSv4?branch=master)

# NAME

IO::Stream::Proxy::SOCKSv4 - SOCKSv4 proxy plugin for IO::Stream

# VERSION

This document describes IO::Stream::Proxy::SOCKSv4 version v2.0.0

# SYNOPSIS

    use IO::Stream;
    use IO::Stream::Proxy::SOCKSv4;

    IO::Stream->new({
        ...
        plugin => [
            ...
            proxy   => IO::Stream::Proxy::SOCKSv4->new({
                host    => 'my.proxy.com',
                port    => 3128,
            }),
            ...
        ],
    });

# DESCRIPTION

This module is plugin for [IO::Stream](https://metacpan.org/pod/IO::Stream) which allow you to route stream
through SOCKSv4 proxy.

You may use several IO::Stream::Proxy::SOCKSv4 plugins for single IO::Stream
object, effectively creating proxy chain (first proxy plugin will define
last proxy in a chain).

## SECURITY

Version 4 of SOCKS protocol doesn't support domain name resolving by proxy,
so resolving happens always on client side. This may result in leaking
client's DNS resolver IP address (usually it's client's address or client's
ISP address) and detecting the fact of using proxy.

## EVENTS

When using this plugin event RESOLVED will never be delivered to user because
there may be two hosts to resolve (target host and proxy host) and it
isn't clear how to handle this case in right way.

Event CONNECTED will be generated after SOCKS proxy successfully connects to
target {host} (and not when socket will connect to SOCKS proxy itself).

# INTERFACE 

## new

    $plugin = IO::Stream::Proxy::SOCKSv4->new({
        host    => $host,
        port    => $port,
    });
    $plugin = IO::Stream::Proxy::SOCKSv4->new({
        host    => $host,
        port    => $port,
        userid  => $ENV{USER},
    });

Connect to proxy $host:$port, optionally using given userid (empty by default).

# DIAGNOSTICS

- `{host}+{port} required`

    You must provide both {host} and {port} to IO::Stream::Proxy::SOCKSv4->new().

- `{fh} already connected`

    You have provided {fh} to IO::Stream->new(), but this is not supported by
    this plugin. Either don't use this plugin or provide {host}+{port} to
    IO::Stream->new() instead.

# LIMITATIONS

SOCKS "BIND" request doesn't supported.

# SUPPORT

## Bugs / Feature Requests

Please report any bugs or feature requests through the issue tracker
at [https://github.com/powerman/perl-IO-Stream-Proxy-SOCKSv4/issues](https://github.com/powerman/perl-IO-Stream-Proxy-SOCKSv4/issues).
You will be notified automatically of any progress on your issue.

## Source Code

This is open source software. The code repository is available for
public review and contribution under the terms of the license.
Feel free to fork the repository and submit pull requests.

[https://github.com/powerman/perl-IO-Stream-Proxy-SOCKSv4](https://github.com/powerman/perl-IO-Stream-Proxy-SOCKSv4)

    git clone https://github.com/powerman/perl-IO-Stream-Proxy-SOCKSv4.git

## Resources

- MetaCPAN Search

    [https://metacpan.org/search?q=IO-Stream-Proxy-SOCKSv4](https://metacpan.org/search?q=IO-Stream-Proxy-SOCKSv4)

- CPAN Ratings

    [http://cpanratings.perl.org/dist/IO-Stream-Proxy-SOCKSv4](http://cpanratings.perl.org/dist/IO-Stream-Proxy-SOCKSv4)

- AnnoCPAN: Annotated CPAN documentation

    [http://annocpan.org/dist/IO-Stream-Proxy-SOCKSv4](http://annocpan.org/dist/IO-Stream-Proxy-SOCKSv4)

- CPAN Testers Matrix

    [http://matrix.cpantesters.org/?dist=IO-Stream-Proxy-SOCKSv4](http://matrix.cpantesters.org/?dist=IO-Stream-Proxy-SOCKSv4)

- CPANTS: A CPAN Testing Service (Kwalitee)

    [http://cpants.cpanauthors.org/dist/IO-Stream-Proxy-SOCKSv4](http://cpants.cpanauthors.org/dist/IO-Stream-Proxy-SOCKSv4)

# AUTHOR

Alex Efros &lt;powerman@cpan.org>

# COPYRIGHT AND LICENSE

This software is Copyright (c) 2009- by Alex Efros &lt;powerman@cpan.org>.

This is free software, licensed under:

    The MIT (X11) License
