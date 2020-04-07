rebar3_oci
==========

A rebar3 plugin to package Erlang releases in a compliant [open container
image][1] format.  Normally, the tar utility library packaged with Erlang
includes file timestamps in the tar output. This makes building an artifact
which uses file hashes like the OCI format inherently non-deterministic.

The plugin packages releases in such a way that _all_ of the configuration must
come at run-time.

The image will be named after the main application. There is currently no way
to change that.

Build
-----

    $ rebar3 compile

Use
---

Add the plugin to your rebar config:

    {plugins, [
        {rebar3_oci, {git, "https://github.com/helium/rebar3_oci.git", {tag, "0.1.0"}}}
    ]}.

Then call directly in an existing application:

    $ rebar3 oci
    ===> Compiling rebar3_oci
    ===> Compiling rebar3_oci
    ===> Verifying dependencies...
    ===> Compiling mylib
    ===> Starting relx build process ...
    ===> Resolving OTP Applications from directories:
          /home/mallen/sandbox/mylib/_build/default/lib
          /home/mallen/sandbox/mylib/_checkouts
          /home/mallen/erlangs/22.3/lib
          /home/mallen/sandbox/mylib/_build/default/rel
    ===> Resolved mylib-0.1.0
    ===> Dev mode enabled, release will be symlinked
    ===> release successfully created!
    ===> OCI image 'mylib.tgz' created (sha256: 5e7d68f0f3b3c0152ebc49ccb37086d1d1110b13c0f2458dd6110ba71b9c6a1b, bytes: 29300)
