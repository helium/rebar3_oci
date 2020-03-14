rebar3_oci
=====

A rebar3 plugin to package releases as an OCI container

Build
-----

    $ rebar3 compile

Use
---

Add the plugin to your rebar config:

    {plugins, [
        {rebar3_oci, {git, "https://host/user/rebar3_oci.git", {tag, "0.1.0"}}}
    ]}.

Then just call your plugin directly in an existing application:


    $ rebar3 rebar3_oci
    ===> Fetching rebar3_oci
    ===> Compiling rebar3_oci
    <Plugin Output>
