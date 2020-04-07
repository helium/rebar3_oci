-module(rebar3_oci_prv).

-export([init/1, do/1, format_error/1]).

-include_lib("kernel/include/file.hrl").

-define(PROVIDER, oci).
-define(DEPS, [release]).
-define(CHUNK_SIZE, 4096).
-define(VERSION, <<"1.0.0">>).


%% ===================================================================
%% Public API
%% ===================================================================
-spec init(rebar_state:t()) -> {ok, rebar_state:t()}.
init(State) ->
    Provider = providers:create([
            {name, ?PROVIDER},            % The 'user friendly' name of the task
            {module, ?MODULE},            % The module implementation of the task
            {bare, true},                 % The task can be run by the user, always true
            {deps, ?DEPS},                % The list of dependencies
            {example, "rebar3 oci"}, % How to use the plugin
            {opts, []},                   % list of options understood by the plugin
            {short_desc, "A rebar3 plugin to package releases as an OCI container"},
            {desc, "A rebar3 plugin to package releases as an OCI container"}
    ]),
    {ok, rebar_state:add_provider(State, Provider)}.


-spec do(rebar_state:t()) -> {ok, rebar_state:t()} | {error, string()}.
do(State) ->
    RelDir = filename:join(rebar_dir:base_dir(State), "rel"), % TODO: some day Tristan promised this will be replaced by a real API call
    TarDir = insecure_mkdtemp(),
    OutName = filename:join(TarDir, random_name()),
    RelFiles = filelib:fold_files(RelDir, ".+", true, fun(F, A) -> add_file(RelDir, F, A) end, []),
    ok = erl_tar:create(OutName, RelFiles, [dereference]),
    {LayerSize, LayerSHA} = sha256_from_file(OutName),
    ConfigJson = jsone:encode(format_oci_config(LayerSHA)),
    ConfigSHA = sha256(ConfigJson),
    ConfigSize = byte_size(ConfigJson),
    ManifestJson = jsone:encode(format_oci_manifest(ConfigSize, ConfigSHA, LayerSize, LayerSHA)),
    ManifestSHA = sha256(ManifestJson),
    ManifestSize = byte_size(ManifestJson),
    IndexJson = jsone:encode(format_oci_index(ManifestSize, ManifestSHA)),
    LayoutJson = jsone:encode(format_oci_layout()),

    WorkDir = insecure_mkdtemp(),
    ok = mkdir_p(filename:join(WorkDir, "blobs/sha256")),
    write_file(WorkDir, <<"oci-layout.json">>, LayoutJson),
    write_file(WorkDir, <<"index.json">>, IndexJson),
    write_blob(WorkDir, ManifestSHA, ManifestJson),
    write_blob(WorkDir, ConfigSHA, ConfigJson),
    file:rename(OutName, filename:join([WorkDir, "blobs/sha256", LayerSHA])),
    ImgFiles = filelib:fold_files(WorkDir, ".+", true, fun(F, A) -> add_file(WorkDir, F, A) end, []),

    Name = rebar_utils:to_list(get_main_app_name(State)) ++ ".tgz",
    ok = erl_tar:create(Name, ImgFiles, [compressed]),
    deltree(TarDir),
    deltree(WorkDir),
    {Sz, ImageSHA} = sha256_from_file(Name),
    rebar_api:info("OCI image '~s' created (sha256: ~s, bytes: ~p)~n", [Name, rebar_utils:to_list(ImageSHA), Sz]),
    {ok, State}.

-spec format_error(any()) ->  iolist().
format_error(Reason) ->
    io_lib:format("~p", [Reason]).

get_main_app_name(State) ->
    case rebar_state:project_apps(State) of
        [AppInfo] -> rebar_app_info:name(AppInfo);
        _ -> rebar_api:error(no_main_app)
    end.

add_file(Dir, F, Acc) ->
    ArchiveName = F -- (Dir ++ "/"),
    [{ArchiveName, F}|Acc].

write_file(D, F, Data) ->
    ok = file:write_file(filename:join(D,F), Data).

write_blob(D, F, Data) ->
    ok = file:write_file(filename:join([D, "blobs/sha256", F]), Data).

random_name() ->
    UniqueNumber = erlang:integer_to_list(erlang:trunc(rand:uniform() * 1000000000000)),
    lists:flatten(["tmp", UniqueNumber, ".tar"]).

%% These functions are copied/adapted from:
%% https://raw.githubusercontent.com/erlware/erlware_commons/master/src/ec_file.erl
%%
%% @doc make a unique temporary directory. Similar function to BSD stdlib
%% %% function of the same name.
-spec insecure_mkdtemp() -> TmpDirPath::file:name() | {error, term()}.
insecure_mkdtemp() ->
    UniqueNumber = erlang:integer_to_list(erlang:trunc(rand:uniform() * 1000000000000)),
    TmpDirPath = filename:join([tmp(), lists:flatten([".tmp_dir", UniqueNumber])]),

    case mkdir_p(TmpDirPath) of
        ok -> TmpDirPath;
        Error -> Error
    end.

-spec tmp() -> file:name().
tmp() ->
    case erlang:system_info(system_architecture) of
        "win32" ->
            case os:getenv("TEMP") of
                false -> "./tmp";
                Val -> Val
            end;
        _SysArch ->
            case os:getenv("TMPDIR") of
                false -> "/tmp";
                Val -> Val
           end
    end.

-spec mkdir_p(file:name()) -> ok | {error, Reason::term()}.
mkdir_p(Path) ->
    %% We are exploiting a feature of ensuredir that that creates all
    %% directories up to the last element in the filename, then ignores
    %% that last element. This way we ensure that the dir is created
    %% and not have any worries about path names
    DirName = filename:join([filename:absname(Path), "tmp"]),
    filelib:ensure_dir(DirName).

is_dir(Path) ->
    case file:read_file_info(Path) of
        {ok, #file_info{type = directory}} -> true;
        _ -> false
    end.

deltree(Path) ->
    case is_dir(Path) of
        false -> file:delete(Path);
        true ->
            lists:foreach(fun(ChildPath) ->
                                  deltree(ChildPath)
                          end, sub_files(Path)),
            file:del_dir(Path)
    end.

sub_files(From) ->
    {ok, SubFiles} = file:list_dir(From),
    [filename:join(From, SubFile) || SubFile <- SubFiles].

%% end quote from ec_file.erl

sha256(Data) ->
    hexlify(crypto:hash(sha256, Data)).

sha256_from_file(File) ->
    {ok, Fd} = file:open(File, [read, binary, raw]),
    HS = crypto:hash_init(sha256),
    {Sz, Raw} = hash_file(Fd, file:read(Fd, ?CHUNK_SIZE), 0, HS),
    {Sz, hexlify(Raw)}.


hash_file(Fd, eof, Pos, HS) ->
    file:close(Fd),
    {Pos, crypto:hash_final(HS)};
hash_file(Fd, {ok, Data}, Pos, HS) ->
    hash_file(Fd, file:read(Fd, ?CHUNK_SIZE),
              Pos+byte_size(Data), crypto:hash_update(HS, Data)).

%% https://stackoverflow.com/a/29819282
hexlify(Bin) when is_binary(Bin) ->
        << <<(hex(H)),(hex(L))>> || <<H:4,L:4>> <= Bin >>.

hex(C) when C < 10 -> $0 + C;
hex(C) -> $a + C - 10.

format_oci_layout() ->
    #{ <<"imageLayoutVersion">> => <<"1.0.0">> }.

%% https://github.com/opencontainers/image-spec/blob/master/config.md
%% application/vnd.oci.image.config.v1+json
%%
format_oci_config(LayerSHA) ->
    #{ <<"architecture">> => <<"amd64">>,
       <<"os">> => <<"linux">>,
       <<"rootfs">> => #{
           <<"type">> => <<"layers">>,
           <<"diff_ids">> => [ <<"sha256:", LayerSHA/binary>> ]
          }
     }.

format_oci_manifest(ConfigSize, ConfigSHA, LayerSize, LayerSHA) ->
    #{ <<"schemaVersion">> => 2,
       <<"config">> => #{
           <<"mediaType">> => <<"application/vnd.oci.image.config.v1+json">>,
           <<"size">> => ConfigSize,
           <<"digest">> => <<"sha256:", ConfigSHA/binary>>
       },
       <<"layers">> => [
            #{
               <<"mediaType">> => <<"application/vnd.oci.image.layer.v1.tar">>,
               <<"size">> => LayerSize,
               <<"digest">> => <<"sha256:", LayerSHA/binary>>
             }
      ]
     }.

format_oci_index(ManifestSize, ManifestSHA) ->
    #{ <<"schemaVersion">> => 2,
       <<"manifests">> => [
            #{
               <<"mediaType">> => <<"application/vnd.oci.image.manifest.v1+json">>,
               <<"size">> => ManifestSize,
               <<"digest">> => <<"sha256:", ManifestSHA/binary>>
             }
       ],
       <<"annotations">> => #{
            <<"com.helium.rebar3_oci.version">> => ?VERSION
       }
     }.

