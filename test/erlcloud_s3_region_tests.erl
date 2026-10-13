%% -*- mode: erlang;erlang-indent-level: 4;indent-tabs-mode: nil -*-
-module(erlcloud_s3_region_tests).
-include_lib("eunit/include/eunit.hrl").
-include("erlcloud_aws.hrl").

%% Signing region selection for S3: regular requests and presigned URLs
%% must sign with the same region for the same config.

-define(VPCE_ID, "vpce-0123456789abcdef0-example").

%% {S3Host, ExpectedRegion}
host_regions() ->
    [%% AWS PrivateLink interface endpoints: regional and zonal,
     %% with and without the bucket prefix
     {"bucket." ?VPCE_ID ".s3.us-west-2.vpce.amazonaws.com", "us-west-2"},
     {"bucket." ?VPCE_ID "-us-west-2a.s3.us-west-2.vpce.amazonaws.com", "us-west-2"},
     {?VPCE_ID ".s3.us-west-2.vpce.amazonaws.com", "us-west-2"},
     {?VPCE_ID "-us-west-2a.s3.us-west-2.vpce.amazonaws.com", "us-west-2"},
     {"bucket." ?VPCE_ID ".s3.cn-north-1.vpce.amazonaws.com.cn", "cn-north-1"},
     {?VPCE_ID ".s3.cn-north-1.vpce.amazonaws.com.cn", "cn-north-1"},
     %% Public endpoints
     {"s3.us-west-2.amazonaws.com", "us-west-2"},
     {"s3.amazonaws.com", "us-east-1"},
     {"s3-external-1.amazonaws.com", "us-east-1"},
     {"s3-us-east-1.amazonaws.com", "us-east-1"},
     {"s3-us-west-2.amazonaws.com", "us-west-2"},
     {"s3.cn-north-1.amazonaws.com.cn", "cn-north-1"},
     %% S3-compatible storage
     {"minio.internal", "us-east-1"},
     {"localhost", "us-east-1"},
     {"127.0.0.1", "us-east-1"}].

region_test_() ->
    {foreach,
     fun() -> meck:new(erlcloud_httpc) end,
     fun(_) -> meck:unload(erlcloud_httpc) end,
     [fun inferred_region_tests/1,
      fun explicit_region_tests/1]}.

inferred_region_tests(_) ->
    [{Host,
      fun() ->
              Config = config(Host, undefined),
              Request = request_region(Config),
              Presign = presign_region(Config),
              ?assertEqual(Expected, Request),
              ?assertEqual(Request, Presign)
      end}
     || {Host, Expected} <- host_regions()].

explicit_region_tests(_) ->
    [{Host,
      fun() ->
              Config = config(Host, "eu-central-1"),
              ?assertEqual("eu-central-1", request_region(Config)),
              ?assertEqual("eu-central-1", presign_region(Config))
      end}
     || {Host, _} <- host_regions()].

aws_region_from_vpce_host_test_() ->
    [?_assertEqual({ok, "us-west-2"},
                   erlcloud_aws:aws_region_from_vpce_host(
                     "bucket." ?VPCE_ID "-us-west-2a.s3.us-west-2.vpce.amazonaws.com")),
     ?_assertEqual(error, erlcloud_aws:aws_region_from_vpce_host("s3.us-west-2.amazonaws.com")),
     ?_assertEqual(error, erlcloud_aws:aws_region_from_vpce_host("vpce.amazonaws.com")),
     ?_assertEqual(error, erlcloud_aws:aws_region_from_vpce_host("minio.internal"))].

aws_region_from_host_vpce_test_() ->
    [?_assertEqual(Expected, erlcloud_aws:aws_region_from_host(Host))
     || {Host, Expected} <- host_regions(),
        string:find(Host, ".vpce.") =/= nomatch].

config(Host, Region) ->
    (erlcloud_s3:new("access-key-id", "secret-access-key", Host, 443))
        #aws_config{aws_region = Region}.

request_region(Config) ->
    Self = self(),
    meck:expect(erlcloud_httpc, request,
                fun(_Url, _Method, Headers, _Body, _Timeout, _Config) ->
                        Self ! {authorization, proplists:get_value("Authorization", Headers)},
                        {ok, {{204, "No Content"}, [], <<>>}}
                end),
    erlcloud_s3:delete_object("bucket", "key", Config),
    receive
        {authorization, Auth} -> credential_region(Auth)
    after 1000 ->
            error(no_request)
    end.

presign_region(Config) ->
    Url = erlcloud_s3:make_presigned_v4_url(60, "bucket", get, "key", [], Config),
    {match, [Region]} =
        re:run(Url, "X-Amz-Credential=[^%]+%2F[0-9]+%2F([^%]+)%2Fs3%2F",
               [{capture, all_but_first, list}]),
    Region.

credential_region(Auth) ->
    {match, [Region]} =
        re:run(Auth, "Credential=[^/]+/[0-9]+/([^/]+)/s3/",
               [{capture, all_but_first, list}]),
    Region.
