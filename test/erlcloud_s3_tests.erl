%% -*- mode: erlang;erlang-indent-level: 4;indent-tabs-mode: nil -*-
-module(erlcloud_s3_tests).
-include_lib("eunit/include/eunit.hrl").
-include("erlcloud.hrl").
-include("erlcloud_aws.hrl").
-include("erlcloud_s3_test_data.hrl").

%% Unit tests for s3.
%% Currently only test error handling and retries.

%%%===================================================================
%%% Test entry points
%%%===================================================================

operation_test_() ->
    {foreach,
        fun start/0,
        fun stop/1,
        [
            fun get_bucket_policy_tests/1,
            fun get_bucket_notification_test/1,
            fun get_bucket_notification_no_prefix_test/1,
            fun get_bucket_notification_no_suffix_test/1,
            fun put_object_tests/1,
            fun error_handling_tests/1,
            fun dns_compliant_name_tests/1,
            fun get_bucket_lifecycle_tests/1,
            fun put_bucket_lifecycle_tests/1,
            fun delete_bucket_lifecycle_tests/1,
            fun encode_bucket_lifecycle_tests/1,
            fun list_inventory_configurations_test/1,
            fun get_inventory_configuration_test/1,
            fun put_bucket_inventory_test/1,
            fun delete_bucket_inventory_test/1,
            fun encode_inventory_test/1,
            fun delete_objects_batch_tests/1,
            fun delete_objects_batch_single_tests/1,
            fun delete_objects_batch_with_err_tests/1,
            fun delete_objects_batch_mixed_tests/1,
            fun put_bucket_encryption_test/1,
            fun get_bucket_encryption_test/1,
            fun get_bucket_encryption_not_found_test/1,
            fun delete_bucket_encryption_test/1,
            fun hackney_proxy_put_validation_test/1,
            fun get_bucket_and_key/1,
            fun signature_test/1,
            fun head_bucket_ok/1,
            fun head_bucket_redirect/1,
            fun head_bucket_bad_request/1,
            fun head_bucket_forbidden/1,
            fun head_bucket_not_found/1
        ]}.

start() ->
    meck:new(erlcloud_httpc),
    ok.

stop(_) ->
    meck:unload(erlcloud_httpc).

config() ->
    config(#aws_config{s3_follow_redirect = true}).

config(Config) ->
    Config#aws_config{
      access_key_id = string:copies("A", 20),
      secret_access_key = string:copies("a", 40)}.

httpc_expect(Response) ->
    httpc_expect(get, Response).

httpc_expect(Method, Response) ->
    fun(_Url, Method2, _Headers, _Body, _Timeout, _Config = #aws_config{hackney_client_options = #hackney_client_options{insecure = Insecure,
															 proxy = Proxy,
															 proxy_auth = Proxy_auth},
								       http_client = Http_client}) ->

            case Http_client of
              hackney ->
                Method = Method2,
                Insecure = false,
                Proxy = <<"10.10.10.10">>,
                Proxy_auth = {<<"AAAA">>, <<"BBBB">>};

              _else ->
                Method = Method2,
                Insecure = true,
                Proxy = undefined,
                Proxy_auth = undefined
	    end,

	    Response
    end.

get_bucket_lifecycle_tests(_) ->
    Response = {ok, {{200, "OK"}, [], <<"
<LifecycleConfiguration xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\">
    <Rule>
        <ID>Archive and then delete rule</ID>
        <Prefix>projectdocs/</Prefix>
        <Status>Enabled</Status>
       <Transition>
           <Days>30</Days>
           <StorageClass>STANDARD_IA</StorageClass>
        </Transition>
        <Transition>
           <Days>365</Days>
           <StorageClass>GLACIER</StorageClass>
        </Transition>
        <Expiration>
           <Days>3650</Days>
        </Expiration>
    </Rule></LifecycleConfiguration>">>}},
    meck:expect(erlcloud_httpc, request, httpc_expect(Response)),
    Result = erlcloud_s3:get_bucket_lifecycle("BucketName", config()),
    ?_assertEqual({ok,
                   [[{expiration,[{days,3650}]},
                     {id,"Archive and then delete rule"},
                     {prefix,"projectdocs/"},
                     {status,"Enabled"},
                     {transition,[[{days,30},{storage_class,"STANDARD_IA"}],
                                  [{days,365},{storage_class,"GLACIER"}]]}]]},
                  Result).

put_bucket_lifecycle_tests(_) ->
    Response = {ok, {{200,"OK"},
                     [{"server","AmazonS3"},
                      {"content-length","0"},
                      {"date","Mon, 18 Jan 2016 09:14:29 GMT"},
                      {"x-amz-request-id","911850E447C20DE3"},
                      {"x-amz-id-2",
                       "lzs7n4Z/9iwJ9Xd+s5s2nnwT6XIp2uhfkRMWvgqTeTXRr9JXl91s/kDnzLnA5eZQYvUVA7vyxLY="}],
                     <<>>}},
    meck:expect(erlcloud_httpc, request, httpc_expect(put, Response)),
    Policy = [[{expiration,[{days,3650}]},
               {id,"Archive and then delete rule"},
               {prefix,"projectdocs/"},
               {status,"Enabled"},
               {transition,[[{days,30},{storage_class,"STANDARD_IA"}],
                            [{days,365},{storage_class,"GLACIER"}]]}]],
    Result = erlcloud_s3:put_bucket_lifecycle("BucketName", Policy, config()),
    Result1 = erlcloud_s3:put_bucket_lifecycle("BucketName", <<"Policy">>, config()),
    [?_assertEqual(ok, Result), ?_assertEqual(ok, Result1)].

delete_bucket_lifecycle_tests(_) ->
    Response = {ok, {{200, "OK"}, [], <<>>}},
    meck:expect(erlcloud_httpc, request, httpc_expect(delete, Response)),
    Result = erlcloud_s3:delete_bucket_lifecycle("BucketName", config()),
    ?_assertEqual(ok, Result).

encode_bucket_lifecycle_tests(_) ->
    Expected = "<?xml version=\"1.0\"?><LifecycleConfiguration><Rule><Expiration><Days>3650</Days></Expiration><ID>Archive and then delete rule</ID><Prefix>projectdocs/</Prefix><Status>Enabled</Status><Transition><Days>30</Days><StorageClass>STANDARD_IA</StorageClass></Transition><Transition><Days>365</Days><StorageClass>GLACIER</StorageClass></Transition></Rule></LifecycleConfiguration>",
    Policy   = [
                [{expiration,[{days,3650}]},
                 {id,"Archive and then delete rule"},
                 {prefix,"projectdocs/"},
                 {status,"Enabled"},
                 {transition,[[{days,30},{storage_class,"STANDARD_IA"}],
                              [{days,365},{storage_class,"GLACIER"}]]}
                ]
               ],
    Expected2 = "<?xml version=\"1.0\"?><LifecycleConfiguration><Rule><ID>al_s3--GLACIER-policy</ID><Prefix></Prefix><Status>Enabled</Status><Transition><Days>10</Days><StorageClass>GLACIER</StorageClass></Transition></Rule><Rule><ID>ed-test-console</ID><Prefix></Prefix><Status>Enabled</Status><Transition><Days>20</Days><StorageClass>GLACIER</StorageClass></Transition></Rule></LifecycleConfiguration>",
    Policy2   = [[{id,"al_s3--GLACIER-policy"},
                  {prefix,[]},
                  {status,"Enabled"},
                  {transition,[[{days,"10"}, {storage_class,"GLACIER"}]]}],
                 [{id,"ed-test-console"},
                  {prefix,[]},
                  {status,"Enabled"},
                  {transition,[[{days,20},{storage_class,"GLACIER"}]]}]],
    Result  = erlcloud_s3:encode_lifecycle(Policy),
    Result2 = erlcloud_s3:encode_lifecycle(Policy2),
    [?_assertEqual(Expected, Result), ?_assertEqual(Expected2, Result2)].

set_bucket_notification_test_() ->
    [?_assertEqual({'NotificationConfiguration',[]},
                   erlcloud_s3:create_notification_xml([])),
     ?_assertError(
            function_clause,
            erlcloud_s3:create_notification_param_xml({filter,[{foo, "bar"}]}, [])),
     ?_assertEqual(
            [{'Filter',[{'S3Key',
                [{'FilterRule',[{'Name',["Prefix"]}, {'Value',["images/"]}]}]}]}],
            erlcloud_s3:create_notification_param_xml({filter,[{prefix, "images/"}]}, [])),
     ?_assertEqual(
            [{'Filter',[{'S3Key',
                [{'FilterRule',[{'Name',["Suffix"]}, {'Value',["jpg"]}]}]}]}],
            erlcloud_s3:create_notification_param_xml({filter,[{suffix, "jpg"}]}, [])),
     ?_assertEqual(
         [{'Filter',[{'S3Key',
             [{'FilterRule',[{'Name',["Prefix"]}, {'Value',["images/"]}]},
              {'FilterRule',[{'Name',["Suffix"]}, {'Value',["jpg"]}]}]}]}],
         erlcloud_s3:create_notification_param_xml({filter,[{prefix, "images/"},
                                                            {suffix, "jpg"}]},
                                                   [])),
     ?_assertEqual(?S3_BUCKET_EVENTS_SIMPLE_XML_FORM,
                   erlcloud_s3:create_notification_xml(?S3_BUCKET_EVENTS_LIST))].

get_bucket_notification_test(_) ->
    Response = {ok, {{200, "OK"}, [], ?S3_BUCKET_EVENT_XML_CONFIG}},
    meck:expect(erlcloud_httpc, request,
        fun("https://s3.amazonaws.com/?notification", _, _, _, _, _) -> Response end),
    ?_assertEqual(?S3_BUCKET_EVENTS_LIST,
        erlcloud_s3:get_bucket_attribute("BucketName", notification, config())).

get_bucket_notification_no_prefix_test(_) ->
    Response = {ok, {{200, "OK"}, [], ?S3_BUCKET_EVENT_XML_CONFIG_NO_PREFIX}},
    meck:expect(erlcloud_httpc, request,
        fun("https://s3.amazonaws.com/?notification", _, _, _, _, _) -> Response end),
    ?_assertEqual(?S3_BUCKET_EVENTS_LIST_NO_PREFIX,
        erlcloud_s3:get_bucket_attribute("BucketName", notification, config())).

get_bucket_notification_no_suffix_test(_) ->
    Response = {ok, {{200, "OK"}, [], ?S3_BUCKET_EVENT_XML_CONFIG_NO_SUFFIX}},
    meck:expect(erlcloud_httpc, request,
        fun("https://s3.amazonaws.com/?notification", _, _, _, _, _) -> Response end),
    ?_assertEqual(?S3_BUCKET_EVENTS_LIST_NO_SUFFIX,
                  erlcloud_s3:get_bucket_attribute("BucketName", notification, config())).

get_bucket_policy_tests(_) ->
    Response = {ok, {{200, "OK"}, [], <<"TestBody">>}},
    meck:expect(erlcloud_httpc, request, httpc_expect(Response)),
    Result = erlcloud_s3:get_bucket_policy("BucketName", config()),
    ?_assertEqual({ok, "TestBody"}, Result).

put_object_tests(_) ->
    Response = {ok, {{200, "OK"}, [{"x-amz-version-id", "version_id"}], <<>>}},
    meck:expect(erlcloud_httpc, request, httpc_expect(put, Response)),
    Result = erlcloud_s3:put_object("BucketName", "Key", "Data", config()),
    ?_assertEqual([{version_id, "version_id"}
                  ,{"x-amz-version-id", "version_id"}
                  ], Result).

dns_compliant_name_tests(_) ->
    [?_assertEqual(true,  erlcloud_util:is_dns_compliant_name("goodname123")),
     ?_assertEqual(true,  erlcloud_util:is_dns_compliant_name("good.name")),
     ?_assertEqual(true,  erlcloud_util:is_dns_compliant_name("good-name")),
     ?_assertEqual(true,  erlcloud_util:is_dns_compliant_name("good--name")),
     ?_assertEqual(false, erlcloud_util:is_dns_compliant_name("Bad.name")),
     ?_assertEqual(false, erlcloud_util:is_dns_compliant_name("badname.")),
     ?_assertEqual(false, erlcloud_util:is_dns_compliant_name(".bad.name")),
     ?_assertEqual(false, erlcloud_util:is_dns_compliant_name("bad.name--"))].

error_handling_no_retry() ->
    Response = {ok, {{500, "Internal Server Error"}, [], <<"TestBody">>}},
    meck:expect(erlcloud_httpc, request, httpc_expect(Response)),
    Result = erlcloud_s3:get_bucket_policy("BucketName", config()),
    ?_assertEqual({error,{http_error,500,"Internal Server Error",<<"TestBody">>}}, Result).

error_handling_default_retry() ->
    Response1 = {ok, {{500, "Internal Server Error"}, [], <<"TestBody">>}},
    Response2 = {ok, {{200, "OK"}, [], <<"TestBody">>}},
    meck:sequence(erlcloud_httpc, request, 6, [Response1, Response2]),
    Result = erlcloud_s3:get_bucket_policy(
               "BucketName",
               config(#aws_config{retry = fun erlcloud_retry:default_retry/1})),
    ?_assertEqual({ok, "TestBody"}, Result).

error_handling_httpc_error() ->
    Response1 = {error, timeout},
    Response2 = {ok, {{200, "OK"}, [], <<"TestBody">>}},
    meck:sequence(erlcloud_httpc, request, 6, [Response1, Response2]),
    Result = erlcloud_s3:get_bucket_policy(
               "BucketName",
               config(#aws_config{retry = fun erlcloud_retry:default_retry/1})),
    ?_assertEqual({ok, "TestBody"}, Result).

%% Handle redirect by using location from error message.
error_handling_redirect_message() ->
    Response1 = {ok, {{307,"Temporary Redirect"}, [],
        <<"<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<Error><Code>TemporaryRedirect</Code>"
          "<Message>Please re-send this request to the specified temporary endpoint. Continue to use the original request endpoint for future requests.</Message>"
          "<Bucket>bucket.name</Bucket>"
          "<Endpoint>bucket.name.s3.eu-central-1.amazonaws.com</Endpoint>"
          "<RequestId>5B157C1FD7B351A9</RequestId>"
          "<HostId>IbIGCfmLGzCxQ14C14VuqbjzLjWZ61M1xF3y9ovUu/j/Qj//BXsrbsAuYQJN//FARyvYtOmj8K0=</HostId></Error>">>}},
    Response2 = {ok, {{200, "OK"}, [], <<"TestBody">>}},
    meck:sequence(erlcloud_httpc, request, 6, [Response1, Response2]),
    Result = erlcloud_s3:get_bucket_policy(
               "bucket.name",
               config()),
    ?_assertEqual({ok, "TestBody"}, Result).

%% Handle redirect by using url from location header.
error_handling_redirect_location() ->
    Response1 = {ok, {{301,"Temporary Redirect"},
        [{"server","AmazonS3"},
         {"date","Wed, 22 Jul 2015 09:58:03 GMT"},
         {"transfer-encoding","chunked"},
         {"content-type","application/xml"},
         {"location",
          "https://kkuzmin-test-frankfurt.s3.eu-central-1.amazonaws.com/"},
         {"x-amz-id-2",
          "YIgyI9Lb9I/dMpDrRASSD8w5YsNAyhRlF+PDF0jlf9Hq6eVLvSkuj+ftZI2RmU5eXnOKW1Wqh20="},
         {"x-amz-request-id","FAECC30C2CD53BCA"}
        ],
        <<>>}},
    Response2 = {ok, {{200, "OK"}, [], <<"TestBody">>}},
    meck:sequence(erlcloud_httpc, request, 6, [Response1, Response2]),
     Result = erlcloud_s3:get_bucket_policy(
                "bucket.name",
                config()),
     ?_assertEqual({ok, "TestBody"}, Result).

%% Handle redirect by using bucket region from "x-amz-bucket-region" header.
error_handling_redirect_bucket_region() ->
    Response1 = {ok, {{301,"Temporary Redirect"},
        [{"server","AmazonS3"},
         {"date","Wed, 22 Jul 2015 09:58:03 GMT"},
         {"transfer-encoding","chunked"},
         {"content-type","application/xml"},
         {"x-amz-id-2",
          "YIgyI9Lb9I/dMpDrRASSD8w5YsNAyhRlF+PDF0jlf9Hq6eVLvSkuj+ftZI2RmU5eXnOKW1Wqh20="},
         {"x-amz-request-id","FAECC30C2CD53BCA"},
         {"x-amz-bucket-region","us-west-1"}
        ],
        <<>>}},
    Response2 = {ok, {{200, "OK"}, [], <<"TestBody">>}},
    meck:sequence(erlcloud_httpc, request, 6, [Response1, Response2]),
     Result = erlcloud_s3:get_bucket_policy(
                "bucket.name",
                config()),
     ?_assertEqual({ok, "TestBody"}, Result).

%% Handle redirect by using bucket region from "x-amz-bucket-region" header.
error_handling_redirect_error() ->
    Response1 = {ok, {{301,"Temporary Redirect"},
        [{"server","AmazonS3"},
         {"date","Wed, 22 Jul 2015 09:58:03 GMT"},
         {"transfer-encoding","chunked"},
         {"content-type","application/xml"},
         {"x-amz-id-2",
          "YIgyI9Lb9I/dMpDrRASSD8w5YsNAyhRlF+PDF0jlf9Hq6eVLvSkuj+ftZI2RmU5eXnOKW1Wqh20="},
         {"x-amz-request-id","FAECC30C2CD53BCA"},
         {"x-amz-bucket-region","us-west-1"}
        ],
        <<>>}},
    Response2 = {ok,{{404,"Not Found"},
                   [{"server","AmazonS3"},
                    {"date","Tue, 25 Aug 2015 17:49:02 GMT"},
                    {"transfer-encoding","chunked"},
                    {"content-type","application/xml"},
                    {"x-amz-id-2",
                     "yjPxn58opjPoTJNIm5sPRjFrRlg4c50Ef9hT1m2nPvamKnr7nePMzKN4gStUSTtf0yp6+b/dzrA="},
                    {"x-amz-request-id","5DE771B2AD75F413"}],
                    <<"<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<Error><Code>NoSuchBucketPolicy</Code><Message>The bu">>}},
    Response3 = {ok, {{301,"Moved Permanently"}, [],
        <<"<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<Error><Code>TemporaryRedirect</Code>"
          "<Message>Please re-send this request to the specified temporary endpoint. Continue to use the original request endpoint for future requests.</Message>"
          "<Bucket>bucket.name</Bucket>"
          "<Endpoint>s3.amazonaws.com</Endpoint>"
          "<RequestId>5B157C1FD7B351A9</RequestId>"
          "<HostId>IbIGCfmLGzCxQ14C14VuqbjzLjWZ61M1xF3y9ovUu/j/Qj//BXsrbsAuYQJN//FARyvYtOmj8K0=</HostId></Error>">>}},
    meck:sequence(erlcloud_httpc, request, 6, [Response1, Response2]),
    Result1 = erlcloud_s3:get_bucket_policy(
            "bucket.name",
            config()),
    meck:sequence(erlcloud_httpc, request, 6, [Response1]),
    Result2 = erlcloud_s3:get_bucket_policy(
            "bucket.name",
            config(#aws_config{s3_follow_redirect = false})),
    meck:sequence(erlcloud_httpc, request, 6, [Response3, Response2]),
    Result3 = erlcloud_s3:get_bucket_policy(
            "bucket.name",
            config(#aws_config{s3_follow_redirect = true})),
    [?_assertMatch({error,{http_error,404,"Not Found",_}}, Result1),
     ?_assertMatch({error,{http_error,301,"Temporary Redirect",_}}, Result2),
     ?_assertMatch({error,{http_error,404,"Not Found",_}}, Result3)].

%% Handle two sequential redirects.
error_handling_double_redirect() ->
    Response1 = {ok, {{301,"Moved Permanently"}, [],
        <<"<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<Error><Code>TemporaryRedirect</Code>"
          "<Message>Please re-send this request to the specified temporary endpoint. Continue to use the original request endpoint for future requests.</Message>"
          "<Bucket>bucket.name</Bucket>"
          "<Endpoint>s3.amazonaws.com</Endpoint>"
          "<RequestId>5B157C1FD7B351A9</RequestId>"
          "<HostId>IbIGCfmLGzCxQ14C14VuqbjzLjWZ61M1xF3y9ovUu/j/Qj//BXsrbsAuYQJN//FARyvYtOmj8K0=</HostId></Error>">>}},
    Response2 = {ok, {{307,"Temporary Redirect"}, [],
        <<"<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<Error><Code>TemporaryRedirect</Code>"
          "<Message>Please re-send this request to the specified temporary endpoint. Continue to use the original request endpoint for future requests.</Message>"
          "<Bucket>bucket.name</Bucket>"
          "<Endpoint>bucket.name.s3.eu-central-1.amazonaws.com</Endpoint>"
          "<RequestId>5B157C1FD7B351A9</RequestId>"
          "<HostId>IbIGCfmLGzCxQ14C14VuqbjzLjWZ61M1xF3y9ovUu/j/Qj//BXsrbsAuYQJN//FARyvYtOmj8K0=</HostId></Error>">>}},
    Response3 = {ok, {{200, "OK"}, [], <<"TestBody">>}},
    meck:sequence(erlcloud_httpc, request, 6, [Response1, Response2, Response3]),
    Result = erlcloud_s3:get_bucket_policy(
               "bucket.name",
               config()),
    ?_assertEqual({ok, "TestBody"}, Result).


error_handling_tests(_) ->
    [error_handling_no_retry(),
     error_handling_default_retry(),
     error_handling_httpc_error(),
     error_handling_redirect_message(),
     error_handling_redirect_location(),
     error_handling_redirect_bucket_region(),
     error_handling_redirect_error(),
     error_handling_double_redirect()
    ].

%% Bucket Inventory tests
list_inventory_configurations_test(_)->
    Response = {ok, {{200, "OK"}, [], <<"
        <ListInventoryConfigurationsResult xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\">
            <InventoryConfiguration>
               <Id>report1</Id>
               <IsEnabled>true</IsEnabled>
               <Destination>
                  <S3BucketDestination>
                     <Format>CSV</Format>
                     <AccountId>123456789012</AccountId>
                     <Bucket>arn:aws:s3:::destination-bucket</Bucket>
                     <Prefix>prefix1</Prefix>
                  </S3BucketDestination>
               </Destination>
               <Schedule>
                  <Frequency>Daily</Frequency>
               </Schedule>
               <Filter>
                  <Prefix>prefix/One</Prefix>
               </Filter>
               <IncludedObjectVersions>All</IncludedObjectVersions>
               <OptionalFields>
                  <Field>Size</Field>
                  <Field>LastModifiedDate</Field>
                  <Field>ETag</Field>
                  <Field>StorageClass</Field>
                  <Field>IsMultipartUploaded</Field>
                  <Field>ReplicationStatus</Field>
               </OptionalFields>
            </InventoryConfiguration>
               <InventoryConfiguration>
               <Id>report2</Id>
               <IsEnabled>true</IsEnabled>
               <Destination>
                  <S3BucketDestination>
                     <Format>CSV</Format>
                     <AccountId>123456789012</AccountId>
                     <Bucket>arn:aws:s3:::bucket2</Bucket>
                     <Prefix>prefix2</Prefix>
                  </S3BucketDestination>
               </Destination>
               <Schedule>
                  <Frequency>Daily</Frequency>
               </Schedule>
               <Filter>
                  <Prefix>prefix/Two</Prefix>
               </Filter>
               <IncludedObjectVersions>All</IncludedObjectVersions>
               <OptionalFields>
                  <Field>Size</Field>
                  <Field>LastModifiedDate</Field>
                  <Field>ETag</Field>
                  <Field>StorageClass</Field>
                  <Field>IsMultipartUploaded</Field>
                  <Field>ReplicationStatus</Field>
               </OptionalFields>
            </InventoryConfiguration>
            <InventoryConfiguration>
               <Id>report3</Id>
               <IsEnabled>true</IsEnabled>
               <Destination>
                  <S3BucketDestination>
                     <Format>CSV</Format>
                     <AccountId>123456789012</AccountId>
                     <Bucket>arn:aws:s3:::bucket3</Bucket>
                     <Prefix>prefix3</Prefix>
                  </S3BucketDestination>
               </Destination>
               <Schedule>
                  <Frequency>Daily</Frequency>
               </Schedule>
               <Filter>
                  <Prefix>prefix/Three</Prefix>
               </Filter>
               <IncludedObjectVersions>All</IncludedObjectVersions>
               <OptionalFields>
                  <Field>Size</Field>
                  <Field>LastModifiedDate</Field>
                  <Field>ETag</Field>
                  <Field>StorageClass</Field>
                  <Field>IsMultipartUploaded</Field>
                  <Field>ReplicationStatus</Field>
               </OptionalFields>
            </InventoryConfiguration>
            <IsTruncated>false</IsTruncated>
        </ListInventoryConfigurationsResult>
    ">>}},
    ExpectedResult =
        {ok, [
            {inventory_configuration, [
                [
                    {id, "report1"},
                    {is_enabled, "true"},
                    {filter, [{prefix, "prefix/One"}]},
                    {destination,
                        [{s3_bucket_destination, [
                            {format, "CSV"},
                            {account_id, "123456789012"},
                            {bucket, "arn:aws:s3:::destination-bucket"},
                            {prefix, "prefix1"}]}]
                    },
                    {schedule, [{frequency, "Daily"}]},
                    {included_object_versions, "All"},
                    {optional_fields, [
                        {field, [
                            "Size",
                            "LastModifiedDate",
                            "ETag",
                            "StorageClass",
                            "IsMultipartUploaded",
                            "ReplicationStatus"
                        ]}
                    ]}
                ],
                [
                    {id, "report2"},
                    {is_enabled, "true"},
                    {filter, [{prefix, "prefix/Two"}]},
                    {destination,
                        [{s3_bucket_destination, [
                            {format, "CSV"},
                            {account_id, "123456789012"},
                            {bucket, "arn:aws:s3:::bucket2"},
                            {prefix, "prefix2"}]}]
                    },
                    {schedule, [{frequency, "Daily"}]},
                    {included_object_versions, "All"},
                    {optional_fields, [
                        {field, [
                            "Size",
                            "LastModifiedDate",
                            "ETag",
                            "StorageClass",
                            "IsMultipartUploaded",
                            "ReplicationStatus"
                        ]}
                    ]}
                ],
                [
                    {id, "report3"},
                    {is_enabled, "true"},
                    {filter, [{prefix, "prefix/Three"}]},
                    {destination,
                        [{s3_bucket_destination, [
                            {format, "CSV"},
                            {account_id, "123456789012"},
                            {bucket, "arn:aws:s3:::bucket3"},
                            {prefix, "prefix3"}]}]
                    },
                    {schedule, [{frequency, "Daily"}]},
                    {included_object_versions, "All"},
                    {optional_fields, [
                        {field, [
                            "Size",
                            "LastModifiedDate",
                            "ETag",
                            "StorageClass",
                            "IsMultipartUploaded",
                            "ReplicationStatus"
                        ]}
                    ]}
                ]
            ]}
        ]},
    meck:expect(erlcloud_httpc, request, httpc_expect(Response)),
    Result = erlcloud_s3:list_bucket_inventory("BucketName", config()),
    ?_assertEqual(
        ExpectedResult,
        Result).


get_inventory_configuration_test(_) ->
    Response = {ok, {{200, "OK"}, [], <<"
        <InventoryConfiguration xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\">
           <Id>report1</Id>
           <IsEnabled>true</IsEnabled>
           <Filter>
              <Prefix>filterPrefix</Prefix>
           </Filter>
           <Destination>
              <S3BucketDestination>
                 <Format>CSV</Format>
                 <AccountId>123456789012</AccountId>
                 <Bucket>arn:aws:s3:::destination-bucket</Bucket>
                 <Prefix>prefix1</Prefix>
              </S3BucketDestination>
           </Destination>
           <Schedule>
              <Frequency>Daily</Frequency>
           </Schedule>
           <IncludedObjectVersions>All</IncludedObjectVersions>
           <OptionalFields>
              <Field>Size</Field>
              <Field>LastModifiedDate</Field>
              <Field>ETag</Field>
              <Field>StorageClass</Field>
              <Field>IsMultipartUploaded</Field>
              <Field>ReplicationStatus</Field>
           </OptionalFields>
        </InventoryConfiguration>">>}},
    ExpectedResult =
        {ok, [
            {id, "report1"},
            {is_enabled, "true"},
            {filter, [{prefix, "filterPrefix"}]},
            {destination,
                [{s3_bucket_destination, [
                    {format, "CSV"},
                    {account_id, "123456789012"},
                    {bucket, "arn:aws:s3:::destination-bucket"},
                    {prefix, "prefix1"}]}]
            },
            {schedule, [{frequency, "Daily"}]},
            {included_object_versions, "All"},
            {optional_fields, [
                {field, [
                    "Size",
                    "LastModifiedDate",
                    "ETag",
                    "StorageClass",
                    "IsMultipartUploaded",
                    "ReplicationStatus"
                ]}
            ]}
        ]},
    meck:expect(erlcloud_httpc, request, httpc_expect(Response)),
    Result = erlcloud_s3:get_bucket_inventory("BucketName", "report1", config()),
    ?_assertEqual(
        ExpectedResult,
        Result).

encode_inventory_test(_)->
    ExpectedXml =
        "<?xml version=\"1.0\"?>"
            "<InventoryConfiguration xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\">"
                "<Id>report1</Id>"
                "<IsEnabled>true</IsEnabled>"
               "<Filter>"
                  "<Prefix>filterPrefix</Prefix>"
               "</Filter>"
               "<Destination>"
                  "<S3BucketDestination>"
                     "<Format>CSV</Format>"
                     "<AccountId>123456789012</AccountId>"
                     "<Bucket>arn:aws:s3:::destination-bucket</Bucket>"
                     "<Prefix>prefix1</Prefix>"
                  "</S3BucketDestination>"
               "</Destination>"
               "<Schedule>"
                  "<Frequency>Daily</Frequency>"
               "</Schedule>"
               "<IncludedObjectVersions>All</IncludedObjectVersions>"
               "<OptionalFields>"
                  "<Field>Size</Field>"
                  "<Field>LastModifiedDate</Field>"
                  "<Field>ETag</Field>"
                  "<Field>StorageClass</Field>"
                  "<Field>IsMultipartUploaded</Field>"
                  "<Field>ReplicationStatus</Field>"
               "</OptionalFields>"
            "</InventoryConfiguration>",
    Inventory =
        [
            {id, "report1"},
            {is_enabled, "true"},
            {filter, [{prefix, "filterPrefix"}]},
            {destination,
                [{s3_bucket_destination, [
                    {format, "CSV"},
                    {account_id, "123456789012"},
                    {bucket, "arn:aws:s3:::destination-bucket"},
                    {prefix, "prefix1"}]}]
            },
            {schedule, [{frequency, "Daily"}]},
            {included_object_versions, "All"},
            {optional_fields, [
                {field, [
                    "Size",
                    "LastModifiedDate",
                    "ETag",
                    "StorageClass",
                    "IsMultipartUploaded",
                    "ReplicationStatus"
                ]}
            ]}
        ],
    Result  = erlcloud_s3:encode_inventory(Inventory),
    ?_assertEqual(ExpectedXml, Result).

put_bucket_inventory_test(_) ->
    Response =
        {ok,
            {
                {200,"OK"},
                [
                    {"server","AmazonS3"},
                    {"content-length","0"},
                    {"date","Mon, 31 Oct 2016 12:00:00 GMT"},
                    {"x-amz-request-id","236A8905248E5A01"},
                    {"x-amz-id-2",
                        "YgIPIfBiKa2bj0KMg95r/0zo3emzU4dzsD4rcKCHQUAdQkf3ShJTOOpXUueF6QKo"}
                ],
                <<>>
            }
        },
    meck:expect(erlcloud_httpc, request, httpc_expect(put, Response)),
    Inventory =
        [
            {id, "report1"},
            {is_enabled, "true"},
            {filter, [{prefix, "filterPrefix"}]},
            {destination,
                [{s3_bucket_destination, [
                    {format, "CSV"},
                    {account_id, "123456789012"},
                    {bucket, "arn:aws:s3:::destination-bucket"},
                    {prefix, "prefix1"}]}]
            },
            {schedule, [{frequency, "Daily"}]},
            {included_object_versions, "All"},
            {optional_fields, [
                {field, [
                    "Size",
                    "LastModifiedDate",
                    "ETag",
                    "StorageClass",
                    "IsMultipartUploaded",
                    "ReplicationStatus"
                ]}
            ]}
        ],
    Result = erlcloud_s3:put_bucket_inventory("BucketName", Inventory, config()),
    ?_assertEqual(ok, Result).

delete_bucket_inventory_test(_) ->
    Response =
        {ok,
            {
                {204,"No Content"},
                [
                    {"server","AmazonS3"},
                    {"date","Wed, 14 May 2014 02:11:22 GMT"},
                    {"x-amz-request-id","0CF038E9BCF63097"},
                    {"x-amz-id-2",
                        "0FmFIWsh/PpBuzZ0JFRC55ZGVmQW4SHJ7xVDqKwhEdJmf3q63RtrvH8ZuxW1Bol5"}
                ],
                <<>>
            }
        },
    meck:expect(erlcloud_httpc, request, httpc_expect(delete, Response)),
    Result = erlcloud_s3:delete_bucket_inventory("BucketName", "report1", config()),
    ?_assertEqual(ok, Result).

delete_objects_batch_single_tests(_) ->
    Response = {ok, {{200, "OK"}, [], <<"<?xml version=\"1.0\" encoding=\"UTF-8\"?><DeleteResult xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\"><Deleted><Key>sample1.txt</Key></Deleted></DeleteResult>">>}},
    meck:expect(erlcloud_httpc, request, httpc_expect(post, Response)),
    Result = erlcloud_s3:delete_objects_batch("BucketName",["sample1.txt"], config()),
    ?_assertEqual([{deleted,["sample1.txt"]},{error,[]}], Result).

delete_objects_batch_tests(_) ->
    Response = {ok, {{200, "OK"}, [], <<"<?xml version=\"1.0\" encoding=\"UTF-8\"?>
<DeleteResult xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\"><Deleted><Key>sample1.txt</Key></Deleted><Deleted><Key>sample2.txt</Key></Deleted><Deleted><Key>sample3.txt</Key></Deleted></DeleteResult>">>}},
    meck:expect(erlcloud_httpc, request, httpc_expect(post, Response)),
    Result = erlcloud_s3:delete_objects_batch("BucketName",["sample1.txt","sample2.txt","sample3.txt"], config()),
    ?_assertEqual([{deleted,["sample1.txt", "sample2.txt","sample3.txt"]},{error,[]}], Result).

delete_objects_batch_with_err_tests(_) ->
    Response = {ok, {{200, "OK"}, [], <<"<?xml version=\"1.0\" encoding=\"UTF-8\"?><DeleteResult xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\"><Error><Key>sample2.txt</Key><Code>AccessDenied</Code><Message>Access Denied</Message></Error></DeleteResult>">>}},
    meck:expect(erlcloud_httpc, request, httpc_expect(post, Response)),
    Result = erlcloud_s3:delete_objects_batch("BucketName",["sample2.txt"], config()),
    ?_assertEqual([{deleted,[]}, {error,[{"sample2.txt","AccessDenied","Access Denied"}]}], Result).

delete_objects_batch_mixed_tests(_) ->
    Response = {ok, {{200, "OK"}, [], <<"<?xml version=\"1.0\" encoding=\"UTF-8\"?><DeleteResult xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\"><Deleted><Key>sample1.txt</Key></Deleted><Error><Key>sample2.txt</Key><Code>AccessDenied</Code><Message>Access Denied</Message></Error></DeleteResult>">>}},
    meck:expect(erlcloud_httpc, request, httpc_expect(post, Response)),
    Result = erlcloud_s3:delete_objects_batch("BucketName",["sample2.txt"], config()),
    ?_assertEqual([{deleted,["sample1.txt"]}, {error,[{"sample2.txt","AccessDenied","Access Denied"}]}], Result).

put_bucket_encryption_test(_) ->
    Response = {ok, {{201, "Created"}, [], <<>>}},
    meck:expect(erlcloud_httpc, request, httpc_expect(put, Response)),
    Cfg     = config(),
    KMSKey  = "arn:aws:kms:us-east-1:1234/5678example",
    Result1 = erlcloud_s3:put_bucket_encryption("bucket", "AES256", Cfg),
    Result2 = erlcloud_s3:put_bucket_encryption("bucket", "aws:kms", KMSKey, Cfg),
    [
        ?_assertEqual(ok, Result1),
        ?_assertEqual(ok, Result2)
    ].

get_bucket_encryption_test(_) ->
    Response = {ok, {{200, "OK"}, [], ?S3_BUCKET_ENCRYPTION}},
    meck:expect(erlcloud_httpc, request, httpc_expect(Response)),
    Result = erlcloud_s3:get_bucket_encryption("bucket", config()),
    ?_assertEqual(
        {ok, [{sse_algorithm,     "aws:kms"},
              {kms_master_key_id, "arn:aws:kms:us-east-1:1234/5678example"}]},
        Result
    ).

get_bucket_encryption_not_found_test(_) ->
    Response = {ok, {{404, "Not Found"}, [], ?S3_BUCKET_ENCRYPTION_NOT_FOUND}},
    meck:expect(erlcloud_httpc, request, httpc_expect(Response)),
    Result = erlcloud_s3:get_bucket_encryption("bucket", config()),
    ?_assertEqual(
        {error, {http_error, 404, "Not Found", ?S3_BUCKET_ENCRYPTION_NOT_FOUND}},
        Result
    ).

delete_bucket_encryption_test(_) ->
    Response = {ok, {{204, "No Content"}, [], <<>>}},
    meck:expect(erlcloud_httpc, request, httpc_expect(delete, Response)),
    Result = erlcloud_s3:delete_bucket_encryption("bucket", config()),
    ?_assertEqual(ok, Result).

hackney_proxy_put_validation_test(_) ->
    Response = {ok, {{200, "OK"}, [{"x-amz-version-id", "version_id"}], <<>>}},
    Config2 = #aws_config{hackney_client_options = #hackney_client_options{insecure = false,
			   proxy = <<"10.10.10.10">>,
			   proxy_auth = {<<"AAAA">>, <<"BBBB">>}},
			  http_client = hackney},
    meck:expect(erlcloud_httpc, request, httpc_expect(put, Response)),
    Result = erlcloud_s3:put_object("BucketName", "Key", "Data", config(Config2)),
    ?_assertEqual([{version_id, "version_id"}
                  ,{"x-amz-version-id", "version_id"}
                  ], Result).

get_bucket_and_key(_) ->
    ErlcloudS3ExportExample = "https://s3.amazonaws.com/some_bucket/path_to_file",
    Result = erlcloud_s3:get_bucket_and_key(ErlcloudS3ExportExample),
    ?_assertEqual({"some_bucket","path_to_file"}, Result).

signature_test(_) ->
    Config = (erlcloud_s3:new("", "", "api.chef-server.dev", 443))#aws_config{s3_scheme="https://", s3_bucket_after_host=true, s3_bucket_access_method=path},

    Path1        = "/bookshelf/organization-c126c62de951893e9deee6b794cf1350/checksum-6a85b976cd88d448beae87d2c35f10e2",
    Date1        = "20210108T194543Z",
    Region       = "us-east-1",
    Method1      = put,
    QueryParams1 = [{"X-Amz-Algorithm","AWS4-HMAC-SHA256"},
                   {"X-Amz-Credential",
                    ["8ab7976fbfba7fd648cf486b32e0ca1cca8bf894",47,
                     ["20210108",47,"us-east-1",47,"s3","/aws4_request"]]},
                   {"X-Amz-Date","20210108T194543Z"},
                   {"X-Amz-Expires","900"},
                   {"X-Amz-SignedHeaders","content-md5;content-type;host"}],
    Headers1     = [{"content-md5",<<"aoW5ds2I1Ei+rofSw18Q4g==">>},
                   {"content-type","application/x-binary"},
                   {"host","api.chef-server.dev:443"}],
    Payload      = "UNSIGNED-PAYLOAD",
    Result1      = erlcloud_s3:signature(Config, Path1, Date1, Region, Method1, QueryParams1, Headers1, Payload),

    Method2      = get,
    QueryParams2 = [{"X-Amz-Algorithm","AWS4-HMAC-SHA256"},
                   {"X-Amz-Credential",
                    ["8ab7976fbfba7fd648cf486b32e0ca1cca8bf894",47,
                     ["20210108",47,"us-east-1",47,"s3","/aws4_request"]]},
                   {"X-Amz-Date","20210108T194543Z"},
                   {"X-Amz-Expires","28800"},
                   {"X-Amz-SignedHeaders","host"}],
    Headers2     = [{"host","api.chef-server.dev:443"}],
    Result2      = erlcloud_s3:signature(Config, Path1, Date1, Region, Method2, QueryParams2, Headers2, Payload),

    [?_assertEqual(Result1, "d1ef3ccb5ce2d5d5927ba5a7d7f9e583f8ba20fa5a497e775d1a6de3e451ef4f"),
     ?_assertEqual(Result2, "89fd7cd94fd35e10a877e8cb3f2261c8697cba5930f59cd84223d9e46e97c29f")].

head_bucket_ok(_) ->
    Response = {ok, {{200, "OK"},
        [
            {"server","AmazonS3"},
            {"transfer-encoding","chunked"},
            {"content-type","application/xml"},
            {"x-amz-access-point-alias","false"},
            {"x-amz-bucket-region","us-west-2"},
            {"date","Mon, 21 Apr 2025 19:45:15 GMT"},
            {"x-amz-id-2",
                "YIgyI9Lb9I/dMpDrRASSD8w5YsNAyhRlF+PDF0jlf9Hq6eVLvSkuj+ftZI2RmU5eXnOKW1Wqh20="},
            {"x-amz-request-id","FAECC30C2CD53BCA"}
        ],
        <<>>}
    },
    meck:expect(erlcloud_httpc, request, httpc_expect(head, Response)),
    Result = erlcloud_s3:head_bucket(
        "bucket.name",
        config()),
    ?_assertEqual(
        [
            {content_length,undefined},
            {content_type,"application/xml"},
            {access_point_alias,"false"},
            {bucket_region,"us-west-2"}
        ], Result
    ).

head_bucket_redirect(_) ->
    Response1 = {ok, {{307, "Temporary Redirect"},
        [
            {"server","AmazonS3"},
            {"transfer-encoding","chunked"},
            {"content-type","application/xml"},
            {"location", "https://bucket.name.s3-us-west-2.amazonaws.com/"},
            {"x-amz-bucket-region","us-west-2"},
            {"date","Mon, 21 Apr 2025 19:45:15 GMT"},
            {"x-amz-id-2",
                "YIgyI9Lb9I/dMpDrRASSD8w5YsNAyhRlF+PDF0jlf9Hq6eVLvSkuj+ftZI2RmU5eXnOKW1Wqh20="},
            {"x-amz-request-id","FAECC30C2CD53BCA"}
        ],
        <<>>}
    },
    Response2 = {ok, {{200, "OK"},
        [
            {"server","AmazonS3"},
            {"transfer-encoding","chunked"},
            {"content-type","application/xml"},
            {"x-amz-access-point-alias","false"},
            {"x-amz-bucket-region","us-west-2"},
            {"date","Mon, 21 Apr 2025 19:45:15 GMT"},
            {"x-amz-id-2",
                "YIgyI9Lb9I/dMpDrRASSD8w5YsNAyhRlF+PDF0jlf9Hq6eVLvSkuj+ftZI2RmU5eXnOKW1Wqh20="},
            {"x-amz-request-id","FAECC30C2CD53BCA"}
        ],
        <<>>}
    },
    meck:sequence(erlcloud_httpc, request, 6, [Response1, Response2]),
    Result = erlcloud_s3:head_bucket(
        "bucket.name",
        config()),
    ?_assertEqual(
        [
            {content_length,undefined},
            {content_type,"application/xml"},
            {access_point_alias,"false"},
            {bucket_region,"us-west-2"}
        ], Result
    ).

head_bucket_bad_request(_) ->
    Response = {ok, {{400, "Bad Request"},
        [
            {"server","AmazonS3"},
            {"transfer-encoding","chunked"},
            {"content-type","application/xml"},
            {"date","Mon, 21 Apr 2025 19:45:15 GMT"},
            {"connection", "close"},
            {"x-amz-id-2",
                "YIgyI9Lb9I/dMpDrRASSD8w5YsNAyhRlF+PDF0jlf9Hq6eVLvSkuj+ftZI2RmU5eXnOKW1Wqh20="},
            {"x-amz-request-id","FAECC30C2CD53BCA"}
        ], <<>>}},
    meck:expect(erlcloud_httpc, request, httpc_expect(head, Response)),
    ?_assertException(
        error,
        {aws_error, {http_error, 400, "Bad Request", <<>>}},
        erlcloud_s3:head_bucket("bucket.name", config())
    ).

head_bucket_forbidden(_) ->
    Response = {ok, {{403, "Forbidden"},
        [
            {"server","AmazonS3"},
            {"transfer-encoding","chunked"},
            {"content-type","application/xml"},
            {"date","Mon, 21 Apr 2025 19:45:15 GMT"},
            {"x-amz-bucket-region","us-west-2"},
            {"x-amz-id-2",
                "YIgyI9Lb9I/dMpDrRASSD8w5YsNAyhRlF+PDF0jlf9Hq6eVLvSkuj+ftZI2RmU5eXnOKW1Wqh20="},
            {"x-amz-request-id","FAECC30C2CD54BCA"}
        ], <<>>}},
    meck:expect(erlcloud_httpc, request, httpc_expect(head, Response)),
    ?_assertException(
        error,
        {aws_error, {http_error, 403, "Forbidden", <<>>}},
        erlcloud_s3:head_bucket("bucket.name", config())
    ).

head_bucket_not_found(_) ->
    Response = {ok, {{404, "Not Found"},
        [
            {"server","AmazonS3"},
            {"transfer-encoding","chunked"},
            {"content-type","application/xml"},
            {"date","Mon, 21 Apr 2025 19:45:15 GMT"},
            {"x-amz-id-2",
                "YIgyI9Lb9I/dMpDrRASSD8w5YsNAyhRlF+PDF0jlf9Hq6eVLvSkuj+ftZI2RmU5eXnOKW1Wqh20="},
            {"x-amz-request-id","FAECC30C2CD54CCA"}
        ], <<>>}},
    meck:expect(erlcloud_httpc, request, httpc_expect(head, Response)),
    ?_assertException(
        error,
        {aws_error, {http_error, 404, "Not Found", <<>>}},
        erlcloud_s3:head_bucket("bucket.name", config())
    ).
