%%%----------------------------------------------------------------------
%%% File    : mod_signup_keyword.erl
%%% Purpose : Keyword-gated In-Band Registration (XEP-0077)
%%% Created : 2026-07-12
%%%
%%% A reusable shared keyword gate on IBR, for friend-of-a-friend signup
%%% on a private XMPP service (your XMPP service). NOT XEP-0445 — that spec is
%%% strictly single-use (one token -> one invitee, bound on first use),
%%% which is the wrong shape for "give every friend the same word."
%%%
%%% Trade-off: if the keyword leaks, anyone who finds the host can register.
%%% Mitigations: constant-time comparison, ejabberd's registration_timeout
%%% (built-in per-IP rate limit), failed-attempt logging (keyword never
%%% logged), and keyword rotation by editing the on-box config.
%%%
%%% Wire protocol (XEP-0004 data form inside jabber:iq:register):
%%%
%%%   GET form:
%%%     <iq type='get' to='HOST'>
%%%       <query xmlns='jabber:iq:register'/>
%%%     </iq>
%%%
%%%   Server replies with a data form advertising three fields:
%%%     username (text-single), password (text-private), keyword (text-private)
%%%     + hidden FORM_TYPE = "urn:xmpp:signup:keyword:0"
%%%
%%%   SET registration:
%%%     <iq type='set' to='HOST'>
%%%       <query xmlns='jabber:iq:register'>
%%%         <x xmlns='jabber:x:data' type='submit'>
%%%           <field var='username'><value>alice</value></field>
%%%           <field var='password'><value>s3cret-pass</value></field>
%%%           <field var='keyword'><value>your-shared-keyword</value></field>
%%%         </x>
%%%       </query>
%%%     </iq>
%%%
%%% The keyword is read from the module config (set on-box, never in source).
%%% Account creation delegates to ejabberd_auth:try_register/3 so SCRAM
%%% hashing, Mnesia, and the existing auth stack are reused unchanged.
%%%
%%%------------------------------------------------------------------------
%%%
%%% ejabberd, Copyright (C) 2002-2026   ProcessOne
%%%
%%% This program is free software; you can redistribute it and/or
%%% modify it under the terms of the GNU General Public License as
%%% published by the Free Software Foundation; either version 2 of the
%%% License, or (at your option) any later version.
%%%
%%% This program is distributed in the hope that it will be useful,
%%% but WITHOUT ANY WARRANTY; without even the implied warranty of
%%% MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
%%% General Public License for more details.
%%%
%%%----------------------------------------------------------------------

-module(mod_signup_keyword).

-author('mod_signup_keyword contributors').

-protocol({xep, 77, '2.4', '1.0.0', "complete", ""}).
-protocol({xep, 4, '2.9', '1.0.0', "complete", ""}).

-behaviour(gen_mod).

%% gen_mod
-export([start/2, stop/1, reload/3, mod_options/1, mod_opt_type/1, mod_doc/0,
         depends/2]).

%% hooks and iq handler
-export([stream_feature_register/2, process_iq/1, c2s_unauthenticated_packet/2]).

%% helpers (exported for the shell / tests)
-export([constant_time_eq/2, extract_field/2]).

-include("logger.hrl").
-include_lib("xmpp/include/xmpp.hrl").
-include("translate.hrl").

%% XEP-0004 FORM_TYPE for our custom registration form. Clients that don't
%% know it still render the fields generically (a data form is a data form).
-define(NS_SIGNUP, <<"urn:xmpp:signup:keyword:0">>).

%% Form field variable names. Keep these stable — Mach and any other client
%% is coded against them.
-define(F_USERNAME, <<"username">>).
-define(F_PASSWORD, <<"password">>).
-define(F_KEYWORD,  <<"keyword">>).

%%%===================================================================
%%% gen_mod callbacks
%%%===================================================================

start(Host, _Opts) ->
    %% Register the unauthenticated-packet hook EXPLICITLY (not via the
    %% {hook,...} gen_mod return tuple). The gen_mod tuple machinery registers
    %% on the host key passed to start/2, but ejabberd_c2s registers its own
    %% reject hook the same way and the ordering must be deterministic. Doing
    %% it explicitly with ejabberd_hooks:add/5 (the pattern proven by
    %% mod_agents in this codebase) makes the registration bulletproof.
    %% Priority 50 < ejabberd_c2s's 100, so we run first and can {stop,...}.
    ejabberd_hooks:add(c2s_unauthenticated_packet, Host, ?MODULE,
                       c2s_unauthenticated_packet, 50),
    {ok, [{iq_handler, ejabberd_local, ?NS_REGISTER, process_iq},
          {iq_handler, ejabberd_sm, ?NS_REGISTER, process_iq},
          {hook, c2s_pre_auth_features, stream_feature_register, 50}]}.

stop(Host) ->
    ejabberd_hooks:delete(c2s_unauthenticated_packet, Host, ?MODULE,
                          c2s_unauthenticated_packet, 50),
    ok.

reload(_Host, _NewOpts, _OldOpts) ->
    ok.

%% We do NOT depend on mod_register. We own the jabber:iq:register IQ
%% namespace ourselves and call ejabberd_auth:try_register/3 directly.
%% Loading both modules would double-register the IQ handler.
depends(_Host, _Opts) ->
    [].

%%%===================================================================
%%% Stream feature advertisement
%%%===================================================================

%% Advertise <register xmlns='urn:xmpp:features:register'/> in the stream
%% features list so clients discover IBR is supported. mod_register does
%% the same; we mirror its gating logic (always advertise when loaded).
-spec stream_feature_register([xmpp_element()], binary()) -> [xmpp_element()].
stream_feature_register(Acc, _Host) ->
    [#feature_register{} | Acc].

%%%===================================================================
%%% Unauthenticated packet hook (pre-auth IBR)
%%%===================================================================

%% The c2s listener calls this hook for every stanza received BEFORE the
%% client authenticates. We intercept jabber:iq:register IQs here, process
%% them, and send the reply directly. Without this, c2s would reject the IQ
%% with <not-authorized/> and close the stream, because our ejabberd_local /
%% ejabberd_sm IQ handlers only run for authenticated sessions.
%%
%% State is the c2s state map; IP and server come from it. We set the IQ's
%% from/to so process_iq sees a well-formed request, then send the result.
%%
%% Mirrors mod_register.erl:74-94.
-spec c2s_unauthenticated_packet(map(), iq() | stanza()) -> map() | {stop, map()}.
c2s_unauthenticated_packet(State, #iq{type = T, sub_els = [_]} = IQ)
  when T == set; T == get ->
    try xmpp:try_subtag(IQ, #register{}) of
        #register{} = Register ->
            Server = maps:get(lserver, State, maps:get(server, State, <<>>)),
            IP = case maps:get(ip, State, undefined) of
                     {A, _} -> A;
                     _ -> undefined
                 end,
            %% Normalize from/to so process_iq/1 has a sane server context.
            IQ1 = xmpp:set_els(IQ, [Register]),
            IQ2 = xmpp:set_from_to(IQ1, jid:make(<<>>), jid:make(Server)),
            IQ3 = case IP of
                      undefined -> IQ2;
                      _ -> xmpp:set_meta(IQ2, #{ip => {IP, 0}})
                  end,
            ResIQ = process_iq(IQ3),
            ResIQ1 = xmpp:set_from_to(ResIQ, jid:make(Server), undefined),
            {stop, ejabberd_c2s:send(State, ResIQ1)};
        false ->
            %% Not a register IQ -- let c2s handle (or reject) normally.
            State
    catch
        C:R ->
            ?ERROR_MSG("signup_keyword: c2s hook crashed ~p:~p", [C, R]),
            Lang = maps:get(lang, State, <<>>),
            Err = xmpp:make_error(IQ, xmpp:err_bad_request(
                                         ?T("Malformed registration request"), Lang)),
            {stop, ejabberd_c2s:send(State, Err)}
    end;
c2s_unauthenticated_packet(State, _Packet) ->
    State.

%%%===================================================================
%%% IQ handler
%%%===================================================================

-spec process_iq(iq()) -> iq() | ignore.
process_iq(#iq{type = get, to = To} = IQ) ->
    %% GET: return a data form describing the fields we need.
    Server = To#jid.lserver,
    Instructions = gen_mod:get_module_opt(Server, ?MODULE, instructions),
    Form = signup_form(Server),
    Register = #register{instructions = Instructions, xdata = Form},
    xmpp:make_iq_result(IQ, Register);
process_iq(#iq{type = set, lang = Lang, to = To, from = From,
               sub_els = [SubEl]} = IQ) ->
    %% SET: validate keyword, then create account.
    %% SubEl is the first (and usually only) child of <query>, already decoded
    %% to a record by the XMPP codec. Match directly -- don't call try_subtag
    %% (that searches INSIDE an element, but SubEl IS the element).
    Server = To#jid.lserver,
    Source = source_ip(From, IQ),
    try
        case SubEl of
            #register{xdata = #xdata{type = submit, fields = Fields}} ->
                %% Data-form submission (the path Mach uses).
                handle_register(IQ, Lang, Server, Source, Fields);
            #register{username = User, password = Password, email = Email}
              when is_binary(User), is_binary(Password) ->
                %% Fallback: legacy jabber:iq:register fields with the keyword
                %% in <email/>. Tolerant, not advertised.
                Keyword = case is_binary(Email) of true -> Email; false -> <<>> end,
                handle_register(IQ, Lang, Server, Source,
                                [{?F_USERNAME, User},
                                 {?F_PASSWORD, Password},
                                 {?F_KEYWORD, Keyword}]);
            _ ->
                Txt = ?T("Malformed registration request"),
                make_error(IQ, xmpp:err_bad_request(Txt, Lang))
        end
    catch
        C:R ->
            ?ERROR_MSG("signup_keyword: process_iq SET crashed ~p:~p", [C, R]),
            make_error(IQ, xmpp:err_bad_request(
                            ?T("Malformed registration request"), Lang))
    end;
process_iq(#iq{lang = Lang} = IQ) ->
    Txt = ?T("Unsupported registration request"),
    make_error(IQ, xmpp:err_bad_request(Txt, Lang)).

%%%===================================================================
%%% Registration core
%%%===================================================================

-spec handle_register(iq(), binary(), binary(),
                      undefined | {inet:ip_address(), non_neg_integer()},
                      [{binary(), binary()}]) -> iq().
handle_register(IQ, Lang, Server, Source, Fields) ->
    Username = extract_field(?F_USERNAME, Fields),
    Password = extract_field(?F_PASSWORD, Fields),
    Keyword  = extract_field(?F_KEYWORD,  Fields),
    Expected = gen_mod:get_module_opt(Server, ?MODULE, keyword),
    case {Username, Password, Keyword} of
        {<<>>, _, _} ->
            make_error(IQ, xmpp:err_bad_request(?T("Missing username"), Lang));
        {_, <<>>, _} ->
            make_error(IQ, xmpp:err_bad_request(?T("Missing password"), Lang));
        {_, _, <<>>} ->
            make_error(IQ, xmpp:err_bad_request(?T("Missing keyword"), Lang));
        _ ->
            case valid_keyword(Keyword, Expected) of
                false ->
                    %% Deliberately generic message + log WITHOUT the keyword.
                    log_failed(Server, Username, Source, bad_keyword),
                    make_error(IQ, xmpp:err_not_allowed(
                                     ?T("Incorrect keyword"), Lang));
                true ->
                    case create_account(Username, Server, Password) of
                        ok ->
                            JID = jid:make(Username, Server),
                            send_welcome(JID, Server),
                            log_success(Server, Username, Source),
                            xmpp:make_iq_result(IQ);
                        {error, exists} ->
                            make_error(IQ, xmpp:err_conflict(
                                             ?T("That username is already taken"), Lang));
                        {error, invalid_jid} ->
                            make_error(IQ, xmpp:err_jid_malformed(
                                             ?T("Invalid username"), Lang));
                        {error, invalid_password} ->
                            make_error(IQ, xmpp:err_not_acceptable(
                                             ?T("Password not acceptable"), Lang));
                        {error, weak_password} ->
                            make_error(IQ, xmpp:err_not_acceptable(
                                             ?T("Password is too weak"), Lang));
                        {error, wait} ->
                            make_error(IQ, xmpp:err_resource_constraint(
                                             ?T("Too many registration attempts; "
                                                "please wait and try again"), Lang));
                        {error, not_allowed} ->
                            make_error(IQ, xmpp:err_not_allowed(
                                             ?T("Registration not allowed"), Lang));
                        {error, db_failure} ->
                            make_error(IQ, xmpp:err_internal_server_error(
                                             ?T("Account service temporarily "
                                                "unavailable"), Lang))
                    end
            end
    end.

%% Constant-time comparison so timing cannot leak the keyword byte-by-byte.
%% Length is already public (the form advertises a keyword field, not its
%% length), but we compare equal-length binaries in constant time anyway
%% and reject on length mismatch without revealing which length.
-spec valid_keyword(binary(), binary()) -> boolean().
valid_keyword(A, B) when is_binary(A), is_binary(B) ->
    case byte_size(A) =:= byte_size(B) of
        false -> false;
        true  -> constant_time_eq(A, B)
    end;
valid_keyword(_, _) ->
    false.

%% True only if A == B byte-for-byte, computed in time independent of the
%% contents. Walks both binaries in lockstep, OR-ing the running XOR into an
%% accumulator; the result is zero iff every byte matched. We track the index
%% ourselves rather than relying on foldl's accumulator because we need to
%% index into B in parallel with A.
-spec constant_time_eq(binary(), binary()) -> boolean().
constant_time_eq(A, B) when byte_size(A) =:= byte_size(B) ->
    Len = byte_size(A),
    Diff = constant_time_eq_loop(A, B, 0, Len, 0),
    Diff =:= 0.

-spec constant_time_eq_loop(binary(), binary(), non_neg_integer(),
                            non_neg_integer(), non_neg_integer()) ->
    non_neg_integer().
constant_time_eq_loop(_A, _B, Idx, Len, Acc) when Idx >= Len ->
    Acc;
constant_time_eq_loop(A, B, Idx, Len, Acc) ->
    BA = binary:at(A, Idx),
    BB = binary:at(B, Idx),
    constant_time_eq_loop(A, B, Idx + 1, Len, Acc bor (BA bxor BB)).

%% Pull a field value out of either a [{Var, Value}] proplist (our internal
%% shape) or a [#xdata_field{}] list (defensive: callers sometimes pass the
%% raw record list). Returns <<>> if absent.
-spec extract_field(binary(), [term()]) -> binary().
extract_field(Var, Fields) ->
    case lists:keyfind(Var, 1, Fields) of
        {Var, Val} when is_binary(Val) -> Val;
        false ->
            %% Maybe it's a list of #xdata_field{} records.
            case [F || #xdata_field{var = V} = F <- Fields, V =:= Var] of
                [#xdata_field{values = [Val | _]}] when is_binary(Val) -> Val;
                _ -> <<>>
            end
    end.

-spec create_account(binary(), binary(), binary()) ->
    ok | {error, exists | invalid_jid | invalid_password |
                    weak_password | wait | not_allowed | db_failure}.
create_account(User, Server, Password) ->
    case jid:is_nodename(User) of
        false ->
            {error, invalid_jid};
        true ->
            case is_reserved(User, Server) of
                true ->
                    %% Treat reserved-name collisions as "taken" so as not
                    %% to leak the reserved list via probing.
                    {error, exists};
                false ->
                    ejabberd_auth:try_register(User, Server, Password)
            end
    end.

-spec is_reserved(binary(), binary()) -> boolean().
is_reserved(User, Server) ->
    Reserved = gen_mod:get_module_opt(Server, ?MODULE, reserved_users),
    lists:member(User, Reserved).

%%%===================================================================
%%% Form construction
%%%===================================================================

-spec signup_form(binary()) -> #xdata{}.
signup_form(_Server) ->
    Fields =
        [#xdata_field{type = hidden, var = <<"FORM_TYPE">>, values = [?NS_SIGNUP]},
         #xdata_field{type = text_single, var = ?F_USERNAME,
                      label = ?T("Username"), required = true,
                      desc = ?T("Lowercase letters, digits, dot, dash, "
                                "or underscore. 1-31 chars.")},
         #xdata_field{type = text_private, var = ?F_PASSWORD,
                      label = ?T("Password"), required = true,
                      desc = ?T("At least 10 characters.")},
         #xdata_field{type = text_private, var = ?F_KEYWORD,
                      label = ?T("Signup keyword"), required = true,
                      desc = ?T("The keyword you were given by the person "
                                "who invited you.")}],
    #xdata{type = form,
           title = ?T("Create an account"),
           instructions = [?T("Fill in your chosen username and password, "
                              "plus the signup keyword from your inviter.")],
           fields = Fields}.

%%%===================================================================
%%% Side effects: welcome message + logging
%%%===================================================================

-spec send_welcome(jid:jid(), binary()) -> ok.
send_welcome(JID, Server) ->
    case gen_mod:get_module_opt(Server, ?MODULE, welcome_message) of
        <<>> ->
            ok;
        Body ->
            Msg = #message{type = normal,
                           from = jid:make(Server),
                           to = JID,
                           body = [#text{data = Body}],
                           subject = [#text{data = ?T("Welcome")}]},
            ejabberd_router:route(Msg),
            ok
    end.

-spec log_success(binary(), binary(),
                  undefined | {inet:ip_address(), non_neg_integer()}) -> ok.
log_success(Server, User, Source) ->
    ?INFO_MSG("Signup-keyword: account ~ts registered on ~ts from ~ts",
              [User, Server, fmt_source(Source)]),
    ok.

-spec log_failed(binary(), binary(),
                 undefined | {inet:ip_address(), non_neg_integer()}, atom()) -> ok.
log_failed(Server, User, Source, Reason) ->
    ?INFO_MSG("Signup-keyword: rejected ~ts on ~ts from ~ts (~ts)",
              [User, Server, fmt_source(Source), Reason]),
    ok.

-spec fmt_source(undefined | {inet:ip_address(), non_neg_integer()}) -> binary().
fmt_source(undefined) -> <<"unknown">>;
fmt_source({IP, _Port}) ->
    list_to_binary(inet:ntoa(IP)).

%%%===================================================================
%%% Helpers
%%%===================================================================

%% Recover the peer IP from the IQ metadata if present (set by c2s).
-spec source_ip(jid:jid() | undefined, iq()) ->
    undefined | {inet:ip_address(), non_neg_integer()}.
source_ip(_From, #iq{meta = Meta}) when is_map(Meta) ->
    case maps:get(ip, Meta, undefined) of
        {_, _} = IP -> IP;
        _ -> undefined
    end;
source_ip(_, _) ->
    undefined.

-spec make_error(iq(), stanza_error()) -> iq().
make_error(IQ, Err) ->
    xmpp:make_error(IQ, Err).

%%%===================================================================
%%% Options
%%%===================================================================

mod_opt_type(keyword) ->
    econf:binary();
mod_opt_type(welcome_message) ->
    econf:binary();
mod_opt_type(reserved_users) ->
    econf:list(econf:binary());
mod_opt_type(instructions) ->
    econf:binary();
mod_opt_type(_) ->
    [].

mod_options(Host) ->
    [{keyword, <<>>},
     {welcome_message,
      <<"Welcome. Your account is ready. Add your friends' "
        "JIDs to start chatting.">>},
     {reserved_users,
      [<<"admin">>, <<"administrator">>, <<"root">>, <<"signup">>,
       <<"ejabberd">>, <<"info">>, <<"support">>, <<"help">>, <<"postmaster">>,
       <<"system">>, <<"host">>, <<"server">>, <<"register">>, <<"bot">>,
       <<"alex">>, <<"www">>, <<"mail">>]},
     %% Mirrors the signup web app's instruction text.
     {instructions,
      iolist_to_binary(
        ["Choose a username and password, then enter the signup keyword "
         "for ", Host, ". Accounts are rate-limited per IP address."])}].

mod_doc() ->
    #{desc =>
          ?T("Keyword-gated In-Band Registration (XEP-0077). Requires a "
             "shared signup keyword in the registration form; validates it "
             "in constant time, then creates the account via the normal "
             "ejabberd auth stack. NOT XEP-0445: the keyword is reusable, "
             "not a single-use invite token. If the keyword leaks, anyone "
             "who finds the host can register -- mitigate with "
             "registration_timeout (built-in per-IP rate limit) and "
             "periodic keyword rotation."),
      opts =>
          [{keyword,
            #{value => ?T("binary"), required => true,
              desc =>
                  ?T("The shared signup keyword. Set this on the box "
                     "(not in source). Required for the module to accept "
                     "any registration.")}},
           {welcome_message,
            #{value => ?T("binary"),
              desc =>
                  ?T("Message body sent to a newly registered user. Empty "
                     "to disable.")}},
           {reserved_users,
            #{value => ?T("[binary]"),
              desc =>
                  ?T("Usernames that cannot be registered even with the "
                     "right keyword.")}},
           {instructions,
            #{value => ?T("binary"),
              desc => ?T("Instructions text in the registration form.")}}]}.
