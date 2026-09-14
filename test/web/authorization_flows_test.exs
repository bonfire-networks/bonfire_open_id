defmodule Bonfire.OpenID.Web.AuthorizationFlowsTest do
  use Bonfire.OpenID.ConnCase, async: false
  import PhoenixTest

  alias Bonfire.OpenID.Provider.ClientApps
  alias Bonfire.UI.Common.Testing.Helpers
  require Logger

  @moduletag capture_log: true
  @redirect_uri "http://localhost:4000/oauth/client/authorization-review"

  setup tags do
    previous = Application.get_env(:bonfire_open_id, :oauth_module)
    Application.put_env(:bonfire_open_id, :oauth_module, Boruta.Oauth)
    on_exit(fn -> Application.put_env(:bonfire_open_id, :oauth_module, previous) end)

    account = Helpers.fake_account!()
    user = Helpers.fake_user!(account)
    client = ClientApps.init_test_client_app(Faker.UUID.v4(), %{
      name: "Authorization review",
      redirect_uris: [@redirect_uri],
      pkce: tags[:pkce] || false,
      confidential: tags[:public_client] != true,
      supported_scopes: ["read", "write", "openid", "profile", "email", "offline_access"]
    })

    {:ok, account: account, user: user, client: client,
      conn: conn(user: user, account: account)}
  end

  for protocol <- ["oauth", "openid"] do
    @protocol protocol

    test "#{protocol}: first consent issues a code, token exchange works and consent is remembered", c do
      path = authorization_path(@protocol, c.client)
      callback = approve(c.conn, path)
      code = callback |> URI.parse() |> Map.fetch!(:query) |> URI.decode_query() |> Map.fetch!("code")
      token = exchange(@protocol, c.client, code)
      assert is_binary(token["access_token"])
      assert is_binary(token["refresh_token"])
      if @protocol == "openid", do: assert(is_binary(token["id_token"]))

      c.conn |> get(path) |> redirected_to() |> assert_callback()

      response = build_conn() |> post("/#{@protocol}/token", token_params(c.client, code))
      assert response.status in [400, 401]
      refute Map.has_key?(json_response(response, response.status), "access_token")
    end

    test "#{protocol}: denying consent preserves state and does not issue a code", c do
      {:ok, view, _} = live(c.conn, authorization_path(@protocol, c.client))
      assert {:error, {:redirect, %{to: callback}}} =
        view |> element("[data-role=oauth_consent_deny]") |> render_click()
      params = callback |> URI.parse() |> Map.fetch!(:query) |> URI.decode_query()
      assert params["state"] == "review-state"
      assert params["error"] == "access_denied"
      refute Map.has_key?(params, "code")
    end

    test "#{protocol}: magic-link first consent preserves the authorization request", c do
      Process.put([:bonfire_ui_me, :login, :passwordless_only], true)
      email = c.account.email |> Bonfire.Data.Identity.Email.put_token() |> Bonfire.Common.Repo.update!()
      path = authorization_path(@protocol, c.client)
      login = conn() |> get("/login/forgot-password/#{email.confirm_token}?go=#{URI.encode_www_form(path)}")
      assert login.status == 200
      {:ok, view, _} = live(login)
      assert {:error, {:live_redirect, %{to: next}}} =
        view |> element("[data-role=oauth_consent_allow]") |> render_click()
      assert URI.parse(next).path == "/#{@protocol}/authorize"
      assert URI.decode_query(URI.parse(next).query) == URI.decode_query(URI.parse(path).query)
      login |> recycle() |> get(next) |> redirected_to() |> assert_callback()
    end

    # The OpenID controller has no equivalent of the OAuth controller's redirect_to_pick_profile,
    # so an account-only session is sent to login instead of the profile picker.
    @tag :fixme
    test "#{protocol}: account-only session can select a profile and reach consent", c do
      Helpers.fake_user!(c.account, %{name: "Review Second Profile"})
      probe = conn(account: c.account) |> get(authorization_path(@protocol, c.client))
      Logger.info("Authorization profile probe: " <> inspect(%{protocol: @protocol, status: probe.status,
        location_path: probe |> get_resp_header("location") |> List.first() |> then(fn location -> if location, do: URI.parse(location).path end),
        account_loaded: is_map(probe.assigns[:current_account]), user_loaded: is_map(probe.assigns[:current_user])}))
      conn(account: c.account)
      |> visit(authorization_path(@protocol, c.client))
      |> wait_async()
      |> assert_has(~s|a[href*="/switch-user/"]|)
      |> click_link(~s|a[href*="/switch-user/"]|, "Review Second Profile")
      |> wait_async()
      |> assert_has("[data-role=oauth_consent_allow]")
    end

    test "#{protocol}: unregistered callback cannot receive a code", c do
      response = c.conn |> get(authorization_path(@protocol, c.client,
        %{"redirect_uri" => "https://unregistered.example/callback"}))
      refute Enum.any?(get_resp_header(response, "location"), &String.starts_with?(&1, "https://unregistered.example"))
      assert response.status in [400, 401, 403, 422]
    end

    @tag pkce: true
    test "#{protocol}: PKCE code exchange rejects the wrong verifier and accepts the correct one", c do
      verifier = :crypto.strong_rand_bytes(32) |> Base.url_encode64(padding: false)
      challenge = :crypto.hash(:sha256, verifier) |> Base.url_encode64(padding: false)
      callback = approve(c.conn, authorization_path(@protocol, c.client,
        %{"code_challenge" => challenge, "code_challenge_method" => "S256"}))
      code = callback |> URI.parse() |> Map.fetch!(:query) |> URI.decode_query() |> Map.fetch!("code")
      bad = build_conn() |> post("/#{@protocol}/token", Map.put(token_params(c.client, code), "code_verifier", String.duplicate("x", 43)))
      assert bad.status in [400, 401]
      refute Map.has_key?(json_response(bad, bad.status), "access_token")
      good = exchange(@protocol, c.client, code, %{"code_verifier" => verifier})
      assert is_binary(good["access_token"])
    end

    test "#{protocol}: refresh and revocation use the issued credentials", c do
      callback = approve(c.conn, authorization_path(@protocol, c.client))
      code = callback |> URI.parse() |> Map.fetch!(:query) |> URI.decode_query() |> Map.fetch!("code")
      token = exchange(@protocol, c.client, code)
      refreshed = build_conn() |> post("/#{@protocol}/token", %{
        "grant_type" => "refresh_token", "refresh_token" => token["refresh_token"],
        "client_id" => c.client.id, "client_secret" => c.client.secret
      }) |> json_response(200)
      assert is_binary(refreshed["access_token"])
      build_conn() |> post("/oauth/revoke", %{"token" => refreshed["access_token"],
        "client_id" => c.client.id, "client_secret" => c.client.secret}) |> response(200)
      rejected = build_conn() |> put_req_header("authorization", "Bearer " <> refreshed["access_token"])
        |> get("/api/v1/accounts/verify_credentials")
      assert rejected.status == 401
    end

    test "#{protocol}: implicit authorization returns tokens in the callback fragment", c do
      type = if @protocol == "openid", do: "id_token token", else: "token"
      {:ok, view, _} = live(c.conn, authorization_path(@protocol, c.client, %{"response_type" => type}))
      assert {:error, {:live_redirect, %{to: next}}} =
        view |> element("[data-role=oauth_consent_allow]") |> render_click()
      callback = c.conn |> get(next) |> redirected_to() |> URI.parse()
      assert callback.path == URI.parse(@redirect_uri).path
      params = URI.decode_query(callback.fragment)
      assert params["state"] == "review-state"
      assert is_binary(params["access_token"])
      if @protocol == "openid", do: assert(is_binary(params["id_token"]))
      refute Map.has_key?(params, "code")
    end

    @tag pkce: true, public_client: true
    test "#{protocol}: public PKCE client exchanges its code without a client secret", c do
      verifier = :crypto.strong_rand_bytes(32) |> Base.url_encode64(padding: false)
      challenge = :crypto.hash(:sha256, verifier) |> Base.url_encode64(padding: false)
      callback = approve(c.conn, authorization_path(@protocol, c.client,
        %{"code_challenge" => challenge, "code_challenge_method" => "S256"}))
      code = callback |> URI.parse() |> Map.fetch!(:query) |> URI.decode_query() |> Map.fetch!("code")
      token = exchange(@protocol, c.client, code, %{"code_verifier" => verifier})
      assert is_binary(token["access_token"])
    end
  end

  test "client credentials issues an app token that cannot impersonate a user", c do
    token = build_conn() |> post("/oauth/token", %{"grant_type" => "client_credentials",
      "client_id" => c.client.id, "client_secret" => c.client.secret, "scope" => "read"}) |> json_response(200)
    assert is_binary(token["access_token"])
    result = build_conn() |> put_req_header("authorization", "Bearer " <> token["access_token"])
      |> get("/api/v1/accounts/verify_credentials")
    assert result.status == 401
  end

  test "openid: prompt none does not display login or consent to a logged-out user", c do
    response = conn() |> get(authorization_path("openid", c.client, %{"prompt" => "none"}))
    callback = response |> redirected_to() |> URI.parse()
    assert callback.path == URI.parse(@redirect_uri).path
    params = URI.decode_query(callback.query || callback.fragment)
    assert params["error"] == "login_required"
    assert params["state"] == "review-state"
  end

  test "openid: prompt login redirects a signed-in user to reauthenticate", c do
    callback = c.conn |> get(authorization_path("openid", c.client, %{"prompt" => "login"})) |> redirected_to()
    assert URI.parse(callback).path == Bonfire.Common.URIs.path(:logout)
  end

  defp authorization_path(protocol, client, extra \\ %{}) do
    params = %{"response_type" => "code", "client_id" => client.id,
      "redirect_uri" => @redirect_uri, "scope" => if(protocol == "openid", do: "openid profile email", else: "read write"),
      "state" => "review-state", "nonce" => "review-nonce"} |> Map.merge(extra)
    "/#{protocol}/authorize?" <> Plug.Conn.Query.encode(params)
  end

  defp approve(conn, path) do
    {:ok, view, _} = live(conn, path)
    assert {:error, {:live_redirect, %{to: next}}} =
      view |> element("[data-role=oauth_consent_allow]") |> render_click()
    callback = conn |> get(next) |> redirected_to()
    assert_callback(callback)
    callback
  end

  defp assert_callback(callback) do
    assert String.starts_with?(callback, @redirect_uri <> "?")
    params = callback |> URI.parse() |> Map.fetch!(:query) |> URI.decode_query()
    assert params["state"] == "review-state"
    assert is_binary(params["code"])
    refute Map.has_key?(params, "error")
  end

  defp token_params(client, code) do
    params = %{"grant_type" => "authorization_code", "code" => code,
      "client_id" => client.id, "redirect_uri" => @redirect_uri}
    if client.confidential, do: Map.put(params, "client_secret", client.secret), else: params
  end

  defp exchange(protocol, client, code, extra \\ %{}) do
    build_conn() |> post("/#{protocol}/token", Map.merge(token_params(client, code), extra)) |> json_response(200)
  end
end
