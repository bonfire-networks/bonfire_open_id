defmodule Bonfire.OpenID.OAuthDanceTest do
  use Bonfire.OpenID.DanceCase, async: false
  use Patch, only: []

  @moduletag :test_instance

  use Arrows
  import Untangle
  import Bonfire.Common.Config, only: [repo: 0]
  use Bonfire.Common.E
  use Bonfire.Common.Config
  alias Bonfire.Common.Utils
  alias Bonfire.Common.TestInstanceRepo
  alias Bonfire.OpenID.Provider.ClientApps

  setup do
    redirect_uri = "http://localhost:4002/oauth/client/test_oauth_provider"
    main_instance = "http://localhost:4000"
    client_id = "b0f15e02-b0f1-b0f1-b0f1-b0f15eb0f15e"

    # Create client with OAuth scopes (different from OpenID Connect scopes)
    assert %Boruta.Ecto.Client{id: ^client_id} =
             client =
             ClientApps.init_test_client_app(client_id, %{
               redirect_uris: [redirect_uri],
               # OAuth scopes, no "openid"
               supported_scopes: ["identity", "data:public", "read", "write"]
             })
             |> debug("client created?")
             |> from_ok()

    %{
      client: client,
      client_id: client_id,
      redirect_uri: redirect_uri,
      main_instance: main_instance
    }
  end

  test "can login using OAuth with authorization code flow",
       %{client: client, redirect_uri: redirect_uri, main_instance: main_instance} = context do
    TestInstanceRepo.apply(fn ->
      assert Boruta.Config.repo() == TestInstanceRepo

      # Use DRY helper
      {_authorize_uri, access_token_uri} = setup_oauth_provider(client, main_instance)

      # Get tokens using DRY helper
      auth_url = get_auth_url(client.name)
      req = create_req_client(main_instance)
      login_response = perform_login_flow(req, auth_url, context)

      query_params = extract_query_params(login_response)
      auth_code = query_params["code"]
      assert auth_code, "Should receive authorization code"

      # Use DRY helper for token exchange
      token_data =
        exchange_code_for_tokens(req, access_token_uri, client, auth_code, redirect_uri)

      assert %{"access_token" => access_token} = token_data
      assert access_token, "Should receive access token"

      # Verify access token works
      verify_userinfo_endpoint(main_instance, access_token)
    end)
  end

  test "can login using OAuth with implicit flow",
       %{client: client, redirect_uri: redirect_uri, main_instance: main_instance} = context do
    TestInstanceRepo.apply(fn ->
      assert Boruta.Config.repo() == TestInstanceRepo

      # Use DRY helper with implicit flow options
      {_authorize_uri, _access_token_uri} =
        setup_oauth_provider(client, main_instance,
          response_type: "token",
          scope: "identity data:public"
        )

      # Rest of test unchanged...
      auth_url = get_auth_url(client.name)
      req = create_req_client(main_instance)
      login_response = perform_login_flow(req, auth_url, context)

      fragment_params = extract_fragment_params(login_response)
      access_token = fragment_params["access_token"]
      assert access_token, "Should receive access token in redirect fragment"

      verify_userinfo_endpoint(main_instance, access_token)
    end)
  end

  test "can authenticate using OAuth client credentials flow",
       %{client: client, main_instance: main_instance} = context do
    TestInstanceRepo.apply(fn ->
      assert Boruta.Config.repo() == TestInstanceRepo

      # Configure OAuth provider for client credentials flow
      access_token_uri = "#{main_instance}/oauth/token"

      provider_config = [
        test_oauth_provider: [
          display_name: client.name,
          client_id: client.id,
          client_secret: client.secret,
          access_token_uri: access_token_uri,
          # OAuth scopes for machine-to-machine
          scope: "identity data:public"
        ]
      ]

      Config.put(:oauth2_providers, provider_config, :bonfire_open_id)

      # Create request client
      req = create_req_client(main_instance)

      # Direct token request - no user login needed
      token_params = %{
        grant_type: "client_credentials",
        client_id: client.id,
        client_secret: client.secret,
        scope: "identity data:public"
      }

      {:ok, token_response} =
        Req.post(req,
          url: access_token_uri,
          form: token_params
        )

      # Verify we get access token
      assert %{"access_token" => access_token} = token_response.body
      assert access_token, "Should receive access token"
      assert token_response.body["token_type"] == "Bearer", "Should be Bearer token"

      # Optional: Check that no refresh token is issued (client credentials typically don't get refresh tokens)
      # refute Map.has_key?(token_response.body, "refresh_token"), "Client credentials flow should not return refresh token"

      # Verify access token works by making authenticated request
      verify_machine_to_machine_endpoint(main_instance, access_token)
    end)
  end

  test "can refresh OAuth tokens",
       %{client: client, redirect_uri: redirect_uri, main_instance: main_instance} = context do
    TestInstanceRepo.apply(fn ->
      assert Boruta.Config.repo() == TestInstanceRepo

      # Step 1: Get initial tokens using authorization code flow
      {access_token, refresh_token} =
        get_initial_tokens_with_refresh(client, redirect_uri, main_instance, context)

      # Verify initial access token works
      verify_userinfo_endpoint(main_instance, access_token)

      # Step 2: Use refresh token to get new access token
      access_token_uri = "#{main_instance}/oauth/token"
      req = create_req_client(main_instance)

      refresh_params = %{
        grant_type: "refresh_token",
        refresh_token: refresh_token,
        client_id: client.id,
        client_secret: client.secret
        # Note: scope is optional in refresh token requests
      }

      {:ok, refresh_response} =
        Req.post(req,
          url: access_token_uri,
          form: refresh_params
        )

      # Verify we get new tokens
      assert %{"access_token" => new_access_token} = refresh_response.body
      assert new_access_token, "Should receive new access token"

      assert new_access_token != access_token,
             "New access token should be different from original"

      # Check if we get a new refresh token (some systems rotate refresh tokens)
      new_refresh_token = refresh_response.body["refresh_token"]

      if new_refresh_token do
        debug("Server rotated refresh token")

        assert new_refresh_token != refresh_token,
               "New refresh token should be different if rotated"
      else
        debug("Server kept same refresh token")
      end

      # Verify new access token works
      verify_userinfo_endpoint(main_instance, new_access_token)

      # Optional: Verify old access token is revoked (depending on server behavior)
      # Some servers revoke old tokens, others keep them valid until expiry
      # verify_token_revoked_or_valid(main_instance, access_token)
    end)
  end

  test "can revoke OAuth tokens",
       %{client: client, redirect_uri: redirect_uri, main_instance: main_instance} = context do
    TestInstanceRepo.apply(fn ->
      assert Boruta.Config.repo() == TestInstanceRepo

      # Step 1: Get initial tokens using authorization code flow
      {access_token, refresh_token} =
        get_initial_tokens_with_refresh(client, redirect_uri, main_instance, context)

      # Verify initial access token works
      verify_userinfo_endpoint(main_instance, access_token)

      # Step 2: Revoke the access token
      revoke_uri = "#{main_instance}/oauth/revoke"
      req = create_req_client(main_instance)

      revoke_params = %{
        token: access_token,
        # Optional hint to help server process faster
        token_type_hint: "access_token",
        client_id: client.id,
        client_secret: client.secret
      }

      {:ok, revoke_response} =
        Req.post(req,
          url: revoke_uri,
          form: revoke_params
        )

      # RFC 7009: Revocation endpoint should return 200 even for invalid tokens
      assert revoke_response.status == 200, "Revocation should return 200 OK"

      # Step 3: Verify access token is now invalid
      verify_token_revoked(main_instance, access_token)

      # Step 4: Test revoking refresh token
      if refresh_token do
        refresh_revoke_params = %{
          token: refresh_token,
          token_type_hint: "refresh_token",
          client_id: client.id,
          client_secret: client.secret
        }

        {:ok, refresh_revoke_response} =
          Req.post(req,
            url: revoke_uri,
            form: refresh_revoke_params
          )

        assert refresh_revoke_response.status == 200,
               "Refresh token revocation should return 200 OK"

        # Verify refresh token is now invalid (try to use it)
        verify_refresh_token_revoked(main_instance, refresh_token, client)
      end
    end)
  end

  test "can revoke public client tokens",
       %{redirect_uri: redirect_uri, main_instance: main_instance} = context do
    TestInstanceRepo.apply(fn ->
      assert Boruta.Config.repo() == TestInstanceRepo

      # Create a public client (no client_secret required)
      public_client_id = String.downcase("0198A525-5899-43EA-710F-85B2998FB92A")

      assert %Boruta.Ecto.Client{id: ^public_client_id} =
               public_client =
               ClientApps.init_test_client_app(public_client_id, %{
                 redirect_uris: [redirect_uri],
                 supported_scopes: ["identity", "data:public"],
                 # Public client
                 confidential: false
               })
               |> debug("public client created")
               |> from_ok()

      # Get tokens for public client
      {access_token, _refresh_token} =
        get_initial_tokens_with_refresh(public_client, redirect_uri, main_instance, context)

      # Verify token works
      verify_userinfo_endpoint(main_instance, access_token)

      # Revoke without client_secret (public client)
      revoke_uri = "#{main_instance}/oauth/revoke"
      req = create_req_client(main_instance)

      revoke_params = %{
        token: access_token,
        token_type_hint: "access_token",
        client_id: public_client.id
        # No client_secret for public clients
      }

      {:ok, revoke_response} =
        Req.post(req,
          url: revoke_uri,
          form: revoke_params
        )

      case revoke_response.status do
        200 ->
          # Server supports public client revocation
          debug("Server supports public client token revocation")
          verify_token_revoked(main_instance, access_token)

        401 ->
          # Server requires client authentication for revocation
          assert %{"error" => "invalid_client"} = revoke_response.body
          debug("Server requires client authentication for token revocation (common behavior)")

        # This is actually compliant behavior - many OAuth servers require
        # client authentication for revocation even for public clients

        _ ->
          flunk("Unexpected revocation response: #{revoke_response.status}")
      end
    end)
  end

  # Helper function to verify token is revoked
  defp verify_token_revoked(main_instance, access_token) do
    {:ok, userinfo_response} =
      Req.get(
        "#{main_instance}/oauth/userinfo",
        headers: [{"authorization", "Bearer #{access_token}"}]
      )

    # Should return 401 Unauthorized for revoked token
    assert userinfo_response.status == 401, "Revoked access token should return 401 Unauthorized"

    # Some servers might return specific error details
    case userinfo_response.body do
      %{"error" => "invalid_token"} ->
        debug("Server returned proper invalid_token error")

      %{"error" => error} ->
        debug("Server returned error: #{error}")

      _ ->
        debug("Server returned 401 without error details (still valid)")
    end
  end

  # Helper function to verify refresh token is revoked
  defp verify_refresh_token_revoked(main_instance, refresh_token, client) do
    access_token_uri = "#{main_instance}/oauth/token"
    req = create_req_client(main_instance)

    # Try to use the revoked refresh token
    refresh_params = %{
      grant_type: "refresh_token",
      refresh_token: refresh_token,
      client_id: client.id,
      client_secret: client.secret
    }

    {:ok, refresh_response} =
      Req.post(req,
        url: access_token_uri,
        form: refresh_params
      )

    # Should return 400 Bad Request for revoked/invalid refresh token
    assert refresh_response.status == 400, "Revoked refresh token should return 400 Bad Request"

    # Should return proper OAuth error
    assert %{"error" => "invalid_grant"} = refresh_response.body
    debug("Refresh token properly revoked - returned invalid_grant error")
  end

  # Helper function to get initial tokens 
  defp get_initial_tokens_with_refresh(client, redirect_uri, main_instance, context) do
    # Configure OAuth provider to return refresh tokens
    authorize_uri = "#{main_instance}/oauth/authorize"
    access_token_uri = "#{main_instance}/oauth/token"

    provider_config = [
      test_oauth_provider: [
        display_name: client.name,
        client_id: client.id,
        client_secret: client.secret,
        authorize_uri: authorize_uri,
        access_token_uri: access_token_uri,
        # offline_access often needed for refresh tokens
        scope: "identity data:public offline_access"
      ]
    ]

    Config.put(:oauth2_providers, provider_config, :bonfire_open_id)

    # Get authorization code
    auth_url = get_auth_url(client.name)
    req = create_req_client(main_instance)
    login_response = perform_login_flow(req, auth_url, context)

    query_params = extract_query_params(login_response)
    auth_code = query_params["code"]

    assert auth_code,
           debug(query_params, "auth_code missing in query_params") &&
             "Should receive authorization code"

    # Exchange code for tokens
    token_params = %{
      grant_type: "authorization_code",
      client_id: client.id,
      client_secret: client.secret,
      code: auth_code,
      redirect_uri: redirect_uri
    }

    {:ok, token_response} =
      Req.post(req,
        url: access_token_uri,
        form: token_params
      )

    # Extract both access and refresh tokens
    assert %{
             "access_token" => access_token,
             "refresh_token" => refresh_token
           } = token_response.body

    assert access_token, "Should receive access token"

    assert refresh_token,
           debug(token_response, "refresh_token missing in body") &&
             "Should receive refresh token for offline access"

    {access_token, refresh_token}
  end

  # token exchange logic for reuse
  defp exchange_code_for_tokens(req, access_token_uri, client, auth_code, redirect_uri) do
    token_params = %{
      grant_type: "authorization_code",
      client_id: client.id,
      client_secret: client.secret,
      code: auth_code,
      redirect_uri: redirect_uri
    }

    {:ok, token_response} =
      Req.post(req,
        url: access_token_uri,
        form: token_params
      )

    token_response.body
  end

  # common OAuth provider setup
  defp setup_oauth_provider(client, main_instance, opts \\ []) do
    authorize_uri = "#{main_instance}/oauth/authorize"
    access_token_uri = "#{main_instance}/oauth/token"
    scope = Keyword.get(opts, :scope, "identity data:public")
    response_type = Keyword.get(opts, :response_type, "code")

    provider_config = [
      test_oauth_provider: [
        display_name: client.name,
        client_id: client.id,
        client_secret: client.secret,
        authorize_uri: authorize_uri,
        access_token_uri: access_token_uri,
        response_type: response_type,
        scope: scope
      ]
    ]

    Config.put(:oauth2_providers, provider_config, :bonfire_open_id)
    {authorize_uri, access_token_uri}
  end

  # Add this helper function
  defp verify_machine_to_machine_endpoint(main_instance, access_token) do
    # For client credentials, we might want to test a different endpoint
    # since there's no user context - it's machine-to-machine

    # Try the userinfo endpoint but expect different behavior for machine auth
    {:ok, response} =
      Req.get(
        "#{main_instance}/oauth/userinfo",
        headers: [{"authorization", "Bearer #{access_token}"}]
      )

    # For client credentials, the response might be different
    # It could return client info instead of user info, or an error
    case response.status do
      200 ->
        # If successful, verify the response structure
        assert is_map(response.body)

      # The response might contain client info rather than user info

      401 ->
        # Some systems don't allow userinfo endpoint for client credentials
        # This is also valid behavior
        debug("Userinfo endpoint rejected client credentials token (expected behavior)")

      _ ->
        flunk("Unexpected response status: #{response.status}")
    end
  end

  # Helper functions (adapted from OpenID test)
  defp get_auth_url(client_name) do
    Bonfire.OpenID.Client.providers_authorization_urls()
    |> ed(client_name, nil)
    |> debug("auth_url")
  end

  defp create_req_client(main_instance) do
    ReqCookieJar.new()

    Req.new(
      base_url: main_instance,
      retry: false,
      cache: false
    )
    |> ReqCookieJar.attach()
  end

  defp perform_login_flow(req, auth_url, context) do
    # Fetch authorization page (might redirect)
    {:ok, response} = Req.get(req, url: auth_url, redirect: false)

    # Handle redirect to actual authorization URL
    actual_auth_url =
      case response.status do
        302 -> response.headers["location"] |> List.first()
        303 -> response.headers["location"] |> List.first()
        _ -> auth_url
      end

    {:ok, response} = Req.get(req, url: actual_auth_url, redirect: true)

    # Extract CSRF token and form data
    doc = Floki.parse_document!(response.body)

    csrf_token =
      doc
      |> Floki.find("input[name=_csrf_token]")
      |> Floki.attribute("value")
      |> List.first() || (debug(doc) && raise "CSRF token not found")

    go_url =
      doc
      |> Floki.find("input[name=go]")
      |> Floki.attribute("value")
      |> List.first() || raise "redirect URI not found"

    # Submit login form
    form_data = %{
      "login_fields[email_or_username]" => context.local.account.email.email_address,
      # Use test_password from DanceCase
      "login_fields[password]" => context.test_password,
      "go" => go_url,
      "_csrf_token" => csrf_token
    }

    {:ok, login_response} =
      Req.post(req,
        url: "/login",
        form: form_data,
        redirect: false
      )

    assert login_response.status == 303, "Should redirect after successful login"
    login_response
  end

  defp extract_fragment_params(login_response) do
    login_response.headers["location"]
    |> List.first()
    |> URI.parse()
    |> Map.get(:fragment)
    |> URI.decode_query()
  end

  defp extract_query_params(login_response) do
    login_response.headers["location"]
    |> List.first()
    |> URI.parse()
    |> Map.get(:query)
    |> URI.decode_query()
  end

  defp verify_userinfo_endpoint(main_instance, access_token) do
    {:ok, userinfo_response} =
      Req.get(
        "#{main_instance}/oauth/userinfo",
        headers: [{"authorization", "Bearer #{access_token}"}]
      )

    # OAuth userinfo response 
    assert %{"sub" => _} = userinfo_response.body
  end
end
