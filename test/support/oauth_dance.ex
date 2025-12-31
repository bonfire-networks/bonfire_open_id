defmodule Bonfire.OpenID.OAuthDance do
  # use Patch, only: []
  import ExUnit.Assertions
  import Bonfire.OpenID.DanceCase

  use Arrows
  import Untangle
  import Bonfire.Common.Config, only: [repo: 0]
  use Bonfire.Common.E
  use Bonfire.Common.Config
  alias Bonfire.Common.Utils
  alias Bonfire.Common.TestInstanceRepo
  alias Bonfire.OpenID.Provider.ClientApps

  def setup do
    client_id = Faker.UUID.v4()
    main_instance = "http://localhost:4000"
    secondary_instance = "http://localhost:4002"
    redirect_uri = "#{main_instance}/oauth/client/" <> client_id

    # Create client with OAuth scopes (different from OpenID Connect scopes)
    client =
      TestInstanceRepo.apply(fn ->
        %Boruta.Ecto.Client{id: ^client_id} =
          ClientApps.init_test_client_app(client_id, %{
            name:
              "Test OAuth Dance Client, configured on provider (secondary instance), redirecting to client (main instance)",
            redirect_uris: [redirect_uri],
            # OAuth scopes, no "openid"
            supported_scopes: ["identity", "data:public", "read", "write"]
          })
          |> debug("client created?")
          |> from_ok()
      end)

    {authorize_uri, access_token_uri} = setup_oauth_provider(client, secondary_instance)

    %{
      client: client,
      client_id: client_id,
      redirect_uri: redirect_uri,
      main_instance: main_instance,
      secondary_instance: secondary_instance,
      authorize_uri: authorize_uri,
      access_token_uri: access_token_uri
    }
  end

  def teardown(client) do
    Config.delete(:oauth2_providers, :bonfire_open_id)
    # Delete client from provider DB
    TestInstanceRepo.apply(fn ->
      repo().delete(client)
    end)
  end

  # Helper function to verify token is revoked
  def verify_token_revoked(secondary_instance, access_token) do
    {:ok, userinfo_response} =
      apply_with_repo_sync(fn ->
        Req.get(
          "#{secondary_instance}/oauth/userinfo",
          headers: [{"authorization", "Bearer #{access_token}"}]
        )
      end)

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
  def verify_refresh_token_revoked(secondary_instance, refresh_token, client) do
    access_token_uri = "#{secondary_instance}/oauth/token"
    req = create_req_client(secondary_instance)

    # Try to use the revoked refresh token
    refresh_params = %{
      grant_type: "refresh_token",
      refresh_token: refresh_token,
      client_id: client.id,
      client_secret: client.secret
    }

    {:ok, refresh_response} =
      apply_with_repo_sync(fn ->
        Req.post(req,
          url: access_token_uri,
          form: refresh_params
        )
      end)

    # Should return 400 Bad Request for revoked/invalid refresh token
    assert refresh_response.status == 400, "Revoked refresh token should return 400 Bad Request"

    # Should return proper OAuth error
    assert %{"error" => "invalid_grant"} = refresh_response.body
    debug("Refresh token properly revoked - returned invalid_grant error")
  end

  # Helper function to get initial tokens 
  def get_initial_tokens_with_refresh(
        client,
        redirect_uri,
        main_instance,
        secondary_instance,
        context
      ) do
    # Log repo in use
    debug(Boruta.Config.repo(), "Repo in use at start of get_initial_tokens_with_refresh")
    debug(client, "OAuth client struct")
    debug(redirect_uri, "OAuth redirect_uri")
    debug(secondary_instance, "OAuth secondary_instance (provider)")

    # Configure OAuth provider to return refresh tokens
    {authorize_uri, access_token_uri} =
      setup_oauth_provider(client, secondary_instance,
        response_type: "code",
        scope: "identity data:public offline_access"
      )

    # Get authorization code
    auth_url = get_auth_url(client.name)
    req = create_req_client(main_instance)
    login_response = perform_login_flow(req, auth_url, context)

    query_params = extract_query_params(login_response)
    debug(query_params, "query_params after login_response")

    query_params =
      if query_params == %{} do
        debug(login_response.headers["location"], "query_params empty, trying with fragment")
        # FIXME? not sure if this workaround is spec-compliant
        extract_fragment_params(login_response)
      end || query_params

    auth_code = query_params["code"]
    debug(auth_code, "Authorization code before token exchange")

    assert auth_code, "Should receive authorization code"

    # Exchange code for tokens
    token_params = %{
      grant_type: "authorization_code",
      client_id: client.id,
      client_secret: client.secret,
      code: auth_code,
      redirect_uri: redirect_uri
    }

    debug(token_params, "Token endpoint request params")

    req = create_req_client(secondary_instance)

    {:ok, token_response} =
      apply_with_repo_sync(fn ->
        Req.post(req,
          url: access_token_uri,
          form: token_params
        )
      end)

    debug(token_response, "Token endpoint response")

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
  def exchange_code_for_tokens(req, access_token_uri, client, auth_code, redirect_uri) do
    token_params = %{
      grant_type: "authorization_code",
      client_id: client.id,
      client_secret: client.secret,
      code: auth_code,
      redirect_uri: redirect_uri
    }

    {:ok, token_response} =
      apply_with_repo_sync(fn ->
        Req.post(req,
          url: access_token_uri,
          form: token_params
        )
      end)

    token_response.body
  end

  # common OAuth provider setup
  def setup_oauth_provider(client, secondary_instance, opts \\ []) do
    authorize_uri = "#{secondary_instance}/oauth/authorize"
    access_token_uri = "#{secondary_instance}/oauth/token"
    scope = Keyword.get(opts, :scope, "identity data:public")
    response_type = Keyword.get(opts, :response_type, "code")

    provider_config = %{
      client.id => [
        display_name: client.name,
        client_id: client.id,
        client_secret: client.secret,
        authorize_uri: authorize_uri,
        access_token_uri: access_token_uri,
        response_type: response_type,
        scope: scope
      ]
    }

    Config.put(:oauth2_providers, provider_config, :bonfire_open_id)

    {authorize_uri, access_token_uri}
  end

  # Add this helper function
  def verify_machine_to_machine_endpoint(secondary_instance, access_token) do
    # For client credentials, we might want to test a different endpoint
    # since there's no user context - it's machine-to-machine

    # Try the userinfo endpoint but expect different behavior for machine auth
    {:ok, response} =
      apply_with_repo_sync(fn ->
        Req.get(
          "#{secondary_instance}/oauth/userinfo",
          headers: [{"authorization", "Bearer #{access_token}"}]
        )
      end)

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
        info("Userinfo endpoint rejected client credentials token (expected behavior)")

      _ ->
        err("Unexpected response status: #{response.status}")
    end
  end

  # Helper functions (adapted from OpenID test)
  def get_auth_url(client_name) do
    Bonfire.OpenID.Client.providers_authorization_urls()
    |> ed(client_name, nil)
    |> debug("auth_url")
  end

  def create_req_client(main_instance) do
    ReqCookieJar.new()

    Req.new(
      base_url: main_instance,
      retry: false,
      cache: false
    )
    |> ReqCookieJar.attach()
  end

  def perform_login_flow(req, auth_url, context) do
    # Fetch authorization page (might redirect)
    {:ok, response} =
      apply_with_repo_sync(fn -> Req.get(req, url: auth_url, redirect: false) end)
      |> flood("Initial GET auth_url response from #{auth_url}")

    # Handle redirect to actual authorization URL
    actual_auth_url =
      case response.status do
        302 -> response.headers["location"] |> List.first()
        303 -> response.headers["location"] |> List.first()
        _ -> raise "Expected redirect to authorization URL, got status #{response.status}"
      end
      |> flood("Actual Auth URL (should be on provider)")

    # Parse actual_auth_url to get the correct base URL for login POST
    uri = URI.parse(actual_auth_url)

    base_url =
      if uri.port && uri.port not in [80, 443] do
        "#{uri.scheme}://#{uri.host}:#{uri.port}"
      else
        "#{uri.scheme}://#{uri.host}"
      end

    req = create_req_client(base_url)

    {:ok, response} =
      apply_with_repo_sync(fn -> Req.get(req, url: actual_auth_url, redirect: true) end)

    # Extract CSRF token and form data
    doc = Floki.parse_document!(response.body)

    [form] =
      doc
      |> Floki.find("form#login-form")

    csrf_token =
      form
      |> Floki.find("input[name=_csrf_token]")
      |> Floki.attribute("value")
      |> List.first() || (debug(doc) && raise "CSRF token not found")

    go_url =
      form
      |> Floki.find("input[name=go]")
      |> Floki.attribute("value")
      |> List.first() || raise "redirect URI not found"

    # Submit login form
    form_data = %{
      "login_fields[email_or_username]" => context.remote.account.email.email_address,
      # Use test_password from DanceCase
      "login_fields[password]" => context.test_password,
      "go" => go_url,
      "_csrf_token" => csrf_token
    }

    {:ok, login_response} =
      apply_with_repo_sync(fn ->
        Req.post(req,
          url: "/login",
          form: form_data,
          redirect: false
        )
      end)

    assert login_response.status == 303, "Should redirect after successful login"
    login_response
  end

  def extract_fragment_params(%{headers: headers} = _login_response),
    do: extract_fragment_params(headers["location"] |> List.first())

  def extract_fragment_params(uri) when is_binary(uri) do
    do_extract_params(uri, :fragment)
  end

  def extract_query_params(%{headers: headers} = _login_response),
    do: extract_query_params(headers["location"] |> List.first())

  def extract_query_params(uri) when is_binary(uri) do
    do_extract_params(uri, :query)
  end

  defp do_extract_params(uri, field \\ :query) do
    uri
    |> URI.parse()
    |> Map.get(field)
    |> case do
      nil -> ""
      query -> query
    end
    |> URI.decode_query()
  end

  def verify_userinfo_endpoint(secondary_instance, access_token) do
    {:ok, userinfo_response} =
      apply_with_repo_sync(fn ->
        Req.get(
          "#{secondary_instance}/oauth/userinfo",
          headers: [{"authorization", "Bearer #{access_token}"}]
        )
      end)

    claims = map_or_decode_jwt(userinfo_response.body)

    assert %{"sub" => _} = claims
  end

  def map_or_decode_jwt(contents) do
    case contents do
      %{} = map ->
        map
        |> debug("userinfo response is already a map")

      jwt when is_binary(jwt) ->
        # Decode JWT using JOSE
        case JOSE.JWT.peek_payload(jwt) do
          %JOSE.JWT{
            fields: claims
          } ->
            claims
            |> debug("userinfo JWT decoded to claims")

          other ->
            debug(other, "Failed to peek JWT payload")
            err("Could not decode JWT userinfo response")
        end
    end
  end
end
