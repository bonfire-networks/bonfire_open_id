defmodule Bonfire.OpenID.OIDCDance do
  # use Patch, only: []
  import ExUnit.Assertions

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
    redirect_uri = "http://localhost:4002/openid/client/" <> client_id
    main_instance = "http://localhost:4000"
    discovery_document_uri = "#{main_instance}/.well-known/openid-configuration"

    # Create client with OpenID Connect scopes
    assert %Boruta.Ecto.Client{id: ^client_id} =
             client =
             ClientApps.init_test_client_app(client_id, %{
               redirect_uris: [redirect_uri],
               supported_scopes: ["openid", "profile", "email", "identity", "data:public"]
             })
             |> debug("client created")
             |> from_ok()

    %{
      client: client,
      client_id: client_id,
      redirect_uri: redirect_uri,
      main_instance: main_instance,
      discovery_document_uri: discovery_document_uri
    }
  end

  def test_oidc_flow(
        %{
          client: client,
          redirect_uri: redirect_uri,
          main_instance: main_instance,
          discovery_document_uri: discovery_document_uri
        } = context,
        opts
      ) do
    TestInstanceRepo.apply(fn ->
      assert Boruta.Config.repo() == TestInstanceRepo

      # Setup provider configuration
      {provider_key, provider_config} =
        build_provider_config(client, main_instance, discovery_document_uri, opts)

      Config.put(:openid_connect_providers, [{provider_key, provider_config}], :bonfire_open_id)

      # Perform authentication flow
      client_name = opts[:client_name] || client.name
      auth_url = get_auth_url(client_name)
      req = create_req_client(main_instance)
      login_response = perform_login_flow(req, auth_url, context)

      # Handle different flow types
      case opts.flow_type do
        :implicit ->
          test_implicit_flow_completion(login_response, main_instance, opts)

        :authorization_code ->
          test_authorization_code_flow_completion(
            login_response,
            client,
            redirect_uri,
            discovery_document_uri,
            req,
            main_instance,
            opts
          )

        # Add this case
        :authorization_code_pkce ->
          test_authorization_code_flow_completion(
            login_response,
            client,
            redirect_uri,
            discovery_document_uri,
            req,
            main_instance,
            opts
          )
      end

      verify_discovery_document(discovery_document_uri, main_instance)
    end)
  end

  def build_provider_config(client, main_instance, discovery_document_uri, opts) do
    client_name = opts[:client_name] || client.name
    provider_key = client.id

    base_config = [
      display_name: client_name,
      client_id: client.id,
      client_secret: client.secret,
      discovery_document_uri: discovery_document_uri,
      response_type: opts.response_type,
      scope: opts.scope
    ]

    # Add PKCE parameters if this is a PKCE flow
    provider_config =
      case opts.flow_type do
        :authorization_code_pkce ->
          # Generate PKCE parameters
          {code_verifier, code_challenge} = generate_pkce_params()

          # Store code verifier for later use in token exchange
          Process.put(:pkce_code_verifier, code_verifier)

          base_config ++
            [
              pkce: true,
              code_challenge: code_challenge,
              code_challenge_method: "S256"
            ]

        _ ->
          base_config
      end

    {provider_key, provider_config}
  end

  def generate_pkce_params do
    # Generate code verifier (43-128 character string)
    code_verifier =
      :crypto.strong_rand_bytes(32)
      |> Base.url_encode64(padding: false)

    # Generate code challenge (SHA256 hash of verifier, base64url encoded)
    code_challenge =
      :crypto.hash(:sha256, code_verifier)
      |> Base.url_encode64(padding: false)

    debug(code_verifier, "PKCE code_verifier")
    debug(code_challenge, "PKCE code_challenge")

    {code_verifier, code_challenge}
  end

  # DRY: Handle implicit flow completion
  def test_implicit_flow_completion(login_response, main_instance, _opts) do
    fragment_params = extract_fragment_params(login_response)

    access_token = fragment_params["access_token"]
    id_token = fragment_params["id_token"]

    debug(fragment_params, "fragment_params")
    assert access_token, "Should receive access token in redirect fragment"
    assert id_token, "Should receive ID token in redirect fragment"

    verify_userinfo_endpoint(main_instance, access_token)
  end

  def test_authorization_code_flow_completion(
        login_response,
        client,
        redirect_uri,
        discovery_document_uri,
        req,
        main_instance,
        opts
      ) do
    # Extract and exchange authorization code
    query_params = extract_query_params(login_response)
    auth_code = query_params["code"]

    assert auth_code,
           debug(query_params, "Should receive authorization code") &&
             "Should receive authorization code"

    # Get tokens (with or without PKCE)
    {:ok, token_response} =
      case opts.flow_type do
        :authorization_code_pkce ->
          # Get code verifier from context (stored during auth URL generation)
          code_verifier = Process.get(:pkce_code_verifier)

          exchange_code_for_tokens_pkce(
            discovery_document_uri,
            req,
            client,
            auth_code,
            redirect_uri,
            code_verifier
          )

        _ ->
          exchange_code_for_tokens(discovery_document_uri, req, client, auth_code, redirect_uri)
      end

    assert %{
             "access_token" => access_token,
             "id_token" => id_token
           } = token_response.body

    assert access_token, "Should receive access token"
    assert id_token, "Should receive ID token"

    # Verify claims if specified
    if verify_claims = opts[:verify_claims] do
      verify_id_token_claims(id_token, verify_claims)
      verify_userinfo_claims(main_instance, access_token, verify_claims)
    else
      verify_userinfo_endpoint(main_instance, access_token)
    end

    # Test cross-instance scenarios if requested
    if opts[:test_cross_instance] do
      test_cross_instance_user_info(id_token, access_token, main_instance)
    end
  end

  def exchange_code_for_tokens_pkce(
        discovery_document_uri,
        req,
        client,
        auth_code,
        redirect_uri,
        code_verifier,
        opts \\ %{}
      ) do
    {:ok, discovery_response} = Req.get(discovery_document_uri)
    token_endpoint = discovery_response.body["token_endpoint"]

    base_params = %{
      grant_type: "authorization_code",
      client_id: client.id,
      code: auth_code,
      redirect_uri: redirect_uri,
      # PKCE code verifier
      code_verifier: code_verifier
    }

    # Only add client_secret for confidential clients
    token_params =
      if opts[:public_client] || not client.confidential do
        base_params
      else
        Map.put(base_params, :client_secret, client.secret)
      end

    Req.post(req, url: token_endpoint, form: token_params)
  end

  # Simple cross-instance user info test
  def test_cross_instance_user_info(id_token, access_token, main_instance) do
    # Extract user identity from ID token
    user_identity = extract_user_identity(id_token)
    debug(user_identity, "user identity from ID token")

    # Fetch user info from remote instance
    {:ok, userinfo_response} =
      Req.get(
        "#{main_instance}/openid/userinfo",
        headers: [
          {"authorization", "Bearer #{access_token}"},
          {"user-agent", "Bonfire-Federation/1.0"}
        ]
      )

    userinfo = map_or_decode_jwt(userinfo_response.body)
    debug(userinfo, "cross-instance userinfo")

    # Verify consistency
    assert user_identity["sub"] == userinfo["sub"],
           "Subject should match between ID token and userinfo"

    assert user_identity["iss"], "Should have issuer (home instance) information"

    # Create canonical user ID for federation
    home_instance = user_identity["iss"]
    canonical_id = "#{user_identity["sub"]}@#{URI.parse(home_instance).host}"
    debug(canonical_id, "canonical federated user ID")

    debug("Cross-instance user info test successful!")
  end

  # Simple helper to extract key identity info
  def extract_user_identity(id_token) do
    [_header, payload, _signature] = String.split(id_token, ".")

    payload =
      case rem(String.length(payload), 4) do
        0 -> payload
        n -> payload <> String.duplicate("=", 4 - n)
      end

    payload
    |> Base.decode64!()
    |> Jason.decode!()
    |> Map.take(["sub", "iss", "aud", "preferred_username", "email"])
  end

  # DRY: Code exchange helper
  def exchange_code_for_tokens(discovery_document_uri, req, client, auth_code, redirect_uri) do
    {:ok, discovery_response} = Req.get(discovery_document_uri)
    token_endpoint = discovery_response.body["token_endpoint"]

    token_params = %{
      grant_type: "authorization_code",
      client_id: client.id,
      client_secret: client.secret,
      code: auth_code,
      redirect_uri: redirect_uri
    }

    Req.post(req, url: token_endpoint, form: token_params)
  end

  # DRY: Dynamic registration flow
  def test_dynamic_registration_flow(registration_endpoint, main_instance, context) do
    redirect_uri = "http://localhost:4002/openid/client/dynamic_test_oidc_provider"

    # Register client with the matching redirect URI
    {client_id, client_secret, registration_access_token, registration_client_uri} =
      perform_dynamic_registration(registration_endpoint, main_instance, redirect_uri)

    # Test the registered client works
    test_dynamic_client_auth_flow(client_id, client_secret, redirect_uri, main_instance, context)

    # Test client management endpoints
    test_client_configuration_retrieval(registration_client_uri, registration_access_token)

    test_client_configuration_update(registration_client_uri, registration_access_token, %{
      "client_name" => "Updated Dynamic Client Name"
    })
  end

  # DRY: Perform dynamic registration - now accepts redirect_uri parameter
  def perform_dynamic_registration(registration_endpoint, main_instance, redirect_uri) do
    req = create_req_client(main_instance)

    registration_request = %{
      # Use the passed redirect_uri
      "redirect_uris" => [redirect_uri],
      "client_name" => "Dynamically Registered Test Client",
      "grant_types" => ["authorization_code", "implicit"],
      "response_types" => ["code", "id_token", "token", "id_token token"],
      "scope" => "openid profile email identity data:public",
      "application_type" => "web",
      "subject_type" => "public",
      "id_token_signed_response_alg" => "RS256",
      "userinfo_signed_response_alg" => "none"
    }

    {:ok, registration_response} =
      Req.post(req,
        url: registration_endpoint,
        json: registration_request,
        headers: [{"content-type", "application/json"}]
      )

    assert registration_response.status in [200, 201], "Dynamic registration should succeed"

    %{
      "client_id" => client_id,
      "client_secret" => client_secret,
      "registration_access_token" => registration_access_token,
      "registration_client_uri" => registration_client_uri
    } = registration_response.body

    debug(client_id, "dynamically registered client_id")
    debug(redirect_uri, "registered redirect_uri")
    assert client_id, "Should receive client_id"
    assert client_secret, "Should receive client_secret"
    assert registration_access_token, "Should receive registration access token"

    {client_id, client_secret, registration_access_token, registration_client_uri}
  end

  # Helper function to test the dynamically registered client
  def test_dynamic_client_auth_flow(
        client_id,
        client_secret,
        redirect_uri,
        main_instance,
        context
      ) do
    # Configure provider with dynamically registered client
    discovery_document_uri = "#{main_instance}/.well-known/openid-configuration"

    # Use a consistent provider key that won't generate a new unique number
    provider_config = [
      dynamic_test_oidc_provider: [
        display_name: "Dynamically Registered Test Client",
        client_id: client_id,
        client_secret: client_secret,
        discovery_document_uri: discovery_document_uri,
        response_type: "authorization_code",
        scope: "openid profile email identity data:public"
      ]
    ]

    Config.put(:openid_connect_providers, provider_config, :bonfire_open_id)

    # Test authorization code flow with dynamic client
    auth_url =
      Bonfire.OpenID.Client.providers_authorization_urls()
      |> ed("Dynamically Registered Test Client", nil)
      |> debug("dynamic client auth_url")

    req = create_req_client(main_instance)
    login_response = perform_login_flow(req, auth_url, context)

    # Extract and exchange authorization code
    query_params = extract_query_params(login_response)
    auth_code = query_params["code"]

    assert auth_code,
           debug(query_params, "Dynamic client should receive authorization code") &&
             "Dynamic client should receive authorization code"

    # Exchange code for tokens using the same redirect_uri
    {:ok, discovery_response} = Req.get(discovery_document_uri)
    token_endpoint = discovery_response.body["token_endpoint"]

    token_params = %{
      grant_type: "authorization_code",
      client_id: client_id,
      client_secret: client_secret,
      code: auth_code,
      # Use the same redirect_uri that was registered
      redirect_uri: redirect_uri
    }

    {:ok, token_response} =
      Req.post(req,
        url: token_endpoint,
        form: token_params
      )

    # Verify tokens received
    assert %{
             "access_token" => access_token,
             "id_token" => id_token
           } = token_response.body

    assert access_token, "Dynamic client should receive access token"
    assert id_token, "Dynamic client should receive ID token"

    # Verify tokens work
    verify_userinfo_endpoint(main_instance, access_token)

    debug("Dynamic client authentication flow successful!")
  end

  # DRY: Get registration endpoint
  def get_registration_endpoint(discovery_document_uri) do
    {:ok, discovery_response} = Req.get(discovery_document_uri)

    case discovery_response.body["registration_endpoint"] do
      nil -> :not_supported
      endpoint -> {:ok, endpoint}
    end
  end

  # DRY: Registration error testing
  def test_registration_error_handling(registration_endpoint, main_instance) do
    req = create_req_client(main_instance)

    invalid_registration_request = %{
      # Invalid URI format
      "redirect_uris" => ["invalid-uri"],
      "client_name" => "Invalid Test Client",
      "grant_types" => ["authorization_code"],
      "response_types" => ["code"],
      "scope" => "openid"
    }

    {:ok, error_response} =
      Req.post(req,
        url: registration_endpoint,
        json: invalid_registration_request,
        headers: [{"content-type", "application/json"}]
      )

    assert error_response.status == 400, "Invalid registration should return 400"
    assert %{"error" => error_type} = error_response.body
    assert error_type in ["invalid_redirect_uri", "invalid_client_metadata"]

    debug("Proper error handling for invalid registration: #{error_type}")
  end

  # Helper function to verify ID token claims
  def verify_id_token_claims(id_token, expected_scopes) do
    # Decode the JWT (you might want to verify signature in production)
    [_header, payload, _signature] = String.split(id_token, ".")

    # Add padding if needed for base64 decoding
    payload =
      case rem(String.length(payload), 4) do
        0 -> payload
        n -> payload <> String.duplicate("=", 4 - n)
      end

    claims =
      payload
      |> Base.decode64!()
      |> Jason.decode!()
      |> debug("ID token claims")

    # Verify standard OpenID Connect claims
    assert claims["iss"], "ID token should have issuer claim"
    assert claims["sub"], "ID token should have subject claim"
    assert claims["aud"], "ID token should have audience claim"
    assert claims["exp"], "ID token should have expiration claim"
    assert claims["iat"], "ID token should have issued at claim"

    # TODO: if we add more claims

    # profile_claims = ["name", "given_name", "family_name", "nickname", "picture", "website"]

    # # Verify scope-specific claims
    # if "profile" in expected_scopes do
    #   # Should have profile-related claims
    #   profile_present = Enum.any?(profile_claims, &Map.has_key?(claims, &1))
    #   assert profile_present, debug(profile_claims, "profile_claims") && "ID token should contain profile claims when profile scope requested"
    # end

    # if "email" in expected_scopes do
    #   # Should have email-related claims
    #   assert claims["email"] || claims["email_verified"], "ID token should contain email claims when email scope requested"
    # end

    # # Verify claims are NOT present for ungranted scopes
    # if "profile" not in expected_scopes do
    #   profile_absent = Enum.all?(profile_claims, &(not Map.has_key?(claims, &1)))
    #   # Note: Some servers might still include basic profile info, so this might be optional
    #   debug("Profile claims absent: #{profile_absent}")
    # end

    claims
  end

  # Helper function to verify userinfo endpoint claims
  def verify_userinfo_claims(main_instance, access_token, expected_scopes) do
    {:ok, userinfo_response} =
      Req.get(
        "#{main_instance}/openid/userinfo",
        headers: [{"authorization", "Bearer #{access_token}"}]
      )

    userinfo =
      map_or_decode_jwt(userinfo_response.body)
      |> debug("Userinfo claims")

    # Should always have sub claim
    assert userinfo["sub"], "Userinfo should always have sub claim"

    # Verify scope-specific claims in userinfo
    if "profile" in expected_scopes do
      profile_claims = ["name", "given_name", "family_name", "nickname", "picture", "website"]
      profile_present = Enum.any?(profile_claims, &Map.has_key?(userinfo, &1))
      # Note: Profile claims in userinfo might be optional depending on user data
      debug("Profile claims present in userinfo: #{profile_present}")
    end

    if "email" in expected_scopes do
      email_present = userinfo["email"] || userinfo["email_verified"]
      # Note: Email claims might be optional depending on user data
      debug("Email claims present in userinfo: #{!!email_present}")
    end

    userinfo
  end

  # Test retrieving client configuration
  def test_client_configuration_retrieval(registration_client_uri, registration_access_token) do
    {:ok, config_response} =
      Req.get(registration_client_uri,
        headers: [{"authorization", "Bearer #{registration_access_token}"}]
      )

    assert config_response.status == 200,
           debug(config_response, "Should retrieve client configuration") &&
             "Should retrieve client configuration"

    config_data = config_response.body

    assert %{
             "client_id" => _,
             "client_name" => _,
             "redirect_uris" => _
           } = config_data

    debug("Client configuration retrieval successful")
    config_data
  end

  # Test updating client configuration  
  def test_client_configuration_update(
        registration_client_uri,
        registration_access_token,
        original_config
      ) do
    # Update client name
    updated_config = Map.put(original_config, "client_name", "Updated Dynamic Client Name")

    {:ok, update_response} =
      Req.put(registration_client_uri,
        json: updated_config,
        headers: [
          {"authorization", "Bearer #{registration_access_token}"},
          {"content-type", "application/json"}
        ]
      )

    assert update_response.status == 200, "Should update client configuration"

    updated_data = update_response.body
    assert updated_data["client_name"] == "Updated Dynamic Client Name"

    debug("Client configuration update successful")
  end

  # Helper functions
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
    # Fetch authorization page
    {:ok, response} = Req.get(req, url: auth_url, redirect: true)

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
    form_data =
      %{
        "login_fields[email_or_username]" => context.local.account.email.email_address,
        "login_fields[password]" => context.test_password,
        "go" => go_url,
        "_csrf_token" => csrf_token
      }
      |> debug("login form data")

    {:ok, login_response} =
      Req.post(req,
        url: "/login",
        form: form_data,
        redirect: false
      )
      |> debug("Performed login form submission")

    assert login_response.status == 303,
           debug(login_response, "login_response") && "Should redirect after successful login"

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

  def verify_userinfo_endpoint(main_instance, access_token) do
    {:ok, userinfo_response} =
      Req.get(
        "#{main_instance}/openid/userinfo",
        headers: [{"authorization", "Bearer #{access_token}"}]
      )

    claims = map_or_decode_jwt(userinfo_response.body)

    assert %{
             "sub" => _
             # "email" => _email,
             # "profile" => _
           } = claims
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

  def verify_discovery_document(discovery_document_uri, main_instance) do
    {:ok, discovery_response} = Req.get(discovery_document_uri)

    assert %{
             "issuer" => ^main_instance,
             "authorization_endpoint" => _,
             "token_endpoint" => _,
             "userinfo_endpoint" => _,
             "jwks_uri" => _,
             "scopes_supported" => scopes
           } = discovery_response.body

    assert "openid" in scopes, "OpenID scope should be supported"

    # Check for optional dynamic registration support
    case discovery_response.body["registration_endpoint"] do
      nil ->
        debug("Server does not support dynamic client registration")

      registration_endpoint ->
        debug("Server supports dynamic client registration at: #{registration_endpoint}")

        assert String.starts_with?(registration_endpoint, main_instance),
               "Registration endpoint should be on same server"
    end

    # Verify JWT signing keys are available
    jwks_uri = discovery_response.body["jwks_uri"]
    {:ok, jwks_response} = Req.get(jwks_uri)
    assert %{"keys" => _} = jwks_response.body

    # Check for other optional endpoints
    optional_endpoints = ["end_session_endpoint", "check_session_iframe", "revocation_endpoint"]

    for endpoint <- optional_endpoints do
      case discovery_response.body[endpoint] do
        nil -> debug("Server does not support #{endpoint}")
        uri -> debug("Server supports #{endpoint} at: #{uri}")
      end
    end
  end

  @doc """
  Fetches JWKS endpoint and validates response format and key structure.

  Verifies:
  - Endpoint returns 200 status
  - Response contains "keys" array
  - Each key has required JWK fields (kid, kty, n, e for RSA)
  - Keys are decodable
  """
  def verify_jwks_endpoint(main_instance) do
    {:ok, jwks_response} = Req.get("#{main_instance}/openid/jwks")

    assert jwks_response.status == 200,
           "JWKS endpoint should return 200"

    assert %{"keys" => keys} = jwks_response.body,
           "JWKS response should contain 'keys' array"

    assert is_list(keys) and length(keys) > 0,
           "Keys should be a non-empty array"

    # Validate each key
    Enum.each(keys, &verify_jwk_key_format/1)

    debug(keys, "JWKS keys verified")
  end

  @doc """
  Validates a single JWK key has required fields per OpenID Connect spec.

  For RSA keys (kty: RSA), requires: kid, kty, n, e
  """
  def verify_jwk_key_format(key) do
    assert is_map(key), "JWK key should be a map"
    assert key["kid"], "JWK key should have 'kid' (Key ID)"
    assert key["kty"], "JWK key should have 'kty' (Key Type)"

    case key["kty"] do
      "RSA" ->
        assert key["n"], "RSA key should have 'n' (modulus)"
        assert key["e"], "RSA key should have 'e' (exponent)"

      "EC" ->
        assert key["crv"], "EC key should have 'crv' (curve)"
        assert key["x"], "EC key should have 'x' coordinate"
        assert key["y"], "EC key should have 'y' coordinate"

      other ->
        debug(other, "Unsupported key type")
    end

    debug(key["kid"], "JWK key format verified")
  end

  @doc """
  Fetches and validates Userinfo endpoint response.

  Verifies:
  - Endpoint returns 200 with Bearer token
  - Response contains 'sub' claim (required by spec)
  - If response is JWT, verifies signature using JWKS keys
  - Returns decoded claims map
  """
  def verify_userinfo_endpoint_with_keys(main_instance, access_token, jwks_keys) do
    {:ok, userinfo_response} =
      Req.get(
        "#{main_instance}/openid/userinfo",
        headers: [{"authorization", "Bearer #{access_token}"}]
      )

    assert userinfo_response.status == 200,
           "Userinfo endpoint should return 200 with valid token"

    userinfo_body = userinfo_response.body

    # Check if response is a JWT string or already-decoded map/JSON
    userinfo =
      cond do
        is_map(userinfo_body) ->
          # Already decoded JSON (Req decoded it for us)
          userinfo_body

        is_binary(userinfo_body) and is_jwt?(userinfo_body) and is_list(jwks_keys) ->
          # JWT string with keys available - verify signature
          verify_userinfo_jwt_signature(userinfo_body, jwks_keys)

        is_binary(userinfo_body) and is_jwt?(userinfo_body) ->
          # JWT string but no keys - just decode without verification
          warn("Userinfo is JWT but no JWKS keys provided for signature verification")
          map_or_decode_jwt(userinfo_body)

        is_binary(userinfo_body) ->
          # Plain JSON string - decode it
          Jason.decode!(userinfo_body)

        true ->
          userinfo_body
      end

    assert is_map(userinfo),
           "Userinfo response should be a map (JSON or decoded JWT)"

    assert userinfo["sub"],
           "Userinfo must contain 'sub' claim per OpenID Connect spec"

    debug(userinfo, "Userinfo endpoint verified")
    userinfo
  end

  @doc """
  Verifies JWT signature of userinfo response using JWKS keys.

  Returns decoded claims if signature is valid, or fails with assertion error.
  """
  def verify_userinfo_jwt_signature(userinfo_jwt, jwks_keys) do
    debug("Userinfo is JWT format, verifying signature with JWKS keys")

    userinfo_claims = verify_jwt_signature(userinfo_jwt, jwks_keys)

    assert is_map(userinfo_claims),
           "Userinfo JWT signature verification should return claims map"

    debug(userinfo_claims, "Userinfo JWT signature verified successfully")
    userinfo_claims
  end

  @doc """
  Checks if a value is a JWT string (has 3 dot-separated parts).

  Returns true if it looks like a JWT, false otherwise.
  """
  def is_jwt?(value) when is_binary(value) do
    case String.split(value, ".") do
      [_header, _payload, _signature] -> true
      _ -> false
    end
  end

  def is_jwt?(_), do: false

  # Private helper to obtain tokens via auth code flow
  defp get_tokens_via_auth_code_flow(context, opts) do
    %{
      client: client,
      redirect_uri: redirect_uri,
      main_instance: main_instance,
      discovery_document_uri: discovery_document_uri
    } = context

    # Setup provider configuration
    {provider_key, provider_config} =
      build_provider_config(client, main_instance, discovery_document_uri, opts)

    Config.put(:openid_connect_providers, [{provider_key, provider_config}], :bonfire_open_id)

    # Perform authentication flow
    client_name = opts[:client_name] || client.name
    auth_url = get_auth_url(client_name)
    req = create_req_client(main_instance)
    login_response = perform_login_flow(req, auth_url, context)

    # Extract and exchange authorization code
    query_params = extract_query_params(login_response)
    auth_code = query_params["code"]

    assert auth_code,
           "Should receive authorization code"

    # Exchange code for tokens
    {:ok, token_response} =
      exchange_code_for_tokens(discovery_document_uri, req, client, auth_code, redirect_uri)

    assert %{
             "access_token" => access_token,
             "id_token" => id_token
           } = token_response.body

    debug(access_token, "access_token obtained")
    debug(id_token, "id_token obtained")

    {access_token, id_token, main_instance}
  end

  @doc """
  Verifies a JWT signature using JWKS keys.

  Extracts the `kid` from JWT header and attempts to verify signature:
  - First tries to find matching key by `kid`
  - If `kid` not found, logs warning and tries all keys
  - Returns decoded claims if ANY key successfully verifies signature
  - Raises assertion error if no key can verify the signature
  """
  def verify_jwt_signature(jwt, jwks_keys) when is_binary(jwt) and is_list(jwks_keys) do
    # Normalize JWT string (strip surrounding quotes/whitespace that some responses include)
    jwt = sanitize_jwt(jwt)

    # Extract JWT header to get kid
    [header_b64, payload_b64, signature_b64] =
      String.split(jwt, ".")
      |> debug("Splitting JWT into parts")

    header =
      header_b64
      |> add_base64_padding()
      |> Base.decode64!()
      |> Jason.decode!()

    kid = header["kid"]

    # Try to find matching key
    case Enum.find(jwks_keys, &(&1["kid"] == kid)) do
      nil when kid ->
        debug(kid, "JWKS key ID not found in keys, trying all available keys")
        verify_with_all_keys(jwt, jwks_keys, [])

      nil ->
        debug("No kid in JWT header, trying all available keys")
        verify_with_all_keys(jwt, jwks_keys, [])

      matching_key ->
        debug(kid, "Found matching JWKS key, verifying signature")
        verify_jwt_with_key(jwt, matching_key, [kid])
    end
  end

  # Helper to sanitize JWT strings that may include surrounding quotes/whitespace
  # FIXME: check if the server is returning quoted strings incorrectly
  defp sanitize_jwt(jwt) when is_binary(jwt) do
    jwt
    |> String.trim()
    |> String.trim_leading("\"")
    |> String.trim_trailing("\"")
    |> String.trim_leading("'")
    |> String.trim_trailing("'")
  end

  @doc """
  Attempts to verify JWT signature with a specific JWK key.

  Returns decoded claims if signature is valid, or error tuple with attempted key IDs.
  """
  def verify_jwt_with_key(jwt, jwk_key, attempted_kids \\ []) do
    try do
      # Convert JWK to JOSE key format and verify
      jose_key = JOSE.JWK.from_map(jwk_key)

      case JOSE.JWT.verify(jose_key, jwt) do
        {true, jwt_struct, _} ->
          # Signature valid, extract claims
          jwt_struct.fields
          |> debug("JWT signature verified successfully")

        {false, _jwt_struct, _} ->
          # Signature invalid with this key
          {:error, {:signature_invalid, attempted_kids}}
      end
    rescue
      e ->
        debug(e, "Error verifying JWT with key")
        {:error, {:verification_failed, attempted_kids}}
    end
  end

  @doc """
  Attempts to verify JWT signature using all available JWKS keys.

  Tries each key in sequence, collecting errors. Returns claims if ANY key succeeds,
  or fails with comprehensive error report if none work.
  """
  def verify_with_all_keys(jwt, [], attempted_kids) do
    # No keys left to try
    assert false,
           "JWT signature could not be verified with any available key. Attempted key IDs: #{inspect(attempted_kids)}"
  end

  def verify_with_all_keys(jwt, [key | remaining_keys], attempted_kids) do
    kid = key["kid"]

    case verify_jwt_with_key(jwt, key, [kid | attempted_kids]) do
      {:error, _reason} ->
        # This key didn't work, try next one
        debug(kid, "JWT signature verification failed with this key, trying next")
        verify_with_all_keys(jwt, remaining_keys, [kid | attempted_kids])

      claims when is_map(claims) ->
        # Success! Return claims
        claims
    end
  end

  # Helper to add base64 padding
  defp add_base64_padding(b64_string) do
    case rem(String.length(b64_string), 4) do
      0 -> b64_string
      n -> b64_string <> String.duplicate("=", 4 - n)
    end
  end

  @doc """
  Fetches JWKS endpoint and returns the keys for signature verification.

  Verifies:
  - Endpoint returns 200 status
  - Response contains "keys" array
  - Each key has required JWK fields
  """
  def fetch_and_verify_jwks_keys(main_instance) do
    {:ok, jwks_response} = Req.get("#{main_instance}/openid/jwks")

    assert jwks_response.status == 200,
           "JWKS endpoint should return 200"

    assert %{"keys" => keys} = jwks_response.body,
           "JWKS response should contain 'keys' array"

    assert is_list(keys) and length(keys) > 0,
           "Keys should be a non-empty array"

    # Validate each key
    Enum.each(keys, &verify_jwk_key_format/1)

    debug(keys, "JWKS keys verified and ready for signature verification")
    keys
  end

  @doc """
  Verifies consistency between ID token and Userinfo endpoint claims.

  Verifies ID token signature using JWKS keys, then checks that
  the 'sub' claim matches between ID token and userinfo.
  """
  def verify_id_token_userinfo_consistency(id_token, main_instance, access_token) do
    # Fetch JWKS keys for signature verification
    jwks_keys = fetch_and_verify_jwks_keys(main_instance)

    # Verify ID token signature using JWKS keys
    id_token_claims = verify_jwt_signature(id_token, jwks_keys)

    assert is_map(id_token_claims),
           "ID token signature verification should return claims map"

    # Verify userinfo endpoint
    userinfo = verify_userinfo_endpoint_with_keys(main_instance, access_token, jwks_keys)

    # Compare subject claims
    assert id_token_claims["sub"] == userinfo["sub"],
           "Subject (sub) claim should match between ID token and userinfo"

    debug("ID token signature verified and claims are consistent with userinfo")
  end

  @doc """
  Tests JWKS and Userinfo endpoints together in a single flow.

  Performs an authorization code flow to obtain tokens, then verifies:
  - JWKS endpoint returns valid JWK keys
  - ID token signature is valid using JWKS keys
  - Userinfo endpoint returns required claims
  - Response formats match OpenID Connect spec
  """

  def test_jwks_and_userinfo_flow(context, opts) do
    TestInstanceRepo.apply(fn ->
      # Get tokens via authorization code flow
      {access_token, id_token, main_instance} =
        get_tokens_via_auth_code_flow(context, opts)

      # Raw check: fetch userinfo without Req decoding to detect quoted JWT strings
      req = create_req_client(main_instance)

      {:ok, raw_resp} =
        Req.get(req,
          url: "#{main_instance}/openid/userinfo",
          headers: [{"authorization", "Bearer #{access_token}"}],
          decode_body: false
        )

      # Normalize header access (Resp.headers may be map or list)
      content_type =
        case raw_resp.headers do
          %{} = m ->
            Map.get(m, "content-type") || Map.get(m, "Content-Type")

          l when is_list(l) ->
            l
            |> Enum.find_value(fn
              {k, v} when is_binary(k) ->
                if String.downcase(k) == "content-type", do: v, else: nil

              _ ->
                nil
            end)

          _ ->
            nil
        end
        |> List.wrap()
        |> List.first()

      raw_body = to_string(raw_resp.body || "")

      # If server returned a JSON-encoded string (quoted JWT) we want to fail the test and show helpful message
      trimmed = raw_body |> String.trim()

      preview =
        trimmed
        |> String.replace("\n", " ")

      # Detect quoted JWTs even when content-type is application/jwt
      is_json_quoted =
        content_type &&
          String.contains?(String.downcase(content_type), "application/json") &&
          String.starts_with?(trimmed, "\"") &&
          String.ends_with?(trimmed, "\"")

      # JWTs typically start with "eyJ"; detect if the server wrapped that JWT in quotes
      is_jwt_quoted =
        content_type &&
          String.contains?(String.downcase(content_type), "application/jwt") &&
          (String.starts_with?(trimmed, "\"eyJ") ||
             String.starts_with?(trimmed, "\\\"eyJ") ||
             (String.starts_with?(trimmed, "\"") && String.ends_with?(trimmed, "\"") &&
                String.contains?(trimmed, "eyJ")))

      if is_json_quoted || is_jwt_quoted do
        flunk(
          "userinfo endpoint returned a quoted JWT string with content-type #{inspect(content_type)}. " <>
            "The server should return a raw JWT with content-type `application/jwt` (no JSON quoting) or return JSON claims as an object. " <>
            "Preview: #{preview}"
        )
      else
        debug(
          preview,
          "Userinfo endpoint response with content_type #{content_type} looks correctly formatted"
        )
      end

      # Continue with full verification (JWKS + ID token + userinfo)
      verify_id_token_userinfo_consistency(id_token, main_instance, access_token)

      debug("JWKS and Userinfo flow test successful!")
    end)
  end
end
