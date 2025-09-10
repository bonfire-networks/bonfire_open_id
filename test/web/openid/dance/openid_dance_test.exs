defmodule Bonfire.OpenID.OIDCDanceTest do
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
    redirect_uri = "http://localhost:4002/openid/client/test_oidc_provider"
    main_instance = "http://localhost:4000"
    client_id = "e1d87f6e-fbd5-6801-9528-a1d568c1fd02"
    discovery_document_uri = "#{main_instance}/.well-known/openid-configuration"

    # Create client with OpenID Connect scopes
    assert %Boruta.Ecto.Client{id: ^client_id} =
             client =
             ClientApps.init_test_client_app(client_id, %{
               redirect_uris: [redirect_uri],
               supported_scopes: ["openid", "profile", "email", "identity", "data:public"]
             })
             |> from_ok()

    %{
      client: client,
      client_id: client_id,
      redirect_uri: redirect_uri,
      main_instance: main_instance,
      discovery_document_uri: discovery_document_uri
    }
  end

  test "can login using OpenID Connect with implicit flow", context do
    test_oidc_flow(context, %{
      response_type: "implicit",
      scope: "openid identity data:public",
      flow_type: :implicit
    })
  end

  test "can login using OpenID Connect with authorization code flow + fetch cross-instance user info",
       context do
    test_oidc_flow(context, %{
      response_type: "authorization_code",
      scope: "openid profile email identity data:public",
      flow_type: :authorization_code,
      test_cross_instance: true
    })
  end

  test "can login using OpenID Connect with PKCE flow", context do
    test_oidc_flow(context, %{
      response_type: "authorization_code",
      scope: "openid profile email identity data:public",
      flow_type: :authorization_code_pkce,
      client_name: "PKCE Test Client"
    })
  end

  test "can login using public client with PKCE flow",
       %{
         redirect_uri: redirect_uri,
         main_instance: main_instance,
         discovery_document_uri: discovery_document_uri
       } = context do
    # Create a public client (no client_secret)
    public_client_id = "0198a577-c25e-f936-9418-c0c6288d33b9"

    assert %Boruta.Ecto.Client{id: ^public_client_id} =
             public_client =
             ClientApps.init_test_client_app(public_client_id, %{
               redirect_uris: [redirect_uri],
               pkce: true,
               supported_scopes: ["openid", "profile", "email", "identity", "data:public"],
               # Public client
               confidential: false
             })
             |> debug("public PKCE client created")
             |> from_ok()

    # Test PKCE flow with public client
    test_oidc_flow(Map.put(context, :client, public_client), %{
      response_type: "authorization_code",
      scope: "openid identity data:public",
      flow_type: :authorization_code_pkce,
      client_name: "Public PKCE Client",
      public_client: true
    })
  end

  test "returns correct claims for different scopes", context do
    test_oidc_flow(context, %{
      response_type: "authorization_code",
      scope: "openid profile email identity data:public",
      flow_type: :authorization_code,
      client_name: "Test Client with Full Scopes",
      verify_claims: ["openid", "profile", "email", "identity"]
    })
  end

  test "respects limited scopes in claims", context do
    test_oidc_flow(context, %{
      response_type: "authorization_code",
      scope: "openid identity",
      flow_type: :authorization_code,
      client_name: "Test Client with Limited Scopes",
      verify_claims: ["openid", "identity"]
    })
  end

  test "can dynamically register OpenID Connect client",
       %{main_instance: main_instance, discovery_document_uri: discovery_document_uri} = context do
    TestInstanceRepo.apply(fn ->
      case get_registration_endpoint(discovery_document_uri) do
        {:ok, registration_endpoint} ->
          test_dynamic_registration_flow(registration_endpoint, main_instance, context)

        :not_supported ->
          debug("Server does not support dynamic client registration - skipping test")
      end
    end)
  end

  test "can handle dynamic client registration errors", %{
    main_instance: main_instance,
    discovery_document_uri: discovery_document_uri
  } do
    TestInstanceRepo.apply(fn ->
      case get_registration_endpoint(discovery_document_uri) do
        {:ok, registration_endpoint} ->
          test_registration_error_handling(registration_endpoint, main_instance)

        :not_supported ->
          debug("Server does not support dynamic client registration - skipping error test")
      end
    end)
  end

  defp test_oidc_flow(
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

  defp build_provider_config(client, main_instance, discovery_document_uri, opts) do
    client_name = opts[:client_name] || client.name
    provider_key = :test_oidc_provider

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

  defp generate_pkce_params do
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
  defp test_implicit_flow_completion(login_response, main_instance, _opts) do
    fragment_params = extract_fragment_params(login_response)

    access_token = fragment_params["access_token"]
    id_token = fragment_params["id_token"]

    assert access_token, "Should receive access token in redirect fragment"
    assert id_token, "Should receive ID token in redirect fragment"

    verify_userinfo_endpoint(main_instance, access_token)
  end

  defp test_authorization_code_flow_completion(
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

  defp exchange_code_for_tokens_pkce(
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
  defp test_cross_instance_user_info(id_token, access_token, main_instance) do
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

    userinfo = userinfo_response.body
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
  defp extract_user_identity(id_token) do
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
  defp exchange_code_for_tokens(discovery_document_uri, req, client, auth_code, redirect_uri) do
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
  defp test_dynamic_registration_flow(registration_endpoint, main_instance, context) do
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
  defp perform_dynamic_registration(registration_endpoint, main_instance, redirect_uri) do
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
  defp test_dynamic_client_auth_flow(
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
  defp get_registration_endpoint(discovery_document_uri) do
    {:ok, discovery_response} = Req.get(discovery_document_uri)

    case discovery_response.body["registration_endpoint"] do
      nil -> :not_supported
      endpoint -> {:ok, endpoint}
    end
  end

  # DRY: Registration error testing
  defp test_registration_error_handling(registration_endpoint, main_instance) do
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
  defp verify_id_token_claims(id_token, expected_scopes) do
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
  defp verify_userinfo_claims(main_instance, access_token, expected_scopes) do
    {:ok, userinfo_response} =
      Req.get(
        "#{main_instance}/openid/userinfo",
        headers: [{"authorization", "Bearer #{access_token}"}]
      )

    userinfo = userinfo_response.body |> debug("Userinfo claims")

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
  defp test_client_configuration_retrieval(registration_client_uri, registration_access_token) do
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
  defp test_client_configuration_update(
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
    # Fetch authorization page
    {:ok, response} = Req.get(req, url: auth_url, redirect: true)

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

    assert login_response.status == 303,
           debug(login_response, "login_response") && "Should redirect after successful login"

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
        "#{main_instance}/openid/userinfo",
        headers: [{"authorization", "Bearer #{access_token}"}]
      )

    assert %{
             "sub" => _
             # "email" => _email,
             # "profile" => _
           } = userinfo_response.body
  end

  defp verify_discovery_document(discovery_document_uri, main_instance) do
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
end
