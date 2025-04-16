defmodule Bonfire.OpenID.OIDCDanceTest do
  use Bonfire.OpenID.ConnCase, async: false
  use Bonfire.OpenID.DanceCase

  @moduletag :test_instance

  import Untangle
  import Bonfire.Common.Config, only: [repo: 0]
  use Bonfire.Common.E

  alias Bonfire.Common.Config
  alias Bonfire.Common.TestInstanceRepo
  alias Bonfire.OpenID.Provider.ClientApps

  #  see https://github.com/bonfire-networks/bonfire-app/issues/1201
  @tag :todo
  test "can login using OpenID Connect", context do
    redirect_uri = "http://localhost:4002/openid/client/test_oidc_provider"
    main_instance = "http://localhost:4000"

    # create a client app on the first instance
    client_id = "e1d87f6e-fbd5-6801-9528-a1d568c1fd02"
    assert Bonfire.Common.Types.uid(client_id)

    # Create client with OpenID Connect scopes
    assert {:ok, %Boruta.Ecto.Client{id: ^client_id} = client} =
             ClientApps.init_test_client_app(client_id, %{
               redirect_uris: [redirect_uri],
               supported_scopes: ["openid", "profile", "email", "identity", "data:public"]
             })
             |> debug("client created")

    TestInstanceRepo.apply(fn ->
      # Configure OpenID Connect provider on the second instance
      discovery_document_uri = "#{main_instance}/.well-known/openid-configuration"

      provider_config = [
        test_oidc_provider: [
          display_name: client.name,
          client_id: client.id,
          client_secret: client.secret,
          discovery_document_uri: discovery_document_uri,
          ##  supported: ["client_credentials", "password", "authorization_code", "refresh_token", "implicit", "revoke", "introspect"]
          response_type: "implicit",
          scope: "identity data:public read write"
          #   redirect_uri: redirect_uri
        ]
      ]

      Config.put(:openid_connect_providers, provider_config, :bonfire_open_id)

      # Get the authorization URL from providers list
      assert auth_url =
               ed(
                 Bonfire.OpenID.Client.providers_authorization_urls() |> debug(),
                 client.name,
                 nil
               )
               |> debug("auth_url")

      # Create a Req client that will maintain cookies throughout all requests
      ReqCookieJar.new()

      req =
        Req.new(
          base_url: main_instance,
          retry: false,
          cache: false
        )
        |> ReqCookieJar.attach()

      # Fetch authorization page
      {:ok, response} = Req.get(req, url: auth_url)

      # Extract CSRF token and form data
      doc =
        response.body
        |> dump()
        |> Floki.parse_document!()

      csrf_token =
        doc
        |> Floki.find("input[name=_csrf_token]")
        |> Floki.attribute("value")
        |> List.first() || raise "CSRF token not found"

      url =
        doc
        |> Floki.find("input[name=go]")
        |> Floki.attribute("value")
        |> List.first() || raise "redirect URI not found"

      # Submit login form
      form_data = %{
        "login_fields[email_or_username]" => context.local.account.email.email_address,
        "login_fields[password]" => context.local.account.credential.password,
        "go" => url,
        "_csrf_token" => csrf_token
      }

      {:ok, %{status: 303} = login_response} =
        Req.post(req,
          url: "#{main_instance}/login",
          form: form_data,
          redirect: false
        )
        |> debug("login_response")

      # Extract authorization code
      auth_code =
        login_response.headers["location"]
        |> List.first()
        |> URI.parse()
        |> Map.get(:fragment)
        |> URI.decode_query()
        |> Map.get("access_token")

      assert auth_code, "Should receive authorization code"

      #   # Exchange code for tokens using token endpoint from discovery document
      #   {:ok, discovery_response} = Req.get(discovery_document_uri)
      #   %{"token_endpoint" => token_endpoint} = discovery_response.body

      #   token_params = %{
      #     # grant_type: #"code id_token token", #"authorization_code",
      #     client_id: client.id,
      #     client_secret: client.secret,
      #     code: auth_code,
      #     redirect_uri: redirect_uri
      #   }

      #   {:ok, token_response} = Req.post(req,
      #     url: token_endpoint,
      #     form: token_params
      #   )

      #   # Verify we get both access token and ID token
      #   assert %{
      #     "access_token" => access_token,
      #     "id_token" => id_token
      #   } = token_response.body

      #   assert access_token, "Should receive access token"
      #   assert id_token, "Should receive ID token"

      #   # Verify userinfo endpoint works
      #   {:ok, userinfo_response} = Req.get(
      #     "#{main_instance}/openid/userinfo",
      #     headers: [
      #       {"authorization", "Bearer #{access_token}"}
      #     ]
      #   )

      #   assert %{
      #     "sub" => _,
      #     "email" => email,
      #     "profile" => _
      #   } = userinfo_response.body

      #   # Verify JWT signing keys are available
      #   {:ok, jwks_response} = Req.get("#{main_instance}/openid/jwks")
      #   assert %{"keys" => _} = jwks_response.body

      #   # Verify discovery document
      #   assert %{
      #     "issuer" => main_instance,
      #     "authorization_endpoint" => _,
      #     "token_endpoint" => _,
      #     "userinfo_endpoint" => _,
      #     "jwks_uri" => _,
      #     "scopes_supported" => scopes
      #   } = discovery_response.body

      #   assert "openid" in scopes, "OpenID scope should be supported"

      #   assert response.body =~ "The oauth provider did not indicate an email for your account"
    end)
  end
end
