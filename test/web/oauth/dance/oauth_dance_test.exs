defmodule Bonfire.OpenID.OAuthDanceTest do
  use Bonfire.OpenID.ConnCase, async: false
  use Bonfire.OpenID.DanceCase

  @moduletag :test_instance

  import Untangle
  import Bonfire.Common.Config, only: [repo: 0]
  use Bonfire.Common.E

  alias Bonfire.Common.Config
  alias Bonfire.Common.TestInstanceRepo

  alias Bonfire.OpenID.Provider.ClientApps

  @tag :test_instance
  test "can login using oAuth", context do
    redirect_uri = "http://localhost:4002/oauth/client/test_oauth_provider"

    # create a client app on the first instance
    client_id = "b0f15e02-b0f1-b0f1-b0f1-b0f15eb0f15e"

    assert {:ok, %Boruta.Ecto.Client{id: ^client_id} = client} =
             ClientApps.init_test_client_app(client_id, %{redirect_uris: [redirect_uri]})
             |> debug("client created")

    TestInstanceRepo.apply(fn ->
      # now we're on a remote instance and should try signing in via the first instance using oauth

      # configure something similar to this using the info above with `Config.put(key, data, otp_app)`
      #   config :bonfire_open_id, :oauth2_providers,
      #     github: [
      #     display_name: "GitHub",
      #     client_id: github_app_client_id,
      #     client_secret: System.get_env("GITHUB_CLIENT_SECRET"),
      #     authorize_uri: "https://github.com/login/oauth/authorize", # TODO
      #     access_token_uri: "https://github.com/login/oauth/access_token",
      #     redirect_uri: "#{Bonfire.Common.URIs.base_url}/openid/client/github",
      #   ]

      client_name = client.name
      main_instance = "http://localhost:4000/"

      # TODO: generate below URLs automatically
      authorize_uri = "http://localhost:4000/oauth/authorize"
      access_token_uri = "http://localhost:4000/oauth/token"

      provider_config = [
        test_oauth_provider: [
          display_name: client_name,
          client_id: client.id,
          client_secret: client.secret,
          authorize_uri: authorize_uri,
          access_token_uri: access_token_uri
          # redirect_uri: redirect_uri     # TODO: get redirect_uri automatically (should be in Boruta.Ecto.Client?)
        ]
      ]

      Config.put(:oauth2_providers, provider_config, :bonfire_open_id)

      # this function gives us the URL to visit based on above config: Bonfire.OpenID.Client.providers_authorization_urls()

      # now use Req to fetch that URL, read the form, and attempt to login using credentials from user in context[:local]

      # Get the authorization URL
      assert auth_url =
               ed(Bonfire.OpenID.Client.providers_authorization_urls(), client_name, nil)
               |> debug()

      # Create a Req client that will maintain cookies throughout all requests
      ReqCookieJar.new()

      req =
        Req.new(
          base_url: "http://localhost:4000",
          retry: false,
          cache: false
        )
        # Enable cookie management
        |> ReqCookieJar.attach()

      # visit auth URL
      {:ok, response} = Req.get(req, url: auth_url)

      # Extract CSRF token from response body
      doc =
        response.body
        |> IO.inspect()
        |> Floki.parse_document!()

      csrf_token =
        doc
        |> Floki.find("input[name=_csrf_token]")
        |> Floki.attribute("value")
        |> List.first() || raise "CSRF not found"

      url =
        doc
        |> Floki.find("input[name=go]")
        |> debug()
        |> Floki.attribute("value")
        |> List.first() || raise "redirect URI not found"

      # debug(context.local, "localuser")

      form_data = %{
        "login_fields[email_or_username]" => context.local.account.email.email_address,
        "login_fields[password]" => context.local.account.credential.password,
        "go" => url,
        "_csrf_token" => csrf_token
        # "client_id" => client.id,
        # "redirect_uri" => redirect_uri,
        # "response_type" => "code",
        # "scope" => "identity"
      }

      # Submit login form
      {:ok, login_response} =
        Req.post(req,
          url: "#{main_instance}/login",
          form: form_data,
          redirect: false
        )
        |> debug()

      # Submit consent form
      # consent_data = %{
      #   "_csrf_token" => csrf_token,
      #   "authorize" => "true"
      # }

      # {:ok, consent_response} = Req.post(req, 
      #   url: authorize_uri,
      #   form: consent_data,
      #   redirect: false
      # ) 
      # |> debug()

      # Extract authorization code from redirect URL
      auth_code =
        login_response.headers["location"]
        |> List.first()
        |> URI.parse()
        |> Map.get(:query)
        |> URI.decode_query()
        |> Map.get("code")

      assert auth_code, "Should receive authorization code"

      # Exchange auth code for access token
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

      assert %{"access_token" => access_token} = token_response.body
      assert access_token, "Should receive access token"

      # Verify access token works by making authenticated request
      {:ok, me_response} =
        Req.get(
          "#{main_instance}/openid/userinfo",
          headers: [
            {"authorization", "Bearer #{access_token}"}
          ]
        )

      assert %{
               "sub" => _
               # "email" => email
             } = me_response.body

      # assert email == context.local.email
    end)
  end
end
