defmodule Bonfire.OpenID.OAuthClientCredentialsDanceTest do
  use Bonfire.OpenID.DanceCase, async: false
  use Patch, only: []
  import Bonfire.OpenID.OAuthDance

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
    setup()
  end

  test "can authenticate using OAuth client credentials flow",
       %{client: client, main_instance: main_instance} = context do
    TestInstanceRepo.apply(fn ->
      assert Boruta.Config.repo() == TestInstanceRepo

      # Configure OAuth provider for client credentials flow
      access_token_uri = "#{main_instance}/oauth/token"

      provider_config = %{
        client.id => [
          display_name: client.name,
          client_id: client.id,
          client_secret: client.secret,
          access_token_uri: access_token_uri,
          # OAuth scopes for machine-to-machine
          scope: "identity data:public"
        ]
      }

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
end
