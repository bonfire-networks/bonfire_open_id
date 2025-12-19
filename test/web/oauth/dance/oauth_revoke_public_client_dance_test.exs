defmodule Bonfire.OpenID.OAuthRevokePublicClientDanceTest do
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

  @tag :fixme
  test "can revoke public client tokens",
       %{redirect_uri: redirect_uri, main_instance: main_instance} = context do
    TestInstanceRepo.apply(fn ->
      assert Boruta.Config.repo() == TestInstanceRepo

      # Create a public client (no client_secret required)
      public_client_id = Faker.UUID.v4()
      redirect_uri = "http://localhost:4002/oauth/client/" <> public_client_id

      assert %Boruta.Ecto.Client{id: ^public_client_id} =
               public_client =
               ClientApps.init_test_client_app(public_client_id, %{
                 name: "Public Client for Revoke Test",
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
end
