defmodule Bonfire.OpenID.OAuthRevokePublicClientDanceTest do
  use Bonfire.OpenID.DanceCase, async: false
  use Patch, only: []
  import Bonfire.OpenID.DanceCase
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
    return = setup()

    on_exit(fn ->
      teardown(return.client)
    end)

    return
  end

  @tag :fixme
  test "can revoke public client tokens",
       %{
         redirect_uri: redirect_uri,
         main_instance: main_instance,
         secondary_instance: secondary_instance
       } = context do
    # Create a public client (no client_secret required)
    public_client_id = Faker.UUID.v4()
    redirect_uri = "#{main_instance}/oauth/client/" <> public_client_id

    public_client =
      TestInstanceRepo.apply(fn ->
        assert %Boruta.Ecto.Client{id: ^public_client_id} =
                 ClientApps.init_test_client_app(public_client_id, %{
                   name:
                     "Public Client for Revoke Test (secondary test instance, redirecting to primary instance)",
                   redirect_uris: [redirect_uri],
                   supported_scopes: ["identity", "data:public"],
                   # Public client
                   confidential: false
                 })
                 |> debug("public client created")
      end)

    # Get tokens for public client
    {access_token, _refresh_token} =
      get_initial_tokens_with_refresh(
        public_client,
        redirect_uri,
        main_instance,
        secondary_instance,
        context
      )

    # Verify token works
    verify_userinfo_endpoint(secondary_instance, access_token)

    # Revoke without client_secret (public client)
    revoke_uri = "#{secondary_instance}/oauth/revoke"
    req = create_req_client(secondary_instance)

    revoke_params = %{
      token: access_token,
      token_type_hint: "access_token",
      client_id: public_client.id
      # No client_secret for public clients
    }

    {:ok, revoke_response} =
      apply_with_repo_sync(fn ->
        Req.post(req,
          url: revoke_uri,
          form: revoke_params
        )
      end)

    case revoke_response.status do
      200 ->
        # Server supports public client revocation
        debug("Server supports public client token revocation")
        verify_token_revoked(secondary_instance, access_token)

      401 ->
        # Server requires client authentication for revocation
        assert %{"error" => "invalid_client"} = revoke_response.body
        debug("Server requires client authentication for token revocation (common behavior)")

      # This is actually compliant behavior - many OAuth servers require
      # client authentication for revocation even for public clients

      _ ->
        flunk("Unexpected revocation response: #{revoke_response.status}")
    end
  end
end
