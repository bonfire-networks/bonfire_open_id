defmodule Bonfire.OpenID.OIDCPKCEPublicClientDanceTest do
  use Bonfire.OpenID.DanceCase, async: false
  use Patch, only: []
  import Bonfire.OpenID.OIDCDance

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
    context = setup()
    on_exit(fn -> teardown(context.client) end)
    context
  end

  @tag :fixme
  test "can login using public client with PKCE flow",
       %{
         redirect_uri: redirect_uri,
         main_instance: main_instance,
         discovery_document_uri: discovery_document_uri
       } = context do
    # Create a public client (no client_secret)
    public_client_id = Faker.UUID.v4()
    redirect_uri = "#{main_instance}/oauth/client/" <> public_client_id

    public_client =
      TestInstanceRepo.apply(fn ->
        assert %Boruta.Ecto.Client{id: ^public_client_id} =
                 ClientApps.init_test_client_app(public_client_id, %{
                   name:
                     "Public Client for PKCE Test (secondary test instance, redirecting to primary instance)",
                   redirect_uris: [redirect_uri],
                   pkce: true,
                   supported_scopes: ["openid", "profile", "email", "identity", "data:public"],
                   # Public client
                   confidential: false
                   #  secret: nil
                 })
                 |> debug("public PKCE client created")
                 |> from_ok()
      end)

    # Test PKCE flow with public client
    test_oidc_flow(Map.put(context, :client, public_client), %{
      response_type: "authorization_code",
      scope: "openid identity data:public",
      flow_type: :authorization_code_pkce,
      client_name: "Public PKCE Client",
      public_client: true
    })
  end
end
