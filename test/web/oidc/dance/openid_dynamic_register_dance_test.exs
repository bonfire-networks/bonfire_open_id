defmodule Bonfire.OpenID.OIDCDynamicRegDanceTest do
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

  test "can dynamically register OpenID Connect client",
       %{
         main_instance: main_instance,
         secondary_instance: secondary_instance,
         discovery_document_uri: discovery_document_uri
       } = context do
    case get_registration_endpoint(discovery_document_uri) do
      {:ok, registration_endpoint} ->
        test_dynamic_registration_flow(
          registration_endpoint,
          main_instance,
          secondary_instance,
          context
        )

      :not_supported ->
        debug("Server does not support dynamic client registration - skipping test")
    end
  end

  test "dynamically registered public client receives no secret",
       %{
         main_instance: main_instance,
         secondary_instance: secondary_instance,
         discovery_document_uri: discovery_document_uri
       } = _context do
    case get_registration_endpoint(discovery_document_uri) do
      {:ok, registration_endpoint} ->
        redirect_uri = "#{main_instance}/openid/client/dynamic_public_test"
        req = create_req_client(secondary_instance)

        {client_id, _registration_access_token, _registration_client_uri} =
          perform_dynamic_registration_public_client(req, registration_endpoint, redirect_uri)

        # Verify the client was stored as non-confidential with PKCE required
        TestInstanceRepo.apply(fn ->
          client = ClientApps.get_by_id(client_id)
          assert client, "Client should exist in DB"
          refute client.confidential, "Client should be non-confidential"
          assert client.pkce, "Client should require PKCE"
        end)

      :not_supported ->
        debug("Server does not support dynamic client registration - skipping test")
    end
  end

  test "can handle dynamic client registration errors", %{
    main_instance: main_instance,
    secondary_instance: secondary_instance,
    discovery_document_uri: discovery_document_uri
  } do
    case get_registration_endpoint(discovery_document_uri) do
      {:ok, registration_endpoint} ->
        test_registration_error_handling(registration_endpoint, secondary_instance)

      :not_supported ->
        debug("Server does not support dynamic client registration - skipping error test")
    end
  end
end
