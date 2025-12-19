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
    setup()
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
end
