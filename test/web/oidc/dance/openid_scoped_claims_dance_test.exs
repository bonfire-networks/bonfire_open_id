defmodule Bonfire.OpenID.OIDCScopedClaimsDanceTest do
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
end
