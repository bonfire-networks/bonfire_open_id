defmodule Bonfire.OpenID.JwksUserinfoDanceTest do
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

  test "can verify JWKS and Userinfo endpoints via authorization code flow", context do
    test_jwks_and_userinfo_flow(context, %{
      response_type: "authorization_code",
      scope: "openid profile email identity data:public",
      flow_type: :authorization_code
    })
  end
end
