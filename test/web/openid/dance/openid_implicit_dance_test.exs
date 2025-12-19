defmodule Bonfire.OpenID.OIDCImplicitDanceTest do
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

  test "can login using OpenID Connect with implicit flow", context do
    test_oidc_flow(context, %{
      response_type: "implicit",
      scope: "openid identity data:public",
      flow_type: :implicit
    })
  end
end
