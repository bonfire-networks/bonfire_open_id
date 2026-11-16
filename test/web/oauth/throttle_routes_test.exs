defmodule Bonfire.OpenID.Web.Oauth.ThrottleRoutesTest do
  @moduledoc """
  Every OAuth endpoint that takes a client's credentials sits behind the form throttle. The throttle plug is a no-op in the test environment (it only runs when ENABLE_RATE_LIMIT=yes is set at compile time), so this checks the pipelines the router applies to each route rather than a 429.
  """
  use Bonfire.OpenID.ConnCase, async: true

  defp pipelines(path) do
    assert %{pipe_through: pipes} =
             Phoenix.Router.route_info(Bonfire.Web.Router, "POST", path, "localhost")

    pipes
  end

  test "control: /oauth/token is throttled" do
    assert :throttle_forms in pipelines("/oauth/token")
  end

  test "/oauth/revoke is throttled like /oauth/token" do
    assert :throttle_forms in pipelines("/oauth/revoke")
  end

  test "/oauth/introspect is throttled like /oauth/token" do
    assert :throttle_forms in pipelines("/oauth/introspect")
  end
end
