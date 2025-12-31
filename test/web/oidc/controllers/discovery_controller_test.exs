defmodule Bonfire.OpenID.Web.Controllers.Openid.DiscoveryControllerTest do
  use Bonfire.OpenID.ConnCase, async: true
  import Phoenix.ConnTest

  setup do
    {:ok, conn: build_conn()}
  end

  test "can fetch OpenID discovery document", %{conn: conn} do
    conn = get(conn, "/.well-known/openid-configuration")

    assert conn.status == 200
    response_body = json_response(conn, 200)

    assert %{
             "issuer" => _,
             "authorization_endpoint" => _,
             "token_endpoint" => _,
             "userinfo_endpoint" => _,
             "jwks_uri" => _,
             "scopes_supported" => scopes
           } = response_body

    assert "openid" in scopes
  end
end
