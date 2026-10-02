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

  test "advertises the client authentication the token endpoint actually accepts", %{conn: conn} do
    methods =
      get(conn, "/.well-known/openid-configuration")
      |> json_response(200)
      |> Map.get("token_endpoint_auth_methods_supported")

    # credentials are read from the request body or a `private_key_jwt` assertion. Absent this key, clients fall back to the spec default of `client_secret_basic`, which is the one method we do not read.
    assert methods == ["client_secret_post", "private_key_jwt"]
  end

  test "advertises PKCE support", %{conn: conn} do
    methods =
      get(conn, "/.well-known/openid-configuration")
      |> json_response(200)
      |> Map.get("code_challenge_methods_supported")

    assert "S256" in methods
  end

  test "advertises grant types and the token management endpoints", %{conn: conn} do
    doc = get(conn, "/.well-known/openid-configuration") |> json_response(200)

    assert "authorization_code" in doc["grant_types_supported"]
    assert doc["revocation_endpoint"]
    assert doc["introspection_endpoint"]
    assert "sub" in doc["claims_supported"]
  end

  test "both discovery documents agree on every key that is not protocol-specific" do
    openid = get(build_conn(), "/.well-known/openid-configuration") |> json_response(200)
    oauth = get(build_conn(), "/.well-known/oauth-authorization-server") |> json_response(200)

    shared =
      ~w(issuer jwks_uri registration_endpoint revocation_endpoint introspection_endpoint
         scopes_supported response_types_supported grant_types_supported
         token_endpoint_auth_methods_supported token_endpoint_auth_signing_alg_values_supported
         code_challenge_methods_supported)

    # both present, so the comparison below cannot pass by comparing two empty maps
    assert Enum.sort(Map.keys(Map.take(openid, shared))) == Enum.sort(shared)
    assert Map.take(openid, shared) == Map.take(oauth, shared)
  end
end
