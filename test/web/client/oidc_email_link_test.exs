defmodule Bonfire.OpenID.Web.OIDCEmailLinkTest do
  @moduledoc """
  Signing in through an admin-configured OpenID Connect service only reaches an existing local account by email when the service says it verified that email (`email_verified: true`), and only when the id token carries the nonce this browser sent. Otherwise anyone who can set an arbitrary email at the service could take over the account, or replay a token meant for another sign-in.
  """
  use Bonfire.OpenID.ConnCase, async: false
  use Repatch.ExUnit

  @moduletag capture_log: true

  setup do
    Process.put([:bonfire_open_id, :openid_connect_providers],
      orcid: %{
        discovery_document_uri: "https://orcid.org/.well-known/openid-configuration",
        client_id: "id",
        client_secret: "secret",
        scope: "openid",
        display_name: "ORCID"
      }
    )

    Repatch.patch(OpenIDConnect, :authorization_uri, fn _provider, _redirect_uri, params ->
      {:ok, "https://orcid.org/authorize?" <> URI.encode_query(params)}
    end)

    Repatch.patch(OpenIDConnect, :fetch_tokens, fn _provider, _params ->
      {:ok, %{"id_token" => "token", "access_token" => "access"}}
    end)

    # the claims the (mocked) service returns for the id token, set by each test
    Repatch.patch(OpenIDConnect, :verify, fn _provider, _token ->
      {:ok, Process.get(:oidc_claims)}
    end)

    account = Bonfire.Me.Fake.fake_account!()
    {:ok, account: account}
  end

  # starts the sign-in as a browser does and returns the browser's conn with the state and nonce the service was sent
  defp start do
    conn = get(conn(), "/openid/client/orcid")
    assert [location] = Plug.Conn.get_resp_header(conn, "location")
    query = location |> URI.parse() |> Map.fetch!(:query) |> URI.decode_query()
    {recycle(conn), query["state"], query["nonce"]}
  end

  # the service answers with `claims` (merged over a base identity), and the browser comes back
  defp come_back(claims_for) when is_function(claims_for, 1) do
    {conn, state, nonce} = start()

    # control for every test: the sign-in was started with a nonce
    assert is_binary(nonce) and nonce != ""

    Process.put(
      :oidc_claims,
      Map.merge(
        %{"iss" => "https://orcid.org", "sub" => "0000-0002-1825-0097", "name" => "A Person"},
        claims_for.(nonce)
      )
    )

    get(conn, "/openid/client/orcid?code=c&state=#{state}")
  end

  defp signed_in_as?(conn, account), do: get_session(conn, :current_account_id) == account.id

  test "an email the service verified signs in the matching account", %{account: account} do
    conn =
      come_back(fn nonce ->
        %{
          "email" => account.email.email_address,
          "email_verified" => true,
          "nonce" => nonce
        }
      end)

    assert signed_in_as?(conn, account)
  end

  test "an email the service did not verify does not sign in the matching account", %{
    account: account
  } do
    conn =
      come_back(fn nonce ->
        %{
          "email" => account.email.email_address,
          "email_verified" => false,
          "nonce" => nonce
        }
      end)

    refute signed_in_as?(conn, account)
  end

  test "an email the service says nothing about does not sign in the matching account", %{
    account: account
  } do
    conn = come_back(fn nonce -> %{"email" => account.email.email_address, "nonce" => nonce} end)

    refute signed_in_as?(conn, account)
  end

  test "an id token with another sign-in's nonce is refused", %{account: account} do
    conn =
      come_back(fn _nonce ->
        %{
          "email" => account.email.email_address,
          "email_verified" => true,
          "nonce" => "a-nonce-from-another-sign-in"
        }
      end)

    refute signed_in_as?(conn, account)
    assert redirected_to(conn) == "/login"
  end

  test "an id token with no nonce is refused", %{account: account} do
    conn =
      come_back(fn _nonce ->
        %{"email" => account.email.email_address, "email_verified" => true}
      end)

    refute signed_in_as?(conn, account)
  end
end
