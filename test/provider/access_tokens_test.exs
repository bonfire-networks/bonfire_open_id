defmodule Bonfire.OpenID.Provider.AccessTokensTest do
  @moduledoc """
  Unit tests for our custom `AccessTokens` adapter, which controls token lifetime
  and refresh-token issuance.

  See bonfire-app#1806: native apps (Mastodon clients) lose access because they
  don't request `offline_access` and so were issued a long-lived token with NO
  refresh token, leaving no recovery path. The adapter's only job is to make
  non-`offline_access` tokens long-lived — it must NOT suppress the refresh token
  the grant wants. Boruta decides whether to mint a refresh token from
  `options[:refresh_token]` (true → refresh token; the authorization_code grant
  passes this). So we issue a refresh token whenever the grant asks for one, in
  BOTH branches; the only difference is the access-token TTL.
  """
  use Bonfire.OpenID.ConnCase, async: false

  alias Bonfire.Me.Fake
  alias Bonfire.OpenID.Provider.AccessTokens
  alias Bonfire.OpenID.Provider.ClientApps
  import Boruta.Ecto.OauthMapper, only: [to_oauth_schema: 1]

  @three_hundred_days div(to_timeout(day: 300), 1_000)

  # `options` mirrors what Boruta passes per grant — the authorization_code grant
  # (used by native apps) passes `refresh_token: true`.
  defp create(scope, options \\ [refresh_token: true]) do
    user = Fake.fake_user!()

    {:ok, client} =
      ClientApps.new(%{
        id: Faker.UUID.v4(),
        name: "test-access-tokens-app-#{Faker.UUID.v4()}",
        redirect_uris: ["http://localhost:4000/oauth/callback"]
      })

    {:ok, token} =
      AccessTokens.create(
        %{client: to_oauth_schema(client), sub: user.id, scope: scope},
        options
      )

    token
  end

  defp ttl_seconds(token) do
    token.expires_at - DateTime.to_unix(token.inserted_at)
  end

  describe "create/2 for a Mastodon-style client (no offline_access)" do
    test "issues a long-lived (>300 day) access token" do
      token = create("read write")
      assert ttl_seconds(token) > @three_hundred_days
    end

    test "ALSO issues a refresh token when the grant asks for one, for a recovery path (#1806)" do
      token = create("read write", refresh_token: true)
      assert token.refresh_token, "expected a refresh token even without offline_access"
    end

    test "does NOT force a refresh token when the grant doesn't want one (e.g. implicit)" do
      token = create("read write", refresh_token: false)
      refute token.refresh_token
    end
  end

  describe "create/2 for a standard OAuth client (offline_access)" do
    test "issues a refresh token" do
      token = create("read write offline_access", refresh_token: true)
      assert token.refresh_token
    end

    test "issues a standard short-lived access token (NOT the 365-day long-lived one)" do
      token = create("read write offline_access")
      assert ttl_seconds(token) <= @three_hundred_days
    end
  end
end
