defmodule Bonfire.OpenID.Web.MastoTokensApiTest do
  @moduledoc """
  Tests for the OAuth token management endpoints:
  - GET  /api/v1/tokens
  - GET  /api/v1/tokens/:id
  - POST /api/v1/tokens/:id/invalidate
  """
  use Bonfire.OpenID.ConnCase, async: false

  import Ecto.Query

  alias Bonfire.Me.Fake
  alias Bonfire.OpenID.Provider.ClientApps
  alias Boruta.Ecto.AccessTokens, as: AccessTokensAdapter
  import Boruta.Ecto.OauthMapper, only: [to_oauth_schema: 1]

  @moduletag :masto_api

  setup do
    account = Fake.fake_account!()
    user = Fake.fake_user!(account)
    token = create_token!(user, "read write")

    conn =
      Phoenix.ConnTest.build_conn()
      |> put_req_header("accept", "application/json")
      |> put_req_header("authorization", "Bearer #{token.value}")

    {:ok, conn: conn, user: user, token: token}
  end

  describe "GET /api/v1/tokens" do
    test "lists the current user's tokens", %{conn: conn} do
      [entry | _] =
        conn
        |> get("/api/v1/tokens")
        |> json_response(200)

      assert entry["id"]
      assert entry["created_at"]
      assert entry["scope"] == "read write"
      assert is_map(entry["application"])
      refute Map.has_key?(entry["application"], "client_secret")
    end

    test "requires authentication" do
      Phoenix.ConnTest.build_conn()
      |> put_req_header("accept", "application/json")
      |> get("/api/v1/tokens")
      |> json_response(401)
    end
  end

  describe "GET /api/v1/tokens/:id" do
    test "returns a single token owned by the user", %{conn: conn} do
      [%{"id" => id} | _] = conn |> get("/api/v1/tokens") |> json_response(200)

      entry = conn |> get("/api/v1/tokens/#{id}") |> json_response(200)
      assert entry["id"] == id
    end

    test "returns 404 for an unknown token", %{conn: conn} do
      conn
      |> get("/api/v1/tokens/#{Faker.UUID.v4()}")
      |> json_response(404)
    end

    test "returns 404 (not 500) for a malformed token id", %{conn: conn} do
      conn
      |> get("/api/v1/tokens/not-a-valid-id")
      |> json_response(404)
    end

    test "cannot read another user's token", %{conn: conn} do
      other = Fake.fake_user!(Fake.fake_account!())
      other_token = create_token!(other, "read")

      conn
      |> get("/api/v1/tokens/#{boruta_token_id(other_token)}")
      |> json_response(404)
    end
  end

  describe "POST /api/v1/tokens/:id/invalidate" do
    test "revokes the target token without affecting other tokens", %{conn: conn, user: user} do
      # a second token to invalidate, so the auth token stays valid for follow-up requests
      extra_id = create_token!(user, "read") |> boruta_token_id()

      ids_before = conn |> get("/api/v1/tokens") |> json_response(200) |> Enum.map(& &1["id"])
      assert extra_id in ids_before

      revoked = conn |> post("/api/v1/tokens/#{extra_id}/invalidate") |> json_response(200)
      assert revoked["id"] == extra_id

      ids_after = conn |> get("/api/v1/tokens") |> json_response(200) |> Enum.map(& &1["id"])
      refute extra_id in ids_after
    end
  end

  # --- helpers ---

  defp create_token!(user, scope) do
    {:ok, client} =
      ClientApps.new(%{
        id: Faker.UUID.v4(),
        name: "test-tokens-app-#{Faker.UUID.v4()}",
        redirect_uris: ["http://localhost:4000/oauth/callback"]
      })

    {:ok, token} =
      AccessTokensAdapter.create(
        %{client: to_oauth_schema(client), sub: user.id, scope: scope},
        []
      )

    token
  end

  # The Mastodon token `id` is the Boruta token's database id.
  defp boruta_token_id(%{value: value}) do
    Boruta.Config.repo().one!(
      from(t in Boruta.Ecto.Token, where: t.value == ^value, select: t.id)
    )
  end
end
