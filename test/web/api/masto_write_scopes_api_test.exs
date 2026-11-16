defmodule Bonfire.OpenID.Web.MastoWriteScopesApiTest do
  @moduledoc """
  A token granted only `read` must be refused (403) on every Mastodon API write endpoint, and nothing may change. A `write` token must still work.
  """
  use Bonfire.OpenID.ConnCase, async: false

  alias Bonfire.Me.{Accounts, Fake, Users}
  alias Bonfire.OpenID.Provider.ClientApps
  alias Bonfire.Posts
  alias Bonfire.Boundaries.Blocks
  alias Bonfire.Social.Graph.Follows
  alias Bonfire.Social.Likes
  alias Boruta.Ecto.AccessTokens
  alias Boruta.Ecto.OauthMapper

  @moduletag :masto_api
  @moduletag capture_log: true

  setup do
    Process.put([:bonfire, :skip_all_boundary_checks], false)
    account = Fake.fake_account!()
    user = Fake.fake_user!(account, %{profile: %{name: "Original name"}})
    other = Fake.fake_user!()
    refute Accounts.is_admin?(user)

    {:ok, client} =
      ClientApps.new(%{
        name: "Write scopes #{Faker.UUID.v4()}",
        redirect_uris: ["https://client.local/callback"]
      })

    {:ok, post} =
      Posts.publish(
        current_user: other,
        post_attrs: %{post_content: %{html_body: "Something to favourite"}},
        boundary: "public"
      )

    {:ok, user: user, other: other, client: client, post: post}
  end

  # sanity control: the one write endpoint that already checks scopes
  test "POST /api/v1/statuses with a read-only token is refused", c do
    conn =
      c |> token_conn("read") |> post("/api/v1/statuses", Jason.encode!(%{"status" => "hello"}))

    assert conn.status in [401, 403]
  end

  describe "a read-only token is refused and nothing changes" do
    test "POST /api/v1/accounts/:id/follow", c do
      conn = c |> token_conn("read") |> post("/api/v1/accounts/#{c.other.id}/follow", "{}")

      assert conn.status in [401, 403]
      refute Follows.following?(c.user, c.other)
    end

    test "POST /api/v1/statuses/:id/favourite", c do
      conn = c |> token_conn("read") |> post("/api/v1/statuses/#{c.post.id}/favourite", "{}")

      assert conn.status in [401, 403]
      refute Likes.liked?(c.user, c.post)
    end

    test "PATCH /api/v1/accounts/update_credentials", c do
      {:ok, before} = Users.by_id(c.user.id)

      conn =
        c
        |> token_conn("read")
        |> patch(
          "/api/v1/accounts/update_credentials",
          Jason.encode!(%{"display_name" => "Hijacked"})
        )

      assert conn.status in [401, 403]
      {:ok, reloaded} = Users.by_id(c.user.id)
      assert reloaded.profile.name == before.profile.name
      refute reloaded.profile.name == "Hijacked"
    end

    test "POST /api/v1/accounts/:id/block", c do
      conn = c |> token_conn("read") |> post("/api/v1/accounts/#{c.other.id}/block", "{}")

      assert conn.status in [401, 403]
      refute Blocks.is_blocked?(c.other, :any, current_user: c.user)
    end
  end

  describe "controls: a write token works" do
    test "POST /api/v1/accounts/:id/follow", c do
      conn = c |> token_conn("write") |> post("/api/v1/accounts/#{c.other.id}/follow", "{}")

      assert conn.status == 200
      assert Follows.following?(c.user, c.other)
    end

    test "POST /api/v1/statuses/:id/favourite", c do
      conn = c |> token_conn("write") |> post("/api/v1/statuses/#{c.post.id}/favourite", "{}")

      assert conn.status == 200
      assert Likes.liked?(c.user, c.post)
    end

    test "PATCH /api/v1/accounts/update_credentials", c do
      conn =
        c
        |> token_conn("write:accounts")
        |> patch(
          "/api/v1/accounts/update_credentials",
          Jason.encode!(%{"display_name" => "Renamed"})
        )

      assert conn.status == 200
      {:ok, reloaded} = Users.by_id(c.user.id)
      assert reloaded.profile.name == "Renamed"
    end

    test "POST /api/v1/accounts/:id/block", c do
      conn = c |> token_conn("write:blocks") |> post("/api/v1/accounts/#{c.other.id}/block", "{}")

      assert conn.status == 200
      assert Blocks.is_blocked?(c.other, :any, current_user: c.user)
    end
  end

  defp token_conn(%{client: client, user: user}, scope) do
    {:ok, token} =
      AccessTokens.create(
        %{client: OauthMapper.to_oauth_schema(client), sub: user.id, scope: scope},
        []
      )

    Phoenix.ConnTest.build_conn()
    |> put_req_header("accept", "application/json")
    |> put_req_header("content-type", "application/json")
    |> put_req_header("authorization", "Bearer #{token.value}")
  end
end
