defmodule Bonfire.OpenID.Web.MastoEditScopesApiTest do
  use Bonfire.OpenID.ConnCase, async: false

  alias Bonfire.Me.{Accounts, Fake}
  alias Bonfire.OpenID.Provider.ClientApps
  alias Bonfire.Posts
  alias Bonfire.Social.Objects
  alias Boruta.Ecto.AccessTokens
  alias Boruta.Ecto.OauthMapper

  @moduletag :masto_api
  @moduletag capture_log: true

  setup do
    Process.put([:bonfire, :skip_all_boundary_checks], false)
    account = Fake.fake_account!()
    user = Fake.fake_user!(account)
    refute Accounts.is_admin?(user)

    {:ok, client} =
      ClientApps.new(%{
        name: "Edit scopes #{Faker.UUID.v4()}",
        redirect_uris: ["https://client.example/callback"]
      })

    {:ok, post} =
      Posts.publish(
        current_user: user,
        post_attrs: %{
          post_content: %{html_body: "Original body", summary: "Original warning"}
        },
        boundary: "public"
      )

    {:ok, account: account, user: user, client: client, post: post}
  end

  for scope <- ["read", "write:media", ""] do
    test "rejects #{inspect(scope)} without changing the post", context do
      token = create_token!(context, unquote(scope))

      token |> token_conn() |> assert_rejected(context, 403)
    end
  end

  for scope <- ["write:statuses", "write"] do
    test "edits own status with #{scope}", context do
      token = create_token!(context, unquote(scope))

      token |> token_conn() |> assert_edited(context)
    end
  end

  test "a session cannot bypass a read-only token", context do
    token = create_token!(context, "read")

    context
    |> edit_session_conn()
    |> put_req_header("authorization", "Bearer #{token.value}")
    |> assert_rejected(context, 403)
  end

  test "a session cannot bypass an invalid token", context do
    context
    |> edit_session_conn()
    |> put_req_header("authorization", "Bearer invalid-token")
    |> assert_rejected(context, 401)
  end

  test "a session cannot turn an app-only token into a user token", context do
    token = create_token!(%{context | user: nil}, "write:statuses")

    context
    |> edit_session_conn()
    |> put_req_header("authorization", "Bearer #{token.value}")
    |> assert_rejected(context, 401)
  end

  test "write scope does not permit editing another user's status", context do
    other_user = Fake.fake_user!()
    refute Accounts.is_admin?(other_user)
    token = create_token!(%{context | user: other_user}, "write:statuses")

    token |> token_conn() |> assert_rejected(context, 404)
  end

  test "preserves session-only editing", context do
    context |> edit_session_conn() |> assert_edited(context)
  end

  test "rejects unauthenticated editing", context do
    api_conn() |> assert_rejected(context, 401)
  end

  defp create_token!(%{client: client, user: user}, scope) do
    {:ok, token} =
      AccessTokens.create(
        %{client: OauthMapper.to_oauth_schema(client), sub: user && user.id, scope: scope},
        []
      )

    token
  end

  defp api_conn do
    Phoenix.ConnTest.build_conn()
    |> put_req_header("accept", "application/json")
    |> put_req_header("content-type", "application/json")
  end

  defp token_conn(token) do
    api_conn()
    |> put_req_header("authorization", "Bearer #{token.value}")
  end

  defp edit_session_conn(%{account: account, user: user}) do
    api_conn()
    |> Plug.Test.init_test_session(%{})
    |> put_session(:current_account_id, account.id)
    |> put_session(:current_user_id, user.id)
  end

  defp edit_status(conn, post) do
    put(
      conn,
      "/api/v1/statuses/#{post.id}",
      Jason.encode!(%{"status" => "Edited body", "spoiler_text" => "Edited warning"})
    )
  end

  defp read_content(context) do
    {:ok, post} =
      Objects.read(context.post.id,
        current_user: context.user,
        preload: [:with_post_content]
      )

    {post.post_content.html_body, post.post_content.summary}
  end

  defp assert_rejected(conn, context, status) do
    before = read_content(context)

    conn = edit_status(conn, context.post)

    assert {conn.status, read_content(context)} == {status, before}
    assert json_response(conn, status)["error"]
  end

  defp assert_edited(conn, context) do
    response = conn |> edit_status(context.post) |> json_response(200)

    assert response["id"] == context.post.id
    assert response["content"] =~ "Edited body"
    assert response["spoiler_text"] == "Edited warning"
    {body, summary} = read_content(context)
    assert body =~ "Edited body"
    assert summary == "Edited warning"
  end
end
