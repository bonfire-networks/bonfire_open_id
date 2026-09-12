defmodule Bonfire.OpenID.Web.MastoDeleteScopesApiTest do
  use Bonfire.OpenID.ConnCase, async: false

  alias Bonfire.Me.Fake
  alias Bonfire.OpenID.Provider.ClientApps
  alias Bonfire.Posts
  alias Boruta.Ecto.AccessTokens
  alias Boruta.Ecto.OauthMapper

  @moduletag :masto_api
  @moduletag capture_log: true

  setup do
    account = Fake.fake_account!()
    user = Fake.fake_user!(account)

    {:ok, client} =
      ClientApps.new(%{
        name: "Delete scopes #{Faker.UUID.v4()}",
        redirect_uris: ["https://client.example/callback"]
      })

    {:ok, post} =
      Posts.publish(
        current_user: user,
        post_attrs: %{post_content: %{html_body: "Deletion regression #{Faker.UUID.v4()}"}},
        boundary: "public"
      )

    {:ok, account: account, user: user, client: client, post: post}
  end

  for scope <- ["read", "write:media", ""] do
    test "rejects #{inspect(scope)} without deleting", context do
      token = create_token!(context, unquote(scope))
      token |> token_conn() |> assert_rejected(context, 403)
    end
  end

  for scope <- ["write:statuses", "write"] do
    test "deletes own status with #{scope}", context do
      token = create_token!(context, unquote(scope))
      response = token |> token_conn() |> delete_status(context.post) |> json_response(200)

      assert response["id"] == context.post.id
      assert {:error, _} = Posts.read(context.post.id, current_user: context.user)
    end
  end

  test "a session cannot bypass a read-only token", context do
    token = create_token!(context, "read")
    context
    |> delete_session_conn()
    |> put_req_header("authorization", "Bearer #{token.value}")
    |> assert_rejected(context, 403)
  end

  test "a session cannot bypass an invalid token", context do
    context
    |> delete_session_conn()
    |> put_req_header("authorization", "Bearer invalid-token")
    |> assert_rejected(context, 401)
  end

  test "a session cannot turn an app-only token into a user token", context do
    token = create_token!(%{context | user: nil}, "write:statuses")
    context
    |> delete_session_conn()
    |> put_req_header("authorization", "Bearer #{token.value}")
    |> assert_rejected(context, 401)
  end

  test "write scope does not permit deleting another user's status", context do
    other_user = Fake.fake_user!()
    token = create_token!(%{context | user: other_user}, "write:statuses")
    token |> token_conn() |> assert_rejected(context, 404)
  end

  test "preserves session-only deletion", context do
    response = context |> delete_session_conn() |> delete_status(context.post) |> json_response(200)
    assert response["id"] == context.post.id
    assert {:error, _} = Posts.read(context.post.id, current_user: context.user)
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
  end

  defp token_conn(token) do
    api_conn()
    |> put_req_header("authorization", "Bearer #{token.value}")
  end

  defp delete_session_conn(%{account: account, user: user}) do
    api_conn()
    |> Plug.Test.init_test_session(%{})
    |> put_session(:current_account_id, account.id)
    |> put_session(:current_user_id, user.id)
  end

  defp delete_status(conn, post), do: delete(conn, "/api/v1/statuses/#{post.id}")

  defp assert_rejected(conn, context, status) do
    conn = delete_status(conn, context.post)
    assert {conn.status, Posts.count_for_user(context.user)} == {status, 1}
    assert json_response(conn, status)["error"]
    assert {:ok, post} = Posts.read(context.post.id, current_user: context.user)
    assert post.id == context.post.id
  end
end
