defmodule Bonfire.OpenID.Web.MastoPublishScopesApiTest do
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
        name: "Publish scopes #{Faker.UUID.v4()}",
        redirect_uris: ["https://client.example/callback"]
      })

    {:ok, account: account, user: user, client: client}
  end

  for scope <- ["read", "write:media", ""] do
    test "rejects #{inspect(scope)} without publishing", context do
      token = create_token!(context, unquote(scope))

      token
      |> token_conn()
      |> assert_rejected(context.user, 403)
    end
  end

  for scope <- ["write:statuses", "write"] do
    test "publishes with #{scope}", context do
      token = create_token!(context, unquote(scope))

      response = token |> token_conn() |> publish() |> json_response(200)

      assert response["id"]
      assert response["content"] =~ "Scope regression"
      assert Posts.count_for_user(context.user) == 1
    end
  end

  test "a session cannot bypass a read-only token", context do
    token = create_token!(context, "read")

    context
    |> publish_session_conn()
    |> put_req_header("authorization", "Bearer #{token.value}")
    |> assert_rejected(context.user, 403)
  end

  test "checks tokens supplied through access_token", context do
    token = create_token!(context, "read")

    api_conn()
    |> assert_rejected(context.user, 403, %{"access_token" => token.value})
  end

  test "rejects an invalid token without publishing", context do
    api_conn()
    |> put_req_header("authorization", "Bearer invalid-token")
    |> assert_rejected(context.user, 401)
  end

  test "a session cannot bypass an invalid token", context do
    context
    |> publish_session_conn()
    |> put_req_header("authorization", "Bearer invalid-token")
    |> assert_rejected(context.user, 401)
  end

  test "a session cannot turn an app-only token into a user token", context do
    token = create_token!(%{context | user: nil}, "write:statuses")

    context
    |> publish_session_conn()
    |> put_req_header("authorization", "Bearer #{token.value}")
    |> assert_rejected(context.user, 401)
  end

  test "preserves session-only publishing", context do
    response = context |> publish_session_conn() |> publish() |> json_response(200)

    assert response["id"]
    assert Posts.count_for_user(context.user) == 1
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

  defp publish_session_conn(%{account: account, user: user}) do
    api_conn()
    |> Plug.Test.init_test_session(%{})
    |> put_session(:current_account_id, account.id)
    |> put_session(:current_user_id, user.id)
  end

  defp publish(conn, params \\ %{}) do
    params = Map.put(params, "status", "Scope regression #{Faker.UUID.v4()}")
    post(conn, "/api/v1/statuses", Jason.encode!(params))
  end

  defp assert_rejected(conn, user, status, params \\ %{}) do
    count_before = Posts.count_for_user(user)

    conn = publish(conn, params)

    assert {conn.status, Posts.count_for_user(user)} == {status, count_before}
    assert json_response(conn, status)["error"]
  end
end
