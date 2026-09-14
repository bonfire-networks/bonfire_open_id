defmodule Bonfire.OpenID.Web.MastoAvatarVisibilityApiTest do
  use Bonfire.OpenID.ConnCase, async: false

  alias Bonfire.Me.Fake

  @moduletag :masto_api
  @moduletag capture_log: true

  setup do
    {:ok, client} =
      Bonfire.OpenID.Provider.ClientApps.new(%{
        name: "Avatar visibility #{Faker.UUID.v4()}",
        redirect_uris: ["https://client.example/callback"]
      })

    actors =
      Map.new([:author, :reader, :outsider], fn role ->
        user = Fake.fake_user!()

        {:ok, token} =
          Boruta.Ecto.AccessTokens.create(
            %{
              client: Boruta.Ecto.OauthMapper.to_oauth_schema(client),
              sub: user.id,
              scope: "read write follow"
            },
            []
          )

        {role, %{user: user, token: token.value}}
      end)

    {:ok, actors}
  end

  test "status accounts preserve uploaded avatars", %{author: author, reader: reader} do
    Bonfire.Files.Simulation.fake_user_with_avatar!(author.user)

    account =
      author |> api_conn() |> get("/api/v1/accounts/verify_credentials") |> json_response(200)

    refute account["avatar"] =~ "/images/avatar.png"
    status = publish(author, "public")

    response =
      reader |> api_conn() |> get("/api/v1/statuses/#{status["id"]}") |> json_response(200)

    assert response["account"]["avatar"] == account["avatar"]
    assert response["account"]["avatar_static"] == account["avatar_static"]
  end

  test "unlisted keeps its visibility and is readable by an outsider", %{
    author: author,
    outsider: outsider
  } do
    status = publish(author, "unlisted")

    response =
      outsider |> api_conn() |> get("/api/v1/statuses/#{status["id"]}") |> json_response(200)

    assert status["visibility"] == "unlisted"
    assert response["visibility"] == "unlisted"
  end

  test "private admits followers and excludes outsiders", %{
    author: author,
    reader: reader,
    outsider: outsider
  } do
    reader
    |> api_conn()
    |> post("/api/v1/accounts/#{author.user.id}/follow", %{})
    |> json_response(200)

    status = publish(author, "private")

    response =
      reader |> api_conn() |> get("/api/v1/statuses/#{status["id"]}") |> json_response(200)

    assert status["visibility"] == "private"
    assert response["visibility"] == "private"
    outsider |> api_conn() |> get("/api/v1/statuses/#{status["id"]}") |> response(404)
  end

  defp publish(actor, visibility) do
    actor
    |> api_conn()
    |> post("/api/v1/statuses", %{status: "Visibility #{Faker.UUID.v4()}", visibility: visibility})
    |> json_response(200)
  end

  defp api_conn(actor) do
    Phoenix.ConnTest.build_conn()
    |> put_req_header("accept", "application/json")
    |> put_req_header("authorization", "Bearer #{actor.token}")
  end
end
