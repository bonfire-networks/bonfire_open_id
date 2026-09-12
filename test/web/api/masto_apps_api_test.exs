defmodule Bonfire.OpenID.Web.MastoAppsApiTest do
  use Bonfire.OpenID.ConnCase, async: false

  alias Bonfire.OpenID.Provider.ClientApps

  @moduletag :masto_api
  @moduletag capture_log: true

  setup do
    params = %{
      "client_name" => "Registration test #{Faker.UUID.v4()}",
      "redirect_uris" => "https://client.example/callback",
      "website" => "https://client.example"
    }

    {:ok, params: params}
  end

  test "anonymous registrations with identical metadata receive distinct credentials", %{
    params: params
  } do
    first = register_app(params)
    second = register_app(params)

    refute first["client_id"] == second["client_id"]
    refute first["client_secret"] == second["client_secret"]
    assert first["client_secret"] != ""
    assert second["client_secret"] != ""
    assert ClientApps.get_by_id(first["client_id"])
    assert ClientApps.get_by_id(second["client_id"])
  end

  test "a registration with the same name preserves each application's callback", %{params: params} do
    first = register_app(params)
    other_callback = "https://other-client.example/callback"

    second = register_app(Map.put(params, "redirect_uris", other_callback))

    refute first["client_id"] == second["client_id"]
    refute first["client_secret"] == second["client_secret"]
    assert first["redirect_uri"] == params["redirect_uris"]
    assert second["redirect_uri"] == other_callback
    assert ClientApps.get_by_id(first["client_id"]).redirect_uris == [params["redirect_uris"]]
    assert ClientApps.get_by_id(second["client_id"]).redirect_uris == [other_callback]
  end

  test "public registration cannot retrieve an internally registered client's credentials", %{
    params: params
  } do
    name = "#{params["client_name"]} #{params["website"]}"
    {:ok, internal_client} = ClientApps.get_or_new(name, params["redirect_uris"])

    registered = register_app(params)

    refute registered["client_id"] == internal_client.id
    refute registered["client_secret"] == internal_client.secret
    assert ClientApps.get_by_id(internal_client.id).secret == internal_client.secret
    assert ClientApps.get_by_id(internal_client.id).redirect_uris == [params["redirect_uris"]]
  end

  test "internal named-client registration still reuses its existing client", %{params: params} do
    {:ok, first} = ClientApps.get_or_new(params["client_name"], params["redirect_uris"])

    {:ok, second} = ClientApps.get_or_new(params["client_name"], params["redirect_uris"])

    assert second.id == first.id
    assert second.secret == first.secret
  end

  defp register_app(params) do
    Phoenix.ConnTest.build_conn()
    |> put_req_header("accept", "application/json")
    |> put_req_header("content-type", "application/json")
    |> post("/api/v1/apps", Jason.encode!(params))
    |> json_response(200)
  end
end
