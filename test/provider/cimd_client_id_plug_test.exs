defmodule Bonfire.OpenID.Provider.CIMDClientIDPlugTest do
  use ExUnit.Case, async: false
  use Repatch.ExUnit

  import Plug.Test

  alias Bonfire.OpenID.Plugs.ClientID
  alias Bonfire.OpenID.Provider.CIMD
  alias Bonfire.OpenID.Provider.ClientApps

  test "existing CIMD clients sync redirect_uris from the fetched metadata document" do
    parent = self()
    client_id = "https://app.example.com/client.jsonld"
    stale_redirect = "bonfire://old-callback"
    fresh_redirect = "bonfire://new-callback"
    stored_client = %{id: "stored-client-id", redirect_uris: [stale_redirect]}

    Repatch.patch(CIMD, :fetch, fn ^client_id ->
      {:ok,
       %{
         redirect_uris: [fresh_redirect],
         name: "Example app",
         grant_types: ["authorization_code"],
         scope: "read write"
       }}
    end)

    Repatch.patch(ClientApps, :get_or_new, fn ^client_id, ^fresh_redirect, attrs ->
      send(parent, {:get_or_new, attrs})
      {:ok, stored_client}
    end)

    Repatch.patch(ClientApps, :update_redirect_uris, fn ^stored_client, redirects ->
      send(parent, {:synced_redirects, redirects})
      {:ok, %{stored_client | redirect_uris: redirects}}
    end)

    path =
      "/oauth/authorize?client_id=#{URI.encode_www_form(client_id)}&redirect_uri=#{URI.encode_www_form(fresh_redirect)}"

    conn =
      :get
      |> conn(path)
      |> Plug.Conn.fetch_query_params()
      |> ClientID.validate_client_id([])

    refute conn.halted
    assert conn.params["client_id"] == stored_client.id
    assert conn.query_params["client_id"] == stored_client.id
    assert_receive {:get_or_new, %{redirect_uris: [^fresh_redirect]}}
    assert_receive {:synced_redirects, [^fresh_redirect]}
  end
end
