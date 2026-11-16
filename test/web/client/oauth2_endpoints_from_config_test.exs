defmodule Bonfire.OpenID.Web.OAuth2EndpointsFromConfigTest do
  @moduledoc """
  The token and userinfo endpoints an OAuth2 sign-in calls are the ones the admin configured for the provider, and nothing in the answer coming back to the browser can change them. This matters because those two calls skip the private-address check (a provider may be on the admin's own network), so an address chosen by someone else would be an open door.

  Requests go through the HTTP client's test adapter, which hands each URL to this test instead of sending it.
  """
  use Bonfire.OpenID.ConnCase, async: false

  @moduletag capture_log: true

  @provider "https://provider.local"
  @elsewhere "https://elsewhere.local"

  setup do
    test_pid = self()

    Tesla.Mock.mock_global(fn %{url: url} ->
      send(test_pid, {:called, url})
      Tesla.Mock.json(%{"access_token" => "t", "sub" => "1"})
    end)

    Process.put([:bonfire_open_id, :oauth2_providers],
      canary: [
        display_name: "Canary",
        client_id: "id",
        client_secret: "secret",
        authorize_uri: @provider <> "/authorize",
        access_token_uri: @provider <> "/token",
        userinfo_uri: @provider <> "/userinfo",
        enable_signup: false
      ]
    )

    :ok
  end

  defp called_urls(acc \\ []) do
    receive do
      {:called, url} -> called_urls([url | acc])
    after
      200 -> Enum.reverse(acc)
    end
  end

  test "the sign-in calls the configured endpoints, and none named in the answer" do
    conn = get(conn(), "/oauth/client/canary")
    assert [location] = Plug.Conn.get_resp_header(conn, "location")
    %{"state" => state} = location |> URI.parse() |> Map.fetch!(:query) |> URI.decode_query()

    query =
      URI.encode_query(%{
        "code" => "c",
        "state" => state,
        "access_token_uri" => @elsewhere <> "/token",
        "token_endpoint" => @elsewhere <> "/token",
        "userinfo_uri" => @elsewhere <> "/userinfo",
        "userinfo_endpoint" => @elsewhere <> "/userinfo"
      })

    # what the sign-in ends in is not the point (the stand-in provider knows no people), only whom it called
    try do
      get(recycle(conn), "/oauth/client/canary?" <> query)
    rescue
      Bonfire.Fail -> :ok
    end

    urls = called_urls()

    # control: the configured token endpoint was called, so the flow got as far as it can
    assert (@provider <> "/token") in urls
    refute Enum.any?(urls, &String.starts_with?(&1, @elsewhere))
  end
end
