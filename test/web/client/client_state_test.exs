defmodule Bonfire.OpenID.Web.ClientStateTest do
  # Signing in through an outside service must only accept the answer to a sign-in this browser started. Otherwise anyone can send a victim a callback link carrying the attacker's own code, and the victim ends up signed in as the attacker.
  use Bonfire.OpenID.ConnCase, async: false
  use Repatch.ExUnit

  @moduletag capture_log: true

  setup do
    Process.put([:bonfire_open_id, :openid_connect_providers],
      orcid: %{
        discovery_document_uri: "https://orcid.org/.well-known/openid-configuration",
        client_id: "id",
        client_secret: "secret",
        scope: "openid",
        display_name: "ORCID"
      }
    )

    Process.put([:bonfire_open_id, :oauth2_providers],
      forge: %{
        client_id: "id",
        client_secret: "secret",
        authorize_uri: "https://forge.example.local/authorize",
        access_token_uri: "https://forge.example.local/token",
        scope: "user"
      }
    )

    Repatch.patch(OpenIDConnect, :authorization_uri, fn _provider, _redirect_uri, params ->
      {:ok, "https://orcid.org/authorize?" <> URI.encode_query(params)}
    end)

    test_pid = self()

    Repatch.patch(OpenIDConnect, :fetch_tokens, fn _provider, _params ->
      send(test_pid, :code_exchanged)
      {:ok, %{"id_token" => "token", "access_token" => "access"}}
    end)

    Repatch.patch(OpenIDConnect, :verify, fn _provider, _token ->
      {:ok, %{"iss" => "https://orcid.org", "sub" => "0000-0002-1825-0097", "name" => "A Person"}}
    end)

    :ok
  end

  # start the sign-in as a browser does, and return the conn that holds its session along with the state the service was sent
  defp start(conn, path) do
    conn = get(conn, path)
    assert [location] = Plug.Conn.get_resp_header(conn, "location")

    state =
      location |> URI.parse() |> Map.fetch!(:query) |> URI.decode_query() |> Map.fetch!("state")

    assert is_binary(state) and state != ""
    {recycle(conn), state}
  end

  # whether a code was sent to the service since the last check
  defp exchanged? do
    receive do
      :code_exchanged ->
        flush_exchanges()
        true
    after
      0 -> false
    end
  end

  defp flush_exchanges do
    receive do
      :code_exchanged -> flush_exchanges()
    after
      0 -> :ok
    end
  end

  describe "OpenID Connect" do
    test "the answer to a sign-in this browser started goes through" do
      {conn, state} = start(conn(), "/openid/client/orcid")

      conn = get(conn, "/openid/client/orcid?code=c&state=#{state}")

      assert exchanged?()
      refute redirected_to_login?(conn)
    end

    test "an answer with no state is refused, and no code is exchanged" do
      {conn, _state} = start(conn(), "/openid/client/orcid")

      conn = get(conn, "/openid/client/orcid?code=c")

      assert redirected_to(conn) == "/login"
      refute exchanged?()
    end

    test "an answer with a state this browser never sent is refused" do
      {conn, _state} = start(conn(), "/openid/client/orcid")

      conn = get(conn, "/openid/client/orcid?code=c&state=made-up")

      assert redirected_to(conn) == "/login"
      refute exchanged?()
    end

    test "an answer to a sign-in nobody started in this browser is refused" do
      conn = conn() |> get("/openid/client/orcid?code=c&state=s")

      assert redirected_to(conn) == "/login"
      refute exchanged?()
    end

    test "the same answer cannot be played twice" do
      {conn, state} = start(conn(), "/openid/client/orcid")

      first = get(conn, "/openid/client/orcid?code=c&state=#{state}")
      assert exchanged?()

      second = first |> recycle() |> get("/openid/client/orcid?code=c&state=#{state}")

      assert redirected_to(second) == "/login"
      refute exchanged?()
    end

    test "starting again replaces the earlier state" do
      {conn, first_state} = start(conn(), "/openid/client/orcid")
      {conn, second_state} = start(conn, "/openid/client/orcid")

      assert redirected_to(get(conn, "/openid/client/orcid?code=c&state=#{first_state}")) ==
               "/login"

      refute exchanged?()
      assert second_state != first_state
    end

    test "a service that answers with an error is still shown that error" do
      assert_raise Bonfire.Fail, ~r/access_denied/, fn ->
        conn() |> get("/openid/client/orcid?error=access_denied")
      end

      refute exchanged?()
    end
  end

  describe "OAuth2" do
    test "an answer with the wrong state is refused before the code is sent anywhere" do
      {conn, _state} = start(conn(), "/oauth/client/forge")

      conn = get(conn, "/oauth/client/forge?code=c&state=made-up")

      assert redirected_to(conn) == "/login"
    end

    test "an answer with no state is refused" do
      {conn, _state} = start(conn(), "/oauth/client/forge")

      conn = get(conn, "/oauth/client/forge?code=c")

      assert redirected_to(conn) == "/login"
    end

    test "a state is kept per provider" do
      {conn, orcid_state} = start(conn(), "/openid/client/orcid")
      {conn, _forge_state} = start(conn, "/oauth/client/forge")

      # the other provider's start did not erase this one
      get(conn, "/openid/client/orcid?code=c&state=#{orcid_state}")
      assert exchanged?()
    end
  end

  defp redirected_to_login?(conn),
    do: conn.status in 300..399 and Plug.Conn.get_resp_header(conn, "location") == ["/login"]
end
