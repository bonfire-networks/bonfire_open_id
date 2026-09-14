defmodule Bonfire.OpenID.ConsentSideEffectsReviewTest do
  use Bonfire.OpenID.ConnCase, async: false
  import PhoenixTest
  alias Bonfire.OpenID.Provider.ClientApps
  alias Bonfire.UI.Common.Testing.Helpers
  @moduletag capture_log: true

  setup tags do
    previous = Application.get_env(:bonfire_open_id, :oauth_module)
    Application.put_env(:bonfire_open_id, :oauth_module, Boruta.Oauth)
    on_exit(fn -> Application.put_env(:bonfire_open_id, :oauth_module, previous) end)
    account = Helpers.fake_account!()
    user = Helpers.fake_user!(account)
    callback = "http://localhost:4000/oauth/client/side-review" <> (tags[:callback_query] || "")

    client =
      ClientApps.init_test_client_app(Faker.UUID.v4(), %{
        name: "Consent side review",
        redirect_uris: [callback],
        supported_scopes: ["read", "write", "openid", "profile"]
      })

    {:ok,
     conn: conn(user: user, account: account), user: user, client: client, callback: callback}
  end

  @tag callback_query: "?destination=inbox"
  test "denial preserves registered callback query parameters", c do
    {:ok, view, _} = live(c.conn, path(c, "oauth", %{}))

    assert {:error, {:redirect, %{to: to}}} =
             view |> element("[data-role=oauth_consent_deny]") |> render_click()

    query = to |> URI.parse() |> Map.fetch!(:query) |> URI.decode_query()
    assert query["destination"] == "inbox"
    assert query["error"] == "access_denied"
    assert query["state"] == "side-review"
  end

  test "implicit denial returns errors in the fragment", c do
    {:ok, view, _} = live(c.conn, path(c, "oauth", %{"response_type" => "token"}))

    assert {:error, {:redirect, %{to: to}}} =
             view |> element("[data-role=oauth_consent_deny]") |> render_click()

    uri = URI.parse(to)
    assert is_binary(uri.fragment)
    assert URI.decode_query(uri.fragment)["error"] == "access_denied"
  end

  test "signed-in prompt none without prior consent returns an error without UI", c do
    response = get(c.conn, path(c, "openid", %{"prompt" => "none"}))
    assert response.status == 302
    query = response |> redirected_to() |> URI.parse() |> Map.fetch!(:query) |> URI.decode_query()
    assert query["error"] == "consent_required"
  end

  test "prompt none with remembered consent issues a code without UI", c do
    Bonfire.OpenID.Web.Consent.remember_consent(c.user, c.client.id, "openid profile")

    response = get(c.conn, path(c, "openid", %{"prompt" => "none"}))

    returned =
      response |> redirected_to() |> URI.parse() |> Map.fetch!(:query) |> URI.decode_query()

    assert is_binary(returned["code"])
    assert returned["state"] == "side-review"
    refute Map.has_key?(returned, "error")
  end

  for signed_in? <- [true, false] do
    @signed_in? signed_in?
    test "prompt none rejects an unregistered callback when signed in is #{signed_in?}", c do
      conn = if @signed_in?, do: c.conn, else: conn()

      response =
        get(
          conn,
          path(c, "openid", %{
            "prompt" => "none",
            "redirect_uri" => "https://unregistered.example/callback"
          })
        )

      assert response.status == 401
      assert get_resp_header(response, "location") == []
      refute html_response(response, 401) =~ "data-role=\"oauth_consent\""
    end

    for mode <- ["query", "fragment"] do
      @mode mode
      @tag callback_query: "?destination=inbox"
      test "prompt none preserves callback and state in #{mode} when signed in is #{signed_in?}",
           c do
        conn = if @signed_in?, do: c.conn, else: conn()
        state = "silent & + / café"

        response =
          get(
            conn,
            path(c, "openid", %{
              "prompt" => "none",
              "response_mode" => @mode,
              "state" => state
            })
          )

        uri = response |> redirected_to() |> URI.parse()
        query = URI.decode_query(uri.query)
        returned = if @mode == "fragment", do: URI.decode_query(uri.fragment), else: query

        assert query["destination"] == "inbox"
        assert returned["state"] == state

        assert returned["error"] ==
                 if(@signed_in?, do: "consent_required", else: "login_required")

        refute Map.has_key?(returned, "code")
        refute Map.has_key?(returned, "access_token")
        refute Bonfire.OpenID.Web.Consent.consented?(c.user, c.client.id, "openid profile")
      end
    end
  end

  for {response_type, response_mode} <- [{"code", "fragment"}, {"token", "query"}] do
    @response_type response_type
    @response_mode response_mode
    @tag callback_query: "?destination=inbox&filter=a%26b"
    test "denial honors explicit #{response_mode} mode for #{response_type}", c do
      state = "denied & + / café"

      {:ok, view, _} =
        live(
          c.conn,
          path(c, "oauth", %{
            "response_type" => @response_type,
            "response_mode" => @response_mode,
            "state" => state
          })
        )

      assert {:error, {:redirect, %{to: to}}} =
               view |> element("[data-role=oauth_consent_deny]") |> render_click()

      uri = URI.parse(to)
      callback_query = URI.decode_query(uri.query)
      assert callback_query["destination"] == "inbox"
      assert callback_query["filter"] == "a&b"

      returned =
        if @response_mode == "fragment", do: URI.decode_query(uri.fragment), else: callback_query

      assert returned["error"] == "access_denied"
      assert returned["state"] == state
      refute Map.has_key?(returned, "code")
      refute Map.has_key?(returned, "access_token")

      if @response_mode == "fragment",
        do: refute(Map.has_key?(callback_query, "error")),
        else: assert(is_nil(uri.fragment))
    end
  end

  defp path(c, protocol, extra) do
    params =
      Map.merge(
        %{
          "client_id" => c.client.id,
          "redirect_uri" => c.callback,
          "scope" => if(protocol == "openid", do: "openid profile", else: "read"),
          "response_type" => "code",
          "state" => "side-review"
        },
        extra
      )

    "/#{protocol}/authorize?" <> URI.encode_query(params)
  end
end
