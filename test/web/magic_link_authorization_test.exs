defmodule Bonfire.OpenID.Web.MagicLinkAuthorizationTest do
  use Bonfire.OpenID.ConnCase, async: false
  alias Bonfire.OpenID.Provider.ClientApps
  alias Bonfire.UI.Common.Testing.Helpers
  @moduletag capture_log: true

  setup tags do
    previous = Application.get_env(:bonfire_open_id, :oauth_module)
    Application.put_env(:bonfire_open_id, :oauth_module, Boruta.Oauth)
    on_exit(fn -> Application.put_env(:bonfire_open_id, :oauth_module, previous) end)
    Process.put([:bonfire_ui_me, :login, :passwordless_only], true)
    account = Helpers.fake_account!()
    user = Helpers.fake_user!(account)
    callback = "http://localhost:4000/oauth/client/magic-review" <> (tags[:callback_query] || "")

    client =
      ClientApps.init_test_client_app(Faker.UUID.v4(), %{
        name: "Magic link regression",
        redirect_uris: [callback],
        pkce: tags[:pkce] || false,
        supported_scopes: ["read", "write", "openid", "profile"]
      })

    {:ok, account: account, user: user, client: client, callback: callback}
  end

  for protocol <- ["oauth", "openid"] do
    @protocol protocol
    @tag pkce: true
    test "#{protocol}: magic-link Allow preserves PKCE, nonce and state through token exchange",
         c do
      verifier = String.duplicate("magic-link-proof-", 4)
      challenge = :crypto.hash(:sha256, verifier) |> Base.url_encode64(padding: false)

      params =
        params(c, @protocol)
        |> Map.merge(%{
          "code_challenge" => challenge,
          "code_challenge_method" => "S256",
          "nonce" => "nonce & + / café"
        })

      login = redeem(c, @protocol, params)
      assert login.status == 200
      {:ok, view, _} = live(login)

      assert {:error, {:live_redirect, %{to: next}}} =
               view |> element("[data-role=oauth_consent_allow]") |> render_click()

      assert URI.parse(next).path == "/#{@protocol}/authorize"
      assert URI.decode_query(URI.parse(next).query) == params
      callback = login |> recycle() |> get(next) |> redirected_to() |> URI.parse()
      returned = URI.decode_query(callback.query)
      assert returned["state"] == params["state"]
      assert is_binary(returned["code"])

      response =
        conn()
        |> post("/#{@protocol}/token", %{
          "grant_type" => "authorization_code",
          "client_id" => c.client.id,
          "client_secret" => c.client.secret,
          "code" => returned["code"],
          "redirect_uri" => c.callback,
          "code_verifier" => verifier
        })
        |> json_response(200)

      assert is_binary(response["access_token"])
    end

    @tag callback_query: "?destination=inbox"
    test "#{protocol}: magic-link Deny preserves callback query and state without granting consent",
         c do
      login = redeem(c, @protocol, params(c, @protocol))
      {:ok, view, _} = live(login)

      assert {:error, {:redirect, %{to: next}}} =
               view |> element("[data-role=oauth_consent_deny]") |> render_click()

      returned = next |> URI.parse() |> Map.fetch!(:query) |> URI.decode_query()
      assert returned["destination"] == "inbox"
      assert returned["error"] == "access_denied"
      assert returned["state"] == params(c, @protocol)["state"]
      refute Map.has_key?(returned, "code")

      refute Bonfire.OpenID.Web.Consent.consented?(
               c.user,
               c.client.id,
               params(c, @protocol)["scope"]
             )
    end
  end

  test "a consumed magic link cannot authenticate a new browser session", c do
    email =
      c.account.email |> Bonfire.Data.Identity.Email.put_token() |> Bonfire.Common.Repo.update!()

    go = "/oauth/authorize?" <> URI.encode_query(params(c, "oauth"))
    path = "/login/forgot-password/#{email.confirm_token}?go=#{URI.encode_www_form(go)}"
    first = get(conn(), path)
    assert first.status == 200
    assert html_response(first, 200) =~ "oauth_consent"
    second = get(conn(), path)
    assert html_response(second, 200) =~ "This sign-in link is invalid or has expired"
    refute html_response(second, 200) =~ "data-role=\"oauth_consent\""
    refute Bonfire.Common.Utils.current_user(second)
  end

  defp params(c, protocol) do
    %{
      "client_id" => c.client.id,
      "redirect_uri" => c.callback,
      "response_type" => "code",
      "state" => "state & + / café",
      "scope" => if(protocol == "openid", do: "openid profile", else: "read write")
    }
  end

  defp redeem(c, protocol, params) do
    email =
      c.account.email |> Bonfire.Data.Identity.Email.put_token() |> Bonfire.Common.Repo.update!()

    go = "/#{protocol}/authorize?" <> URI.encode_query(params)
    conn() |> get("/login/forgot-password/#{email.confirm_token}?go=#{URI.encode_www_form(go)}")
  end
end
