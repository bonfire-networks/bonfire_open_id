defmodule Bonfire.OpenID.Web.Oauth.ConsentTest do
  use Bonfire.OpenID.ConnCase, async: false
  import PhoenixTest

  alias Bonfire.OpenID.Provider.ClientApps

  @redirect_uri "http://localhost:4000/oauth/client/consent-test"

  alias Bonfire.UI.Common.Testing.Helpers

  setup do
    # the consent screen exercises the real boruta authorize flow, not the Mox used by
    # the controller-unit tests (configured in config/bonfire_open_id.exs)
    previous = Application.get_env(:bonfire_open_id, :oauth_module)
    Application.put_env(:bonfire_open_id, :oauth_module, Boruta.Oauth)
    on_exit(fn -> Application.put_env(:bonfire_open_id, :oauth_module, previous) end)

    account = Helpers.fake_account!()
    user = Helpers.fake_user!(account)

    client =
      ClientApps.init_test_client_app(Faker.UUID.v4(), %{
        name: "Consent Test App",
        redirect_uris: [@redirect_uri],
        supported_scopes: ["read", "write"]
      })

    {:ok, conn: conn(user: user, account: account), user: user, account: account, client: client}
  end

  defp authorize_path(client, opts \\ []) do
    scope = Keyword.get(opts, :scope, "read write")

    "/oauth/authorize?" <>
      URI.encode_query(%{
        "response_type" => "code",
        "client_id" => client.id,
        "redirect_uri" => @redirect_uri,
        "scope" => scope,
        "state" => "xyz"
      })
  end

  test "shows a consent screen with the client and requested scopes when not previously consented",
       %{conn: conn, client: client} do
    conn
    |> visit(authorize_path(client))
    |> wait_async()
    # |> PhoenixTest.open_browser()
    |> assert_has("[data-role=oauth_consent]")
    |> assert_has("[data-role=oauth_consent]", text: "Consent Test App")
    |> assert_has("[data-role=oauth_scope]", text: "read")
    |> assert_has("[data-role=oauth_scope]", text: "write")
    |> assert_has("[data-role=oauth_consent_allow]")
    |> assert_has("[data-role=oauth_consent_deny]")
  end

  test "Allow records consent, and the authorization code is then issued silently",
       %{conn: conn, client: client} do
    {:ok, view, _html} = live(conn, authorize_path(client))

    assert {:error, {:live_redirect, %{to: to}}} =
             view |> element("[data-role=oauth_consent_allow]") |> render_click()

    # approval re-invokes the OAuth authorize flow
    assert to =~ "/oauth/authorize"

    # consent is now remembered, so following back issues the code without prompting again
    resp = get(conn, to)
    location = redirected_to(resp)
    assert location =~ @redirect_uri
    assert location =~ "code="
    assert location =~ "state=xyz"
  end

  test "Deny redirects back to the client with access_denied", %{conn: conn, client: client} do
    {:ok, view, _html} = live(conn, authorize_path(client))

    assert {:error, {:redirect, %{to: external}}} =
             view |> element("[data-role=oauth_consent_deny]") |> render_click()

    assert external =~ @redirect_uri
    assert external =~ "error=access_denied"
    assert external =~ "state=xyz"
  end

  test "shows the switch-user picker when no profile is resolved, and picking one continues to consent",
       %{account: account, client: client} do
    # a second profile in the account makes the choice ambiguous
    _user2 = Helpers.fake_user!(account, %{name: "Second Profile"})
    # session has the account but no selected user
    account_conn = conn(account: account)

    account_conn
    |> visit(authorize_path(client))
    |> wait_async()
    # account-level session with no resolved profile → redirected to the switch-user picker
    |> assert_has(~s|a[href*="/switch-user/"]|)
    # picking a profile switches identity and loops back to the consent screen
    |> click_link(~s|a[href*="/switch-user/"]|, "Second Profile")
    |> wait_async()
    |> assert_has("[data-role=oauth_consent_allow]")
    |> assert_has("[data-role=oauth_consent_deny]")
  end
end
