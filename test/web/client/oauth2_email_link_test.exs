defmodule Bonfire.OpenID.Web.OAuth2EmailLinkTest do
  @moduledoc """
  An OAuth2 service (no `email_verified` claim, unlike OpenID Connect) only reaches an existing local account by email when the admin listed it as trusted (`:trusted_oauth2_email_providers`, set by `OAUTH2_TRUSTED_EMAIL_PROVIDERS`). The default is no provider: any other one is treated like a service that shared no email, so anyone who can set an arbitrary email there can't sign in as its owner.
  """
  use Bonfire.OpenID.ConnCase, async: false
  use Repatch.ExUnit
  import Tesla.Mock

  @moduletag capture_log: true

  setup do
    Process.put([:bonfire_open_id, :oauth2_providers],
      shiny: [
        display_name: "Shiny",
        client_id: "id",
        client_secret: "secret",
        authorize_uri: "https://sso.example.local/authorize",
        access_token_uri: "https://sso.example.local/token",
        userinfo_uri: "https://sso.example.local/userinfo",
        scope: "profile",
        enable_signup: true
      ]
    )

    account = Bonfire.Me.Fake.fake_account!()
    {:ok, account: account}
  end

  # the browser starts the sign-in, the (mocked) service answers with `userinfo`, and the browser comes back
  defp come_back(userinfo) do
    mock(fn
      %{method: :post, url: "https://sso.example.local/token"} ->
        json(%{"access_token" => "access"})

      %{method: :get, url: "https://sso.example.local/userinfo"} ->
        json(userinfo)
    end)

    conn = get(conn(), "/openid/client/shiny")
    assert [location] = Plug.Conn.get_resp_header(conn, "location")

    state =
      location |> URI.parse() |> Map.fetch!(:query) |> URI.decode_query() |> Map.fetch!("state")

    get(recycle(conn), "/openid/client/shiny?code=c&state=#{state}")
  end

  defp signed_in_as?(conn, account), do: get_session(conn, :current_account_id) == account.id

  test "a provider not on the trusted list does not sign in the account with a matching email", %{
    account: account
  } do
    # control: the list is empty by default
    assert Bonfire.OpenID.Client.trusted_oauth2_email_providers() == []

    conn = come_back(%{"id" => "123", "email" => account.email.email_address})

    refute signed_in_as?(conn, account)
  end

  test "a provider on the trusted list signs in the account with a matching email", %{
    account: account
  } do
    Process.put([:bonfire_open_id, :trusted_oauth2_email_providers], ["shiny"])

    conn = come_back(%{"id" => "123", "email" => account.email.email_address})

    assert signed_in_as?(conn, account)
  end
end
