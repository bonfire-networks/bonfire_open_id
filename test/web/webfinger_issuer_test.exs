defmodule Bonfire.OpenID.Web.WebfingerIssuerTest do
  @moduledoc "An OpenID Connect client that knows only someone's handle finds the instance's sign-in service through WebFinger (OpenID Connect Discovery 1.0, section 2), when the instance runs one."
  # changes an environment variable, which every test reads
  use Bonfire.OpenID.ConnCase, async: false

  @issuer_rel "http://openid.net/specs/connect/1.0/issuer"

  setup do
    user = Bonfire.Me.Fake.fake_user!()
    host = URI.parse(Bonfire.Common.URIs.base_url()).host
    {:ok, resource: "acct:#{user.character.username}@#{host}"}
  end

  test "a user's WebFinger names the instance as their OpenID Connect issuer", %{
    resource: resource
  } do
    links = webfinger_links(resource)

    # the positive first: this is the user's WebFinger
    assert Enum.any?(links, &(&1["rel"] == "self"))

    issuer = get(build_conn(), "/.well-known/openid-configuration") |> json_response(200)
    assert [%{"href" => href}] = Enum.filter(links, &(&1["rel"] == @issuer_rel))
    assert href == issuer["issuer"]
  end

  test "with the sign-in service switched off, WebFinger names no issuer", %{resource: resource} do
    previous = System.get_env("ENABLE_SSO_PROVIDER")
    System.delete_env("ENABLE_SSO_PROVIDER")

    on_exit(fn ->
      if previous, do: System.put_env("ENABLE_SSO_PROVIDER", previous)
    end)

    links = webfinger_links(resource)

    # the positive first: the user's WebFinger still answers
    assert Enum.any?(links, &(&1["rel"] == "self"))
    refute Enum.any?(links, &(&1["rel"] == @issuer_rel))
    # and the discovery document the issuer would lead to isn't there either
    assert get(build_conn(), "/.well-known/openid-configuration").status == 404
  end

  defp webfinger_links(resource) do
    build_conn()
    |> put_req_header("accept", "application/json")
    |> get("/.well-known/webfinger?" <> URI.encode_query(%{"resource" => resource}))
    |> json_response(200)
    |> Map.fetch!("links")
  end
end
