defmodule Bonfire.OpenID.Test.OAuthWalk do
  @moduledoc "Walks authorize, consent and token exchange the way a client app does."
  import ExUnit.Assertions
  import Phoenix.ConnTest
  import Phoenix.LiveViewTest

  @endpoint Application.compile_env!(:bonfire, :endpoint_module)

  def authorization_path(protocol, params),
    do: "/#{protocol}/authorize?" <> Plug.Conn.Query.encode(params)

  @doc "Clicks Allow on the consent screen and returns the callback URL the client is sent to."
  def approve(conn, path) do
    {:ok, view, _} = live(conn, path)

    assert {:error, {:live_redirect, %{to: next}}} =
             view |> element("[data-role=oauth_consent_allow]") |> render_click()

    conn |> get(next) |> redirected_to()
  end

  def callback_code(callback) do
    params = callback |> URI.parse() |> Map.get(:query) |> Kernel.||("") |> URI.decode_query()
    refute Map.has_key?(params, "error")
    assert is_binary(params["code"])
    params["code"]
  end

  @doc "Exchanges a code for a token, sending the body as `:form` or `:json` like the client does."
  def exchange(protocol, params, encoding \\ :form) do
    build_conn() |> post_encoded("/#{protocol}/token", params, encoding) |> json_response(200)
  end

  def post_encoded(conn, path, params, :json),
    do:
      conn
      |> Plug.Conn.put_req_header("content-type", "application/json")
      |> post(path, Jason.encode!(params))

  def post_encoded(conn, path, params, :form),
    do:
      conn
      |> Plug.Conn.put_req_header("content-type", "application/x-www-form-urlencoded")
      |> post(path, URI.encode_query(params))
end
