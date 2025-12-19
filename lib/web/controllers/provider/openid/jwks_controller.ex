defmodule Bonfire.OpenID.Web.Openid.JwksController do
  @behaviour Boruta.Openid.JwksApplication

  use Bonfire.UI.Common.Web, :controller

  alias Bonfire.OpenID.Web.OpenidView

  def openid_module,
    do: Application.get_env(:bonfire_open_id, :openid_module, Boruta.Openid)

  def jwks_index(conn, _params) do
    openid_module().jwks(conn, __MODULE__)
  end

  @impl Boruta.Openid.JwksApplication
  def jwk_list(conn, jwk_keys) do
    conn
    |> put_view(OpenidView)
    |> render("jwks.json", jwk_keys: jwk_keys)
  end
end
