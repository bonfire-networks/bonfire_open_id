defmodule Bonfire.OpenID.Web.Oauth.RevokeController do
  @behaviour Boruta.Oauth.RevokeApplication

  use Bonfire.UI.Common.Web, :controller

  alias Boruta.Oauth.Error
  alias Bonfire.OpenID.Web.OauthView

  def oauth_module,
    do: Application.get_env(:bonfire_open_id, :oauth_module, Boruta.Oauth)

  def revoke(%Plug.Conn{} = conn, _params) do
    flood("oauth_revoke called")
    oauth_module().revoke(conn, __MODULE__)
  end

  @impl Boruta.Oauth.RevokeApplication
  def revoke_success(%Plug.Conn{} = conn) do
    flood("oauth_revoke succeeded")
    send_resp(conn, 200, "")
  end

  @impl Boruta.Oauth.RevokeApplication
  def revoke_error(conn, %Error{
        status: status,
        error: error,
        error_description: error_description
      }) do
    conn
    |> put_status(status)
    |> put_view(OauthView)
    |> render("error.json", error: error, error_description: error_description)
  end
end
