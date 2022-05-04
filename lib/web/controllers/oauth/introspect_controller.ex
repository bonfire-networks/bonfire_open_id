defmodule Bonfire.OpenID.Web.Oauth.IntrospectController do
  @behaviour Boruta.Oauth.IntrospectApplication

  use Bonfire.UI.Common.Web, :controller

  alias Boruta.Oauth.Error
  alias Boruta.Oauth.IntrospectResponse
  alias Bonfire.OpenID.Web.OauthView

  def oauth_module, do: Application.get_env(:bonfire_open_id, :oauth_module, Boruta.Oauth)

  def introspect(%Plug.Conn{} = conn, _params) do
    conn |> oauth_module().introspect(__MODULE__)
  end

  @impl Boruta.Oauth.IntrospectApplication
  def introspect_success(conn, %IntrospectResponse{} = response) do
    conn
    |> put_view(OauthView)
    |> render("introspect.json", response: response)
  end

  @impl Boruta.Oauth.IntrospectApplication
  def introspect_error(conn, %Error{
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
