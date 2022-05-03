defmodule Bonfire.OpenID.Web.Oauth.AuthorizeController do
  @behaviour Boruta.Oauth.AuthorizeApplication

  use Bonfire.Web, :controller

  alias Boruta.Oauth.AuthorizeResponse
  alias Boruta.Oauth.Error
  alias Boruta.Oauth.ResourceOwner
  alias Bonfire.OpenID.Web.OauthView

  def oauth_module, do: Application.get_env(:bonfire_open_id, :oauth_module, Boruta.Oauth)

  def authorize(%Plug.Conn{} = conn, _params) do
    current_user = conn.assigns[:current_user]
    conn = store_go(conn)

    authorize_response(
      conn,
      current_user
    )
  end

  defp authorize_response(conn, %_{} = current_user) do
    conn
    |> oauth_module().authorize(
      %ResourceOwner{sub: to_string(current_user.id), username: current_user.character.username},
      __MODULE__
    )
  end

  defp authorize_response(conn, _params) do
    redirect_to_login(conn)
  end

  @impl Boruta.Oauth.AuthorizeApplication
  def authorize_success(
        conn,
        %AuthorizeResponse{} = response
      ) do
    redirect(conn, external: AuthorizeResponse.redirect_to_url(response))
  end

  @impl Boruta.Oauth.AuthorizeApplication
  def authorize_error(
        %Plug.Conn{} = conn,
        %Error{status: :unauthorized}
      ) do
    redirect_to_login(conn)
  end

  def authorize_error(
        conn,
        %Error{format: format} = error
      )
      when not is_nil(format) do
    conn
    |> redirect(external: Error.redirect_to_url(error))
  end

  def authorize_error(
        conn,
        %Error{status: status, error: error, error_description: error_description}
      ) do
    conn
    |> put_status(status)
    |> put_view(OauthView)
    |> render("error.html", error: error, error_description: error_description)
  end

  @impl Boruta.Oauth.AuthorizeApplication
  def preauthorize_success(_conn, _response), do: :ok

  @impl Boruta.Oauth.AuthorizeApplication
  def preauthorize_error(_conn, _response), do: :ok

  defp store_go(conn) do
    conn
    |> put_session(
      :go,
      current_path(conn)
    )
  end

  defdelegate redirect_to_login(conn), to: Bonfire.OpenID.Web.Openid.AuthorizeController

end
