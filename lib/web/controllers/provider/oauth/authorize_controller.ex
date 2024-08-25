defmodule Bonfire.OpenID.Web.Oauth.AuthorizeController do
  @behaviour Boruta.Oauth.AuthorizeApplication

  use Bonfire.UI.Common.Web, :controller

  alias Boruta.Oauth.AuthorizeResponse
  alias Boruta.Oauth.Error
  alias Boruta.Oauth.ResourceOwner
  alias Bonfire.OpenID.Web.OauthView

  def oauth_module,
    do: Application.get_env(:bonfire_open_id, :oauth_module, Boruta.Oauth)

  def authorize(%Plug.Conn{} = conn, _params) do
    agent = current_user(conn) || current_account(conn)
    conn = store_go(conn)

    authorize_response(
      conn,
      agent
    )
  end

  def from_query_string(conn, query) do
    query_params =
      Plug.Conn.Query.decode(query)
      |> debug()

    authorize(%{conn | query_params: query_params}, query_params)
  end

  defp authorize_response(conn, %_{} = agent) do
    %ResourceOwner{
      sub: to_string(agent.id),
      username: e(agent, :character, :username, nil) || e(agent, :email, :email_address, nil)
    }
    # |> debug()
    |> oauth_module().authorize(
      conn,
      ...,
      __MODULE__
    )
    |> debug()
  end

  defp authorize_response(conn, other) do
    warn(other, "no agent in conn")
    redirect_to_login(conn)
  end

  @impl Boruta.Oauth.AuthorizeApplication
  def authorize_success(
        conn,
        %AuthorizeResponse{} = response
      ) do
    conn
    # |> Plug.Conn.put_status(303) # to support redirect after a POST
    |> redirect_to(
      AuthorizeResponse.redirect_to_url(response)
      |> debug(),
      type: :maybe_external
    )
  end

  @impl Boruta.Oauth.AuthorizeApplication
  def authorize_error(
        conn,
        %Error{status: :unauthorized, error: :invalid_client} = error
      ) do
    authorize_error(
      conn,
      %{error | status: :bad_request}
    )
  end

  def authorize_error(
        %Plug.Conn{} = conn,
        %Error{status: :unauthorized} = error
      ) do
    error(error)
    redirect_to_login(conn)
  end

  def authorize_error(
        conn,
        %Error{format: format} = error
      )
      when not is_nil(format) do
    error(error)

    redirect_to(
      conn,
      Error.redirect_to_url(error),
      type: :maybe_external
    )
  end

  def authorize_error(
        conn,
        %Error{
          status: status,
          error: error_detail,
          error_description: error_description
        } = error
      ) do
    error(error)

    conn
    |> put_status(status)
    |> put_view(OauthView)
    |> render("error.html", error: error_detail, error_description: error_description)
  end

  @impl Boruta.Oauth.AuthorizeApplication
  def preauthorize_success(_conn, _response), do: :ok

  @impl Boruta.Oauth.AuthorizeApplication
  def preauthorize_error(_conn, _response), do: :ok

  defp store_go(conn) do
    put_session(
      conn,
      :go,
      current_path(conn)
    )
  end

  defdelegate redirect_to_login(conn),
    to: Bonfire.OpenID.Web.Openid.AuthorizeController
end
