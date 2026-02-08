defmodule Bonfire.OpenID.Web.Oauth.AuthorizeController do
  @behaviour Boruta.Oauth.AuthorizeApplication

  use Bonfire.UI.Common.Web, :controller

  alias Boruta.Oauth.AuthorizeResponse
  alias Boruta.Oauth.Error
  alias Boruta.Oauth.ResourceOwner
  alias Bonfire.OpenID.Web.OauthView

  def oauth_module,
    do: Application.get_env(:bonfire_open_id, :oauth_module, Boruta.Oauth)

  def authorize(%Plug.Conn{} = conn, params) do
    current_account = current_account(conn)
    current_user = current_user(conn) || current_account
    conn = store_user_return_to(conn)

    login_hint = params["login_hint"]

    if current_user && !login_hint_matches?(current_user, login_hint) do
      flood(
        login_hint,
        "login_hint doesn't match the current session user, redirecting to pick profile"
      )

      # if login_hint do 
      # Users.by_account!(current_account, exclude_user_id: Enums.id(current_user))
      # TODO iteration on user profiles and try to find a match with login_hint before redirecting to pick profile
      # else
      redirect_to_pick_profile(conn)
      # end
    else
      authorize_response(
        conn,
        current_user
      )
    end
  end

  defp login_hint_matches?(_current_user, nil), do: true
  defp login_hint_matches?(_current_user, ""), do: true

  defp login_hint_matches?(current_user, login_hint) when is_binary(login_hint) do
    case Bonfire.Me.Characters.display_username(current_user, true, true) do
      "@" <> current_username -> current_username == login_hint
      "@" <> _ = current_username -> current_username == login_hint
      "@" <> _ = current_username -> current_username == "@" <> login_hint
      current_username when is_binary(current_username) -> current_username == login_hint
      _ -> false
    end
  end

  defp login_hint_matches?(_current_user, _), do: true

  @doc "Callback called by Bonfire.UI.Common.redirect_to_previous_go when redirect back to /oauth/authorize after login. This extracts the query string and calls authorize/2 directly instead of redirecting back to this controller."
  def from_query_string(conn, query) do
    query_params =
      query
      |> flood("from_query_string query")
      |> Plug.Conn.Query.decode()
      |> flood("from_query_string decoded")
      |> Bonfire.OpenID.Provider.ClientApps.maybe_transform_client_id()
      |> flood("query_params from_query_string")

    authorize(%{conn | query_params: query_params, params: query_params}, query_params)
  end

  defp authorize_response(conn, %_{} = current_user) do
    with {:ok, %ResourceOwner{} = resource_owner} <- Bonfire.OpenID.get_user(current_user) do
      conn
      |> oauth_module().authorize(
        resource_owner,
        __MODULE__
      )
    else
      e ->
        err(e, "Could not build resource owner from current_user")
    end
  end

  defp authorize_response(conn, _params) do
    redirect_to_login(conn)
  end

  @impl Boruta.Oauth.AuthorizeApplication
  def authorize_success(
        conn,
        %AuthorizeResponse{} = response
      ) do
    conn
    # |> Plug.Conn.put_status(303) # TODO? to support redirect after a POST
    |> redirect_to(
      AuthorizeResponse.redirect_to_url(response)
      |> flood("authorize_success redirect url"),
      type: :maybe_external
    )
  end

  @impl Boruta.Oauth.AuthorizeApplication
  def authorize_error(
        conn,
        %Error{status: :unauthorized, error: :invalid_client} = error
      ) do
    error(error, "Invalid client error")

    authorize_error(
      conn,
      %{error | status: :bad_request}
    )
  end

  def authorize_error(
        %Plug.Conn{} = conn,
        %Error{status: :unauthorized} = error
      ) do
    warn(error, "Redirecting to login for unauthorized error")
    redirect_to_login(conn)
  end

  def authorize_error(
        conn,
        %Error{format: format} = error
      )
      when not is_nil(format) do
    error(error, "Redirecting to error")

    conn
    |> redirect_to(
      Error.redirect_to_url(error),
      type: :maybe_external
    )
  end

  def authorize_error(
        conn,
        %Error{
          status: status,
          error: :invalid_client = error,
          error_description: error_description
        }
      ) do
    error(conn.query_params, inspect(error))

    conn
    |> put_status(status)
    |> put_view(OauthView)
    |> render("error.html", error: error, error_description: error_description)
  end

  def authorize_error(
        conn,
        %Error{status: status, error: error, error_description: error_description}
      ) do
    error(error, inspect(error_description))

    conn
    |> put_status(status)
    |> put_view(OauthView)
    |> render("error.html", error: error, error_description: error_description)
  end

  @impl Boruta.Oauth.AuthorizeApplication
  def preauthorize_success(_conn, _response), do: :ok

  @impl Boruta.Oauth.AuthorizeApplication
  def preauthorize_error(_conn, _response), do: :ok

  defp store_user_return_to(conn, url \\ nil) do
    conn
    |> put_session(
      :go,
      url || current_path(conn, conn.query_params)
    )
  end

  def redirect_to_pick_profile(conn, go_after_url \\ nil) do
    # where to redirect in order for the user to login
    # NOTE: after successfully logged in, it should redirect to `get_session(conn, :go)`
    redirect_to(
      conn,
      "#{Bonfire.Common.URIs.path(:switch_user)}?context=openid&#{URI.encode_query(%{"go" => go_after_url || current_path(conn, conn.query_params)})}"
    )
  end

  defdelegate redirect_to_login(conn, go_after_url \\ nil),
    to: Bonfire.OpenID.Web.Openid.AuthorizeController
end
