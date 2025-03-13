defmodule Bonfire.OpenID.Web.Openid.AuthorizeController do
  @behaviour Boruta.Oauth.AuthorizeApplication
  use Bonfire.UI.Common.Web, :controller

  alias Boruta.Oauth.AuthorizeResponse
  alias Boruta.Oauth.Error
  alias Boruta.Oauth.ResourceOwner
  alias Bonfire.OpenID.Web.OauthView

  def oauth_module,
    do: Application.get_env(:bonfire_open_id, :oauth_module, Boruta.Oauth)

  def authorize(%Plug.Conn{} = conn, _params) do
    go_after_url = go_after_url(conn)

    conn =
      conn
      |> store_go(go_after_url)
      |> put_unsigned_request()

    resource_owner =
      get_resource_owner(conn)
      |> info("resource_owner")

    with {:unchanged, conn} <- prompt_redirection(conn),
         {:unchanged, conn} <- max_age_redirection(conn, resource_owner),
         {:unchanged, conn} <-
           login_redirection(conn, go_after_url) |> info("login_redirection?") do
      conn
      |> store_go(nil)
      |> info("go_stored")
      |> oauth_module().authorize(resource_owner, __MODULE__)
      |> info("authorized?")
    end
  end

  def from_query_string(conn, query) do
    query_params =
      Plug.Conn.Query.decode(query)
      |> Map.update("response_type", "code id_token token", fn existing_value ->
        # FIXME: temp workaround for this error: Invalid response_type param, may be on of `code` for Authorization Code request, `code id_token`, `code token`, `code id_token token` for Hybrid requests, or `token`, `id_token token` for Implicit requests
        case existing_value do
          "authorization_code" -> "code"
          "implicit" -> "id_token token"
          _ -> "code id_token token"
        end
      end)
      |> info()

    authorize(%{conn | query_params: query_params}, query_params)
  end

  @impl Boruta.Oauth.AuthorizeApplication
  def authorize_success(
        conn,
        %AuthorizeResponse{} = response
      ) do
    redirect_to(conn, AuthorizeResponse.redirect_to_url(response), type: :maybe_external)
  end

  @impl Boruta.Oauth.AuthorizeApplication
  def authorize_error(
        %Plug.Conn{} = conn,
        %Error{status: :unauthorized, error: :login_required} = error
      ) do
    redirect_to(conn, Error.redirect_to_url(error), type: :maybe_external)
  end

  def authorize_error(
        %Plug.Conn{} = conn,
        %Error{status: :unauthorized, error: :invalid_resource_owner}
      ) do
    redirect_to_login(conn)
  end

  def authorize_error(
        conn,
        %Error{
          format: format
        } = error
      )
      when not is_nil(format) do
    redirect_to(conn, Error.redirect_to_url(error), type: :maybe_external)
  end

  def authorize_error(
        conn,
        %Error{
          status: status,
          error: error,
          error_description: error_description
        }
      ) do
    error(error, inspect(error_description))

    conn
    |> put_status(status)
    |> put_view(OauthView)
    |> render("error.html", error: error, error_description: error_description)
  end

  defp put_unsigned_request(%Plug.Conn{query_params: query_params} = conn) do
    unsigned_request_params =
      with request <- Map.get(query_params, "request", ""),
           {:ok, params} <- Joken.peek_claims(request) do
        params
      else
        _ -> %{}
      end

    query_params = Map.merge(query_params, unsigned_request_params)

    %{conn | query_params: query_params}
  end

  defp prompt_redirection(%Plug.Conn{query_params: %{"prompt" => "login"}} = conn) do
    log_out_user(conn)
  end

  defp prompt_redirection(%Plug.Conn{} = conn), do: {:unchanged, conn}

  defp max_age_redirection(
         %Plug.Conn{query_params: %{"max_age" => max_age}} = conn,
         %ResourceOwner{} = resource_owner
       ) do
    case login_expired?(resource_owner, max_age) do
      true ->
        log_out_user(conn)

      false ->
        {:unchanged, conn}
    end
  end

  defp max_age_redirection(%Plug.Conn{} = conn, _resource_owner),
    do: {:unchanged, conn}

  defp login_expired?(%ResourceOwner{last_login_at: last_login_at}, max_age)
       when not is_nil(last_login_at) do
    now = DateTime.to_unix(DateTime.utc_now())

    with {max_age, _} <- Integer.parse("#{max_age}"),
         true <- now - DateTime.to_unix(last_login_at) >= max_age do
      true
    else
      _ -> false
    end
  end

  defp login_expired?(_, _) do
    # FIXME
    false
  end

  defp login_redirection(conn, go_after_url \\ nil)

  defp login_redirection(%Plug.Conn{assigns: %{current_user: _current_user}} = conn, _) do
    {:unchanged, conn}
  end

  defp login_redirection(%Plug.Conn{query_params: %{"prompt" => "none"}} = conn, _) do
    {:unchanged, conn}
  end

  defp login_redirection(%Plug.Conn{} = conn, go_after_url) do
    redirect_to_login(conn, go_after_url)
  end

  defp get_resource_owner(conn) do
    case Bonfire.OpenID.get_user(conn) do
      {:ok, %ResourceOwner{} = ro} ->
        ro

      _ ->
        %ResourceOwner{sub: nil}
    end
  end

  defp go_after_url(conn) do
    # remove prompt and max_age params affecting redirections
    current_path(conn)
    |> String.replace(~r/prompt=(login|none)/, "")
    |> String.replace(~r/max_age=(\d+)/, "")
  end

  defp store_go(conn, url) do
    # remove prompt and max_age params affecting redirections
    put_session(
      conn,
      :go,
      url
    )
  end

  def redirect_to_login(conn, go_after_url \\ nil) do
    # where to redirect in order for the user to login
    # NOTE: after successfully logged in, it should redirect to `get_session(conn, :go)`
    redirect_to(
      conn,
      "#{Bonfire.Common.URIs.path(:login)}?#{URI.encode_query(%{"go" => go_after_url})}"
    )
  end

  defp log_out_user(conn) do
    # where to redirect in order for the user to log out
    # NOTE: after successfully logged out, it should redirect to `get_session(conn, :go)`
    redirect_to(conn, Bonfire.Common.URIs.path(:logout))
  end
end
