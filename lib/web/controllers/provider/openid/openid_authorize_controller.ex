defmodule Bonfire.OpenID.Web.Openid.AuthorizeController do
  @behaviour Boruta.Oauth.AuthorizeApplication

  use Bonfire.UI.Common.Web, :controller
  use Bonfire.Common.Repo

  alias Boruta.Oauth.AuthorizeResponse
  alias Boruta.Oauth.Error
  alias Boruta.Oauth.ResourceOwner
  alias Bonfire.OpenID.Web.OauthView

  def oauth_module,
    do: Application.get_env(:bonfire_open_id, :oauth_module, Boruta.Oauth)

  def authorize(%Plug.Conn{} = conn, params) do
    conn = store_user_return_to(conn)
    # |> put_unsigned_request()

    # Map.get(conn, :query_params)
    # |> flood("Authorize request with params")

    with {:unchanged, conn} <- prompt_redirection(conn),
         resource_owner = get_resource_owner(conn),
         {:unchanged, conn} <- max_age_redirection(conn, resource_owner),
         {:unchanged, conn} <- login_redirection(conn) |> flood("login_redirection?") do
      oauth_module().authorize(conn, resource_owner, __MODULE__)
    end
  end

  @doc "Callback called by Bonfire.UI.Common.redirect_to_previous_go when redirect back to /openid/authorize after login. This extracts the query string and calls authorize/2 directly instead of redirecting back to this controller."
  def from_query_string(conn, query) do
    query_params =
      Plug.Conn.Query.decode(query)
      |> flood("from_query_string query_params")
      |> Map.update("response_type", "code id_token token", fn existing_value ->
        # FIXME: temp workaround for this error: Invalid response_type param, may be on of `code` for Authorization Code request, `code id_token`, `code token`, `code id_token token` for Hybrid requests, or `token`, `id_token token` for Implicit requests
        case existing_value do
          "authorization_code" -> "code"
          "implicit" -> "id_token token"
          _ -> "code id_token token"
        end
      end)
      |> Bonfire.OpenID.Provider.ClientApps.maybe_transform_client_id()
      |> add_unsigned_request()
      |> flood("from_query_string transformed query_params")

    conn
    |> Map.put(:query_params, query_params)
    |> authorize(query_params)
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
    warn("Unauthorized, redirecting")
    # TODO? redirect to login instead of error?
    redirect_to(conn, Error.redirect_to_url(error), type: :maybe_external)
  end

  def authorize_error(
        %Plug.Conn{} = conn,
        %Error{status: :unauthorized, error: :invalid_resource_owner}
      ) do
    warn("Invalid resource owner, redirecting to login")
    redirect_to_login(conn)
  end

  def authorize_error(
        conn,
        %Error{
          format: format
        } = error
      )
      when not is_nil(format) do
    warn(error, "Redirecting to error")
    redirect_to(conn, Error.redirect_to_url(error), type: :maybe_external)
  end

  def authorize_error(
        conn,
        %Error{status: status, error: error, error_description: error_description}
      ) do
    if error == :invalid_client do
      repo().all(from Boruta.Ecto.Client, order_by: [desc: :updated_at])
      |> IO.inspect(label: "Clients in DB in #{Config.repo()}")
    end

    error(error, inspect(error_description))
    flood(conn)

    conn
    |> put_status(status)
    |> put_view(OauthView)
    |> render("error.html", error: error, error_description: error_description)
  end

  # what was this for?
  defp add_unsigned_request(query_params) do
    unsigned_request_params =
      with request when is_binary(request) <- Map.get(query_params, "request"),
           {:ok, params} <- Joken.peek_claims(request) do
        params
      else
        _ -> %{}
      end

    Map.merge(query_params, unsigned_request_params)
  end

  defp store_user_return_to(conn, url \\ nil) do
    # remove prompt and max_age params affecting redirections
    conn
    |> put_session(
      :go,
      (url ||
         current_path(conn, conn.query_params))
      |> String.replace(~r/prompt=(login|none)/, "")
      |> String.replace(~r/max_age=(\d+)/, "")
    )
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

  defp max_age_redirection(%Plug.Conn{} = conn, _resource_owner), do: {:unchanged, conn}

  defp login_expired?(%ResourceOwner{last_login_at: last_login_at}, max_age)
       when not is_nil(last_login_at) do
    now = DateTime.utc_now() |> DateTime.to_unix()

    with "" <> max_age <- max_age,
         {max_age, _} <- Integer.parse(max_age),
         true <- now - DateTime.to_unix(last_login_at) >= max_age do
      true
    else
      _ -> false
    end
  end

  defp login_expired?(resource_owner, _) do
    warn(resource_owner, "Could not determine last_login_at")
    # FIXME?
    false
  end

  defp login_redirection(%Plug.Conn{assigns: %{current_user: _current_user}} = conn) do
    {:unchanged, conn}
  end

  defp login_redirection(%Plug.Conn{query_params: %{"prompt" => "none"}} = conn) do
    {:unchanged, conn}
  end

  defp login_redirection(%Plug.Conn{} = conn) do
    redirect_to_login(conn)
  end

  defp get_resource_owner(conn) do
    case Bonfire.OpenID.get_user(conn) do
      {:ok, %ResourceOwner{} = resource_owner} ->
        resource_owner

      e ->
        error(e, "Could not find current user")

        # %ResourceOwner{sub: nil}

        # current_user ->
        #   %ResourceOwner{
        #     sub: to_string(current_user.id),
        #     username: e(agent, :character, :username, nil) || e(agent, :email, :email_address, nil),
        #     # last_login_at: current_user.last_login_at
        #   }
    end
  end

  def redirect_to_login(conn, go_after_url \\ nil) do
    # where to redirect in order for the user to login
    # NOTE: after successfully logged in, it should redirect to `get_session(conn, :go)`
    redirect_to(
      conn,
      "#{Bonfire.Common.URIs.path(:login)}?#{URI.encode_query(%{"go" => go_after_url || current_path(conn, conn.query_params)})}"
    )
  end

  defp log_out_user(conn) do
    # where to redirect in order for the user to log out
    # NOTE: after successfully logged out, it should redirect to `get_session(conn, :go)`
    redirect_to(conn, Bonfire.Common.URIs.path(:logout))
  end
end
