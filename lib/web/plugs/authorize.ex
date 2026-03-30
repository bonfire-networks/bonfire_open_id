defmodule Bonfire.OpenID.Plugs.Authorize do
  use Bonfire.UI.Common.Web, :plug
  import Bonfire.Common.E

  alias Boruta.Oauth.Authorization.AccessToken
  alias Boruta.Oauth.Scope

  alias Bonfire.Common.Extend

  def load_authorization(conn, opts) do
    maybe_load_authorization(conn, opts) || conn
  end

  def maybe_load_authorization(conn, opts \\ []) do
    with [authorization_header] <- get_req_header(conn, "authorization"),
         [_authorization_header, bearer] <- Regex.run(~r/[B|b]earer (.+)/, authorization_header),
         {:ok, token} <- AccessToken.authorize(value: bearer) do
      load_token_user(conn, token)
    else
      {:error, reason} ->
        debug(reason, "Could not load or verify Bearer authorization")
        nil

      [] ->
        # No Authorization header - try access_token query param (used by SSE/streaming clients)
        maybe_load_from_query_param(conn)

      other when is_list(other) ->
        debug("Could not find valid Bearer authorization")
        nil

      other ->
        debug(other, "Could not load authorization")
        nil
    end || maybe_fallback_load_authorization(conn, opts)
  end

  defp load_token_user(conn, token) do
    # Always assign the token (works for app-only/client_credentials tokens too)
    conn = assign(conn, :current_token, token)

    # Optionally load the user if the token has a subject
    if token.sub && Bonfire.Common.Cache.get!("force_logout:#{token.sub}") do
      conn
    else
      case token.sub && Bonfire.Me.Users.get_current(token.sub) do
        %{} = user -> assign(conn, :current_user, user)
        _ -> conn
      end
    end
  end

  defp maybe_load_from_query_param(conn) do
    with access_token when is_binary(access_token) <- conn.params["access_token"],
         {:ok, token} <- AccessToken.authorize(value: access_token) do
      load_token_user(conn, token)
    else
      _ -> nil
    end
  end

  defp maybe_fallback_load_authorization(conn, opts) do
    if module = Extend.maybe_module(Bonfire.UI.Me.Plugs.LoadCurrentUser) do
      module.call(conn, opts)
    end
  end

  def authorize(conn, [_h | _t] = required_scopes) do
    case authorized_scopes?(conn, required_scopes) do
      true ->
        conn

      false ->
        debug(required_scopes, "Authorize plug failed to validate scopes")
        raise Bonfire.Fail, :unauthorized
    end
  end

  def authorized_scopes?(conn, required_scopes) do
    current_scopes = Scope.split(conn.assigns[:current_token].scope)

    Enum.empty?(List.wrap(required_scopes) -- current_scopes)
  end
end
