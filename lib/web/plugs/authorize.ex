defmodule Bonfire.OpenID.Plugs.Authorize do
  import Plug

  use Bonfire.UI.Common.Web, :controller

  alias Boruta.Oauth.Authorization.AccessToken
  alias Boruta.Oauth.Scope

  def load_authorization(conn, _opts) do
    maybe_load_authorization(conn) || conn
  end

  def maybe_load_authorization(conn, _opts \\ []) do
    with [authorization_header] <- get_req_header(conn, "authorization"),
         [_authorization_header, bearer] <- Regex.run(~r/[B|b]earer (.+)/, authorization_header),
         {:ok, token} <- AccessToken.authorize(value: bearer),
         %{} = user <- Bonfire.Me.Users.get_current(token.sub) do
      conn
      # |> assign(:current_bearer_token, bearer)
      |> assign(:current_token, token)
      |> assign(:current_user, user)
    else
      other ->
        info(other, "Could not load authorization")
        nil
    end
  end

  def authorize(conn, [_h | _t] = required_scopes) do
    current_scopes = Scope.split(conn.assigns[:current_token].scope)

    case Enum.empty?(required_scopes -- current_scopes) do
      true ->
        conn

      false ->
        raise Bonfire.Fail, :unauthorized
    end
  end
end
