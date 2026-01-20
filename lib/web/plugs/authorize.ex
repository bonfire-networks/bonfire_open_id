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
         {:ok, token} <- AccessToken.authorize(value: bearer),
         %{} = user <-
           Bonfire.Me.Users.get_current(token.sub) || error(token, "No user found") do
      conn
      # |> assign(:current_bearer_token, bearer)
      |> assign(:current_token, token)
      |> assign(:current_user, user)
      |> assign(:user_email_confirmed?, email_confirmed?(user))
    else
      {:error, reason} ->
        flood(reason, "Could not load or verify Bearer authorization")
        nil

      [] ->
        flood("Could not find Bearer authorization")
        nil

      other when is_list(other) ->
        flood("Could not find valid Bearer authorization")
        nil

      other ->
        flood(other, "Could not load authorization")
        nil
    end || maybe_fallback_load_authorization(conn, opts)
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
        flood(required_scopes, "Authorize plug failed to validate scopes")
        raise Bonfire.Fail, :unauthorized
    end
  end

  def authorized_scopes?(conn, required_scopes) do
    current_scopes = Scope.split(conn.assigns[:current_token].scope)

    Enum.empty?(List.wrap(required_scopes) -- current_scopes)
  end

  defp email_confirmed?(user) do
    with account_id when is_binary(account_id) <-
           e(user, :account, :id, nil) || e(user, :accounted, :account_id, nil),
         %{email: %{confirmed_at: confirmed_at}} when not is_nil(confirmed_at) <-
           Bonfire.Me.Accounts.Queries.login_by_account_id(account_id)
           |> Bonfire.Common.Repo.maybe_one() do
      true
    else
      _ -> false
    end
  end
end
