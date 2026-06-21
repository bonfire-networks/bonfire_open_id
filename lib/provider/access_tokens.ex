defmodule Bonfire.OpenID.Provider.AccessTokens do
  @moduledoc """
  Custom AccessTokens adapter that issues long-lived tokens (1 year) for standard
  OAuth scopes (Mastodon-compatible) and short-lived tokens when `offline_access`
  scope is requested (standard OAuth 2.0 flow).

  In both cases we issue a refresh token whenever the grant asks for one (Boruta
  decides this via `options[:refresh_token]`, set by e.g. the authorization_code
  grant), so native apps always have a recovery path. See bonfire-app#1806: not
  issuing a refresh token for Mastodon clients (which don't request
  `offline_access`) left them with no way to recover once the token was gone.
  """

  @behaviour Boruta.Oauth.AccessTokens

  @long_lived_ttl div(to_timeout(day: 365), 1_000)

  defdelegate get_by(params), to: Boruta.Ecto.AccessTokens
  defdelegate revoke(token), to: Boruta.Ecto.AccessTokens
  defdelegate revoke_refresh_token(token), to: Boruta.Ecto.AccessTokens

  @impl Boruta.Oauth.AccessTokens
  def create(%{scope: scope, client: client} = params, options) do
    if offline_access?(scope) do
      Boruta.Ecto.AccessTokens.create(params, options)
    else
      # Mastodon-style client: make the access token long-lived (they don't refresh
      # on a short cycle), but keep the grant's refresh-token decision intact so apps
      # that do refresh still get a refresh token for recovery. See #1806.
      updated_client = %{client | access_token_ttl: @long_lived_ttl}

      Boruta.Ecto.AccessTokens.create(
        %{params | client: updated_client},
        options
      )
    end
  end

  defp offline_access?(scope) when is_binary(scope),
    do: "offline_access" in String.split(scope, " ", trim: true)

  defp offline_access?(_), do: false
end
