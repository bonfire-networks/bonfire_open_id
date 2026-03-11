defmodule Bonfire.OpenID.Provider.AccessTokens do
  @moduledoc """
  Custom AccessTokens adapter that issues long-lived tokens (1 year) for standard
  OAuth scopes (Mastodon-compatible) and short-lived tokens with refresh tokens
  when `offline_access` scope is requested (standard OAuth 2.0 flow).
  """

  @behaviour Boruta.Oauth.AccessTokens

  @long_lived_ttl 60 * 60 * 24 * 365

  defdelegate get_by(params), to: Boruta.Ecto.AccessTokens
  defdelegate revoke(token), to: Boruta.Ecto.AccessTokens
  defdelegate revoke_refresh_token(token), to: Boruta.Ecto.AccessTokens

  @impl Boruta.Oauth.AccessTokens
  def create(%{scope: scope, client: client} = params, options) do
    if offline_access?(scope) do
      Boruta.Ecto.AccessTokens.create(params, options)
    else
      updated_client = %{client | access_token_ttl: @long_lived_ttl}

      Boruta.Ecto.AccessTokens.create(
        %{params | client: updated_client},
        Keyword.put(options, :refresh_token, false)
      )
    end
  end

  defp offline_access?(scope) when is_binary(scope),
    do: "offline_access" in String.split(scope, " ", trim: true)

  defp offline_access?(_), do: false
end
