defmodule Bonfire.OpenID.Clients do
  defdelegate list_clients, to: Boruta.Ecto.Admin
  defdelegate list_scopes, to: Boruta.Ecto.Admin
  defdelegate list_active_tokens, to: Boruta.Ecto.Admin

  def new(params) when is_map(params) do
    %{
      # OAuth client_id
      id: SecureRandom.uuid(),
      # OAuth client_secret
      secret: SecureRandom.hex(64),
      # Display name
      name: "A client",
      # one day
      access_token_ttl: 60 * 60 * 24,
      # one minute
      authorization_code_ttl: 60,
      # one month
      refresh_token_ttl: 60 * 60 * 24 * 30,
      # one day
      id_token_ttl: 60 * 60 * 24,
      # redirect_uris: ["http://redirect.uri"], # OAuth client redirect_uris
      # take following authorized_scopes into account (skip public scopes)
      authorize_scope: true,
      # scopes that are authorized using this client
      authorized_scopes: [%{name: "identity"}, %{name: "data:public"}],
      # client supported grant types
      supported_grant_types: [
        "client_credentials",
        "password",
        "authorization_code",
        "refresh_token",
        "implicit",
        "revoke",
        "introspect"
      ],
      # PKCE enabled
      pkce: false,
      # do not require client_secret for refreshing tokens
      public_refresh_token: false,
      # do not require client_secret for revoking tokens
      public_revoke: false
    }
    |> Map.merge(params)
    |> Boruta.Ecto.Admin.create_client()
  end

  def new(name, redirect_uris)
      when is_binary(name) and is_list(redirect_uris) and
             length(redirect_uris) > 0 do
    new(%{name: name, redirect_uris: redirect_uris})
  end

  def new(name, redirect_uri)
      when is_binary(name) and is_binary(redirect_uri) do
    new(name, [redirect_uri])
  end
end
