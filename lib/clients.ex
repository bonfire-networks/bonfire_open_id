defmodule Bonfire.OpenID.Clients do

  defdelegate list_clients, to: Boruta.Ecto.Admin
  defdelegate list_scopes, to: Boruta.Ecto.Admin
  defdelegate list_active_tokens, to: Boruta.Ecto.Admin

  def new(params) when is_map(params) do
    %{
      id: SecureRandom.uuid(), # OAuth client_id
      secret: SecureRandom.hex(64), # OAuth client_secret
      name: "A client", # Display name
      access_token_ttl: 60 * 60 * 24, # one day
      authorization_code_ttl: 60, # one minute
      refresh_token_ttl: 60 * 60 * 24 * 30, # one month
      id_token_ttl: 60 * 60 * 24, # one day
      # redirect_uris: ["http://redirect.uri"], # OAuth client redirect_uris
      authorize_scope: true, # take following authorized_scopes into account (skip public scopes)
      authorized_scopes: [%{name: "identity"}, %{name: "data:public"}], # scopes that are authorized using this client
      supported_grant_types: [ # client supported grant types
        "client_credentials",
        "password",
        "authorization_code",
        "refresh_token",
        "implicit",
        "revoke",
        "introspect"
      ],
      pkce: false, # PKCE enabled
      public_refresh_token: false, # do not require client_secret for refreshing tokens
      public_revoke: false # do not require client_secret for revoking tokens
    }
    |> Map.merge(params)
    |> Boruta.Ecto.Admin.create_client()
  end

  def new(name, redirect_uris) when is_binary(name) and is_list(redirect_uris) and length(redirect_uris)>0 do
    new(%{name: name, redirect_uris: redirect_uris})
  end

  def new(name, redirect_uri) when is_binary(name) and is_binary(redirect_uri) do
    new(name, [redirect_uri])
  end
end
