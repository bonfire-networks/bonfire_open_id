defmodule Bonfire.OpenID.Provider.ClientApps do
  defdelegate list_clients, to: Boruta.Ecto.Admin
  defdelegate list_scopes, to: Boruta.Ecto.Admin
  defdelegate list_active_tokens, to: Boruta.Ecto.Admin

  @doc "Define an OAuth client app, providing a name and redirect URI(s)"
  def new(name, redirect_uris)
      when is_binary(name) and is_list(redirect_uris) and
             length(redirect_uris) > 0 do
    new(%{name: name, redirect_uris: redirect_uris})
  end

  def new(name, redirect_uri)
      when is_binary(name) and is_binary(redirect_uri) do
    new(name, [redirect_uri])
  end

  def new(params) when is_map(params) do
    %{
      # OAuth client_id
      id: SecureRandom.uuid(),
      # OAuth client_secret
      secret: SecureRandom.hex(64),
      # Display name
      name: "Client app",
      # one day
      access_token_ttl: 60 * 60 * 24,
      # one minute
      authorization_code_ttl: 60,
      # one month
      refresh_token_ttl: 60 * 60 * 24 * 30,
      # one day
      id_token_ttl: 60 * 60 * 24,
      # ID token signature algorithm, defaults to "RS512"
      id_token_signature_alg: "RS256",
      # userinfo signature algorithm, defaults to nil (no signature)
      userinfo_signed_response_alg: "RS256",
      # OAuth client redirect_uris
      redirect_uris: ["#{Bonfire.Common.URIs.base_url()}/oauth/ready"],
      # take following authorized_scopes into account (skip public scopes)
      authorize_scope: true,
      # scopes that are authorized using this client
      authorized_scopes: [
        %{name: "identity"},
        %{name: "data:public"},
        %{name: "read"},
        %{name: "write"},
        %{name: "follow"},
        %{name: "push"}
      ],
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
      public_revoke: false,
      # activate-able client authentication methods
      token_endpont_auth_methods: [
        "client_secret_basic",
        "client_secret_post",
        "client_secret_jwt",
        "private_key_jwt"
      ]
      # token_endpoint_jwt_auth_alg: nil, # associated to authentication methods, the algorithm to use along
      # jwt_public_key: nil # pem public key to be used with `private_key_jwt` authentication method
    }
    |> Map.merge(params)
    |> Boruta.Ecto.Admin.create_client()
  end

  def init_test_client_app do
    new(%{id: "b0f15e02-b0f1-b0f1-b0f1-b0f15eb0f15e", name: "Test client app"})
  end
end
