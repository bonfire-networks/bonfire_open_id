defmodule Bonfire.OpenID.Provider.ClientApps do
  use Bonfire.Common.Repo
  import Bonfire.Common.Utils
  # alias Bonfire.Common.Enums
  alias Bonfire.Common.Types

  defdelegate list_clients, to: Boruta.Ecto.Admin
  defdelegate list_scopes, to: Boruta.Ecto.Admin
  defdelegate list_active_tokens, to: Boruta.Ecto.Admin

  def get_or_new(id_or_name, redirect_uri) do
    case get(Types.uid(id_or_name), id_or_name, redirect_uri) |> debug("got") do
      nil -> new(id_or_name, redirect_uri) |> debug("newed")
      client -> {:ok, client}
    end
  end

  def get_or_new(clauses) do
    case get(clauses) |> debug("got") do
      nil -> new(Map.new(clauses)) |> debug("newed")
      client -> {:ok, client}
    end
  end

  def update_redirect_uris(client, redirect_uris)
      when is_list(redirect_uris) do
    update_client(client, %{redirect_uris: redirect_uris})
  end

  def update_redirect_uris(client, redirect_uri)
      when is_binary(redirect_uri) do
    update_redirect_uris(client, [redirect_uri])
  end

  # eg: update_scopes(client, ["openid", "email"])
  def update_scopes(client, scopes \\ default_scopes()) do
    update_client(client, %{
      authorize_scope: true,
      authorized_scopes:
        List.wrap(scopes)
        |> Enum.map(fn
          %{name: scope} -> %{name: scope}
          scope -> %{name: scope}
        end)
    })
  end

  def update_client(%Boruta.Ecto.Client{} = client, %{} = attrs) do
    Boruta.Ecto.Admin.update_client(client, attrs)
  end

  def update_client(client_id, %{} = attrs) when is_binary(client_id) do
    if client = get_by_id(client_id) do
      Boruta.Ecto.Admin.update_client(client, attrs)
    end
  end

  def get(id \\ nil, name, redirect_uri)

  def get(nil, name, redirect_uri) when is_binary(redirect_uri) do
    repo().one(
      from c in Boruta.Ecto.Client, where: ^name == c.name and ^redirect_uri in c.redirect_uris
    )
  end

  def get(nil, name, [redirect_uri]) when is_binary(redirect_uri) do
    get(nil, name, redirect_uri)
  end

  def get(id, _name, _redirect_uri) do
    get_by_id(id)
  end

  def get(id: id) do
    # Boruta.ClientsAdapter.get_client(id)
    get_by_id(id)
  end

  def get(clauses) do
    repo().get_by(Boruta.Ecto.Client, clauses)
  end

  def get_by_id(id) do
    repo().one(from c in Boruta.Ecto.Client, where: ^id == c.id)
  end

  @doc "Define an OAuth client app, providing a name and redirect URI(s)"
  def new(id_or_name, redirect_uris)
      when is_binary(id_or_name) and is_list(redirect_uris) and
             length(redirect_uris) > 0 do
    new(
      %{
        id: Types.uid(id_or_name) || SecureRandom.uuid(),
        name: id_or_name,
        redirect_uris: redirect_uris
      }
      |> debug("map")
    )
  end

  def new(id_or_name, redirect_uri)
      when is_binary(id_or_name) and is_binary(redirect_uri) do
    new(id_or_name, [redirect_uri] |> debug("uri"))
  end

  def new(params) when is_map(params) do
    %{
      # OAuth client_id
      id: Types.uid(params[:id]) || SecureRandom.uuid(),
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
      # ...existing code...
      authorized_scopes: default_scopes(),
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
    |> debug("map to create")
    # |> Enums.deep_merge(params)
    |> Boruta.Ecto.Admin.create_client()
  end

  def init_test_client_app(id \\ "b0f15e02-b0f1-b0f1-b0f1-b0f15eb0f15e", attrs \\ %{}) do
    case get(id: id) do
      nil -> new(Map.merge(%{id: id, name: "Test client app"}, attrs))
      client -> client
    end
  end

  def prepare_redirect_uris(other) when is_binary(other) do
    [prepare_redirect_uri(other)]
  end

  def prepare_redirect_uris(list) when is_list(list) do
    Enum.map(list, &prepare_redirect_uri/1)
  end

  # def prepare_redirect_uri("com.tapbots.Ivory.19300:/request_token"<>rest) do
  #   "com.tapbots.Ivory.19300://request_token"<>rest
  # end
  def prepare_redirect_uri(uri), do: uri

  def default_scopes,
    do: [
      %{name: "openid"},
      %{name: "identity"},
      %{name: "data:public"},
      %{name: "follow"},
      %{name: "profile"},
      %{name: "push"},
      %{name: "admin:read"},
      %{name: "admin:read:accounts"},
      %{name: "admin:read:canonical_email_blocks"},
      %{name: "admin:read:domain_allows"},
      %{name: "admin:read:domain_blocks"},
      %{name: "admin:read:email_domain_blocks"},
      %{name: "admin:read:ip_blocks"},
      %{name: "admin:read:reports"},
      %{name: "admin:write"},
      %{name: "admin:write:accounts"},
      %{name: "admin:write:canonical_email_blocks"},
      %{name: "admin:write:domain_allows"},
      %{name: "admin:write:domain_blocks"},
      %{name: "admin:write:email_domain_blocks"},
      %{name: "admin:write:ip_blocks"},
      %{name: "admin:write:reports"},
      %{name: "read"},
      %{name: "read:accounts"},
      %{name: "read:blocks"},
      %{name: "read:bookmarks"},
      %{name: "read:favourites"},
      %{name: "read:filters"},
      %{name: "read:follows"},
      %{name: "read:lists"},
      %{name: "read:mutes"},
      %{name: "read:notifications"},
      %{name: "read:search"},
      %{name: "read:statuses"},
      %{name: "write"},
      %{name: "write:accounts"},
      %{name: "write:blocks"},
      %{name: "write:bookmarks"},
      %{name: "write:conversations"},
      %{name: "write:favourites"},
      %{name: "write:filters"},
      %{name: "write:follows"},
      %{name: "write:lists"},
      %{name: "write:media"},
      %{name: "write:mutes"},
      %{name: "write:notifications"},
      %{name: "write:reports"},
      %{name: "write:statuses"}
    ]
end
