defmodule Bonfire.OpenID.Provider.ClientApps do
  use Bonfire.Common.Repo
  import Bonfire.Common.Utils
  # alias Bonfire.Common.Enums
  alias Bonfire.Common.Types

  defdelegate list_clients, to: Boruta.Ecto.Admin
  defdelegate list_scopes, to: Boruta.Ecto.Admin
  defdelegate list_active_tokens, to: Boruta.Ecto.Admin

  # TODO: put in config
  def default_scopes,
    do: [
      "openid",
      "identity",
      "data:public",
      "follow",
      "profile",
      "email",
      "offline_access",
      "push",
      "admin:read",
      "admin:read:accounts",
      "admin:read:canonical_email_blocks",
      "admin:read:domain_allows",
      "admin:read:domain_blocks",
      "admin:read:email_domain_blocks",
      "admin:read:ip_blocks",
      "admin:read:reports",
      "admin:write",
      "admin:write:accounts",
      "admin:write:canonical_email_blocks",
      "admin:write:domain_allows",
      "admin:write:domain_blocks",
      "admin:write:email_domain_blocks",
      "admin:write:ip_blocks",
      "admin:write:reports",
      "read",
      "read:accounts",
      "read:blocks",
      "read:bookmarks",
      "read:favourites",
      "read:filters",
      "read:follows",
      "read:lists",
      "read:mutes",
      "read:notifications",
      "read:search",
      "read:statuses",
      "write",
      "write:accounts",
      "write:blocks",
      "write:bookmarks",
      "write:conversations",
      "write:favourites",
      "write:filters",
      "write:follows",
      "write:lists",
      "write:media",
      "write:mutes",
      "write:notifications",
      "write:reports",
      "write:statuses"
    ]

  # Overload to accept attrs for dynamic client creation (e.g., PKCE/public)
  def get_or_new(id_or_name, redirect_uris, attrs \\ %{}) do
    id = id_or_name_to_id(id_or_name)

    case get(id, id_or_name, redirect_uris) |> debug("got") do
      nil ->
        redirect_uris = List.wrap(redirect_uris)

        new(Map.merge(%{id: id, name: id_or_name, redirect_uris: redirect_uris}, attrs))
        |> debug("newed")

      client ->
        {:ok, client}
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
      authorized_scopes: scopes_maps(scopes)
    })
  end

  def scopes_maps(scopes \\ default_scopes()) do
    List.wrap(scopes)
    |> Enum.map(fn
      %{name: scope} -> %{name: scope}
      scope -> %{name: scope}
    end)
  end

  def scopes_structs(scopes \\ default_scopes()) do
    List.wrap(scopes)
    |> Enum.map(fn
      %{name: scope} -> %Boruta.Oauth.Scope{name: scope}
      scope -> %Boruta.Oauth.Scope{name: scope}
    end)
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

  def get(nil, name, redirect_uris) when is_list(redirect_uris) do
    # TODO: compare the arrays regardless of order, checking if all given uris are in the client's redirect_uris (even if it has extra ones configured)?
    repo().one(
      from c in Boruta.Ecto.Client, where: ^name == c.name and ^redirect_uris == c.redirect_uris
    )
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

  def id_or_name_to_id(id_or_name) do
    cond do
      uuid?(id_or_name) ->
        id_or_name

      true ->
        hash_to_uuid(id_or_name)
    end
  end

  @doc "Define an OAuth client app, providing a name and redirect URI(s)"
  def new(id \\ nil, id_or_name, redirect_uris)
      when is_binary(id_or_name) and is_list(redirect_uris) and
             length(redirect_uris) > 0 do
    new(
      %{
        id: id || id_or_name_to_id(id_or_name),
        name: id_or_name,
        redirect_uris: redirect_uris
      }
      |> debug("map")
    )
  end

  def new(id, id_or_name, redirect_uri)
      when is_binary(id_or_name) and is_binary(redirect_uri) do
    new(id, id_or_name, [redirect_uri] |> debug("uri"))
  end

  def new(params) when is_map(params) do
    # Ensure id is a UUID, and store original if not
    id =
      case params[:id] do
        nil ->
          generate_client_id()

        id ->
          if uuid?(id) do
            id
          else
            hash_to_uuid(id)
          end
      end

    # set some defaults
    %{
      # OAuth client_id
      id: id,
      # Display name
      name: Map.get(params, :name) || params[:id] || "Client app",
      # one day
      access_token_ttl: 60 * 60 * 24,
      # one minutes
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
      authorized_scopes: scopes_maps(),
      # client supported grant types - NOTE: device not yet supported: https://github.com/malach-it/boruta_auth/issues/46
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
      # require client_secret for refreshing tokens?
      public_refresh_token: false,
      # see OAuth 2.0 confidentiality (requires client secret for some flows)
      confidential: true,
      # require client_secret for revoking tokens?
      public_revoke: true,
      # activate-able client authentication methods
      token_endpoint_auth_methods: [
        "client_secret_basic",
        "client_secret_post",
        "client_secret_jwt",
        "private_key_jwt"
      ]
      # token_endpoint_jwt_auth_alg: nil, # associated to authentication methods, the algorithm to use along
      # jwt_public_key: nil # pem public key to be used with `private_key_jwt` authentication method
    }
    |> Map.merge(params)
    # OAuth client_secret
    |> Map.put_new_lazy(:secret, fn -> SecureRandom.hex(64) end)
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

  def register_dynamic_client(params) do
    # Validate required fields
    with {:ok, validated_params} <-
           params
           |> debug("input params")
           |> validate_registration_params()
           |> debug("validated params") do
      registration_access_token = generate_registration_access_token()
      client_id = generate_client_id()

      # Store registration token in metadata since Boruta doesn't have a dedicated field
      client_params = %{
        id: client_id,
        redirect_uris: validated_params["redirect_uris"],
        supported_scopes: parse_scopes(validated_params["scope"]) || default_scopes(),
        supported_grant_types: validated_params["grant_types"] || ["authorization_code"],
        name: validated_params["client_name"] || "Dynamically Registered Client",
        # Store registration token in metadata
        metadata: %{"registration_access_token" => registration_access_token}
      }

      case new(client_params) do
        {:ok, client} ->
          client_response = %{
            "client_id" => client.id,
            "client_secret" => client.secret,
            "registration_access_token" => registration_access_token,
            "registration_client_uri" =>
              "#{Bonfire.Common.URIs.base_url()}/openid/register/#{client.id}",
            "client_name" => client.name,
            "redirect_uris" => client.redirect_uris,
            "grant_types" => client.supported_grant_types,
            "response_types" => validated_params["response_types"] || ["code"],
            "scope" =>
              Enum.join(client.authorized_scopes |> Enum.map(& &1.name) || default_scopes(), " ")
          }

          {:ok, client_response}

        error ->
          error
      end
    end
  end

  # Update this function to check metadata
  def get_client_by_registration_token(client_id, registration_token) do
    case get_by_id(client_id) do
      nil ->
        {:error, :not_found}

      # Check metadata for the registration token
      %{metadata: %{"registration_access_token" => ^registration_token}} = client ->
        {:ok, client}

      client ->
        # Debug what we actually have
        debug(client.metadata, "client metadata")
        debug(registration_token, "looking for token")
        {:error, :invalid_token}
    end
  end

  # Also update the client configuration update to preserve the registration token
  def update_client_configuration(client_id, registration_token, params) do
    with {:ok, client} <- get_client_by_registration_token(client_id, registration_token),
         converted_params = convert_oidc_to_internal_params(params) do
      # Preserve the registration token in metadata when updating
      updated_metadata =
        Map.merge(client.metadata || %{}, %{"registration_access_token" => registration_token})

      converted_params = Map.put(converted_params, :metadata, updated_metadata)

      case update_client(client, converted_params) do
        {:ok, updated_client} ->
          client_config = %{
            "client_id" => updated_client.id,
            "client_secret" => updated_client.secret,
            "client_name" => updated_client.name,
            "redirect_uris" => updated_client.redirect_uris,
            "grant_types" => updated_client.supported_grant_types || ["authorization_code"],
            "response_types" =>
              convert_grant_types_to_response_types(updated_client.supported_grant_types),
            "scope" =>
              Enum.join(updated_client.authorized_scopes |> Enum.map(& &1.name) || [], " "),
            "token_endpoint_auth_method" =>
              if(updated_client.confidential, do: "client_secret_post", else: "none")
          }

          {:ok, client_config}

        error ->
          error
      end
    end
  end

  def get_client_configuration(client_id, registration_token) do
    case get_client_by_registration_token(client_id, registration_token)
         |> repo().maybe_preload(:authorized_scopes) do
      {:ok, client} ->
        client_config = %{
          "client_id" => client.id,
          "client_secret" => client.secret,
          "client_name" => client.name,
          "redirect_uris" => client.redirect_uris,
          "grant_types" => client.supported_grant_types || ["authorization_code"],
          "response_types" => convert_grant_types_to_response_types(client.supported_grant_types),
          "scope" => Enum.join(client.authorized_scopes |> Enum.map(& &1.name) || [], " "),
          "token_endpoint_auth_method" =>
            if(client.confidential, do: "client_secret_post", else: "none")
        }

        {:ok, client_config}

      error ->
        error
    end
  end

  def update_client_configuration(client_id, registration_token, params) do
    with {:ok, client} <- get_client_by_registration_token(client_id, registration_token),
         converted_params = convert_oidc_to_internal_params(params),
         {:ok, updated_client} <- update_client(client, converted_params) do
      # Return updated client config in OpenID Connect format
      client_config = %{
        "client_id" => updated_client.id,
        "client_secret" => updated_client.secret,
        "client_name" => updated_client.name,
        "redirect_uris" => updated_client.redirect_uris,
        "grant_types" => updated_client.supported_grant_types || ["authorization_code"],
        "response_types" =>
          convert_grant_types_to_response_types(updated_client.supported_grant_types),
        "scope" => Enum.join(updated_client.authorized_scopes |> Enum.map(& &1.name) || [], " "),
        "token_endpoint_auth_method" =>
          if(updated_client.confidential, do: "client_secret_post", else: "none")
      }

      {:ok, client_config}
    end
  end

  def delete_client(client_id, registration_token) do
    case get_client_by_registration_token(client_id, registration_token) do
      {:ok, client} ->
        case repo().delete(client) do
          {:ok, _} -> :ok
          {:error, changeset} -> {:error, changeset}
        end

      error ->
        error
    end
  end

  # Helper functions
  defp convert_grant_types_to_response_types(grant_types) when is_list(grant_types) do
    grant_types
    |> Enum.flat_map(fn
      "authorization_code" -> ["code"]
      "implicit" -> ["token", "id_token", "id_token token"]
      _ -> []
    end)
    |> Enum.uniq()
  end

  defp convert_grant_types_to_response_types(_), do: ["code"]

  defp convert_oidc_to_internal_params(params) do
    converted = %{}

    converted =
      if params["client_name"],
        do: Map.put(converted, :name, params["client_name"]),
        else: converted

    converted =
      if params["redirect_uris"],
        do: Map.put(converted, :redirect_uris, params["redirect_uris"]),
        else: converted

    converted =
      if params["scope"],
        do: Map.put(converted, :authorized_scopes, scopes_maps(parse_scopes(params["scope"]))),
        else: converted

    converted
  end

  defp validate_registration_params(params) do
    # Skip redirect_uri validation for device code flow
    debug(params, "validating params")
    grant_type = params["grant_type"]
    application_type = params["application_type"] || "web"

    if grant_type == "urn:ietf:params:oauth:grant-type:device_code" do
      {:ok, params}
    else
      case params["redirect_uris"] do
        uris when is_list(uris) and length(uris) > 0 ->
          # TEMP workaround: Filter out native URIs (custom scheme, no host) to avoid Boruta validation error
          # TODO: Open an issue/PR upstream to allow native redirect URIs per OIDC spec
          filtered_uris =
            Enum.filter(uris, fn uri ->
              case URI.parse(uri) do
                %URI{scheme: _, host: nil} ->
                  false

                %URI{scheme: nil, host: _} ->
                  false

                _ ->
                  true
              end
            end)

          if Enum.all?(filtered_uris, &valid_redirect_uri?(&1, application_type)) and
               length(filtered_uris) > 0 do
            # Pass only filtered URIs to params
            {:ok, Map.put(params, "redirect_uris", filtered_uris)}
          else
            {:error, :invalid_redirect_uri}
          end

        _ ->
          {:error, :invalid_redirect_uri}
      end
    end
  end

  # Accepts http/https for web apps, and custom schemes for native apps (e.g., edu.kit.data.oidc-agent:/redirect)
  defp valid_redirect_uri?(uri, application_type) when is_binary(uri) do
    case URI.parse(uri) do
      %URI{scheme: scheme, host: host, path: path} ->
        cond do
          application_type == "web" and scheme in ["http", "https"] and is_binary(host) ->
            true

          # application_type == "native" and scheme not in ["http", "https"] and (is_binary(host) or is_binary(path)) ->
          #   true
          scheme not in ["http", "https"] and (is_binary(host) or is_binary(path)) ->
            # Accept custom schemes for native apps even if application_type is not set
            true

          true ->
            false
        end

      _ ->
        false
    end
  end

  defp valid_redirect_uri?(_, _), do: false

  defp generate_client_id do
    SecureRandom.uuid()
  end

  defp generate_registration_access_token do
    :crypto.strong_rand_bytes(32) |> Base.url_encode64(padding: false)
  end

  defp parse_scopes(scope_string) when is_binary(scope_string) do
    String.split(scope_string, " ", trim: true)
  end

  defp parse_scopes(_), do: nil

  # workaround for Boruta: If client_id is not a UUID, hash and encode as UUID, and store original.
  def maybe_transform_client_id(params) do
    case Map.get(params, "client_id") do
      nil ->
        params

      client_id ->
        if uuid?(client_id) do
          params
        else
          params
          |> Map.put("original_client_id", client_id)
          |> Map.put("client_id", hash_to_uuid(client_id))
        end
    end
  end

  @doc """
  Returns true if the given string is a UUID.

      iex> Bonfire.OpenID.Provider.ClientApps.uuid?("b0f15e02-b0f1-b0f1-b0f1-b0f15eb0f15e")
      true
      iex> Bonfire.OpenID.Provider.ClientApps.uuid?("https://foo.bar")
      false
  """
  def uuid?(
        <<a::binary-size(8), "-", b::binary-size(4), "-", c::binary-size(4), "-",
          d::binary-size(4), "-", e::binary-size(12)>>
      ) do
    Enum.all?([a, b, c, d, e], &String.match?(&1, ~r/^[0-9a-fA-F]+$/))
  end

  def uuid?(_), do: false

  @doc """
  Hashes a string and encodes it as a UUID.

      iex> uuid = Bonfire.OpenID.Provider.ClientApps.hash_to_uuid("https://foo.bar")
      iex> Bonfire.OpenID.Provider.ClientApps.uuid?(uuid)
      true
  """
  def hash_to_uuid(str) do
    <<a::binary-size(16), _::binary>> = :crypto.hash(:sha256, str)
    <<d1::32, d2::16, d3::16, d4::16, d5::48>> = a

    :io_lib.format("~8.16.0b-~4.16.0b-~4.16.0b-~4.16.0b-~12.16.0b", [d1, d2, d3, d4, d5])
    |> IO.iodata_to_binary()
  end
end
