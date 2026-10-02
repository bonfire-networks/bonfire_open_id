defmodule Bonfire.OpenID.Provider do
  def alg_supported, do: ["RS256", "RS512"]

  @doc "Maps the grant-type spellings some clients send as a `response_type` onto the real thing. Lives here because `response_types_supported` used to advertise exactly these values, which is where clients got them. Any other value passes through for Boruta to validate, including an already-valid `code`."
  def normalize_response_type(%{"response_type" => "authorization_code"} = params),
    do: Map.put(params, "response_type", "code")

  def normalize_response_type(%{"response_type" => "implicit"} = params),
    do: Map.put(params, "response_type", "id_token token")

  def normalize_response_type(params), do: params

  # Response types, not grant types: the grant list belongs under `grant_types_supported`. Boruta validates these as a space-separated set drawn from `code`/`id_token`/`token` (and `vp_token`, which we do not offer), so this is the standard OIDC set.
  @response_types_supported [
    "code",
    "id_token",
    "token",
    "id_token token",
    "code id_token",
    "code token",
    "code id_token token"
  ]

  @grant_types_supported [
    "authorization_code",
    "implicit",
    "password",
    "client_credentials",
    "refresh_token"
  ]

  def openid_configuration_data do
    Bonfire.Common.URIs.base_url()
    |> metadata("openid")
    |> Map.merge(%{
      "id_token_signing_alg_values_supported" => alg_supported(),
      "subject_types_supported" => ["public"],
      "claims_supported" => ["sub", "name", "preferred_username", "email", "email_verified"]
    })
  end

  def oauth_authorization_server_data do
    Bonfire.Common.URIs.base_url()
    |> metadata("oauth")
    |> Map.merge(%{
      # CIMD: clients may use their own HTTPS URL as client_id (no pre-registration needed)
      "client_id_metadata_document_supported" => true,
      # This instance's own CIMD URL, used when connecting to other servers as a client
      "client_id" => Bonfire.OpenID.Client.cimd_client_id()
      # "ui_locales_supported" => ["en"]
    })
  end

  # Everything both documents advertise identically. `prefix` picks the protocol's own authorize/token/userinfo routes; JWKS, dynamic registration, revocation and introspection are each served under a single path shared by both.
  defp metadata(base_url, prefix) do
    %{
      "issuer" => "#{base_url}",
      "authorization_endpoint" => "#{base_url}/#{prefix}/authorize",
      "token_endpoint" => "#{base_url}/#{prefix}/token",
      "userinfo_endpoint" => "#{base_url}/#{prefix}/userinfo",
      "jwks_uri" => "#{base_url}/openid/jwks",
      "registration_endpoint" => "#{base_url}/openid/register",
      "revocation_endpoint" => "#{base_url}/oauth/revoke",
      "introspection_endpoint" => "#{base_url}/oauth/introspect",
      # TODO: replace with actual scopes we want to use as a provider
      "scopes_supported" => Bonfire.OpenID.Provider.ClientApps.default_scopes(),
      "response_types_supported" => @response_types_supported,
      "grant_types_supported" => @grant_types_supported,
      # Credentials are read from the request body or a `private_key_jwt` assertion. Omitting this key is worse than useless: clients then assume the spec default of `client_secret_basic`, the one method we do not read.
      "token_endpoint_auth_methods_supported" => ["client_secret_post", "private_key_jwt"],
      "token_endpoint_auth_signing_alg_values_supported" => alg_supported(),
      "code_challenge_methods_supported" => ["S256", "plain"]
    }
  end
end
