defmodule Bonfire.OpenID.Provider do
  def alg_supported, do: ["RS256", "RS512"]

  @doc "Maps the grant-type spellings some clients send as a `response_type` onto the real thing. Lives here because `response_types_supported` used to advertise exactly these values, which is where clients got them. Any other value passes through for Boruta to validate, including an already-valid `code`."
  def normalize_response_type(%{"response_type" => "authorization_code"} = params),
    do: Map.put(params, "response_type", "code")

  def normalize_response_type(%{"response_type" => "implicit"} = params),
    do: Map.put(params, "response_type", "id_token token")

  def normalize_response_type(params), do: params

  def openid_configuration_data do
    base_url = Bonfire.Common.URIs.base_url()

    %{
      # "authorization_endpoint"=> "#{base_url}/oauth/authorize",
      "authorization_endpoint" => "#{base_url}/openid/authorize",
      "issuer" => "#{base_url}",
      "jwks_uri" => "#{base_url}/openid/jwks",
      "registration_endpoint" => "#{base_url}/openid/register",
      "id_token_signing_alg_values_supported" => alg_supported(),
      # response types, not grant types: the grant list belongs under `grant_types_supported`.
      # Boruta validates these as a space-separated set drawn from `code`/`id_token`/`token`
      # (and `vp_token`, which we do not offer), so this is the standard OIDC set.
      "response_types_supported" => [
        "code",
        "id_token",
        "token",
        "id_token token",
        "code id_token",
        "code token",
        "code id_token token"
      ],
      "subject_types_supported" => [
        "public"
      ],
      # TODO: replace with actual scopes we want to use as a provider
      "scopes_supported" => Bonfire.OpenID.Provider.ClientApps.default_scopes(),
      "token_endpoint" => "#{base_url}/openid/token",
      "userinfo_endpoint" => "#{base_url}/openid/userinfo"
    }
  end

  def oauth_authorization_server_data do
    base_url = Bonfire.Common.URIs.base_url()

    %{
      "issuer" => "#{base_url}",
      "authorization_endpoint" => "#{base_url}/oauth/authorize",
      "token_endpoint" => "#{base_url}/oauth/token",
      # NOTE: points to OpenID dynamic client registration endpoint instead
      "registration_endpoint" => "#{base_url}/openid/register",
      "userinfo_endpoint" => "#{base_url}/oauth/userinfo",
      # NOTE: points to OpenID jwks endpoint instead
      "jwks_uri" => "#{base_url}/openid/jwks",
      "revocation_endpoint" => "#{base_url}/oauth/revoke",
      "introspection_endpoint" => "#{base_url}/oauth/introspect",
      "scopes_supported" => Bonfire.OpenID.Provider.ClientApps.default_scopes(),
      # "token_endpoint_auth_methods_supported"=>
      #   ["client_secret_basic", "private_key_jwt"],
      "token_endpoint_auth_signing_alg_values_supported" => alg_supported(),
      # response types, not grant types: the grant list belongs under `grant_types_supported`.
      # Boruta validates these as a space-separated set drawn from `code`/`id_token`/`token`
      # (and `vp_token`, which we do not offer), so this is the standard OIDC set.
      "response_types_supported" => [
        "code",
        "id_token",
        "token",
        "id_token token",
        "code id_token",
        "code token",
        "code id_token token"
      ],
      "grant_types_supported" => [
        "authorization_code",
        "implicit",
        "password",
        "client_credentials",
        "refresh_token"
      ],
      # CIMD: clients may use their own HTTPS URL as client_id (no pre-registration needed)
      "client_id_metadata_document_supported" => true,
      # This instance's own CIMD URL, used when connecting to other servers as a client
      "client_id" => Bonfire.OpenID.Client.cimd_client_id()
      # "ui_locales_supported" => ["en"]
    }
  end
end
