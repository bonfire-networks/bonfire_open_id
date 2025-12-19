defmodule Bonfire.OpenID.Provider do
  def openid_configuration_data do
    base_url = Bonfire.Common.URIs.base_url()

    %{
      # "authorization_endpoint"=> "#{base_url}/oauth/authorize",
      "authorization_endpoint" => "#{base_url}/openid/authorize",
      "issuer" => "#{base_url}",
      "jwks_uri" => "#{base_url}/openid/jwks",
      "registration_endpoint" => "#{base_url}/openid/register",
      "id_token_signing_alg_values_supported" => [
        "RS512"
      ],
      "response_types_supported" => [
        "client_credentials",
        "password",
        "authorization_code",
        "refresh_token",
        "implicit",
        "revoke",
        "introspect"
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
      "token_endpoint_auth_signing_alg_values_supported" => ["RS256", "RS512"],
      "response_types_supported" => [
        "client_credentials",
        "password",
        "authorization_code",
        "refresh_token",
        "implicit",
        "revoke",
        "introspect"
      ],
      "grant_types_supported" => [
        "authorization_code",
        "implicit",
        "password",
        "client_credentials",
        "refresh_token"
      ]
      # "ui_locales_supported" => ["en"]
    }
  end
end
