defmodule Bonfire.OpenID.Web.OpenidView do
  use Bonfire.UI.Common.Web, :view

  def render("jwks.json", %{jwk_keys: jwk_keys}) do
    %{keys: jwk_keys}
  end

  def render("userinfo.json", %{userinfo: userinfo}) do
    userinfo
  end

  def render("openid-configuration.json", _) do
    base_url = Bonfire.Common.URIs.base_url()

    %{
      # "authorization_endpoint"=> "#{base_url}/oauth/authorize",
      "authorization_endpoint" => "#{base_url}/openid/authorize",
      "id_token_signing_alg_values_supported" => [
        "RS512"
      ],
      "issuer" => "#{base_url}",
      "jwks_uri" => "#{base_url}/openid/jwks",
      "registration_endpoint" => "#{base_url}/openid/register",
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

  def render("error.html", %{error: error, error_description: error_description}) do
    error(error, to_string(error_description))
    error_description
  end
end
