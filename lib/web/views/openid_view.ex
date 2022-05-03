defmodule Bonfire.OpenID.Web.OpenidView do
  use Bonfire.Web, :view

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
      "authorization_endpoint"=> "#{base_url}/openid/authorize",
      "id_token_signing_alg_values_supported"=> [
          "RS512"
      ],
      "issuer"=> "#{base_url}",
      "jwks_uri"=> "#{base_url}/openid/jwks",
      "response_types_supported"=> [
          "client_credentials",
          "password",
          "authorization_code",
          "refresh_token",
          "implicit",
          "revoke",
          "introspect"
      ],
      "subject_types_supported"=> [
          "public"
      ],
      "token_endpoint"=> "#{base_url}/oauth/token",
      "userinfo_endpoint"=> "#{base_url}/openid/userinfo"
    }
  end

  def render("error.html", %{error: error, error_description: error_description}) do
    error_description
  end
end
