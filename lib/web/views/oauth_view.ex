defmodule Bonfire.OpenID.Web.OauthView do
  use Bonfire.UI.Common.Web, :view

  alias Boruta.Oauth.IntrospectResponse
  alias Boruta.Oauth.TokenResponse

  def render("token.json", %{
        response: %TokenResponse{
          token_type: token_type,
          access_token: access_token,
          expires_in: expires_in,
          refresh_token: refresh_token,
          id_token: id_token
        }
      }) do
    Enum.filter(
      %{
        token_type: String.capitalize(token_type || "Bearer"),
        access_token: access_token,
        expires_in: expires_in,
        refresh_token: refresh_token,
        id_token: id_token
      },
      fn
        {_key, nil} -> false
        _ -> true
      end
    )
    |> Enum.into(%{created_at: System.os_time(:second)})
    |> debug()
  end

  def render("introspect.json", %{
        response: %IntrospectResponse{
          active: active,
          client_id: client_id,
          username: username,
          scope: scope,
          sub: sub,
          iss: iss,
          exp: exp,
          iat: iat
        }
      }) do
    case active do
      true ->
        %{
          active: true,
          client_id: client_id,
          username: username,
          scope: scope,
          sub: sub,
          iss: iss,
          exp: exp,
          iat: iat
        }

      false ->
        %{active: false}
    end
  end

  def render("error.json", %{error: error, error_description: error_description}) do
    %{
      error: error,
      error_description: error_description
    }
  end

  def render("error.html", %{error: error, error_description: error_description}) do
    error(error, to_string(error_description))
    error_description
  end

  def render("oauth-authorization-server.json", _) do
    base_url = Bonfire.Common.URIs.base_url()

    %{
      "issuer" => base_url,
      "authorization_endpoint" => "#{base_url}/oauth/authorize",
      "token_endpoint" => "#{base_url}/oauth/token",
      "registration_endpoint" => "#{base_url}/openid/register", # NOTE: points to OpenID dynamic client registration endpoint instead
      "userinfo_endpoint"=> "#{base_url}/oauth/userinfo",
      "jwks_uri" => "#{base_url}/openid/jwks", # NOTE: points to OpenID jwks endpoint instead
      "revocation_endpoint" => "#{base_url}/oauth/revoke",
      "introspection_endpoint" => "#{base_url}/oauth/introspect",
      "scopes_supported" => Bonfire.OpenID.Provider.ClientApps.default_scopes(),
      # "token_endpoint_auth_methods_supported"=>
      #   ["client_secret_basic", "private_key_jwt"],
      # "token_endpoint_auth_signing_alg_values_supported"=>
      #   ["RS256"],
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
      ],
      # "ui_locales_supported" => ["en"]
    }
  end
end
